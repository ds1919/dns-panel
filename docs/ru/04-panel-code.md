# 04 — Код панели

Стек: **Perl + Apache (`mod_fcgid`, `mod_rewrite`) + фронтенд без сборки.** Страницы и API обслуживает
один постоянный процесс `www/panel.fcgi`: модули компилируются один раз на процесс, а не на каждый запрос.
Пакеты (Perl-модули из apt, `libfcgi-perl`, `libapache2-mod-fcgid`) ставит `deploy/install.sh`.

## Раскладка `www/`

```
www/                       # DocumentRoot (/var/www/vhost/dns-panel → /opt/dns-panel/www)
├── panel.fcgi             # постоянный процесс: на запрос выполняет index.pl или api.pl
├── index.pl               # страницы: белый список, сессия, каркас, AJAX-фрагменты
├── api.pl                 # JSON API /dns-api/… и /health/{live,ready}
├── login.pl logout.pl 404.pl
├── header.pl              # head()/shell_start()/shell_end(): сайдбар, top bar, баннер STANDBY
├── .htaccess              # rewrite на panel.fcgi, запрет служебных каталогов и файлов
├── include/functions.pm   # вся логика: БД, сессии, права, RRset-слой, валидация, раздача, DNSSEC, HA, Pulse
├── API/                   # Router.pm (маршруты), Response.pm (JSON-ответы)
├── pages/                 # фрагменты: dashboard zones records labels propagation pulse ha audit settings account
├── js/                    # app.js (ядро DNSPanel.*), navigation.js, search.js + по файлу на страницу/раздел
├── css/                   # main.css, dashboard.css, ha.css, themes/
└── mcp/dns-mcp.pl         # MCP-сервер (stdio), см. 10-mcp.md
```

Пути в коде — через `FindBin` (`$FindBin::RealBin/…`). Конфиг читается из `../etc/panel.toml` относительно
`include/` ([02-architecture.md](02-architecture.md#конфигурация)).

## Постоянный процесс

`panel.fcgi` выполняет скрипт через `do`, поэтому файловые переменные свежие на каждый запрос. Правила:

- состояние на время запроса — только в переменных, которые сбрасывает `functions::request_begin()`
  (кэши запроса, соединения с БД);
- страницы подключаются через `do`, не `require`;
- `exit` в скрипте завершает запрос, а не процесс;
- каждый `alarm(N)` снимается `alarm 0` на всех путях, иначе он сработает в следующем запросе.

Скрипты (`index.pl`, `api.pl`, `pages/*.pl`) перечитываются на каждый запрос, а модули (`functions.pm`,
`API/*.pm`, `header.pl`) компилируются один раз на процесс: после их правки нужен новый процесс (`systemctl reload apache2`).
Без `mod_fcgid` тот же `panel.fcgi` работает как обычный CGI (`www/.htaccess`).

## `index.pl` + `header.pl`

- Страница — из `?page=` или пути (`/zones` → `panel.fcgi?page=zones`); белый список `%KNOWN_PAGES`.
  Все страницы требуют сессии (`%PUBLIC_PAGES` пуст); сессия — cookie `session_token`.
- На узле STANDBY пары сессия сбрасывается и пользователь уходит на `/login`, где показан сервисный адрес.
- Два режима: полный ответ (каркас + страница) и `?ajax=1` (только фрагмент, для `navigation.js`).
- Каркас: `head()` → `shell_start()` (сайдбар, top bar с глобальным поиском, баннер STANDBY) → единственный
  `<main id="main-content">` → `shell_end()` (общие оверлеи `#modal-overlay`, `#pulse-overlay`).
  Страницы отдают только внутренний контент.
- `index.pl` ставит cookie `csrf_token` (double-submit) и `dp_theme` (тема на странице входа).
- Весь JS грузится сразу (`load_all_js`, `defer`), чтобы переходы по меню не теряли логику страниц.
  Ассеты версионируются `?v=` (mtime + размер файла).

## `api.pl` + `API/`

- `api.pl` срезает префикс `/dns-api/`, читает тело из STDIN, проверяет сессию, CSRF
  (cookie `csrf_token` = заголовок `X-CSRF-Token`) и HA-гейт записи (`ha_write_verdict`) для изменяющих
  методов, затем отдаёт запрос в `API::Router`. `/health/*` — без сессии и CSRF.
- `API/Router.pm` — таблица `@ROUTES` (regex по `METHOD + PATH`), права проверяет каждый обработчик.
- `API/Response.pm` — `ok`, `created`, `bad_request`, `unauthorized`, `forbidden`, `not_found`, `conflict`,
  `server_error`, `service_unavailable`. Формат: `{ success: bool, data | error }`.

Эндпоинты — [11-api.md](11-api.md).

## Фронтенд

- `app.js` — ядро `window.DNSPanel`: `api`, `patchPage`, `dialog`/`confirm`/`prompt`/`alert`, `selectHtml`,
  общий компонент фильтров (`filterInit`, `filtersGet`, …), busy-курсор на время изменений.
- `navigation.js` — переходы по меню и подсветка активного пункта; в первой отрисовке не участвует.
- Остальные файлы — по странице или разделу (`zones.js`, `records.js`, `dnssec.js`, `import.js`,
  `dynamic.js`, `users_access.js`, …).

Правила первого кадра и обновления без перезагрузки — [02-architecture.md](02-architecture.md#первый-кадр-и-обновление-страниц),
дизайн-система — [07-ui-design.md](07-ui-design.md).

## Правила разработки

### Инварианты

- **HA не делает автоматический failover.** Switchover и emergency запускает человек.
- **Событийно, без таймеров.** Никаких `sleep`, «ждать до N секунд» и обходов по таймеру. Готовность —
  sd_notify; повторы — по сроку из БД; периодично только то, что наблюдает внешний мир (подписка BIND на
  каталог) или страхует от дрейфа.
- **Панель управляет только своим PowerDNS.** BIND на secondary она не конфигурирует, только наблюдает по DNS.
  «Кому отдаём зоны» — флаг группы `zone_axfr`; чужой upstream панель не хранит.
- **HA-гейт записи fail-closed.** На STANDBY, во время операции HA и при неизвестном состоянии панель и фоновые
  проходы ничего не пишут. Гейт один — `ha_write_verdict` в Perl.
- **Правила только в `functions.pm`.** Go-демоны решают «когда» и «сколько сразу», но не дублируют DNS-правила
  (компоненты — [02-architecture.md](02-architecture.md#компоненты-на-узле)).
- **Один путь применения раздачи** — `apply_zones` (одна зона, список или все).
- **Всё на английском** в коде, комментариях, логах и UI.
- **Автотестов нет** (ни Perl, ни Go). Проверка — чтение кода + живая панель; `make check` = gofmt + go vet.

### Факты, без которых легко сломать

- **Панель — постоянный FastCGI-процесс**: см. [Постоянный процесс](#постоянный-процесс).
- **После действия страница целиком не перезагружается** (`DNSPanel.patchPage` или ответ API) — полная
  перезагрузка только когда меняется весь экран (смена роли зоны, HA). См.
  [02-architecture.md](02-architecture.md#первый-кадр-и-обновление-страниц).
- **PowerDNS — только 5.1.x** из `repo.powerdns.com` (ветка `auth-51`), установщик это проверяет. 4.8 из
  Ubuntu 24.04 не даёт менять `TSIG-ALLOW-AXFR` через API.
- **API — `/dns-api/`, не `/api/`**: `/api` на dev-хосте занят чужим сервисом.
- **`capability_grants.capability` — ENUM.** Несуществующее право молча не вставится → всегда 403.
- **Два интервала PowerDNS:** `zone-cache-refresh-interval` — кэш списка зон (новую зону панель объявляет
  `rediscover`); `xfr-cycle-interval` — пересчёт содержимого catalog-зоны и её NOTIFY. NOTIFY каталога вручную
  бесполезен: уйдёт старый serial.
- **SLAVE не попадает в каталог** (ограничение PowerDNS) → только Direct AXFR. NATIVE не раздаётся.
- **Каталожные записи — через PowerDNS HTTP API.** `AXFR-MASTER-TSIG` API не обслуживает (422) — только SQL.
- **Записи подписанной зоны пишутся SQL** → после каждой записи обязателен rectify (`zone_sync_verify` делает его сам).
- **Своя политика на зоне помечается `X-DNSPANEL-POLICY`**; уборка сирот идёт только по этому маркеру.
- **TSIG-ключ уходит сам**, когда снята последняя ссылка; ключи, заведённые на сервере руками, не трогаются.
- **Perl + UTF-8:** `functions.pm` ставит `:utf8` на STDOUT; скрипт с не-ASCII текстом — с `use utf8`.
- **Профиль, метки и группы — разные сущности:** профиль — пресет SOA/NS (при создании зоны необязателен),
  метки — теги без влияния на DNS, группы прав ≠ группы серверов.
- **`dig -k` из `/tmp` не читается** (AppArmor) и молча идёт без подписи → `dns-agent` передаёт ключ через stdin.
- **Установщик пишет в MariaDB только с `sql_log_bin=0`**: иначе в паре появляются errant GTID.

### Как проверять

1. Прочитать реальный контракт (`www/API/Router.pm`) и код.
2. `perl -c` / `node --check` / `make check` по тронутым файлам.
3. Увидеть результат в живой панели (после правки модулей — новый процесс, см. [Постоянный процесс](#постоянный-процесс)).
4. Геометрию — одноразовой страницей в scratchpad с настоящими данными + headless-скриншот; в репозиторий
   такие стенды не кладутся.
5. Всё, что заведено для пробы, убирать функциями ядра (`zone_delete_everywhere`, `tsig_keys_forget_unused`)
   с обеих сторон — строка панели и копия в PowerDNS.

Схема БД: `docs/INSTALL/schema.sql` — полная схема для чистой установки; любое изменение — ещё и файл в
`deploy/migrations/` (правила — [там же](../../deploy/migrations/README.md)), в одном коммите.

### Отложено сознательно

- `emergency.go`/`reseed.go` после точки невозврата уходят в `StateFailed` — нужен разбор каждой точки.
- Configure HA — синхронный HTTP без журналируемой операции.
- Меню `DNSPanel.selectHtml` — `position:absolute`, в таблице будет обрезаться; при первом появлении такого
  select'а перевести на фиксированный слой, как `.grp-ms-pop`.
- API-поле `renotify` в `POST /zones` принимается для совместимости, но для зоны в раздаче значение производное.
