# 02 — Архитектура

## Часть A. DNS-кластер

```
                       ┌──────────────────────────┐
                       │ DNS Panel (Perl FastCGI) │
                       └────────────┬─────────────┘
                                    │ SQL (записи, bump SOA serial), HTTP API (метаданные, каталоги)
                                    ▼
                       ┌──────────────────────────┐
                       │  Shadow-master PowerDNS  │  ← скрытый, НЕ в NS-записях
                       │  backend: gmysql         │
                       └────────────┬─────────────┘
                                    │ NOTIFY  ─────────────►
                                    │ AXFR    ◄─────────────
              ┌─────────────────────┼─────────────────────┐
              ▼                     ▼                     ▼
       ┌────────────┐        ┌────────────┐        ┌────────────┐
       │ BIND slave │        │ BIND slave │        │ BIND slave │  ← публичные NS
       └────────────┘        └────────────┘        └────────────┘
```

- **Shadow-master (PowerDNS 5.1).** Авторитативный источник зон, адрес не публикуется в NS-записях. В проде —
  HA-пара с общим сервисным адресом ([13-ha-topology.md](13-ha-topology.md), [22-ha-contract.md](22-ha-contract.md)).
- **Secondary (BIND).** Публичные серверы имён, перечислены в NS-записях. Панель их не конфигурирует, только
  наблюдает по DNS. Кому и как уходят зоны (прямая раздача, каталоги RFC 9432, два канала NOTIFY) —
  [16-delivery.md](16-delivery.md).

### Поток правки зоны

1. SQL-транзакция в БД PowerDNS: SOA `FOR UPDATE`, запись изменений, bump serial.
2. Для подписанной зоны — rectify (цепочка NSEC/NSEC3).
3. Через `dns-agent`: сброс кэша зоны в PowerDNS, проверка, что PowerDNS отдаёт новый serial, NOTIFY.
4. Итог — в `zone_sync_state` и в аудит. Неудачу повторяет `dns-sync-worker`.

Secondary-зоны (`domains.type = SLAVE`) PowerDNS сам тянет с внешнего мастера (`domains.master`) и отдаёт
дальше. Подробно — [05-dns-model.md](05-dns-model.md), почему прямой SQL — [24-dns-engine.md](24-dns-engine.md).

## Часть B. Панель

```
Apache (mod_fcgid + mod_rewrite, www/.htaccess)
   │
   └── panel.fcgi      постоянный процесс; на запрос выполняет (do) index.pl или api.pl
         ├── index.pl        страницы: проверка сессии, каркас (header.pl) + pages/*.pl
         ├── api.pl          JSON API /dns-api/… и /health/{live,ready} → API::Router
         └── include/functions.pm   вся логика: БД, права, DNS-правила, HA-гейт записи
   login.pl, logout.pl, 404.pl — отдельные CGI
```

Код — [04-panel-code.md](04-panel-code.md), БД — [03-database.md](03-database.md).

### Первый кадр и обновление страниц

- `index.pl` печатает страницу целиком одним ответом: каркас + сама страница в `#main-content`. Данные,
  нужные первому кадру, приезжают в самой странице (bootstrap-блок JSON). **Первый кадр обязан быть
  правдой**: без прочерков, запасного порядка и пустых таблиц, которые через мгновение перестраиваются.
  Допустимая асинхронная догрузка помечается в коде строкой `async-ok:` с объяснением.
- `js/navigation.js` работает только на переходах по меню: тянет `/ajax/<page>` и подставляет фрагмент
  в `#main-content`, не трогая каркас.
- После действия страница не перезагружается. Страницы, которые рисует сервер, обновляются через
  `DNSPanel.patchPage` (свежий HTML, заменяется только отличающееся); страницы, которые рисует JS, берут
  изменения из ответа API. Опрос меняет данные точечно, DOM не пересоздаётся.

### Компоненты на узле

| | под кем | что |
|---|---|---|
| панель (`panel.fcgi`) | `www-data` | UI и API; все DNS-правила |
| `dns-agent` (Go) | `pdns` | посредник к PowerDNS: `pdns_control` и `dig` с проверенными аргументами; сокет `/run/dns-panel/pdns` |
| `dns-sync-worker` (Go) + `libexec/sync-task.pl` | `www-data` | решает КОГДА: повтор зон, Probe, наблюдение каталогов, страховочная сверка; проходы и HA-гейт — в Perl |
| `dns-ha-manager` (Go) | `dns-ha` | логика пары ([23-ha-manager.md](23-ha-manager.md)); будит sync-worker при смене гейта записи |
| `dns-ha-agent` (Go) | `root` | HA-действия: read_only MariaDB, роль PowerDNS, адрес на `lo`, проба готовности (17900) |
| `pulse-server` (Go) | `dns-pulse` | по желанию: NS Pulse, запускает `pulse-apply.pl`, ведёт список целей Pinger |
| `pulse-agent`, `dns-watcher` (Go) | — | ставятся вне узла панели: тестер NS Pulse; внешний исполнитель пробы anycast |

### Конфигурация

- **`etc/panel.toml`** — только то, что нужно до подключения к БД, и свойства узла: `panel_db`, `pdns_db`,
  `pdns_api`, `auth`, `agent`, `pulse`, `ha` (шаблон — `etc/panel.example.toml`). Переменные окружения
  не используются.
- **`etc/secrets/`** — пароли и ключи отдельными файлами; в `panel.toml` только пути к ним.
- **Таблица `settings`** — то, чем администратор управляет из панели (Settings); реплицируется в паре.

Служебные каталоги (`include`, `API`, `pages`, `mcp`) и файлы `*.json|sql|pm|md` закрыты от веба в `www/.htaccess`.
