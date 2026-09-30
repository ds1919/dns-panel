# 05 — dns-agent (привилегированный посредник PowerDNS)

Панель работает под `www-data` и **не имеет доступа** к control-socket PowerDNS
(`/run/pdns/pdns.controlsocket`, владелец `pdns:pdns`). Поэтому после прямого SQL в gmysql
она сообщает PowerDNS об изменениях не сама, а через маленький привилегированный демон.

```
DNS Panel / API / MCP (www-data)
        │ unix-socket /run/dns-panel/pdns/dns-agent.sock  (0660 pdns:www-data)
        ▼
dns-agent (User=pdns, Go: src/dns-agent → bin/dns-agent)
        │
        ▼
pdns_control rediscover | purge zone$ | notify zone | retrieve zone     +    dig (SOA, AXFR)
```

**Только фиксированные команды, без shell.** Зона проверяется так же, как в панели
(`dns_validate_zonename`), адрес сервера — как IP, TSIG-ключ — по формату; у каждого запуска
`pdns_control`/`dig` таймаут `timeout`. `dig` (verify, soa_at, axfr_at) идёт параллельно, не больше
`max_concurrent` запросов сразу (остальные ждут в очереди сокета); `pdns_control` — строго по одному, и ожидание
своей очереди входит в тот же `timeout`. Клиент, который подключился и молчит, отключается по таймауту.

## Протокол (JSON-строка → JSON-строка)

| Запрос | Ответ |
|--------|-------|
| `{"cmd":"ping"}` | `{"ok":1,"pong":1}` |
| `{"cmd":"rediscover"}` | `{"ok":1,"output":"Ok"}` |
| `{"cmd":"purge","zone":"z"}` | `{"ok":1,"output":"<N>"}` (purge `z$` — зона+поддерево) |
| `{"cmd":"notify","zone":"z"}` | `{"ok":1,"output":"Added to queue"}` |
| `{"cmd":"retrieve","zone":"z"}` | `{"ok":1,"output":"Added retrieval request..."}` (SLAVE: немедленный AXFR от primary) |
| `{"cmd":"verify","zone":"z","expect_serial":N}` | `{"ok":1,"served":true,"serial":N,"matches":true}` |
| `{"cmd":"soa_at","zone":"z","server":"ip"}` | `{"ok":1,"serial":N}` — SOA на другом сервере (Make primary: не отстаём ли от старого мастера) |
| `{"cmd":"axfr_at","zone":"z","server":"ip","key":{"name","algorithm","secret"}?}` | `{"ok":1,"records":[...]}` — AXFR с другого сервера (Import); отказ — `{"ok":0,"status":"REFUSED",...}`, ключ отвергнут — плюс `"tsig_rejected":1` |

Ошибка — `{"ok":0,"error":"..."}`. TSIG-секрет уходит в `dig -k /dev/stdin`: не в argv (виден в `ps`) и не
в файл (AppArmor-профиль dig не читает `/tmp`).

## Установка

Бинарник (Go, только стандартная библиотека) приходит собранным в пакете релиза (из исходников — `make build`)
(`make -C src/dns-agent build` → `bin/dns-agent`, на узлах Go нет). Ставит `deploy/install.sh`: юнит
`etc/systemd/dns-agent.service` симлинком в `/etc/systemd/system/`, `enable` + `restart`.

Unit-ключевое:
- `Type=notify` — `systemctl start` возвращается, когда сокет открыт;
- `User=pdns` — доступ к control-socket PowerDNS;
- агент **не** состоит в группе `www-data`: её члены читают секреты панели (`panel.toml`, пароли БД);
- каталог сокета `/run/dns-panel/pdns` — `2750 pdns:www-data` (tmpfiles, `etc/tmpfiles/dns-panel.conf`): setgid
  даёт сокету группу `www-data`, панель может его открыть, но писать в каталог не может. Если группа сокета
  не та, агент не стартует.

## Конфигурация

`etc/dns-agent.toml` — конфиг самого агента (свой файл: процессу под pdns не нужны пароли БД панели):

```toml
socket          = "/run/dns-panel/pdns/dns-agent.sock"
socket_group    = "www-data"
timeout         = 5                          # секунды на запрос, включая очередь к pdns_control
max_concurrent  = 16                         # запросов одновременно
pdns_control    = "/usr/bin/pdns_control"
dig             = "/usr/bin/dig"
verify_resolver = "127.0.0.1"
```

Неизвестный ключ или строка без `=` — ошибка при старте, а не молчаливое значение по умолчанию. Панель находит
сокет по `[agent] socket` в `etc/panel.toml`.

## Проверка вручную (от www-data)

```bash
sudo -u www-data perl -I /opt/dns-panel/www/include -MJSON -e 'use functions qw(dns_agent_call); print encode_json(dns_agent_call(q(ping))), "\n"'
```

## Prod-контур синхронизации (как это использует панель)

```
Primary, создание:    SQL commit → rediscover → verify SOA → NOTIFY → durable-статус
Secondary, создание:  SQL commit → rediscover → retrieve (AXFR запрошен) → pending_transfer
Удаление зоны:        SQL commit → rediscover → verify «не обслуживается» → durable-статус
Правка RRset:         SQL commit → purge zone$ → verify serial → notify zone
```

Secondary при создании ничего не ждёт и не проверяет: трансфер PowerDNS ставит в очередь, а его
завершение наблюдает worker. Пачка переноса делает `rediscover` один раз на все зоны. Приехавшей
secondary считается зона, которую PowerDNS **отдаёт** и которую он **сверил с текущим primary**
(`domains.last_check > 0`: его ставит PowerDNS после удачного AXFR или SOA-сверки, а смена источника и
Make secondary обнуляют). Только «отдаётся» мало: после смены источника зона продолжает отдавать
данные прежнего primary. **Refresh AXFR** на странице зоны — один `retrieve`, то есть «запрошено», а
не «приехало»; приезд видно по Last check.

Статус хранится в `dns_panel.zone_sync_state` (`pdns_state`: `active` / `pending_transfer` /
`transfer_problem` / `activation_failed` / `removed` / …; `notify_state`: `notified` / `notify_failed` /
`not_attempted` / `not_applicable`). **Сбой агента после commit НЕ откатывает БД** — зона создана, но
состояние это показывает, и worker его доводит.

> Благодаря явному `rediscover` **не нужен** `zone-cache-refresh-interval=0` — держите штатный
> default (300). Прямой SQL мимо HTTP API не сбрасывает zone-cache сам, поэтому это делает агент.

## Автовосстановление (dns-sync-worker)

`zone_sync_state` хранит `operation` (`activate`|`deactivate`), `attempts` (число подряд неудач),
`last_attempt_at`, `next_retry_at`, `pending_since` и `state_version` (CAS). Worker берёт только зоны,
которым «пора» (`next_retry_at <= NOW()`):

- **activate** — `activation_failed` / `notify_failed`: повтор `zone_sync_verify` (verify по актуальному
  SOA-serial из БД → NOTIFY). Зона пропала из PowerDNS → `orphaned`.
- **pending_transfer** (secondary) — проверка раз в `sync.poll_seconds`: приехала (отдаётся и сверена) →
  `active`, нет → AXFR просится снова. Ждёт дольше `sync.transfer_timeout_seconds` с начала ожидания (Refresh AXFR начинает его заново)
  → `transfer_problem` с backoff: это граница «показать проблему», а не признак окончания трансфера.
- **deactivate** — после удаления зона всё ещё отдаётся (`still_served` / `deactivation_failed`) →
  повтор `rediscover` + verify «больше не обслуживается» (успех = `removed`).

Оператор может нажать **Retry now** в баннере проблемы на странице зоны — это тот же проход, что у worker'а.

- **Демон** `dns-sync-worker` (Go, `src/dns-sync-worker`) решает только, **когда** работать. Что делать —
  проходы `libexec/sync-task.pl` (Perl, правила в `functions.pm`): `retry-due`, `reconcile`, `probe-batch`,
  `catalogs`, `schedule`. Каждый проход сам проверяет HA (на STANDBY и во время заморозки ничего не пишет,
  неизвестное состояние — fail-closed) и возвращает JSON с расписанием, которое оставил в БД. Юнит
  `etc/systemd/dns-sync-worker.service`: `Type=notify` (готов, когда открыт wake-сокет), `User=www-data`; ставит
  `deploy/install.sh`, бинарник приходит собранным в пакете релиза (из исходников — `make build`). Таймеров systemd нет — расписание держит сам демон.
- Всё состояние — в БД (`next_retry_at`, очередь Probe `probe_state='queued'`, сама политика). Демон спит
  до ближайшего срока; панель, поставив что-то в очередь, будит его датаграммой в
  `/run/dns-panel/sync/wake.sock` (`sync_wake`; каталог — `2750 www-data:dns-ha` из tmpfiles, setgid даёт
  сокету группу `dns-ha`, чтобы будить мог и `dns-ha-manager`). Потерянный пинок стоит не больше одного интервала каталогов.

  | что | когда |
  |---|---|
  | повтор зон (`retry-due`) | ровно в `next_retry_at` |
  | Probe (`probe-batch`) | сразу после постановки в очередь, партия за партией, пока очередь не кончится |
  | наблюдение каталогов (`catalogs`) | каждые `sync.catalog_check_seconds` (60) — BIND сам ничего не сообщает |
  | страховочная сверка раздачи и Dynamic (`reconcile`) | каждые `sync.reconcile_seconds` (600) после конца прохода; правки применяются сразу, это только от дрейфа. Не сошлась (PowerDNS недоступен) — снова через `sync.backoff_initial_seconds` (60) |
  | нода может писать снова (стала ACTIVE, операция HA закончилась) | сразу полная сверка: `dns-ha-manager` будит демон в тот же момент, когда открывается гейт записи |
- Проход, который ничего не сдвинул (зона занята ручным Retry, агент недоступен), не повторяется сразу, а
  ждёт следующего интервала каталогов или пинка. Взаимоисключение с ручным Retry — advisory `GET_LOCK`;
  устаревшая задача (параллельный create/delete сменил `operation`/версию) отбрасывается по CAS как `superseded`.
- Параметры — настройки в таблице `dns_panel.settings` (`sync.poll_seconds` 30,
  `sync.transfer_timeout_seconds` 3600, `sync.backoff_initial_seconds` 60, `sync.backoff_max_seconds` 3600,
  `sync.catalog_check_seconds` 60, `sync.reconcile_seconds` 600, `sync.retry_batch` 100, `import.probe_batch` 50,
  `import.probe_budget_seconds` 60; значения по умолчанию — `%SETTING_DEFAULTS`
  в `functions.pm`). Секции `[sync]` в `etc/panel.toml` нет.

```bash
systemctl status dns-sync-worker; journalctl -u dns-sync-worker -f
# один проход вручную (под www-data — нужен доступ к сокету агента и БД):
sudo -u www-data /opt/dns-panel/libexec/sync-task.pl retry-due
```

Эндпоинты панели: `GET /dns-api/sync/problems` (проблемные зоны, фильтр по доступу),
`POST /dns-api/zones/:id/retry-sync` (Retry now), `POST /dns-api/zones/:id/refresh-axfr` (Refresh AXFR);
оба POST требуют write-доступ к зоне. В UI: баннер на зоне, бейдж + фильтр **Sync** в списке зон.
