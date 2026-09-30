# 23 — HA-контур: `dns-ha-manager` и `dns-ha-agent`

Как устроен и что делает HA-контур пары. Код — `src/dns-ha` (сборка — [src/dns-ha/README.md](../../src/dns-ha/README.md)).
Правила, которые контур гарантирует, — [22-ha-contract.md](22-ha-contract.md); размещение в проде —
[13-ha-topology.md](13-ha-topology.md); установка и сборка пары — [INSTALL/02-ha-pair.md](INSTALL/02-ha-pair.md).

---

## 1. Состояния узла

```
Standalone ──(сопряжение, §14.5)──▶ Paired · HA not configured ──(pair build, §14.6)──▶ Paired · HA active
                                            ▲                                                │
                                            └──────────────── dismantle (§11) ───────────────┘
```

| состояние | что есть на узле | как работает |
|---|---|---|
| Standalone | нет доверия к соседу | обычный одиночный узел |
| Paired · HA not configured | `peer.key` + запись `ha_trusted_peer`, эффективной ревизии нет | как одиночный: writable, PowerDNS `yes/yes`, без публикации (решение `ha_not_configured`) |
| Paired · HA active | эффективная ревизия конфигурации пары, epoch, право быть ACTIVE у одного узла | роли ACTIVE / STANDBY |

Доверие снимается только явно (`-pair reset -force`), не из-за недоступного соседа.

---

## 2. Процессы и граница привилегий

| процесс | под кем | что делает |
|---|---|---|
| `dns-ha-manager` | `dns-ha` | цикл наблюдения/решений (§8), операции (§9–11), peer-канал TCP 7901 (§6), управляющий сокет `/run/dns-panel/ha/manager.sock` (0660), проба готовности anycast (§14.2) |
| `dns-ha-agent` | `root` | единственный, кто меняет узел (MariaDB, PowerDNS, адрес, секреты); только unix-сокет `/run/dns-panel/ha/agent.sock`, сеть не слушает |

Сетевой процесс не root и не имеет прав менять роль узла; root-процесс не принимает решений и исполняет
фиксированный набор типизированных команд. Группа `dns-ha` означает «может пользоваться HA-IPC»; `www-data`
входит в неё, обратного членства нет (иначе сетевой демон читал бы `etc/secrets`).

Оба юнита — `Type=notify`: готовность сообщается `sd_notify` после того, как поднят сокет (manager — после
первого наблюдения и схемы/идентичности). Manager не зависит от панели: при остановленном Apache пара
продолжает сходиться.

**Команды агента.** Мутации: `promote`, `demote`, `enable_notifier`, `disable_notifier`, `announce_panel`,
`withdraw_panel`, `rejoin_replica`, `reseed_replica`, `drain_relay`, `emergency_promote`, `stop_replication`,
`release_publication`. Служебные (сопряжение, создание и роспуск пары, публикация): `install_peer_key`,
`remove_peer_key`, `install_secret`, `read_secret`, `ensure_pair_grants`, `enable_failsafe`/`disable_failsafe`,
`reset_pair_state`, `resolve_publication_device`, `check_publication`, `address_present`, `drop_address`.
Чтение: `status`, `preflight`, `inventory`.

Контракт мутаций:
- обязательны `operation_id` и `cluster_epoch`; epoch ниже принятого → `stale_epoch`;
- повтор той же пары (`operation_id`, команда) → `ok, noop` без повторного действия (durable done-set);
- максимальный принятый epoch и done-set — `/opt/dns-panel/var/agent-state.json` (root 0600, fsync);
- одна мутация за раз (flock), иначе `busy`;
- `status`/`preflight` ничего не меняют и лок не берут. `preflight` подтверждает только, что
  привилегированный путь работает (MariaDB доступна, `read_only` читается, реплика не в явной ошибке).

Роль PowerDNS агент меняет в `/etc/powerdns/pdns.d/90-ha-role.conf` (пара `primary`/`secondary`): запись
файла → проверка конфига → рестарт → PONG → сверка фактической роли; не подтвердилась → `role_unverified`.

---

## 3. Право быть ACTIVE

### 3.1 Роль выводится из права

Роль узла — не строка в базе, а состояние **authority** в safety-файле (§4.3):

| состояние | смысл |
|---|---|
| `valid_current` | право выдано на текущий epoch → узел ACTIVE |
| `stale` | право прошлого epoch — не право |
| `absent` | права нет → STANDBY |
| `foreign_role` | запись испорчена |
| `unknown` | safety-файл не прочитан → роль `unknown`, решения только «ждать» |

### 3.2 Откуда берётся право

| тип | кто выдаёт | когда |
|---|---|---|
| `bootstrap` | создание пары, донору (§14.6) | epoch 1 |
| `handoff` | прежний ACTIVE при плановом переключении, после доказанного demote и drain (§9) | epoch + 1 |
| `emergency` | оператор типизированным основанием (§10.1) | epoch + 1 |

Приём handoff-сертификата (`handoff_certificate`) проверяет: есть `operation_id`; издатель совпадает с
подписавшим отправителем; узел не огорожен; epoch ровно `max_seen_epoch + 1`; отпечаток конфигурации
совпадает; узел ещё не физически ACTIVE. Право пишется в safety **до** ответа; повтор того же сертификата
(epoch, издатель, тип) — успех.

Право само по себе позволяет **оставаться** ACTIVE. **Стать** ACTIVE после потери физического состояния
можно только с дополнительным доказательством (§8.3).

### 3.3 Epoch

- `max_seen_epoch` — в safety-файле, монотонен. Плановое переключение и аварийное повышение поднимают его на
  1; пересев и роспуск не меняют.
- Агент хранит свою копию (максимальный принятый `cluster_epoch`); если она опередила safety-файл —
  `safety_epoch_consistency` в `ha_healthy` краснеет.
- Сосед с бо́льшим epoch → узел уходит в безопасное состояние (§8.2). Peer-команды из прошлого epoch не
  исполняются (§6.1).

### 3.4 Физика

`@@global.read_only` по-прежнему защищает данные (`pdns`, `dns_panel`). Право и физика сверяются независимо:
ACTIVE с `read_only=1` или не-ACTIVE с `read_only=0` → `role_vs_physics` (manager) и `ha_role_mismatch`
(write-gate панели, [22 §6](22-ha-contract.md#6-write-gate-панели)).

Fail-safe пары — `etc/mariadb/ha-failsafe.cnf` (`read_only=ON`, `skip_slave_start=ON`), симлинк
`/etc/mysql/mariadb.conf.d/61-dns-panel-ha.cnf`. Кладётся при создании пары, убирается роспуском; после
рестарта MariaDB узел пары стартует read-only и без потоков репликации, роль возвращает сходимость.

---

## 4. Хранилище

| что | где |
|---|---|
| конфигурация пары (ревизии), журнал операций, проекция состояния, реестр peer-мутаций, идентичность и доверие | локальная MariaDB-база `dns_ha` |
| доказательства: epoch, право быть ACTIVE, handoff, emergency, огораживание, доказательство фиксации конфигурации | файл `/opt/dns-panel/var/safety.json` |

### 4.1 `dns_ha` не реплицируется

`binlog_ignore_db = dns_ha` и `replicate_ignore_db = dns_ha` в `etc/mariadb/dns-panel.cnf` на обоих узлах,
`binlog_format = ROW` (фильтр работает по базе таблицы). `sql_log_bin=0` не используется: он требует
`BINLOG ADMIN`. Настройки проверяются непрерывно (§12.3).

### 4.2 Доступ к MariaDB

`'dns-ha'@'localhost'` через `unix_socket` (пароля нет): `ALL` на `dns_ha.*`, глобально `READ_ONLY ADMIN`
(писать `dns_ha` на read-only STANDBY) и `SLAVE MONITOR` (`SHOW REPLICA STATUS`). К `pdns`/`dns_panel`
доступа нет: опись данных для создания пары даёт агент. Базу и гранты создаёт установщик, схему
Схему (`src/dns-ha/internal/store/dns_ha.sql`, встроена в бинарник) применяет сам manager.

### 4.3 Файлы

```
/opt/dns-panel/var/safety.json        dns-ha:dns-ha 0600   доказательства (ниже)
/opt/dns-panel/var/agent-state.json   root:root 0600       принятый epoch + done-set агента
/run/dns-panel/ha/                    root:dns-ha 0770     manager.sock, agent.sock, agent.lock, safety.lock
```

`safety.json`: `node_id`, `max_seen_epoch`, `authority`, `committed_config`, `handoff`, `emergency`,
`fenced_node`. Единственный писатель — `safety.Store.Update`: мьютекс + flock на
`/run/dns-panel/ha/safety.lock` (не на самом файле: он заменяется через rename), перечитывание перед
изменением, атомарная запись. Незнакомые поля сохраняются. Доказательства с epoch больше `max_seen_epoch`
отвергаются. Файл привязан к `node_id` узла: чужой — `safety_foreign`.

### 4.4 Таблицы `dns_ha`

| таблица | что |
|---|---|
| `ha_schema` | версия схемы |
| `ha_identity` | UUID узла (одна строка, создаётся при первом старте, не меняется) |
| `ha_trusted_peer` | результат сопряжения: `committing`/`trusted`, UUID и адрес соседа, отпечатки ключа и стенограммы |
| `ha_config_revision` | ревизии: `STAGED`/`EFFECTIVE`/`REJECTED`, `payload_hash`, `payload_blob` |
| `ha_nodes`, `ha_settings`, `ha_replication`, `ha_publication` | проекция ревизии для панели и SQL (§7.1) |
| `ha_operations`, `ha_operation_steps` | журнал операций и их шагов (§9–11) |
| `ha_state` | проекция наблюдаемого состояния |
| `ha_peer_requests` | durable-дедупликация peer-мутаций (§6.1) |

#### 4.4.1 Инвариант

В `dns_ha` нет ни одного доказательства права: epoch, authority, огораживание и доказательство фиксации
конфигурации — только в safety-файле. Потеря `dns_ha` — сброс локального контура (новый UUID, нет ревизии и
доверия, пару собирают заново — [INSTALL/02 §5.4](INSTALL/02-ha-pair.md#54-пересборка-пары-с-нуля)), но не
основание забыть epoch или огораживание. Нет safety-файла — нет права (`unknown`/`absent`), повышения нет.

### 4.5 Секреты

| файл (`/opt/dns-panel/etc/secrets/`) | владелец | откуда |
|---|---|---|
| `peer.key` | `dns-ha:dns-ha 0600` | выводится обоими узлами при сопряжении (§14.5), кладёт агент `install_peer_key` (write-once) |
| `repl.secret`, `ha_monitor.secret` | `root:root 0600` | создание пары: значения донора (или новые), соседу передаются зашифрованными (§6), гранты `repl`/`ha_monitor` на обоих |
| `auth-master.key` | root, группа панели | донор → приёмник после пересева (TOTP-секреты в `dns_panel` зашифрованы им) |

В ревизии только `secret_ref`, не значения. Локальными остаются `panel-db.password`, `pdns-db.password`,
`pdns-api.key`.

---

## 5. Конфигурация узла

`/opt/dns-panel/etc/ha.toml` — только доступ к своей базе:

```toml
[database]
socket   = "/run/mysqld/mysqld.sock"
database = "dns_ha"
```

Разбор строгий: неизвестный ключ, значение без кавычек, устаревший `node = …` — ошибка старта. Идентичность —
в `ha_identity`. Конфиг агента `ha-agent.toml` — [INSTALL/02 §4](INSTALL/02-ha-pair.md#4-конфигурация-узла).

Всё о паре (адреса, репликация, публикация) — в ревизии конфигурации (§7). Рабочие константы — в коде
(`internal/config/platform.go`, порт — `cmd/dns-ha-manager/pairing.go`):

| параметр | значение |
|---|---|
| период наблюдения | 3 с |
| таймаут агента / peer-вызова | 5 с |
| допустимое расхождение часов (`ts`) | ±30 с |
| возраст снимка соседа, годный как доказательство | ≤ 30 с |
| лимит peer-сообщения | 64 KiB |
| peer-порт | 7901 |

`settings` в ревизии хранятся и переносятся, но рантаймом не читаются.

---

## 6. Peer-канал

Один listener на TCP 7901 для сопряжения (§14.5) и протокола пары. Пока ревизии нет, слушает все адреса;
после — `peer_listen_host:peer_listen_port` своей строки ревизии.

- Конверт `{body, sig}`: `sig = hex(HMAC-SHA256(peer.key, body))` над **точными байтами** `body`.
  `peer.key` — 64 hex, формат проверяется при загрузке.
- Запрос: `protocol_version` (1), `message_id`, `sender_node_id`, `recipient_node_id`, `epoch`, `ts`, `nonce`,
  `cmd`, `payload`, `payload_hash`, `request_hash`.
- Проверки: подпись, версия протокола (несовпадение — `peer_protocol_version`), отправитель = ожидаемый сосед,
  получатель = я, `ts` в окне ±30 с (**часы узлов должны быть синхронизированы**), одноразовый `nonce`,
  whitelist команд, `payload_hash`, размер.
- Ответ привязан к запросу (`request_message_id`, `request_nonce`, отправитель, `ts`) и подписан; клиент
  сверяет всё — старый подписанный ответ повторно не подсунуть.
- Трафик не шифруется. Секреты при создании пары шифруются AES-256-GCM ключом
  `HKDF(peer.key, "dns-panel secret transfer v1")`.

| класс | команды |
|---|---|
| чтение | `hello`, `status`, `inventory`, `operation_journal` |
| создание пары (принимаются только пока у узла нет эффективной ревизии) | `init_prepare`, `init_reseed`, `init_finish`, `init_seed`, `init_device`, `init_recap`, `init_check` |
| мутации | `config_stage`, `config_commit`, `prepare_switchover`, `await_gtid`, `handoff_certificate`, `clear_fencing`, `release_pair` |

До создания пары (есть только доверие) канал поднимается из `ha_trusted_peer` в режиме чтения: новые мутации
отвергаются, реестр только отвечает на повторы уже выполненных.

### 6.1 Мутации

- Исполняются только при полном наборе: реестр (`ha_peer_requests`) + gate + исполнитель; нет любого —
  типизированный отказ (`peer_ledger_unavailable`, `peer_mutation_gate_unavailable`).
- Регистрация запроса и действие — одна транзакция. `message_id` обозначает логическое действие и
  сохраняется между попытками (`nonce`/`ts` — свои на каждую): повтор возвращает тот же результат; тот же
  `message_id` с другим смыслом — `peer_message_id_conflict`. Отказы «по существу» не кешируются: после
  исправления узла повтор проверяется заново.
- Gate получателя: safety-файл валиден, epoch известен, получатель не огорожен, epoch запроса не меньше своего
  (`config_stage`/`config_commit` — строго равен), получатель сам не ACTIVE — кроме `clear_fencing`, которую
  решает именно ACTIVE. Отказ — `peer_mutation_not_allowed` / `peer_epoch_mismatch`.

---

## 7. Ревизии конфигурации пары

### 7.1 Модель

Конфигурация пары — ревизия: узлы (UUID; имя, hostname, площадка, описание — только для людей;
`peer_listen_host/port`, `replication_host`, `publication_device`, `admin_ip`), публикация
(`provider`, `params`), репликация (`port`, `user`, `secret_ref`), `settings`. Хранится каноническими байтами
`payload_blob` и их SHA-256 `payload_hash`; одинаковый `payload_hash` на обоих узлах и есть «одна
конфигурация».

Рабочую конфигурацию manager берёт **только** из `payload_blob`: хеш от самих байтов → сверка с
`payload_hash` → разбор → конец данных → сверка с каноническим видом (`config_payload_hash_mismatch`,
`config_payload_not_canonical`). Таблицы `ha_nodes`/… — витрина; расхождение — `config_projection_drift` в
`ha_healthy`.

Источник репликации — свойство узла: STANDBY подключается к `replication_host` узла, который доказанно ACTIVE
(`observe.ExpectedReplicationSource`; тот же адрес используют планировщик, health и план).

Ревизия 1 создаётся при создании пары (§14.6).

### 7.2 Проведение ревизии

Только на ACTIVE (панель: `PUT /ha/config`, `PUT /ha/publication`); номер назначает manager (текущий + 1):

```
1. stage локально
2. config_stage → сосед сохраняет те же байты как STAGED
3. commit локально: доказательство committed_config в safety (fsync) → STAGED→EFFECTIVE
4. config_commit → сосед: доказательство → EFFECTIVE
```

Сосед недоступен на шаге 2 — ревизия не применяется нигде. Потерян шаг 4 — ACTIVE на новой ревизии, сосед в
`STAGED`: `config_agreement` в `ha_healthy` краснеет (`config_commit_unsynced`), повтор проведения доводит.

### 7.3 Правила

- Инициирует только ACTIVE; на STANDBY конфигурация только для чтения.
- Плановое переключение и пересев требуют одинакового отпечатка на обеих сторонах; подтверждение соседа для
  повышения (§8.3) — тоже.
- Валидация содержимого — на обеих сторонах до сохранения.

### 7.4 Параметры канала неизменяемы

Ревизия, меняющая `peer_listen_host`/`peer_listen_port`, отвергается
(`config_transport_change_requires_rotation`): при асимметричном применении канал рвётся, и дослать commit
становится нечем. Ротации нет; смена адреса канала — пересборка пары.

### 7.5 Порядок фиксации и восстановление

На узле: проверить STAGED (хеш, байты) → доказательство в safety (temp → fsync → rename → fsync каталога) →
`STAGED→EFFECTIVE` и отметка запроса `DONE` одной транзакцией. На каждом старте, до чтения эффективной
ревизии, `recoverConfigCommit` сверяет доказательство с базой: `EFFECTIVE` с тем же хешем — ничего;
`STAGED` с тем же хешем — фиксация достраивается; иначе — сообщение в лог, молча не чинится.

---

## 8. Непрерывная сходимость

Каждые 3 с:

```
ensure     поднять то, что ещё не поднято: peer-канал, журнал операций, достроить сопряжение/фиксацию
operation  есть ли у узла текущая операция (журнал недоступен → считается, что есть)
observe    агент (status, preflight), dns_ha, safety.json, репликация, my_print_defaults, status соседа
health     service_ready / ha_healthy (§12)
plan       planner.Plan(observation) → решение; shadow.Build → точный список команд агента
execute    если идёт операция — её шаг (§9–11); иначе — план сходимости
publish    статус в сокет и соседу; при смене «ACTIVE и нет операции» — разбудить dns-sync-worker
```

Планировщик работает на сырой observation, не на вердикте health. dns-sync-worker будится датаграммой в
`/run/dns-panel/sync/wake.sock`; нет воркера — не ошибка.

### 8.1 Установившееся состояние — NOOP

Команда агенту выдаётся только когда наблюдение доказало расхождение желаемого и фактического; идемпотентность
агента — вторая линия, а не повод вызывать вхолостую. Каждая попытка сходимости — новый `operation_id`
(`conv-<epoch>-<ns>`): со старым агент ответил бы `noop` из done-set.

### 8.2 Решения

Правила по порядку, первое сработавшее решает (`internal/planner`):

| # | условие | действие / причина |
|---|---|---|
| 0 | агент не отвечает / `read_only` не наблюдается | `hold` / `agent_unavailable` |
| 0.1 | HA не настроен (нет ревизий) | `restore_active` или `noop` / `ha_not_configured` |
| 1 | узел огорожен (по своему safety или по соседу) | `demote_safe` (если writable/опубликован) или `hold` / `fenced_self` |
| 2 | у соседа epoch больше | `demote_safe` или `hold` / `peer_newer_epoch` |
| 3–4 | writable или опубликован без действующего права | `demote_safe` / `no_active_authority`, `standby_physically_writable` |
| 5 | право есть, writable, NOTIFY, публикация, `secondary` | `noop` / `steady_active` |
| 6 | право есть, writable, но PowerDNS/публикация не подтверждены | `restore_active` / `active_services_degraded` |
| 7 | право есть, но узел read-only (физика потеряна) | `promote` только по §8.3, иначе `hold` |
| 8 | STANDBY, репликация нездорова | `rejoin` к подтверждённому ACTIVE, иначе `hold` / `replication_broken`, `peer_unconfirmed` |
| 9 | STANDBY с NOTIFY или `secondary=yes` | `quiet_standby` (`disable_notifier`) |
| — | иначе | `noop` / `steady_standby` (или `hold` / `role_unknown`, если право не прочитано) |

Планы:
- `demote_safe` — `disable_notifier`, `withdraw_panel`, `demote`: всегда все три, независимо друг от друга;
- `promote` — `promote`, `enable_notifier`, `announce_panel` до первой неудачи; откат — `withdraw_panel`,
  `disable_notifier`, `demote` под отдельным `operation_id` (`…-rollback`);
- `restore_active` — только недостающее (для `ha_not_configured` — ещё `promote`, без публикации);
- `rejoin` — `rejoin_replica` к источнику из §7.1.

Исполнитель (`internal/execute`) ничего не решает: защитные шаги выполняет все, повышающие обрывает на первой
неудаче или на ответе без доказанного состояния (повтор из done-set) и откатывает; исход `needs_reobserve`.

### 8.3 «Остаться ACTIVE» ≠ «стать ACTIVE»

- **Остаться.** Право `valid_current` и узел физически ACTIVE — работает дальше; недоступность соседа роли не
  меняет (только `ha_healthy=false`).
- **Стать** (право есть, но `read_only=1`, например после рестарта MariaDB) — нужно ещё одно из:
  - handoff-право во время его собственной операции (приём роли при плановом переключении);
  - свежее подтверждение соседа: снимок ≤ 30 с, сосед считает себя STANDBY и физически standby
    (`read_only=1`, NOTIFY и публикация явно выключены), тот же epoch, та же конфигурация, никто не огорожен,
    у соседа нет операции.

  Без этого — `hold`: пока узел лежал, пара могла уйти на новый epoch аварийно.
- **STANDBY** без соседа остаётся STANDBY и сам не повышается; `rejoin` — только к подтверждённому ACTIVE.

---

## 9. Плановое переключение

Запуск на ACTIVE: панель `POST /ha/switchover {target?}` или
`sudo -u dns-ha dns-ha-manager -switchover [-to <node>]`. Создаётся операция `sw-<node>-<epoch>[-tryN]`
(`PENDING`), новый epoch = `max_seen_epoch + 1`. Одновременно у узла — одна операция. Ведёт **source**.

| шаг | что |
|---|---|
| `preflight_local` | я ACTIVE с правом, не огорожен, epoch операции = мой + 1, preflight агента ок, сосед наблюдается свежим, конфигурации совпадают |
| `preflight_peer` | `prepare_switchover`: target не ACTIVE, не огорожен, epoch новее, тот же отпечаток конфигурации, агент и preflight ок, репликация `IO=Yes SQL=Yes`, есть интерфейс для сервисного адреса |
| `disable_notifier`, `withdraw_panel`, `demote` | source перестаёт быть источником зон, снимает публикацию, `read_only=1`; затем ожидание наблюдения `read_only=1` |
| `drain_gtid` | `await_gtid`: target выполняет `MASTER_GTID_WAIT(<GTID source>, 60)`; пустая позиция (пустой binlog) — нечего ждать |
| `handoff_record` | **точка невозврата**: в safety source одной записью — новый epoch, след передачи, собственное право снято |
| `handoff_deliver` | `handoff_certificate`: target принимает право (§3.2) и открывает у себя операцию |
| (ожидание) | сосед `role=active` и `service_ready` |
| `rejoin_replica` | source подключается репликой к новому ACTIVE с позиции своего binlog (`seed_from_binlog`) |
| `verify` | у себя `read_only=1`, `IO/SQL=Yes`; сосед ACTIVE и `service_ready` |

Target повышается своей сходимостью (§8.3: handoff во время операции → `promote`, `enable_notifier`,
`announce_panel`) и закрывает свою запись операции, когда физически стал ACTIVE.

Отказы:
- до `handoff_record` — `ABORTED`; команды агенту шли в текущем epoch, право не тронуто, сходимость
  возвращает службы;
- после — операция остаётся `RUNNING` с причиной и повторяется каждым циклом (все шаги идемпотентны).

Пока идёт операция, `service_ready=false` (проба закрыта), write-gate панели отвечает `409 writes_frozen`.

---

## 10. Аварийное повышение и пересев

### 10.1 Аварийное повышение

На выжившем узле: панель `POST /ha/emergency {ack, accept_relay_loss?}` (право `ha.emergency`) или
`sudo -u dns-ha dns-ha-manager -emergency -ack <основание> -operator <кто> [-accept-relay-loss]`.
Автоматически не происходит никогда.

Основания (`ack`): `old_active_database_stopped` | `old_active_host_down` | `operator_isolated`.

| шаг | что |
|---|---|
| `preflight_local` | основание из списка, автор указан, узел не ACTIVE, epoch операции = мой + 1, сам не огорожен, агент доступен; отказ, если сосед отвечает свежим снимком, считает себя ACTIVE **и** `service_ready` (это плановое переключение) |
| `fence_record` | **точка невозврата**: в safety — новый epoch, право `emergency`, `fenced_node` = прежний ACTIVE, запись основания и автора |
| `relay_loss_accepted` | только с `accept_relay_loss`: согласие на потерю записывается до опасного шага |
| `emergency_promote` | агент под одним локом: `STOP SLAVE IO_THREAD` → дождаться применения relay log SQL-потоком → `STOP SLAVE` (строго `No/No`) → `read_only=0`. Дренаж не доказан → отказ, если нет `accept_relay_loss` |
| `enable_notifier`, `announce_panel` | NOTIFY и публикация |
| `verify` | узел физически ACTIVE и с правом |

Отказ до `fence_record` — `ABORTED`, после — `FAILED` без отката (продолжение — `resume`, §10.3).

Огороженный узел (`RESEED_REQUIRED`) видит `fenced_node` у соседа: сам не повышается и не подключается
репликой; если writable/опубликован — уходит в безопасное состояние (§8.2, правило 1).

Автоматической сверки SOA serial нет. Если с `accept_relay_loss` потеряны правки, уже ушедшие на secondary,
serial зоны в новой базе может оказаться не выше опубликованного — такие зоны надо проверить вручную.

### 10.2 Пересев

На огороженном узле: панель `POST /ha/reseed` (`ha.emergency`) или `sudo -u dns-ha dns-ha-manager -reseed`.
Epoch не меняется.

| шаг | что |
|---|---|
| `preflight_local` | узел не ACTIVE, агент доступен, сосед наблюдается свежим и ACTIVE, epoch операции = epoch соседа, конфигурации совпадают |
| `accept_epoch` | принять epoch пары, стереть у себя право и handoff |
| `reseed_replica` | агент: полный дамп `dns_panel` и `pdns` с ACTIVE (учётка `ha_monitor`), затем репликация; `dns_ha` не трогается |
| `verify` | `read_only=1`, `IO/SQL=Yes`, источник — ожидаемый |
| `unfence` | `clear_fencing` на ACTIVE: снимает огораживание только ACTIVE, и только если видит узел свежим и read-only |

### 10.3 Возобновление

`POST /ha/operations/:id/resume {accept_relay_loss?}` или `dns-ha-manager -resume -id <id> [-accept-relay-loss]`:
операция `FAILED`/`ABORTED` снова `RUNNING`, если она принадлежит узлу, её epoch равен текущему или
следующему и другой операции нет. Выполненные шаги пропускаются по журналу. Роспуск не возобновляется
никогда. Журнал и шаги: `dns-ha-manager -operation [-id <id>]`, панель `GET /ha/operations[/:id]`.

---

## 11. Роспуск пары

Только на ACTIVE, только из панели: `POST /ha/dismantle` (`ha.emergency`, требуется ввести фразу
подтверждения). Итог — «Paired · HA not configured»: данные на обоих узлах остаются, доверие остаётся, epoch
не меняется.

| шаг | что |
|---|---|
| `preflight` | я ACTIVE, сосед доступен и STANDBY, других операций нет |
| `freeze_writes` | `demote`: я перестаю принимать запись |
| `drain_gtid` | сосед применил всё записанное мной |
| `peer_release` | `release_pair`: сосед останавливает репликацию, снимает fail-safe, становится writable, снимает адрес, удаляет записи пары |
| `local_release` | у себя: сброс конфигурации реплики, снятие fail-safe и публикации, снова writable |
| `verify` | HA выключен на обоих и оба writable |
| очистка | записи пары и журнал на своём узле (не журналируется) |

Отказ до `peer_release` — отмена с возвратом записи; начиная с `peer_release` — только вперёд (повтор каждым
циклом).

---

## 12. Health: `service_ready` и `ha_healthy`

Два независимых вердикта (`internal/health`). `service_ready` — можно ли слать на узел трафик (им
открывается проба, §14.2); `ha_healthy` — исправен ли контур пары (панель, алерты). Проблемы избыточности
(сосед, конфигурация, prerequisites) `service_ready` не красят. `unknown` везде считается неуспехом.

### 12.1 `service_ready`

Проверки: `agent`, `writable`, `pdns_primary`, `pdns_secondary` (на ACTIVE; агент без поля — не красит),
`published`, `service_address` (anycast: на сервисном адресе принимает TCP/53), `not_frozen` (нет операции),
`role_vs_physics`, `active_authority`. STANDBY — `service_ready=false` по определению. Поверх manager
закрывает готовность, если идёт операция или журнал операций недоступен, и если проба anycast не открылась
(`readiness_probe`).

### 12.2 `ha_healthy`

`mysql_prerequisites`, `store` (`dns_ha` доступна, схема полна, конфигурация прочитана), `safety_store`,
`peer_reachable`, `peer_epoch`, `safety_epoch_consistency`, `peer_observation_fresh` (≤ 30 с),
`config_agreement`, `config_projection`, `agent_preflight`, `replication` (ACTIVE не реплицирует; STANDBY
`IO/SQL=Yes` с ожидаемого источника), `fenced_node`, `anycast_address` (старый anycast-адрес ещё на `lo`),
`pdns_role` (ACTIVE и узел без HA — `yes/yes`, STANDBY — `no/no`), `agent`.

### 12.3 Prerequisites MariaDB

Проверяется сохранённая конфигурация (`my_print_defaults mysqld`, не runtime: `skip-slave-start` не
системная переменная, а runtime `read_only` на ACTIVE ничего не говорит о следующем старте):

| опция | требуется |
|---|---|
| `read_only` | `ON` |
| `skip-slave-start` | `ON` |
| `gtid_strict_mode` | `ON` |
| `binlog_format` | `ROW` |
| `log_slave_updates` | `ON` |
| `binlog-ignore-db`, `replicate-ignore-db` | среди значений `dns_ha` (только когда схема `dns_ha` создана) |

Расхождение — `mysql_prerequisite_drift: <опция>: want …, got …` в `ha_healthy`; трафик с узла не снимает.

---

## 13. Панель и управляющий сокет

Панель — тонкий фасад: HA-логики в ней нет, решения и отказы по существу — у manager'а.

**Сокет** `/run/dns-panel/ha/manager.sock`: одна JSON-строка запроса, одна строка ответа
(`{ok:true, result}` / `{ok:false, error, message}`); пустой запрос = `status`. Команды: `status`, `config`,
`config_apply`, `publication_apply`, `operations`, `operation`, `switchover`, `emergency`, `reseed`,
`dismantle`, `resume`, `pair_status`, `pair_inventory`, `pair_devices`, `pair_create`, `pair_join`,
`pair_approve`, `pair_reject`, `pair_reset`, `pair_build`. Дедлайн: `pair_build` 15 мин; `pair_join`,
`pair_approve`, `pair_reset`, `pair_inventory`, `publication_apply` 2 мин; остальные 30 с.

```bash
echo '{"cmd":"status"}' | sudo -u dns-ha nc -U /run/dns-panel/ha/manager.sock
```

`status`: вердикт health (`role`, `service_ready`, `ha_healthy`, `reason`, `service_checks`, `ha_checks`),
`decision`, `would_execute`, `execution` (`mutations_attempted`, `outcome`, `operation`), `pair` (карточки
`self`/`peer`, публикация, `config_revision`/`config_hash`, `ha_configured` — `true`/`false`/`null`,
`fenced_node`, `authority`, репликация), `probe` (только anycast).

**REST** (`www/API/Router.pm`, через `ha_manager_request` в `functions.pm`):

| маршрут | право |
|---|---|
| `GET /ha/status`, `GET /ha/config`, `GET /ha/operations`, `GET /ha/operations/:id` | `ha.manage` |
| `PUT /ha/config`, `PUT /ha/publication`, `PUT /ha/pair-address` | `ha.manage` |
| `POST /ha/switchover` | `ha.manage` |
| `POST /ha/emergency`, `POST /ha/reseed`, `POST /ha/dismantle` | `ha.emergency` |
| `POST /ha/operations/:id/resume` | по типу операции: emergency/reseed/dismantle или неизвестный тип, а также `accept_relay_loss` — `ha.emergency`; иначе `ha.manage` |
| `GET /ha/pair`, `/ha/pair/inventory`, `/ha/pair/devices`; `POST /ha/pair/{create,join,approve,reject,reset,build}` | `ha.manage` |

Намерения отвечают `202` с `operation_id`, отказ manager'а — `409`, manager недоступен — `503`; всё пишется в
аудит с автором (`requested_by`). `accept_relay_loss` принимается только JSON-boolean. Write-gate и его
исключения для этих маршрутов — [22 §6](22-ha-contract.md#6-write-gate-панели).

UI — страница High availability (`www/js/ha.js`): сопряжение, создание пары, состояние обоих узлов,
операции, настройки публикации.

---

## 14. Узел: публикация, раскладка, сопряжение, создание пары

### 14.1 Публикация сервисного адреса

Провайдер и адрес — в ревизии (`publication.provider`, `publication.params`); интерфейс у каждого узла свой
(`publication_device` в строке узла, узел определяет его сам по адресу/маршруту).

| провайдер | «опубликован» = | снятие |
|---|---|---|
| `floating_ip` | адрес поднят на интерфейсе (истина — `ip -o addr show`, не код возврата); после подъёма — три gratuitous ARP | адрес снимается; не удалось снять — ошибка (два владельца адреса недопустимы) |
| `anycast` | проба готовности открыта (§14.2); `/32` постоянно на `lo` обоих узлов | адрес не снимается: и `announce_panel`, и `withdraw_panel` держат его поднятым, меняется только marker |
| `marker` | адресом распоряжается внешний механизм (BGP-демон, балансировщик); агент ведёт только marker намерения | — |

Юнит агента разрешает `AF_NETLINK` (`ip addr`) и `AF_PACKET` (ARP).

### 14.2 Anycast: проба готовности

TCP-порт пробы (`probe_port` в `publication.params`, ≥ 1024; подсказка в UI — 17900) держит сам manager
(`internal/probe`): порт открыт ровно при `service_ready`. Протокола внутри нет — только рукопожатие.

```
ACTIVE + service_ready     открыт
ACTIVE degraded, операция  закрыт
STANDBY                    закрыт
manager умер               закрыт (сокет уходит вместе с процессом)
```

Куда вести маршрут, решает внешняя сеть по пробе: Cisco IP SLA `tcp-connect` + track, BGP или
[dns-watcher](INSTALL/reference/07-dns-watcher.md). Панель маршрутизацию не знает и показывает только
`TCP <порт> open`. Фактически открытый порт отдаётся в `probe.open_port` и соседу.

### 14.3 Смена адреса и порта на живой паре

`PUT /ha/publication` (`publication_apply`): проверка ресурсов на обоих узлах и новая ревизия (§7.2). Новый
порт узлы открывают своей сходимостью; старый anycast-адрес каждый узел снимает сам (`drop_address`), пока он
висит — `anycast_address` в `ha_healthy`.

### 14.4 Раскладка

```
/opt/dns-panel/
├── bin/    dns-ha-manager, dns-ha-agent, dns-agent, dns-sync-worker, dns-watcher, sync-task.pl, утилиты
├── etc/    panel.toml, ha.toml, ha-agent.toml, secrets/, mariadb/, systemd/, tmpfiles/
├── var/    safety.json, agent-state.json — только то, что обязано читаться без базы
├── www/    web-приложение (/var/www/vhost/dns-panel → сюда)
└── docs/

/run/dns-panel/               tmpfiles.d (etc/tmpfiles/dns-panel.conf)
├── ha/     root:dns-ha 0770      manager.sock, agent.sock, agent.lock, safety.lock
├── pdns/   pdns:www-data 2750    сокет dns-agent
└── sync/   www-data:dns-ha 2750  wake-сокет dns-sync-worker
```

Каталоги в `/run` делятся по границе привилегий и создаются tmpfiles с фиксированным владельцем (не
`RuntimeDirectory=`: каталог общий для процессов под разными пользователями). У manager'а
`ProtectSystem=strict`, поэтому `ReadWritePaths=/opt/dns-panel/var /run/dns-panel/ha` обязателен: без него
он не зафиксирует epoch и право.

### 14.5 Сопряжение

CLI (то же делает панель через сокет; попытка живёт в памяти работающего manager'а):

```bash
dns-ha-manager -pair create                    # A: окно на 10 минут
dns-ha-manager -pair join -address <A>[:port]  # B: печатает шесть цифр
dns-ha-manager -pair status                    # A: код, node_id соседа, заявленный hostname, наблюдаемый адрес
dns-ha-manager -pair approve                   # A: цифры совпали
dns-ha-manager -pair reject | -pair reset [-force]
```

- Без открытого окна команды сопряжения отвергаются; одновременно принимается один запрос (`pairing_busy`).
  Узел, у которого уже есть доверие или `peer.key`, не сопрягается.
- `pair_hello` (обязательство отвечающей стороны A) → `pair_request` (раскрытие эфемерных X25519-ключей) →
  обе стороны считают шестизначный код от стенограммы. Обязательство не даёт подобрать ключ под код.
- `pair_commit` (после Approve; подписан сессионным ключом `HKDF(…, "dns-panel pairing session v1")`, с
  направлением) → каждая сторона сама выводит `peer.key = HKDF(X25519-секрет + стенограмма, "dns-panel peer
  key v1")`; по сети ключ не передаётся. Порядок: запись `ha_trusted_peer` (`committing`) → агент
  `install_peer_key`.
- `pair_complete` (подписан `peer.key`, идемпотентен) → `trusted`.
- До Approve ничего не пишется; перезапуск закрывает окно. Прерванное сопряжение не восстанавливается, а
  сбрасывается (`-pair reset`: `remove_peer_key` по отпечатку, затем запись) и повторяется.
- Код связывает ключи и идентичности сторон, но не показанный рядом hostname. Управляющая сеть считается
  доверенной.

### 14.6 Создание пары

```bash
dns-ha-manager -pair inventory     # что есть в базах обоих узлов
dns-ha-manager -pair build -provider floating_ip|anycast|marker [-address <CIDR>] [-probe-port N] [-id <id>]
```

Выполняется на **доноре** — узле, чьи данные остаются; данные приёмника заменяются, слияния нет. Шаги
(`internal/pairsetup`):

| # | что | донор / приёмник |
|---|---|---|
| 0 | проверка решений человека (провайдер, адрес, порт), «HA здесь ещё не настроен», свободны ли порт и адрес на обоих | ничего не меняется |
| 1 | `repl.secret`, `ha_monitor.secret`: значения донора (нет — создаются) | донор |
| 2 | `init_prepare`: секреты (зашифрованы), гранты для донора; приёмник сообщает свой интерфейс | приёмник |
| 3 | гранты для приёмника (до старта репликации) | донор |
| 4 | ревизия 1 собирается и валидируется | — |
| 5 | `init_reseed`: `ReseedReplica(донор)` с проверкой `IO/SQL=Yes` и позиции | приёмник, **необратимо** |
| 6 | `init_finish`: `auth-master.key` донора | приёмник |
| 7 | `init_seed`: fail-safe + ревизия 1, epoch 1 → STANDBY | приёмник |
| 8 | fail-safe + ревизия 1 + право `bootstrap`, epoch 1 → ACTIVE; публикация — сходимостью | донор |

До шага 5 оба узла остаются работающими одиночными. Повтор прерванной попытки — та же команда с `-id`:
пересев повторно не выполняется, наполовину созданная пара достраивается тем же содержимым.

Standalone-установка сразу HA-ready (`deploy/install.sh` + `etc/mariadb/dns-panel.example.cnf`: binlog, ROW, GTID strict,
`log_slave_updates`, `*-ignore-db = dns_ha`, случайный `server_id`), поэтому создание пары не правит `my.cnf` и
не перезапускает MariaDB: fail-safe добавляется отдельным файлом, текущий `read_only` выставляет агент.
