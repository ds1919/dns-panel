# 03 — Схема БД

Задействованы **две независимые базы**:

1. **БД панели** `dns_panel` — своя. Схема: `docs/INSTALL/schema.sql`.
2. **БД PowerDNS** `pdns` (`gmysql` backend) — то, чем управляем. Схема стандартная от PowerDNS;
   здесь описано, **что из неё используем**.

---

## A. БД панели (`docs/INSTALL/schema.sql`)

Записи зон здесь не хранятся — только то, чего у PowerDNS нет: пользователи и права, инвентарь раздачи,
настройки зон панели, наблюдение, перенос. Ссылки на зону — логические (`domain_id`/`zone_id` →
`pdns.domains.id`, без FK между базами). HA-роли сюда не входят: они в локальной нереплицируемой `dns_ha`
([23-ha-manager.md](23-ha-manager.md)).

| Группа | Таблицы | Подробно |
|--------|---------|----------|
| Идентичность и вход | `users`, `auth_identities`, `password_credentials`, `totp_credentials`, `recovery_codes`, `sessions`, `auth_throttle` | [08-auth.md](08-auth.md) |
| Внешний доступ | `api_tokens` | [11-api.md](11-api.md) |
| Права | `groups`, `user_groups`, `zone_access`, `capability_grants` | [20-permissions.md](20-permissions.md) |
| Настройки панели | `settings` (только изменённые ключи; дефолты в коде) | |
| Журнал | `audit_log` | [15-audit-log.md](15-audit-log.md) |
| Инвентарь раздачи | `tsig_keys`, `ip_groups`, `ip_group_members`, `secondary_groups`, `secondary_nodes`, `secondary_group_members`, `secondary_node_endpoints`, `secondary_group_ip_groups`, `secondary_group_tsig_keys`, `secondary_node_tsig_keys` | [16-delivery.md](16-delivery.md) |
| Раздача зон | `catalogs`, `catalog_groups`, `catalog_nodes`, `catalog_primary_endpoints`, `catalog_subscriptions`, `zone_direct_axfr` | [16-delivery.md](16-delivery.md) |
| Динамические обновления | `dyn_profiles`, `dyn_profile_sources`, `dyn_profile_keys`, `zone_dynamic`, `zone_dynamic_sources`, `zone_dynamic_keys` | [05-dns-model.md](05-dns-model.md) |
| Профили и метки зон | `zone_profiles`, `zone_profile_nameservers`, `label_categories`, `label_values`, `zone_labels` | [05-dns-model.md](05-dns-model.md) |
| Состояние синхронизации | `zone_sync_state` (`pdns_state`/`notify_state`, попытки, `next_retry_at`) | [02-architecture.md](02-architecture.md) |
| Наблюдение | `probe_policies`, `record_health`, `zone_lifecycle`, `monitoring_sources` | |
| NS Pulse | `pulse_*` | [25-ns-pulse.md](25-ns-pulse.md) |
| Перенос со старого BIND | `import_sources`, `import_zones` | [26-zone-import.md](26-zone-import.md) |

Несколько правил схемы, которые важно знать:

- **`auth_identities`** — только внешние методы (`cert`/`oauth`). `provider`/`principal` NOT NULL, иначе
  UNIQUE(`type`,`provider`,`principal`) не уникализировал бы NULL и один CN можно было бы привязать двоим.
  «Один пароль / один TOTP на пользователя» — `PRIMARY KEY(user_id)` в `password_credentials`/`totp_credentials`.
- **`sessions.token`** — hex SHA-256 токена из cookie, сам токен не хранится. logout — `is_active=0`.
- **`tsig_keys`** неизменяемы (имя/алгоритм/секрет задаются при создании); секрет в `audit_log` не пишется.
- **Защита от удаления** используемого объекта — FK RESTRICT, а не только предварительный COUNT.

---

## B. БД PowerDNS (gmysql)

Панель пишет в `domains`, `records`, `domainmetadata` напрямую (SQL) и читает `tsigkeys`/`cryptokeys`;
TSIG-ключи и DNSSEC-ключи заводятся через HTTP API PowerDNS. `comments` только чистится при удалении зоны,
`supermasters` не используется. Почему так — [24-dns-engine.md](24-dns-engine.md).

### `domains` — зоны

| Поле | Назначение |
|------|-----------|
| `id` | ID зоны (URL панели `?zone=<id>`, ссылки из БД панели) |
| `name` | имя зоны, без завершающей точки |
| `type` | `MASTER` / `SLAVE` / `NATIVE` (+ `PRODUCER` у каталогов) — см. [05-dns-model.md](05-dns-model.md) |
| `master` | для `SLAVE`: адреса primary через `,` |
| `last_check` | для `SLAVE`: когда PowerDNS последний раз сверился с primary; смена источника обнуляет |
| `notified_serial` | serial последнего разосланного NOTIFY, **не** текущий SOA serial |
| `catalog` | членство в каталоге — единственный источник истины ([16-delivery.md](16-delivery.md)) |
| `account` | не используем: свои пометки — в `X-DNSPANEL-*` metadata |

Serial в UI — третье поле SOA-записи (`soa_serial` в `pdns_list_domains`/`pdns_get_domain`), не `notified_serial`.

### `records` — записи зон

Стандартные поля (`domain_id`, `name`, `type`, `content`, `ttl`, `prio`, `disabled`) плюс два поля панели,
добавляемые при установке (`docs/INSTALL/reference/03-powerdns.md`): `updated_by`, `updated_at` — кто и когда
менял запись. PowerDNS перечисляет колонки явно, лишние ему не мешают.

Список записей (`pdns_list_records`) и счётчики не показывают empty non-terminals (строки без `type`) и
данные подписи (`RRSIG`, `NSEC`, `NSEC3`, `NSEC3PARAM`, `DNSKEY`, `CDS`, `CDNSKEY`, `TYPE65534`).

SOA `content`: `primary hostmaster serial refresh retry expire minimum`. Serial поднимается один раз на
транзакцию внутри `pdns_apply_rrsets` (`_lock_soa` → `_bump_soa_row`, под `SELECT … FOR UPDATE`).

### `domainmetadata` — метаданные зон

| kind | Кто ставит и зачем |
|------|-------------------|
| `ALLOW-AXFR-FROM`, `TSIG-ALLOW-AXFR`, `ALSO-NOTIFY` | раздача вниз, одним расчётом ([16-delivery.md](16-delivery.md)) |
| `SLAVE-RENOTIFY` | secondary-зона в раздаче: NOTIFY вниз после приёма |
| `AXFR-MASTER-TSIG` | ключ, которым secondary-зона забирает AXFR у primary |
| `ALLOW-DNSUPDATE-FROM`, `TSIG-ALLOW-DNSUPDATE`, `NOTIFY-DNSUPDATE` | динамические обновления ([05-dns-model.md](05-dns-model.md)) |
| `PRESIGNED`, `NSEC3PARAM` | DNSSEC; `PRESIGNED` у перенесённых подписанных зон снимается при Make primary |
| `X-DNSPANEL-POLICY` | метка «политику раздачи поставила панель» |
| `X-DNSPANEL-PROFILE` | код профиля зоны |
| `X-DNSPANEL-IMPORT`, `-IMPORT-DYNAMIC`, `-IMPORT-DNSSEC` | пометки переноса со старого BIND ([26-zone-import.md](26-zone-import.md)) |

Свои пометки — в `X-DNSPANEL-*` (PowerDNS разрешает приложениям metadata с префиксом `X-`), а не в
`domains.account` — свободном поле, которое легко конфликтует с другими инструментами.

### Чего НЕ делаем

- Не заводим собственных таблиц-дублёров зон/записей поверх PowerDNS.
- Не тащим мультитенантность, внешних провайдеров и историю версий записей без явной необходимости.
