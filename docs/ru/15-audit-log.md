# 15 — Аудит-лог

Журнал значимых операций: **кто, когда, что сделал, что было и что стало**. Нужен для разбора инцидентов,
отката по смыслу и подотчётности (в том числе при управлении через ИИ).

## Что логируем

- **Правки DNS:** записи (`add_record`, `replace_rrset`, `delete_record`, `update_soa`), зоны (`create_zone`,
  `delete_zone`, `create_reverse_zones`, смена роли, источник secondary, настройки, метки, DNSSEC, динамические
  обновления), перенос (`import_zones` + `create_zone` на каждую зону) — с **before/after**.
- **Раздача и инвентарь:** серверы, группы, каталоги, TSIG-ключи (секрет не пишется никогда), профили.
- **Пользователи и доступ:** пользователи, группы, права, сертификаты, второй фактор, отзыв сессий.
- **HA-решения человека** (`ha_switchover_create`, `ha_emergency_promote`, pairing, конфигурация) с
  `operation_id`/`request_id`; механика операций живёт в истории HA-менеджера ([23-ha-manager.md](23-ha-manager.md)).
- **Система:** повторы синхронизации worker'ом (`retry_sync`), переключения NS Pulse (`pulse_switch`, `pulse_held`).
- **Отказы прав** — `result=denied` (API: `inventory_access_denied` с нужной capability; MCP — отказ по зоне
  или capability).

Вход (только полный: после пароля и второго фактора, или по сертификату) и выход пишутся как `login`/`logout`
с методом входа и IP; остальной контекст сессии лежит в `sessions`.

## Где пишется

На уровне **вызывающего** (API `API/Router.pm`, MCP `mcp/dns-mcp.pl`, worker), где известен actor, — **не**
внутри `pdns_*` (это чистые операции с данными). Единая точка — `audit_log({...})` в `functions.pm`; API
пишет через `_inv_audit`, который добавляет снимок имени объекта.

## Схема (`docs/INSTALL/schema.sql` → `audit_log`)

В БД панели `dns_panel` (реплицируется вместе с ней). Код панели в таблицу только добавляет строки.

| Поле | Назначение |
|------|-----------|
| `id`, `ts` | автоинкремент, время |
| `actor`, `actor_role` | кто (username/CN; `system`, `pulse` для фоновых) |
| `source` | `api` / `mcp` / `system` / `panel` (ENUM допускает ещё `ha-agent`, `cli`, `emergency-cli`) |
| `via` | как вошёл внешний запрос: `token <имя>` / `oidc <провайдер>` / `anonymous`; пусто для сессии панели и stdio-MCP |
| `action` | технический код действия |
| `target_type`, `target` | тип объекта + идентификатор (id, имя зоны, `name TYPE` у RRset, operation_id) |
| `target_label` | **снимок** читаемого имени объекта на момент события — переживает удаление объекта |
| `before_val`, `after_val` | JSON состояния до/после |
| `result` | `ok` / `denied` / `error` / `partial` |
| `detail` | причина отказа/ошибки |
| `ip`, `request_id` | контекст, корреляция |

## Просмотр

- **Страница Audit log** (capability `audit.read`): фильтры actor / action / result / type / source и поиск по
  target (в том числе по `target_label`), постранично; строка раскрывается в before/after. Коды действий и
  типов показываются словами из одного словаря (`%AUDIT_ACTION_LABELS`, `%AUDIT_TYPE_LABELS`); незнакомый код
  очеловечивается.
- **API:** `GET /dns-api/audit?actor=&action=&result=&target_type=&source=&target=&limit=&offset=` (limit ≤ 500).
- **История у объекта:** записи RRset (`GET /zones/:id/audit?name=&type=`), сервера
  (`GET /secondary/servers/:id/audit`), пользователя (ссылка на Audit log с фильтром actor).
- **Dashboard** — последние события без автоматических `retry_sync` worker'а.

## Ретеншн

Сейчас не ограничен: панель строки не удаляет и во внешнее хранилище не выгружает.
