# 20 — Права доступа (модель)

Права **внутри DNS-панели** (не отдельная IAM-система). Два вида:

- **доступ к зоне** — `No access · Read only · Write` (`none|read|write`);
- **панельные права (capabilities)** — действия над самими зонами и инфраструктурой.

Права = членство в группах + личные правила. Ролей нет.

## Доступ к зоне

**`Write` на зону = полное владение её содержимым:**
- любые RRset (A/AAAA/CNAME/MX/TXT/SRV/PTR/…), создание и удаление имён внутри зоны;
- apex `SOA` и `NS`, дочерние делегации (`NS`, `DS`);
- метки зоны, Retry sync, повторный AXFR secondary-зоны;
- история (audit) зоны.

`Read only` — просмотр. `No access` — зона не видна: её нет в списках и поиске, прямое обращение → 404
(существование не раскрывается).

**Не входит в zone-Write** — это панельные права: создание/удаление зоны, смена роли (promote/demote),
профиль, DNSSEC, динамические обновления, раздача (Direct AXFR, каталог), права, HA.

### Область правила (scope)

```
all   — все зоны (default субъекта)
zone  — конкретная зона
```

### Как складываются правила

Для (пользователь, зона):
1. **Каждая группа** считает свой доступ: внутри группы `zone` важнее `all`.
2. **Группы складываются по максимуму** (`none < read < write`): группа только добавляет, узкое правило одной
   группы не сужает широкое правило другой.
3. **Личное правило** сравнивается с результатом групп **по специфичности**: более точный уровень побеждает,
   при равенстве — личное.

```
Группа A:       all  Read only ;  itos.corp  Write
Пользователь:   all  No access ;  project.corp  Write

→ project.corp : личное zone-правило — Write
→ itos.corp    : zone-правило группы точнее личного all → Write
→ прочие зоны  : группа all=read и личное all=none одного уровня → личное → No access
```

Producer-зоны каталогов всегда `none` (управляются как каталоги на странице Propagation). Если правила не
удалось прочитать целиком, доступ `none` ко всему.

## Панельные права (capabilities)

Список — `@functions::CAPABILITIES` (он же ENUM `capability_grants.capability`):

```
zones.manage          создание/удаление зоны, роль, профиль, DNSSEC, dynamic, reverse, импорт зон, профили зон
labels.manage         справочник меток (категории и значения)
secondary.manage      Servers: узлы, группы, адреса
distribution.manage   Direct AXFR, ключи TSIG, группы разрешённых IP, назначение зоны в каталог
catalog.manage        Catalog: каталоги, их подписчики и назначенные серверы
pulse.manage          NS Pulse: тестеры, проверки, правила (правило пишет DNS без zone-Write)
users.manage          пользователи, группы, права
audit.read            аудит-лог
ha.manage             HA: состояние, конфиг, switchover, создание пары
ha.emergency          аварийный promote, reseed, dismantle
```

Продолжение HA-операции (`resume`) требует того же права, что и её запуск.

Названия на экране (Settings → Users & access) совпадают с вкладками страницы Propagation: `secondary.manage`
= Manage servers, `distribution.manage` = Manage Direct AXFR, `catalog.manage` = Manage catalogs. Страница
Propagation открыта при любом из трёх и показывает только свои вкладки. Чтение инвентаря серверов допускает
`secondary.manage` или `distribution.manage`.

### Группа даёт, личный запрет отнимает

Право есть, если **есть разрешение** (личное или через группу) и **нет личного запрета**
(`capability_grants.effect = allow|deny`):

```
группа «DNS Administrators» → ha.manage        ← даёт всем участникам
пользователь jdoe       → ha.manage: deny  ← у него одного права нет
```

Запреты только личные: у группы «нет права» и «запрет» — одно и то же. На (субъект, право) одна строка —
либо allow, либо deny. Гард «останется хотя бы один активный администратор» (`users.manage`) действует при
снятии права, запрете, выходе из группы и деактивации пользователя.

## Где проверяется

Один слой в `functions.pm`: `build_access_context`/`access_for`/`effective_zone_access` для зон,
`has_capability`/`capability_check` для панельных прав. Его зовут страницы, HTTP API
([11-api.md](11-api.md)) и MCP ([10-mcp.md](10-mcp.md), субъект — `requester`). Отказы и изменения прав
пишутся в [аудит-лог](15-audit-log.md).

## Интерфейс

Settings → Users & access: у пользователя и группы — панельные права (сгруппированы: Zones, Propagation,
NS Pulse, Administration) и таблица доступа к зонам (default + по зонам). У пользователя таблица показывает
доступ от групп (с именем группы), личное правило и итоговый доступ; изменение можно посмотреть заранее
(`POST /dns-api/users/:id/access/preview`).

## Модель данных (в `dns_panel`)

```
groups             id, name, description
user_groups        user_id, group_id                                  -- M:N
zone_access        subject_type(group|user), subject_id,
                   scope(all|zone), zone_id?, access(none|read|write)
capability_grants  subject_type(group|user), subject_id, capability, effect(allow|deny)
```

Личное правило = строка с `subject_type=user`; «наследовать» = отсутствие строки. Схема —
`docs/INSTALL/schema.sql`. Первый администратор (`deploy/bootstrap-admin.pl`) получает группу
«DNS Administrators» со всеми правами и `zone_access all=write`.
