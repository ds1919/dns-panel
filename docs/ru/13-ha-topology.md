# 13 — HA-топология (прод)

Как пара стоит в проде. Базовая схема shadow-master + BIND-слейвы — [02-architecture.md](02-architecture.md);
правила HA — [22-ha-contract.md](22-ha-contract.md); механика — [23-ha-manager.md](23-ha-manager.md); установка —
[INSTALL/02-ha-pair.md](INSTALL/02-ha-pair.md).

## Топология

```
DC1                                       DC2
┌──────────────────────────────┐         ┌──────────────────────────────┐
│ узел A (LXC) — ACTIVE        │         │ узел B (LXC) — STANDBY       │
│ MariaDB        read_only=0   │ ──────▶ │ MariaDB        read_only=1   │
│ PowerDNS       primary+sec.  │ async   │ PowerDNS       primary=no    │
│ панель, MCP, dns-ha-*        │ GTID    │ панель, MCP, dns-ha-*        │
└──────────────┬───────────────┘         └──────────────┬───────────────┘
               │ NOTIFY — только ACTIVE                 │
               └────────── AXFR/IXFR — с обоих ─────────┘
                                   │
                    N × secondary (BIND) в ДЦ и офисах
```

- **Узел** — один LXC: MariaDB, PowerDNS, панель и MCP, `dns-agent`, `dns-sync-worker`, `dns-ha-manager`,
  `dns-ha-agent`. Состав узлов одинаков, различаются они только ролью.
- **MariaDB.** Единственный писатель — ACTIVE; STANDBY — асинхронная GTID-реплика с `read_only=1`.
  Реплицируются `dns_panel` и `pdns`; `dns_ha` у каждого узла своя ([23 §4](23-ha-manager.md#4-хранилище)).
- **Панель, MCP, PowerDNS** каждого узла работают с локальной MariaDB. Запись принимает только ACTIVE
  (write-gate, [22 §6](22-ha-contract.md#6-write-gate-панели)).
- **PowerDNS.** ACTIVE — `primary=yes secondary=yes`: рассылает NOTIFY и сам забирает secondary-зоны.
  STANDBY — `no/no`: оба режима пишут в базу, а она read-only. AXFR отдают оба узла (у STANDBY данные
  приходят репликацией). Роль — только в `90-ha-role.conf`
  ([INSTALL/02 §4](INSTALL/02-ha-pair.md#4-конфигурация-узла)).
- **Secondary** держат unicast-адреса обоих мастеров и тянут зону с любого доступного. Число secondary и кому
  что отдаётся — не часть HA ([16-delivery.md](16-delivery.md)).
- **Сервисный адрес пары** ведёт на текущий ACTIVE; через него работает панель. Адреса узлов — управляющие
  ([22 §7](22-ha-contract.md#7-панель-на-узле-пары)).

## Сервисный адрес в сети

| режим | что нужно от сети |
|---|---|
| `floating_ip` | общий L2-сегмент: `/32` переезжает на новый ACTIVE, соседей оповещает gratuitous ARP |
| `anycast` | `/32` постоянно на `lo` обоих узлов; маршрут на узел с открытой пробой готовности держит внешняя сеть — Cisco IP SLA + track, BGP или [dns-watcher](INSTALL/reference/07-dns-watcher.md) |
| `marker` | адресом управляет внешний механизм (BGP-демон, балансировщик) |

Подробно — [23 §14.1–14.2](23-ha-manager.md#141-публикация-сервисного-адреса).

## Почему один LXC на узел

Нагрузка небольшая; отказ контейнера или ДЦ перекрывает второй узел. Минус один: проблема или обновление
MariaDB одновременно останавливает панель и PowerDNS этого узла. На резолвинг это не влияет — зоны
обслуживают независимые secondary.

## Ресурсы (на узел)

```
2 vCPU · 2–4 GB RAM · 20 GB disk
```

Диск: ОС 4–6 GB · MariaDB + PowerDNS — обычно сотни МБ · панель и демоны < 1 GB · binlog 2–4 GB (с лимитом) ·
журналы 1–2 GB (с лимитом) · резерв 5–8 GB.

Бэкапы — вне этих LXC: потеря контейнера не должна уносить и базу, и её копию.
