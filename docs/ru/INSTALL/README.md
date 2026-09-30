# INSTALL — установка DNS Panel

English: [../../INSTALL/README.md](../../INSTALL/README.md)

Ubuntu 24.04 (noble) или 26.04 (resolute), LXC. Perl-модули — **из apt**, не CPAN; PowerDNS 5.1 — из
`repo.powerdns.com`. Узел ставится пакетом (`apt install ./dns-panel_<версия>_amd64.deb`), его postinst запускает
`deploy/install.sh`; из исходников тот же установщик запускает `deploy/deploy.sh`.

| Профиль | Когда | Runbook |
|---------|-------|---------|
| **Standalone** | Любой узел: одиночная панель и фундамент для пары. `sh powerdns-repo.sh && apt install ./dns-panel_<версия>_amd64.deb` под root на узле (из исходников — `deploy/deploy.sh <узел>`). | [01-standalone.md](01-standalone.md) |
| **HA-пара** | Два узла, active-standby. Собирается из двух установленных узлов в панели (High availability → pairing), без отдельной установки. | [02-ha-pair.md](02-ha-pair.md) |

Сервисный адрес пары (Floating IP или anycast) — [02 §6](02-ha-pair.md#6-сервисный-адрес).

## Схема БД

- [`schema.sql`](../../INSTALL/schema.sql) — полная схема `dns_panel` для чистой установки. Существующая база обновляется
  миграциями из [`deploy/migrations/`](../../../deploy/migrations/README.md) ([01 §5](01-standalone.md#5-обновление-кода)).
  Таблицы HA — в отдельной локальной БД `dns_ha`, схему применяет сам `dns-ha-manager`.
  ([reference/02-mariadb.md](reference/02-mariadb.md)).

## Справочники компонентов

[reference/](../../INSTALL/reference/): [пакеты](reference/01-packages.md), [MariaDB](reference/02-mariadb.md),
[PowerDNS](reference/03-powerdns.md), [Apache и panel.toml](reference/04-panel-deploy.md) (+ mTLS),
[dns-agent и dns-sync-worker](reference/05-dns-agent.md), [BIND-secondary](reference/06-bind-secondaries.md)
(Catalog Zones), [dns-watcher](reference/07-dns-watcher.md) (проба готовности anycast-пары → маршрут, NAT,
BIRD — когда нет Cisco IP SLA).

## Обновление уже установленного кода

`apt install ./dns-panel_<новая версия>_amd64.deb`, на паре сначала ACTIVE; схема обновляется миграциями —
[01 §5](01-standalone.md#5-обновление-кода).
