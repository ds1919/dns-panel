# INSTALL — installing DNS Panel

Русская версия: [ru/INSTALL/README.md](../ru/INSTALL/README.md)

Ubuntu 24.04 (noble) or 26.04 (resolute), LXC. Perl modules come **from apt**, not CPAN; PowerDNS 5.1 comes from
`repo.powerdns.com`. A node is installed by the package (`apt install ./dns-panel_<version>_amd64.deb`), whose postinst
runs `deploy/install.sh`; from a source checkout the same installer runs through `deploy/deploy.sh`.

| Profile | When | Runbook |
|---------|------|---------|
| **Standalone** | Any node: a single panel and the foundation for a pair. `sh powerdns-repo.sh && apt install ./dns-panel_<version>_amd64.deb` as root on the node (from a checkout: `deploy/deploy.sh <node>`). | [01-standalone.md](01-standalone.md) |
| **HA pair** | Two nodes, active-standby. Assembled from two installed nodes in the panel (High availability → pairing), with no separate installation. | [02-ha-pair.md](02-ha-pair.md) |

The pair's service address (floating IP or anycast) — [02 §6](02-ha-pair.md#6-service-address).

## DB schema

- [`schema.sql`](schema.sql) — the full `dns_panel` schema for a clean installation. An existing database is updated
  by migrations from [`deploy/migrations/`](../../deploy/migrations/README.md) ([01 §5](01-standalone.md#5-updating-the-code)).
  HA tables live in a separate local database `dns_ha`; `dns-ha-manager` applies its schema itself.
  ([reference/02-mariadb.md](reference/02-mariadb.md)).

## Component references

[reference/](reference/): [packages](reference/01-packages.md), [MariaDB](reference/02-mariadb.md),
[PowerDNS](reference/03-powerdns.md), [Apache and panel.toml](reference/04-panel-deploy.md) (+ mTLS),
[dns-agent and dns-sync-worker](reference/05-dns-agent.md), [BIND secondary](reference/06-bind-secondaries.md)
(Catalog Zones), [dns-watcher](reference/07-dns-watcher.md) (anycast pair readiness probe → route, NAT,
BIRD — when there is no Cisco IP SLA).

## Updating already installed code

`apt install ./dns-panel_<new version>_amd64.deb`, on a pair ACTIVE first; the schema is updated by migrations —
[01 §5](01-standalone.md#5-updating-the-code).
