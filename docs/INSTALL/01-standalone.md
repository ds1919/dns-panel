# 01 — Standalone: one working node from scratch

A node is installed with **one command**. A single installation carries the HA stack from the start (dns-ha-agent and dns-ha-manager
are running, `[ha] enabled = true`), but there is no pair yet: the pair is assembled later, in the panel, from two such nodes —
[02-ha-pair.md](02-ha-pair.md). There is no separate "HA installation".

**Requirements:** Ubuntu 24.04 (noble) or 26.04 (resolute), an LXC container; on any other OS the installer stops.
Internet access to `repo.powerdns.com` (PowerDNS 5.1 is installed from there), root on the node. Go is not needed for
installing: the package carries the built binaries.

## 1. Installation

From the release: `dns-panel_<version>_amd64.deb` and `powerdns-repo.sh`. As root on the node:

```bash
sh powerdns-repo.sh                      # the PowerDNS 5.1 repository (repo.powerdns.com, pinned)
apt install ./dns-panel_1.0.0_amd64.deb
```

apt installs the dependencies (PowerDNS, MariaDB, Apache, Perl modules); the package's postinst runs
`deploy/install.sh --package`, the same installer as below without its apt part.

From a source checkout (developers): `make build` (Go 1.24+), then `deploy/deploy.sh ds@10.0.0.11 [...]` checks all given
nodes at once (ssh, Ubuntu version, sudo or root), copies the tree to `~/dns-panel` on each node (a tar stream over ssh)
and runs the installer there; `make deb` builds the package.

Or on the node itself, from a tree already copied there (`bin/` must contain the built `dns-agent`, `dns-sync-worker`,
`dns-ha-agent`, `dns-ha-manager` — without them the installer stops):

```bash
sudo ~/dns-panel/deploy/install.sh [--admin LOGIN]
```

The installer asks nothing and ends with checks and the first administrator's temporary password:

```
==> checks
  ok    panel.toml parses
  ok    PowerDNS answers
  ok    PowerDNS API
  ok    dns-agent answers
  ok    dns-ha-agent running
  ok    dns-ha-manager running
  ok    dns-sync-worker running
  ok    panel ready (/health/ready)
  ok    config outside web root
==> first administrator
  TEMPORARY PASSWORD (shown once — must be changed at first login): …
DNS Panel is installed: http://10.0.0.11/
```

Then — the browser: `http://<node address>/`, log in with the temporary password, change the password, set up TOTP. Create a test
zone and check `dig @<node address> <zone> SOA` — the end-to-end path panel → dns-agent → PowerDNS.

## 2. What the installer does

In order, and every step is safe to repeat:

| step | what |
|-----|-----|
| packages | the `repo.powerdns.com` repository (`<codename>-auth-51`, key in `/etc/apt/keyrings/powerdns.asc`, pin `pdns-*` 600); Perl modules from apt, Apache with `libapache2-mod-fcgid`, MariaDB, `pdns-server` + `pdns-backend-mysql` — [reference/01-packages.md](reference/01-packages.md). If PowerDNS is not 5.1.x — stop. `pdns-backend-bind` is removed; Apache modules `cgid fcgid rewrite headers env`; the `systemd-resolved` stub is removed from `:53` if it is there |
| users | `dns-ha` (HA manager), `www-data` joins the `dns-ha` group — only to use the HA IPC sockets |
| tree | `/opt/dns-panel/{www,bin,docs,etc,var}`: `www`, `bin`, `docs` are synced in full; in `etc` — only templates, units and what the repository carries; the node's working configs are not touched |
| secrets | `etc/secrets/{panel-db.password,pdns-db.password,pdns-api.key,auth-master.key}` — random, `0640 root:www-data`; there are no pair secrets here, they appear at pairing |
| node configs | `panel.toml`, `dns-agent.toml`, `ha.toml`, `ha-agent.toml` from `*.example.toml` — only if they do not exist yet; `[ha] enabled = true` is turned on in `panel.toml` |
| MariaDB | `etc/mariadb/dns-panel.cnf` (random `server_id`, binlog, GTID — §4) → `/etc/mysql/mariadb.conf.d/60-dns-panel.cnf`; databases `dns_panel`, `pdns`, `dns_ha`; users `dnspanel`, `pdns` (the password is always brought in line with the secret file), `dns-ha` (unix_socket, data — only `dns_ha`); schemas — only into empty databases |
| … on a pair | all of this bypasses the binlog (`sql_log_bin=0`): each node has its own passwords, and an `ALTER USER` that reached the neighbour would cut its panel off from the database, and on STANDBY would produce the replica's "own" GTIDs; on a node with `read_only=ON` (STANDBY) the databases are not touched at all |
| PowerDNS | `etc/powerdns/dns-panel.conf` → `/etc/powerdns/pdns.d/` (written in full every time — §3); `90-ha-role.conf` with `primary=yes secondary=yes` — only if it does not exist (after that HA owns it); a role set anywhere else — stop; restart — only if the config changed or PowerDNS is not running (on ACTIVE this is a pause in DNS) |
| services | tmpfiles `/run/dns-panel/{ha,pdns,pulse,sync}`, units as symlinks from `etc/systemd`: `dns-agent`, `dns-sync-worker`, `dns-ha-agent`, `dns-ha-manager`, `pulse-server` — enable + restart |
| Apache | `/var/www/vhost/dns-panel → /opt/dns-panel/www`, site `dns-panel` from `etc/apache`, `000-default` is disabled — [reference/04-panel-deploy.md](reference/04-panel-deploy.md) |
| administrator | `deploy/bootstrap-admin.pl`, if the database has no users at all |

The working `etc/*.toml`, `etc/secrets/`, `etc/powerdns/`, `etc/mariadb/dns-panel.cnf` are created on the node and are not
part of the repository.

> **DB schema.** `schema.sql` is the full schema for a clean installation: the installer loads it only into an empty database and
> marks all of the release's migrations as applied. An existing database is updated by migrations (§5).

## 3. Why PowerDNS is configured this way

**`local-address=0.0.0.0`** — listen on ALL local addresses rather than listing them.

Listing addresses breaks HA: the pair's service address (floating IP, anycast `/32` on `lo`) appears on the node
LATER than the installation and is changed from the panel. With an explicit list PowerDNS does not listen on it — the address is up, the role is ACTIVE,
the readiness probe is open, and `dig` to the published address answers `connection refused`. With `0.0.0.0` a change of the
service address does not touch the PowerDNS configuration. Interfaces where DNS must not listen are closed by
the firewall.

**The role — `primary` and `secondary` — lives ONLY in `90-ha-role.conf`**, as a pair: a standalone node and ACTIVE —
`yes/yes`, STANDBY — `no/no`. `primary` sends NOTIFY; `secondary` itself checks secondary zones (migration from the
old master, foreign zones) against their primary by SOA refresh and accepts NOTIFY from it; without it such a zone
arrives only while the panel requests the transfer, and then silently freezes. Both write to the database, and the STANDBY database is a
read-only replica, so HA switches them together, with one restart. They must NOT be in `dns-panel.conf`:
PowerDNS reads `pdns.d` in alphabetical order, `dns-panel.conf` comes after `90-ha-role.conf` and would override the role
that HA sets.

**Dynamic updates:** `dnsupdate=yes`, an **empty** `allow-dnsupdate-from`, `forward-dnsupdate=no`
(RFC 2136). Who may send them is set by the panel itself for each dynamic zone, via metadata. The global list
adds up with the zone's list: `0.0.0.0/0` here would open address-based updates to all zones, and the default
(`127.0.0.0/8,::1`) would silently add localhost. Secondary zones are updated by their master, so updates are not
forwarded to it.

**`zone-cache-refresh-interval=300`** — a safety net in the background. The panel writes zones directly into gmysql, and PowerDNS
learns about a new zone through an explicit `rediscover` via dns-agent ([reference/05-dns-agent.md](reference/05-dns-agent.md)),
not by polling the DB.

**`allow-axfr-ips`, `xfr-cycle-interval`, `send-signed-notify` — distribution of zones downstream** ([../16-delivery.md](../16-delivery.md)):

`allow-axfr-ips=127.0.0.0/8,::1` allows AXFR **by address, that is, without TSIG**. Authorization is held by the per-zone
`TSIG-ALLOW-AXFR` that the panel sets, so secondary addresses must NOT be added here: any address
from here bypasses the panel's entire policy. It is checked with one command FROM THE secondary's ADDRESS:
```bash
dig @<powerdns> <any-distributed-zone> AXFR      # without a key it must answer "Transfer failed"
```

`xfr-cycle-interval=5` — how fast consumers learn that a zone appeared in or left the catalog. PowerDNS computes the content of the
PRODUCER zone itself in this cycle; until the cycle runs, the catalog serial stays the same, so a NOTIFY from outside
(including from the panel) carries the old serial and changes nothing. The default of 60 s gives up to a minute of delay. We do not
set it to one: in the same cycle PowerDNS polls the freshness of its secondary zones.

`send-signed-notify=no` — NOTIFY goes out unsigned. Each secondary has its own TSIG key, and PowerDNS
signs a zone's NOTIFY with ONE key (the first one found for the zone) → all the others get `tsig verify failure
(BADKEY)`, and they learn about a new zone only by the catalog's SOA refresh. This does not weaken AXFR: it
still requires the personal key, and BIND accepts an unsigned NOTIFY from its primary.

## 4. MariaDB: a standalone node ready for a pair

`server_id` is random and different on each node, the binlog and GTID are on, `bind-address = 0.0.0.0`, `dns_ha` is excluded
from replication. None of this is dynamic: changing it at pairing time would mean restarting a live database under DNS.
`read_only` and `skip_slave_start` are NOT included here — they are the role's fail-safe, which pair creation puts in a separate file.
Details — [reference/02-mariadb.md](reference/02-mariadb.md).

## 5. Updating the code

`apt install ./dns-panel_<new version>_amd64.deb` (or, from a checkout, the same `deploy/deploy.sh <node>`): code and
templates arrive anew, services are restarted, the node configuration, secrets and data stay.

The database schema is updated by migrations ([deploy/migrations/](../../deploy/migrations/README.md)). As the first step, **before
the code is replaced**, the installer runs the files that are not in `schema_migrations` — only on the writable node
(standalone or ACTIVE); before that — a dump of `dns_panel` into `/opt/dns-panel/var/backup/` (the last five
are kept). If a migration fails, the installation stops, and the node keeps running on the old version and the old
schema. With the package dpkg has already unpacked the new files when postinst runs: a failed migration leaves the
package unconfigured (`apt` reports it), the database is as before plus the dump.

**A pair** — ACTIVE first, then STANDBY (`deploy/deploy.sh <ACTIVE> <STANDBY>` does it in that order):

Migrations run on ACTIVE and reach STANDBY through replication; the manager and the panel are bound by a JSON contract, so
both nodes are updated. Which version and schema a node runs — in `/health/ready`: `version` (the `VERSION` file) and
`schema` (the last migration, `base` — the release's own schema).

## 6. NS Pulse (switching records by host state)

This section is optional: the panel works without it, the NS Pulse page simply says honestly that there is nobody
to do the switching. But if rules are created, the daemon must be running, otherwise "Turn on" turns nothing on.

**pulse-server** (decides and edits records) is installed and started by `deploy/install.sh` on every panel node: user
`dns-pulse`, `etc/pulse-server.toml` from the template (`[apply]`, `[control]` and `[ha]` enabled), the unit. It keeps its TLS certificate
in `dns_panel` and creates it on first start (the node is still standalone, the database is writable). When a pair is created,
the receiver's database is replaced by the donor's, and both nodes work with the donor's certificate — agents do not notice a switchover. At startup the log shows the certificate fingerprint
and the socket path.

**pulse-agent** goes onto each site that runs checks (it can also be on a panel node), from its own package
`dns-panel-pulse-agent_<version>_amd64.deb`. The server address for agents is set IN THE PANEL: **NS Pulse → Agent
config**. The ready agent file is there too — four lines, the same for all sites: there is no personal secret in it;
the agent makes its own key on first start. As root:
```bash
apt install ./dns-panel-pulse-agent_1.0.0_amd64.deb     # user pulse-agent, the unit (enabled)
nano /opt/dns-panel/etc/pulse-agent.toml                 # paste what the panel showed
systemctl start pulse-agent
journalctl -u pulse-agent -n 5                           # → a code like 7F3A-91C2 and "waiting for approval"
```
The agent appears in the panel as a request — **NS Pulse → Waiting for approval**. It is identified by host name and the code from
the log; after `Approve` it gets a name and tasks.

Check that the loop is alive: the NS Pulse page has NO "The Pulse server is not running on this node" bar, and
the approved agent is shown as `online`.
