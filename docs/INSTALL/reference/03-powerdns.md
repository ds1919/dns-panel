# 03 — PowerDNS (shadow-master) + gmysql

The panel manages zones and records in the **PowerDNS MySQL backend** (`gmysql`, database `pdns`). PowerDNS runs as a
hidden master: it stores the data, sends NOTIFY and serves AXFR to secondaries. Public serving is done by the
BIND secondaries ([06-bind-secondaries.md](06-bind-secondaries.md)). Everything below is done by `deploy/install.sh`.

## Installation: PowerDNS 5.1

The panel is built and tested on **PowerDNS 5.1**; it is installed from the official repository (the `auth-51` branch), not from
the distribution (Ubuntu 24.04 ships the EOL 4.8, whose API does not accept `TSIG-ALLOW-AXFR`):

```bash
sudo install -d -m 0755 /etc/apt/keyrings
sudo curl -fsSL https://repo.powerdns.com/FD380FBB-pub.asc -o /etc/apt/keyrings/powerdns.asc
echo "deb [signed-by=/etc/apt/keyrings/powerdns.asc] http://repo.powerdns.com/ubuntu $(. /etc/os-release; echo $VERSION_CODENAME)-auth-51 main" \
  | sudo tee /etc/apt/sources.list.d/powerdns.list
printf 'Package: pdns-*\nPin: origin repo.powerdns.com\nPin-Priority: 600\n' | sudo tee /etc/apt/preferences.d/powerdns
sudo apt-get update && sudo apt-get install pdns-server pdns-backend-mysql
dpkg-query -W -f='${Version}\n' pdns-server      # the installer requires 5.1.x, otherwise it stops
```

`pdns-backend-bind` is removed together with `/etc/powerdns/pdns.d/*bind*` and `/etc/powerdns/bindbackend.conf`:
PowerDNS must launch only gmysql.

## The `pdns` database

The database and the `'pdns'@'127.0.0.1'` user — [02-mariadb.md](02-mariadb.md). The package schema is loaded into an EMPTY
database, plus two "who/when changed the record" columns (written by the panel, not read by PowerDNS):

```bash
sudo mysql pdns < /usr/share/pdns-backend-mysql/schema/schema.mysql.sql
sudo mysql pdns -e "ALTER TABLE records ADD COLUMN updated_by VARCHAR(255) NULL, ADD COLUMN updated_at DATETIME(6) NULL"
```

## Config

`/opt/dns-panel/etc/powerdns/dns-panel.conf` (`root:pdns 0640`) → symlink `/etc/powerdns/pdns.d/dns-panel.conf`.
The installer writes the whole file on every run (manual edits are overwritten); PowerDNS is restarted
only if the file changed or PowerDNS is not running.

```ini
launch=gmysql
gmysql-host=127.0.0.1
gmysql-dbname=pdns
gmysql-user=pdns
gmysql-password=<etc/secrets/pdns-db.password>
gmysql-dnssec=yes
dnsupdate=yes
allow-dnsupdate-from=
forward-dnsupdate=no
local-address=0.0.0.0
api=yes
api-key=<etc/secrets/pdns-api.key>
webserver=yes
webserver-address=127.0.0.1
webserver-port=8081
zone-cache-refresh-interval=300
allow-axfr-ips=127.0.0.0/8,::1
send-signed-notify=no
xfr-cycle-interval=5
```

Why exactly these values — [../01-standalone.md §3](../01-standalone.md#3-why-powerdns-is-configured-this-way).

The role (`primary`/`secondary`) is NOT here: it lives only in `/etc/powerdns/pdns.d/90-ha-role.conf` (on a standalone
node `yes/yes`, in a pair it is managed by dns-ha-agent). The installer creates this file if it is missing and
stops if the role is set anywhere else.

Changes to **records inside a known zone** are served immediately (records are read from gmysql on every query);
`zone-cache-refresh-interval` affects only the zone list. PowerDNS learns about a new zone via `rediscover` from
dns-agent, which also confirms serving by SOA serial ([05-dns-agent.md](05-dns-agent.md)).

## Check

```bash
sudo pdns_control rping        # → PONG
curl -fsS -H "X-API-Key: $(sudo cat /opt/dns-panel/etc/secrets/pdns-api.key)" http://127.0.0.1:8081/api/v1/servers/localhost
dig @127.0.0.1 <zone> SOA +noall +answer     # after the panel creates a test zone
```

## Connection from the panel

`etc/panel.toml`:

```toml
[pdns_db]
host          = "127.0.0.1"
name          = "pdns"
user          = "pdns"
password_file = "/opt/dns-panel/etc/secrets/pdns-db.password"

[pdns_api]
url      = "http://127.0.0.1:8081"
server   = "localhost"
key_file = "/opt/dns-panel/etc/secrets/pdns-api.key"
```

## Next

- Zone distribution to secondaries (ALLOW-AXFR-FROM / TSIG / ALSO-NOTIFY, Catalog Zones) — [../../16-delivery.md](../../16-delivery.md).
- HA — [../02-ha-pair.md](../02-ha-pair.md), [../../13-ha-topology.md](../../13-ha-topology.md).
- The zone and record model — [../../05-dns-model.md](../../05-dns-model.md).
