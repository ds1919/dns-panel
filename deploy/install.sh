#!/usr/bin/env bash
# DNS Panel — one-command node install (Debian/Ubuntu, LXC).
#
#   sudo ./deploy/install.sh [--admin LOGIN]
#
# Run from an unpacked product tree (a clone, or a copy shipped by deploy/deploy.sh). Installs a STANDALONE node
# with the HA stack already in place: a pair is formed later in the panel (High availability → pairing) from
# two such nodes. There is no separate "HA install".
#
# Re-running is safe and is how updates happen: code (www/ bin/ libexec/ deploy/ docs/, etc/ templates) is copied again and
# services restart, while node config, secrets and databases stay as they are. It asks nothing: passwords
# and keys are generated (0600/0640 files in etc/secrets), no node address is needed (PowerDNS listens on
# 0.0.0.0 — docs/INSTALL/01-standalone.md §3). The first administrator is created if the database has none.
#
# Left to the human: open http://<node address>/, sign in with the password shown ONCE, change it and
# enroll TOTP.
set -euo pipefail

ADMIN=admin
# --package: run from the .deb's postinst. apt has already installed every dependency (debian control) and holds
# the dpkg lock, so this run installs no packages itself; the files are already in /opt/dns-panel.
PACKAGE=0
while [ $# -gt 0 ]; do
    case "$1" in
        --admin) ADMIN="$2"; shift 2 ;;
        --package) PACKAGE=1; shift ;;
        -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

[ "$(id -u)" = 0 ] || { echo "run as root (sudo)" >&2; exit 1; }
SRC=$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)
PANEL=/opt/dns-panel
SECRETS=$PANEL/etc/secrets
step() { printf '\n==> %s\n' "$*"; }
rand() { head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | cut -c1-32; }

# The Go binaries a panel node runs (pulse-agent and dns-watcher are built too, but run on other machines).
NODE_BINS="dns-agent dns-sync-worker dns-ha-agent dns-ha-manager pulse-server"
for b in $NODE_BINS; do
    [ -x "$SRC/bin/$b" ] || { echo "$SRC/bin/$b is missing — build it on the dev machine (make -C src/<component> build) or use deploy/deploy.sh" >&2; exit 1; }
done

step "packages"
export DEBIAN_FRONTEND=noninteractive
# PowerDNS comes from its own repository, one fixed branch (deploy/powerdns-repo.sh): the panel is built and
# checked against 5.1. The package list here is the same as Depends in deploy/deb/control.
if [ $PACKAGE = 0 ]; then
    sh "$SRC/deploy/powerdns-repo.sh" >/dev/null
    # confold: an upgrade keeps our pdns.conf instead of stopping to ask about it.
    apt-get install -y -qq -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold \
        perl libcgi-pm-perl libdbi-perl libdbd-mysql-perl libjson-perl libwww-perl \
        libcrypt-urandom-perl libcrypt-argon2-perl libcryptx-perl libauth-googleauth-perl libimager-qrcode-perl \
        apache2 libapache2-mod-fcgid libfcgi-perl bind9-dnsutils rsync curl \
        mariadb-server mariadb-client \
        pdns-server pdns-backend-mysql >/dev/null
    # The PowerDNS bind backend conflicts with gmysql (launch+=bind) — purge it along with its config.
    apt-get purge -y -qq pdns-backend-bind >/dev/null 2>&1 || true
fi
pdns_ver=$(dpkg-query -W -f='${Version}' pdns-server)
case "$pdns_ver" in
    5.1.*) ;;
    *) echo "PowerDNS $pdns_ver is installed, the panel needs 5.1.x (repo.powerdns.com, see deploy/powerdns-repo.sh)" >&2; exit 1 ;;
esac
rm -f /etc/powerdns/pdns.d/*bind* /etc/powerdns/bindbackend.conf
a2enmod -q cgid fcgid rewrite headers env >/dev/null
perl -MCGI -MDBI -MDBD::mysql -MJSON -MCrypt::Argon2 -MImager::QRCode -MAuth::GoogleAuth -MCrypt::URandom -MCryptX -MFCGI -e 1

# :53 is taken by the systemd-resolved stub — PowerDNS would not start.
if systemctl is-active --quiet systemd-resolved && ss -lntu | grep -q '127.0.0.53:53'; then
    mkdir -p /etc/systemd/resolved.conf.d
    printf '[Resolve]\nDNSStubListener=no\n' > /etc/systemd/resolved.conf.d/no-stub.conf
    ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
    systemctl restart systemd-resolved
fi

step "users"
getent group dns-ha >/dev/null || groupadd -r dns-ha
id dns-ha >/dev/null 2>&1 || useradd -r -g dns-ha -s /usr/sbin/nologin -d /nonexistent dns-ha
usermod -aG dns-ha www-data     # the panel reads the HA IPC sockets — and nothing beyond that
# pulse-server: its own user (a network daemon); asks dns-ha-manager for the write right like the panel does.
id dns-pulse >/dev/null 2>&1 || useradd -r -U -s /usr/sbin/nologin -d /nonexistent dns-pulse
usermod -aG dns-ha dns-pulse

# Database upgrade (deploy/migrations/README.md) runs BEFORE the code is replaced: if a migration fails, the
# installer stops and the node keeps running the old version on the old schema. Only an existing, writable
# dns_panel is touched (standalone or ACTIVE); a STANDBY receives the change by replication, so migrations go
# through the binlog, unlike everything else the installer writes. A fresh install gets schema.sql below.
migrations_pending() {
    local f v
    for f in "$SRC"/deploy/migrations/[0-9]*.sql; do
        [ -e "$f" ] || continue
        v=$(basename "$f" .sql)
        [ -n "$(mysql -N dns_panel -e "SELECT 1 FROM schema_migrations WHERE version='$v'")" ] || echo "$f"
    done
}
if mysql -N -e 'SELECT 1' >/dev/null 2>&1 \
   && [ "$(mysql -N -e "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='dns_panel'")" != 0 ] \
   && [ "$(mysql -N -e 'SELECT @@global.read_only')" = 0 ]; then
    step "database upgrade"
    # Installs from before migrations existed are the v1.0 baseline: the table appears, nothing is recorded.
    mysql dns_panel -e "CREATE TABLE IF NOT EXISTS schema_migrations (version VARCHAR(64) NOT NULL,
        applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (version)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
    pending=$(migrations_pending)
    if [ -z "$pending" ]; then
        echo "schema is current"
    else
        install -d -m 0700 $PANEL/var/backup
        dump=$PANEL/var/backup/dns_panel-$(date -u +%Y%m%dT%H%M%SZ).sql.gz
        mysqldump --single-transaction --routines dns_panel | gzip > "$dump"
        echo "backup: $dump"
        ls -1t $PANEL/var/backup/dns_panel-*.sql.gz | tail -n +6 | xargs -r rm -f   # keep the last five
        for f in $pending; do
            v=$(basename "$f" .sql)
            echo "migration $v"
            mysql dns_panel < "$f" || { echo "migration $v failed — nothing else changed; the database is backed up in $dump" >&2; exit 1; }
            mysql dns_panel -e "INSERT INTO schema_migrations (version) VALUES ('$v')"
        done
    fi
fi

step "files → $PANEL"
install -d -m 0755 $PANEL
if [ "$SRC" != "$PANEL" ]; then
    # Code is synced whole, extras deleted. Node config, secrets and state (var/) are left alone:
    # etc/ receives only templates, units and what the repository carries.
    for d in www libexec deploy docs; do rsync -a --delete "$SRC/$d/" "$PANEL/$d/"; done
    install -m 0644 "$SRC/VERSION" $PANEL/VERSION
    rsync -a --delete --delete-excluded $(for b in $NODE_BINS; do printf -- '--include=/%s ' "$b"; done) --exclude='*' "$SRC/bin/" "$PANEL/bin/"
    rsync -a --exclude='/secrets/' --exclude='/powerdns/' --exclude='/mariadb/dns-panel.cnf' --exclude='/tls/' --exclude='/apache/dns-panel-tls*.conf' \
          --exclude='/panel.toml' --exclude='/dns-agent.toml' --exclude='/ha.toml' --exclude='/ha-agent.toml' \
          --exclude='/pulse-server.toml' --exclude='/pulse-agent.toml' --exclude='/dns-watcher.toml' \
          "$SRC/etc/" "$PANEL/etc/"
fi
chown -R root:www-data $PANEL/www $PANEL/docs
chmod -R u=rwX,g=rX,o=rX $PANEL/www $PANEL/docs
chown -R root:root $PANEL/bin $PANEL/libexec $PANEL/deploy && chmod 0755 $PANEL/bin/* $PANEL/libexec/* $PANEL/deploy/*
# etc/ arrives owned by whoever copied it (rsync -a): templates and units become root, not writable by others.
# Working files and secrets get their owners below, so secrets/ is skipped here.
find $PANEL/etc -path $SECRETS -prune -o -exec chown root:root {} + -exec chmod go-w {} +
install -d -o dns-ha -g dns-ha -m 0750 $PANEL/var
install -d -o root -g dns-ha -m 0750 $SECRETS
install -d -o root -g root -m 0755 $PANEL/etc/powerdns

step "secrets"
secret() {   # secret <file> <group>: create random if missing; permissions always
    [ -s "$SECRETS/$1" ] || rand > "$SECRETS/$1"
    chown "root:$2" "$SECRETS/$1"; chmod 0640 "$SECRETS/$1"
}
secret panel-db.password www-data
secret pdns-db.password  www-data
secret pdns-api.key      www-data
# TOTP secret encryption key: 32 random bytes in base64 (the format the panel expects).
[ -s "$SECRETS/auth-master.key" ] || head -c 32 /dev/urandom | base64 -w0 > "$SECRETS/auth-master.key"
chown root:www-data "$SECRETS/auth-master.key"; chmod 0640 "$SECRETS/auth-master.key"
PANEL_PW=$(cat $SECRETS/panel-db.password); PDNS_PW=$(cat $SECRETS/pdns-db.password); API_KEY=$(cat $SECRETS/pdns-api.key)

step "node configuration"
conf() {     # conf <name> <owner:group> <mode>: working file from the template, only if it does not exist yet
    [ -e "$PANEL/etc/$1" ] || cp "$PANEL/etc/${1%.toml}.example.toml" "$PANEL/etc/$1"
    chown "$2" "$PANEL/etc/$1"; chmod "$3" "$PANEL/etc/$1"
}
conf panel.toml     root:www-data 0640
conf dns-agent.toml root:pdns     0640
conf ha.toml        root:dns-ha   0640
conf ha-agent.toml  root:root     0600
conf pulse-server.toml root:dns-pulse 0640
# The HA stack is installed on every node, whether or not it is ever paired.
sed -i 's/^\(\s*enabled\s*=\s*\)false/\1true/' $PANEL/etc/panel.toml $PANEL/etc/pulse-server.toml

step "MariaDB"
# A standalone node is ready for pairing from the start: binlog, GTID, random server_id (cnf is created once).
# The working cnf gets a RANDOM server_id once: the two nodes of a pair must differ, server_id is not dynamic,
# and an existing file is never rewritten (its id may already be in the binlog). The template's installer
# note (from "# TEMPLATE." to the next bare "#") is left out of the working file.
if [ ! -e $PANEL/etc/mariadb/dns-panel.cnf ]; then
    SERVER_ID=$(od -An -N4 -tu4 /dev/urandom | tr -d ' '); [ "$SERVER_ID" != 0 ] || SERVER_ID=1
    sed -e "s/__SERVER_ID__/$SERVER_ID/" -e '/^# TEMPLATE\./,/^#$/d' \
        $PANEL/etc/mariadb/dns-panel.example.cnf > $PANEL/etc/mariadb/dns-panel.cnf
fi
# Files made before 1.0 named the binlog by an absolute path in /var/lib/mysql, which does not exist on Ubuntu
# 26.04 (the data directory is /var/lib/mariadb): the bare name is the same file where the path was valid.
sed -i 's#^log_bin\([[:space:]]*\)=\([[:space:]]*\)/var/lib/mysql/mariadb-bin$#log_bin\1=\2mariadb-bin#' $PANEL/etc/mariadb/dns-panel.cnf
chown root:root $PANEL/etc/mariadb/dns-panel.cnf; chmod 0644 $PANEL/etc/mariadb/dns-panel.cnf
mariadb_failed() { echo "MariaDB did not start:" >&2; journalctl -u mariadb -n 15 --no-pager -o cat >&2 || true; exit 1; }
if [ "$(readlink /etc/mysql/mariadb.conf.d/60-dns-panel.cnf || true)" != "$PANEL/etc/mariadb/dns-panel.cnf" ]; then
    ln -sf $PANEL/etc/mariadb/dns-panel.cnf /etc/mysql/mariadb.conf.d/60-dns-panel.cnf
    systemctl restart mariadb || mariadb_failed
fi
systemctl enable -q mariadb
systemctl is-active -q mariadb || systemctl start mariadb || mariadb_failed
# EVERYTHING the installer writes to MariaDB bypasses the binlog (sql_log_bin=0). Users and grants are per node
# (passwords from its own secrets), and in a pair the binlog goes to the peer: ALTER USER with this node's
# password applied on the peer would cut its panel off from the database. On STANDBY these would also be
# errant local GTIDs that a switchover would carry to the new replica. Schemas load only into the empty
# database of a standalone node — before pairing, which starts with a reseed, so they need no binlog either.
sql() { mysql "$@" --init-command='SET SESSION sql_log_bin=0'; }
if [ "$(mysql -N -e 'SELECT @@global.read_only')" = 1 ]; then
    # A pair's STANDBY: its databases are a copy of ACTIVE and change only via replication. Users and schemas exist.
    echo "read-only node (HA standby) — databases left to replication"
else
    # Users get the password from the file, and a re-run resets it to the file (CREATE IF NOT EXISTS would not).
    sql <<SQL
CREATE DATABASE IF NOT EXISTS dns_panel CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE DATABASE IF NOT EXISTS pdns      CHARACTER SET utf8mb4;
CREATE DATABASE IF NOT EXISTS dns_ha;
CREATE USER IF NOT EXISTS 'dnspanel'@'127.0.0.1'; ALTER USER 'dnspanel'@'127.0.0.1' IDENTIFIED BY '$PANEL_PW';
CREATE USER IF NOT EXISTS 'dnspanel'@'localhost'; ALTER USER 'dnspanel'@'localhost' IDENTIFIED BY '$PANEL_PW';
CREATE USER IF NOT EXISTS 'pdns'@'127.0.0.1';     ALTER USER 'pdns'@'127.0.0.1'     IDENTIFIED BY '$PDNS_PW';
CREATE USER IF NOT EXISTS 'dns-ha'@'localhost' IDENTIFIED VIA unix_socket;
GRANT ALL PRIVILEGES ON dns_panel.* TO 'dnspanel'@'127.0.0.1';
GRANT ALL PRIVILEGES ON dns_panel.* TO 'dnspanel'@'localhost';
GRANT ALL PRIVILEGES ON pdns.*      TO 'pdns'@'127.0.0.1';
GRANT ALL PRIVILEGES ON dns_ha.*    TO 'dns-ha'@'localhost';
-- manager: write to its own dns_ha even under read_only (STANDBY) and see replication state (docs/23 §3)
GRANT READ_ONLY ADMIN, SLAVE MONITOR ON *.* TO 'dns-ha'@'localhost';
FLUSH PRIVILEGES;
SQL
    tables() { mysql -N -e "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='$1'"; }
    # Schemas load only into an empty database: schema.sql does not alter existing tables, and loading on
    # top would be a silent divergence.
    if [ "$(tables pdns)" = 0 ]; then
        sql pdns < /usr/share/pdns-backend-mysql/schema/schema.mysql.sql
        # who/when changed a record — written by the panel, ignored by PowerDNS
        sql pdns -e "ALTER TABLE records ADD COLUMN updated_by VARCHAR(255) NULL, ADD COLUMN updated_at DATETIME(6) NULL"
    fi
    if [ "$(tables dns_panel)" = 0 ]; then
        sql dns_panel < $PANEL/docs/INSTALL/schema.sql
        # schema.sql already contains every shipped migration
        for f in $PANEL/deploy/migrations/[0-9]*.sql; do
            [ -e "$f" ] && sql dns_panel -e "INSERT IGNORE INTO schema_migrations (version) VALUES ('$(basename "$f" .sql)')"
        done
    else
        echo "dns_panel already has tables — schema left as is"
    fi
fi
# pulse-server reads which addresses the zones publish (slow sweep): its own account, SELECT only. On every
# node, a STANDBY too: accounts are per node, root is not held back by read_only, and sql_log_bin=0 keeps it
# out of the binlog.
sql <<SQL
CREATE USER IF NOT EXISTS 'dns-pulse'@'localhost' IDENTIFIED VIA unix_socket;
GRANT SELECT ON pdns.domains TO 'dns-pulse'@'localhost';
GRANT SELECT ON pdns.records TO 'dns-pulse'@'localhost';
SQL

step "PowerDNS"
# The config is entirely ours and rewritten every run (it holds secrets from etc/secrets). The primary/secondary
# role is NOT here: 90-ha-role.conf owns it (yes/yes on a standalone node, driven by dns-ha-agent in a pair).
# Why these values — docs/INSTALL/01-standalone.md §3.
PDNS_CONF=$PANEL/etc/powerdns/dns-panel.conf
PDNS_WAS=$(md5sum $PDNS_CONF 2>/dev/null || true)
cat > $PDNS_CONF <<CONF
# generated by deploy/install.sh — edits are overwritten on the next run
launch=gmysql
gmysql-host=127.0.0.1
gmysql-dbname=pdns
gmysql-user=pdns
gmysql-password=$PDNS_PW
gmysql-dnssec=yes
dnsupdate=yes
allow-dnsupdate-from=
forward-dnsupdate=no
local-address=0.0.0.0
api=yes
api-key=$API_KEY
webserver=yes
webserver-address=127.0.0.1
webserver-port=8081
zone-cache-refresh-interval=300
allow-axfr-ips=127.0.0.0/8,::1
send-signed-notify=no
xfr-cycle-interval=5
CONF
chown root:pdns $PANEL/etc/powerdns/dns-panel.conf; chmod 0640 $PANEL/etc/powerdns/dns-panel.conf
ln -sf $PANEL/etc/powerdns/dns-panel.conf /etc/powerdns/pdns.d/dns-panel.conf
if [ ! -e /etc/powerdns/pdns.d/90-ha-role.conf ]; then
    printf '# managed by dns-ha-agent (HA role) — do not edit by hand\nprimary=yes\nsecondary=yes\n' \
        > /etc/powerdns/pdns.d/90-ha-role.conf
fi
# A role set anywhere else would override the role file (docs/INSTALL/02-ha-pair.md §4).
if grep -Hn '^\s*\(primary\|secondary\|master\|slave\)\s*=' /etc/powerdns/pdns.conf /etc/powerdns/pdns.d/*.conf \
        | grep -v '/90-ha-role.conf:'; then
    echo "PowerDNS role is set outside 90-ha-role.conf (lines above) — remove it" >&2; exit 1
fi
systemctl enable pdns >/dev/null 2>&1
# Restart only if the config really changed or PowerDNS is down: on a pair's ACTIVE this is a DNS pause,
# and a panel code update is no reason for one.
if [ "$(md5sum $PDNS_CONF)" != "$PDNS_WAS" ] || ! systemctl is-active --quiet pdns; then
    systemctl restart pdns
fi
pdns_control rping >/dev/null

step "services"
ln -sf $PANEL/etc/tmpfiles/dns-panel.conf /etc/tmpfiles.d/dns-panel.conf
systemd-tmpfiles --create /etc/tmpfiles.d/dns-panel.conf
for u in dns-agent.service dns-sync-worker.service dns-ha-agent.service dns-ha-manager.service pulse-server.service; do
    ln -sf $PANEL/etc/systemd/$u /etc/systemd/system/$u
done
systemctl daemon-reload
systemctl enable -q dns-agent dns-sync-worker dns-ha-agent dns-ha-manager pulse-server
# restart, not just start: on a re-run the processes must pick up the new code
systemctl restart dns-agent dns-ha-agent
systemctl restart dns-ha-manager
systemctl restart dns-sync-worker pulse-server

step "Apache"
install -d /var/www/vhost
ln -sfn $PANEL/www /var/www/vhost/dns-panel
ln -sf $PANEL/etc/apache/dns-panel.conf /etc/apache2/sites-available/dns-panel.conf
a2dissite -q 000-default >/dev/null 2>&1 || true
a2ensite -q dns-panel >/dev/null
systemctl restart apache2     # restart: www-data has just joined the dns-ha group
# HTTPS from the certificates in etc/tls/, if any (deploy/tls.sh); a no-op without them.
sh $PANEL/deploy/tls.sh

step "checks"
fail=0
check() { if eval "$2" >/dev/null 2>&1; then printf '  ok    %s\n' "$1"; else printf '  FAIL  %s\n' "$1"; fail=1; fi; }
check "panel.toml parses"        "sudo -u www-data perl -I $PANEL/www/include -e 'use functions qw(load_panel_config); load_panel_config()'"
check "PowerDNS answers"         "pdns_control rping"
check "PowerDNS API"             "curl -fsS -H 'X-API-Key: $API_KEY' http://127.0.0.1:8081/api/v1/servers/localhost"
check "dns-agent answers"        "sudo -u www-data perl -I $PANEL/www/include -e 'use functions qw(dns_agent_call); exit(dns_agent_call(q(ping))->{pong} ? 0 : 1)'"
check "dns-ha-agent running"     "systemctl is-active dns-ha-agent"
check "dns-ha-manager running"   "systemctl is-active dns-ha-manager"
check "dns-sync-worker running"  "systemctl is-active dns-sync-worker"
check "pulse-server running"     "systemctl is-active pulse-server"
# A pair's STANDBY honestly answers "not accepting writes" — for it that is the healthy state.
check "panel ready (/health/ready)" "curl -sS http://127.0.0.1/health/ready | grep -Eq '\"ready\":1|\"role\":\"standby\"'"
# Over plain HTTP on purpose (/health/ is not redirected, everything else may be): the answer must not be 200.
check "config outside web root"  "[ \"\$(curl -sk --path-as-is -o /dev/null -w '%{http_code}' -L http://127.0.0.1/../etc/panel.toml)\" != 200 ]"

if [ "$(mysql -N dns_panel -e 'SELECT COUNT(*) FROM users')" = 0 ]; then
    step "first administrator"
    perl $PANEL/deploy/bootstrap-admin.pl --username "$ADMIN" --display-name "Administrator"
fi

echo
if [ $fail = 0 ]; then
    echo "DNS Panel is installed: http://$(hostname -I | awk '{print $1}')/"
else
    echo "installed with failed checks (above)" >&2; exit 1
fi
