#!/usr/bin/env bash
# DNS Panel — full removal from a node: the product, MariaDB, PowerDNS, Apache and ALL their data. For test
# stands and from-scratch re-acceptance; on a production node this destroys DNS.
#
#   sudo ./deploy/uninstall.sh --delete-all-data
#
# MariaDB is purged together with mysql-common: a leftover package keeps /etc/mysql, and the next install puts
# mariadb-server on top of a half-removed config — postinst then does not initialise the data directory.
set -euo pipefail
[ "${1:-}" = --delete-all-data ] || { sed -n '2,6p' "$0"; exit 2; }
[ "$(id -u)" = 0 ] || { echo "run as root (sudo)" >&2; exit 1; }

systemctl stop dns-ha-manager dns-ha-agent dns-agent dns-sync-worker \
               pulse-server pulse-agent pdns apache2 mariadb 2>/dev/null || true
systemctl disable dns-ha-manager dns-ha-agent dns-agent dns-sync-worker pulse-server pulse-agent 2>/dev/null || true
rm -f /etc/systemd/system/dns-*.service /etc/systemd/system/dns-*.timer /etc/systemd/system/pulse-*.service \
      /etc/tmpfiles.d/dns-panel.conf
systemctl daemon-reload

# The pair's service address, if this node held it (floating IP on an interface, anycast /32 on lo): it
# belongs to the pair, not to the node.
ip -o -4 addr show | awk '$4 ~ /\/32$/ && $4 !~ /^127\./ {print $2, $4}' | while read -r dev a; do
    ip addr del "$a" dev "$dev" 2>/dev/null || true
done

export DEBIAN_FRONTEND=noninteractive
apt-get purge -y -qq 'mariadb-*' mysql-common galera-4 'pdns-*' apache2 apache2-bin apache2-data apache2-utils >/dev/null 2>&1 || true
apt-get autoremove -y -qq >/dev/null 2>&1 || true
rm -rf /var/lib/mysql /var/lib/mariadb /etc/mysql /etc/powerdns /etc/apache2 /var/www/vhost /opt/dns-panel /run/dns-panel

gpasswd -d www-data dns-ha >/dev/null 2>&1 || true
userdel dns-pulse 2>/dev/null || true
userdel dns-ha 2>/dev/null || true
groupdel dns-ha 2>/dev/null || true

echo "DNS Panel removed from $(hostname)"
