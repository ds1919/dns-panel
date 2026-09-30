#!/bin/sh
# DNS Panel needs PowerDNS 5.1, which comes from the PowerDNS repository (Ubuntu ships other versions: 24.04 has
# the EOL 4.8, whose API refuses TSIG-ALLOW-AXFR). This adds that repository — one fixed branch, pinned — so that
# `apt install ./dns-panel_<version>_amd64.deb` can resolve pdns-server. Safe to run again. Run as root.
#
#   sh powerdns-repo.sh
set -eu
PDNS_BRANCH=51
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
. /etc/os-release
case "${ID}:${VERSION_CODENAME}" in
    ubuntu:noble|ubuntu:resolute) ;;
    *) echo "unsupported OS ${PRETTY_NAME:-$ID}: DNS Panel needs Ubuntu 24.04 or 26.04" >&2; exit 1 ;;
esac
export DEBIAN_FRONTEND=noninteractive
command -v curl >/dev/null || { apt-get update -qq; apt-get install -y -qq ca-certificates curl >/dev/null; }
install -d -m 0755 /etc/apt/keyrings
[ -s /etc/apt/keyrings/powerdns.asc ] || curl -fsSL https://repo.powerdns.com/FD380FBB-pub.asc -o /etc/apt/keyrings/powerdns.asc
echo "deb [signed-by=/etc/apt/keyrings/powerdns.asc] http://repo.powerdns.com/ubuntu ${VERSION_CODENAME}-auth-${PDNS_BRANCH} main" \
    > /etc/apt/sources.list.d/powerdns.list
printf 'Package: pdns-*\nPin: origin repo.powerdns.com\nPin-Priority: 600\n' > /etc/apt/preferences.d/powerdns
apt-get update -qq
echo "PowerDNS ${PDNS_BRANCH%?}.${PDNS_BRANCH#?} repository added (repo.powerdns.com, ${VERSION_CODENAME}-auth-${PDNS_BRANCH})"
