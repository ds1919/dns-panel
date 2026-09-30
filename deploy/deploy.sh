#!/usr/bin/env bash
# DNS Panel — install or update node(s) from a source checkout: check → copy the tree → run deploy/install.sh on
# each node. For installing a node by hand there is the .deb (make deb, or the release): apt install ./dns-panel_*.deb.
#
#   deploy/deploy.sh [user@]node [[user@]node ...]
#
# Nothing is built here: run make build first. The first run installs, later runs update: install.sh leaves config,
# secrets and databases alone. The manager and the panel share a JSON contract, so a node always gets the whole tree.
#
# This machine needs ssh and tar; a node needs Ubuntu 24.04/26.04 and sudo (or a root login). Everything else is
# installed on the node by install.sh.
set -euo pipefail
[ $# -gt 0 ] || { sed -n '2,12p' "$0"; exit 2; }
ROOT=$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)
NODE_BINS="dns-agent dns-sync-worker dns-ha-agent dns-ha-manager pulse-server"

# ---- This machine
missing=""
for c in ssh tar; do command -v "$c" >/dev/null 2>&1 || missing="$missing $c"; done
[ -z "$missing" ] || { echo "This machine needs:$missing (Ubuntu/Debian: sudo apt-get install -y openssh-client tar)" >&2; exit 1; }

nobin=""
for b in $NODE_BINS; do [ -x "$ROOT/bin/$b" ] || nobin="$nobin $b"; done
if [ -n "$nobin" ]; then
    echo "The DNS Panel binaries are missing in $ROOT/bin:$nobin" >&2
    echo "Build them first: make build (Go 1.24+). To install without building, use the release package: apt install ./dns-panel_<version>_amd64.deb" >&2
    exit 1
fi
# In a source checkout, binaries older than the sources would ship a manager that does not match the panel.
if [ -d "$ROOT/src" ]; then
    oldest=$(ls -1tr $(for b in $NODE_BINS; do echo "$ROOT/bin/$b"; done) | head -1)
    if [ -n "$(find "$ROOT/src" -name '*.go' -newer "$oldest" -print -quit)" ]; then
        echo "Go sources are newer than the binaries in bin/ — run make build first." >&2; exit 1
    fi
fi

# ---- The nodes: all of them are checked before anything is copied, so a problem shows up front, not halfway
# through the second node. ssh -n: the check must not read what is typed in this terminal.
fail=0
declare -A SUDO
for host in "$@"; do
    if ! out=$(ssh -n -o ConnectTimeout=10 "$host" '. /etc/os-release 2>/dev/null; echo "os=$ID $VERSION_ID"; echo "uid=$(id -u)";
               command -v sudo >/dev/null && echo sudo=yes; command -v tar >/dev/null && echo tar=yes; true' 2>&1); then
        echo "$host: cannot connect over ssh — $(echo "$out" | tail -1)" >&2; fail=1; continue
    fi
    os=$(echo "$out" | sed -n 's/^os=//p')
    case "$os" in
        "ubuntu 24.04"|"ubuntu 26.04") ;;
        *) echo "$host: unsupported system '${os:-unknown}' — Ubuntu 24.04 or 26.04 is required" >&2; fail=1; continue ;;
    esac
    echo "$out" | grep -qx tar=yes || { echo "$host: tar is not installed" >&2; fail=1; continue; }
    if echo "$out" | grep -qx uid=0; then SUDO[$host]=""
    elif echo "$out" | grep -qx sudo=yes; then SUDO[$host]="sudo "
    else echo "$host: not root and sudo is not installed" >&2; fail=1; continue; fi
done
[ $fail = 0 ] || exit 1

# ---- Copy and install. The tree goes as a tar stream into a fresh ~/dns-panel (nothing left from an older copy);
# history, Go sources, local configs and this machine's state stay here.
for host in "$@"; do
    echo "==> $host"
    tar -C "$ROOT" -czf - \
        --exclude='./.git' --exclude='./src' --exclude='./var/*' --exclude='./tmp' --exclude='./dist' --exclude='./.claude' \
        --exclude='./etc/secrets' --exclude='./etc/powerdns' --exclude='./etc/mariadb/dns-panel.cnf' --exclude='./etc/tls' --exclude='./etc/apache/dns-panel-tls*.conf' \
        --exclude='./etc/panel.toml' --exclude='./etc/dns-agent.toml' --exclude='./etc/ha.toml' --exclude='./etc/ha-agent.toml' \
        --exclude='./etc/pulse-server.toml' --exclude='./etc/pulse-agent.toml' --exclude='./etc/dns-watcher.toml' . \
      | ssh "$host" 'rm -rf ~/dns-panel.new && mkdir -p ~/dns-panel.new && tar -xzf - -C ~/dns-panel.new && rm -rf ~/dns-panel && mv ~/dns-panel.new ~/dns-panel'
    ssh -t "$host" "${SUDO[$host]}\$HOME/dns-panel/deploy/install.sh"
done
