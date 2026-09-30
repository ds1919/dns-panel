#!/usr/bin/env bash
# Builds the Debian packages into dist/ from the committed tree (HEAD) and the binaries in bin/ (make deb runs it
# after make build):
#
#   dns-panel_<v>_amd64.deb              a panel node (/opt/dns-panel; postinst runs deploy/install.sh --package)
#   dns-panel-pulse-agent_<v>_amd64.deb  an NS Pulse tester, for the sites that run checks
#   dns-panel-watcher_<v>_amd64.deb      the service-address watcher, for a pair without a router doing it
#   powerdns-repo.sh, SHA256SUMS
#
# Every file belongs to exactly one package, so the agent can also go onto a panel node.
set -euo pipefail
ROOT=$(cd "$(dirname "$(readlink -f "$0")")/../.." && pwd)
V=$(cat "$ROOT/VERSION")
OUT=$ROOT/dist
git -C "$ROOT" diff --quiet HEAD -- || { echo "uncommitted changes — commit first, the packages are made from HEAD" >&2; exit 1; }

TREE=$(mktemp -d); trap 'rm -rf "$TREE"' EXIT
git -C "$ROOT" archive HEAD | tar -x -C "$TREE"
rm -rf "$OUT"; mkdir -p "$OUT"

NODE_BINS="dns-agent dns-sync-worker dns-ha-agent dns-ha-manager pulse-server"
AGENT_FILES="etc/systemd/pulse-agent.service etc/pulse-agent.example.toml"
WATCHER_FILES="etc/systemd/dns-watcher.service etc/dns-watcher.example.toml"

# pkg <control dir> <staging dir>: DEBIAN/ from deploy/deb/<dir>, then dpkg-deb.
pkg() {
    local d=$1 r=$2 name
    mkdir -p "$r/DEBIAN"
    sed "s/@VERSION@/$V/" "$ROOT/deploy/deb/$d/control" > "$r/DEBIAN/control"
    echo "Installed-Size: $(du -sk "$r/opt" | cut -f1)" >> "$r/DEBIAN/control"
    install -m 0755 "$ROOT/deploy/deb/$d/postinst" "$ROOT/deploy/deb/$d/prerm" "$ROOT/deploy/deb/$d/postrm" "$r/DEBIAN/"
    name=$(sed -n 's/^Package: //p' "$r/DEBIAN/control")
    dpkg-deb --root-owner-group -Zxz --build "$r" "$OUT/${name}_${V}_amd64.deb" >/dev/null
    rm -rf "$r"
    echo "  $OUT/${name}_${V}_amd64.deb"
}
# part <staging dir> <file...>: copy files of the tree (bin/* from the build) under /opt/dns-panel.
part() {
    local r=$1; shift
    for f in "$@"; do
        install -D -m "$( [ "${f%%/*}" = bin ] && echo 0755 || echo 0644 )" \
            "$( [ "${f%%/*}" = bin ] && echo "$ROOT/$f" || echo "$TREE/$f" )" "$r/opt/dns-panel/$f"
    done
}

# The panel: the whole tree without Go sources and without the agent's and the watcher's files.
R=$(mktemp -d); mkdir -p "$R/opt/dns-panel"
cp -a "$TREE/." "$R/opt/dns-panel/"; rm -rf "$R/opt/dns-panel/src"
for f in $AGENT_FILES $WATCHER_FILES; do rm -f "$R/opt/dns-panel/$f"; done
mkdir -p "$R/opt/dns-panel/bin"; for b in $NODE_BINS; do install -m 0755 "$ROOT/bin/$b" "$R/opt/dns-panel/bin/"; done
pkg . "$R"

R=$(mktemp -d); part "$R" bin/pulse-agent $AGENT_FILES; pkg pulse-agent "$R"
R=$(mktemp -d); part "$R" bin/dns-watcher $WATCHER_FILES; pkg watcher "$R"

cp "$ROOT/deploy/powerdns-repo.sh" "$OUT/"
(cd "$OUT" && sha256sum ./*.deb powerdns-repo.sh | sed 's# \./# #' > SHA256SUMS)
cat "$OUT/SHA256SUMS"
