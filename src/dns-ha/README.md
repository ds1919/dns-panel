# dns-ha (Go): dns-ha-manager + dns-ha-agent

HA contour of the pair: the manager observes, decides and runs operations; the privileged agent is the only
process that changes the node. How it works — [docs/23-ha-manager.md](../../docs/23-ha-manager.md); installing a
pair — [docs/INSTALL/02-ha-pair.md](../../docs/INSTALL/02-ha-pair.md).

## Build

Built on the dev machine only; nodes get static binaries (no Go toolchain there). `deploy/deploy.sh` does it.

```bash
make build   # ../../bin/dns-ha-manager, ../../bin/dns-ha-agent (CGO_ENABLED=0, -trimpath, revision embedded)
make check   # gofmt + go vet (the project has no automated tests)
```

## Layout

- `cmd/dns-ha-manager`, `cmd/dns-ha-agent` — the two daemons;
- `internal/` — observation (`observe`, `health`, `probe`), decisions (`planner`), operations (`ops`, `execute`,
  `pairsetup`, `pairing`), the peer protocol (`peer`), the local store (`store`, schema `store/dns_ha.sql`
  embedded in the binary and applied by the manager), safety state (`safety`), the agent (`agent`, `agentd`).

## Configuration

- manager: `/opt/dns-panel/etc/ha.toml` — only how to reach its own `dns_ha` (unix socket). Everything else comes
  from configuration revisions in `dns_ha`; platform paths are constants in `internal/config/platform.go`.
- agent: `/opt/dns-panel/etc/ha-agent.toml`.

Parsing is strict: an unknown key fails the start.

## CLI (manager)

`-config`, `-once` (print the state as JSON and exit), `-version`; operations: `-pair`, `-switchover`,
`-emergency -ack … -operator …`, `-accept-relay-loss`, `-reseed`, `-resume -id …`, `-operation`; publication:
`-provider`, `-address`, `-probe-port`. Their meaning and preconditions are in docs/23.
