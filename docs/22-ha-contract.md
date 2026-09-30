# 22 — HA contract (rules)

What the HA layer guarantees. How it is implemented — [23-ha-manager.md](23-ha-manager.md) (section links below),
production placement — [13-ha-topology.md](13-ha-topology.md).

HA is optional: a single node works without it.

## 1. Node modes

- `[ha] enabled = true` in `panel.toml` means only "the HA layer is installed on this node". Without it the node is
  a standalone node: the manager is not consulted, the write gate lets everything through, `/health/ready` checks only local
  dependencies.
- With the layer installed, whether a pair exists is answered by the manager: `ha_configured` = `true` / `false` / `null`.
  `false` (no revision, including after dismantling) — the node works as a single node. `null` — "unknown", and this
  is not "HA off": writes are denied.
- States Standalone → Paired · HA not configured → Paired · HA active — [23 §1](23-ha-manager.md#1-node-states).

## 2. Single writer

- A pair has exactly one ACTIVE: MariaDB `read_only=0`, PowerDNS `primary=yes secondary=yes`, the service address
  published. STANDBY: `read_only=1`, PowerDNS `no/no`, an asynchronous replica of ACTIVE.
- The role is defined by the right to be ACTIVE (durable proof in the node's safety file), not by a row in the database.
  The right is granted only by pair creation, handover during a planned switchover, or the operator in an emergency
  ([23 §3](23-ha-manager.md#3-the-right-to-be-active)).
- **Physics.** `read_only` protects the data regardless of software decisions: the panel and PowerDNS accounts do not have
  `SUPER`/`READ ONLY ADMIN`. The right and the physics are checked independently; a mismatch is a sign of split-brain, and writes
  are denied.
- After a MariaDB restart, a pair node starts read-only (fail-safe) and takes its role back only with
  proof ([23 §8.3](23-ha-manager.md#83-stay-active--become-active)).
- The epoch is monotonic; a node that sees a larger epoch on its peer goes to a safe state; commands from
  a past epoch are not executed.

## 3. Planned switchover

A role swap between two **live** nodes; the old ACTIVE is not shut down and becomes STANDBY.

1. It is started on ACTIVE; the target is a healthy STANDBY with the same pair configuration, not fenced, with replication
   running.
2. First the source stops writing and publishing, and `read_only=1` is proven by observation.
3. Then the target provably applies everything up to the source's GTID position — the only proof of no data loss.
4. Only after that does the source hand over the right (new epoch = current + 1) and give up its own — the point of
   no return. Before it, any failure cancels the operation and the source stays ACTIVE; after it, the operation is not
   rolled back but completed.
5. If the source disappears before handing over the right, the target does not promote itself.
6. While the operation runs, writes are closed and the node is not ready to accept traffic.

Steps — [23 §9](23-ha-manager.md#9-planned-switchover).

## 4. Emergency promotion

1. Only by human decision, never automatically: two nodes cannot tell "the peer died" from "the network broke".
2. The basis is a typed confirmation that the former ACTIVE is stopped, plus the author; both are recorded.
3. Refused if the peer responds and serves traffic: that is a planned switchover.
4. The new epoch, the right, and the fencing of the former ACTIVE are recorded before the node becomes writable.
5. A received but unapplied relay log is applied first; continuing without proof is possible only with
   explicit consent to data loss.
6. A fenced node does not promote itself and does not connect as a replica; it returns to the pair only via reseed,
   and the fencing is lifted by ACTIVE.

Steps — [23 §10](23-ha-manager.md#10-emergency-promotion-and-reseed).

## 5. Split-brain without an arbiter

There is no witness, quorum or automatic arbitration. Safety comes from ordering (demote and drain before handing over
the right), the `read_only` physics, the monotonic epoch, fencing, and a human in the emergency path.

When the link breaks, ACTIVE keeps serving (`ha_healthy=false`), STANDBY does not promote. The price: a fenced
but running former ACTIVE that cannot be reached keeps serving; on first contact it sees
a larger epoch or its own fencing and goes to a safe state.

## 6. Panel write gate

`ha_write_verdict` (`www/include/functions.pm`) — on every mutating request:

| condition | response |
|---|---|
| HA not installed | allowed |
| manager does not respond | `503 ha_manager_unavailable` |
| `ha_configured = null` | `503 ha_state_unknown` |
| `ha_configured = false` | allowed |
| role `unknown` | `503 ha_role_unknown` |
| not ACTIVE | `409 standby_read_only` |
| an HA operation is running on the node | `409 writes_frozen` |
| local `read_only` not read / database unavailable | `503 ha_read_only_unknown` / `503 ha_db_unavailable` |
| ACTIVE, but `read_only=1` | `503 ha_role_mismatch` |

Where it applies: `api.pl` — all `POST/PUT/PATCH/DELETE` after authentication and CSRF; MCP
(`www/mcp/dns-mcp.pl`) — non-readonly tools; background tasks (`libexec/sync-task.pl` via `ha_gate_action`:
`standby_read_only`/`writes_frozen` → skip, other denials → error).

Exceptions in `api.pl` (the manager has its own, stricter gate; authentication, CSRF and permission still apply):
`POST ha/switchover`, `ha/emergency`, `ha/reseed`, `ha/operations/:id/resume`,
`ha/pair/{create,join,approve,reject,reset,build}`.

There is no separate "freeze" flag: writes are closed while the manager's journal has an operation for the node. On every
change of "ACTIVE and no operation", the manager wakes `dns-sync-worker`.

## 7. The panel on a pair node

- **Addresses.** The working entry point is the pair's service address; it leads to ACTIVE. Node addresses are for management: on STANDBY
  the panel shows the state and manages the pair, and writes are rejected by the write gate.
- **Logging in on STANDBY is impossible:** a session is a row in `dns_panel.sessions`, and the database is read-only. `login.pl`
  responds `401` to a wrong password, `409` with `code` (`standby_read_only` | `ha_role_unknown` |
  `ha_manager_unavailable`) and the service address if the node cannot create a session, `503` on other errors.
  The same reason is shown on the login page in advance.
- **`/health/ready`** (`node_health`): `200` only if ready, otherwise `503` with the checks. In a pair with HA
  enabled, the local checks (`panel_db`, `schema`, `pdns_db`, `pdns_control`) are joined by the manager's response and its
  `service_ready`; during an operation — `switching`; ACTIVE without agent confirmation — `degraded`; without
  NOTIFY and publication — `activating`. `/health/live` does not touch the database. The anycast route is determined not by
  `/health/ready` but by the manager's probe ([23 §14.2](23-ha-manager.md#142-anycast-readiness-probe)).
