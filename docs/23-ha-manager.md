# 23 — HA loop: `dns-ha-manager` and `dns-ha-agent`

How the pair's HA loop is built and what it does. Code: `src/dns-ha` (build: [src/dns-ha/README.md](../src/dns-ha/README.md)).
Rules the loop guarantees: [22-ha-contract.md](22-ha-contract.md); production placement:
[13-ha-topology.md](13-ha-topology.md); installing and building a pair: [INSTALL/02-ha-pair.md](INSTALL/02-ha-pair.md).

---

## 1. Node states

```
Standalone ──(pairing, §14.5)──▶ Paired · HA not configured ──(pair build, §14.6)──▶ Paired · HA active
                                            ▲                                                │
                                            └──────────────── dismantle (§11) ───────────────┘
```

| state | what the node has | how it works |
|---|---|---|
| Standalone | no trust in a peer | ordinary standalone node |
| Paired · HA not configured | `peer.key` + a `ha_trusted_peer` record, no effective revision | like a standalone node: writable, PowerDNS `yes/yes`, no publication (decision `ha_not_configured`) |
| Paired · HA active | effective revision of the pair configuration, epoch, the right to be ACTIVE held by one node | ACTIVE / STANDBY roles |

Trust is removed only explicitly (`-pair reset -force`), never because the peer is unreachable.

---

## 2. Processes and the privilege boundary

| process | runs as | what it does |
|---|---|---|
| `dns-ha-manager` | `dns-ha` | observation/decision loop (§8), operations (§9–11), peer channel TCP 7901 (§6), control socket `/run/dns-panel/ha/manager.sock` (0660), anycast readiness probe (§14.2) |
| `dns-ha-agent` | `root` | the only one that changes the node (MariaDB, PowerDNS, address, secrets); only the unix socket `/run/dns-panel/ha/agent.sock`, does not listen on the network |

The network process is not root and has no rights to change the node's role; the root process makes no decisions and
executes a fixed set of typed commands. Group `dns-ha` means "may use HA IPC"; `www-data`
is a member of it, there is no reverse membership (otherwise the network daemon could read `etc/secrets`).

Both units are `Type=notify`: readiness is reported with `sd_notify` once the socket is up (manager: after
the first observation and schema/identity). The manager does not depend on the panel: with Apache stopped the pair
keeps converging.

**Agent commands.** Mutations: `promote`, `demote`, `enable_notifier`, `disable_notifier`, `announce_panel`,
`withdraw_panel`, `rejoin_replica`, `reseed_replica`, `drain_relay`, `emergency_promote`, `stop_replication`,
`release_publication`. Service commands (pairing, pair build and dismantle, publication): `install_peer_key`,
`remove_peer_key`, `install_secret`, `read_secret`, `ensure_pair_grants`, `enable_failsafe`/`disable_failsafe`,
`reset_pair_state`, `resolve_publication_device`, `check_publication`, `address_present`, `drop_address`.
Read: `status`, `preflight`, `inventory`.

Mutation contract:
- `operation_id` and `cluster_epoch` are required; an epoch below the accepted one → `stale_epoch`;
- repeating the same pair (`operation_id`, command) → `ok, noop` without repeating the action (durable done-set);
- the maximum accepted epoch and the done-set live in `/opt/dns-panel/var/agent-state.json` (root 0600, fsync);
- one mutation at a time (flock), otherwise `busy`;
- `status`/`preflight` change nothing and take no lock. `preflight` only confirms that
  the privileged path works (MariaDB is reachable, `read_only` is readable, the replica is not in an explicit error).

The agent changes the PowerDNS role in `/etc/powerdns/pdns.d/90-ha-role.conf` (the `primary`/`secondary` pair): write the
file → check the config → restart → PONG → verify the actual role; not confirmed → `role_unverified`.

---

## 3. The right to be ACTIVE

### 3.1 The role is derived from the right

A node's role is not a string in the database but the state of the **authority** in the safety file (§4.3):

| state | meaning |
|---|---|
| `valid_current` | the right is issued for the current epoch → the node is ACTIVE |
| `stale` | a right from a past epoch is not a right |
| `absent` | no right → STANDBY |
| `foreign_role` | the record is corrupted |
| `unknown` | the safety file was not read → role `unknown`, decisions are only "wait" |

### 3.2 Where the right comes from

| type | who issues it | when |
|---|---|---|
| `bootstrap` | pair build, to the donor (§14.6) | epoch 1 |
| `handoff` | the previous ACTIVE during a planned switchover, after a proven demote and drain (§9) | epoch + 1 |
| `emergency` | the operator, with a typed reason (§10.1) | epoch + 1 |

Accepting a handoff certificate (`handoff_certificate`) checks: `operation_id` is present; the issuer matches
the signing sender; the node is not fenced; the epoch is exactly `max_seen_epoch + 1`; the configuration fingerprint
matches; the node is not yet physically ACTIVE. The right is written to safety **before** the reply; repeating the same certificate
(epoch, issuer, type) is a success.

The right by itself allows a node to **stay** ACTIVE. **Becoming** ACTIVE after losing the physical state
requires additional proof (§8.3).

### 3.3 Epoch

- `max_seen_epoch` lives in the safety file and is monotonic. A planned switchover and an emergency promotion raise it by
  1; reseed and dismantle do not change it.
- The agent keeps its own copy (the maximum accepted `cluster_epoch`); if it is ahead of the safety file,
  `safety_epoch_consistency` in `ha_healthy` turns red.
- A peer with a higher epoch → the node goes to the safe state (§8.2). Peer commands from a past epoch are not
  executed (§6.1).

### 3.4 Physics

`@@global.read_only` still protects the data (`pdns`, `dns_panel`). The right and the physics are checked independently:
ACTIVE with `read_only=1` or non-ACTIVE with `read_only=0` → `role_vs_physics` (manager) and `ha_role_mismatch`
(the panel's write gate, [22 §6](22-ha-contract.md#6-panel-write-gate)).

The pair fail-safe is `etc/mariadb/ha-failsafe.cnf` (`read_only=ON`, `skip_slave_start=ON`), symlinked as
`/etc/mysql/mariadb.conf.d/61-dns-panel-ha.cnf`. It is installed at pair build and removed by dismantle; after
a MariaDB restart a pair node starts read-only and without replication threads, convergence restores the role.

---

## 4. Storage

| what | where |
|---|---|
| pair configuration (revisions), operation journal, state projection, peer-mutation ledger, identity and trust | local MariaDB database `dns_ha` |
| proofs: epoch, right to be ACTIVE, handoff, emergency, fencing, configuration commit proof | file `/opt/dns-panel/var/safety.json` |

### 4.1 `dns_ha` is not replicated

`binlog_ignore_db = dns_ha` and `replicate_ignore_db = dns_ha` in `etc/mariadb/dns-panel.cnf` on both nodes,
`binlog_format = ROW` (the filter works by the table's database). `sql_log_bin=0` is not used: it requires
`BINLOG ADMIN`. The settings are checked continuously (§12.3).

### 4.2 MariaDB access

`'dns-ha'@'localhost'` via `unix_socket` (no password): `ALL` on `dns_ha.*`, globally `READ_ONLY ADMIN`
(to write `dns_ha` on a read-only STANDBY) and `SLAVE MONITOR` (`SHOW REPLICA STATUS`). It has no access to `pdns`/`dns_panel`:
the data inventory for pair build comes from the agent. The installer creates the database and grants; the
manager itself applies the schema (`src/dns-ha/internal/store/dns_ha.sql`, embedded in the binary).

### 4.3 Files

```
/opt/dns-panel/var/safety.json        dns-ha:dns-ha 0600   proofs (below)
/opt/dns-panel/var/agent-state.json   root:root 0600       accepted epoch + agent done-set
/run/dns-panel/ha/                    root:dns-ha 0770     manager.sock, agent.sock, agent.lock, safety.lock
```

`safety.json`: `node_id`, `max_seen_epoch`, `authority`, `committed_config`, `handoff`, `emergency`,
`fenced_node`. The only writer is `safety.Store.Update`: mutex + flock on
`/run/dns-panel/ha/safety.lock` (not on the file itself: it is replaced via rename), re-read before
the change, atomic write. Unknown fields are preserved. Proofs with an epoch above `max_seen_epoch`
are rejected. The file is bound to the node's `node_id`: a foreign one is `safety_foreign`.

### 4.4 `dns_ha` tables

| table | what |
|---|---|
| `ha_schema` | schema version |
| `ha_identity` | node UUID (one row, created at first start, never changes) |
| `ha_trusted_peer` | pairing result: `committing`/`trusted`, peer UUID and address, key and transcript fingerprints |
| `ha_config_revision` | revisions: `STAGED`/`EFFECTIVE`/`REJECTED`, `payload_hash`, `payload_blob` |
| `ha_nodes`, `ha_settings`, `ha_replication`, `ha_publication` | projection of the revision for the panel and SQL (§7.1) |
| `ha_operations`, `ha_operation_steps` | journal of operations and their steps (§9–11) |
| `ha_state` | projection of the observed state |
| `ha_peer_requests` | durable deduplication of peer mutations (§6.1) |

#### 4.4.1 Invariant

`dns_ha` holds no proof of the right at all: epoch, authority, fencing and the configuration commit
proof are only in the safety file. Losing `dns_ha` resets the local loop (new UUID, no revision and no
trust, the pair is built again: [INSTALL/02 §5.4](INSTALL/02-ha-pair.md#54-rebuilding-the-pair-from-scratch)), but it is not
a reason to forget the epoch or fencing. No safety file means no right (`unknown`/`absent`) and no promotion.

### 4.5 Secrets

| file (`/opt/dns-panel/etc/secrets/`) | owner | source |
|---|---|---|
| `peer.key` | `dns-ha:dns-ha 0600` | derived by both nodes during pairing (§14.5), installed by the agent via `install_peer_key` (write-once) |
| `repl.secret`, `ha_monitor.secret` | `root:root 0600` | pair build: the donor's values (or new ones), sent to the peer encrypted (§6), `repl`/`ha_monitor` grants on both |
| `auth-master.key` | root, panel group | donor → receiver after reseed (TOTP secrets in `dns_panel` are encrypted with it) |

The revision holds only `secret_ref`, not values. `panel-db.password`, `pdns-db.password`,
`pdns-api.key` stay local.

---

## 5. Node configuration

`/opt/dns-panel/etc/ha.toml` holds only access to its own database:

```toml
[database]
socket   = "/run/mysqld/mysqld.sock"
database = "dns_ha"
```

Parsing is strict: an unknown key, an unquoted value, the obsolete `node = …` are startup errors. Identity lives
in `ha_identity`. The agent config `ha-agent.toml`: [INSTALL/02 §4](INSTALL/02-ha-pair.md#4-node-configuration).

Everything about the pair (addresses, replication, publication) is in the configuration revision (§7). Operating constants are in the code
(`internal/config/platform.go`, the port in `cmd/dns-ha-manager/pairing.go`):

| parameter | value |
|---|---|
| observation period | 3 s |
| agent / peer call timeout | 5 s |
| allowed clock skew (`ts`) | ±30 s |
| age of a peer snapshot usable as proof | ≤ 30 s |
| peer message limit | 64 KiB |
| peer port | 7901 |

`settings` in the revision are stored and carried over but not read by the runtime.

---

## 6. Peer channel

One listener on TCP 7901 for pairing (§14.5) and the pair protocol. While there is no revision, it listens on all addresses;
after that, on `peer_listen_host:peer_listen_port` from its own row of the revision.

- Envelope `{body, sig}`: `sig = hex(HMAC-SHA256(peer.key, body))` over the **exact bytes** of `body`.
  `peer.key` is 64 hex characters, the format is checked on load.
- Request: `protocol_version` (1), `message_id`, `sender_node_id`, `recipient_node_id`, `epoch`, `ts`, `nonce`,
  `cmd`, `payload`, `payload_hash`, `request_hash`.
- Checks: signature, protocol version (mismatch: `peer_protocol_version`), sender = expected peer,
  recipient = me, `ts` within the ±30 s window (**node clocks must be synchronized**), single-use `nonce`,
  command whitelist, `payload_hash`, size.
- The reply is bound to the request (`request_message_id`, `request_nonce`, sender, `ts`) and signed; the client
  verifies all of it, so an old signed reply cannot be replayed.
- Traffic is not encrypted. Secrets at pair build are encrypted with AES-256-GCM using the key
  `HKDF(peer.key, "dns-panel secret transfer v1")`.

| class | commands |
|---|---|
| read | `hello`, `status`, `inventory`, `operation_journal` |
| pair build (accepted only while the node has no effective revision) | `init_prepare`, `init_reseed`, `init_finish`, `init_seed`, `init_device`, `init_recap`, `init_check` |
| mutations | `config_stage`, `config_commit`, `prepare_switchover`, `await_gtid`, `handoff_certificate`, `clear_fencing`, `release_pair` |

Before pair build (only trust exists) the channel is brought up from `ha_trusted_peer` in read mode: new mutations
are rejected, the ledger only answers repeats of already executed ones.

### 6.1 Mutations

- Executed only with the full set: ledger (`ha_peer_requests`) + gate + executor; if any is missing,
  a typed refusal (`peer_ledger_unavailable`, `peer_mutation_gate_unavailable`).
- Registering the request and the action are one transaction. `message_id` denotes a logical action and
  is kept across attempts (`nonce`/`ts` are fresh for each): a repeat returns the same result; the same
  `message_id` with a different meaning is `peer_message_id_conflict`. Substantive refusals are not cached: after
  the node is fixed, a repeat is checked again.
- Recipient gate: the safety file is valid, the epoch is known, the recipient is not fenced, the request epoch is not below its own
  (`config_stage`/`config_commit`: strictly equal), the recipient itself is not ACTIVE, except for `clear_fencing`, which
  is decided precisely by the ACTIVE. Refusal: `peer_mutation_not_allowed` / `peer_epoch_mismatch`.

---

## 7. Pair configuration revisions

### 7.1 Model

The pair configuration is a revision: nodes (UUID; name, hostname, site, description are for humans only;
`peer_listen_host/port`, `replication_host`, `publication_device`, `admin_ip`), publication
(`provider`, `params`), replication (`port`, `user`, `secret_ref`), `settings`. It is stored as canonical bytes
`payload_blob` and their SHA-256 `payload_hash`; an identical `payload_hash` on both nodes is what "one
configuration" means.

The manager takes the working configuration **only** from `payload_blob`: hash of the bytes themselves → compare with
`payload_hash` → parse → end of data → compare with the canonical form (`config_payload_hash_mismatch`,
`config_payload_not_canonical`). The `ha_nodes`/… tables are a showcase; a divergence is `config_projection_drift` in
`ha_healthy`.

The replication source is a property of the node: the STANDBY connects to the `replication_host` of the node that is provably ACTIVE
(`observe.ExpectedReplicationSource`; the planner, health and the plan use the same address).

Revision 1 is created at pair build (§14.6).

### 7.2 Committing a revision

Only on the ACTIVE (panel: `PUT /ha/config`, `PUT /ha/publication`); the manager assigns the number (current + 1):

```
1. stage locally
2. config_stage → the peer stores the same bytes as STAGED
3. commit locally: committed_config proof in safety (fsync) → STAGED→EFFECTIVE
4. config_commit → peer: proof → EFFECTIVE
```

If the peer is unreachable at step 2, the revision is applied nowhere. If step 4 is lost, the ACTIVE is on the new revision and the peer is in
`STAGED`: `config_agreement` in `ha_healthy` turns red (`config_commit_unsynced`), repeating the commit completes it.

### 7.3 Rules

- Only the ACTIVE initiates; on the STANDBY the configuration is read-only.
- A planned switchover and reseed require the same fingerprint on both sides; so does the peer confirmation for
  promotion (§8.3).
- Content is validated on both sides before saving.

### 7.4 Channel parameters are immutable

A revision that changes `peer_listen_host`/`peer_listen_port` is rejected
(`config_transport_change_requires_rotation`): with asymmetric application the channel breaks, and there is nothing left
to deliver the commit over. There is no rotation; changing the channel address means rebuilding the pair.

### 7.5 Commit order and recovery

On the node: check STAGED (hash, bytes) → proof in safety (temp → fsync → rename → fsync of the directory) →
`STAGED→EFFECTIVE` and marking the request `DONE` in one transaction. On every start, before reading the effective
revision, `recoverConfigCommit` compares the proof with the database: `EFFECTIVE` with the same hash — nothing to do;
`STAGED` with the same hash — the commit is completed; otherwise a log message, it is not silently repaired.

---

## 8. Continuous convergence

Every 3 s:

```
ensure     bring up what is not up yet: peer channel, operation journal, finish pairing/commit
operation  whether the node has a current operation (journal unavailable → assumed it does)
observe    agent (status, preflight), dns_ha, safety.json, replication, my_print_defaults, peer status
health     service_ready / ha_healthy (§12)
plan       planner.Plan(observation) → decision; shadow.Build → exact list of agent commands
execute    if an operation is running, its step (§9–11); otherwise the convergence plan
publish    status to the socket and to the peer; on a change of "ACTIVE and no operation", wake dns-sync-worker
```

The planner works on the raw observation, not on the health verdict. dns-sync-worker is woken by a datagram to
`/run/dns-panel/sync/wake.sock`; a missing worker is not an error.

### 8.1 Steady state is NOOP

A command is sent to the agent only when the observation has proven a divergence between desired and actual; the agent's
idempotency is the second line of defense, not a reason to call it idly. Each convergence attempt gets a new `operation_id`
(`conv-<epoch>-<ns>`): with the old one the agent would answer `noop` from the done-set.

### 8.2 Decisions

Rules in order, the first one that fires decides (`internal/planner`):

| # | condition | action / reason |
|---|---|---|
| 0 | agent does not respond / `read_only` is not observed | `hold` / `agent_unavailable` |
| 0.1 | HA not configured (no revisions) | `restore_active` or `noop` / `ha_not_configured` |
| 1 | node is fenced (by its own safety or by the peer) | `demote_safe` (if writable/published) or `hold` / `fenced_self` |
| 2 | peer has a higher epoch | `demote_safe` or `hold` / `peer_newer_epoch` |
| 3–4 | writable or published without a valid right | `demote_safe` / `no_active_authority`, `standby_physically_writable` |
| 5 | right present, writable, NOTIFY, publication, `secondary` | `noop` / `steady_active` |
| 6 | right present, writable, but PowerDNS/publication not confirmed | `restore_active` / `active_services_degraded` |
| 7 | right present, but the node is read-only (physics lost) | `promote` only per §8.3, otherwise `hold` |
| 8 | STANDBY, replication unhealthy | `rejoin` to a confirmed ACTIVE, otherwise `hold` / `replication_broken`, `peer_unconfirmed` |
| 9 | STANDBY with NOTIFY or `secondary=yes` | `quiet_standby` (`disable_notifier`) |
| — | otherwise | `noop` / `steady_standby` (or `hold` / `role_unknown` if the right was not read) |

Plans:
- `demote_safe`: `disable_notifier`, `withdraw_panel`, `demote`, always all three, independently of each other;
- `promote`: `promote`, `enable_notifier`, `announce_panel` until the first failure; rollback: `withdraw_panel`,
  `disable_notifier`, `demote` under a separate `operation_id` (`…-rollback`);
- `restore_active`: only what is missing (for `ha_not_configured`, also `promote`, without publication);
- `rejoin`: `rejoin_replica` to the source from §7.1.

The executor (`internal/execute`) decides nothing: it runs all protective steps, and aborts promoting steps at the first
failure or at a reply without a proven state (a repeat from the done-set) and rolls them back; outcome `needs_reobserve`.

### 8.3 "Stay ACTIVE" ≠ "become ACTIVE"

- **Stay.** Right `valid_current` and the node physically ACTIVE: it keeps working; peer unavailability does not
  change the role (only `ha_healthy=false`).
- **Become** (the right is present but `read_only=1`, e.g. after a MariaDB restart) requires one more of:
  - a handoff right during its own operation (taking over the role in a planned switchover);
  - a fresh peer confirmation: snapshot ≤ 30 s, the peer considers itself STANDBY and is physically standby
    (`read_only=1`, NOTIFY and publication explicitly off), same epoch, same configuration, nobody fenced,
    the peer has no operation.

  Without it: `hold`, because while the node was down the pair could have moved to a new epoch via emergency.
- A **STANDBY** without a peer stays STANDBY and does not promote itself; `rejoin` goes only to a confirmed ACTIVE.

---

## 9. Planned switchover

Started on the ACTIVE: panel `POST /ha/switchover {target?}` or
`sudo -u dns-ha dns-ha-manager -switchover [-to <node>]`. An operation `sw-<node>-<epoch>[-tryN]`
(`PENDING`) is created, new epoch = `max_seen_epoch + 1`. A node has one operation at a time. The **source** drives it.

| step | what |
|---|---|
| `preflight_local` | I am ACTIVE with the right, not fenced, operation epoch = mine + 1, agent preflight ok, the peer is observed fresh, configurations match |
| `preflight_peer` | `prepare_switchover`: target is not ACTIVE, not fenced, epoch is newer, same configuration fingerprint, agent and preflight ok, replication `IO=Yes SQL=Yes`, an interface for the service address exists |
| `disable_notifier`, `withdraw_panel`, `demote` | the source stops being the zone source, withdraws publication, `read_only=1`; then waits to observe `read_only=1` |
| `drain_gtid` | `await_gtid`: the target runs `MASTER_GTID_WAIT(<source GTID>, 60)`; an empty position (empty binlog) means nothing to wait for |
| `handoff_record` | **point of no return**: in the source's safety, in one record: new epoch, handoff trace, own right removed |
| `handoff_deliver` | `handoff_certificate`: the target accepts the right (§3.2) and opens the operation on its side |
| (wait) | peer `role=active` and `service_ready` |
| `rejoin_replica` | the source connects as a replica to the new ACTIVE from the position of its own binlog (`seed_from_binlog`) |
| `verify` | locally `read_only=1`, `IO/SQL=Yes`; the peer is ACTIVE and `service_ready` |

The target is promoted by its own convergence (§8.3: handoff during an operation → `promote`, `enable_notifier`,
`announce_panel`) and closes its operation record once it has physically become ACTIVE.

Failures:
- before `handoff_record`: `ABORTED`; agent commands ran in the current epoch, the right is untouched, convergence
  restores the services;
- after it: the operation stays `RUNNING` with a reason and is retried every cycle (all steps are idempotent).

While an operation is running, `service_ready=false` (the probe is closed), and the panel's write gate answers `409 writes_frozen`.

---

## 10. Emergency promotion and reseed

### 10.1 Emergency promotion

On the surviving node: panel `POST /ha/emergency {ack, accept_relay_loss?}` (right `ha.emergency`) or
`sudo -u dns-ha dns-ha-manager -emergency -ack <reason> -operator <who> [-accept-relay-loss]`.
It never happens automatically.

Reasons (`ack`): `old_active_database_stopped` | `old_active_host_down` | `operator_isolated`.

| step | what |
|---|---|
| `preflight_local` | reason from the list, author specified, node is not ACTIVE, operation epoch = mine + 1, not fenced itself, agent reachable; refused if the peer answers with a fresh snapshot, considers itself ACTIVE **and** `service_ready` (that is a planned switchover) |
| `fence_record` | **point of no return**: in safety: new epoch, `emergency` right, `fenced_node` = the previous ACTIVE, record of reason and author |
| `relay_loss_accepted` | only with `accept_relay_loss`: the consent to the loss is recorded before the dangerous step |
| `emergency_promote` | agent under one lock: `STOP SLAVE IO_THREAD` → wait for the SQL thread to apply the relay log → `STOP SLAVE` (strictly `No/No`) → `read_only=0`. Drain not proven → refusal unless `accept_relay_loss` |
| `enable_notifier`, `announce_panel` | NOTIFY and publication |
| `verify` | the node is physically ACTIVE and holds the right |

Failure before `fence_record`: `ABORTED`; after it: `FAILED` without rollback (continue with `resume`, §10.3).

The fenced node (`RESEED_REQUIRED`) sees `fenced_node` on the peer: it does not promote itself and does not connect
as a replica; if writable/published, it goes to the safe state (§8.2, rule 1).

There is no automatic SOA serial reconciliation. If edits that already reached the secondaries are lost with `accept_relay_loss`,
the zone serial in the new database may turn out not higher than the published one; such zones must be checked manually.

### 10.2 Reseed

On the fenced node: panel `POST /ha/reseed` (`ha.emergency`) or `sudo -u dns-ha dns-ha-manager -reseed`.
The epoch does not change.

| step | what |
|---|---|
| `preflight_local` | node is not ACTIVE, agent reachable, the peer is observed fresh and ACTIVE, operation epoch = peer epoch, configurations match |
| `accept_epoch` | accept the pair's epoch, erase its own right and handoff |
| `reseed_replica` | agent: full dump of `dns_panel` and `pdns` from the ACTIVE (account `ha_monitor`), then replication; `dns_ha` is not touched |
| `verify` | `read_only=1`, `IO/SQL=Yes`, the source is the expected one |
| `unfence` | `clear_fencing` on the ACTIVE: only the ACTIVE removes fencing, and only if it sees the node fresh and read-only |

### 10.3 Resuming

`POST /ha/operations/:id/resume {accept_relay_loss?}` or `dns-ha-manager -resume -id <id> [-accept-relay-loss]`:
a `FAILED`/`ABORTED` operation becomes `RUNNING` again if it belongs to the node, its epoch equals the current or
the next one, and there is no other operation. Completed steps are skipped according to the journal. Dismantle is never
resumed. Journal and steps: `dns-ha-manager -operation [-id <id>]`, panel `GET /ha/operations[/:id]`.

---

## 11. Dismantling the pair

Only on the ACTIVE, only from the panel: `POST /ha/dismantle` (`ha.emergency`, a confirmation phrase must be
typed). The result is "Paired · HA not configured": the data on both nodes remains, trust remains, the epoch
does not change.

| step | what |
|---|---|
| `preflight` | I am ACTIVE, the peer is reachable and STANDBY, no other operations |
| `freeze_writes` | `demote`: I stop accepting writes |
| `drain_gtid` | the peer has applied everything I wrote |
| `peer_release` | `release_pair`: the peer stops replication, removes the fail-safe, becomes writable, drops the address, deletes the pair records |
| `local_release` | locally: reset the replica configuration, remove the fail-safe and publication, writable again |
| `verify` | HA is off on both and both are writable |
| cleanup | pair records and journal on its own node (not journaled) |

Failure before `peer_release`: cancellation with writes restored; from `peer_release` on, forward only (retried every
cycle).

---

## 12. Health: `service_ready` and `ha_healthy`

Two independent verdicts (`internal/health`). `service_ready`: whether traffic may be sent to the node (it
opens the probe, §14.2); `ha_healthy`: whether the pair loop is sound (panel, alerts). Redundancy problems
(peer, configuration, prerequisites) do not turn `service_ready` red. `unknown` counts as failure everywhere.

### 12.1 `service_ready`

Checks: `agent`, `writable`, `pdns_primary`, `pdns_secondary` (on the ACTIVE; an agent without the field does not turn it red),
`published`, `service_address` (anycast: the service address accepts TCP/53), `not_frozen` (no operation),
`role_vs_physics`, `active_authority`. A STANDBY is `service_ready=false` by definition. On top of that the manager
closes readiness if an operation is running or the operation journal is unavailable, and if the anycast probe did not open
(`readiness_probe`).

### 12.2 `ha_healthy`

`mysql_prerequisites`, `store` (`dns_ha` reachable, schema complete, configuration read), `safety_store`,
`peer_reachable`, `peer_epoch`, `safety_epoch_consistency`, `peer_observation_fresh` (≤ 30 s),
`config_agreement`, `config_projection`, `agent_preflight`, `replication` (the ACTIVE does not replicate; the STANDBY
`IO/SQL=Yes` from the expected source), `fenced_node`, `anycast_address` (the old anycast address is still on `lo`),
`pdns_role` (ACTIVE and a node without HA: `yes/yes`, STANDBY: `no/no`), `agent`.

### 12.3 MariaDB prerequisites

The saved configuration is checked (`my_print_defaults mysqld`, not runtime: `skip-slave-start` is not a
system variable, and runtime `read_only` on the ACTIVE says nothing about the next start):

| option | required |
|---|---|
| `read_only` | `ON` |
| `skip-slave-start` | `ON` |
| `gtid_strict_mode` | `ON` |
| `binlog_format` | `ROW` |
| `log_slave_updates` | `ON` |
| `binlog-ignore-db`, `replicate-ignore-db` | `dns_ha` among the values (only once the `dns_ha` schema exists) |

A divergence is `mysql_prerequisite_drift: <option>: want …, got …` in `ha_healthy`; it does not take traffic off the node.

---

## 13. Panel and control socket

The panel is a thin facade: it contains no HA logic, decisions and substantive refusals belong to the manager.

**Socket** `/run/dns-panel/ha/manager.sock`: one JSON request line, one reply line
(`{ok:true, result}` / `{ok:false, error, message}`); an empty request = `status`. Commands: `status`, `config`,
`config_apply`, `publication_apply`, `operations`, `operation`, `switchover`, `emergency`, `reseed`,
`dismantle`, `resume`, `pair_status`, `pair_inventory`, `pair_devices`, `pair_create`, `pair_join`,
`pair_approve`, `pair_reject`, `pair_reset`, `pair_build`. Deadline: `pair_build` 15 min; `pair_join`,
`pair_approve`, `pair_reset`, `pair_inventory`, `publication_apply` 2 min; the rest 30 s.

```bash
echo '{"cmd":"status"}' | sudo -u dns-ha nc -U /run/dns-panel/ha/manager.sock
```

`status`: health verdict (`role`, `service_ready`, `ha_healthy`, `reason`, `service_checks`, `ha_checks`),
`decision`, `would_execute`, `execution` (`mutations_attempted`, `outcome`, `operation`), `pair` (cards
`self`/`peer`, publication, `config_revision`/`config_hash`, `ha_configured` — `true`/`false`/`null`,
`fenced_node`, `authority`, replication), `probe` (anycast only).

**REST** (`www/API/Router.pm`, via `ha_manager_request` in `functions.pm`):

| route | right |
|---|---|
| `GET /ha/status`, `GET /ha/config`, `GET /ha/operations`, `GET /ha/operations/:id` | `ha.manage` |
| `PUT /ha/config`, `PUT /ha/publication`, `PUT /ha/pair-address` | `ha.manage` |
| `POST /ha/switchover` | `ha.manage` |
| `POST /ha/emergency`, `POST /ha/reseed`, `POST /ha/dismantle` | `ha.emergency` |
| `POST /ha/operations/:id/resume` | by operation type: emergency/reseed/dismantle or an unknown type, and also `accept_relay_loss` — `ha.emergency`; otherwise `ha.manage` |
| `GET /ha/pair`, `/ha/pair/inventory`, `/ha/pair/devices`; `POST /ha/pair/{create,join,approve,reject,reset,build}` | `ha.manage` |

Intents answer `202` with `operation_id`, a manager refusal is `409`, manager unavailable is `503`; everything is written to the
audit log with the author (`requested_by`). `accept_relay_loss` is accepted only as a JSON boolean. The write gate and its
exceptions for these routes: [22 §6](22-ha-contract.md#6-panel-write-gate).

UI: the High availability page (`www/js/ha.js`): pairing, pair build, state of both nodes,
operations, publication settings.

---

## 14. Node: publication, layout, pairing, pair build

### 14.1 Publishing the service address

The provider and address are in the revision (`publication.provider`, `publication.params`); each node has its own interface
(`publication_device` in the node's row, the node determines it itself from the address/route).

| provider | "published" = | withdrawal |
|---|---|---|
| `floating_ip` | the address is up on the interface (the truth is `ip -o addr show`, not the return code); after bringing it up, three gratuitous ARPs | the address is removed; failure to remove is an error (two owners of the address are not allowed) |
| `anycast` | the readiness probe is open (§14.2); the `/32` is permanently on `lo` of both nodes | the address is not removed: both `announce_panel` and `withdraw_panel` keep it up, only the marker changes |
| `marker` | the address is managed by an external mechanism (BGP daemon, load balancer); the agent only maintains the intent marker | — |

The agent unit allows `AF_NETLINK` (`ip addr`) and `AF_PACKET` (ARP).

### 14.2 Anycast: readiness probe

The probe TCP port (`probe_port` in `publication.params`, ≥ 1024; the UI hint is 17900) is held by the manager itself
(`internal/probe`): the port is open exactly when `service_ready`. There is no protocol inside, only the handshake.

```
ACTIVE + service_ready     open
ACTIVE degraded, operation closed
STANDBY                    closed
manager died               closed (the socket goes away with the process)
```

Where to route is decided by the external network based on the probe: Cisco IP SLA `tcp-connect` + track, BGP or
[dns-watcher](INSTALL/reference/07-dns-watcher.md). The panel knows nothing about routing and shows only
`TCP <port> open`. The actually open port is reported in `probe.open_port` and to the peer.

### 14.3 Changing the address and port on a live pair

`PUT /ha/publication` (`publication_apply`): resource check on both nodes and a new revision (§7.2). The nodes open the new
port through their convergence; each node drops the old anycast address itself (`drop_address`), and while it is
still there, `anycast_address` shows in `ha_healthy`.

### 14.4 Layout

```
/opt/dns-panel/
├── bin/    dns-ha-manager, dns-ha-agent, dns-agent, dns-sync-worker, dns-watcher, sync-task.pl, utilities
├── etc/    panel.toml, ha.toml, ha-agent.toml, secrets/, mariadb/, systemd/, tmpfiles/
├── var/    safety.json, agent-state.json — only what must be readable without the database
├── www/    web application (/var/www/vhost/dns-panel → here)
└── docs/

/run/dns-panel/               tmpfiles.d (etc/tmpfiles/dns-panel.conf)
├── ha/     root:dns-ha 0770      manager.sock, agent.sock, agent.lock, safety.lock
├── pdns/   pdns:www-data 2750    dns-agent socket
└── sync/   www-data:dns-ha 2750  dns-sync-worker wake socket
```

The directories in `/run` are split along the privilege boundary and created by tmpfiles with a fixed owner (not
`RuntimeDirectory=`: the directory is shared by processes running as different users). The manager has
`ProtectSystem=strict`, so `ReadWritePaths=/opt/dns-panel/var /run/dns-panel/ha` is mandatory: without it
it cannot commit the epoch and the right.

### 14.5 Pairing

CLI (the panel does the same via the socket; the attempt lives in the memory of the running manager):

```bash
dns-ha-manager -pair create                    # A: 10-minute window
dns-ha-manager -pair join -address <A>[:port]  # B: prints six digits
dns-ha-manager -pair status                    # A: code, peer node_id, claimed hostname, observed address
dns-ha-manager -pair approve                   # A: the digits match
dns-ha-manager -pair reject | -pair reset [-force]
```

- Without an open window, pairing commands are rejected; one request is accepted at a time (`pairing_busy`).
  A node that already has trust or `peer.key` does not pair.
- `pair_hello` (commitment of the responding side A) → `pair_request` (disclosure of ephemeral X25519 keys) →
  both sides compute a six-digit code from the transcript. The commitment prevents fitting a key to a code.
- `pair_commit` (after Approve; signed with the session key `HKDF(…, "dns-panel pairing session v1")`, with
  direction) → each side derives `peer.key = HKDF(X25519 secret + transcript, "dns-panel peer
  key v1")` itself; the key is never sent over the network. Order: write `ha_trusted_peer` (`committing`) → agent
  `install_peer_key`.
- `pair_complete` (signed with `peer.key`, idempotent) → `trusted`.
- Nothing is written before Approve; a restart closes the window. An interrupted pairing is not recovered but
  reset (`-pair reset`: `remove_peer_key` by fingerprint, then the record) and repeated.
- The code binds the keys and identities of the sides, but not the hostname shown next to it. The management network is considered
  trusted.

### 14.6 Pair build

```bash
dns-ha-manager -pair inventory     # what is in the databases of both nodes
dns-ha-manager -pair build -provider floating_ip|anycast|marker [-address <CIDR>] [-probe-port N] [-id <id>]
```

Run on the **donor**, the node whose data remains; the receiver's data is replaced, there is no merge. Steps
(`internal/pairsetup`):

| # | what | donor / receiver |
|---|---|---|
| 0 | check the human decisions (provider, address, port), "HA is not configured here yet", whether the port and address are free on both | nothing changes |
| 1 | `repl.secret`, `ha_monitor.secret`: the donor's values (created if absent) | donor |
| 2 | `init_prepare`: secrets (encrypted), grants for the donor; the receiver reports its interface | receiver |
| 3 | grants for the receiver (before replication starts) | donor |
| 4 | revision 1 is assembled and validated | — |
| 5 | `init_reseed`: `ReseedReplica(donor)` with a check of `IO/SQL=Yes` and the position | receiver, **irreversible** |
| 6 | `init_finish`: the donor's `auth-master.key` | receiver |
| 7 | `init_seed`: fail-safe + revision 1, epoch 1 → STANDBY | receiver |
| 8 | fail-safe + revision 1 + `bootstrap` right, epoch 1 → ACTIVE; publication via convergence | donor |

Until step 5 both nodes remain working standalone nodes. Retrying an interrupted attempt is the same command with `-id`:
reseed is not repeated, a half-built pair is completed with the same content.

A standalone installation is HA-ready from the start (`deploy/install.sh` + `etc/mariadb/dns-panel.example.cnf`: binlog, ROW, GTID strict,
`log_slave_updates`, `*-ignore-db = dns_ha`, random `server_id`), so pair build does not edit `my.cnf` and
does not restart MariaDB: the fail-safe is added as a separate file, and the agent sets the current `read_only`.
