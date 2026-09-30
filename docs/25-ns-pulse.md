# 25 — NS Pulse: testers and record switching

NS Pulse checks the reachability of specific addresses from remote sites and, based on the results, switches
RRsets in the panel's zones. Its second mode is **Pinger** (slow sweep): an unhurried pass over all A/AAAA addresses
to see which of them have not answered for a long time.

Related: [22-ha-contract.md](22-ha-contract.md) and [23-ha-manager.md](23-ha-manager.md) (the right to write),
[24-dns-engine.md](24-dns-engine.md) (the record edit path), [16-delivery.md](16-delivery.md) (where zones
go). Installation — [INSTALL/01-standalone.md](INSTALL/01-standalone.md), section "NS Pulse". Code: `src/dns-pulse`,
`libexec/pulse-apply.pl`, the NS PULSE section in `www/include/functions.pm`, `www/js/pulse.js`.

---

## 0. What it does and does not do

- **ICMP** and **TCP connect** checks against a specific IP (not a name: after the first switch, a check of the
  switched name would already be checking a different host). There are no application-level checks (HTTP etc.);
- a check is assigned to tester **groups** (many-to-many); see the caveat about per-agent assignment in §6;
- a rule on an RRset: **ordered branches** "if conditions — publish such-and-such set", at the bottom always
  "otherwise — the default set"; conditions on check state and on schedule;
- history — state bars (intervals in MariaDB, no separate metrics store);
- Pinger is observation only: it creates no rules and does not affect DNS.

There are no different answers for different networks (BIND `view`), no weights and no geography: a rule changes an ordinary zone, and
all of its recipients get the change. The agent knows nothing about zones and records — only addresses.

---

## 1. Parts

| Part | Where | What it does |
|-------|-----|------------|
| `pulse-server` (Go) | panel node | accepts agents, hands out tasks, writes states to `dns_panel`, keeps deadlines, decides on switching |
| `pulse-agent` (Go) | any site | connects to the server itself, runs probes, sends only transitions; takes part in Pinger |
| `libexec/pulse-apply.pl` | panel node | started by the server; switches the set through `pdns_apply_rrsets` or verifies the zone (`--verify`) |
| NS Pulse page | panel | tabs **Agents / Checks / Rules / History** |
| Pulse column, Pinger dot | records page | entry to the RRset rule and to the address history (§6, §7) |
| Settings → **Pinger & Pulse** | panel | Pinger parameters, new-check template, history retention |

There are no network checks in the panel's web requests. Binaries are built with `make -C src/dns-pulse build`
(static, `CGO_ENABLED=0`); the agent uses the standard library + `x/net/icmp`, the server also a MySQL driver.

### Agent config

```toml
server      = "10.0.0.10:7902"
enroll_key  = "…"      # shared site key
fingerprint = ""       # SHA-256 of the server certificate (64 hex); empty — remember on first connection
log_level   = "info"   # debug | info | warn
#[reconnect]           # reconnect pause, default 1s…30s
#min = "1s"
#max = "30s"
```

Any other key is a startup error: targets, intervals and thresholds come only from the panel. The file is identical on
all machines: it contains no personal secret, name or id. **NS Pulse → Agent config** shows a ready-made file (address,
key, fingerprint); the server address is stored in `settings.pulse_server_address` and is set there too.
The `-no-icmp` flag forbids ICMP to the agent even when it has the privileges. The log goes to stdout (journald).

### Agent enrollment

1. On first start the agent creates the key `agent.key` in `StateDirectory` (64 hex) and prints to the log a code
   like `7F3A-91C2` — the first 8 characters of the key's SHA-256. The server stores only the hash (`pulse_testers.key_hash`).
2. An unknown key with a correct `enroll_key` is a request: a row in `pulse_testers` without `approved_at`, the reply is
   `goodbye "waiting for approval in the panel"`. Repeated connections update the same row.
3. A person sees the request (host name, address, code) in **Agents → Waiting for approval**, approves it, gives it a name
   and a location. The agent learns its name from `welcome`.

Until approval there are no tasks and no result writes. `enroll_key` is stored in plain text (`pulse_enrollment`) and
only grants a place in the queue; changing the key (`POST /pulse/enrollment/key`) closes the door to unapproved agents
and does not affect approved ones. Deleting a tester means "forget": a running agent comes back as a request.

The address the agent came from is written to `pulse_testers.addr` and shown; only the key identifies the agent.

### TLS and fingerprint

TLS is always on (minimum TLS 1.2). On first start the server generates a self-signed certificate
(ECDSA P-256, 10 years) and puts it into `pulse_server_tls` — the certificate belongs to the **pair** and is replicated
with `dns_panel`, so an HA role change does not change the fingerprint.

The agent does not check the name in the certificate; it compares the SHA-256 of the DER certificate:

- an explicit `fingerprint` in the config always takes precedence over the remembered one;
- an empty one is remembered on the first connection (`server.fingerprint` in `StateDirectory`, atomically, before
  sending the key); after that the same one is required, and on a change the agent refuses with a message about substitution;
- the protocol supports a "next fingerprint": `next_fingerprint` from the server is saved next to the current one,
  the agent replies `fingerprint_ack`; after the first full session with the new one it becomes current.
  **The server does not send `next_fingerprint` yet** — rotating the certificate currently requires editing the agents.

### Agent privileges for ICMP

The `pulse-agent.service` unit: not root, `AmbientCapabilities=CAP_NET_RAW`, `NoNewPrivileges`. An
unprivileged ping socket (`net.ipv4.ping_group_range`) also works. The agent checks whether ICMP is possible at start and
reports it in `hello`; without ICMP the server gives it no ICMP tasks (the pair stays without data → `unknown`), and
the agent does not take part in Pinger. Missing privileges never turn into `down`.

### Reconnection

A disconnect is a normal state (the service address moves between nodes). The agent reconnects with a growing
pause (`reconnect.min…max`), **checks continue** — they belong to the process, not the connection, and
hysteresis is not reset. After connecting, the agent sends the current state of all checks. The send queue
keeps the last message of each kind (the last state for each check), so
what accumulated during the disconnect is not replayed.

---

## 2. The right to change DNS

- `pulse-server` asks `dns-ha-manager` for the role (`{"cmd":"status"}` over `ha.socket`) on the handshake,
  on **every** agent message, when deadlines fire and on recomputations. The answer is cached for
  `timeouts.ha_verdict_ttl` (1 s). No answer or `ha_configured` unknown — refusal. `ha.enabled = false`
  (a node without HA) — observing is always allowed.
- "Allowed to observe" = role `active` (or HA is not configured). An HA operation in progress does not hinder observation: it
  freezes writes to zones, not the intake of results.
- **STANDBY does not accept agents**: `goodbye "this node is not active — connect to the service address"`.
  Having lost the role, the server drops all deadlines, holds, retries, Pinger rebuilds and cuts agent streams.
- Only `pulse-apply.pl` writes to a zone, through `pdns_apply_rrsets` (transaction, serial, audit).
  It asks for the write right itself, with the same `ha_write_verdict` as the panel; `skip` (not our node,
  freeze) and `fail` mean refusal, and the server retries the switch with a growing pause.
- Agents do not edit DNS: they report what they saw.

---

## 3. Agent ↔ server protocol

One long-lived TLS connection, one JSON object with a `type` field per line (up to 1 MiB), `internal/wire`. Not gRPC.

| Message | Who | Content |
|-----------|-----|-----------|
| `hello` | agent | `agent_key`, `enroll_key`, `hostname`, `run_id`, `version`, `can_icmp`, `can_ipv4`, `can_ipv6` |
| `welcome` | server | `tester_id`, `tester_name`, `confirm_every_seconds` |
| `assign` | server | `tasks[]` — the full set: `check_id`, `config_version`, `kind`, `target_ip`, `port`, `interval_seconds`, `timeout_ms`, `probes_per_run`, `ok_probes_required`, `fail_threshold`, `ok_threshold` |
| `accepted` | agent | `checks[]` (`check_id`, `config_version`) — the accepted set |
| `transition` | agent | `check_id`, `config_version`, `state` (`healthy`/`degraded`/`down`), `detail` |
| `confirm` | agent | `checks[]` — what is running now; an empty list is sent too |
| `next_fingerprint` / `fingerprint_ack` | server / agent | fingerprint rotation (§1) |
| `sweep_claim` / `sweep_batch` / `sweep_result` | Pinger (§7) | |
| `goodbye` | server | `reason` |

```text
{"type":"hello","agent_key":"…","enroll_key":"…","hostname":"cn-probe-01","run_id":"…","can_icmp":true}
← {"type":"welcome","tester_id":1,"tester_name":"msk-1","confirm_every_seconds":30}
← {"type":"assign","tasks":[…]}
{"type":"transition","check_id":7,"config_version":3,"state":"down"}
{"type":"confirm","checks":[{"check_id":7,"config_version":3}]}
```

`goodbye` reasons: `waiting for approval in the panel`, `enrollment key rejected`, `this tester is switched
off in the panel`, `this tester is no longer allowed to report`, `superseded by a newer connection`,
`check-in interval changed — reconnect for the new one`, "node is not active" (§2).

**The agent sends no measurements** — only transitions, the state after (re)connecting, and confirmations.
Timestamps are set by the server.

**Per-task confirmation.** `confirm` every `confirm_every_seconds` = `confirm_max_age_seconds / 3`
(at least 1 s). Freshness is stored on the pair (`pulse_results.confirmed_at`) and is advanced by a result for the pair
or by a confirmation listing the pair with the **current** `config_version`; a live TCP connection gives no freshness.

**The task version** (`pulse_checks.config_version`) grows only when the measurement changes: kind, address,
port, interval, timeout, probes, thresholds. Renaming, the on/off switch and the set of runners do not change it.
When the version grows, the panel immediately moves the pairs to `unknown/stale_config`; the server
ignores a result for the old version.

**Delivering edits.** There is no "tasks changed" signal from the panel to the agent. The server compares the list in
every `confirm` with the effective set and, on a mismatch, sends the full `assign` — an edit arrives no
later than `confirm_every_seconds`. The agent applies the set as a whole; it does not restart a check with the same
version.

**One tester — one stream.** A new connection supersedes the previous one; the server tags every stream with its
generation and on every message checks that the stream is current, otherwise — `goodbye` without writing. `run_id`
(new on every process start) is for people: a supersession with a different `run_id` is logged by the server
as "a second copy is running nearby". This is not shown on the tester card.

**Revocation.** On every message the server rereads the tester row: deleted, switched off, not approved or
key changed — `goodbye` and disconnect; `confirm_max_age_seconds` changed — disconnect, the new interval comes with
a new `welcome`. There is no separate panel signal to cut a stream: a revoked agent is cut off by its own
next message (no later than `confirm_every_seconds`).

---

## 4. States

The state of a "check × tester" pair is computed by the **agent** (`internal/probe/state.go`). One run =
`probes_per_run` probes in a row:

```text
all probes answered                       → clean run
at least ok_probes_required answered      → partial (accumulates neither failure nor recovery)
fewer                                     → failed

fail_threshold failed in a row   → down
ok_threshold clean in a row      → healthy
otherwise                        → degraded   (including right after the check starts)
```

On the server a pair has four states: `healthy`, `degraded`, `down`, `unknown`. `unknown` has a reason
(`unknown_reason`), which decisions do not look at:

| Reason | When |
|---------|-------|
| `no_result_yet` | the pair has just appeared or the check/tester has been switched back on |
| `silent` | the confirmation deadline has expired (§5) |
| `stale_config` | the measurement has changed, there is no result for the new version yet |
| `disabled` | the operator switched off the tester or the check |

A `pulse_results` row exists exactly as long as the pair exists (the check is assigned to a group the tester
belongs to); the panel creates and deletes it on check assignment, group membership changes and group deletion
(`_pulse_sync_results`); deleting a check or tester removes the rows by cascade. The on/off switch does not delete
the pair but moves it to `unknown/disabled`; tasks are handed out only if both sides are on.

"The tester is silent" is `unknown`, not "the host is dead": loss of observation does not move DNS (§6).

The agent's own state is separate: `pulse_testers.state` = `online` / `silent` / `disabled`. Only a confirmation
sets `online`; switching a tester back on gives `silent` until the first confirmation.

## 4.1. History

Only **closed** intervals are stored; the current segment is `state` + `since` in the current row:

| What | Closed intervals | Current segment |
|-----|--------------------|-----------------|
| pair | `pulse_intervals` | `pulse_results.state`, `since` |
| agent | `pulse_tester_intervals` | `pulse_testers.state`, `state_since` |
| Pinger address | `pulse_sweep_intervals` (`ended_by` — who saw the change) | `pulse_sweep_targets.last_state`, `state_since` |
| switches | `pulse_rule_events` (+ `pulse_rule_event_checks`) | — |

A transition is written in one transaction under `SELECT … FOR UPDATE` of the pair row; the previous state is read under
the same lock. A transition to the same `state` is not a transition (only `state` is compared, not the reason).
An interval never ends before it starts.

**Retention** — `pulse_history_days` (default 90, 1…3650). Trimming happens along the way: when an object's interval
closes, old intervals of that same object are deleted; when a rule event is written, old events of that
rule are. There is no background cleanup, so an object that has gone quiet keeps its old intervals. If the setting row is missing
or the value is invalid, nothing is deleted.

**Screen.** The History tab: a bar per check over 1d / 1w / 1m (`GET /dns-api/pulse/history?window=`),
expansion by agent, DNS switch markers. The colour of a check's bar is the worst answer of its agents at each
moment; grey — nobody answered, hatching — the pair was not observed. A one-day bar is present in the Checks and
Agents tables and on conditions in the rule editor. There are no live updates: the bar is correct as of opening.

---

## 5. Deadlines

| Setting | Where | Default |
|-----------|-----|--------------|
| interval, response timeout, probes/answers needed, failure/recovery threshold | check | 5 s, 1000 ms, 3/1, 3/3 (template — Settings → New check defaults) |
| branch hold ("holds for N s") | rule branch | 30 s |
| hold before returning to the default set | rule | 300 s |
| `confirm_max_age_seconds` — how long a confirmation counts as fresh | tester | 90 s |

Out-of-range values on a check, tester and rule are clamped by the panel to the limit (`_pulse_int`); in Settings they are
refused with a reason. `confirm_max_age_seconds` is also how long the server is willing to decide on
stale data: if the channel to the agent fails together with the target, the rule sees the previous
`healthy` until the deadline expires. For testers in switching rules it is worth keeping short.

**There are no periodic sweeps.** Instead — a timer for a specific moment:

- for a pair: `confirmed_at + confirm_max_age`; every confirmation or result resets it;
  when it fires, the pair becomes `unknown/silent`, and the interval is closed at the moment knowledge ended;
- an agent has its own timer from `last_confirm_at` (a tester without tasks has no pair deadlines); when it fires — `silent`;
- a timer is set only if both sides are on and `confirmed_at` is not empty;
- a timer that fires before the real deadline is reset to the real one; a failed write is retried
  with a pause of `timeouts.retry_min…retry_max` (1 s…1 min);
- expiry is an event too: the rules that look at this pair/this agent are recomputed.

**Cold start** (`Activate`): before opening the port the server sets all deadlines from the database (overdue ones
fire immediately), starts a full rebuild of Pinger targets and recomputes all enabled rules. Start
is allotted `timeouts.db + timeouts.apply`; if the deadlines cannot be read, the daemon exits; if the recomputation fails, it
keeps running and the rules are on retry. On a node without the role `Activate` does nothing.

**Role change.** After a successful `promote` and `emergency_promote`, `dns-ha-agentd` sends `activate` to the control socket,
after `demote` — `deactivate` (in the background, with retries; no socket — silently). `activate` = the same
`Activate`; the reply `{"ok":true}` comes only when the deadlines are set and the rules are decided. `deactivate` asks for the role
once more and, if the node is not active, drops deadlines, holds, wakeups and streams. In addition, the very first
agent handshake on a new active node triggers `Activate`. The socket path in `dns-ha-agentd` is hardcoded
(`/run/dns-panel/pulse/control.sock`); if it differs in `pulse-server.toml`, the server logs a
warning that role change signals will not arrive.

---

## 6. Pulse rule

A rule belongs to an **RRset** (zone + name + type) and manages the set of values as a whole. Types: `A AAAA
CNAME MX NS SRV TXT` (`@PULSE_RR_TYPES`); the zone must be writable (not SLAVE). One rule per
RRset (`UNIQUE(domain_id, rr_name, rr_type)`). Pulse does not know what an IP is: a branch publishes a set, for MX
it may simply be a different priority. For CNAME the set has exactly one value. The content is checked by
`dns_validate`, as for ordinary records.

**Entry.** On the records page the **Pulse** column (visible with the `pulse.manage` permission) on every RRset of a
supported type: `off` / `default` / `rule N` / `switched` / `held`; a click opens the rule editor
over the page (`/pulse?rule=N` or `/pulse?zone=…&name=…&type=…`). Opening creates nothing:
the rule appears in the database on the first save, **switched off**, with the default set = the current
zone content. The **Rules** tab on the NS Pulse page is a list of configured rules with filtering; from there
a configuration can also be copied to other records (up to 100 at a time; the logic is always copied, the values — only
for the same type).

**Branches** are evaluated top to bottom, at the bottom always "otherwise — the default set":

```text
1. If ANY:      ICMP 10.20.20.1 unavailable (all agents)
                TCP 10.30.30.1:8080 unavailable (any agent)
   → publish 10.10.10.2 if it holds for 30 s
2. If ALL:      TCP 10.30.30.2:8080 unavailable (at least 2 agents)
                schedule: Mon–Fri 09:00–18:00
   → publish 10.10.10.3 if it holds for 30 s
otherwise → default 10.10.10.1 if it holds for 300 s
```

Conditions are of two kinds:

1. **Check**: `expect` = `available` (healthy) / `degraded` / `unavailable` (down); there is no `NOT`.
   The condition's observers are **all** runners of the check (`pulse_condition_testers`, rebuilt by the panel
   on every change of assignment and group membership). Observer agreement `agg`:

   | `agg` | true | false | otherwise |
   |-------|---------|-------|-------|
   | `any` | at least one answered as expected | all answered otherwise | unknown |
   | `all` | all answered as expected | at least one otherwise | unknown |
   | `at_least N` | as expected ≥ N | N cannot be reached even with the silent ones | unknown |

   A pair in `unknown` is "no answer", not "no". No observers — unknown. The editor suggests `all`;
   `N` is at most the number of runners.
2. **Schedule**: weekdays (`days_mask`, bits Mon…Sun), a time window `HH:MM` (both bounds, may cross
   midnight), dates from/to. One time zone per rule (`schedule_tz`, default UTC; an unknown zone →
   UTC). A schedule is always decidable.

A branch joins conditions with `any` (OR) or `all` (AND), there is no nesting:

| Branch | `any` | `all` |
|-------|-------|-------|
| matched | at least one true | all true |
| not matched | all false | at least one false |
| unknown | otherwise | otherwise |

The first matched branch wins; the default set applies only if all branches above are confirmed not to
match. **An unknown branch stops evaluation: the record stays as it is** (`rules.Decide` → `nil`).
A branch without conditions is unknown (such a branch cannot be saved, but it may become empty by cascade when a
check is deleted).

**Hold.** The decision differs from what is published → a timer for the target's hold (the branch's or
`default_hold_seconds`). The target changed — the countdown restarts; the decision became "unknown" or matches
what is published — the timer is dropped. When it expires, the decision is made again and only then is
`pulse-apply.pl --rule N [--branch M] --reason …` called. A failed apply is retried with a growing pause without
another hold.

**When it is recomputed** — only on an event: a pair transition, an expired deadline, a schedule boundary (a timer to
the nearest window boundary or midnight), the panel's `recompute` signal (saving a rule, branches, check,
tester, group membership), `activate`. A failed recomputation is retried with a pause of `retry_min…retry_max`.

**Apply** (`pulse_rule_apply`, under `FOR UPDATE` of the rule row): rule switched off — refusal; already in
the needed state — nothing; the zone already contains the needed set — only the bookkeeping is updated, without a SOA bump; otherwise
`pdns_apply_rrsets` with `REPLACE`, then the `published` mark, an event in `pulse_rule_events` and a
`pulse_switch` entry in the audit log. Order: first the zone, then the mark.

**A manual edit of a managed record** is rejected in `pdns_apply_rrsets` (except on the `pulse` path), that is from the
UI as well as through API/MCP: "… is managed by NS Pulse — switch the rule off to edit it by hand".

**`held`.** Before a write and on every recomputation without a switch (`--verify`) the published set is
compared with the zone as a set of canonical values. A mismatch (the zone was edited bypassing the panel) — the rule
goes to `held`, `pulse_held` is written to the audit log, and the handler no longer touches it. An empty `published`
(after re-saving the branches) does not count as a mismatch.

**Switching off and on.**

- Switching off does not touch the zone: what is published stays, and the record can be edited by hand again.
- Switching on requires at least one branch, no branch without conditions and no condition without a runner.
- Switching on a rule that was on the default set re-captures the default set from the zone.
- Switching on from `switched` or `held` does not touch the sets: the state is derived by comparing the zone with the sets —
  matches the default → `default`, a branch → `switched` by it, nothing → `switched` without a branch, and the handler
  publishes the current decision. So switching off and on is how you leave `held` and return the record to Pulse.
- Saving the branches recreates them and derives the state the same way.

Deleting a rule does not touch the zone.

**Preview in the editor.** Evaluation starts from the live pair states (`pulse_rule_get` returns
`live_state`); a condition's state can be tried out ("what-if"): only the output changes, the branch gets
a preview mark, nothing goes to DNS. If `pulse-server` does not answer on the control socket,
the page shows "The Pulse server is not running on this node — nothing is being switched".

**Groups and runners.** A group is a set of testers for a task, not a location and not a `view`. The runners of a
check in the panel = the agents of its groups ∪ those assigned individually (`pulse_check_agents`), without duplicates
(`_pulse_runners_sql`). **Discrepancy:** `pulse-server` hands out tasks only through groups
(`store.Tasks`), and the condition check before switching a rule on also looks only at groups — an individually
assigned agent does not get the task.

---

## 7. Pinger (slow sweep)

**Targets** are addresses from enabled A/AAAA records of the panel's zones — primary ones, and secondary ones too when
**Settings → Pinger & Pulse → Include secondary zones** is on (`pulse_sweep_secondary`); one address in several records is
one target (`pulse_sweep_targets`, key `target_ip + net_scope`, there is only one scope so far — `default`). The link
"address in this record" is a `pulse_sweep_refs` interval (`since…until`); links are not deleted.

**The list is maintained by the record path:** after every `pdns_apply_rrsets` and zone deletion,
`pulse_sweep_after_write` is called; it sends pulse-server `{"cmd":"sweep","zone":N}`, and the server (`internal/store/sweepsync.go`)
rebuilds the zone's links under the named lock `psweep:<id>`; A/AAAA are read under the lock from the PowerDNS database
with its own read-only account `dns-pulse`. An address gone from all records — the last answer is closed with an interval, the target
is marked `unref_at`, the lease is dropped with a generation bump; it came back — the same target with its history, but without
freshness (it goes to the front of the queue). A target without links for longer than `pulse_history_days` is deleted entirely.

If the rebuild fails, the zone is marked in `pulse_sweep_dirty` (if the daemon is not listening, the panel marks it). The daemon
remembers the zone and retries the marked ones with a pause of `retry_min…retry_max`; at start, on `activate` and when the
secondary setting changes (`{"cmd":"sweep","all":true}`) — a full rebuild of all zones, each zone with its own time limit.

Secondary zones change by transfer, which the panel does not see. On an agent check-in (at most once a minute),
pulse-server compares the SOA of every secondary with its last look and rebuilds the zones whose SOA changed. All of this
happens only on the active node; demotion aborts a rebuild in progress.

**The queue** goes through the same agent stream, only at the agent's request:

```text
agent  → sweep_claim
server → sweep_batch: sweep[] {target_id, generation, ip, timeout_ms, probes}, sweep_parallel
         or an empty batch with sweep_again_seconds — when to ask again
agent  → sweep_result: answers[] {target_id, generation, state: available | unavailable}
```

- handing out is one `FOR UPDATE SKIP LOCKED` transaction: the longest-unchecked first (never-checked first of all),
  address family by the agent's `can_ipv4`/`can_ipv6`, the previous check no less than `pulse_sweep_interval` ago, without a live
  lease held by someone else; a lease is set and `lease_generation` is bumped;
- lease duration = 2 × ⌈batch/parallel⌉ × probes × timeout, at least 1 s;
- an answer is accepted only if the target, agent and generation match, the lease has not expired and the target is not orphaned;
  an accepted answer releases the lease;
- on a session disconnect the unfulfilled leases of that session (with their generations) return to the queue immediately;
- an empty batch: `sweep_again_seconds` is computed by the database (the later of "due in the cycle" and "someone else's lease
  ends"), but at most 60 s: the server does not wake agents, and a new address must not wait a whole round; no parameters in `settings` yet — "come back later" (`retry_min`); the agent has neither IPv4 nor IPv6
  — 0, there will be no sweep in this session.

The agent measures only **ICMP** (an agent without ICMP does not take part in Pinger), with the parallelism from the batch, up to
`probes` attempts: an answer — `available`, no answer — `unavailable`. No route to the address (`RoutableTo`) or
the probe cannot be run — no answer at all, the lease will expire, someone else will check the target. The agent does not send
`unknown`: it is a server state (not checked, nobody to check AAAA).

A target's state is **the last actual check, and it does not go stale**. There is no voting: in a cycle a target is
checked by one agent. `pulse_sweep_interval` means "no more often than", not "at least once every".

**Parameters** (Settings → Pinger & Pulse, the Pinger card; the `settings` rows are created by the panel on first
read or on a full rebuild, the daemon has no defaults of its own):

| Key | Default | Limits |
|------|--------------|---------|
| `pulse_sweep_interval`, s | 3600 | 60…86400 |
| `pulse_sweep_batch` | 20 | 1…500 |
| `pulse_sweep_parallel` | 4 | 1…64 |
| `pulse_sweep_probes` | 2 | 1…10 |
| `pulse_sweep_timeout_ms` | 1000 | 100…10000 |
| `pulse_history_days` (History card) | 90 | 1…3650 |

The **New check defaults** card (`pulse_check_interval`, `_timeout_ms`, `_probes`, `_ok_probes`,
`_fail_runs`, `_ok_runs`) is a template for a new check; it does not change existing checks.

**In a zone** only a problem is visible: an address value in the `unavailable` state has a red dot ("No ICMP
reply since …"); a click opens the record history on the Pinger tab. Records table filters: Pulse
(`off / default / rule / held`) and Pinger (`unavailable / available / not checked`), by the row's `data-*`.

**Record history** is a window with tabs **Changes** (audit), **Pulse** (what Pulse published and why,
`pulse_rule_events`; only for Pulse types) and **Pinger** (a bar per address, trimmed by the link
intervals, and one transition table with filtering by address; only A/AAAA). Pinger is visible to everyone who can see the
zone (`GET /pulse/zones/N/rrset/sweep`); everything else in NS Pulse requires `pulse.manage`.

---

## 8. Data (`dns_panel`) and configuration

Schema — `docs/INSTALL/schema.sql`, section NS Pulse. Tables:

| Table | What |
|---------|-----|
| `pulse_server_tls` | server certificate (one row) |
| `pulse_enrollment` | `enroll_key` (one row) |
| `pulse_testers` | testers and requests: `key_hash`, `approved_at`, `enabled`, `confirm_max_age_seconds`, `can_ipv4/6`, `state`, `last_confirm_at`, `addr` |
| `pulse_groups`, `pulse_group_members` | groups and their membership |
| `pulse_checks` | checks: `kind`, `target_ip`, `port`, intervals, thresholds, `enabled`, `config_version` |
| `pulse_check_groups`, `pulse_check_agents` | whom a check is assigned to (groups; individually — see §6) |
| `pulse_results` | current pair state, `unknown_reason`, `since`, `confirmed_at` |
| `pulse_intervals`, `pulse_tester_intervals` | closed intervals (§4.1) |
| `pulse_rules` | RRset rule: `ttl`, `default_hold_seconds`, `schedule_tz`, `enabled`, `state` (`default/switched/held`), `active_branch_id` |
| `pulse_branches` | branches: `position`, `match_mode`, `hold_seconds` |
| `pulse_rrset_values` | sets: `branch_id IS NULL` — default; `published=1` — what is published |
| `pulse_conditions`, `pulse_condition_testers` | conditions and their observers |
| `pulse_rule_events`, `pulse_rule_event_checks` | switches (`from_set`, `to_set`, `reason`, `actor`) and which checks the rule consulted |
| `pulse_sweep_targets`, `pulse_sweep_refs`, `pulse_sweep_intervals`, `pulse_sweep_dirty` | Pinger |

`probe_policies` and `record_health` are not part of NS Pulse and are not used by the code.

**`pulse-server.toml`** (`etc/pulse-server.example.toml`):

| Key | Default |
|------|--------------|
| `listen` | `0.0.0.0:7902` |
| `[db] socket, name, user, password_file` | `/run/mysqld/mysqld.sock`, `dns_panel`, — (required), — |
| `[ha] enabled, socket` | `false`, `/run/dns-panel/ha/manager.sock` |
| `[apply] command` | `/opt/dns-panel/libexec/pulse-apply.pl` |
| `[pdns] socket, name, user` | `/run/mysqld/mysqld.sock`, `pdns`, `dns-pulse` (unix_socket, read-only) |
| `[control] socket, group` | `/run/dns-panel/pulse/control.sock`, `www-data` |
| `[timeouts] db, ha, ha_verdict_ttl, retry_min, retry_max, apply` | `10s, 3s, 1s, 1s, 1m, 30s` |

Panel: `[pulse] control_socket` in `panel.toml` (the same path). The socket directory is created by tmpfiles
(`/run/dns-panel/pulse`, `root:www-data 0770`); the socket is `0660` with the `[control] group` group.

**Control socket** — one JSON line per connection, reply `{"ok":true|false,"error":…}`:

| Command | Sent by | Action |
|---------|----------|----------|
| `{"cmd":"recompute","rule":N}` (`0` — all) | panel | recompute the rule(s) |
| `{"cmd":"sweep","zone":N}` | panel | catch up the Pinger target list |
| `{"cmd":"activate"}` / `{"cmd":"deactivate"}` | `dns-ha-agentd` | role change (§5) |

The panel's signal is fire-and-forget: its failure does not fail the save.

**`pulse-apply.pl`**: `--rule N [--branch M] [--reason "…"]` — switch (without `--branch` — the default
set); `--rule N --verify` — verify the zone. The reply is one JSON line (`ok`, `changed`, `state`, `held`,
`ha`, `error`), exit code 0 — done or nothing to change, 1 — refusal.

**API** — `/dns-api/pulse/*` (`www/API/Router.pm`), permission `pulse.manage` (except `rrset/sweep`): `GET /pulse`,
testers (`approve`, `PUT`, `DELETE`), groups and membership, checks and assignment (`PUT /checks/N/groups`
with `groups` and optional `agents`), rules (`POST /rules`, `PUT /rules/N`, `PUT /rules/N/branches`,
`POST /rules/N/clone`, `DELETE`), `GET /pulse/history`, `GET /pulse/zones/N/rrset[/history|/sweep]`,
`PUT /pulse/settings`, `PUT /pulse/server/address`, `POST /pulse/enrollment/key`. Deleting a check or
tester returns `affected_rules`.
