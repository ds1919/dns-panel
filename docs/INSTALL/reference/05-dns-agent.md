# 05 — dns-agent (privileged PowerDNS intermediary)

The panel runs as `www-data` and **has no access** to the PowerDNS control socket
(`/run/pdns/pdns.controlsocket`, owner `pdns:pdns`). So after direct SQL into gmysql
it does not notify PowerDNS of changes itself but goes through a small privileged daemon.

```
DNS Panel / API / MCP (www-data)
        │ unix-socket /run/dns-panel/pdns/dns-agent.sock  (0660 pdns:www-data)
        ▼
dns-agent (User=pdns, Go: src/dns-agent → bin/dns-agent)
        │
        ▼
pdns_control rediscover | purge zone$ | notify zone | retrieve zone     +    dig (SOA, AXFR)
```

**Only fixed commands, no shell.** The zone is validated the same way as in the panel
(`dns_validate_zonename`), the server address as an IP, the TSIG key by format; every run of
`pdns_control`/`dig` has the `timeout` timeout. `dig` (verify, soa_at, axfr_at) runs in parallel, at most
`max_concurrent` requests at once (the rest wait in the socket queue); `pdns_control` runs strictly one at a time, and waiting
for its turn counts toward the same `timeout`. A client that connects and stays silent is disconnected on timeout.

## Protocol (JSON line → JSON line)

| Request | Response |
|--------|-------|
| `{"cmd":"ping"}` | `{"ok":1,"pong":1}` |
| `{"cmd":"rediscover"}` | `{"ok":1,"output":"Ok"}` |
| `{"cmd":"purge","zone":"z"}` | `{"ok":1,"output":"<N>"}` (purge `z$` — zone+subtree) |
| `{"cmd":"notify","zone":"z"}` | `{"ok":1,"output":"Added to queue"}` |
| `{"cmd":"retrieve","zone":"z"}` | `{"ok":1,"output":"Added retrieval request..."}` (SLAVE: immediate AXFR from the primary) |
| `{"cmd":"verify","zone":"z","expect_serial":N}` | `{"ok":1,"served":true,"serial":N,"matches":true}` |
| `{"cmd":"soa_at","zone":"z","server":"ip"}` | `{"ok":1,"serial":N}` — SOA on another server (Make primary: are we behind the old master) |
| `{"cmd":"axfr_at","zone":"z","server":"ip","key":{"name","algorithm","secret"}?}` | `{"ok":1,"records":[...]}` — AXFR from another server (Import); refusal — `{"ok":0,"status":"REFUSED",...}`, key rejected — plus `"tsig_rejected":1` |

An error is `{"ok":0,"error":"..."}`. The TSIG secret goes to `dig -k /dev/stdin`: not into argv (visible in `ps`) and not
into a file (the dig AppArmor profile does not read `/tmp`).

## Installation

The binary (Go, standard library only) comes built in the release package (from source: `make build`)
(`make -C src/dns-agent build` → `bin/dns-agent`, the nodes have no Go). `deploy/install.sh` installs it: the unit
`etc/systemd/dns-agent.service` as a symlink in `/etc/systemd/system/`, `enable` + `restart`.

Unit essentials:
- `Type=notify` — `systemctl start` returns once the socket is open;
- `User=pdns` — access to the PowerDNS control socket;
- the agent is **not** a member of the `www-data` group: its members read the panel's secrets (`panel.toml`, DB passwords);
- the socket directory `/run/dns-panel/pdns` is `2750 pdns:www-data` (tmpfiles, `etc/tmpfiles/dns-panel.conf`): setgid
  gives the socket the `www-data` group, so the panel can open it but cannot write to the directory. If the socket group
  is wrong, the agent does not start.

## Configuration

`etc/dns-agent.toml` is the agent's own config (a separate file: a process running as pdns does not need the panel's DB passwords):

```toml
socket          = "/run/dns-panel/pdns/dns-agent.sock"
socket_group    = "www-data"
timeout         = 5                          # seconds per request, including the queue for pdns_control
max_concurrent  = 16                         # concurrent requests
pdns_control    = "/usr/bin/pdns_control"
dig             = "/usr/bin/dig"
verify_resolver = "127.0.0.1"
```

An unknown key or a line without `=` is an error at startup, not a silent default. The panel finds
the socket via `[agent] socket` in `etc/panel.toml`.

## Manual check (as www-data)

```bash
sudo -u www-data perl -I /opt/dns-panel/www/include -MJSON -e 'use functions qw(dns_agent_call); print encode_json(dns_agent_call(q(ping))), "\n"'
```

## Production sync flow (how the panel uses it)

```
Primary, create:    SQL commit → rediscover → verify SOA → NOTIFY → durable status
Secondary, create:  SQL commit → rediscover → retrieve (AXFR requested) → pending_transfer
Zone delete:        SQL commit → rediscover → verify "not served" → durable status
RRset edit:         SQL commit → purge zone$ → verify serial → notify zone
```

A secondary zone waits for nothing and checks nothing on creation: PowerDNS queues the transfer, and its
completion is observed by the worker. A migration batch runs `rediscover` once for all zones. A secondary zone
counts as arrived when PowerDNS **serves** it and has **checked it against the current primary**
(`domains.last_check > 0`: PowerDNS sets it after a successful AXFR or SOA check, and a source change and
Make secondary reset it). "Served" alone is not enough: after a source change the zone keeps serving
the previous primary's data. **Refresh AXFR** on the zone page is a single `retrieve`, i.e. "requested", not
"arrived"; arrival is visible in Last check.

The status is stored in `dns_panel.zone_sync_state` (`pdns_state`: `active` / `pending_transfer` /
`transfer_problem` / `activation_failed` / `removed` / …; `notify_state`: `notified` / `notify_failed` /
`not_attempted` / `not_applicable`). **An agent failure after commit does NOT roll back the DB** — the zone is created, but
the state shows this, and the worker completes it.

> Thanks to the explicit `rediscover`, `zone-cache-refresh-interval=0` is **not needed** — keep the standard
> default (300). Direct SQL bypassing the HTTP API does not reset the zone cache by itself, so the agent does it.

## Automatic recovery (dns-sync-worker)

`zone_sync_state` stores `operation` (`activate`|`deactivate`), `attempts` (number of consecutive failures),
`last_attempt_at`, `next_retry_at`, `pending_since` and `state_version` (CAS). The worker takes only zones
that are "due" (`next_retry_at <= NOW()`):

- **activate** — `activation_failed` / `notify_failed`: repeat `zone_sync_verify` (verify against the current
  SOA serial from the DB → NOTIFY). The zone disappeared from PowerDNS → `orphaned`.
- **pending_transfer** (secondary) — checked every `sync.poll_seconds`: arrived (served and checked) →
  `active`, not yet → AXFR is requested again. Waits longer than `sync.transfer_timeout_seconds` since the wait began (Refresh AXFR restarts it)
  → `transfer_problem` with backoff: this is the "show the problem" threshold, not a sign that the transfer is over.
- **deactivate** — after deletion the zone is still served (`still_served` / `deactivation_failed`) →
  repeat `rediscover` + verify "no longer served" (success = `removed`).

The operator can press **Retry now** in the problem banner on the zone page — it is the same pass the worker runs.

- **The daemon** `dns-sync-worker` (Go, `src/dns-sync-worker`) decides only **when** to work. What to do is
  the passes of `libexec/sync-task.pl` (Perl, rules in `functions.pm`): `retry-due`, `reconcile`, `probe-batch`,
  `catalogs`, `schedule`. Each pass checks HA itself (on STANDBY and during a freeze it writes nothing,
  an unknown state is fail-closed) and returns JSON with the schedule it left in the DB. The unit
  `etc/systemd/dns-sync-worker.service`: `Type=notify` (ready once the wake socket is open), `User=www-data`; installed by
  `deploy/install.sh`, the binary comes built in the release package (from source: `make build`). There are no systemd timers — the daemon keeps the schedule itself.
- All state is in the DB (`next_retry_at`, the Probe queue `probe_state='queued'`, the policy itself). The daemon sleeps
  until the nearest due time; the panel, having queued something, wakes it with a datagram to
  `/run/dns-panel/sync/wake.sock` (`sync_wake`; the directory is `2750 www-data:dns-ha` from tmpfiles, setgid gives
  the socket the `dns-ha` group so that `dns-ha-manager` can wake it too). A lost nudge costs at most one catalog interval.

  | what | when |
  |---|---|
  | zone retries (`retry-due`) | exactly at `next_retry_at` |
  | Probe (`probe-batch`) | right after queueing, batch after batch, until the queue is empty |
  | catalog observation (`catalogs`) | every `sync.catalog_check_seconds` (60) — BIND reports nothing by itself |
  | safety reconciliation of distribution and Dynamic (`reconcile`) | every `sync.reconcile_seconds` (600) after the end of a pass; changes are applied immediately, this is only against drift. Did not converge (PowerDNS unavailable) — again after `sync.backoff_initial_seconds` (60) |
  | the node can write again (became ACTIVE, the HA operation finished) | full reconciliation right away: `dns-ha-manager` wakes the daemon at the same moment the write gate opens |
- A pass that moved nothing (the zone is busy with a manual Retry, the agent is unavailable) is not repeated immediately but
  waits for the next catalog interval or a nudge. Mutual exclusion with a manual Retry is an advisory `GET_LOCK`;
  a stale task (a concurrent create/delete changed `operation`/version) is discarded by CAS as `superseded`.
- Parameters are settings in the `dns_panel.settings` table (`sync.poll_seconds` 30,
  `sync.transfer_timeout_seconds` 3600, `sync.backoff_initial_seconds` 60, `sync.backoff_max_seconds` 3600,
  `sync.catalog_check_seconds` 60, `sync.reconcile_seconds` 600, `sync.retry_batch` 100, `import.probe_batch` 50,
  `import.probe_budget_seconds` 60; defaults are `%SETTING_DEFAULTS`
  in `functions.pm`). There is no `[sync]` section in `etc/panel.toml`.

```bash
systemctl status dns-sync-worker; journalctl -u dns-sync-worker -f
# one pass by hand (as www-data — needs access to the agent socket and the DB):
sudo -u www-data /opt/dns-panel/libexec/sync-task.pl retry-due
```

Panel endpoints: `GET /dns-api/sync/problems` (problem zones, filtered by access),
`POST /dns-api/zones/:id/retry-sync` (Retry now), `POST /dns-api/zones/:id/refresh-axfr` (Refresh AXFR);
both POSTs require write access to the zone. In the UI: a banner on the zone, a badge + the **Sync** filter in the zone list.
