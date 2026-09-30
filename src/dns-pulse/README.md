# dns-pulse

The two NS Pulse daemons: `pulse-server` (on the panel node) and `pulse-agent` (at the sites).
Specification: [docs/25-ns-pulse.md](../../docs/25-ns-pulse.md).

    make build     # static binaries in ../../bin (CGO_ENABLED=0, linux/amd64)
    make check     # gofmt + go vet

The binaries are static on purpose: a site receives a single file that does not care which Ubuntu it runs on.

## What matters here without reading everything

**There are no background sweeps.** Silence produces no events, so this is the one place where time is unavoidable;
but instead of "check everyone every N seconds" there is a DEADLINE for a specific moment, moved forward by every
confirmation. While confirmations keep coming, nothing happens; once they stop, one timer fires for one pair.

**The agent sends only transitions.** Nobody needs a stream of probes: the status bar is built from changes. The state
(healthy / degraded / down) with hysteresis is computed by the agent itself in `internal/probe/state.go`, which also holds
the only tests of this module: a bug in the hysteresis moves DNS.

**Trust is by fingerprint, not by name.** The service address moves between HA nodes, so checking the name in the
certificate is pointless. The certificate belongs to the PAIR and lives in the replicated `dns_panel`: a separate one
per node would make a regular switchover look to the agents like a spoofed server.

**The STANDBY does not accept agents.** Not out of courtesy: it has `read_only=1`, and accepting the stream would mean
showing agents as connected while recording nothing.

## Protocol

One long-lived TLS connection, one JSON line per message: `internal/wire`. We started with gRPC and dropped it for a
reason given in the specification itself: the only thing the framework added to a long-lived stream on top of TLS was
keepalive, which is declared insufficient here (checks can stall while the connection is alive), and per-task
confirmation has to be built on top of it anyway. An agent of your own can be written from this description in any
language, without installing any tooling:

    {"type":"hello","agent_key":"…","enroll_key":"…","hostname":"cn-probe-01","run_id":"…","can_icmp":true}
    ← {"type":"welcome","tester_id":1,"tester_name":"msk-1","confirm_every_seconds":30}
    ← {"type":"assign","tasks":[…]}
    {"type":"transition","check_id":7,"config_version":3,"state":"down"}
    {"type":"confirm","checks":[{"check_id":7,"config_version":3}]}

Until the agent is approved, the conversation ends at the very first reply:

    ← {"type":"goodbye","reason":"waiting for approval in the panel"}

## The agent comes on its own, it gets a name later

The order is the reverse of the usual one: first the agent is started on the machine, then a person in the panel says
who it is. That is how it actually happens: the panel cannot know about a machine before it shows up, and making a
person first create a record, then carry its personal secret to the machine and hope the right one connected is extra
work and an extra chance to make a mistake.

So **there is no personal secret in the configuration file**: the agent generates its `agent_key` on first start and
stores it in `StateDirectory`; only its hash leaves the machine. The configuration file is the same on every machine: it
is baked into the image or distributed by configuration management. The shared `enroll_key` grants exactly one right:
to get into the pending list. There are no tasks and no result recording before approval, so a leaked key means junk in
the queue, not influence on DNS.

Telling apart five requests that arrive at once is not done by address: the agent reports its hostname and, on start,
prints a code like `7F3A-91C2` to its log, the first eight characters of its key's hash. The same code is shown in the
pending list.

Deleting an approved tester means "forget": if the agent keeps running on the machine, it will show up again, this time
as a request. To keep it from coming back, stop it on the machine; changing `enroll_key` in the panel closes the door
to everyone not yet approved and does not affect the approved ones.

## Every number has an owner

There are no magic seconds in the code, and this is a rule, not tidiness. There are exactly three owners:

* **measurement parameters** (interval, limits, thresholds, freshness) live in the database and are edited in the panel;
* **what follows from them unambiguously** (how often to confirm, when a deadline expires) is computed;
  there is no separate setting: a computed value cannot drift out of sync and cannot be set to an hour;
* **technical timeouts with no source in the database** (the HA manager call limit, retry backoffs,
  reconnection) live in `internal/config`, as named fields with defaults that can be
  overridden in TOML.

A setting is added only when two installations must have different answers. Every setting is a promise to support any
value written into it, so a mechanism that should not exist does not get a setting: it gets removed. That is how the
timer-based HA role polling and the "safety" alarm in the sender went away.

## Dependencies

`pulse-agent`: the standard library plus `x/net/icmp`. We deliberately do not write our own ICMP: the savings are
negligible, and a bug in the checksum, in matching a reply to its request, or in filtering out foreign packets looks
**like the host being unreachable**: the agent will honestly say "no reply", the rule will honestly switch the record,
and people will go looking for a network failure that does not exist.

`pulse-server`: the same plus the MySQL driver.
