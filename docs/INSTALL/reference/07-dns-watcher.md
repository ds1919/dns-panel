# dns-watcher — pair readiness probe → action, where there is no Cisco IP SLA

An HA pair in **Anycast** mode has a single contract with the network: the **readiness probe** (TCP, `17900` by default)
is open only on the ACTIVE node and only while it is ready to serve. The service address (`/32` on `lo`) sits on both
nodes; where it leads is decided by the external network based on the probe. The panel and the HA daemons know nothing about this network.

`dns-watcher` is one way to act on this probe. It knows nothing about routes, NAT or DNS itself:
it reduces the probes of the two nodes to a single state and, when that state changes, runs a rule from the configuration. What the
rule does — a route, nftables, iptables, BIRD, a custom script — is up to whoever writes it.

| what acts on the probe | where |
|---|---|
| **Cisco IP SLA + track + static route** | a router in each DC — a working option, example below |
| **dns-watcher → `/32` route** | the host through which clients reach the address, or the client itself |
| **dns-watcher → NAT (nftables / iptables)** | a separate host in the clients' network when there is nothing to route with; the host is a single point of failure |
| **dns-watcher → BIRD** (`birdc enable/disable`) | a Linux router with BGP in each DC — announces the `/32` while its own node is ready |

HAProxy (community) does not fit here: it does not proxy UDP, and DNS is primarily UDP. Keepalived/IPVS is
a load balancer in front of DNS, not anycast: the address lives on the load balancer, and in an inter-DC setup the balancer itself becomes the
node whose failure the pair is meant to avoid. BIRD cannot check an arbitrary TCP port — hence it is paired
with the watcher.

## States and rules

Every `interval` — a TCP connect to the probe of both nodes. A node is ready after `rise` consecutive successful checks and
stops being ready after `fall` failed ones — a single random packet loss does not switch traffic (as with
IP SLA/HAProxy). This yields one of the states:

| state | when |
|---|---|
| `node1_up` / `node2_up` | exactly this node is ready |
| `both_down` | neither is ready |
| `both_up` | the probe is open on both — **split-brain**; sending traffic to one of two "active" nodes at random means choosing whose records get lost |
| `stop` | (optional) the watcher is stopping (`SIGTERM`/`SIGINT`) |

`[conditions]` assigns a rule to each state; a rule is a section with a list of `commands`:

```toml
address    = "10.0.0.53"
node1      = "10.0.0.11"
node1_port = 17900
node2      = "10.0.0.12"
node2_port = 17900

[conditions]
node1_up  = "ACTIVE"
node2_up  = "ACTIVE"
both_down = "WITHDRAW"
both_up   = "SPLIT"
stop      = "WITHDRAW"

[ACTIVE]
commands = [
  "ip route replace $ADDRESS/32 via $ACTIVE_NODE",
]
```

- a rule runs **only on a state change**;
- commands run via `/bin/sh -c`, **strictly in order**; the first failing one stops the rule, the rule is not considered
  applied and is retried on the next round until it succeeds;
- values for commands come **explicitly from the configuration**, nothing is guessed from the host's interfaces:

  | variable | source |
  |---|---|
  | `$ADDRESS` | `address` — the pair's service address, without a mask (the command writes the mask itself: `$ADDRESS/32`) |
  | `$WATCHER_NODE` | `watcher_node` — the address of this host on which to catch traffic (NAT) |
  | `$NODE1`, `$NODE1_PORT`, `$NODE2`, `$NODE2_PORT` | `node1`, `node1_port`, `node2`, `node2_port` |
  | custom | the `[variables]` section, e.g. `DEVICE = "eth0"` → `$DEVICE`; names from this table are forbidden there |
  | `$STATE` | the current state (`node1_up`… `stop`) |
  | `$ACTIVE_NODE`, `$ACTIVE_PORT` | the ready node for `node1_up`/`node2_up`; empty for `both_*` and `stop` |

  so a single `ACTIVE` rule serves both nodes, and changing an address is one line in the file;
- `command_timeout` (`10s` by default) is a safeguard: a hung command is killed together with its
  processes, and the rule is retried on the next round; otherwise a single hung `birdc` would stop both the checks and
  stop handling;
- successful commands are silent (a rule can log by itself, `logger`); a failure is logged once, with the command's
  output;
- commands run as root, so the watcher refuses to start if the configuration file is not owned by root
  or is writable by group or others.

Ready-made variants are in [`etc/dns-watcher.example.toml`](../../../etc/dns-watcher.example.toml): route (enabled),
NAT via nftables and via iptables, BIRD (commented out).

## Route

```
client ──► this host ── ip route 10.0.0.53/32 via <ACTIVE> ──► ACTIVE (address on lo) :53 / :80
```

Clients must reach the service address **through** this host (it is their router) — or this host must
be the client itself. A development laptop:

```bash
sudo bin/dns-watcher -config etc/dns-watcher.toml     # file owned by root, not writable by group and others
dig @10.0.0.53 example.com SOA
curl http://10.0.0.53/
```

## NAT

```
client ──► $WATCHER_NODE (this host's address, e.g. 10.0.0.250 on eth0) ── DNAT ──► ACTIVE :53 udp/tcp, :80
```

When there is nothing to route with: clients reach this host's address as an ordinary address of their network. The rule
enables `ip_forward`, sets up DNAT from `$WATCHER_NODE` to `$ACTIVE_NODE` with masquerade and flushes conntrack for
the address — otherwise already open flows would keep going to the previous node. In the nftables variant the table is declared and
the rules are replaced in one transaction: repeated switches go through the same rule, with no gap without rules.

Because of masquerade, the node sees this host's address as the client, not the real client: this affects the panel's log and
the PowerDNS ACL — do not allow zone transfers through such an address. The `$WATCHER_NODE` address is an ordinary address of this host,
the rules do not touch it: on `both_down` a request to it is refused immediately instead of disappearing into nowhere.

## Installation

The watcher is installed not on the pair's nodes but on the host through which clients reach the service address (or on the
client itself). It has its own package, `dns-panel-watcher_<version>_amd64.deb` from the release; as root:

```bash
apt install ./dns-panel-watcher_1.0.0_amd64.deb
install -m 0600 /opt/dns-panel/etc/dns-watcher.example.toml /opt/dns-panel/etc/dns-watcher.toml   # adjust nodes and rules
systemctl start dns-watcher
journalctl -u dns-watcher -f
```

The package enables the unit; it starts once `etc/dns-watcher.toml` exists (the config is not in the package, so an
upgrade keeps it). From source: `make -C src/dns-watcher build` → `bin/dns-watcher`.

The unit is `Type=notify`: `systemctl start` returns once the first rule has run. The nodes and the probe port are the
same as in the pair configuration (High availability → Anycast): the watcher asks the panel nothing.

## Cisco: the same on a router

```
ip sla 1
 tcp-connect 10.0.0.11 17900
 frequency 5
ip sla schedule 1 life forever start-time now
track 1 ip sla 1 reachability
!
ip sla 2
 tcp-connect 10.0.0.12 17900
 frequency 5
ip sla schedule 2 life forever start-time now
track 2 ip sla 2 reachability
!
ip route 10.0.0.53 255.255.255.255 10.0.0.11 track 1
ip route 10.0.0.53 255.255.255.255 10.0.0.12 track 2
```

In different DCs each router has its own node and its own track; the `/32` route is propagated further by whatever
protocol the network already uses. On split-brain, Cisco with two tracked routes spreads traffic across both —
unlike the watcher's `both_up` rule.
