# 13 — HA topology (production)

How the pair is laid out in production. The base shadow-master + BIND secondaries scheme — [02-architecture.md](02-architecture.md);
HA rules — [22-ha-contract.md](22-ha-contract.md); mechanics — [23-ha-manager.md](23-ha-manager.md); installation —
[INSTALL/02-ha-pair.md](INSTALL/02-ha-pair.md).

## Topology

```
DC1                                       DC2
┌──────────────────────────────┐         ┌──────────────────────────────┐
│ node A (LXC) — ACTIVE        │         │ node B (LXC) — STANDBY       │
│ MariaDB        read_only=0   │ ──────▶ │ MariaDB        read_only=1   │
│ PowerDNS       primary+sec.  │ async   │ PowerDNS       primary=no    │
│ panel, MCP, dns-ha-*         │ GTID    │ panel, MCP, dns-ha-*         │
└──────────────┬───────────────┘         └──────────────┬───────────────┘
               │ NOTIFY — ACTIVE only                   │
               └────────── AXFR/IXFR — from both ───────┘
                                   │
                    N × secondary (BIND) in DCs and offices
```

- **Node** — one LXC: MariaDB, PowerDNS, the panel and MCP, `dns-agent`, `dns-sync-worker`, `dns-ha-manager`,
  `dns-ha-agent`. All nodes have the same components and differ only in role.
- **MariaDB.** The only writer is ACTIVE; STANDBY is an asynchronous GTID replica with `read_only=1`.
  `dns_panel` and `pdns` are replicated; each node has its own `dns_ha` ([23 §4](23-ha-manager.md#4-storage)).
- **The panel, MCP, PowerDNS** of each node work with the local MariaDB. Only ACTIVE accepts writes
  (write gate, [22 §6](22-ha-contract.md#6-panel-write-gate)).
- **PowerDNS.** ACTIVE — `primary=yes secondary=yes`: sends NOTIFY and fetches secondary zones itself.
  STANDBY — `no/no`: both modes write to the database, and it is read-only. Both nodes serve AXFR (on STANDBY the data
  arrives through replication). The role lives only in `90-ha-role.conf`
  ([INSTALL/02 §4](INSTALL/02-ha-pair.md#4-node-configuration)).
- **Secondaries** hold the unicast addresses of both masters and pull the zone from whichever is available. The number of secondaries and who
  gets what is not part of HA ([16-delivery.md](16-delivery.md)).
- **The pair's service address** points to the current ACTIVE; the panel is used through it. Node addresses are for management
  ([22 §7](22-ha-contract.md#7-the-panel-on-a-pair-node)).

## Service address in the network

| mode | what is needed from the network |
|---|---|
| `floating_ip` | a shared L2 segment: the `/32` moves to the new ACTIVE, neighbours are notified by gratuitous ARP |
| `anycast` | the `/32` is permanently on `lo` of both nodes; the route to the node with an open readiness probe is kept by the external network — Cisco IP SLA + track, BGP or [dns-watcher](INSTALL/reference/07-dns-watcher.md) |
| `marker` | the address is managed by an external mechanism (a BGP daemon, a load balancer) |

Details — [23 §14.1–14.2](23-ha-manager.md#141-publishing-the-service-address).

## Why one LXC per node

The load is small; a container or DC failure is covered by the second node. The one downside: a MariaDB problem or upgrade
stops the panel and PowerDNS of that node at the same time. Resolution is not affected — zones
are served by independent secondaries.

## Resources (per node)

```
2 vCPU · 2–4 GB RAM · 20 GB disk
```

Disk: OS 4–6 GB · MariaDB + PowerDNS — usually hundreds of MB · panel and daemons < 1 GB · binlog 2–4 GB (capped) ·
logs 1–2 GB (capped) · reserve 5–8 GB.

Backups live outside these LXCs: losing a container must not take both the database and its copy.
