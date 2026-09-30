# DNS Panel — documentation

Русская версия: [ru/README.md](ru/README.md)

An internal web panel for a **shadow-master PowerDNS + BIND secondary** DNS cluster. The panel writes zones and
records to the PowerDNS MySQL backend (`gmysql`), PowerDNS sends NOTIFY, and the secondaries pull zones via AXFR/IXFR.

Stack: **Perl FastCGI + a frontend without a build step**, background daemons in Go; no Docker and no Python.

The documents describe the current state. If a document disagrees with the code, the code is the source of truth; fix the document.

## Document map

| Document | About |
|----------|-------|
| [INSTALL/](INSTALL/README.md)        | Installation: standalone node and HA pair, packages, MariaDB, PowerDNS, BIND; `schema.sql` |
| [01-overview.md](01-overview.md)     | Why the project exists, principles, scope |
| [02-architecture.md](02-architecture.md) | Architecture of the DNS cluster and the panel, components on a node |
| [03-database.md](03-database.md)     | The panel database and the PowerDNS tables it uses |
| [04-panel-code.md](04-panel-code.md) | Panel code: `www/` layout, routing, API, frontend |
| [05-dns-model.md](05-dns-model.md)   | Zone and record model |
| [07-ui-design.md](07-ui-design.md)   | UI: layout, navigation, palette and themes, component rules |
| [08-auth.md](08-auth.md)             | Authentication |
| [10-mcp.md](10-mcp.md)               | MCP server for AI agents |
| [11-api.md](11-api.md)               | HTTP API: endpoints, authorization, format |
| [13-ha-topology.md](13-ha-topology.md) | Production HA topology: two nodes, MariaDB replication, anycast |
| [15-audit-log.md](15-audit-log.md)   | Audit log |
| [16-delivery.md](16-delivery.md)     | Zone distribution: Direct AXFR and catalogs (RFC 9432) |
| [20-permissions.md](20-permissions.md) | Permissions: zone access, groups, admin rights |
| [22-ha-contract.md](22-ha-contract.md) | HA contract: standalone/pair, switchover, emergency, split-brain |
| [23-ha-manager.md](23-ha-manager.md) | `dns-ha-manager` (Go): how the HA loop works |
| [24-dns-engine.md](24-dns-engine.md) | DNS engine: why PowerDNS + gmysql, what is written with direct SQL |
| [25-ns-pulse.md](25-ns-pulse.md)     | NS Pulse: ICMP/TCP testers (TLS + JSON), switching records to a fallback address |
| [26-zone-import.md](26-zone-import.md) | Migrating zones from the old master |
| [ROADMAP.md](ROADMAP.md)           | What v1.0 delivers, what comes next, project history |
