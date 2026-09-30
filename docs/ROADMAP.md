# Roadmap

## v1.0 — released

- Primary and secondary zones, forward and reverse; RRset editing, automatic PTR, SOA/NS profiles, labels.
- Distribution to secondaries: servers and groups, TSIG, RFC 9432 catalog zones, direct AXFR, NOTIFY.
- DNSSEC: online signing, key management, migration of signed zones with their keys.
- Migration from an old BIND master, including dynamic-update settings and DNSSEC keys.
- Dynamic DNS (RFC 2136) per zone or by profile.
- Active/standby pair: MariaDB replication, anycast or floating address, manual switchover, emergency paths.
- NS Pulse: remote ICMP/TCP testers and record-switching rules; Pinger.
- Users, groups, per-zone access, capabilities, TOTP and client certificates; audit log.
- HTTP API (`/dns-api/v1/`, OpenAPI) and remote MCP; API tokens, OIDC providers, anonymous read.

## Next — v1.1: DNS monitoring

What is happening on the DNS servers, as opposed to NS Pulse, which answers "is this endpoint alive".

- Query statistics from every secondary: QPS and history, query types, response codes, UDP/TCP, traffic.
- Top clients and top names, to see load and attacks at a glance.
- Transfer and serial state per server and zone.
- Server load: CPU, memory.
- Charts per server and per group, and an overview dashboard of load and anomalies.

Planned storage: time series in VictoriaMetrics; high-cardinality data (client addresses, query names) in VictoriaLogs rather
than in metric labels. Charts inside the panel; Grafana stays an option for deeper analysis.

## Later

- Health-based DNS failover beyond single records.
- GeoDNS and traffic steering.

## History

| When | Milestone |
|------|-----------|
| July 2026 | Zone and record management on PowerDNS: primary, secondary, reverse zones with PTR; first catalog zones |
| August 2026 | Users, groups and permissions. High availability: first in Perl, then rewritten as one Go manager with promotion authority and a fenced standby; live acceptance on a real pair. One-command installation into `/opt/dns-panel` |
| early September 2026 | Distribution reworked around servers, groups and catalogs; TSIG handled end to end. NS Pulse with remote testers |
| mid September 2026 | Migration from an old BIND master; Dynamic DNS; Pinger |
| late September 2026 | DNSSEC with migration of signed zones; clean-install and reboot acceptance of a pair; HTTP API v1, remote MCP, API tokens and OIDC; built-in documentation |
