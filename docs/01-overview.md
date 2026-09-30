# 01 — Project overview and goals

## Why

The DNS network runs on **BIND** with an old in-house panel (PHP + Python) in LXC on an outdated Debian
that cannot be upgraded. The project replaces the master and the panel:

- **Shadow-master on PowerDNS** — a hidden authoritative master: it is not published in NS records and does not
  serve public queries. It stores zones in MySQL (`gmysql`) and sends NOTIFY.
- **Secondaries stay on BIND** — public name servers that pull zones from the shadow-master via AXFR.
- **Our own panel** on top of PowerDNS. Existing ones (e.g. PowerDNS-Admin) are overly complex, ship in Docker and
  are written in Python — that does not suit us.

Zones from the old master are migrated by the panel — [26-zone-import.md](26-zone-import.md).

## Principles

1. **Zone data lives in PowerDNS** (`domains`, `records`, `domainmetadata`, `cryptokeys`). The panel is an editor
   on top of it and keeps no copies.
2. **The panel's own DB holds only its own data:** users, permissions, audit, distribution, profiles, labels, NS Pulse
   ([03-database.md](03-database.md)).
3. **No heavy frontend.** Server-side rendering + targeted AJAX; no SPA frameworks and no build step.
4. **No Python and no Docker.** Deployment is a file tree in `/opt/dns-panel`, Apache + `mod_fcgid`, systemd units
   for the Go daemons.
5. **Every change to zone data increments the SOA serial** — otherwise the secondaries do not update.

## Scope

- Internal and external zones, subdomains and delegation, reverse zones and PTR.
- Security records (CAA, TLSA, SSHFP, SPF/DKIM/DMARC, etc.).
- Secondary zones: PowerDNS pulls the zone from an external master itself and serves it onward.
- Zone distribution to secondaries: Direct AXFR and via RFC 9432 catalogs ([16-delivery.md](16-delivery.md)).
- DNSSEC: signing, key management, migrating signed zones together with their keys.
- Dynamic DNS (RFC 2136 UPDATE from DHCP with TSIG).
- HA pair with manual switchover ([22-ha-contract.md](22-ha-contract.md)).
- NS Pulse: switching records based on the results of external checks ([25-ns-pulse.md](25-ns-pulse.md)).

The zone and record model — [05-dns-model.md](05-dns-model.md).
