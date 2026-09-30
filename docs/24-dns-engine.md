# 24. DNS engine: why PowerDNS + gmysql

What the panel is built on, why, and under what conditions we will revisit the question.

## Decision

**PowerDNS Authoritative + the `gmysql` backend**. The panel works with the `pdns` database directly (SQL) where
the operation must be atomic and complete, and via the **PowerDNS HTTP API** where it concerns PowerDNS's own state: cache,
kind change, TSIG keys, DNSSEC keys and rectify, part of the metadata. Immediate actions after a write
(`purge`, `notify`, `retrieve`, `rediscover`) go through `dns-agent` — the PowerDNS control socket.

What is not there: the `remote` backend, a second engine alongside, our own copy of the zones in the panel database, an intermediate publisher.

## Why not the API alone

- The API does not serve the **`AXFR-MASTER-TSIG`** metadata endpoint (it responds 422). Therefore the source of a secondary zone
  is changed in one SQL transaction — addresses, `last_check` and key together (`zone_secondary_source_set`): done separately,
  any failure between steps would leave the new key with the old address — a zone that silently does not transfer. The zone cache
  is cleared by `rediscover` after the transaction.
- **There is no atomicity across API steps.** Changing the role to secondary means changing, all at once, the zone type, the primary addresses,
  the key, resetting `last_check` and erasing the local records. Via the API these are several independent requests, and
  between them PowerDNS could pick up the zone with the new source, and a late erase would wipe records that had **already
  arrived**. In one database transaction it is a single change, and PowerDNS learns of the new role after it.

Rule: **direct SQL where the operation must be atomic or where the API cannot handle the needed field; the API where
it concerns PowerDNS's own state.**

## Who owns what

| Zone | Who writes the content | What the panel does |
|------|----------------------|-------------------|
| Primary (`MASTER`/`NATIVE`) | the panel | edits records, maintains the serial, DNSSEC keys, shows history |
| Secondary (`SLAVE`) | PowerDNS via AXFR from someone else's primary | edits only the **source** (addresses, TSIG) and direct downstream distribution; records are read-only |

A secondary zone can be distributed downstream via the direct list, but not via a catalog: a producer announces only the server's own
zones (see [16-delivery.md](16-delivery.md), [05-dns-model.md](05-dns-model.md)).

## The panel's duties with direct SQL

Writing into someone else's schema means taking on what the server would otherwise do:

- **Data correctness.** Type, content and name are validated before the write (`dns_validate`,
  `dns_record_name_norm`): the name is normalised (no trailing dot, except for the root), broken names
  are rejected, not "fixed".
- **Transactions and lock order.** Every edit is one transaction. The order is shared: `domains` rows in
  ascending `id` order (`SELECT … FOR UPDATE`), then SOA rows, then records. One order on all paths —
  otherwise two operations on the same pair of zones deadlock against each other.
- **The role is checked under the lock.** An early check gives a clear error before any work, but the deciding check is
  the one **inside the transaction** (`_lock_zones_writable`): while the edit waited in line, the zone could have become
  secondary, and the first AXFR would wipe the edit. Zone deletion also takes the `domains` row first. Creating a
  zone with delegation locks and checks the parents before any write; a refusal is total.
- **Serial.** Every transaction bumps the serial exactly once, on the already locked SOA row.
- **Actions after the write.** PowerDNS does not learn of an edit in the database by itself: the panel runs rectify on a signed zone,
  `purge` (cache), `notify` (recipients) and, for secondary, `retrieve` via `dns-agent`, and records the outcome in
  `zone_sync_state`.
- **Schema compatibility.** We write only to gmysql tables (`domains`, `records`, `domainmetadata`; on
  zone deletion also `comments`, `cryptokeys`) and in the same fields as the server; the only extension is
  `records.updated_by`/`updated_at` ([03-database.md](03-database.md)). The PowerDNS schema may change in a new
  major version — it must be checked on upgrade.

**Boundary.** The locks order the panel's operations: edit ↔ role change ↔ zone deletion. PowerDNS itself
(an AXFR in progress, its own metadata such as `CATALOG-HASH`) writes to the database on its own schedule and is not governed by these
locks: between deleting a zone in SQL and telling PowerDNS about it, the daemon may write a row about a zone that no longer exists.
If a problem shows up there, it is fixed separately, not by extending this mechanism.

## What we considered and rejected

- **The `remote` backend** (PowerDNS asks the panel on every query). The panel ends up in the name resolution path:
  its failure becomes a DNS outage, not an interface outage. Today the panel can be down while the server answers.
- **A chain of DNS servers** (the panel writes to its own server, which serves further). One more node to maintain
  for a task that a database transaction solves.
- **A copy of all records in the panel database** (the panel is the source of truth, PowerDNS is derived). Two copies
  diverge, and the question arises which one is right. There is one source of truth: the PowerDNS database.

Rejected on maintenance cost, not on principle.

## When we will revisit the engine comparison

The trigger is a concrete need:

- hundreds of zones edited concurrently are needed, and the bottleneck is the engine itself or its database;
- a PowerDNS upgrade breaks the `gmysql` schema so that direct SQL is no longer an affordable price;
- a requirement appears that PowerDNS does not support at all (a specific data type, custom response logic).
