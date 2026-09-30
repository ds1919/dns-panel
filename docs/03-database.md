# 03 — Database schema

**Two independent databases** are involved:

1. **The panel database** `dns_panel` — our own. Schema: `docs/INSTALL/schema.sql`.
2. **The PowerDNS database** `pdns` (`gmysql` backend) — what we manage. The schema is the standard PowerDNS one;
   this section describes **what we use from it**.

---

## A. Panel database (`docs/INSTALL/schema.sql`)

Zone records are not stored here — only what PowerDNS does not have: users and permissions, the distribution inventory,
panel zone settings, monitoring, migration. References to a zone are logical (`domain_id`/`zone_id` →
`pdns.domains.id`, no FK across databases). HA roles are not here: they live in the local non-replicated `dns_ha`
([23-ha-manager.md](23-ha-manager.md)).

| Group | Tables | Details |
|--------|---------|----------|
| Identity and login | `users`, `auth_identities`, `password_credentials`, `totp_credentials`, `recovery_codes`, `sessions`, `auth_throttle` | [08-auth.md](08-auth.md) |
| External access | `api_tokens` | [11-api.md](11-api.md) |
| Permissions | `groups`, `user_groups`, `zone_access`, `capability_grants` | [20-permissions.md](20-permissions.md) |
| Panel settings | `settings` (changed keys only; defaults in code) | |
| Log | `audit_log` | [15-audit-log.md](15-audit-log.md) |
| Distribution inventory | `tsig_keys`, `ip_groups`, `ip_group_members`, `secondary_groups`, `secondary_nodes`, `secondary_group_members`, `secondary_node_endpoints`, `secondary_group_ip_groups`, `secondary_group_tsig_keys`, `secondary_node_tsig_keys` | [16-delivery.md](16-delivery.md) |
| Zone distribution | `catalogs`, `catalog_groups`, `catalog_nodes`, `catalog_primary_endpoints`, `catalog_subscriptions`, `zone_direct_axfr` | [16-delivery.md](16-delivery.md) |
| Dynamic updates | `dyn_profiles`, `dyn_profile_sources`, `dyn_profile_keys`, `zone_dynamic`, `zone_dynamic_sources`, `zone_dynamic_keys` | [05-dns-model.md](05-dns-model.md) |
| Zone profiles and labels | `zone_profiles`, `zone_profile_nameservers`, `label_categories`, `label_values`, `zone_labels` | [05-dns-model.md](05-dns-model.md) |
| Sync state | `zone_sync_state` (`pdns_state`/`notify_state`, attempts, `next_retry_at`) | [02-architecture.md](02-architecture.md) |
| Monitoring | `probe_policies`, `record_health`, `zone_lifecycle`, `monitoring_sources` | |
| NS Pulse | `pulse_*` | [25-ns-pulse.md](25-ns-pulse.md) |
| Migration from the old BIND | `import_sources`, `import_zones` | [26-zone-import.md](26-zone-import.md) |

A few schema rules worth knowing:

- **`auth_identities`** — external methods only (`cert`/`oauth`). `provider`/`principal` are NOT NULL, otherwise
  UNIQUE(`type`,`provider`,`principal`) would not make NULLs unique and one CN could be bound to two users.
  "One password / one TOTP per user" — `PRIMARY KEY(user_id)` in `password_credentials`/`totp_credentials`.
- **`sessions.token`** — hex SHA-256 of the cookie token; the token itself is not stored. Logout — `is_active=0`.
- **`tsig_keys`** are immutable (name/algorithm/secret are set on creation); the secret is not written to `audit_log`.
- **Protection against deleting** an object in use — FK RESTRICT, not just a preliminary COUNT.

---

## B. PowerDNS database (gmysql)

The panel writes to `domains`, `records`, `domainmetadata` directly (SQL) and reads `tsigkeys`/`cryptokeys`;
TSIG keys and DNSSEC keys are created via the PowerDNS HTTP API. `comments` is only cleaned up when a zone is deleted;
`supermasters` is not used. Why — [24-dns-engine.md](24-dns-engine.md).

### `domains` — zones

| Field | Purpose |
|------|-----------|
| `id` | zone ID (panel URL `?zone=<id>`, references from the panel database) |
| `name` | zone name, without the trailing dot |
| `type` | `MASTER` / `SLAVE` / `NATIVE` (+ `PRODUCER` for catalogs) — see [05-dns-model.md](05-dns-model.md) |
| `master` | for `SLAVE`: primary addresses separated by `,` |
| `last_check` | for `SLAVE`: when PowerDNS last checked with the primary; changing the source resets it |
| `notified_serial` | serial of the last NOTIFY sent, **not** the current SOA serial |
| `catalog` | catalog membership — the single source of truth ([16-delivery.md](16-delivery.md)) |
| `account` | not used: our own markers go in `X-DNSPANEL-*` metadata |

The serial in the UI is the third field of the SOA record (`soa_serial` in `pdns_list_domains`/`pdns_get_domain`), not `notified_serial`.

### `records` — zone records

Standard fields (`domain_id`, `name`, `type`, `content`, `ttl`, `prio`, `disabled`) plus two panel fields
added at installation (`docs/INSTALL/reference/03-powerdns.md`): `updated_by`, `updated_at` — who changed the record and when.
PowerDNS lists columns explicitly, so extra ones do not bother it.

The record list (`pdns_list_records`) and counters do not show empty non-terminals (rows without `type`) or
signing data (`RRSIG`, `NSEC`, `NSEC3`, `NSEC3PARAM`, `DNSKEY`, `CDS`, `CDNSKEY`, `TYPE65534`).

SOA `content`: `primary hostmaster serial refresh retry expire minimum`. The serial is bumped once per
transaction inside `pdns_apply_rrsets` (`_lock_soa` → `_bump_soa_row`, under `SELECT … FOR UPDATE`).

### `domainmetadata` — zone metadata

| kind | Who sets it and why |
|------|-------------------|
| `ALLOW-AXFR-FROM`, `TSIG-ALLOW-AXFR`, `ALSO-NOTIFY` | downstream distribution, from one calculation ([16-delivery.md](16-delivery.md)) |
| `SLAVE-RENOTIFY` | a secondary zone in distribution: NOTIFY downstream after a transfer is received |
| `AXFR-MASTER-TSIG` | the key a secondary zone uses to pull AXFR from the primary |
| `ALLOW-DNSUPDATE-FROM`, `TSIG-ALLOW-DNSUPDATE`, `NOTIFY-DNSUPDATE` | dynamic updates ([05-dns-model.md](05-dns-model.md)) |
| `PRESIGNED`, `NSEC3PARAM` | DNSSEC; `PRESIGNED` on migrated signed zones is removed on Make primary |
| `X-DNSPANEL-POLICY` | marker "the distribution policy was set by the panel" |
| `X-DNSPANEL-PROFILE` | zone profile code |
| `X-DNSPANEL-IMPORT`, `-IMPORT-DYNAMIC`, `-IMPORT-DNSSEC` | markers of migration from the old BIND ([26-zone-import.md](26-zone-import.md)) |

Our own markers go in `X-DNSPANEL-*` (PowerDNS allows applications metadata with the `X-` prefix), not in
`domains.account` — a free-form field that easily conflicts with other tools.

### What we do NOT do

- We do not create our own tables duplicating zones/records on top of PowerDNS.
- We do not bring in multitenancy, external providers or record version history without a clear need.
