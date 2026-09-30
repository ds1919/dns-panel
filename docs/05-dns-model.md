# 05 — Zone and record model

What the panel models and how.

## Zone types (`domains.type`)

| Type | What it means here |
|-----|-------------|
| `MASTER` (Primary) | A zone for which our PowerDNS is the source. Edited in the panel, NOTIFY is sent out. The main case. |
| `SLAVE` (Secondary) | PowerDNS pulls the zone itself via AXFR from someone else's primary (`domains.master`). Records are read-only; the panel edits only the source. |
| `NATIVE` | The panel does **not create** such zones (Add zone offers only Primary and Secondary). An existing NATIVE zone is shown as is and can be made Secondary. PowerDNS serves AXFR for NATIVE zones, but does not send NOTIFY and does not put them in a catalog (`gmysql-info-all-primary-query` filters `d.type in ('MASTER','PRODUCER')`): downstream learns about a change only through SOA refresh. |

### Secondary: distribution downstream

A secondary zone can be served to its own receivers through the direct list (`zone_direct_axfr`) — this is a property of the zone,
not of the role. For such a zone the panel sets `SLAVE-RENOTIFY`, otherwise PowerDNS does not send NOTIFY downstream after a transfer. A
secondary zone is not put in a catalog: the PRODUCER announces only the server's own zones. Details —
[16-delivery.md](16-delivery.md).

### Secondary: where it comes from and when it arrives

The Secondary block on the zone page shows the upstream, TSIG, serial and transfer state; its header has two
buttons. **Edit upstream** (`PUT /zones/:id/secondary-source`) changes the primary addresses and the key. **Refresh AXFR**
(`POST /zones/:id/refresh-axfr`, write access to the zone) asks PowerDNS to pull the zone again —
`pdns_control retrieve` once, even if the zone is already Active; Edit upstream does the same after saving.
This is what distinguishes the button from Retry now in the problems banner: that one requests a transfer only while the zone has not arrived.
An explicit request also bypasses the PowerDNS backoff after the master refuses.

The response is "AXFR requested", not "arrived". Arrival is `domains.last_check` (Last check in the block): PowerDNS sets it
after a successful check against the primary, and changing the source or Make secondary resets it. A secondary counts as
Active only when it is served **and** checked against the current primary; the sync worker takes over the waiting from there. In the audit log —
`refresh_axfr`.

### Dynamic updates (RFC 2136)

Accepting updates is enabled in Zone settings (Dynamic updates: On / Off; for a secondary — in advance). Who may update the zone
(usually DHCP) is a **property of the zone itself**: the **Dynamic updates** button in the zone header (present only when accepting is
enabled), a separate modal; it does not touch the flag. It holds DHCP server addresses and/or **one** TSIG key (name,
algorithm, secret — like `key "…" { algorithm …; secret "…"; }` in BIND; the key is shown in clear, there is Generate).
The mode follows from what is set:

| Set | ALLOW-DNSUPDATE-FROM | TSIG-ALLOW-DNSUPDATE |
|--------|----------------------|----------------------|
| addresses | DHCP addresses | — |
| key | `0.0.0.0/0`, `::/0` (any address) | key |
| both | DHCP addresses | key |

Identical settings for many zones are a **Dynamic DHCP profile** (Settings → Dynamic DHCP profiles). A zone can
**follow** it ("Follow profile changes"): a profile edit reaches all such zones and PowerDNS right away. Editing
any field in the zone or clearing the checkbox breaks the link — the values stay. "Save as profile" is in the zone settings.
Deleting a profile leaves the zones their values. The values always live with the zone (`zone_dynamic` +
`zone_dynamic_sources` / `zone_dynamic_keys`); the profile is `dyn_profiles` + its own addresses/key.

A key name in PowerDNS is one per installation. The same name with the same secret is the same key; with a different secret it is
a **key change** (audit log: `tsig_key_update`), and it is allowed only if the key is used only by those the
edit affects: the profile and the zones following it, or this one zone. If anyone else holds the key — refused,
a different name is needed. On every pass the sync worker also reconciles the keys of dynamic zones and profiles with PowerDNS. A key goes away
by itself when nothing refers to it anymore. `NOTIFY-DNSUPDATE` is always set — otherwise the secondaries would not learn
about the update. PowerDNS increments the serial itself.

Accepting updates is for primaries only. Add zone and Reverse offer to follow a profile right away. For a secondary the settings are set
in advance — they take effect after Make primary; for a migrated dynamic zone (`X-DNSPANEL-IMPORT-DYNAMIC`) Make
primary promotes it only with accepting enabled and only when the settings are already set, and removes the migration mark. Make
secondary turns accepting off (the settings stay). The flag and the values are intent: if the PowerDNS API did not respond,
the sync worker finishes applying them.

**pdns.conf is not touched at runtime and PowerDNS is not restarted.** At installation: `dnsupdate=yes`,
an **empty** `allow-dnsupdate-from` (the global list is added to the zone's) and `forward-dnsupdate=no`
(`docs/INSTALL/reference/03-powerdns.md`).

### DNSSEC

PowerDNS signs by itself, on the fly, from its own keys; the panel manages them. The **DNSSEC** button in the header of a
primary zone: sign with one CSK (default `ECDSAP256SHA256`), add a key (generate or
import a BIND `.private`), Activate/Publish, delete, unsign; the DS for the parent (SHA-256)
is shown for KSK/CSK. API: `GET|PUT /zones/:id/dnssec`, `POST /zones/:id/dnssec/keys`,
`PUT|DELETE /zones/:id/dnssec/keys/:kid`. Every key change bumps the serial.

Records are written with SQL, so a signed zone needs a rectify after every write: it is done inside
`zone_sync_verify`, and a failure counts as a failed activation (the sync worker retries it). Signature data is not shown or counted in the
record list. Migrating a signed zone from the old server together with its keys —
[26-zone-import.md](26-zone-import.md).

### Changing the zone role

The role changes in both directions, in one place — the zone's own Zone settings.

| Operation | What it does |
|----------|-----------|
| **Make primary** (`POST /zones/:id/promote`) | `SLAVE` → `MASTER`. Records and the SOA serial stay, the upstream and its TSIG are removed. Requires the zone to have arrived already: a zone without SOA would become an empty authoritative one. |
| **Make secondary** (`POST /zones/:id/demote`) | `MASTER`/`NATIVE` → `SLAVE`. Needs primary addresses (at least one) and, optionally, TSIG. From then on records arrive via AXFR and are not edited by hand. |

Both are confirmed with the zone name on the API (`confirm_name`). In the interface the name is typed only for **Make secondary**:
there the zone's records are replaced by the transferred ones, while with Make primary they stay in place.

A role change does not touch the direct distribution. It does touch the catalog: `Make secondary` removes the zone from the catalog
(the PRODUCER announces only its own zones); the form says so before the click, and on the API the removal additionally requires
`distribution.manage`.

**Local records are erased on Make secondary**: the content is at the primary, and until the transfer arrives
there is nothing to serve — "the zone is served" means exactly "the zone has arrived". The type, primary addresses, key, resetting
`last_check` and erasing the records are ONE transaction in the PowerDNS database, and only after it does PowerDNS
learn about the new role (why — [24-dns-engine.md](24-dns-engine.md)).

The primary addresses and key in both operations are validated by one function, `_secondary_source_fields`, and a source edit
on an existing secondary is written by `zone_secondary_source_set` — in one transaction.

## Internal vs external domains

A zone has no separate "internal/external" attribute — it would decide nothing in DNS. The question splits into three:

1. **Different NS/SOA/catalog → different profiles** ("FXTM Internal" and "FXTM External"). A profile is one preset,
   and it also holds the default catalog. It is needed when creating a primary — it provides the initial SOA/NS; after creation
   the profile is an optional binding (`X-DNSPANEL-PROFILE`) that can be removed (`None`). For a secondary, SOA and NS
   arrive via AXFR, so it needs no profile.
2. **An attribute for the eye and for filters → a label** (Labels, e.g. a `Scope` category with the values
   `Internal`/`External`).
3. **Who actually receives the zone** is decided by distribution (Propagation/Catalog) — the only place where such a
   decision takes effect.

## Subdomains and delegation

- A subdomain within the same zone is just records with a `name` like `sub.example.net`.
- Delegation to a separate zone is `NS` records in the parent + a separate zone. Creating a zone with delegation
  writes the NS into the parent in the same transaction (and bumps its serial); the zone delete dialog names its
  delegated child zones.

## Record types

Allowed types (`dns_validate`): `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`, `PTR`, `SRV`, `CAA`, `TLSA`,
`SSHFP`, `SPF`, `NAPTR`, `DNAME`, `DS`; `SOA` is edited separately. For `MX`/`SRV`/`CAA` the form assembles `content` from
fields; for the rest it is a single value with format validation. The zone's own DNSSEC records (`DNSKEY`, `RRSIG`, `NSEC*`,
`CDS`/`CDNSKEY`) are maintained by PowerDNS and are not created by hand.

## SOA and serial

- `content` format: `primary hostmaster serial refresh retry expire minimum`.
- Defaults for new zones (NS/hostmaster/SOA timers) are in `zone_profiles` (Settings → Zone profiles); without a profile
  NS and hostmaster come from the form, and the timers are standard. The serial of a new zone is `YYYYMMDD01`.
- **Every change to zone data bumps the serial exactly once** (inside `pdns_apply_rrsets`), otherwise
  the secondaries do not pick up the changes.

## NOTIFY / AXFR

Who the zone is served to and who gets NOTIFY, the panel writes into the zone metadata (`ALLOW-AXFR-FROM`,
`TSIG-ALLOW-AXFR`, `ALSO-NOTIFY`) from the direct list and the catalog — [16-delivery.md](16-delivery.md).
