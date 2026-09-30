# 26. Migrating zones from the old master

The task is not "importing files" but **moving**: the old BIND has hundreds of zones, and they have to be taken
together with their records, without typing anything by hand. There is one scenario: old BIND → this panel.

## Where the list comes from

You cannot ask DNS to "list your zones": AXFR works only by a known name, and the old server has no catalog
(RFC 9432). The list comes as a file that BIND lays out itself:

```
named-checkconf -p > bind-export.conf
```

`include` directives are already expanded, everything is normalized to one form. The file is parsed once and stored as a list in the database
(`import_sources` + `import_zones`); the file itself is not kept (only its sha256). The columns hold what is used for
filtering and decisions: name, role, `masters` of slave zones, the dynamic flag, the signed flag; everything else
that was read (ACLs, `also-notify`, `allow-query`, forwarders, key names, zone file, unknown directives) goes
into `config_json`, for reference. From keys and ACLs the panel takes only what dynamic zones need: who is allowed
to update them, together with the secrets of those keys (secrets are not sent to the browser).

The old DNS address is taken from the file (`listen-on`, non-loopback addresses): if there is one candidate, it is filled in;
if there are several, the panel lists them and waits for a choice.

## How the content moves

Records are fetched by **PowerDNS itself over AXFR**, not by a parser:

```
the zone is created as Secondary → AXFR → you see what arrived (SOA, number of records)
   → from then on it is a regular panel zone: Make primary or leave it Secondary
```

What arrives is exactly what the old server **currently serves**.

### Where the zone will be transferred from

| what it was on the old server | where we take it from | what next |
|---------------------------|-----------------|------------|
| `master` / `primary` — its own zone | from **it** | a mirror with the migration marker `X-DNSPANEL-IMPORT`; we promote it when ready |
| `slave` / `secondary` — someone else's zone | from **its own masters** (`masters` from the config) | a regular panel secondary zone, without the marker; no reason to promote it |

Using the export server's address for all of them is not an option: someone else's zone would update only until that server is switched off, and then
would silently freeze.

## Each load is a separate operation

One load is **one old DNS server**. A second server can be loaded any time later; its list is compared with
what the panel has NOW:

| What the panel has | What we show |
|--------------|----------------|
| no zone | `new` — create a Secondary from this source |
| Secondary from THIS same address | `same source` — already taken from here |
| Secondary from a different address | `other source` — already exists, taken from a different address |
| Primary/Native | `ours` — already exists, it is ours |

**Import never touches an existing zone.** What to do with a match is decided by a person in Compare (below).
Two versions of one zone are not mixed. The database does not remember what the zone was on another old server: `other source`
says only "Secondary from such-and-such address", next to the role from the current export.

Reloading an export of the **same** master updates rows by name, adds new ones, detects changed ones
by `config_hash`, and marks disappeared ones as `gone` (`last_seen_at` older than the load). The `new` and
`changed` flags are reset at the start of each load of this source — the `Since last load` filter.

Row state:

| state | meaning |
|-----------|------------|
| `pending` | nothing done yet |
| `imported` | created by THIS migration operation (`panel_zone_id` is ours, the zone is in place) |
| `imported_gone` | we created it, but the zone is no longer in the panel |
| `exists` | **conflict**: a zone with this name exists, but it did not come from here ("Conflict — already exists") |
| `reviewed` | the current version was chosen ("Kept current") |
| `failed` | an attempt was made and failed, the reason is in `note` |

## Parsing: what gets flagged

- **Dynamic zones** (`allow-update`, `update-policy`). `allow-update` is expanded through named ACLs into
  addresses and keys; `update-policy`, `any`, negations and anything else that cannot be carried over are shown as is.
  The flag is written to the zone (`X-DNSPANEL-IMPORT-DYNAMIC`) in the same transaction as the zone itself.
- **Signed zones** (`auto-dnssec`/`inline-signing`) — `X-DNSPANEL-IMPORT-DNSSEC`, see "DNSSEC" below.
- **`in-view "…";` is not a zone**, but a reference to the same zone from another view; such blocks are not counted as zones.
- **One name with several real definitions** (split-horizon) — `review`, cannot be selected: the panel has one zone
  per name.
- **An empty `forwarders { };`** means nothing; a non-empty one — `review`.
- **The root zone `.` (`hint`)** does not get into the list. Other unsupported types (forward, stub…) are visible, but
  without a checkbox.
- **Unknown directives** are not thrown away: their names go into `review`, and the zone is flagged.

## Screen

**Settings → Import.** At the top are the same filters as on Zones (a shared component): search, Status, Kind, Type,
Dynamic, Master, DNSSEC, Review, Since last load and `Clear`, which appears only when something is selected.
Rows are selected with the checkbox in the header, as in Users & access: it takes the rows visible after filtering; rows hidden by the filter are not
dropped from the selection. **Checkboxes are never set automatically.** Clicking a name expands the row: everything read from the
config and everything the panel knows about its own zone with the same name.

### Probe source

The `Source serial` and `Source records` columns are **the old server's side and only that**. The import server
(`import_sources.master`) is queried, including for its slave zones. One AXFR through dns-agent (`axfr_at`) gives the serial and
the number of records. **Probe source** only queues zones (`probe_state = queued`); the worker does the querying —
a batch per pass (`settings.import.probe_batch`, 50 by default; no longer than `import.probe_budget_seconds`,
60 s), the result is stored in the row (`source_serial`, `source_record_count`, `probed_at`). If it did not transfer, a
`no transfer` badge with the reason: REFUSED — allow-transfer does not let us in, SERVFAIL — the zone is not loaded on the server itself,
NOTAUTH — the zone is not its own or the key was not accepted. If it did not answer at all, the reason is set at once on all queued zones of the source.
Not probed — a dash. A zone that we also have, with a different serial, gets a `serial differs` badge.

### Compare and Copy

**Compare** (in the expanded row, for a zone that exists in the panel) — a live AXFR from the source against our zone in
PowerDNS (`GET /import/zones/:id/diff`). Two tables side by side: on the left **Import · source address**, on the right
**Current**, each with its serial. One row is one name+type, in zone order; differences are highlighted, a different TTL
is labelled. The `All changes` (default) / `Different` / `Import only` / `Current only` /
`Identical` switch with counts, and search by name, only change which rows are visible. The SOA is compared in full, except for the serial.
Both sides are normalized the same way (names, including inside CNAME/NS/PTR/MX/SRV/SOA, are lowercase without the trailing
dot; the MX/SRV priority is in the data); signature data (RRSIG/NSEC/DNSKEY…) is not compared.

**Copy — individual records, without importing the zone.** The → arrow carries an RRset from Import to Current as a whole
(name+type). Until applied, this exists only in the window: the Import version appears on the right, × cancels the copy; checkboxes (on Import only) +
`Copy N selected` — several at once, the selection survives filter changes and search. Only `Apply
changes` writes to the zone: `POST /import/zones/:id/copy {rrsets:[{name,type}]}`. The browser sends only the keys — the server takes the content
from a live AXFR. The write path is the same as for record editing (`pdns_apply_rrsets`: one transaction, one
serial bump, audit `replace_rrset` marked "copied from import"), permissions — write on the zone. Role, profile and
distribution do not change; the apex SOA and NS are not copied; a Secondary has no arrows.

For a zone in conflict, the same window offers a decision for the zone as a whole:
- **Keep current** — the row is no longer offered (`reviewed`); you can change your mind in the same place.
- **Import this version** (`POST /import/zones/:id/take`) — the zone becomes what the migration would have made it:
  a Secondary from the same place (for a master zone of the source — the source itself, for its slave zone — that zone's masters), with the same flags.
  A Primary goes through Make secondary (records are erased, the catalog is removed, confirmation by zone name);
  for a Secondary only the source changes and an AXFR is requested immediately.

## TSIG

**The key for AXFR from the export server** is a single shared control, the same as for any Secondary zone (Add zone, Zone
settings → Upstream primaries, Make secondary): None / an existing key / "+ Add key…" (name, algorithm,
secret; you can paste a BIND `key {…}` block). Which key the old server requires does not follow from its config,
so the control appears only when Probe has shown a transfer refusal (REFUSED/NOTAUTH or a rejected
key) or a key is already selected. The zone stores only the key name (`AXFR-MASTER-TSIG`).

- A new key is created once per batch, in the panel and in PowerDNS, after all shared checks. A name already taken
  by a key in PowerDNS is a refusal: the panel does not overwrite someone else's secret.
- After each batch the new key goes through cleanup: if nothing refers to it (for example, the batch contained
  only someone else's secondary zones), it is deleted. Cleanup looks at real references and does not touch a key in use.
- **Probe and Compare are signed with the same key** that is selected for the migration; the name is remembered on the source
  (`import_sources.probe_tsig`), the worker takes the secret from PowerDNS. A key in "new" mode is not available for probing —
  the first migration creates it. dns-agent passes the key to dig via stdin and treats as an error a run in which dig
  did not read the key (otherwise dig silently does an unsigned AXFR).
- **The old server's secondaries of someone else's zones** are transferred from their own masters with their own key: if a key with the same name already exists in
  PowerDNS, it is set automatically; otherwise the row is marked `TSIG key required: <name>`, and the key is set in Zone settings.
- A key that nobody uses after `Make primary` or zone deletion is removed from the panel and from PowerDNS automatically.

## Creation — through the common path

`POST /zones/import` carries only `source_id` and the names; zones are created by the same function as "Add zone"
(`pdns_create_zone`). Everything else the core takes **from the saved list**, not from the browser:

| from the list | what for |
|-----------|-------|
| `import_sources.master` | export server address |
| `import_zones.source_type` | its own zone or someone else's, whether it is transferred by AXFR at all |
| `import_zones.source_master` | the real masters of someone else's secondary |
| `last_seen_at` | the zone is not in the latest load — refusal |
| `dynamic`, DNSSEC, `allow-update` | zone flags and its Dynamic updates settings |

The browser sends batches of 50 (the core accepts up to 200). A zone that failed to be created is reported **inside the successful
response** of the batch, and the migration continues; a failure of the request itself stops the migration, the screen rereads the list,
a retry is safe. The zone and its markers are one transaction; the `import_zones` row follows, and if it
fails to be written, the zone is removed and goes into the failures. PowerDNS learns about created zones with one `rediscover` per batch,
then an AXFR request for each; the worker watches for arrival. If the agent did not answer, the remaining zones of the batch immediately get
`transfer_problem`.

There is no profile during migration: SOA and NS arrive via AXFR, and one profile per batch would be wrong — a single export contains zones
of different brands. `X-DNSPANEL-PROFILE` is not written, `Make primary` does not rewrite SOA and NS; a profile can be
set in Zone settings if desired.

**Dynamic zones** get the "who is allowed" settings right at import (for a secondary they wait for Make primary):
if there is a Dynamic DHCP profile with one of the old keys, the zone follows it; otherwise the addresses and key from `allow-update`
(ACLs expanded). The key is taken from the export itself (`key { algorithm; secret; }`) and is created once for all
zones; a panel key with the same name and a different secret is not touched — the zone gets a flag. If the key is not defined in the file
(the include did not get into the export), the zone is flagged `TSIG key required`, and the Dynamic updates form fills in the name and
algorithm and asks only for the secret. A zone that already had settings keeps them. Redirecting DHCP to our
address is DHCP server configuration, which the panel does not manage.

The log gets a `create_zone` entry for each zone and a separate `import_zones` entry for the batch.

## Promotion — a separate step, on the zone itself

Import makes the zone a **mirror of the old server**: a Secondary without downstream distribution. It is promoted in the same place as any
other zone: **Zone settings → Make primary**. What is checked and what happens:

- **only what has arrived is promoted**: a zone without an SOA is refused;
- **the version is checked against the source**: for a zone with `X-DNSPANEL-IMPORT`, Make primary asks the old
  server for the SOA (`soa_at` through dns-agent) and compares the serial. Fail-closed: no answer or a mismatch — no
  promotion. It can be bypassed only explicitly (`ignore_source_serial`) — when the old server is already switched off;
- **dynamic** zones (`X-DNSPANEL-IMPORT-DYNAMIC`) — only with update acceptance and only when the settings
  are defined: in the Make primary window acceptance is turned on automatically, otherwise the role change would silently cut off DHCP;
- **signed** zones — with their keys carried over, or explicitly without DNSSEC (below);
- migration markers are removed; distribution does not change — Direct AXFR and the catalog are assigned in Zone settings.

### DNSSEC

A signed zone arrives as a mirror with foreign signatures. Keys are uploaded from the **DNSSEC** badge in the import
row: based on the source's live DNSKEY set, the modal names the required files `K<zone>.+<alg>+<tag>.key/.private`
and accepts them (`POST /import/zones/:id/dnssec/keys`); the private parts are stored in the list row until promotion.
The same place offers "Drop DNSSEC" (`PUT /import/zones/:id/dnssec`): the zone is promoted unsigned, and the DS at the registrar
must be removed beforehand.

`Make primary` carries the keys over (`_dnssec_promote_plan` / `_dnssec_promote_finish`):

1. every DNSKEY that arrived via AXFR must match an uploaded pair in full (flags, algorithm, public key),
   otherwise the refusal `DNSSEC private key missing`;
2. the keys are created through the API while the zone is still a secondary and read back — PowerDNS must hold the same DNSKEYs, otherwise
   rollback;
3. role change; presigned data (RRSIG/NSEC/NSEC3/DNSKEY/CDS/CDNSKEY/TYPE65534) and the `PRESIGNED` flag are removed,
   NSEC3PARAM stays the same, a new serial and rectify;
4. the private keys are deleted from the import list.

The DS at the registrar does not change.

### Gradual replacement of a live master (cutover)

If the old BIND is an active primary with many secondaries of its own, promotion is **the moment the zone changes owner**.
The order for one zone:

```
1. the zone is imported, it is a Secondary of the old BIND                → production untouched
2. the old BIND is added in Propagation and Direct AXFR is enabled for the zone — BEFORE promotion
3. changes are frozen on the old BIND
4. Make primary in the panel (it checks the serial against the old BIND itself)
5. right after that, on the old BIND the zone becomes a Secondary of our PowerDNS
       PDNS Primary → old BIND Secondary → its secondaries keep transferring as before
6. secondaries are moved to our distribution one by one; when the last one has moved, the old BIND is switched off
```

**Promote ourselves first, then demote the old server**: the other way round would create a loop of two Secondaries, and
there would be nothing to check the serial against. The short interval with two primaries is safe: changes are frozen,
versions are checked.

**Step 2 is mandatory**: an imported zone is created without distribution, and the old server would get REFUSED. Both
conditions are needed: the old server is in Propagation (its address goes into `ALLOW-AXFR-FROM`) **and** the zone has Direct AXFR. If it is
in a group with TSIG, it needs a key. The old BIND's config is edited by hand: the panel does not manage it.
