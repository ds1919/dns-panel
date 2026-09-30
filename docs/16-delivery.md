# 16 — Zone distribution: direct distribution and catalogs

## Model

A zone has **two independent facts**. Neither is derived from the other, and changing one does not touch the other.

| | Direct = None | Direct = Allow |
|---|---|---|
| **Catalog = none** | nobody | everyone allowed in Servers |
| **Catalog = A** | subscribers of A | union |

- **Direct distribution** is a row in `zone_direct_axfr`. Receivers are not selected: it is the whole Servers inventory
  where a node is allowed to take zones (its own `axfr_policy=allow` or a group with `zone_axfr=1`).
- **Catalog** is `pdns.domains.catalog`, in PowerDNS itself. **There is intentionally no copy in the panel:** two copies
  of one fact diverge. Only subscribers that are allowed to take zones take a zone via the catalog; the others
  get only the list of names from us.
- **Networks of a group** (`secondary_group_prefixes`, the **Networks** field of a group with Require TSIG off) join
  `ALLOW-AXFR-FROM` of the zones the group receives, next to its servers' addresses: for AXFR clients that are a network,
  not a server. A TSIG group adds none — PowerDNS ORs the ACL with TSIG, so a network would allow unsigned transfers.
  Networks get no NOTIFY.

A catalog is a standalone object: `catalogs(id, name, fqdn, pdns_domain_id, last_error)` plus subscribers
(`catalog_groups`, `catalog_nodes`) and the addresses of our PowerDNS that the catalog publishes
(`catalog_primary_endpoints`). It is created in one action: a row plus a producer zone (RFC 9432) in PowerDNS.
There is no plan, no gates and no separate apply step.

PowerDNS limitation: a PRODUCER announces only its own primary zones. A secondary zone is **not accepted** into a catalog —
the refusal is explicit. It can still be distributed directly (the panel sets `SLAVE-RENOTIFY` on it).

## How it is applied

The single entry point is `apply_zones(\@ids)` (or `undef` = all distributed zones). A single zone, a list and the background
pass all go through it.

Inside, shared data is computed **once per call** (direct distribution receivers, subscribers of the affected catalogs,
node NOTIFY addresses, key reconciliation with PowerDNS, current metadata of all zones); per zone only comparison and
writing of the **differences** remain. If it matches, nothing is written: every metadata write is an API call.

Zone permissions — `ALLOW-AXFR-FROM` + `TSIG-ALLOW-AXFR` + `ALSO-NOTIFY` — are written **in one operation from one
calculation**: two paths writing them separately would overwrite each other.

`X-DNSPANEL-POLICY` is the panel's marker: by it the recovery pass (`orphan_policy_sweep`) tells our
policy apart from one set by hand and removes it from zones that nobody receives anymore. It is set first when
applying and removed last when cleaning up.

## What lives where

| Question | Source of truth |
|---|---|
| Is the zone in direct distribution? | `dns_panel.zone_direct_axfr` |
| Is the zone in a catalog? | `pdns.domains.catalog` |
| Who do we give zones to? | `secondary_groups.zone_axfr` + `secondary_nodes.axfr_policy` |
| Who is subscribed to the catalog? | `catalog_groups` + `catalog_nodes` |
| Has the catalog reached the server? | `catalog_subscriptions` (observed via DNS; the panel does not configure BIND) |

## Two NOTIFY channels

The catalog goes to **all** subscribers that support RFC 9432: from it a server learns what to create, even if it
takes the data from someone else. The zones themselves go only to those we give them to. `notify_policy=off` on a server turns off
NOTIFY for zones, but not for the catalog.

`send-signed-notify=no` on this installation is intentional: PowerDNS signs NOTIFY with one key per zone, and
the other subscribers would get BADKEY.

## Verification

There are no automated tests ([04-panel-code.md](04-panel-code.md#how-to-verify)): distribution is verified on a live pair — `dig` to a secondary,
`pdns_control`, the panel log.
