# 20 — Permissions (model)

Permissions **inside the DNS panel** (not a separate IAM system). Two kinds:

- **zone access** — `No access · Read only · Write` (`none|read|write`);
- **panel permissions (capabilities)** — actions on the zones themselves and on the infrastructure.

Permissions = group membership + personal rules. There are no roles.

## Zone access

**`Write` on a zone = full ownership of its content:**
- any RRsets (A/AAAA/CNAME/MX/TXT/SRV/PTR/…), creating and deleting names inside the zone;
- apex `SOA` and `NS`, child delegations (`NS`, `DS`);
- zone labels, Retry sync, re-running AXFR of a secondary zone;
- the zone's history (audit).

`Read only` — viewing. `No access` — the zone is not visible: it is absent from lists and search, direct access → 404
(its existence is not disclosed).

**Not part of zone Write** — these are panel permissions: creating/deleting a zone, changing its role (promote/demote),
profile, DNSSEC, dynamic updates, distribution (Direct AXFR, catalog), permissions, HA.

### Rule scope

```
all   — all zones (the subject's default)
zone  — a specific zone
```

### How rules combine

For (user, zone):
1. **Each group** computes its own access: within a group, `zone` beats `all`.
2. **Groups combine by maximum** (`none < read < write`): a group only adds; a narrow rule of one
   group does not narrow a broad rule of another.
3. **The personal rule** is compared with the group result **by specificity**: the more specific level wins;
   on a tie, the personal rule wins.

```
Group A:        all  Read only ;  itos.corp  Write
User:           all  No access ;  project.corp  Write

→ project.corp : personal zone rule — Write
→ itos.corp    : the group's zone rule is more specific than the personal all → Write
→ other zones  : group all=read and personal all=none are the same level → personal → No access
```

Catalog producer zones are always `none` (they are managed as catalogs on the Propagation page). If the rules
cannot be read in full, access is `none` to everything.

## Panel permissions (capabilities)

The list is `@functions::CAPABILITIES` (also the ENUM `capability_grants.capability`):

```
zones.manage          create/delete a zone, role, profile, DNSSEC, dynamic, reverse, zone import, zone profiles
labels.manage         label directory (categories and values)
secondary.manage      Servers: nodes, groups, addresses
distribution.manage   Direct AXFR, TSIG keys, allowed IP groups, assigning a zone to a catalog
catalog.manage        Catalog: catalogs, their subscribers and assigned servers
pulse.manage          NS Pulse: testers, checks, rules (a rule writes DNS without zone Write)
users.manage          users, groups, permissions
audit.read            audit log
ha.manage             HA: state, config, switchover, pair creation
ha.emergency          emergency promote, reseed, dismantle
```

Continuing an HA operation (`resume`) requires the same permission as starting it.

The on-screen names (Settings → Users & access) match the tabs of the Propagation page: `secondary.manage`
= Manage servers, `distribution.manage` = Manage Direct AXFR, `catalog.manage` = Manage catalogs. The
Propagation page opens with any of the three and shows only the matching tabs. Reading the server inventory is allowed
with `secondary.manage` or `distribution.manage`.

### A group grants, a personal deny takes away

A permission is held if there **is an allow** (personal or via a group) and **no personal deny**
(`capability_grants.effect = allow|deny`):

```
group "DNS Administrators" → ha.manage        ← granted to all members
user jdoe                  → ha.manage: deny  ← only this user lacks it
```

Denies are personal only: for a group, "no permission" and "deny" are the same thing. There is one row per (subject, permission) —
either allow or deny. The guard "at least one active administrator remains" (`users.manage`) applies when
a permission is revoked, denied, the user leaves a group, or the user is deactivated.

## Where it is checked

A single layer in `functions.pm`: `build_access_context`/`access_for`/`effective_zone_access` for zones,
`has_capability`/`capability_check` for panel permissions. It is called by the pages, the HTTP API
([11-api.md](11-api.md)) and MCP ([10-mcp.md](10-mcp.md), the subject is `requester`). Denials and permission changes
are written to the [audit log](15-audit-log.md).

## Interface

Settings → Users & access: a user and a group have panel permissions (grouped: Zones, Propagation,
NS Pulse, Administration) and a zone access table (default + per zone). For a user, the table shows
access from groups (with the group name), the personal rule and the effective access; a change can be previewed
(`POST /dns-api/users/:id/access/preview`).

## Data model (in `dns_panel`)

```
groups             id, name, description
user_groups        user_id, group_id                                  -- M:N
zone_access        subject_type(group|user), subject_id,
                   scope(all|zone), zone_id?, access(none|read|write)
capability_grants  subject_type(group|user), subject_id, capability, effect(allow|deny)
```

A personal rule = a row with `subject_type=user`; "inherit" = no row. The schema is
`docs/INSTALL/schema.sql`. The first administrator (`deploy/bootstrap-admin.pl`) gets the group
"DNS Administrators" with all permissions and `zone_access all=write`.
