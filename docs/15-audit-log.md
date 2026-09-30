# 15 — Audit log

A log of significant operations: **who did what and when, what it was before and what it became**. It serves
incident analysis, meaningful rollback and accountability (including management through AI).

## What is logged

- **DNS changes:** records (`add_record`, `replace_rrset`, `delete_record`, `update_soa`), zones (`create_zone`,
  `delete_zone`, `create_reverse_zones`, role change, secondary source, settings, labels, DNSSEC, dynamic
  updates), migration (`import_zones` + `create_zone` for each zone) — with **before/after**.
- **Distribution and inventory:** servers, groups, catalogs, TSIG keys (the secret is never written), profiles.
- **Users and access:** users, groups, permissions, certificates, second factor, session revocation.
- **Human HA decisions** (`ha_switchover_create`, `ha_emergency_promote`, pairing, configuration) with
  `operation_id`/`request_id`; the mechanics of operations live in the HA manager's history ([23-ha-manager.md](23-ha-manager.md)).
- **System:** sync retries by the worker (`retry_sync`), NS Pulse switches (`pulse_switch`, `pulse_held`).
- **Permission denials** — `result=denied` (API: `inventory_access_denied` with the required capability; MCP — denial by zone
  or capability).

Login (full only: after the password and second factor, or by certificate) and logout are written as `login`/`logout`
with the login method and IP; the rest of the session context lives in `sessions`.

## Where it is written

At the **caller** level (API `API/Router.pm`, MCP `mcp/dns-mcp.pl`, worker), where the actor is known — **not**
inside `pdns_*` (those are pure data operations). The single entry point is `audit_log({...})` in `functions.pm`; the API
writes through `_inv_audit`, which adds a snapshot of the object's name.

## Schema (`docs/INSTALL/schema.sql` → `audit_log`)

In the panel database `dns_panel` (replicated along with it). Panel code only appends rows to the table.

| Field | Purpose |
|------|-----------|
| `id`, `ts` | auto-increment, time |
| `actor`, `actor_role` | who (username/CN; `system`, `pulse` for background jobs) |
| `source` | `api` / `mcp` / `system` / `panel` (the ENUM also allows `ha-agent`, `cli`, `emergency-cli`) |
| `via` | how an external request came in: `token <name>` / `oidc <provider>` / `anonymous`; empty for a panel session and stdio MCP |
| `action` | technical action code |
| `target_type`, `target` | object type + identifier (id, zone name, `name TYPE` for an RRset, operation_id) |
| `target_label` | **snapshot** of the object's readable name at the time of the event — survives deletion of the object |
| `before_val`, `after_val` | JSON of the state before/after |
| `result` | `ok` / `denied` / `error` / `partial` |
| `detail` | reason for the denial/error |
| `ip`, `request_id` | context, correlation |

## Viewing

- **Audit log page** (capability `audit.read`): filters actor / action / result / type / source and search by
  target (including `target_label`), paginated; a row expands into before/after. Action and
  type codes are shown as words from a single dictionary (`%AUDIT_ACTION_LABELS`, `%AUDIT_TYPE_LABELS`); an unknown code
  is humanized.
- **API:** `GET /dns-api/audit?actor=&action=&result=&target_type=&source=&target=&limit=&offset=` (limit ≤ 500).
- **History on the object:** RRset entries (`GET /zones/:id/audit?name=&type=`), server
  (`GET /secondary/servers/:id/audit`), user (a link to the Audit log filtered by actor).
- **Dashboard** — recent events, excluding the worker's automatic `retry_sync`.

## Retention

Currently unlimited: the panel does not delete rows and does not export them to external storage.
