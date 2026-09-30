# 11 — HTTP API

The panel's JSON API. The frontend uses it, and scripts can call it too. It uses the same `functions.pm` layer
as the pages and MCP ([10-mcp.md](10-mcp.md)). Implementation: [api.pl](../www/api.pl) +
[API/Router.pm](../www/API/Router.pm) (the `@ROUTES` table is the source of truth for the route list) +
[API/Response.pm](../www/API/Response.pm). Requests are served by the persistent `panel.fcgi` process.

## Where to send requests

The prefix is **`/dns-api/v1/`** (`.htaccess`: `^dns-api/(.*)$ → panel.fcgi`); `/dns-api/` without a version is
the same API, and the UI uses it:

```
https://<service-address>/dns-api/v1/<endpoint>
```

The external contract (routes for scripts and integrations) is described in OpenAPI:
`GET /dns-api/v1/openapi.json` (no authentication; [API/OpenAPI.pm](../www/API/OpenAPI.pm)). All other
routes are internal UI routes.

Load balancer probes are also available from the root: `/health/live`, `/health/ready`.

## Authentication and order of checks

1. **Health** (`/health`, `/health/live`, `/health/ready`) and `openapi.json` — no session and no CSRF; `/health/live`
   does not touch the database.
2. **Who is calling** — the first one present:
   - the `session_token` cookie of a full session ([08-auth.md](08-auth.md)) — a browser;
   - `Authorization: Bearer <token>` (or `X-API-Key: <token>`): a `dnsp_…` API token acts as its
     owner; a JWT acts as the user from the token of the configured OIDC provider ([10-mcp.md](10-mcp.md#who-is-calling)).
     An invalid token → `401`;
   - nothing at all, with "Anonymous read" enabled — `anonymous`, only `GET /zones`, `/zones/:id`,
     `/zones/:id/rrsets`, `/subdomains`, `/stats`, read access to all zones.
   Otherwise → `401` `Authentication required`. Tokens and settings: Settings → External access (`users.manage`).
3. **CSRF** for POST/PUT/PATCH/DELETE with a browser session — the `X-CSRF-Token` header, equal to the `csrf_token` cookie.
   Missing → `403`. CSRF does not apply to tokens (there is no cookie).
4. **HA write gate** for modifying methods: in a pair they pass only on an ACTIVE, writable, non-frozen
   node, otherwise `409`/`503` with a `code`. Exceptions are the HA control commands (`POST /ha/switchover`, `/ha/emergency`,
   `/ha/reseed`, `/ha/pair/*`, `/ha/operations/:id/resume`): the manager has its own gate.
5. **Permissions** in the handler — zone access or capability ([20-permissions.md](20-permissions.md)).

```bash
curl -H 'Authorization: Bearer dnsp_…' https://<service-address>/dns-api/v1/zones
curl -X PATCH -H 'Authorization: Bearer dnsp_…' -H 'Content-Type: application/json' \
  --data '{"rrsets":[{"name":"www","type":"A","ttl":300,"changetype":"REPLACE","records":[{"content":"192.0.2.10"}]}]}' \
  https://<service-address>/dns-api/v1/zones/12/rrsets
```

In the audit log such changes have `source=api` and `via` set to `token <name>`, `oidc <provider>` or `anonymous`.

## Permissions (summary)

- Zone routes: `No access` → **404** (existence is not disclosed), `read` — GET only, changing
  content (`rrsets`, `records`, `soa`, `name-servers`, `labels`, `retry-sync`, `refresh-axfr`) — `write`.
  Zone responses include an `access` field.
- The zone itself (create, delete, profile, promote/demote, secondary-source, DNSSEC, dynamic, reverse, import,
  zone-profiles) — `zones.manage`.
- `secondary/*` — `secondary.manage` / `distribution.manage` (TSIG, IP groups, bindings);
  `catalogs/*` — `catalog.manage`; `zones/:id/distribution`, `direct-axfr`, `zones/:id/catalog` —
  `distribution.manage`; `pulse/*` — `pulse.manage`; `users/*`, `permission-groups/*`, `identities`,
  `zone-access` — `users.manage`; `audit` — `audit.read`; `labels/*` (changes) — `labels.manage`;
  `ha/*` — `ha.manage` / `ha.emergency`; `account/*` — only the user themselves.

## Format

Request: filter parameters in the query string; the body of modifying requests is JSON (`Content-Type: application/json`).

Response ([API/Response.pm](../www/API/Response.pm)):

```jsonc
{ "success": true,  "data": { /* ... */ } }
{ "success": false, "error": "message" }
```

Statuses: `200`, `201`, `400`, `401`, `403`, `404`, `409`, `500`, `503`. `/health/live`, `/health/ready` and the HA routes
return their own JSON without the envelope (`/health/ready`: `200` or `503` with the structure of checks; HA — the manager's response, `503` if it
is unavailable). No route → `404` `No route for METHOD /path`.

## Routes

Paths are relative to `/dns-api`; `:id` is numeric.

**Health**
```
GET  /health  /health/live  /health/ready
```

**Zones**
```
GET    /zones                          POST   /zones
GET    /zones/defaults                 GET    /zones/upstream-keys
GET    /zones/:id                      PATCH  /zones/:id        DELETE /zones/:id
GET    /zones/:id/stats                GET    /zones/:id/subdomains?type=
GET    /zones/:id/propagation          GET    /zones/:id/ptr-status
GET    /zones/:id/audit
POST   /zones/:id/retry-sync           POST   /zones/:id/refresh-axfr
POST   /zones/:id/promote              POST   /zones/:id/demote
PUT    /zones/:id/secondary-source
GET|PUT /zones/:id/dynamic
PUT    /zones/:id/labels
GET    /sync/problems
GET    /reverse/preview?cidr=          POST   /reverse
```

**DNSSEC**
```
GET|PUT /zones/:id/dnssec
POST    /zones/:id/dnssec/keys
PUT|DELETE /zones/:id/dnssec/keys/:kid
```

**Records**
```
GET    /zones/:id/rrsets               PATCH  /zones/:id/rrsets     # RRset contract: name+type, REPLACE/DELETE
PATCH  /zones/:id/soa
POST   /zones/:id/name-servers         PATCH|DELETE /zones/:id/name-servers/:nid
POST   /zones/:id/records              PATCH|DELETE /zones/:id/records/:rid
POST   /zones/:id/records/batch        POST   /zones/:id/records/delete
POST   /zones/:id/records/with-ptr     POST   /zones/:id/records/:rid/ptr
GET    /records/search?q=&field=name|content|any&type=&limit=
GET    /dns/query?name=&type=&server=&port=
```

**Zone profiles and Dynamic DHCP**
```
GET|POST /zone-profiles                GET|PUT|DELETE /zone-profiles/:id
GET|POST /dynamic/profiles             PUT|DELETE /dynamic/profiles/:id
```

**Import from the old master** ([26-zone-import.md](26-zone-import.md))
```
GET|POST /import/sources               GET  /import/sources/:id
POST   /import/sources/:id/probe
GET    /import/zones/:id/diff?tsig=
POST   /import/zones/:id/take          POST /import/zones/:id/copy     POST /import/zones/:id/mark
GET|PUT /import/zones/:id/dnssec       POST /import/zones/:id/dnssec/keys
POST   /zones/import/sources           POST /zones/import
```

**Labels**
```
GET    /labels
POST   /labels/categories              DELETE /labels/categories/:id
POST   /labels/values                  DELETE /labels/values/:id
```

**Distribution: servers, TSIG, IP groups**
```
GET    /secondary/tsig-keys/:id/secret
GET|POST /secondary/ip-groups          GET|PATCH|DELETE /secondary/ip-groups/:id
POST   /secondary/ip-groups/:id/members          DELETE /secondary/ip-groups/:id/members/:mid
GET|POST /secondary/groups             GET|PATCH|DELETE /secondary/groups/:id
POST   /secondary/groups/:id/members             DELETE /secondary/groups/:id/members/:nid
POST   /secondary/groups/:id/ip-groups           DELETE /secondary/groups/:id/ip-groups/:gid
POST   /secondary/groups/:id/tsig-keys           DELETE /secondary/groups/:id/tsig-keys/:kid
POST   /secondary/groups/:id/tsig-keys/:kid/primary
GET|POST /secondary/servers            GET|PUT|DELETE /secondary/servers/:id
GET    /secondary/servers/:id/audit
PUT    /secondary/servers/:id/catalogs           PUT /secondary/servers/:id/default-group
POST   /secondary/servers/:id/tsig-keys          DELETE /secondary/servers/:id/tsig-keys/:kid
POST   /secondary/servers/:id/tsig-keys/:kid/primary
GET|POST /secondary/nodes              GET|PATCH|DELETE /secondary/nodes/:id
POST   /secondary/nodes/:id/endpoints            PATCH|DELETE /secondary/nodes/:id/endpoints/:eid
```

**Catalogs and zone distribution**
```
GET|POST /catalogs                     GET|PATCH|DELETE /catalogs/:id
PUT    /catalogs/:id/groups            POST   /catalogs/:id/provision
DELETE /catalogs/:id/nodes/:nid
GET    /catalogs/:id/subscriptions/:sid/config   POST /catalogs/:id/subscriptions/:sid/recheck
GET    /zones/:id/distribution
PUT    /zones/:id/direct-axfr          PUT    /zones/direct-axfr    # bulk, one request
PUT    /zones/:id/catalog              # {catalog_id} or null to remove from the catalog
```

**NS Pulse** ([25-ns-pulse.md](25-ns-pulse.md))
```
GET    /pulse                          PUT    /pulse/settings
POST   /pulse/enrollment/key           PUT    /pulse/server/address
POST   /pulse/testers/:id/approve      PUT|DELETE /pulse/testers/:id
POST   /pulse/groups                   PUT|DELETE /pulse/groups/:id     PUT /pulse/groups/:id/members
POST   /pulse/checks                   PUT|DELETE /pulse/checks/:id     PUT /pulse/checks/:id/groups
POST   /pulse/rules                    GET|PUT|DELETE /pulse/rules/:id
PUT    /pulse/rules/:id/branches       POST   /pulse/rules/:id/clone
GET    /pulse/history
GET    /pulse/zones/:id/records        GET    /pulse/zones/:id/rrset
GET    /pulse/zones/:id/rrset/history  GET    /pulse/zones/:id/rrset/sweep
```

**HA** ([23-ha-manager.md](23-ha-manager.md))
```
GET    /ha/status                      GET|PUT /ha/config
PUT    /ha/publication                 PUT    /ha/pair-address
GET    /ha/operations                  GET    /ha/operations/:op
POST   /ha/switchover   /ha/emergency   /ha/reseed   /ha/dismantle
POST   /ha/operations/:op/resume
GET    /ha/pair   /ha/pair/inventory   /ha/pair/devices
POST   /ha/pair/create   /ha/pair/join   /ha/pair/approve   /ha/pair/reject   /ha/pair/reset   /ha/pair/build
```

**Audit**
```
GET    /audit
```

**Account** (own user only)
```
GET    /account                        PUT    /account/preferences
POST   /account/password               POST   /account/recovery-codes
POST   /account/totp/begin             POST   /account/totp/confirm
DELETE /account/totp/pending           DELETE /account/totp
DELETE /account/sessions/:sid          DELETE /account/sessions      # all except the current one
```

**Users and permissions**
```
GET|POST /users                        GET|PUT|DELETE /users/:id
POST   /users/:id/password
POST   /users/:id/totp/reset           PUT    /users/:id/totp/required    DELETE /users/:id/totp
GET    /users/:id/sessions             DELETE /users/:id/sessions/:sid    DELETE /users/:id/sessions
PUT    /users/:id/session-policy
GET    /users/:id/effective-access     POST   /users/:id/access/preview   PUT /users/:id/access
POST   /users/:id/groups               DELETE /users/:id/groups/:gid
POST   /users/:id/capabilities         DELETE /users/:id/capabilities/:cap
POST   /users/:id/zone-access          DELETE /zone-access/:id
POST   /users/:id/identities           DELETE /identities/:id
GET|POST /permission-groups            GET|PUT|DELETE /permission-groups/:id
POST   /permission-groups/:id/members  DELETE /permission-groups/:id/members/:uid
POST   /permission-groups/:id/capabilities   DELETE /permission-groups/:id/capabilities/:cap
POST   /permission-groups/:id/zone-access    PUT /permission-groups/:id/access
```

## Examples

```bash
curl https://<panel>/dns-api/health
# { "success": true, "data": { "status": "ok", "service": "dns-panel" } }

curl -b cookies.txt https://<panel>/dns-api/zones/1/rrsets
# { "success": true, "data": { "zone": "example.net", "access": "write", "rrsets": [ ... ] } }

curl -b cookies.txt -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' -X PATCH \
     -d '{"rrsets":[{"name":"www","type":"A","changetype":"REPLACE","records":[{"content":"10.0.0.5"}]}]}' \
     https://<panel>/dns-api/zones/1/rrsets
```

`$CSRF` is the value of the `csrf_token` cookie set by the panel page.

## How to add an endpoint

1. Logic goes into `include/functions.pm` (pages and MCP reuse it).
2. The route goes into `@ROUTES` (`API/Router.pm`): `[ 'GET', qr{^/path$}, \&_handler ]`. Narrow paths before broad ones.
3. The handler checks permissions and returns `API::Response->ok({...})` / `->not_found(...)` and so on.
4. Zone content changes go through the `functions.pm` write functions (they bump the SOA and send NOTIFY), with an
   audit log entry.
