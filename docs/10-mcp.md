# 10 — MCP server (managing DNS through AI)

The MCP server lets an AI agent view zones and records, edit records, and create and delete zones. It uses
the same `include/functions.pm` layer as the panel: the same permissions, the same write path (transaction, SOA bump,
NOTIFY), the same HA gate and audit.

- **Tools and dispatcher:** `www/include/MCPServer.pm`.
- **Remote (main):** `https://<service-address>/mcp`, Streamable HTTP — `www/mcp/http.pl` inside `panel.fcgi`.
  Enabled in Settings → External access.
- **Local stdio:** `www/mcp/dns-mcp.pl` — for an agent on the node itself.

## Tools

| Tool | Purpose | Writes? |
|-----------|-----------|:---:|
| `whoami` | capabilities and the list of zones with `write` | — |
| `list_zones` | accessible zones (with `access`); `No access` is not shown | — |
| `get_zone` | zone by name/id + SOA + metadata; `No access` → "Zone not found" | — |
| `list_rrsets` | the zone's RRsets (`name+type`), filters `type`/`name` | — |
| `count_records` | total + breakdown by type + number of hosts (opt. `type`) | — |
| `list_subdomains` | the zone's hosts + delegated zones (respecting access) | — |
| `search_records` | search across accessible zones (`field`: name/content/any, `type`, `limit`) | — |
| `dns_query` | live DNS query (`dig TYPE NAME @server`) | — |
| `check_propagation` | SOA serial/record on the master and secondaries — arrived/lagging | — |
| `apply_rrsets` | a batch of RRset changes (contract as `PATCH /dns-api/v1/zones/:id/rrsets`): REPLACE/DELETE, atomic, one SOA bump; `write` on the zone | ✎ |
| `create_zone` | create a primary zone (SOA+NS from `profile`); `zones.manage` | ✎ |
| `delete_zone` | delete a whole zone; `confirm=true` + `zones.manage` | ✎ |

A zone is given by `zone` (name) or `zone_id`. A record name is `@`, relative (`www`) or an FQDN. Modifying
tools work only on the ACTIVE node of a pair; on STANDBY — error `standby_read_only`.

## Who is calling

Permissions are always those of a specific panel user ([20-permissions.md](20-permissions.md)). How that user
is determined depends on the transport.

**Remote `/mcp`** — the request proves the user; the client does not name them (there is no `requester` in the schemas, and it is
ignored):

| Header | Who |
|-----------|-----|
| `Authorization: Bearer dnsp_…` or `X-API-Key: dnsp_…` | the owner of the API token (Settings → External access → API tokens) |
| `Authorization: Bearer <JWT>` | the user from a token of one of the OIDC providers (below) |
| none, "Anonymous read" enabled | `anonymous`: read-only tools only, reading all zones |
| none | `401` + `WWW-Authenticate: Bearer` |

**OIDC.** There can be any number of providers (Settings → External access → OIDC providers: name, Issuer,
Audience, Username claim, on/off). The provider is chosen by the token's `iss` — the Issuer of an enabled provider must match it
exactly; different providers lead to the same panel users.
The panel verifies the token signature with a key from the provider's JWKS (`<issuer>/.well-known/openid-configuration`
→ `jwks_uri`; keys are kept in the process and re-read on an unknown `kid`), `iss`, `aud`, `exp`/`nbf`.
Algorithms RS256/384/512, ES256/384. The user is looked up by the claim value (default
`preferred_username`) — an exact match (case-insensitive) with `username`, e-mail or any certificate CN
of the user. All matches are collected: they must point to one user, otherwise it is
refused — neither the first match nor "the one with more rights" is chosen. Not found or ambiguous — `401`.
No manual mappings are kept. To keep ambiguity from arising, the panel does not allow saving a CN, e-mail or
username that already names another user (one user can have several CNs).

Audience is comma-separated if several values are accepted. For Microsoft Entra: issuer
`https://login.microsoftonline.com/<tenant>/v2.0`, audience — the Application ID URI or client id of the application
registration; the token must be issued **for this application** (tokens for Microsoft Graph cannot be verified).

**Local stdio** — the agent on the node is trusted and names the person itself in the `requester` of every call. The server
looks them up as a certificate CN, then as `username`; not passed — `mcp.default_user`; not found —
"Permission denied: unknown requester".

All changes and refusals (`result=denied`) go to the [audit log](15-audit-log.md) with `source=mcp`; for remote also
`via` (`token <name>`, `oidc <provider>`, `anonymous`).

## Remote protocol

- `POST /mcp` — one JSON-RPC message (or an array); response `application/json`. Notifications only → `202`.
- `GET /mcp` → `405`: the server-to-client stream is not used, there are no sessions (`Mcp-Session-Id`).
- `Origin`, if sent, must match `Host` (protection against DNS rebinding) — otherwise `403`.
- `protocolVersion`: 2024-11-05, 2025-03-26, 2025-06-18.
- If there are enabled OIDC providers — `/.well-known/oauth-protected-resource` (RFC 9728): `resource` and
  `authorization_servers` = their issuers; `WWW-Authenticate` in a `401` refers to it.
- The panel listens on HTTP; for clients from the internet (Copilot, etc.) it is published over HTTPS externally
  (a reverse proxy to the service address).

## Settings

Settings → External access (permission `users.manage`), in the `settings` table, shared by the pair:

| Key | Default | Purpose |
|------|--------------|-----------|
| `external.mcp_http` | `0` | remote MCP at `/mcp` |
| `external.anonymous_read` | `0` | reading zones and records without a token (API and MCP) |
| `mcp.readonly` | `0` | modifying tools are hidden and rejected (both transports) |
| `mcp.default_user` | `''` | default `requester` for stdio (no screen) |

## Connecting a client

Remote (any client with Streamable HTTP):

```json
{
  "mcpServers": {
    "dns-panel": {
      "url": "https://dns.example.com/mcp",
      "headers": { "Authorization": "Bearer dnsp_…" }
    }
  }
}
```

Microsoft Copilot Studio: an MCP server at the URL `…/mcp`; authentication — API key (header `X-API-Key`,
value `dnsp_…`; acts as one user — the token owner) or OAuth 2.0 via an application registration in
Entra (acts as whoever writes in Teams) — then an OIDC provider with the same issuer and
audience is added in the panel.

Local stdio (the process must read `etc/panel.toml` — run as the panel user):

```json
{
  "mcpServers": {
    "dns-panel": { "command": "sudo", "args": ["-u", "www-data", "perl", "/opt/dns-panel/www/mcp/dns-mcp.pl"] }
  }
}
```

## Quick check

```bash
curl -s -X POST https://dns.example.com/mcp -H 'Authorization: Bearer dnsp_…' -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"whoami","arguments":{}}}'

printf '%s\n' \
 '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}' \
 '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_zones","arguments":{"requester":"Fedya"}}}' \
 | sudo -u www-data perl /opt/dns-panel/www/mcp/dns-mcp.pl
```
