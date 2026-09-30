# DNS Panel — MCP server

MCP server for managing PowerDNS through an AI agent. It reuses the panel's access layer
(`../include/functions.pm`).

- **Run:** `perl mcp/dns-mcp.pl` (stdio, JSON-RPC 2.0)
- **Config:** databases from `etc/panel.toml`, same as the panel; in the settings (`settings`), `mcp.readonly` means read-only,
  `mcp.default_user` is an optional default requester.
- **Tools:** whoami, list_zones, get_zone, list_rrsets, count_records, list_subdomains,
  search_records, dns_query, check_propagation, apply_rrsets, create_zone, delete_zone.
- **Permissions:** the requester's identity comes in the `requester` argument (= name in Teams = CN)
  and is checked on the server against capability_grants + zone_access (see docs/10-mcp.md, 20-permissions.md).

Full description, client registration and examples: **[../docs/10-mcp.md](../../docs/10-mcp.md)**.

Quick check:

```bash
printf '%s\n' \
 '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}' \
 '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
 | perl dns-mcp.pl
```
