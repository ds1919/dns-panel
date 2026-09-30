# 02 — Architecture

## Part A. DNS cluster

```
                       ┌──────────────────────────┐
                       │ DNS Panel (Perl FastCGI) │
                       └────────────┬─────────────┘
                                    │ SQL (records, bump SOA serial), HTTP API (metadata, catalogs)
                                    ▼
                       ┌──────────────────────────┐
                       │  Shadow-master PowerDNS  │  ← hidden, NOT in NS records
                       │  backend: gmysql         │
                       └────────────┬─────────────┘
                                    │ NOTIFY  ─────────────►
                                    │ AXFR    ◄─────────────
              ┌─────────────────────┼─────────────────────┐
              ▼                     ▼                     ▼
       ┌────────────┐        ┌────────────┐        ┌────────────┐
       │ BIND slave │        │ BIND slave │        │ BIND slave │  ← public NS
       └────────────┘        └────────────┘        └────────────┘
```

- **Shadow master (PowerDNS 5.1).** The authoritative source of zones; its address is not published in NS records. In production it is
  an HA pair with a shared service address ([13-ha-topology.md](13-ha-topology.md), [22-ha-contract.md](22-ha-contract.md)).
- **Secondary (BIND).** Public name servers, listed in NS records. The panel does not configure them; it only
  observes them over DNS. Who receives the zones and how (direct distribution, RFC 9432 catalogs, two NOTIFY channels) —
  [16-delivery.md](16-delivery.md).

### Zone edit flow

1. An SQL transaction in the PowerDNS database: SOA `FOR UPDATE`, writing the changes, bumping the serial.
2. For a signed zone — rectify (the NSEC/NSEC3 chain).
3. Via `dns-agent`: purging the zone cache in PowerDNS, checking that PowerDNS serves the new serial, NOTIFY.
4. The outcome goes to `zone_sync_state` and the audit log. A failure is retried by `dns-sync-worker`.

Secondary zones (`domains.type = SLAVE`) are pulled by PowerDNS itself from an external master (`domains.master`) and served
further. Details — [05-dns-model.md](05-dns-model.md); why direct SQL — [24-dns-engine.md](24-dns-engine.md).

## Part B. Panel

```
Apache (mod_fcgid + mod_rewrite, www/.htaccess)
   │
   └── panel.fcgi      persistent process; per request runs (do) index.pl or api.pl
         ├── index.pl        pages: session check, frame (header.pl) + pages/*.pl
         ├── api.pl          JSON API /dns-api/… and /health/{live,ready} → API::Router
         └── include/functions.pm   all logic: DB, permissions, DNS rules, HA write gate
   login.pl, logout.pl, 404.pl — separate CGI scripts
```

Code — [04-panel-code.md](04-panel-code.md), database — [03-database.md](03-database.md).

### First frame and page updates

- `index.pl` prints the whole page in one response: the frame + the page itself in `#main-content`. The data
  needed for the first frame arrives within the page (a JSON bootstrap block). **The first frame must be
  true**: no dashes, fallback ordering or empty tables that get rebuilt a moment later.
  Permitted asynchronous loading is marked in the code with an `async-ok:` line and an explanation.
- `js/navigation.js` works only on menu navigation: it fetches `/ajax/<page>` and inserts the fragment
  into `#main-content` without touching the frame.
- After an action the page is not reloaded. Server-rendered pages are updated via
  `DNSPanel.patchPage` (fresh HTML, only what differs is replaced); JS-rendered pages take
  the changes from the API response. Polling updates data in place; the DOM is not recreated.

### Components on the node

| | runs as | what |
|---|---|---|
| panel (`panel.fcgi`) | `www-data` | UI and API; all DNS rules |
| `dns-agent` (Go) | `pdns` | intermediary to PowerDNS: `pdns_control` and `dig` with validated arguments; socket `/run/dns-panel/pdns` |
| `dns-sync-worker` (Go) + `libexec/sync-task.pl` | `www-data` | decides WHEN: zone retries, Probe, catalog monitoring, safety-net reconciliation; the passes and the HA gate are in Perl |
| `dns-ha-manager` (Go) | `dns-ha` | pair logic ([23-ha-manager.md](23-ha-manager.md)); wakes the sync worker when the write gate changes |
| `dns-ha-agent` (Go) | `root` | HA actions: MariaDB read_only, PowerDNS role, address on `lo`, readiness probe (17900) |
| `pulse-server` (Go) | `dns-pulse` | optional: NS Pulse, runs `pulse-apply.pl`, maintains the Pinger target list |
| `pulse-agent`, `dns-watcher` (Go) | — | installed outside the panel node: NS Pulse tester; external executor of the anycast probe |

### Configuration

- **`etc/panel.toml`** — only what is needed before connecting to the database, plus node properties: `panel_db`, `pdns_db`,
  `pdns_api`, `auth`, `agent`, `pulse`, `ha` (template — `etc/panel.example.toml`). Environment variables
  are not used.
- **`etc/secrets/`** — passwords and keys as separate files; `panel.toml` contains only the paths to them.
- **The `settings` table** — what the administrator manages from the panel (Settings); replicated within the pair.

Service directories (`include`, `API`, `pages`, `mcp`) and `*.json|sql|pm|md` files are closed to the web in `www/.htaccess`.
