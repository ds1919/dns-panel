# 04 — Panel code

Stack: **Perl + Apache (`mod_fcgid`, `mod_rewrite`) + a frontend without a build step.** Pages and the API are served by
one persistent process, `www/panel.fcgi`: modules are compiled once per process, not on every request.
Packages (Perl modules from apt, `libfcgi-perl`, `libapache2-mod-fcgid`) are installed by `deploy/install.sh`.

## `www/` layout

```
www/                       # DocumentRoot (/var/www/vhost/dns-panel → /opt/dns-panel/www)
├── panel.fcgi             # persistent process: runs index.pl or api.pl per request
├── index.pl               # pages: whitelist, session, shell, AJAX fragments
├── api.pl                 # JSON API /dns-api/… and /health/{live,ready}
├── login.pl logout.pl 404.pl
├── header.pl              # head()/shell_start()/shell_end(): sidebar, top bar, STANDBY banner
├── .htaccess              # rewrite to panel.fcgi, deny service directories and files
├── include/functions.pm   # all logic: DB, sessions, permissions, RRset layer, validation, distribution, DNSSEC, HA, Pulse
├── API/                   # Router.pm (routes), Response.pm (JSON responses)
├── pages/                 # fragments: dashboard zones records labels propagation pulse ha audit settings account
├── js/                    # app.js (DNSPanel.* core), navigation.js, search.js + one file per page/section
├── css/                   # main.css, dashboard.css, ha.css, themes/
└── mcp/dns-mcp.pl         # MCP server (stdio), see 10-mcp.md
```

Paths in the code go through `FindBin` (`$FindBin::RealBin/…`). The config is read from `../etc/panel.toml` relative to
`include/` ([02-architecture.md](02-architecture.md#configuration)).

## Persistent process

`panel.fcgi` runs a script via `do`, so file-scoped variables are fresh on every request. Rules:

- per-request state lives only in variables reset by `functions::request_begin()`
  (request caches, DB connections);
- pages are loaded with `do`, not `require`;
- `exit` in a script ends the request, not the process;
- every `alarm(N)` is cleared with `alarm 0` on all paths, otherwise it fires in the next request.

Scripts (`index.pl`, `api.pl`, `pages/*.pl`) are re-read on every request, while modules (`functions.pm`,
`API/*.pm`, `header.pl`) are compiled once per process: after editing them a new process is needed (`systemctl reload apache2`).
Without `mod_fcgid` the same `panel.fcgi` works as plain CGI (`www/.htaccess`).

## `index.pl` + `header.pl`

- The page comes from `?page=` or the path (`/zones` → `panel.fcgi?page=zones`); whitelist `%KNOWN_PAGES`.
  All pages require a session (`%PUBLIC_PAGES` is empty); the session is the `session_token` cookie.
- On the STANDBY node of a pair the session is dropped and the user goes to `/login`, which shows the service address.
- Two modes: full response (shell + page) and `?ajax=1` (fragment only, for `navigation.js`).
- Shell: `head()` → `shell_start()` (sidebar, top bar with global search, STANDBY banner) → a single
  `<main id="main-content">` → `shell_end()` (shared overlays `#modal-overlay`, `#pulse-overlay`).
  Pages return only the inner content.
- `index.pl` sets the `csrf_token` cookie (double-submit) and `dp_theme` (theme on the login page).
- All JS is loaded at once (`load_all_js`, `defer`) so that menu navigation does not lose page logic.
  Assets are versioned with `?v=` (mtime + file size).

## `api.pl` + `API/`

- `api.pl` strips the `/dns-api/` prefix, reads the body from STDIN, checks the session, CSRF
  (cookie `csrf_token` = header `X-CSRF-Token`) and the HA write gate (`ha_write_verdict`) for modifying
  methods, then hands the request to `API::Router`. `/health/*` — without session and CSRF.
- `API/Router.pm` — the `@ROUTES` table (regex on `METHOD + PATH`); each handler checks permissions itself.
- `API/Response.pm` — `ok`, `created`, `bad_request`, `unauthorized`, `forbidden`, `not_found`, `conflict`,
  `server_error`, `service_unavailable`. Format: `{ success: bool, data | error }`.

Endpoints — [11-api.md](11-api.md).

## Frontend

- `app.js` — the `window.DNSPanel` core: `api`, `patchPage`, `dialog`/`confirm`/`prompt`/`alert`, `selectHtml`,
  the shared filter component (`filterInit`, `filtersGet`, …), a busy cursor while changes are in progress.
- `navigation.js` — menu navigation and highlighting of the active item; it takes no part in the first render.
- The other files are per page or section (`zones.js`, `records.js`, `dnssec.js`, `import.js`,
  `dynamic.js`, `users_access.js`, …).

Rules for the first frame and updating without reload — [02-architecture.md](02-architecture.md#first-frame-and-page-updates),
design system — [07-ui-design.md](07-ui-design.md).

## Development rules

### Invariants

- **HA does no automatic failover.** Switchover and emergency are started by a human.
- **Event-driven, no timers.** No `sleep`, no "wait up to N seconds", no timer-driven sweeps. Readiness is
  sd_notify; retries follow a due time from the DB; only what observes the outside world (BIND's subscription to a
  catalog) or guards against drift is periodic.
- **The panel manages only its own PowerDNS.** It does not configure BIND on the secondaries, it only observes them over DNS.
  "Who we serve zones to" is the group flag `zone_axfr`; the panel stores no foreign upstream.
- **The HA write gate is fail-closed.** On STANDBY, during an HA operation and when the state is unknown, the panel and background
  passes write nothing. There is one gate — `ha_write_verdict` in Perl.
- **Rules only in `functions.pm`.** Go daemons decide "when" and "how many at once", but do not duplicate DNS rules
  (components — [02-architecture.md](02-architecture.md#components-on-the-node)).
- **One path for applying distribution** — `apply_zones` (one zone, a list or all).
- **Everything in English** in code, comments, logs and UI.
- **No automated tests** (neither Perl nor Go). Verification is reading the code + the live panel; `make check` = gofmt + go vet.

### Facts that make it easy to break things if you miss them

- **The panel is a persistent FastCGI process**: see [Persistent process](#persistent-process).
- **After an action the page is not fully reloaded** (`DNSPanel.patchPage` or the API response) — a full
  reload only when the whole screen changes (zone role change, HA). See
  [02-architecture.md](02-architecture.md#first-frame-and-page-updates).
- **PowerDNS is 5.1.x only** from `repo.powerdns.com` (branch `auth-51`); the installer checks this. 4.8 from
  Ubuntu 24.04 does not allow changing `TSIG-ALLOW-AXFR` via the API.
- **The API is `/dns-api/`, not `/api/`**: `/api` on the dev host is taken by another service.
- **`capability_grants.capability` is an ENUM.** A nonexistent capability is silently not inserted → always 403.
- **Two PowerDNS intervals:** `zone-cache-refresh-interval` — the zone list cache (the panel announces a new zone with
  `rediscover`); `xfr-cycle-interval` — recomputing the catalog zone's content and its NOTIFY. A manual catalog NOTIFY
  is useless: it carries the old serial.
- **SLAVE does not go into a catalog** (a PowerDNS limitation) → Direct AXFR only. NATIVE is not distributed.
- **Catalog records go through the PowerDNS HTTP API.** The API does not handle `AXFR-MASTER-TSIG` (422) — SQL only.
- **Records of a signed zone are written with SQL** → a rectify is mandatory after every write (`zone_sync_verify` does it itself).
- **The panel's own policy on a zone is marked with `X-DNSPANEL-POLICY`**; orphan cleanup goes only by this marker.
- **A TSIG key goes away by itself** when the last reference is removed; keys created on the server by hand are not touched.
- **Perl + UTF-8:** `functions.pm` sets `:utf8` on STDOUT; a script with non-ASCII text needs `use utf8`.
- **Profile, labels and groups are different entities:** a profile is an SOA/NS preset (optional when creating a zone),
  labels are tags with no effect on DNS, permission groups ≠ server groups.
- **`dig -k` cannot read from `/tmp`** (AppArmor) and silently goes without a signature → `dns-agent` passes the key via stdin.
- **The installer writes to MariaDB only with `sql_log_bin=0`**: otherwise errant GTIDs appear in the pair.

### How to verify

1. Read the actual contract (`www/API/Router.pm`) and the code.
2. `perl -c` / `node --check` / `make check` on the touched files.
3. See the result in the live panel (after editing modules — a new process, see [Persistent process](#persistent-process)).
4. Geometry — with a one-off page in the scratchpad with real data + a headless screenshot; such stands are not
   committed to the repository.
5. Everything created for a trial is removed with core functions (`zone_delete_everywhere`, `tsig_keys_forget_unused`)
   on both sides — the panel row and the copy in PowerDNS.

DB schema: `docs/INSTALL/schema.sql` is the full schema for a clean install; any change also needs a file in
`deploy/migrations/` (rules — [there](../deploy/migrations/README.md)), in the same commit.

### Deliberately deferred

- `emergency.go`/`reseed.go` go to `StateFailed` after the point of no return — each point needs to be worked through.
- Configure HA is synchronous HTTP without a logged operation.
- The `DNSPanel.selectHtml` menu is `position:absolute` and will be clipped inside a table; when such a
  select first appears, move it to a fixed layer, like `.grp-ms-pop`.
- The API field `renotify` in `POST /zones` is accepted for compatibility, but for a zone in distribution the value is derived.
