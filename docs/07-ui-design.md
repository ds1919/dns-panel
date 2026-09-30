# 07 — UI / design

The UI is in English. The interface is built around operator tasks, not around database tables.

## Layout

- **Left — sidebar** (`header.pl`): `Dashboard · Zones · Labels · Propagation · NS Pulse · High availability ·
  Audit log · Settings`; at the bottom — the user (a link to Account). Records is not a menu item: records
  open on the zone page.
- **Top bar** — only the global search by name or IP (`js/search.js`, `GET /dns-api/records/search`).
- **STANDBY banner** under the top bar — on a pair node that does not hold the service address: edits here are
  rejected, work has to be done on the service address.
- The main content is a single `<main id="main-content">`.

## Pages

- **Zones** — the zone table with the shared filter component; Add zone — in a modal.
- **Zone page** (`/records?zone=<id>`) — SOA and apex NS in an accordion, the RRset table below; Zone settings
  (role, Dynamic updates, distribution) and DNSSEC — modals from the zone page.
- **Settings** — tabs `Zone profiles · Import · Dynamic DHCP profiles · Pinger & Pulse · Users & access`,
  visible according to permissions. A new tab is added to `availTabs()` **and** to the `initTab()` whitelist (`js/settings.js`).

## Palette and themes

The default is a neutral dark-grey theme (`:root` in `css/main.css`): greyscale background and chrome, a muted
teal accent (`--accent: #4bb3a5`) used sparingly — the active item, the primary button, status.

Themes are `css/themes/*.css`, selected in Account (`@THEMES` in `functions.pm`; empty = follow the browser,
`auto.css`). A theme overrides **only CSS variables** (colours, `--font-ui`, `--bg-pattern`), not the layout.
Components do not hardcode colours — only `var(--…)`. The server inserts the theme link, so there is no
flash of a different theme.

## Component rules

- **Controls are styled once, by tag** (`input`, `textarea`, `select`, buttons — in `main.css`).
  Classes are only for variants (size, width, behaviour). Page CSS does not recolour standard
  elements, it sets only geometry.
- Dropdowns — `DNSPanel.selectHtml` (`.ui-select`, a menu in the panel's theme, not the native popup).
- Dialogs — shared modals (`#modal-overlay`, `DNSPanel.dialog`/`confirm`): a modal keeps the page's
  context. There are no drawers.
- A control inside a table is one text line high: switching read → edit does not change the row height.
- Thin borders (1px), 8–10px radii, dense tables, hover without bright highlights.
- System font (`system-ui` and on down the stack); `www/` has no external dependencies (fonts, CDN).

Page behaviour (first frame, updates without reload, polling without recreating the DOM) —
[02-architecture.md](02-architecture.md#first-frame-and-page-updates).
