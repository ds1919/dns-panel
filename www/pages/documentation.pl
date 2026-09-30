#!/usr/bin/perl

use strict;
use warnings;
use utf8;
use open ':std', ':encoding(UTF-8)';

# Documentation: a short admin guide, static HTML. Full references live in docs/ in the repository.

print <<'HTML';
<div class="page-head"><div><h1>Documentation</h1><div class="sub">How the panel works, in short. Full reference: <code>docs/</code> in the repository.</div></div></div>
<div class="docs">
<nav class="docs-toc">
  <a href="#doc-start">Getting started</a>
  <a href="#doc-zones">Zones &amp; records</a>
  <a href="#doc-roles">Primary / Secondary</a>
  <a href="#doc-dist">Distribution &amp; catalogs</a>
  <a href="#doc-dyn">Dynamic DNS</a>
  <a href="#doc-dnssec">DNSSEC</a>
  <a href="#doc-import">Import</a>
  <a href="#doc-pulse">NS Pulse</a>
  <a href="#doc-ha">High availability</a>
  <a href="#doc-users">Users &amp; permissions</a>
  <a href="#doc-api">HTTP API</a>
  <a href="#doc-mcp">MCP</a>
  <a href="#doc-roadmap">Roadmap</a>
</nav>
<div class="docs-body">

<section id="doc-start" class="card">
<h2>Getting started</h2>
<p>The panel manages its own PowerDNS server. Every change is written to the PowerDNS database, checked on the
live server and announced to the secondaries (NOTIFY).</p>
<ol>
  <li><b>Zones</b> — add a zone (<b>+ Add zone</b>) or bring existing ones in via <b>Settings → Import</b>.</li>
  <li><b>Propagation</b> — register the secondary servers that receive zones, then put zones in a catalog or give them by direct AXFR.</li>
  <li><b>High availability</b> — optionally join a second node into an ACTIVE/STANDBY pair.</li>
  <li><b>Settings → Users &amp; access</b> — create operators and give them groups.</li>
</ol>
</section>

<section id="doc-zones" class="card">
<h2>Zones &amp; records</h2>
<p>Open a zone to edit its records. Records are edited by RRset (name + type): adding, changing or deleting
records bumps the SOA serial once and sends NOTIFY.</p>
<ul>
  <li><b>Zone settings</b> (on the zone page) — role, SOA, name servers, catalog, Dynamic DNS, DNSSEC.</li>
  <li><b>Zone profiles</b> (Settings) — SOA/NS presets and the default catalog for new zones.</li>
  <li><b>Labels</b> — free tags for grouping and filtering zones.</li>
  <li>An A/AAAA record can create its PTR in the matching reverse zone.</li>
</ul>
</section>

<section id="doc-roles" class="card">
<h2>Primary / Secondary</h2>
<ul>
  <li><b>Primary</b> — the zone is edited here.</li>
  <li><b>Secondary</b> — the zone is copied (AXFR) from upstream primaries; read-only here. Optional TSIG key.</li>
  <li><b>Make primary</b> turns a secondary into a primary with its current data (used for migration). <b>Make secondary</b> does the reverse.</li>
</ul>
</section>

<section id="doc-dist" class="card">
<h2>Distribution &amp; catalogs</h2>
<p><b>Propagation</b> decides which servers get which zones.</p>
<ul>
  <li><b>Servers</b> — the secondaries (BIND and others), grouped; a group can be allowed to transfer zones.</li>
  <li><b>Catalogs</b> — RFC 9432 catalog zones: a server subscribed to a catalog picks up its member zones automatically.</li>
  <li><b>Direct AXFR</b> — zones given to servers without a catalog. Secondary zones always go this way (PowerDNS cannot put them in a catalog).</li>
</ul>
</section>

<section id="doc-dyn" class="card">
<h2>Dynamic DNS</h2>
<p>Lets a DHCP server update a primary zone (RFC 2136). Enable it in <b>Zone settings → Dynamic DHCP</b>:
either follow a <b>Dynamic DHCP profile</b> (Settings) or give the zone its own TSIG key and allowed networks.
Updates are signed with TSIG and limited to the listed networks.</p>
</section>

<section id="doc-dnssec" class="card">
<h2>DNSSEC</h2>
<p>Signing is local: PowerDNS signs the zone online. Enable it in <b>Zone settings → DNSSEC</b>; a CSK is created.
Publish the DS record at the parent. Keys can be added, deactivated or removed in the same dialog.
A signed zone imported from another server can keep its keys (see Import), so validation does not break.</p>
</section>

<section id="doc-import" class="card">
<h2>Import</h2>
<p><b>Settings → Import</b> moves zones from an old BIND master: upload its configuration
(<code>named-checkconf -p &gt; bind-export.conf</code>), pick zones, import; content arrives by AXFR. Zones arrive as secondaries of the old server, so nothing changes for clients;
switch each to primary when ready (<b>Make primary</b>). Dynamic DNS settings and DNSSEC keys found in the export are carried over.</p>
</section>

<section id="doc-pulse" class="card">
<h2>NS Pulse</h2>
<p>Testers at remote sites check specific addresses (ICMP or TCP connect). A rule on an RRset publishes another
set of records while its conditions hold (check state, schedule) and returns to the main set otherwise.
<b>Pinger</b> slowly walks all A/AAAA addresses and only shows which ones stopped answering. Testers are
enrolled in <b>Settings → Pinger &amp; Pulse</b>; rules are set on the record (Pulse badge) or on the <b>NS Pulse</b> page.</p>
</section>

<section id="doc-ha" class="card">
<h2>High availability</h2>
<p>Two nodes form a pair: the <b>ACTIVE</b> node takes changes and answers on the service address; the
<b>STANDBY</b> node replicates its database and is read-only. <b>Switchover</b> moves the role in a few seconds.
The pair is created on the <b>High availability</b> page from two standalone nodes; the donor's data is kept.
Sign in on the service address: a STANDBY sends you to the ACTIVE node.</p>
</section>

<section id="doc-users" class="card">
<h2>Users &amp; permissions</h2>
<ul>
  <li>Sign-in: password, optional two-factor (TOTP) or a registered client certificate.</li>
  <li>Permissions = the user's groups plus personal grants: capabilities (manage zones, users, HA…) and zone access (read / write / none) for all zones or per zone.</li>
  <li>A personal <b>No access</b> on a user overrides what groups give.</li>
  <li>Every change is in the <b>Audit log</b>, with who, when and from where (panel, API, MCP).</li>
</ul>
</section>

<section id="doc-api" class="card">
<h2>HTTP API</h2>
<p>Base path <code>/dns-api/v1/</code> on the service address, JSON in and out. A call acts as a panel user and has
exactly that user's permissions; changes are in the Audit log. On a STANDBY node writes return
<code>409 standby_read_only</code>. <a class="link" href="/dns-api/v1/openapi.json" download="dns-panel-openapi.json">Download OpenAPI</a></p>
<p><b>Authentication.</b> Send <code>Authorization: Bearer &lt;token&gt;</code> (or <code>X-API-Key: &lt;token&gt;</code>):</p>
<ul>
  <li><b>API token</b> — created in <b>Settings → External access</b> for a user; acts as that user.</li>
  <li><b>OIDC access token</b> — from your identity provider (Microsoft Entra, Keycloak, Okta…), when that provider is added in External access; acts as the user whose certificate CN, username or e-mail matches the token.</li>
  <li><b>No token</b> — only when <b>Anonymous read</b> is on: zones and records can be read.</li>
</ul>
<table class="docs-routes">
  <tr><td>GET</td><td>zones</td><td>zones visible to you</td></tr>
  <tr><td>POST</td><td>zones</td><td>create: <code>{"name","role":"primary"|"secondary","masters":[…]}</code></td></tr>
  <tr><td>GET · DELETE</td><td>zones/:id</td><td>details / delete with <code>{"confirm_name":"&lt;zone&gt;"}</code></td></tr>
  <tr><td>GET · PATCH</td><td>zones/:id/rrsets</td><td>list / change RRsets</td></tr>
  <tr><td>PATCH</td><td>zones/:id/soa</td><td>SOA fields</td></tr>
  <tr><td>GET · PUT</td><td>zones/:id/dnssec</td><td>state / <code>{"enabled":true}</code></td></tr>
  <tr><td>GET</td><td>audit</td><td>audit log; <code>zones/:id/audit</code> for one zone</td></tr>
  <tr><td>GET</td><td>health/ready</td><td>node readiness (no auth)</td></tr>
</table>
<div class="docs-code"><button type="button" class="btn btn-sm" data-doc-copy>Copy</button><pre>curl -X PATCH https://dns.example.com/dns-api/v1/zones/12/rrsets \
  -H 'Authorization: Bearer dnsp_…' -H 'Content-Type: application/json' \
  --data '{"rrsets":[
    {"name":"www","type":"A","ttl":300,"changetype":"REPLACE","records":[{"content":"192.0.2.10"}]},
    {"name":"old","type":"CNAME","changetype":"DELETE"}]}'</pre></div>
</section>

<section id="doc-mcp" class="card">
<h2>MCP</h2>
<p>An MCP server for AI assistants at <code>/mcp</code> on the service address (Streamable HTTP). Switch it on in
<b>Settings → External access</b>. Authentication is the same as for the HTTP API; the assistant acts as that
user, with that user's permissions, and its changes are in the Audit log (source <b>mcp</b>). Without write
access, or with <b>MCP read-only</b> on, only the reading tools are available.</p>
<p>Tools: <code>whoami</code>, <code>list_zones</code>, <code>get_zone</code>, <code>list_rrsets</code>,
<code>count_records</code>, <code>list_subdomains</code>, <code>search_records</code>, <code>dns_query</code>,
<code>check_propagation</code>, <code>apply_rrsets</code>, <code>create_zone</code>, <code>delete_zone</code>.</p>
<p>Client configuration:</p>
<div class="docs-code"><button type="button" class="btn btn-sm" data-doc-copy>Copy</button><pre>{
  "mcpServers": {
    "dns-panel": {
      "url": "https://dns.example.com/mcp",
      "headers": { "Authorization": "Bearer dnsp_…" }
    }
  }
}</pre></div>
<p><b>Acting for each person.</b> With an API token every request acts as the token's owner. For an assistant
used by many people (for example Microsoft Copilot in Teams), connect it with OAuth through your identity
provider and add it under <b>OIDC providers</b> in External access with the same issuer and audience: each request then acts as
the person who asked. People are recognised by their certificate CN, username or e-mail; nothing is mapped by hand.</p>
<p><b>Local.</b> On the node itself an assistant can also run the server over stdio:
<code>sudo -u www-data perl /opt/dns-panel/www/mcp/dns-mcp.pl</code>; then it names the person in the
<code>requester</code> argument of each call.</p>
</section>

<section id="doc-roadmap" class="card">
<h2>Roadmap</h2>
<p><b>v1.0</b> — everything described above.</p>
<p><b>Next, v1.1 — DNS monitoring:</b> query statistics from every secondary (QPS, query types, response codes,
UDP/TCP, traffic), top clients and names, transfer and serial state, server load; charts per server and group,
and an overview of load and anomalies.</p>
<p><b>Later:</b> health-based failover beyond single records, GeoDNS and traffic steering.</p>
</section>

</div>
</div>
HTML
