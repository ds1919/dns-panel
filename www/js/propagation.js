/* DNS Panel — Propagation.
   Tabs: Servers | Catalogs. Servers = ONE inventory table over /dns-api/secondary/*, styled with the
   SAME shared components as the rest of the site (.data-table / .badge / .link / .lc-* / .filter).
   Groups are simple tags with a default TSIG (generated here, secret shown once). A group's allow-axfr
   ACL is built automatically from its member servers' IPs — no ACL/IP objects in the UI. Data arrives
   inline (#prop-data); mutations hit /secondary/* (RBAC on the server). */

(function () {
    'use strict';

    var DATA = null;
    var TAB = 'servers';
    var SORT = { k: 'name', d: 1 };
    var FILTER = { group: '', status: '' };
    var SEARCH = '';
    var EDIT = null;                     // server id being inline-edited
    // Uncommitted Edit-row changes, kept apart from the server object: the auth modal replaces that object
    // with the backend response, and the draft must survive it.
    var DRAFT = null;                    // {sid, name, ip, description, enabled, gids[], cids[], notify_policy, axfr_policy}
    var MODAL = null;                    // {kind:'groups'} | null
    var GM = { edit: null, newG: false, draft: null };   // draft: working copy of the group form (survives re-renders)
    var HIST = null;                     // {id,name,loading,rows,err} for the history modal
    var NT = null;                       // personal TSIG modal: {nodeId, revealed:{}, addOpen, addName, addAlgo, addSecret}
    // ---- Catalogs tab (master-detail) ----
    var CSEL = null;                     // selected catalog catalog_id
    var CTAB = 'zones';                  // catalog sub-tab: zones | servers
    // Direct AXFR tab table state. Same shape as the catalog zone picker's because it is the same table;
    // one set of functions serves both so the two zone lists never filter or sort differently.
    var DX = { search: '', mKind: '', mLabel: '', mShow: 'all',
               sort: { k: 'zone', d: 1 }, menu: null, sel: {}, busy: null };
    // Zone table state in use: the picker's while it is open, otherwise the tab's (the picker only opens
    // from the Catalog tab).
    // The "?" help is shared panel UI (app.js); this is only a local alias.
    var helpDot = function (id, text) { return window.DNSPanel.helpDot(id, text); };

    function zst() { return (CMODAL && CMODAL.kind === 'zones') ? CMODAL : DX; }
    function zTable() { return (CMODAL && CMODAL.kind === 'zones') || TAB === 'direct'; }
    function zRerender() { if (CMODAL && CMODAL.kind === 'zones') renderCatModal(); else render(); }
    var CNEW = null;                     // new-catalog draft {name,description} | null
    var CHEAD = null;                    // header edit draft {aid,name,description} | null
    var CMODAL = null;                   // zone/group picker {kind:'zones'|'groups', aid}
    var CSUBM = null;                    // open reference config modal { aid, nid, showSecret, state, cfg, err }
    var CEXP = {};                       // expanded groups on the Servers sub-tab: key aid+':'+gid → true

    var ACTION_LABEL = { secondary_server_save: 'Saved', secondary_server_delete: 'Deleted' };
    var IC_EYE = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7-11-7-11-7z"/><circle cx="12" cy="12" r="3"/></svg>';
    var IC_EYEOFF = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20C5 20 1 12 1 12a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>';
    var IC_COPY = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>';

    function onPage() { return !!document.getElementById('prop-data'); }
    function esc(s) { return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'); }
    function canSec()  { return DATA && DATA.caps && DATA.caps.sec; }
    function canDist() { return DATA && DATA.caps && DATA.caps.dist; }
    function canCat()  { return DATA && DATA.caps && DATA.caps.cat; }   // catalog.manage — provisioning intent + apply
    function byId(arr, id) { id = +id; for (var i = 0; i < (arr || []).length; i++) if (+arr[i].id === id) return arr[i]; return null; }
    function fail(err) { window.DNSPanel.alert({ message: (err && err.message) ? err.message : 'Request failed' }); }
    async function copyText(txt) {
        try { if (navigator.clipboard && navigator.clipboard.writeText) { await navigator.clipboard.writeText(txt); return; } } catch (e) {}
        var ta = document.createElement('textarea'); ta.value = txt; ta.style.position = 'fixed'; ta.style.opacity = '0';
        document.body.appendChild(ta); ta.focus(); ta.select();
        try { document.execCommand('copy'); } catch (e) {}
        document.body.removeChild(ta);
    }
    function uiSelect(name, opts, value) { return window.DNSPanel.selectHtml(name, opts, value); }
    function pad(n) { return (n < 10 ? '0' : '') + n; }
    function utcStamp() { var d = new Date(); return d.getUTCFullYear() + '-' + pad(d.getUTCMonth() + 1) + '-' + pad(d.getUTCDate()) + ' ' + pad(d.getUTCHours()) + ':' + pad(d.getUTCMinutes()) + ':' + pad(d.getUTCSeconds()); }
    function replaceServer(s) { var a = DATA.servers || []; for (var i = 0; i < a.length; i++) if (+a[i].id === +s.id) { a[i] = s; return; } a.push(s); }
    // Sync catalogs' node_ids after the server's direct assignments change.
    function syncServerCatalogsLocal(nid, audIds) {
        nid = +nid; var want = {}; (audIds || []).forEach(function (a) { want[+a] = 1; });
        (DATA.catalogs || []).forEach(function (c) {
            var has = (c.node_ids || []).indexOf(nid) >= 0;
            // A changed membership also drops the catalog's loaded consumer status, or the catalog's Servers tab
            // shows the new server without its authorization and subscription state.
            if (want[+c.catalog_id] && !has) { c.node_ids = c.node_ids || []; c.node_ids.push(nid); delete CCONS[+c.catalog_id]; }
            else if (!want[+c.catalog_id] && has) { c.node_ids = c.node_ids.filter(function (x) { return +x !== nid; }); delete CCONS[+c.catalog_id]; }
        });
    }
    function localizeTimes(root) {
        (root || document).querySelectorAll('.lc-time[data-utc]').forEach(function (el) {
            var u = el.getAttribute('data-utc'); if (u) el.textContent = window.DNSPanel.fmtTime(u);
        });
    }
    // client-side TSIG generation: we hold the plaintext → can show it once; server stores it write-only.
    function randArr(n) { var a = new Uint8Array(n); (window.crypto || window.msCrypto).getRandomValues(a); return a; }
    function randomSecret() { var a = randArr(32), s = ''; for (var i = 0; i < a.length; i++) s += String.fromCharCode(a[i]); return btoa(s); }
    function shortHex() { return Array.prototype.map.call(randArr(2), function (b) { return ('0' + b.toString(16)).slice(-2); }).join(''); }
    function slug(s) { return (String(s || 'group').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '')) || 'group'; }
    function keySuffix(secret) { return (String(secret || '').replace(/[^a-z0-9]/gi, '').toLowerCase().slice(0, 5)) || shortHex(); }   // 5 chars of the key make the name unique
    function suggestKeyName(gname, secret) { return slug(gname) + '-' + keySuffix(secret); }

    function readData() { var el = document.getElementById('prop-data'); try { DATA = el ? JSON.parse(el.textContent) : null; } catch (e) { DATA = null; } }
    function restore() {
        try { var s = JSON.parse(localStorage.getItem('propNav') || '{}');
            if (s.tab === 'catalogs' || s.tab === 'direct') TAB = s.tab;
            if (s.sort && s.sort.k) SORT = { k: s.sort.k, d: s.sort.d === -1 ? -1 : 1 };
            if (s.ctab === 'servers') CTAB = 'servers';
            if (s.cat && catById(s.cat)) CSEL = +s.cat;   // selected catalog survives F5 (if it still exists)
        } catch (e) {}
    }
    function saveNav() { try { localStorage.setItem('propNav', JSON.stringify({ tab: TAB, sort: SORT, cat: CSEL, ctab: CTAB })); } catch (e) {} }

    function groupStatusPill(g) {
        var st = g.axfr_status || {}, n = (st.issues || []).length;
        if (st.consumer_ready) return '<span class="badge master">Ready</span>';
        if (st.policy_ready)   return '<span class="badge slave">Incomplete · ' + n + '</span>';
        return '<span class="badge err">Not ready · ' + n + '</span>';
    }
    function statusBadge(s) { return s.enabled ? '<span class="badge master">Active</span>' : '<span class="badge slave">Disabled</span>'; }

    function nodePrimaryKey(s) { return (s.tsig_keys || []).filter(function (k) { return +k.is_primary === 1; })[0] || null; }
    function groupPrimaryKey(g) { return (g && g.tsig_keys || []).filter(function (k) { return +k.is_primary === 1; })[0] || null; }   // display: the group's active key
    function groupNameById(gid) { var g = byId(DATA.groups, gid); return g ? g.name : ('#' + gid); }
    function keyNameFor(s, ea) {   // key name for the tooltip, from the group or personal keys
        if (!ea || !ea.tsig_key_id) return '';
        var list = ea.source === 'personal' ? (s.tsig_keys || []) : (ea.group_id ? ((byId(DATA.groups, ea.group_id) || {}).tsig_keys || []) : []);
        var k = list.filter(function (x) { return +x.id === +ea.tsig_key_id; })[0];
        return k ? k.name : '';
    }
    // Formats backend s.effective_auth; JS never recomputes auth/readiness (the backend is the single resolver).
    function authBadge(s) {
        var ea = s.effective_auth || { source: 'none', authorized: 0 };
        // issues come from the backend; "incomplete" without a reason is a useless badge.
        var why = (ea.issues || []).join('; ');
        if (ea.source === 'none') return { label: 'not authorized', cls: 'slave', why: why || 'add an address or a personal TSIG key' };
        var kn = keyNameFor(s, ea), cls = ea.authorized ? 'master' : 'warn';
        if (ea.source === 'personal') return { label: 'TSIG · personal', cls: cls, why: why, what: 'Personal TSIG key' + (kn ? ': ' + kn : '') };
        if (ea.source === 'group')    return { label: 'TSIG · ' + groupNameById(ea.group_id), cls: cls, why: why, what: 'TSIG key of group ' + groupNameById(ea.group_id) + (kn ? ' (' + kn + ')' : '') };
        return { label: 'IP ACL', cls: cls, why: why,
                 what: ea.group_id ? 'IP ACL of group ' + groupNameById(ea.group_id) : 'IP ACL: the server’s own address' };
    }
    // The badge is the button: authorization is configured where its result is shown. It is clickable in
    // the Edit row too, and the unsaved row edit survives (stashEditRow).
    function serverAuth(s) {
        var b = authBadge(s), incomplete = (b.cls === 'warn' || b.cls === 'slave');
        var title = [b.what, (incomplete && b.why) ? 'Missing: ' + b.why : ''].filter(function (x) { return x; }).join(' — ');
        var body = esc(b.label) + (b.cls === 'warn' ? ' · incomplete' : '');
        var reason = (incomplete && b.why) ? '<div class="mini text-mute auth-why">' + esc(b.why) + '</div>' : '';
        if (!canDist()) return '<span class="badge ' + b.cls + '" data-tip="' + esc(title) + '">' + body + '</span>' + reason;
        return '<button type="button" class="badge ' + b.cls + ' badge-btn" data-srv-tsig="' + s.id + '" data-tip="' + esc(title) + '">' + body + '</button>' + reason;
    }
    function authSortKey(s) { var ea = s.effective_auth || {}; return (ea.source || 'zz') + (ea.authorized ? '1' : '0'); }

    // ---------- API ----------
    // policy_warning is handled here, at the single API entry point: the setting is saved, but the
    // distribution policy (TSIG-ALLOW-AXFR / ALLOW-AXFR-FROM / ALSO-NOTIFY) did not reach PowerDNS and the
    // worker will reconcile it. Handling it per call site would get forgotten somewhere.
    async function api(path, method, body) {
        var res = await window.DNSPanel.api(path, { method: method, body: body ? JSON.stringify(body) : undefined });
        var w = res && res.data && res.data.policy_warning;
        // Title matches the catalogs.last_error banner: the recompute covers AXFR authorization and NOTIFY.
        if (w) window.DNSPanel.alert({ title: 'Distribution policy not applied',
                                       message: w + '. The setting is saved; the panel keeps retrying in the background.' });
        return res;
    }
    async function refresh() {
        var main = document.getElementById('main-content');
        try {
            var res = await fetch('/ajax/propagation', { credentials: 'same-origin' });
            if (res.status === 401 || res.redirected) { window.location.href = '/login'; return; }
            // fetch rejects only on network errors; without this check a 500/403 page would be inserted as content.
            if (!res.ok) throw new Error('HTTP ' + res.status);
            main.innerHTML = await res.text();
        } catch (e) { console.error('propagation: refresh failed', e); return; }
        CCONS = {};   // subscriber state follows the data just re-read
        readData(); if (DATA) render();
    }
    // Re-read servers (authoritative effective_auth) after a GROUP auth change: its default members' badges
    // go stale. Keeps catalog_ids; leaves the modal alone.
    async function refreshServers() {
        try {
            var res = await api('secondary/servers', 'GET'); var list = res && res.data && res.data.servers;
            if (!list) return;
            // GET servers omits last_by/last_at and catalog_ids: carry them over. A group operation doesn't change
            // the server itself, so Last change stays as it was.
            var omap = {}; (DATA.servers || []).forEach(function (s) { omap[+s.id] = s; });
            list.forEach(function (s) { var o = omap[+s.id]; if (o) { s.catalog_ids = o.catalog_ids || []; s.last_by = o.last_by; s.last_at = o.last_at; } else { s.catalog_ids = []; } });
            CCONS = {};
            DATA.servers = list; render();   // the modal (#prop-modal) is a separate overlay; render() doesn't touch it
        } catch (e) { window.DNSPanel.alert({ message: 'Server authorization may be stale — refresh (F5) to re-sync.' }); }   // don't stay silent: badges may be stale
    }

    // ---------- tabs ----------
    // Order: who may transfer at all (Servers) → how zones normally leave (Direct AXFR) → the catalog, which
    // only announces primary zones. Each tab is shown only with its permission.
    function allowedTabs() {
        var out = [];
        if (canSec())  out.push({ id: 'servers',  label: 'Servers' });
        if (canDist()) out.push({ id: 'direct',   label: 'Direct AXFR' });
        if (canCat())  out.push({ id: 'catalogs', label: 'Catalog' });
        return out;
    }
    // The remembered or URL-given tab may not be permitted: fall back to the first allowed one rather than
    // showing nothing.
    function normalizeTab() {
        var tabs = allowedTabs();
        if (tabs.length && !tabs.some(function (t) { return t.id === TAB; })) TAB = tabs[0].id;
    }
    function tabsHtml() {
        var tabs = allowedTabs();
        if (tabs.length < 2) return '';   // a single tab needs no switcher
        return '<div class="dist-tabs">' + tabs.map(function (t) {
            return '<button class="dist-tab' + (TAB === t.id ? ' active' : '') + '" data-tab="' + t.id + '">' + t.label + '</button>';
        }).join('') + '</div>';
    }

    // ---------- servers: filter + sort ----------
    function serverMatches(s) {
        if (FILTER.group && !(s.groups || []).some(function (g) { return +g.id === +FILTER.group; })) return false;
        if (FILTER.status === 'enabled' && !s.enabled) return false;
        if (FILTER.status === 'disabled' && s.enabled) return false;
        if (SEARCH) {
            var q = SEARCH.toLowerCase();
            var hay = [s.name, s.ip, s.description, (s.groups || []).map(function (g) { return g.name; }).join(' ')].join(' ').toLowerCase();
            if (hay.indexOf(q) < 0) return false;
        }
        return true;
    }
    function sortKey(s, k) {
        if (k === 'enabled') return s.enabled ? '1' : '0';
        if (k === 'group')   return (((s.groups || [])[0] || {}).name || '').toLowerCase();
        if (k === 'auth')    return authSortKey(s);
        if (k === 'lc')      return String(s.last_at || '');
        return String(s[k] == null ? '' : s[k]).toLowerCase();
    }
    function sortedServers() {
        var rows = (DATA.servers || []).filter(serverMatches), k = SORT.k, d = SORT.d;
        return rows.sort(function (a, b) {
            var x = sortKey(a, k), y = sortKey(b, k);
            if (x < y) return -d; if (x > y) return d;
            return String(a.name).toLowerCase() < String(b.name).toLowerCase() ? -1 : 1;
        });
    }

    // ---------- servers: edit draft ----------
    function draftFor(id) { return (DRAFT && +DRAFT.sid === +id) ? DRAFT : null; }
    // Capture the Edit row before something re-renders the table (the auth modal applies changes
    // immediately and re-renders on close).
    function stashEditRow(id) {
        var row = document.querySelector('tr.editing[data-sid="' + id + '"]'); if (!row) return;
        var val = function (sel) { var e = row.querySelector(sel); return e ? (e.value || '').trim() : null; };
        var d = { sid: +id, name: val('[data-f="name"]'), ip: val('[data-f="ip"]'), description: val('[data-f="description"]') };
        var en = row.querySelector('[data-f="enabled"]'); if (en) d.enabled = en.checked ? 1 : 0;
        d.gids = []; row.querySelectorAll('[data-g]').forEach(function (c) { if (c.checked) d.gids.push(+c.getAttribute('data-g')); });
        if (canCat()) {
            d.cids = []; row.querySelectorAll('[data-c]').forEach(function (c) { if (c.checked) d.cids.push(+c.getAttribute('data-c')); });
        }
        if (canDist()) {
            var np = row.querySelector('[data-pf="notify_policy"]:checked'); if (np) d.notify_policy = np.value;
            var ap = row.querySelector('[data-pf="axfr_policy"]:checked');   if (ap) d.axfr_policy   = ap.value;
        }
        DRAFT = d;
    }

    // ---------- servers: render ----------
    function groupChips(s) {
        var gs = s.groups || []; if (!gs.length) return '<span class="text-mute">—</span>';
        var shown = gs.slice(0, 3).map(function (g) { return '<span class="chip">' + esc(g.name) + '</span>'; }).join(' ');
        return shown + (gs.length > 3 ? ' <span class="chip chip-more">+' + (gs.length - 3) + '</span>' : '');
    }
    // Trigger label names the kind ("Groups · 2"): a bare "none" couldn't tell groups from catalogs.
    function msLabel(kind, n) {
        var word = kind === 'catalog' ? 'Catalogs' : 'Groups';
        return word + ' · ' + (n ? String(n) : 'none');
    }
    // Searchable multi-select: trigger + popover with list and search; checkboxes are read from the row DOM on Save.
    function grpMultiSelect(s) {
        var d = draftFor(s.id), ids = d ? d.gids : (s.groups || []).map(function (g) { return +g.id; });
        var have = {}; ids.forEach(function (gid) { have[+gid] = 1; });
        var n = ids.length;
        var opts = (DATA.groups || []).map(function (g) {
            return '<label class="gms-opt"><input type="checkbox" data-g="' + g.id + '"' + (have[+g.id] ? ' checked' : '') + '> ' + esc(g.name) + '</label>';
        }).join('') || '<div class="text-mute" style="padding:.4rem;">No groups — create one first.</div>';
        return '<div class="grp-ms" data-ms-kind="group"><button type="button" class="grp-ms-trigger" data-grp-ms-toggle>'
            + '<span class="grp-ms-count">' + msLabel('group', n) + '</span> ▾</button>'
            + '<div class="grp-ms-pop" hidden><div class="grp-ms-head">Groups</div>'
            + '<input class="field-input sm grp-ms-search" placeholder="Search groups…" data-grp-ms-search>'
            + '<div class="grp-ms-list">' + opts + '</div></div></div>';
    }
    // Server → catalogs (direct assignments): chips, and a multi-select in edit (reuses the .grp-ms popover).
    // Columns follow permissions: server catalogs need catalog.manage, delivery policies distribution.manage.
    function srvCols() { return 7 + (canCat() ? 1 : 0) + (canDist() ? 2 : 0); }
    // Catalogs the server gets via groups: {catalog_id: groupName}. Removable only via the group.
    function serverCatalogsViaGroups(s) {
        var gids = {}; (s.groups || []).forEach(function (g) { gids[+g.id] = g.name; });
        var via = {};
        (DATA.catalogs || []).forEach(function (c) {
            (c.group_ids || []).forEach(function (gid) { if (gids[+gid] != null && via[+c.catalog_id] == null) via[+c.catalog_id] = gids[+gid]; });
        });
        return via;
    }
    // Effective catalogs = via-group ∪ direct; via-group wins in display.
    function serverEffectiveCatalogs(s) {
        var via = serverCatalogsViaGroups(s), direct = {}; (s.catalog_ids || []).forEach(function (id) { direct[+id] = 1; });
        var out = [];
        (DATA.catalogs || []).forEach(function (c) {
            var aid = +c.catalog_id;
            if (via[aid] != null) out.push({ aid: aid, name: c.name, via: 'group', groupName: via[aid] });
            else if (direct[aid]) out.push({ aid: aid, name: c.name, via: 'direct' });
        });
        return out;
    }
    function catChipsForServer(s) {
        var eff = serverEffectiveCatalogs(s); if (!eff.length) return '<span class="text-mute">—</span>';
        var shown = eff.slice(0, 3).map(function (c) {
            return c.via === 'group'
                ? '<span class="chip chip-via" data-tip="via group ' + esc(c.groupName) + '">' + esc(c.name) + '</span>'
                : '<span class="chip" data-tip="direct assignment">' + esc(c.name) + '</span>';
        }).join(' ');
        return shown + (eff.length > 3 ? ' <span class="chip chip-more">+' + (eff.length - 3) + '</span>' : '');
    }
    function catMultiSelect(s) {
        var d = draftFor(s.id), dids = d && d.cids ? d.cids : (s.catalog_ids || []);
        var direct = {}; dids.forEach(function (id) { direct[+id] = 1; });
        var via = serverCatalogsViaGroups(s);
        var base = 0, k; for (k in via) if (via.hasOwnProperty(k)) base++;   // via-group catalogs (locked)
        var dcount = 0; (DATA.catalogs || []).forEach(function (c) { if (via[+c.catalog_id] == null && direct[+c.catalog_id]) dcount++; });
        var n = base + dcount;
        var opts = (DATA.catalogs || []).map(function (c) {
            var aid = +c.catalog_id;
            if (via[aid] != null)   // via a group: checked+disabled, removable only by removing the group from the catalog
                return '<label class="gms-opt gms-locked" data-tip="Delivered via group ' + esc(via[aid]) + ' — remove the group from the distribution to change this"><input type="checkbox" checked disabled> ' + esc(c.name) + ' <span class="mini text-mute">via ' + esc(via[aid]) + '</span></label>';
            return '<label class="gms-opt"><input type="checkbox" data-c="' + aid + '"' + (direct[aid] ? ' checked' : '') + '> ' + esc(c.name) + '</label>';
        }).join('') || '<div class="text-mute" style="padding:.4rem;">No catalogs yet.</div>';
        return '<div class="grp-ms" data-ms-kind="catalog" data-cat-base="' + base + '"><button type="button" class="grp-ms-trigger" data-grp-ms-toggle>'
            + '<span class="grp-ms-count">' + msLabel('catalog', n) + '</span> ▾</button>'
            + '<div class="grp-ms-pop" hidden><div class="grp-ms-head">Catalogs</div>'
            + '<input class="field-input sm grp-ms-search" placeholder="Search distributions…" data-grp-ms-search>'
            + '<div class="grp-ms-list">' + opts + '</div></div></div>';
    }
    // The Servers table shows only the server's own setting: the effective value belongs to the
    // (server, catalog) pair and is shown in Catalogs → Servers. It covers zone data NOTIFY only; catalog
    // membership changes are always announced to every subscriber.
    var NP_LABEL = { inherit: 'Inherit', on: 'On', off: 'Off' };
    var AP_LABEL = { inherit: 'Inherit', allow: 'Allow', deny: 'Deny' };
    var NP_HINT = 'Zone NOTIFY: whether PowerDNS tells this server that a zone\u2019s data changed. '
                + 'Inherit = as set on the server\u2019s groups. Catalog membership changes are always announced '
                + 'to every subscriber, regardless of this setting.';
    var AP_HINT = 'AXFR: whether this server may transfer zone data from our PowerDNS. '
                + 'Inherit = as set on the server\u2019s groups; with no group Inherit means Allow. '
                + 'This is not access to everything: only zones of the distributions assigned to this server.';
    function npOf(s) { var v = (s && s.notify_policy) || 'inherit'; return NP_LABEL[v] ? v : 'inherit'; }
    function apOf(s) { var v = (s && s.axfr_policy)   || 'inherit'; return AP_LABEL[v] ? v : 'inherit'; }
    // One control for both policies: a dropdown in the fixed .grp-ms layer, not the themed select, whose
    // position:absolute menu would be clipped by .table-wrap{overflow:hidden}.
    function policyCell(cur, labels, hint) {
        return '<span class="' + (cur === 'inherit' ? 'text-mute' : '') + '" data-tip="' + esc(hint) + '">' + labels[cur] + '</span>';
    }
    function policyPick(s, field, cur, labels, order, hint) {
        if (!canDist()) return policyCell(cur, labels, hint);   // editing needs distribution.manage
        var nm = field + '-' + ((s && s.id) || 'new');
        var opts = order.map(function (k) {
            return '<label class="gms-opt"><input type="radio" name="' + nm + '" data-pf="' + field + '" value="' + k + '"'
                 + (k === cur ? ' checked' : '') + '> ' + labels[k] + '</label>';
        }).join('');
        return '<div class="grp-ms" data-ms-kind="' + field + '" data-tip="' + esc(hint) + '"><button type="button" class="grp-ms-trigger" data-grp-ms-toggle>'
            + '<span class="grp-ms-count">' + labels[cur] + '</span> \u25be</button>'
            + '<div class="grp-ms-pop" hidden><div class="grp-ms-list">' + opts + '</div></div></div>';
    }
    function notifySeg(s) { var d = draftFor(s.id); return policyPick(s, 'notify_policy', npOf(d && d.notify_policy ? d : s), NP_LABEL, ['inherit','on','off'], NP_HINT); }
    function axfrSeg(s)   { var d = draftFor(s.id); return policyPick(s, 'axfr_policy',   apOf(d && d.axfr_policy   ? d : s), AP_LABEL, ['inherit','allow','deny'], AP_HINT); }
    function notifyCell(s) { return policyCell(npOf(s), NP_LABEL, NP_HINT); }
    function th(k, label) {
        var arr = SORT.k === k ? (SORT.d === 1 ? ' ↑' : ' ↓') : '';
        return '<th class="th-sort' + (SORT.k === k ? ' sorted' : '') + '" data-sort="' + k + '">' + esc(label) + arr + '</th>';
    }
    function lastChangeCell(s) {
        if (!s.last_by && !s.last_at) return '<span class="text-mute">—</span>';
        var raw = s.last_at || '', when = raw ? esc(raw.substring(0, 16)) : '';
        var info = window.DNSPanel.actorIcon(s.last_by || '')
            + '<div class="lc-at mono text-mute lc-time" data-utc="' + esc(raw) + '">' + when + '</div>';
        var hist = '<button type="button" class="prop-icbtn" data-srv-hist="' + s.id + '" data-tip="Change history"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 3v5h5"/><path d="M3.05 13A9 9 0 1 0 6 5.3L3 8"/><path d="M12 7v5l3 2"/></svg></button>';
        return '<div class="lc-cell">' + info + hist + '</div>';
    }
    function serverRow(s) {
        if (EDIT === +s.id && canSec()) {
            var d = draftFor(s.id) || {}, dv = function (k, fb) { return d[k] != null ? d[k] : fb; };
            return '<tr class="editing" data-sid="' + s.id + '">'
                + '<td><input class="field-input sm" data-f="name" value="' + esc(dv('name', s.name)) + '" placeholder="name">'
                    + '<input class="field-input sm mt4" data-f="description" value="' + esc(dv('description', s.description || '')) + '" placeholder="description (optional)"></td>'
                + '<td><input class="field-input sm mono" data-f="ip" value="' + esc(dv('ip', s.ip || '')) + '"></td>'
                + '<td>' + grpMultiSelect(s) + '</td>'
                + (canCat()  ? '<td>' + catMultiSelect(s) + '</td>' : '')
                + (canDist() ? '<td>' + axfrSeg(s) + '</td>' : '')
                + (canDist() ? '<td>' + notifySeg(s) + '</td>' : '')
                + '<td>' + serverAuth(s) + '</td>'
                + '<td><label class="chk"><input type="checkbox" data-f="enabled"' + (dv('enabled', s.enabled) ? ' checked' : '') + '> Active</label></td>'
                + '<td>' + lastChangeCell(s) + '</td>'
                + '<td class="right nowrap"><a href="#" class="link" data-srv-save="' + s.id + '">Save</a> <a href="#" class="link" data-srv-cancel style="margin-left:.5rem;color:var(--text-mute);">Cancel</a></td>'
                + '</tr>';
        }
        var act = canSec()
            ? '<a href="#" class="link" data-srv-edit="' + s.id + '">Edit</a> <a href="#" class="link" data-srv-del="' + s.id + '" style="margin-left:.6rem;color:var(--danger);">Delete</a>'
            : '';
        return '<tr data-sid="' + s.id + '">'
            + '<td><b>' + esc(s.name) + '</b>' + (s.description ? '<div class="mini text-mute">' + esc(s.description) + '</div>' : '') + '</td>'
            + '<td class="mono">' + esc(s.ip || '—') + '</td>'
            + '<td>' + groupChips(s) + '</td>'
            + (canCat()  ? '<td>' + catChipsForServer(s) + '</td>' : '')
            + (canDist() ? '<td>' + policyCell(apOf(s), AP_LABEL, AP_HINT) + '</td>' : '')
            + (canDist() ? '<td>' + notifyCell(s) + '</td>' : '')
            + '<td>' + serverAuth(s) + '</td>'
            + '<td>' + statusBadge(s) + '</td>'
            + '<td>' + lastChangeCell(s) + '</td>'
            + '<td class="right nowrap">' + act + '</td>'
            + '</tr>';
    }
    function groupOpts(ph) { return [{ value: '', label: ph }].concat((DATA.groups || []).map(function (g) { return { value: String(g.id), label: g.name }; })); }
    function serverToolbar() {
        var sopts = [{ value: '', label: 'All statuses' }, { value: 'enabled', label: 'Active' }, { value: 'disabled', label: 'Disabled' }];
        return '<div class="toolbar">'
            + '<div class="search"><svg class="ic" viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/></svg>'
            + '<input placeholder="Search servers…" data-search value="' + esc(SEARCH) + '"></div>'
            + uiSelect('prop-flt-group', groupOpts('All groups'), FILTER.group)
            + uiSelect('prop-flt-status', sopts, FILTER.status)
            + '</div>';
    }
    // Groups at a glance: a group is an object of its own now (it may allow networks with no server in it).
    // NOTIFY is left out: for a group it is only the default of its future members, and next to a network it
    // would read as if a whole range got NOTIFY.
    function groupsSection() {
        var gs = (DATA.groups || []).slice().sort(function (a, b) { return String(a.name).localeCompare(String(b.name)); });
        var rows = gs.map(function (g) {
            var nets = (g.prefixes || []).length ? g.prefixes.map(function (p) { return '<div class="mono">' + esc(p) + '</div>'; }).join('') : '<span class="text-mute">—</span>';
            var k = g.axfr_auth_mode === 'tsig_only' ? groupPrimaryKey(g) : null;
            var auth = g.axfr_auth_mode === 'tsig_only' ? (k ? 'TSIG ' + esc(k.name) : '<span class="text-mute">TSIG — no key</span>') : 'IP ACL';
            return '<tr class="grp-row" data-grp-row="' + g.id + '"><td><b>' + esc(g.name) + '</b></td><td>' + esc(g.description || '') + '</td>'
                + '<td>' + (g.node_count || 0) + '</td><td>' + nets + '</td>'
                + '<td>' + (+g.zone_axfr ? 'Allow' : '<span class="text-mute">Deny</span>') + '</td><td>' + auth + '</td></tr>';
        }).join('') || '<tr><td colspan="6" class="text-dim" style="padding:.8rem 1rem;">No groups</td></tr>';
        return '<div class="cat-tabc-head"><span>Groups</span>'
            + ((canSec() || canDist()) ? '<button class="btn btn-ghost sm" data-groups-open>Manage groups</button>' : '') + '</div>'
            + '<div class="table-wrap"><table class="data-table grp-table"><thead><tr><th>Group</th><th>Description</th><th>Servers</th><th>Networks</th><th>AXFR</th><th>Authorization</th></tr></thead>'
            + '<tbody>' + rows + '</tbody></table></div>';
    }
    // Blank "server" for the add form: same multi-select renderers as Edit. With no group there is nothing
    // to inherit, so defaults are Allow/On (Inherit would silently mean off); picking groups switches to Inherit.
    function blankServer() { return { id: 'new', name: '', ip: '', description: '', enabled: 1, groups: [],
                                      axfr_policy: 'allow', notify_policy: 'on',
                                      catalog_ids: [], tsig_keys: [], effective_auth: null }; }
    function addRow() {
        if (!canSec()) return '';
        var b = blankServer();
        return '<div class="srv-tbl-add">'
            + '<input class="field-input sa-name" data-f="name" placeholder="server name">'
            + '<input class="field-input mono sa-ip" data-f="ip" placeholder="IP address">'
            + '<input class="field-input sa-desc" data-f="description" placeholder="description (optional)">'
            + grpMultiSelect(b)
            + (canCat()  ? catMultiSelect(b) : '')
            + (canDist() ? '<span class="sa-notify"><span class="sa-lbl">AXFR</span>' + axfrSeg(b) + '</span>' : '')
            + (canDist() ? '<span class="sa-notify"><span class="sa-lbl">Zone NOTIFY</span>' + notifySeg(b) + '</span>' : '')
            + '<button class="btn btn-primary" data-srv-add-save>Add server</button>'
            + '</div>';
    }
    function serversView() {
        var rows = sortedServers();
        var body = rows.length ? rows.map(serverRow).join('')
            : '<tr><td colspan="' + srvCols() + '" class="text-dim" style="padding:1rem;">' + ((DATA.servers || []).length ? 'No servers match the filters.' : 'No secondary servers yet — add one above.') + '</td></tr>';
        var table = '<div class="table-wrap"><table class="data-table srv-table"><thead><tr>'
            + th('name', 'Name') + th('ip', 'IP address') + th('group', 'Groups')
            + (canCat()  ? '<th>Catalogs</th>' : '')
            + (canDist() ? '<th>AXFR</th>' : '')
            + (canDist() ? '<th>Zone NOTIFY</th>' : '')
            + th('auth', 'Authorization') + th('enabled', 'Status') + th('lc', 'Last change') + '<th class="right">Actions</th>'
            + '</tr></thead><tbody>' + body + '</tbody></table></div>';
        return groupsSection()
            + '<div class="cat-tabc-head srv-head"><span>Secondary servers</span></div>'
            + serverToolbar() + addRow() + table;
    }
    // ---------- Catalogs tab ----------
    function catById(aid) { return byId2(DATA.catalogs, 'catalog_id', aid); }
    function byId2(arr, key, id) { id = +id; for (var i = 0; i < (arr || []).length; i++) if (+arr[i][key] === id) return arr[i]; return null; }
    function zoneById(did) { return byId2(DATA.all_zones, 'domain_id', did); }
    function catalogOfZone(did) { did = +did; var cs = DATA.catalogs || []; for (var i = 0; i < cs.length; i++) if ((cs[i].zone_ids || []).indexOf(did) >= 0) return cs[i]; return null; }
    // Two factual states: the producer zone exists in PowerDNS, or its creation failed and we say so.
    function catStatusPill(c) {
        if (c.last_error) return '<span class="pill warn" data-tip="' + esc(c.last_error) + '">Problem</span>';
        if (c.provisioned) return '<span class="pill ok">Ready</span>';
        return '<span class="pill muted" data-tip="The producer zone was not created in PowerDNS \u2014 retry from the menu">Not created</span>';
    }
    function catalogsView() {
        if (!canCat()) return '<div class="card"><p class="text-dim" style="margin:0;">Read access requires <code>catalog.manage</code>.</p></div>';
        if (DATA.catalogs_err) return '<div class="card banner-err"><p style="margin:0;">Failed to load catalogs: ' + esc(DATA.catalogs_err) + '.</p></div>';
        return '<div class="prop-cat-split">' + catList() + '<div class="cat-detail">' + catDetail() + '</div></div>';
    }
    // Catalog contents: a single list, from PowerDNS.
    function catShownZones(c) { return (c && c.zone_ids) || []; }

    function catList() {
        var head = '<div class="plist-head"><span>Catalogs</span><button class="btn btn-primary sm" data-cat-new-open>+ New</button></div>';
        var rows = (DATA.catalogs || []).map(function (c) {
            var sel = (+CSEL === +c.catalog_id && !CNEW) ? ' selected' : '';
            var nz = catShownZones(c).length, ng = (c.group_ids || []).length;
            return '<button class="plist-row' + sel + '" data-cat-sel="' + c.catalog_id + '">'
                + '<div class="plist-name">' + esc(c.name) + '</div>'
                + '<div class="plist-sub mono">' + (c.fqdn ? esc(c.fqdn) : 'no catalog zone') + '</div>'
                // Status is a separate flex item: inline text, a green pill on the selected accent card read as truncated.
                + '<div class="plist-sub plist-meta"><span>' + nz + ' zone' + (nz === 1 ? '' : 's') + ' · ' + ng + ' group' + (ng === 1 ? '' : 's') + '</span>'
                + catStatusPill(c) + '</div></button>';
        }).join('') || '<div class="text-dim" style="padding:.6rem .8rem;">No catalogs yet — click <b>+ New</b>.</div>';
        return '<div class="plist">' + head + '<div class="plist-rows">' + rows + '</div></div>';
    }
    function catDetail() {
        if (CNEW) return catNewForm();
        var c = CSEL ? catById(CSEL) : null;
        if (!c) return '<div class="cat-empty"><p class="text-dim">Select a catalog on the left, or click <b>+ New</b> to create one.</p></div>';
        return catHeader(c) + catSubtabs(c) + (CTAB === 'servers' ? catServersTab(c) : catZonesTab(c));
    }
    // The new-catalog form asks for the FQDN and creates the catalog in one action.
    // Same field order and labels for create and edit; attr marks the form's fields (data-catnf / data-cathf).
    function catFields(attr, v, opt) {
        opt = opt || {};
        return '<div class="frow"><label>Name</label><input class="field-input" ' + attr + '="name" value="'
             + esc(v.name || '') + '" placeholder="catalog name"></div>'
             + '<div class="frow"><label>Catalog zone (FQDN)</label><input class="field-input mono" ' + attr + '="fqdn" value="'
             + esc(v.fqdn || '') + '" placeholder="catalog.example.com"'
             + (opt.fqdnLocked ? ' readonly data-tip="PowerDNS cannot rename a producer zone \u2014 delete the catalog and create a new one"' : '') + '></div>';
    }
    function catNewForm() {
        var d = CNEW || {};
        return '<div class="cat-head-edit"><h2 class="cat-title" style="margin-top:0">New catalog</h2>'
            + catFields('data-catnf', d)
            + '<div class="cat-head-act"><button class="btn btn-ghost sm" data-cat-new-cancel>Cancel</button>'
            + '<button class="btn btn-primary sm" data-cat-new-save>' + (d.busy ? 'Creating\u2026' : 'Create catalog') + '</button></div>'
            + '<p class="text-dim mini" style="margin:.6rem 0 0;">The catalog zone is created in PowerDNS right away. '
            + 'Zones and server groups are added from the tabs afterwards.</p></div>';
    }
    function catNodeName(id) { var s = byId(DATA.servers, id); return s ? esc(s.name) : ('server #' + id); }
    // Catalog header on one line: name · FQDN · counts · status · [⋯]. Name/FQDN are edited via ⋯ → Edit.
    function catHeader(c) {
        var aid = c.catalog_id;
        if (CHEAD && +CHEAD.aid === +aid) {
            var prov = +c.provisioned === 1;
            return '<div class="cat-head-edit">'
                + catFields('data-cathf', CHEAD, { fqdnLocked: prov })
                + '<div class="cat-head-act"><button class="btn btn-ghost sm" data-cat-head-cancel>Cancel</button><button class="btn btn-primary sm" data-cat-head-save="' + aid + '">Save</button></div></div>';
        }
        var nz = catShownZones(c).length, ng = (c.group_ids || []).length;
        var meta = [];
        if (c.fqdn) meta.push('<span class="mono">' + esc(c.fqdn) + '</span>');
        meta.push(nz + ' zone' + (nz === 1 ? '' : 's'));
        meta.push(ng + ' group' + (ng === 1 ? '' : 's'));
        meta.push('catalog list from: ' + catSourceLabel());
        var axfrWarn = c.last_error ? ' <span class="pill err" data-tip="' + esc(c.last_error) + '">AXFR policy sync failed</span>' : '';
        return '<div class="cat-head1"><div class="cat-head1-main">'
            + '<span class="cat-title">' + esc(c.name) + '</span>'
            + ' <span class="cat-head1-meta">' + meta.join(' · ') + '</span> ' + catStatusPill(c) + axfrWarn
            + '</div><div class="cat-head1-side">' + catHeaderMenu(c) + '</div></div>'
            + '<div class="text-mute cat-desc">' + esc(c.fqdn || '') + '</div>';
    }
    // The ⋯ menu is a native <details>: close it on outside click, Esc and when any modal opens (otherwise
    // it pops back up when the modal closes).
    function closeCatMenus() {
        var open = document.querySelectorAll('.cat-menu[open]');
        for (var i = 0; i < open.length; i++) open[i].removeAttribute('open');
    }
    function catHeaderMenu(c) {
        if (!canCat()) return '';
        var aid = c.catalog_id, items = '';
        items += '<button class="cat-menu-item" data-cat-head-edit="' + aid + '">Edit name / FQDN</button>';
        // Creation failed: offer a retry.
        if (!c.provisioned) items += '<button class="cat-menu-item" data-cat-retry="' + aid + '">Retry creating in PowerDNS</button>';
        items += '<button class="cat-menu-item danger" data-cat-del="' + aid + '">Delete catalog\u2026</button>';
        return '<details class="cat-menu"><summary class="icon-btn" aria-label="More">\u22ef</summary><div class="cat-menu-pop">' + items + '</div></details>';
    }
    async function catRetry(aid) {
        try { var res = await api('catalogs/' + aid + '/provision', 'POST', {}); applyCatLocal(aid, res && res.data); }
        catch (e) { fail(e); }
        render();
    }
    function applyCatLocal(aid, d) {
        var c = catById(aid); if (!c || !d) return;
        c.name = d.name; c.fqdn = d.fqdn;
        c.provisioned = d.provisioned ? 1 : 0;
        c.last_error = d.last_error;
    }
    async function catSubRecheck(aid, nid) {
        try { await api('catalogs/' + aid + '/subscriptions/' + nid + '/recheck', 'POST', {}); }
        catch (e) { fail(e); }
    }
    // Reference config modal ("?" on a server row): what to configure in BIND by hand. Writes nothing, no cache.
    function openSubModal(aid, nid) { CSUBM = { aid: +aid, nid: +nid, showSecret: false, state: 'loading' }; renderSubModal(); loadSubConfig(); }
    function renderSubModal() {
        var ov = document.getElementById('prop-sub-modal');
        if (!CSUBM) { if (ov) ov.remove(); return; }
        closeCatMenus();   // don't leave the ⋯ menu open behind the overlay
        var nm = catNodeName(CSUBM.nid);
        if (!ov) { ov = document.createElement('div'); ov.id = 'prop-sub-modal'; ov.className = 'dm-overlay'; document.body.appendChild(ov); }
        var body;
        if (CSUBM.state === 'loading') body = '<p class="text-dim">Loading configuration…</p>';
        else if (CSUBM.state === 'error') body = '<p class="text-mute">Config failed: ' + esc(CSUBM.err || 'request failed') + '</p><button class="btn sm" data-sub-cfg-refresh>Retry</button>';
        else {
            var cfg = CSUBM.cfg || {}, frags = cfg.fragments || [];
            body = '<p class="mini text-dim cat-manual-intro">Reference configuration for <b>' + esc(nm) + '</b>. Apply it to BIND by hand (the panel does not write it), then <b>Recheck</b>.</p>';
            body += frags.map(function (f, i) {
                var text = f.text || '';
                var shown = (cfg.tsig && !CSUBM.showSecret) ? text.replace(/(secret\s+")[^"]*(")/g, '$1••••••••$2') : text;   // TSIG secret hidden by default
                return '<div class="cat-frag"><div class="cat-frag-h"><span>' + esc(f.title || ('Fragment ' + (i + 1))) + '</span>'
                     + '<button class="lnk sm" data-sub-copy="' + i + '">Copy</button></div>'
                     + '<pre class="cat-manual-cfg">' + esc(shown) + '</pre></div>';
            }).join('');
            if (cfg.tsig) body += '<button class="lnk sm" data-sub-secret>' + (CSUBM.showSecret ? 'Hide secret' : 'Show secret') + '</button>';
        }
        ov.innerHTML = '<div class="dm-panel cfg-panel" role="dialog" aria-modal="true">'
            + '<div class="dm-head"><div class="dm-title">BIND configuration — ' + esc(nm) + '</div><button class="icon-btn" data-sub-close aria-label="Close">×</button></div>'
            + '<div class="dm-body">' + body + '</div>'
            + '<div class="dm-foot"><button class="btn btn-ghost" data-sub-close>Close</button></div></div>';
    }
    async function loadSubConfig() {
        var m = CSUBM; if (!m) return;
        try { var res = await api('catalogs/' + m.aid + '/subscriptions/' + m.nid + '/config', 'GET'); if (CSUBM === m) { m.state = 'loaded'; m.cfg = (res && res.data) || null; } }
        catch (e) { if (CSUBM === m) { m.state = 'error'; m.err = (e && e.message) ? e.message : 'request failed'; } }
        renderSubModal();
    }
    function subCopy(i) {
        if (!CSUBM || CSUBM.state !== 'loaded') return;
        var frags = (CSUBM.cfg && CSUBM.cfg.fragments) || []; var f = frags[+i];
        if (f && f.text && navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(f.text).catch(function () {});
    }
    async function subRecheck(aid, nid) {   // live DNS check of the subscription, then refresh statuses
        try { await api('catalogs/' + aid + '/subscriptions/' + nid + '/recheck', 'POST', {}); await loadCatConsumers(aid); }
        catch (e) { fail(e); }
    }
    // Every consumer takes the catalog from our PowerDNS (single producer). Display only: addresses come from
    // PowerDNS itself (local-address); empty means it doesn't listen externally or is unreachable.
    function catSourceLabel() {
        var eps = DATA.pdns_endpoints || [];
        var why = DATA.pdns_endpoints_pair
            ? 'The service address of the HA pair: secondaries pull from whichever node is ACTIVE, never from '
              + 'a node\u2019s own address, which belongs to the STANDBY after a switchover.'
            : 'Read from PowerDNS itself \u2014 its local-address and local-port, with loopback '
              + 'addresses removed; if it listens on a wildcard, the node addresses are used instead. '
              + 'The panel does not store this address, so change it in the PowerDNS configuration.';
        // Show the hint when empty too: it explains why.
        if (!eps.length) return '<span class="text-warn">PowerDNS is not reachable from outside</span>'
                              + helpDot('catsrc', why);
        return '<span class="mono">' + esc(eps.map(function (e) { return e.address + ':' + e.port; }).join(', ')) + '</span>'
             + helpDot('catsrc', why);
    }
    function catSubtabs(c) {
        return '<div class="dist-tabs cat-subtabs">'
            + '<button class="dist-tab' + (CTAB === 'zones' ? ' active' : '') + '" data-ctab="zones">Zones</button>'
            + '<button class="dist-tab' + (CTAB === 'servers' ? ' active' : '') + '" data-ctab="servers">Servers</button></div>';
    }
    function catZonesTab(c) {
        var aid = +c.catalog_id;
        // Shows only what the catalog contains; Direct AXFR is a zone property and lives in zone settings.
        var rows = catShownZones(c).map(function (did) {
            var z = zoneById(did), nm = z ? z.zone : ('#' + did);
            return '<tr><td class="mono">' + esc(nm) + '</td>'
                + '<td>' + (z ? '<span class="chip">' + esc(z.kind || '') + '</span>' : '') + '</td>'
                + '<td class="right"><a href="#" class="link" data-cat-zone-rm="' + did + '">Remove from catalog</a></td></tr>';
        }).join('') || '<tr><td colspan="3" class="text-dim" style="padding:1rem;">'
                     + 'No zones in this catalog yet \u2014 click <b>Add zones</b>.</td></tr>';
        // Membership applies immediately on Save/Remove, so there is no Apply step.
        return '<div class="cat-tabc"><div class="cat-tabc-head"><span>Zones</span>'
            + '<button class="btn btn-primary sm" data-cat-zones-add="' + aid + '">+ Add zones</button></div>'
            + '<div class="table-wrap"><table class="data-table"><thead><tr><th>Zone</th><th>Kind</th><th class="right">Actions</th></tr></thead><tbody>' + rows + '</tbody></table></div></div>';
    }
    // Subscriber statuses load on demand: they are DNS observations, not needed for the first paint.
    var CCONS = {};   // catalog_id → { state:'loading'|'loaded'|'error', list, err }
    function catConsumers(aid) { var p = CCONS[+aid]; return (p && p.state === 'loaded') ? p.list : null; }
    async function loadCatConsumers(aid) {
        try { var res = await api('catalogs/' + aid, 'GET');
              CCONS[+aid] = { state: 'loaded', list: (res && res.data && res.data.consumers) || [] }; }
        catch (e) { CCONS[+aid] = { state: 'error', err: (e && e.message) || 'request failed' }; }
        render();
    }
    function isConnected(cs) { var s = cs.subscription; return !!(s && s.verified && s.observed_state === 'subscribed'); }
    // Status is purely a DNS observation (the panel does not configure BIND).
    function consumerStatus(cs) {
        if (cs.blockers && cs.blockers.length) return { label: 'Blocked: ' + cs.blockers[0], cls: 'blk' };
        var s = cs.subscription;
        if (!s || !s.observed_state || s.observed_state === 'unknown') return { label: 'Not checked', cls: 'muted', at: s && s.observed_at };
        var st = s.observed_state;
        if (st === 'subscribed')   return { label: 'Synced', cls: 'ok', at: s.observed_at };
        if (st === 'lagging')      return { label: 'Lagging' + (s.observed_serial ? ' (serial ' + s.observed_serial + ')' : ''), cls: 'warn', at: s.observed_at };
        if (st === 'unsubscribed') return { label: 'Not found', cls: 'muted', at: s.observed_at };
        // 'error': refine by last_error
        var le = s.last_error || '';
        if (/producer unavailable/i.test(le))       return { label: 'Producer unavailable', cls: 'err', at: s.observed_at };
        if (/serial mismatch/i.test(le))            return { label: 'Serial mismatch', cls: 'err', at: s.observed_at };
        if (/unreachable|no dns response/i.test(le)) return { label: 'Unreachable', cls: 'err', at: s.observed_at };
        return { label: 'Error' + (le ? ': ' + le : ''), cls: 'err', at: s.observed_at };
    }
    function consumerAuth(cs) {
        if ((cs.auth_mode || 'none') === 'tsig_only') { var g = cs.auth_group_id ? byId(DATA.groups, cs.auth_group_id) : null; return 'TSIG' + (g ? ' · ' + esc(g.name) : ''); }
        if ((cs.auth_mode || 'none') === 'ip_only') return 'IP ACL';
        return '<span class="text-mute">none</span>';
    }
    // Consumer row: name · IP · description · auth · observed status · last check · [?] [Recheck].
    // NOTIFY shows its source: via group / override / no group.
    function consumerNotify(cs) {
        var n = cs.notify; if (!n) return '<span class="text-mute">—</span>';
        var src = n.source === 'override' ? 'override'
                : n.source === 'none'     ? 'no group'
                : (n.via && n.via.length) ? 'via ' + n.via.join(', ') : 'group';
        return '<span class="' + (n.on ? 'cst cst-ok' : 'text-mute') + '">' + (n.on ? 'On' : 'Off') + '</span>'
             + ' <span class="mini text-mute">· ' + esc(src) + '</span>';
    }
    function consumerRow(aid, cs, extra) {
        var s = byId(DATA.servers, cs.node_id);
        var st = consumerStatus(cs);
        var last = st.at ? '<span class="lc-time" data-utc="' + esc(st.at) + '"></span>' : '<span class="text-mute">—</span>';
        var acts = '<span class="cat-srv-acts">'
                 + '<button class="icon-btn sm" data-sub-open="' + cs.node_id + '" data-aud="' + aid + '" data-tip="BIND configuration">?</button>'
                 + '<button class="btn sm" data-sub-recheck="' + cs.node_id + '" data-aud="' + aid + '">Recheck</button>' + (extra || '') + '</span>';
        return '<tr class="cat-srv-row"><td>' + esc(cs.name) + '</td><td class="mono">' + esc((s && s.ip) || '—') + '</td>'
            + '<td>' + esc((s && s.description) || '') + '</td><td class="mini">' + consumerAuth(cs) + '</td>'
            + '<td class="mini nowrap">' + consumerNotify(cs) + '</td>'
            + '<td><span class="cst cst-' + st.cls + '">' + esc(st.label) + '</span></td><td class="mini text-mute">' + last + '</td>'
            + '<td class="right">' + acts + '</td></tr>';
    }
    function catServersTab(c) {
        var aid = +c.catalog_id, cons = catConsumers(aid);
        // Loaded when the tab is first shown; the load re-renders once, so this runs a single time.
        if (!CCONS[aid]) { CCONS[aid] = { state: 'loading' }; loadCatConsumers(aid); }
        var consErr = (CCONS[aid].state === 'error') ? 'Status unavailable: ' + CCONS[aid].err : '';
        var pending = consErr ? '<span class="text-dim mini">' + esc(consErr) + '</span>' : '<span class="text-dim mini">Loading…</span>';
        var byGroup = {}, directById = {};
        if (cons) cons.forEach(function (cs) {
            (cs.group_ids || []).forEach(function (gid) { (byGroup[gid] = byGroup[gid] || []).push(cs); });
            if (cs.direct) directById[+cs.node_id] = cs;
        });
        var NC = 8;   // must match the header column count, or the group row's action lands in the wrong column
        var loadingRow = '<tr><td colspan="' + NC + '" class="text-dim mini" style="padding:.4rem 1rem;">' + (consErr ? esc(consErr) : 'Loading status…') + '</td></tr>';
        var connCount = function (list) { return list.filter(isConnected).length; };
        var head = '<thead><tr><th>Server</th><th>IP</th><th>Description</th><th>Authorization</th><th>Zone NOTIFY</th><th>Catalog status</th><th>Last check</th><th class="right">Action</th></tr></thead>';
        // Groups: aggregate row "name · description · X/Y connected" + expand. A server in two groups shows in both.
        var grows = (c.group_ids || []).map(function (gid) {
            var g = byId(DATA.groups, gid), nm = g ? g.name : ('#' + gid), list = byGroup[gid] || [];
            var open = !!CEXP[aid + ':' + gid];
            var meta = [];
            if (g && g.description) meta.push(esc(g.description));
            meta.push(cons ? (connCount(list) + '/' + list.length + ' connected') : ((g ? (g.node_count || 0) : 0) + ' servers'));
            var headRow = '<tr class="grp-head"><td colspan="' + (NC - 1) + '"><a href="#" class="grp-toggle" data-cat-grp-toggle="' + gid + '" data-aud="' + aid + '"><span class="caret">' + (open ? '▾' : '▸') + '</span> <b>' + esc(nm) + '</b></a> <span class="text-dim mini">· ' + meta.join(' · ') + '</span></td>'
                + '<td class="right"><a href="#" class="link" data-cat-group-rm="' + gid + '" style="color:var(--danger)">Remove group</a></td></tr>';
            var body = '';
            if (open) {
                if (!cons) body = loadingRow;
                else if (!list.length) body = '<tr><td colspan="' + NC + '" class="text-dim mini" style="padding:.4rem 1rem;">No servers in this group.</td></tr>';
                else body = list.map(function (cs) { return consumerRow(aid, cs); }).join('');
            }
            return headRow + body;
        }).join('') || '<tr><td colspan="' + NC + '" class="text-dim" style="padding:.8rem 1rem;">No groups assigned — click <b>Add groups</b>.</td></tr>';
        var groups = '<div class="cat-tabc-head"><span>Server groups</span>'
            + '<span class="cat-tabc-acts"><button class="btn btn-ghost sm" data-cat-nodes-add="' + aid + '">+ Add servers</button>'
            + '<button class="btn btn-primary sm" data-cat-groups-add="' + aid + '">+ Add groups</button></span></div>'
            + '<div class="table-wrap"><table class="data-table cat-srv-table">' + head + '<tbody>' + grows + '</tbody></table></div>';
        // Direct servers block only when there are direct assignments.
        var individual = '';
        if ((c.node_ids || []).length) {
            var irows = (c.node_ids || []).map(function (nid) {
                var rm = ' <a href="#" class="link" data-cat-node-rm="' + nid + '" style="color:var(--danger)">Remove assignment</a>';
                var cs = cons ? directById[+nid] : null;
                if (cs) return consumerRow(aid, cs, rm);
                var s = byId(DATA.servers, nid);
                return '<tr class="cat-srv-row"><td>' + esc(s ? s.name : ('#' + nid)) + '</td><td class="mono">' + esc((s && s.ip) || '—') + '</td><td>' + esc((s && s.description) || '') + '</td><td colspan="4">' + (cons ? '<span class="text-mute">—</span>' : pending) + '</td><td class="right">' + rm + '</td></tr>';
            }).join('');
            individual = '<div class="cat-tabc-head" style="margin-top:1.2rem;"><span>Direct servers</span></div>'
                + '<div class="table-wrap"><table class="data-table cat-srv-table">' + head + '<tbody>' + irows + '</tbody></table></div>';
        }
        return '<div class="cat-tabc">' + groups + individual + '</div>';
    }

    // ---- catalog picker modal (zones / groups). Save reads checkbox state from the DOM; zone search filters in place. ----
    function renderCatModal() {
        var ov = document.getElementById('prop-cat-modal');
        if (!CMODAL) { if (ov) ov.remove(); return; }
        closeCatMenus();   // don't leave the ⋯ menu open behind the overlay
        var c = catById(CMODAL.aid);
        if (!c) { CMODAL = null; if (ov) ov.remove(); return; }
        if (!ov) { ov = document.createElement('div'); ov.id = 'prop-cat-modal'; ov.className = 'dm-overlay'; document.body.appendChild(ov); }
        var isZones = CMODAL.kind === 'zones', isNodes = CMODAL.kind === 'servers';
        var title = (isZones ? 'Add zones — ' : isNodes ? 'Add servers — ' : 'Add groups — ') + esc(c.name)
                  + (isZones ? helpDot('pick', pickHelpText(c)) : '');
        var body = isZones ? zonePickBody(c) : isNodes ? nodePickBody(c) : groupPickBody(c);
        ov.innerHTML = '<div class="dm-panel wide' + (isZones ? ' zone-picker' : '') + '" role="dialog" aria-modal="true">'
            + '<div class="dm-head"><div class="dm-title">' + title + '</div><button class="icon-btn" data-cat-modal-close aria-label="Close">×</button></div>'
            + '<div class="dm-body">' + body + '</div>'
            + '<div class="dm-foot"><button class="btn btn-ghost" data-cat-modal-close>Cancel</button>'
            + '<button class="btn btn-primary" data-cat-modal-save' + (CMODAL.busy ? ' disabled' : '') + '>'
            + (CMODAL.busy ? CMODAL.busy : (isZones ? 'Save zones' : isNodes ? 'Save servers' : 'Save groups')) + '</button></div></div>';
        if (isZones) {
            updateZbulk();   // counter + tri-state select-all
            if (!CMODAL.focused) { var f = ov.querySelector('[data-zsearch]'); if (f) { try { f.focus(); } catch (e) {} CMODAL.focused = true; } }   // focus search once, not on every filter re-render
        }
    }
    // ---- zone chooser: search + Kind/Labels/Show filters + sort + tri-state select-all ----
    var Z_KIND  = [['', 'any'], ['forward', 'forward'], ['reverse', 'reverse']];
    var LSEP = '';
    function zAllLabels() {
        var seen = {}, out = [];
        (DATA.all_zones || []).forEach(function (r) { (r.labels || []).forEach(function (l) {
            var key = l.slug + LSEP + l.value; if (!seen[key]) { seen[key] = 1; out.push({ key: key, label: (l.category || l.slug) + ': ' + l.value }); } }); });
        out.sort(function (a, b) { return a.label < b.label ? -1 : (a.label > b.label ? 1 : 0); });
        return out;
    }
    // Zone table cells shared by every zone-list screen, following the Zones page's classes and wording, so
    // the same list looks the same everywhere.
    var Z_ROLE = { SLAVE: 'Secondary', NATIVE: 'Native' };
    function zTypeClass(t) { t = String(t || '').toLowerCase(); return t === 'slave' ? 'slave' : t === 'native' ? 'native' : 'master'; }
    function zRoleLabel(t) { return Z_ROLE[String(t || '').toUpperCase()] || 'Primary'; }
    function zNameCell(r, extra) {
        var k = String(r.kindx || r.kind || '');
        var rev = k === 'reverse6' ? ' <span class="badge kind-rev">REVERSE&nbsp;v6</span>'
                : /^reverse/.test(k) ? ' <span class="badge kind-rev">REVERSE</span>' : '';
        return '<td class="zone-name">' + esc(r.zone) + rev + (extra || '') + '</td>';
    }
    function zTypeCell(r) {
        return '<td><span class="badge ' + zTypeClass(r.type) + '" data-tip="' + esc(r.type || '') + '">'
             + zRoleLabel(r.type) + '</span></td>';
    }
    function zoneLabelChips(r) {
        var labs = r.labels || []; if (!labs.length) return '<span class="text-mute">—</span>';
        var html = labs.slice(0, 3).map(function (l) { return '<span class="lbl-tag"' + (l.color ? ' style="--c:' + esc(l.color) + '"' : '') + '>' + esc(l.value) + '</span>'; }).join('');
        if (labs.length > 3) html += '<span class="lbl-more">+' + (labs.length - 3) + '</span>';
        return html;
    }
    function zFilterOpts(name) {
        if (name === 'mKind')  return Z_KIND;
        if (name === 'mLabel') return [['', 'all']].concat(zAllLabels().map(function (o) { return [o.key, o.label]; }));
        // Same "Show" filter, labelled per screen: catalog membership vs. direct AXFR allowed.
        if (name === 'mShow')  return (zst() === DX)
            ? [['all', 'All'], ['in', 'Allow'], ['out', 'None']]
            : [['all', 'All'], ['in', 'In catalog'], ['out', 'Not in catalog']];
        return [];
    }
    function zFilter(name, prefix) {
        var st0 = zst();
        var opts = zFilterOpts(name), cur = st0[name] || '';
        var curLabel = cur; for (var i = 0; i < opts.length; i++) if (opts[i][0] === cur) { curLabel = opts[i][1]; break; }
        var menu = (st0.menu === name)
            ? '<div class="filter-menu">' + opts.map(function (o) { return '<div class="filter-opt' + (o[0] === cur ? ' sel' : '') + '" data-zval="' + esc(o[0]) + '" data-zfor="' + name + '">' + esc(o[1]) + '</div>'; }).join('') + '</div>' : '';
        return '<span class="filter-wrap' + (st0.menu === name ? ' open' : '') + '"><button class="filter" type="button" data-zfilter="' + name + '">' + (prefix ? esc(prefix) + ': ' : '') + esc(curLabel) + ' ▾</button>' + menu + '</span>';
    }
    function zSort(list) {
        var k = zst().sort.k, d = zst().sort.d;
        return list.slice().sort(function (x, y) { var a, b;
            if (k === 'labels') { a = ((x.labels || [])[0] || {}).value || ''; b = ((y.labels || [])[0] || {}).value || ''; }
            else { a = String(x[k] == null ? '' : x[k]); b = String(y[k] == null ? '' : y[k]); }
            return a < b ? -d : (a > b ? d : 0); });
    }
    function zRows() {
        var st = zst();
        var s = (st.search || '').toLowerCase(), lparts = st.mLabel ? st.mLabel.split(LSEP) : null;
        var rows = (DATA.all_zones || []).filter(function (r) {
            if (st.mKind && r.kind !== st.mKind) return false;
            if (lparts && !(r.labels || []).some(function (l) { return l.slug === lparts[0] && l.value === lparts[1]; })) return false;
            // Only primary zones can be in a catalog (PowerDNS limitation); offering others suggests an action that
            // never happens.
            if (st.onlyMaster && String(r.type || '').toUpperCase() !== 'MASTER') return false;
            // "Included": the picker's tick, or on the tab whether direct AXFR is allowed.
            var inc = st.isOn ? st.isOn(+r.domain_id) : !!st.includes[+r.domain_id];
            if (st.mShow === 'in' && !inc) return false;
            if (st.mShow === 'out' && inc) return false;
            if (s && String(r.zone).toLowerCase().indexOf(s) < 0) return false;
            return true;
        });
        return zSort(rows);
    }
    // Ticked rows: in the catalog picker they are the answer (ticked = in catalog); on Direct AXFR just a bulk
    // selection. Different stores, shared counter and select-all.
    function zSelSet() { var st = zst(); return st.includes || st.sel; }
    function zCount() { var set = zSelSet(); return Object.keys(set).filter(function (k) { return set[k]; }).length; }
    // Show progress during bulk actions: silence between click and prompt led to repeat clicks.
    function zbulkText() { return DX.busy ? DX.busy : (zCount() + ' selected'); }
    function updateZbulk() {
        var el = document.querySelector('.zbulk'); if (el) el.textContent = zbulkText();
        var list = zRows(), set = zSelSet(), sv = list.filter(function (r) { return set[+r.domain_id]; }).length;
        var all = document.querySelector('[data-zselall]');
        if (all) { all.checked = list.length > 0 && sv === list.length; all.indeterminate = sv > 0 && sv < list.length; }
        var bulk = document.querySelectorAll('[data-dx-bulk]');
        for (var i = 0; i < bulk.length; i++) bulk[i].disabled = (zCount() === 0) || !!DX.busy;
    }
    function zBody(list, c) {
        if (!list.length) return '<tr><td class="zpick-msg" colspan="' + (CMODAL.onlyMaster ? 4 : 5) + '">No zones match the filters.</td></tr>';
        var set = CMODAL.includes;
        return list.map(function (r) {
            var owner = catalogOfZone(r.domain_id), other = (owner && +owner.catalog_id !== +c.catalog_id) ? owner : null;
            return '<tr><td class="th-check"><input type="checkbox" data-zpick data-domain="' + r.domain_id + '"'
                + (set[+r.domain_id] ? ' checked' : '') + '></td>'
                + zNameCell(r, other ? ' <span class="mini text-mute">\u00b7 in ' + esc(other.name) + '</span>' : '')
                + '<td class="c-labels">' + zoneLabelChips(r) + '</td>'
                + (CMODAL.onlyMaster ? '' : zTypeCell(r)) + '</tr>';
        }).join('');
    }
    function rebuildZbody() {   // re-render only the body so the search input keeps focus
        var tb = document.querySelector('#zpick-body');
        if (tb) { tb.innerHTML = zBody(zRows(), catById(CMODAL.aid)); updateZbulk(); return; }
        tb = document.querySelector('#dx-body');
        if (tb) { tb.innerHTML = dxBody(zRows()); updateZbulk(); }
    }
    // The hint must describe exactly what the tick does here: unticking removes from the catalog and leaves
    // Direct AXFR alone.
    function pickHelpText(c) {
        return 'Tick a zone to announce it in ' + esc(c.fqdn) + ' (primary zones only); unticking removes it '
             + 'from the catalog. Direct AXFR is not affected \u2014 it is a separate list on its own tab.'
             + ' A zone belongs to one catalog at a time \u2014 ticking it here moves it out of any other.';
    }
    function zonePickBody(c) {
        function th(k, label) { var arr = CMODAL.sort.k === k ? (CMODAL.sort.d === 1 ? ' ↑' : ' ↓') : ''; return '<th class="th-sort' + (CMODAL.sort.k === k ? ' sorted' : '') + '" data-zsort="' + k + '">' + label + arr + '</th>'; }
        return '<div class="toolbar zpick-toolbar"><div class="search"><svg class="ic" viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/></svg><input placeholder="Search zones…" data-zsearch value="' + esc(CMODAL.search || '') + '"></div>'
              + zFilter('mKind', 'Kind') + zFilter('mLabel', 'Labels') + zFilter('mShow', 'Show')
              + '<span class="zbulk">' + zbulkText() + '</span></div>'
            + '<div class="table-wrap zpick-wrap"><table class="data-table zpick-table"><thead><tr>'
              + '<th class="th-check"><input type="checkbox" data-zselall="1" aria-label="Select / clear all shown"></th>'
              + th('zone', 'Zone') + th('labels', 'Labels')
              + (CMODAL.onlyMaster ? '' : th('type', 'Type'))   // catalog zones all share one type: no column
              + '</tr></thead>'
              + '<tbody id="zpick-body">' + zBody(zRows(), c) + '</tbody></table></div>';
    }
    // Servers assigned to the catalog by themselves, not through a group (the same assignment as the catalog
    // field of a server on the Servers tab).
    function nodePickBody(c) {
        var cur = {}; (c.node_ids || []).forEach(function (x) { cur[+x] = 1; });
        var rows = (DATA.servers || []).map(function (s) {
            return '<label class="pick-row"><input type="checkbox" data-npick="' + s.id + '"' + (cur[+s.id] ? ' checked' : '') + '>'
                + '<span class="pick-main">' + esc(s.name) + '</span>'
                + '<span class="pick-meta mono">' + esc(s.ip || '') + '</span></label>';
        }).join('') || '<p class="text-dim">No servers exist yet. Add them on the Servers tab.</p>';
        return '<p class="dm-hint">Select the servers that receive this catalog by themselves, outside any group.</p><div class="pick-list">' + rows + '</div>';
    }
    async function catNodesSave() {
        var c = catById(CMODAL.aid); if (!c) return;
        var ov = document.getElementById('prop-cat-modal'); if (!ov) return;
        var aid = +c.catalog_id;
        var boxes = Array.prototype.slice.call(ov.querySelectorAll('[data-npick]'));
        for (var i = 0; i < boxes.length; i++) {
            var nid = +boxes[i].getAttribute('data-npick'), s = byId(DATA.servers, nid); if (!s) continue;
            var has = (s.catalog_ids || []).map(Number).indexOf(aid) >= 0;
            if (has === boxes[i].checked) continue;
            var cids = (s.catalog_ids || []).map(Number).filter(function (x) { return x !== aid; });
            if (boxes[i].checked) cids.push(aid);
            await api('secondary/servers/' + nid + '/catalogs', 'PUT', { catalog_ids: cids });
            s.catalog_ids = cids; syncServerCatalogsLocal(nid, cids);
        }
        delete CCONS[aid];
        CMODAL = null; renderCatModal(); render();
    }
    function groupPickBody(c) {
        var cur = {}; (c.group_ids || []).forEach(function (g) { cur[+g] = 1; });
        var rows = (DATA.groups || []).map(function (g) {
            var nc = g.node_count || 0;
            return '<label class="pick-row"><input type="checkbox" data-gpick="' + g.id + '"' + (cur[+g.id] ? ' checked' : '') + '>'
                + '<span class="pick-main">' + esc(g.name) + '</span>'
                + '<span class="pick-meta">' + groupStatusPill(g) + ' · ' + nc + ' server' + (nc === 1 ? '' : 's') + '</span></label>';
        }).join('') || '<p class="text-dim">No groups exist yet. Create groups from the Servers tab → Manage groups.</p>';
        return '<p class="dm-hint">Select which server groups receive this distribution’s zones.</p><div class="pick-list">' + rows + '</div>';
    }

    // ---- delivery changes (optimistic: local DATA + render; errors surface via fail()) ----
    // Local state comes from what the server returned, for both lists: the response is the zone's
    // post-change state ({direct, catalog_id}), so the screen matches a reload.
    function applyDeliveryLocal(did, data) {
        did = +did;
        directLocal(did, !!(data && data.direct));
        var aid = (data && data.catalog_id) ? +data.catalog_id : null;
        (DATA.catalogs || []).forEach(function (c) {
            c.zone_ids         = (c.zone_ids         || []).filter(function (x) { return +x !== did; });

        });
        if (aid) {
            var c = catById(aid);
            if (c) {
                (c.zone_ids = c.zone_ids || []).push(did);

            }
        }
    }
    async function catNewSave() {
        var d = CNEW || {}, name = (d.name || '').trim(), fqdn = (d.fqdn || '').trim();
        if (!name) { window.DNSPanel.alert({ message: 'Name is required.' }); return; }
        if (d.busy) return;
        d.busy = 1; render();
        var res;
        if (!fqdn) { window.DNSPanel.alert({ message: 'Catalog zone (FQDN) is required.' }); return; }
        try { res = await api('catalogs', 'POST', { name: name, fqdn: fqdn, group_ids: [] }); }
        catch (e) { d.busy = 0; render(); throw e; }
        var id = res && res.data && res.data.id;
        if (!id) { d.busy = 0; render(); window.DNSPanel.alert({ message: 'Created, but the panel got no id back.' }); return; }
        (DATA.catalogs = DATA.catalogs || []).push({ catalog_id: +id, name: name,
            fqdn: (res.data.fqdn || fqdn), provisioned: res.data.provisioned ? 1 : 0,
            last_error: res.data.last_error, group_ids: [], node_ids: [], zone_ids: [] });
        CSEL = +id; CTAB = 'zones'; CNEW = null;
        if (res.data.policy_warning) window.DNSPanel.alert({ message: 'Catalog created, but policy was not applied: ' + res.data.policy_warning });
        render();
    }
    async function catHeadSave(aid) {
        var h = CHEAD; if (!h) return;
        var name = (h.name || '').trim(); if (!name) { window.DNSPanel.alert({ message: 'Name is required.' }); return; }
        await api('catalogs/' + aid, 'PATCH', { name: name });
        var c = catById(aid); if (c) { c.name = name; }
        var fqdn = (h.fqdn || '').trim();
        if (fqdn && fqdn !== ((c && c.fqdn) || '')) {
            try { var res = await api('catalogs/' + aid, 'PATCH', { fqdn: fqdn }); applyCatLocal(aid, res && res.data); }
            catch (e) { CHEAD = null; render(); fail(e); return; }
        }
        CHEAD = null; render();
    }
    // Delete: zones leave the catalog and the producer zone is removed from PowerDNS. Ask first, stating the
    // zone count, then DELETE with ?confirm=1.
    async function catDelete(aid) {
        var c = catById(aid); if (!c) return;
        var nz = catShownZones(c).length;
        var msg = nz
            ? '<div>' + nz + ' zone(s) will stop being announced in <b>' + esc(c.fqdn) + '</b>.</div>'
              + '<div style="margin-top:.4rem;">Direct AXFR is a separate list and is not affected.</div>'
            : '<div>The catalog is empty.</div>';
        if (c.provisioned) msg += '<div style="margin-top:.4rem;">The catalog zone <b>' + esc(c.fqdn)
                                + '</b> will be deleted from PowerDNS, and its subscribers will drop the zones it announced.</div>';
        if (!(await window.DNSPanel.confirm({ title: 'Delete ' + (c.name || 'catalog') + '?',
                                              message: msg, okText: 'Delete', danger: true }))) return;
        try { await api('catalogs/' + aid + '?confirm=1', 'DELETE'); }
        catch (e) { fail(e); return; }
        DATA.catalogs = (DATA.catalogs || []).filter(function (x) { return +x.catalog_id !== +aid; });
        if (+CSEL === +aid) CSEL = null;
        render();
    }
    async function catZonesSave() {
        var c = catById(CMODAL.aid); if (!c) return;
        if (CMODAL.busy) return;                   // repeated Save while work is in progress
        var setSaving = function (t) {
            if (CMODAL) CMODAL.busy = t || null;
            document.body.style.cursor = t ? 'progress' : '';
            renderCatModal();
        };
        // Each changed zone goes through the same per-zone route as Manage Zone (consequences, confirmation,
        // catalog membership); no bulk bypass.
        var want = CMODAL.includes || {};
        // A tick means "in THIS catalog": compare with the catalog's contents at open time.
        var picked = {}; Object.keys(want).forEach(function (k) { if (want[k]) picked[+k] = 1; });
        var wasTicked = {}; catShownZones(c).forEach(function (d) { wasTicked[+d] = 1; });
        var toPin  = Object.keys(picked).map(Number).filter(function (d) { return !wasTicked[d]; });
        var toAuto = Object.keys(wasTicked).map(Number).filter(function (d) { return !picked[d]; });
        if (!toPin.length && !toAuto.length) { CMODAL = null; renderCatModal(); render(); return; }

        // Busy from the first click: the consequence check and the writes both hit the network, and otherwise
        // Save looks dead and gets clicked again.
        setSaving('Checking\u2026');
        var okAll;
        try { okAll = toAuto.length ? await window.DNSPanel.confirmStopServing(toAuto, 'in this catalog') : true; }
        catch (e) { setSaving(null); throw e; }
        if (!okAll) { setSaving(null); return; }

        var failed = [], done = 0, total = toPin.length + toAuto.length;
        // The tick controls catalog membership only; Direct AXFR is a separate list.
        var applyOne = async function (did, inCat) {
            setSaving('Applying ' + (++done) + ' of ' + total + '\u2026');
            try {
                var r = await api('zones/' + did + '/catalog', 'PUT', { catalog_id: inCat ? +c.catalog_id : null });
                applyDeliveryLocal(+did, (r && r.data) || {});
            } catch (e) { failed.push('zone ' + did + ': ' + ((e && e.message) || 'failed')); }
        };
        for (var i = 0; i < toPin.length;  i++) await applyOne(toPin[i],  true);
        for (var j = 0; j < toAuto.length; j++) await applyOne(toAuto[j], false);
        document.body.style.cursor = '';

CMODAL = null; renderCatModal(); render();
        if (failed.length) window.DNSPanel.alert({ message: 'Some zones were not applied: ' + failed.join('; ') });
    }
    async function catGroupsSave() {
        var c = catById(CMODAL.aid); if (!c) return;
        var ov = document.getElementById('prop-cat-modal'); if (!ov) return;
        var want = []; ov.querySelectorAll('[data-gpick]:checked').forEach(function (cb) { want.push(+cb.getAttribute('data-gpick')); });
        await api('catalogs/' + c.catalog_id + '/groups', 'PUT', { group_ids: want });
        c.group_ids = want; delete CCONS[+c.catalog_id];
        CMODAL = null; renderCatModal(); render();
    }
    async function catZoneRemove(did) {
        var c = CSEL ? catById(CSEL) : null; if (!c) return;
        // Removes from the catalog only: the zone stops being announced, Direct AXFR stays (toggled in the
        // zone's settings).
        var ok = await window.DNSPanel.confirmStopServing([+did], 'in this catalog');
        if (!ok) return;
        try {
            var r = await api('zones/' + did + '/catalog', 'PUT', { catalog_id: null });
            applyDeliveryLocal(+did, (r && r.data) || {});
        } catch (e) { window.DNSPanel.alert({ title: 'Zone not changed', message: (e && e.message) || 'Failed to change assignment' }); return; }
        render();
    }
    async function catGroupRemove(gid) {
        var c = CSEL ? catById(CSEL) : null; if (!c) return;
        var want = (c.group_ids || []).filter(function (x) { return +x !== +gid; });
        await api('catalogs/' + c.catalog_id + '/groups', 'PUT', { group_ids: want });
        c.group_ids = want; delete CCONS[+c.catalog_id];
        render();
    }
    async function catNodeRemove(nid) {
        var c = CSEL ? catById(CSEL) : null; if (!c) return;
        var aid = +c.catalog_id;
        await api('catalogs/' + aid + '/nodes/' + nid, 'DELETE');
        c.node_ids = (c.node_ids || []).filter(function (x) { return +x !== +nid; });
        var s = byId(DATA.servers, nid); if (s) s.catalog_ids = (s.catalog_ids || []).filter(function (x) { return +x !== aid; });
        delete CCONS[aid];
        render();
    }

    // ---------- Direct AXFR: which zones leave by plain transfer ----------
    // Separate from the catalog, which only announces primary zones; data goes by the same AXFR either way.
    // Binary per zone: recipients come from the Servers inventory, and a listed zone goes to every permitted
    // server. Edited inline, often in bulk.
    function directOn(did) { return (DATA.direct_zone_ids || []).indexOf(+did) >= 0; }
    function directLocal(did, on) {
        did = +did;
        var l = DATA.direct_zone_ids = (DATA.direct_zone_ids || []).filter(function (x) { return +x !== did; });
        if (on) l.push(did);
    }
    // Row: bulk selection + compact Allow/None radio. No "not distributable" branch: NATIVE and catalog zones
    // never reach all_zones (zone_eligible_for_distribution filters them out).
    function dxBody(list) {
        if (!list.length) return '<tr><td class="zpick-msg" colspan="6">No zones match the filters.</td></tr>';
        return list.map(function (r) {
            var did = +r.domain_id, on = directOn(did);
            var radio = function (val, label, checked) {
                return '<label class="chk"><input type="radio" name="dx-' + did + '" value="' + val + '"'
                     + (checked ? ' checked' : '') + '> ' + label + '</label>';
            };
            var ctl = radio('1', 'Allow', on) + radio('', 'None', !on);
            return '<tr><td class="th-check"><input type="checkbox" data-dxsel data-domain="' + did + '"'
                 + (DX.sel[did] ? ' checked' : '') + '></td>'
                 + zNameCell(r)
                 + '<td class="c-labels">' + zoneLabelChips(r) + '</td>' + zTypeCell(r)
                 // display:flex on the <td> itself breaks table layout (the column drifts from its header); the inner
                 // block holds the layout.
                 + '<td class="dx-ctl"><div class="dx-ctl-in">' + ctl + '</div></td></tr>';
        }).join('');
    }
    function directView() {
        DX.isOn = function (did) { return directOn(did); };
        var th = function (k, label) {
            var st = DX.sort, arr = st.k === k ? (st.d === 1 ? ' \u2191' : ' \u2193') : '';
            return '<th class="th-sort' + (st.k === k ? ' sorted' : '') + '" data-zsort="' + k + '">' + label + arr + '</th>';
        };
        var n = zCount();
        var help = 'Allow \u2014 every server that is permitted to take zones from us gets this one directly '
                 + 'by AXFR and gets NOTIFY. Who those servers are is decided on the Servers tab, not here.'
                 + ' Announcing a zone in a catalog is a separate, independent choice made on the Catalog tab: '
                 + 'a zone can be in both lists, in one of them, or in neither.';
        return '<div class="cat-tabc"><div class="cat-tabc-head"><span>Zones' + helpDot('direct', help) + '</span></div>'
             + '<div class="toolbar zpick-toolbar"><div class="search"><svg class="ic" viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/></svg>'
             + '<input placeholder="Search zones…" data-zsearch value="' + esc(DX.search || '') + '"></div>'
             + zFilter('mKind', 'Kind') + zFilter('mLabel', 'Labels') + zFilter('mShow', 'Show')
             + '<span class="zbulk">' + zbulkText() + '</span>'
             // Bulk action mirrors the row control: the same binary question.
             + '<button class="btn btn-ghost sm" data-dx-bulk="1"' + ((n && !DX.busy) ? '' : ' disabled') + '>Allow selected</button>'
             + '<button class="btn btn-ghost sm" data-dx-bulk=""' + ((n && !DX.busy) ? '' : ' disabled') + '>Set to None</button></div>'
             + '<div class="table-wrap"><table class="data-table zpick-table dx-table"><thead><tr>'
             + '<th class="th-check"><input type="checkbox" data-zselall="1" aria-label="Select / clear all shown"></th>'
             + th('zone', 'Zone') + th('labels', 'Labels') + th('type', 'Type')
             + '<th>Direct AXFR</th></tr></thead><tbody id="dx-body">' + dxBody(zRows()) + '</tbody></table></div></div>';
    }
    // Saves immediately. A failure must revert the control and say why, or the screen shows a value the
    // server doesn't have.
    async function directSet(did, on, prevOn) {
        // Revert only when nothing was saved; after a response the row re-renders from the server's state.
        var revert = function () {
            var want = prevOn ? '1' : '';
            var rs = document.querySelectorAll('input[type=radio][name="dx-' + did + '"]');
            for (var i = 0; i < rs.length; i++) rs[i].checked = (String(rs[i].value) === want);
        };
        // Confirm only when turning off (it takes delivery away). The catalog is untouched.
        if (DX.busy) { revert(); return; }
        setBusy('Applying\u2026');
        try {
            var ok = on ? true : await window.DNSPanel.confirmStopServing([+did], 'by direct AXFR');
            if (!ok) { revert(); return; }
            var r;
            try { r = await api('zones/' + did + '/direct-axfr', 'PUT', { on: !!on }); }
            catch (e) {
                // Request failed, so nothing was saved: revert.
                revert();
                window.DNSPanel.alert({ title: 'Direct AXFR not changed', message: (e && e.message) || 'Failed' });
                return;
            }
            var d = (r && r.data) || {};
            (d.zones || []).forEach(function (z) { applyDeliveryLocal(+z.domain_id, z); });
            // Saved but not applied is not "unchanged": the toggle keeps the saved value, and we say applying is
            // deferred instead of asking for a retry.
            if ((d.failed || []).length) {
                var z0 = zoneById(+did);
                window.DNSPanel.alert({
                    title: 'Saved, but not applied to PowerDNS',
                    message: '<div>The choice is saved in the panel and the background sync will keep retrying.</div>'
                           + '<div style="margin-top:.4rem;">' + esc((z0 ? z0.zone : ('zone ' + did))
                           + ' \u2014 ' + (d.failed[0].error || 'failed')) + '</div>' });
            }
        } finally { setBusy(null); }
        render();
    }

    // Bulk apply: enabling is safe; disabling takes delivery away, so confirm with the same preview as per zone.
    async function directBulk(target) {
        if (DX.busy) return;   // buttons are already disabled, but the action can be triggered otherwise
        var ids = Object.keys(DX.sel).filter(function (k) { return DX.sel[k]; }).map(Number);
        if (!ids.length) return;
        var on = !!(target && String(target) === '1');
        // Busy from the first click, before any request.
        setBusy('Checking\u2026');
        try {
            if (!on) {
                var okAll = await window.DNSPanel.confirmStopServing(ids, 'by direct AXFR');
                if (!okAll) return;
            }
            // One request for the whole batch (per-zone requests repeated the shared work N times).
            setBusy('Applying ' + ids.length + ' zone' + (ids.length === 1 ? '' : 's') + '\u2026');
            var res;
            try { res = await api('zones/direct-axfr', 'PUT', { domain_ids: ids, on: on }); }
            catch (e) { window.DNSPanel.alert({ title: 'Zones were not changed', message: (e && e.message) || 'failed' }); return; }
            var d = (res && res.data) || {};
            // Update from the response: it carries every zone's post-change state.
            (d.zones || []).forEach(function (z) { applyDeliveryLocal(+z.domain_id, z); });
            DX.sel = {};
            // "Saved but not applied" differs from "not changed": the choice is saved and the background sync will
            // finish it.
            if ((d.failed || []).length) {
                var names = d.failed.map(function (f) {
                    var z = zoneById(+f.domain_id);
                    return (z ? z.zone : ('zone ' + f.domain_id)) + ' \u2014 ' + (f.error || 'failed');
                });
                window.DNSPanel.alert({
                    title: 'Saved, but not applied to PowerDNS',
                    message: '<div>The choice is saved in the panel and the background sync will keep retrying.</div>'
                           + '<div style="margin-top:.4rem;">' + names.map(esc).join('<br>') + '</div>' });
            }
        } finally { setBusy(null); }
        render();
    }
    // Busy lives in state, not the DOM, so it survives re-renders; the page-wide cursor shows work in progress.
    function setBusy(text) {
        DX.busy = text || null;
        document.body.style.cursor = text ? 'progress' : '';
        var el = document.querySelector('.zbulk'); if (el) el.textContent = zbulkText();
        var bulk = document.querySelectorAll('[data-dx-bulk]');
        for (var i = 0; i < bulk.length; i++) bulk[i].disabled = !!text || (zCount() === 0);
    }

    // Keep ?catalog in the URL in sync with the selection (replaceState: no history entry per click).
    function syncUrl() {
        try {
            var u = new URL(window.location.href);
            if (TAB === 'catalogs' && CSEL && catById(CSEL)) u.searchParams.set('catalog', CSEL);
            else u.searchParams.delete('catalog');
            history.replaceState(history.state, '', u.pathname + u.search + u.hash);
        } catch (e) {}
    }
    function render() {
        var root = document.getElementById('prop-root'); if (!root) return;
        normalizeTab();
        root.innerHTML = tabsHtml() + (TAB === 'servers' ? serversView() : TAB === 'direct' ? directView() : catalogsView());
        localizeTimes(root); saveNav(); syncUrl(); renderSubModal();
    }

    // ---------- Manage groups modal (master-detail: group list left, settings right) ----------
    function groupSideRow(g) {
        var sel = !GM.newG && GM.edit === +g.id;
        return '<button class="gm-side-row' + (sel ? ' selected' : '') + '" data-gm-edit="' + g.id + '">'
            + '<div class="gm-side-name">' + esc(g.name) + '</div>'
            + '<div class="gm-side-sub">' + (g.axfr_auth_mode === 'tsig_only' ? 'TSIG only' : 'IP ACL') + ' · ' + (g.node_count || 0) + ' srv' + ((g.prefixes || []).length ? ' · ' + g.prefixes.length + ' net' : '') + '</div></button>';
    }
    // ---- group editor: group fields in GM.draft; TSIG keys (list + radio) apply immediately ----
    var TK_ALGOS = ['hmac-sha256', 'hmac-sha512', 'hmac-sha384', 'hmac-sha224', 'hmac-sha1', 'hmac-md5'];
    function algoOpts() { return TK_ALGOS.map(function (a) { return { value: a, label: a }; }); }
    function initDraft(g) { GM.draft = { forId: +g.id, name: g.name, description: g.description || '', requireTsig: g.axfr_auth_mode === 'tsig_only', sendNotify: g.send_notify != 0, zoneAxfr: g.zone_axfr != 0, prefixes: (g.prefixes || []).join('\n'), revealed: {}, addOpen: false, addName: '', addAlgo: 'hmac-sha256', addSecret: '' }; }
    function initNewDraft() { GM.draft = { forId: 'new', name: '', description: '', requireTsig: false, sendNotify: true, zoneAxfr: true, prefixes: '' }; }
    function prefixList(t) { return String(t || '').split(/[\s,;]+/).map(function (s) { return s.trim(); }).filter(Boolean); }
    function bindConfig(name, algo, secret) { return 'key "' + name + '" {\n    algorithm ' + algo + ';\n    secret "' + secret + '";\n};\n'; }
    function parseBindKey(t) {
        t = String(t || '');
        var name = (t.match(/key\s+"?([^"\s{]+)"?/i) || [])[1] || '';
        var algo = (t.match(/algorithm\s+"?([a-z0-9-]+)"?/i) || [])[1] || 'hmac-sha256';
        var secret = (t.match(/secret\s+"([^"]+)"/i) || [])[1] || (t.match(/secret\s+([A-Za-z0-9+/=]{8,})/i) || [])[1] || '';
        if (!secret) return null;
        return { name: name, algorithm: algo.toLowerCase(), secret: secret };
    }
    function keyItem(g, k) {
        var d = GM.draft, primary = +k.is_primary === 1;   // keys are immutable (name/algorithm/secret): only Reveal/Copy/Remove and the active choice
        var revealed = d.revealed[k.id] != null;
        var val = revealed ? esc(d.revealed[k.id]) : '••••••••••••••••';
        var acts = canDist()
            ? '<button type="button" class="icon-btn" data-tk-reveal="' + k.id + '" aria-label="' + (revealed ? 'Hide' : 'Show') + '">' + (revealed ? IC_EYEOFF : IC_EYE) + '</button>'
                + '<button type="button" class="icon-btn" data-tk-copy="' + k.id + '" data-tip="Copy BIND config">' + IC_COPY + '</button>'
                + '<a href="#" class="link" data-tk-remove="' + k.id + '" style="color:var(--danger)">Remove</a>'
            : '';
        return '<div class="tk-item' + (primary ? ' active' : '') + '">'
            + '<label class="tk-radio"><input type="radio" name="tk-prim-' + g.id + '" data-tk-primary="' + k.id + '"' + (primary ? ' checked' : '') + (canDist() ? '' : ' disabled') + '></label>'
            + '<div class="tk-body"><div class="tk-head"><b>' + esc(k.name) + '</b> <span class="mini text-mute">' + esc(k.algorithm) + '</span>' + (primary ? ' <span class="badge master">Active</span>' : '') + '</div>'
            + '<div class="tk-secret"><input class="field-input sm mono ts-secret-inp" value="' + val + '" readonly>' + acts + '</div></div></div>';
    }
    function tsigKeysSection(g) {
        var keys = g.tsig_keys || [], d = GM.draft;
        var list = keys.length ? keys.map(function (k) { return keyItem(g, k); }).join('') : '<div class="text-mute" style="padding:.3rem 0;">No TSIG key yet.</div>';
        var add = d.addOpen
            ? '<div class="tk-add"><div class="frow"><label>Name</label><input class="field-input sm" data-add-name value="' + esc(d.addName) + '" placeholder="key name"></div>'
                + '<div class="frow"><label>Algorithm</label>' + uiSelect('tk-add-algo', algoOpts(), d.addAlgo) + '</div>'
                + '<div class="frow"><label>Secret</label><input class="field-input sm mono" data-add-secret value="' + esc(d.addSecret) + '" placeholder="secret"> <a href="#" class="link tsig-act" data-tk-add-gen>Generate</a></div>'
                + '<div class="dsec-act"><button class="btn btn-primary sm" data-tk-add-save>Add</button><a href="#" class="link" data-tk-add-cancel>cancel</a></div></div>'
            : (canDist() ? '<div class="dsec-act tk-addbar"><button class="btn btn-ghost sm" data-tk-add-open>+ Add TSIG key</button><a href="#" class="link sm" data-tk-import>Import from BIND config</a></div>' : '');
        return '<div class="frow frow-tk"><label>TSIG keys</label><div class="tk-block' + (d.requireTsig ? '' : ' dimmed') + '">' + list + add + '</div></div>';
    }
    function groupFields() {
        var d = GM.draft;
        return '<div class="frow"><label>Name</label><input class="field-input" data-gm="name" value="' + esc(d.name) + '" placeholder="group name"></div>'
            + '<div class="frow"><label>Description</label><input class="field-input" data-gm="description" value="' + esc(d.description) + '" placeholder="optional"></div>'
            // The note sits under the control in the same column (.frow-note); positioned beside it, long text
            // overlapped the next row. AXFR states only what the panel controls: whether we let this group
            // transfer zones from our PowerDNS.
            + frowChk('AXFR', 'data-gm-zaxfr', d.zoneAxfr, 'Allow AXFR from PowerDNS',
                      'Off — these servers do not transfer zone data from us; where they take it is their own configuration.')
            + frowChk('NOTIFY', 'data-gm-notify', d.sendNotify, 'Notify these servers when zone data changes',
                      'Default for the group; a server can override it. Catalog changes are announced to everyone regardless.')
            + '<div class="frow"><label>Require TSIG</label><label class="chk"><input type="checkbox" data-gm-req' + (d.requireTsig ? ' checked' : '') + '></label></div>'
            // Networks are part of the IP ACL: with TSIG required they would allow unsigned transfers, so they are off then.
            + '<div class="frow frow-note"><label>Networks</label><div class="frow-col">'
            + '<textarea class="field-input mono" rows="3" data-gm="prefixes" placeholder="35.199.192.0/19"' + (d.requireTsig ? ' disabled' : '') + '>' + esc(d.prefixes || '') + '</textarea>'
            + '<div class="mini text-mute">' + (d.requireTsig ? 'Only for IP ACL (Require TSIG off).' : 'May transfer this group’s zones, besides its servers. No NOTIFY.') + '</div></div></div>';
    }
    function frowChk(label, attr, on, text, note) {
        return '<div class="frow frow-note"><label>' + esc(label) + '</label><div class="frow-col">'
             + '<label class="chk"><input type="checkbox" ' + attr + (on ? ' checked' : '') + '> ' + esc(text) + '</label>'
             + '<div class="mini text-mute">' + esc(note) + '</div></div></div>';
    }
    function groupNewForm() {
        return '<div class="gm-edit">' + groupFields()
            + '<div class="gm-foot end"><button class="btn btn-ghost" data-gm-new-cancel>Cancel</button><button class="btn btn-primary" data-gm-new-save>Create group</button></div></div>';
    }
    function groupEditForm(g) {
        return '<div class="gm-edit" data-gid="' + g.id + '">' + groupFields() + tsigKeysSection(g)
            + '<div class="gm-foot"><button class="btn btn-danger" data-gm-del="' + g.id + '">Delete group</button>'
            + '<button class="btn btn-primary" data-gm-save="' + g.id + '">Save</button></div></div>';
    }
    function groupsModalBody() {
        var rows = (DATA.groups || []).map(groupSideRow).join('') || '<div class="text-mute" style="padding:.6rem;">No groups yet.</div>';
        var side = '<div class="gm-side"><div class="gm-side-head"><span>Groups</span>'
            + (canSec() ? '<button class="btn btn-primary sm" data-gm-new-open>+ New</button>' : '') + '</div>'
            + '<div class="gm-side-list">' + rows + '</div></div>';
        var detail;
        if (GM.newG && canSec()) { if (!GM.draft || GM.draft.forId !== 'new') initNewDraft(); detail = groupNewForm(); }
        else if (GM.edit) { var g = byId(DATA.groups, GM.edit); if (g && (!GM.draft || GM.draft.forId !== +GM.edit)) initDraft(g); detail = g ? groupEditForm(g) : '<div class="gm-empty">This group no longer exists.</div>'; }
        else detail = '<div class="gm-empty">Select a group, or use <b>+ New</b>.</div>';
        return '<div class="gm-split">' + side + '<div class="gm-detail">' + detail + '</div></div>';
    }
    function renderModal() {
        var ov = document.getElementById('prop-modal');
        if (!MODAL) { if (ov) ov.remove(); return; }
        closeCatMenus();   // don't leave the ⋯ menu open behind the overlay
        if (!ov) { ov = document.createElement('div'); ov.id = 'prop-modal'; ov.className = 'dm-overlay'; document.body.appendChild(ov); }
        ov.innerHTML = '<div class="dm-panel wide" role="dialog" aria-modal="true">'
            + '<div class="dm-head"><div class="dm-title">Manage groups</div><button class="icon-btn" data-gm-close aria-label="Close">×</button></div>'
            + '<div class="dm-body">' + groupsModalBody() + '</div>'
            + '<div class="dm-foot"><button class="btn btn-ghost" data-gm-close>Close</button></div></div>';
    }
    function openGroupsModal() { MODAL = { kind: 'groups' }; GM = { edit: (DATA.groups && DATA.groups[0]) ? +DATA.groups[0].id : null, newG: false, draft: null }; renderModal(); }
    function closeModal() { MODAL = null; GM.draft = null; renderModal(); render(); }   // render(): pull group changes into the servers table

    // ---------- history modal ----------
    function histRow(h) {
        var raw = h.ts || '', when = raw ? esc(raw.substring(0, 16)) : '';
        return '<tr><td class="mono lc-time" data-utc="' + esc(raw) + '">' + when + '</td>'
            + '<td>' + esc(h.actor || 'system') + '</td>'
            + '<td>' + esc(ACTION_LABEL[h.action] || h.action || '') + '</td>'
            + '<td>' + (h.detail ? esc(h.detail) : '<span class="text-mute">—</span>') + '</td></tr>';
    }
    function renderHist() {
        var ov = document.getElementById('prop-hist');
        if (!HIST) { if (ov) ov.remove(); return; }
        if (!ov) { ov = document.createElement('div'); ov.id = 'prop-hist'; ov.className = 'dm-overlay'; document.body.appendChild(ov); }
        var body;
        if (HIST.loading) body = '<p class="dm-hint">Loading…</p>';
        else if (HIST.err) body = '<div class="card banner-err"><p style="margin:0;">' + esc(HIST.err) + '</p></div>';
        else if (!(HIST.rows || []).length) body = '<p class="text-dim">No history yet.</p>';
        else body = '<div class="table-wrap"><table class="data-table"><thead><tr><th>When</th><th>Who</th><th>Action</th><th>Detail</th></tr></thead><tbody>'
            + HIST.rows.map(histRow).join('') + '</tbody></table></div>';
        ov.innerHTML = '<div class="dm-panel wide" role="dialog" aria-modal="true">'
            + '<div class="dm-head"><div class="dm-title">History — ' + esc(HIST.name) + '</div><button class="icon-btn" data-hist-close aria-label="Close">×</button></div>'
            + '<div class="dm-body">' + body + '</div>'
            + '<div class="dm-foot"><button class="btn btn-ghost" data-hist-close>Close</button></div></div>';
        localizeTimes(ov);
    }
    async function openHistory(id) {
        var s = byId(DATA.servers, id);
        HIST = { id: id, name: s ? s.name : ('#' + id), loading: true, rows: [] }; renderHist();
        try { var res = await api('secondary/servers/' + id + '/audit', 'GET'); HIST.rows = (res && res.data && res.data.history) || []; HIST.loading = false; }
        catch (e) { HIST.loading = false; HIST.err = (e && e.message) ? e.message : 'Failed to load history'; }
        renderHist();
    }
    function closeHist() { HIST = null; renderHist(); }

    // ---------- personal TSIG modal (per server): multiple keys + active (radio), mirrors group TSIG ----------
    function ntKeyItem(k, hasPersonalPrimary) {
        var primary = +k.is_primary === 1, revealed = NT.revealed[k.id] != null;
        var val = revealed ? esc(NT.revealed[k.id]) : '••••••••••••••••';
        var acts = '<button type="button" class="icon-btn" data-nt-reveal="' + k.id + '" aria-label="' + (revealed ? 'Hide' : 'Show') + '">' + (revealed ? IC_EYEOFF : IC_EYE) + '</button>'
            + '<button type="button" class="icon-btn" data-nt-copy="' + k.id + '" data-tip="Copy BIND config">' + IC_COPY + '</button>'
            + '<a href="#" class="link" data-nt-remove="' + k.id + '" style="color:var(--danger)">Remove</a>';
        return '<div class="tk-item' + (primary ? ' active' : '') + '">'
            + '<label class="tk-radio"><input type="radio" name="nt-src" data-nt-src="personal:' + k.id + '"' + (primary ? ' checked' : '') + '></label>'
            + '<div class="tk-body"><div class="tk-head"><b>' + esc(k.name) + '</b> <span class="mini text-mute">' + esc(k.algorithm) + '</span>' + (primary ? ' <span class="badge master">Active</span>' : '') + '</div>'
            + '<div class="tk-secret"><input class="field-input sm mono ts-secret-inp" value="' + val + '" readonly>' + acts + '</div></div></div>';
    }
    function ntGroupItem(s, g, active) {   // group as auth source (radio in the shared nt-src set); label follows the group's mode
        var isTsig = g.axfr_auth_mode === 'tsig_only', gk = isTsig ? groupPrimaryKey(g) : null;
        var keylbl = isTsig ? (gk ? 'TSIG ' + esc(gk.name) : '<span class="text-mute">TSIG — no key</span>') : '<span class="text-mute">IP ACL</span>';
        return '<label class="tk-item' + (active ? ' active' : '') + '"><span class="tk-radio"><input type="radio" name="nt-src" data-nt-src="group:' + g.id + '"' + (active ? ' checked' : '') + '></span>'
            + '<span class="tk-body"><span class="tk-head"><b>' + esc(g.name) + '</b> <span class="mini text-mute">' + keylbl + '</span>' + (active ? ' <span class="badge master">Active</span>' : '') + '</span></span></label>';
    }
    function ntBody(s) {
        var ab = authBadge(s), pk = nodePrimaryKey(s);
        var grows = (s.groups || []).map(function (gg) { var g = byId(DATA.groups, gg.id); return g ? ntGroupItem(s, g, (!pk && +s.default_group_id === +g.id)) : ''; }).join('')
            || '<div class="text-mute" style="padding:.3rem 0;">This server is in no group. Add it to a group in the Servers table, or give it a personal key below.</div>';
        var pkeys = (s.tsig_keys || []).length ? (s.tsig_keys || []).map(function (k) { return ntKeyItem(k, !!pk); }).join('') : '<div class="text-mute" style="padding:.3rem 0;">No personal key.</div>';
        var add = NT.addOpen
            ? '<div class="tk-add"><div class="frow"><label>Name</label><input class="field-input sm" data-nt-add-name value="' + esc(NT.addName || '') + '"></div>'
                + '<div class="frow"><label>Algorithm</label>' + uiSelect('nt-add-algo', algoOpts(), NT.addAlgo || 'hmac-sha256') + '</div>'
                + '<div class="frow"><label>Secret</label><input class="field-input sm mono" data-nt-add-secret value="' + esc(NT.addSecret || '') + '"> <a href="#" class="link tsig-act" data-nt-add-gen>Generate</a></div>'
                + '<div class="dsec-act"><button class="btn btn-primary sm" data-nt-add-save>Add</button><a href="#" class="link" data-nt-add-cancel>cancel</a></div></div>'
            : '<div class="dsec-act tk-addbar"><button class="btn btn-ghost sm" data-nt-add-open>+ Add TSIG key</button><a href="#" class="link sm" data-nt-import>Import from BIND config</a></div>';
        var why = (((s.effective_auth || {}).issues) || []).join('; ');
        return '<div class="eff-line" style="margin-bottom:.9rem;"><span class="eff-k">Effective authorization</span><span><b>' + esc(ab.label) + '</b></span></div>'
            + (why ? '<p class="dm-hint dm-hint-warn">Missing: ' + esc(why) + '</p>' : '')
            + '<div class="ntsec-h">Authorization source</div>'
            + '<p class="dm-hint">Pick the group that authorizes this server. Only this one group is used for AXFR: its TSIG key, or its IP ACL if the group is set to IP ACL. The server’s other groups decide only which distributions it receives.</p>'
            + '<div class="tk-block">' + grows + '</div>'
            + '<div class="ntsec-h" style="margin-top:1rem;">Personal TSIG key</div>'
            + '<p class="dm-hint">A personal key overrides the group above for this server alone.</p>'
            + '<div class="tk-block">' + pkeys + add + '</div>';
    }
    function renderNtsig() {
        var ov = document.getElementById('prop-ntsig');
        if (!NT) { if (ov) ov.remove(); return; }
        var s = byId(DATA.servers, NT.nodeId);
        if (!s) { NT = null; if (ov) ov.remove(); return; }
        if (!ov) { ov = document.createElement('div'); ov.id = 'prop-ntsig'; ov.className = 'dm-overlay'; document.body.appendChild(ov); }
        ov.innerHTML = '<div class="dm-panel" role="dialog" aria-modal="true">'
            + '<div class="dm-head"><div class="dm-title">AXFR authorization — ' + esc(s.name) + '</div><button class="icon-btn" data-nt-close aria-label="Close">×</button></div>'
            + '<div class="dm-body">' + ntBody(s) + '</div>'
            + '<div class="dm-foot"><button class="btn btn-ghost" data-nt-close>Close</button></div></div>';
    }
    function openNtsig(id) { stashEditRow(id); NT = { nodeId: +id, revealed: {}, addOpen: false, addName: '', addAlgo: 'hmac-sha256', addSecret: '' }; renderNtsig(); }
    function closeNtsig() { NT = null; renderNtsig(); render(); }   // render(): refresh the auth badge in the table
    // Replace the local server with the backend response (authoritative tsig_keys/effective_auth/default_group_id),
    // keeping catalog_ids. Personal TSIG / default group edits are server changes (audit target=secondary_node),
    // so Last change = now / current user.
    function applyServer(res, nid) { var s = res && res.data; if (!s) return null; var old = byId(DATA.servers, nid); s.catalog_ids = old ? (old.catalog_ids || []) : []; s.last_by = DATA.user; s.last_at = utcStamp(); replaceServer(s); return s; }
    function snapAuth(s) { return { dg: s.default_group_id, prim: (s.tsig_keys || []).map(function (k) { return { id: +k.id, p: +k.is_primary }; }), ea: s.effective_auth }; }
    function restoreAuth(s, snap) { s.default_group_id = snap.dg; (s.tsig_keys || []).forEach(function (k) { var f = snap.prim.filter(function (p) { return p.id === +k.id; })[0]; if (f) k.is_primary = f.p; }); s.effective_auth = snap.ea; }
    async function ntAdd(nid) {
        var nm = (NT.addName || '').trim(), sec = (NT.addSecret || '').trim();
        if (!nm) { window.DNSPanel.alert({ message: 'Key name is required.' }); return; }
        if (!sec) { window.DNSPanel.alert({ message: 'Enter a secret or click Generate.' }); return; }
        var res = await api('secondary/servers/' + nid + '/tsig-keys', 'POST', { name: nm, algorithm: NT.addAlgo || 'hmac-sha256', secret: sec });   // backend creates and binds atomically
        applyServer(res, nid); NT.addOpen = false; NT.addName = ''; NT.addSecret = ''; renderNtsig();
    }
    async function ntRemove(nid, kid) {
        if (!(await window.DNSPanel.confirm({ title: 'Remove personal TSIG key', message: 'Remove this key from the server? It will fall back to its group’s TSIG or IP ACL.', okText: 'Remove', danger: true }))) return;
        var res = await api('secondary/servers/' + nid + '/tsig-keys/' + kid, 'DELETE');
        applyServer(res, nid); delete NT.revealed[kid]; renderNtsig();
    }
    async function ntSetPrimary(nid, kid) {   // optimistic radio → authoritative backend response → rollback on error
        var s = byId(DATA.servers, nid); if (!s) return; var snap = snapAuth(s);
        (s.tsig_keys || []).forEach(function (k) { k.is_primary = (+k.id === +kid) ? 1 : 0; }); renderNtsig();
        try { var res = await api('secondary/servers/' + nid + '/tsig-keys/' + kid + '/primary', 'POST'); applyServer(res, nid); renderNtsig(); }
        catch (err) { restoreAuth(s, snap); renderNtsig(); fail(err); }
    }
    async function ntSetGroup(nid, gid) {   // pick the default group as key source (clears the active personal key)
        var s = byId(DATA.servers, nid); if (!s) return; var snap = snapAuth(s);
        s.default_group_id = +gid; (s.tsig_keys || []).forEach(function (k) { k.is_primary = 0; }); renderNtsig();
        try { var res = await api('secondary/servers/' + nid + '/default-group', 'PUT', { group_id: +gid }); applyServer(res, nid); renderNtsig(); }
        catch (err) { restoreAuth(s, snap); renderNtsig(); fail(err); }
    }
    async function ntReveal(kid) {
        if (NT.revealed[kid] != null) { delete NT.revealed[kid]; renderNtsig(); return; }
        var sec = await fetchSecret(kid); if (sec) NT.revealed[kid] = sec.secret; renderNtsig();
    }
    async function ntCopy(nid, kid) {
        var key = (byId(DATA.servers, nid).tsig_keys || []).filter(function (k) { return +k.id === +kid; })[0]; if (!key) return;
        var sec = NT.revealed[kid]; if (sec == null) { var s = await fetchSecret(kid); if (!s) return; sec = s.secret; }
        await copyText(bindConfig(key.name, key.algorithm, sec)); window.DNSPanel.alert({ message: 'BIND key configuration copied to clipboard.' });
    }

    // ---------- mutations ----------
    async function saveServer(id) {
        var row = document.querySelector('tr.editing[data-sid="' + id + '"]'); if (!row) return;
        var name = (row.querySelector('[data-f="name"]').value || '').trim();
        var ip = (row.querySelector('[data-f="ip"]').value || '').trim();
        var desc = (row.querySelector('[data-f="description"]').value || '').trim();
        var en = row.querySelector('[data-f="enabled"]').checked;
        var gids = []; row.querySelectorAll('[data-g]').forEach(function (c) { if (c.checked) gids.push(+c.getAttribute('data-g')); });
        var cids = null;
        if (canCat()) { cids = []; row.querySelectorAll('[data-c]').forEach(function (c) { if (c.checked) cids.push(+c.getAttribute('data-c')); }); }
        if (!name || !ip) { window.DNSPanel.alert({ message: 'Name and IP are required.' }); return; }
        var body = { name: name, ip: ip, description: desc, group_ids: gids, enabled: en };
        if (canDist()) {
            var np = row.querySelector('[data-pf="notify_policy"]:checked'); if (np) body.notify_policy = np.value;
            var ap = row.querySelector('[data-pf="axfr_policy"]:checked');   if (ap) body.axfr_policy   = ap.value;
        }
        var res = await api('secondary/servers/' + id, 'PUT', body);
        var s = res && res.data;
        if (s) {   // apply the response now (incl. effective_auth) so edits show even if the catalogs call fails
            s.last_by = DATA.user; s.last_at = utcStamp();
            var old = byId(DATA.servers, id);
            s.catalog_ids = old ? (old.catalog_ids || []) : [];
            replaceServer(s); EDIT = null; DRAFT = null; render();
        }
        if (s && cids) {   // catalog assignment is a separate call; on failure the server is already applied locally
            await api('secondary/servers/' + id + '/catalogs', 'PUT', { catalog_ids: cids });
            s.catalog_ids = cids; syncServerCatalogsLocal(id, cids); render();
        }
    }
    async function addServer() {
        var root = document.querySelector('.srv-tbl-add'); if (!root) return;
        var name = (root.querySelector('[data-f="name"]').value || '').trim();
        var ip = (root.querySelector('[data-f="ip"]').value || '').trim();
        var desc = (root.querySelector('[data-f="description"]').value || '').trim();
        var gids = []; root.querySelectorAll('[data-g]').forEach(function (c) { if (c.checked) gids.push(+c.getAttribute('data-g')); });
        var cids = []; if (canCat()) root.querySelectorAll('[data-c]').forEach(function (c) { if (c.checked) cids.push(+c.getAttribute('data-c')); });
        if (!name || !ip) { window.DNSPanel.alert({ message: 'Name and IP are required.' }); return; }
        var abody = { name: name, ip: ip, description: desc, group_ids: gids, enabled: true };
        if (canDist()) {
            var np = root.querySelector('[data-pf="notify_policy"]:checked'); if (np) abody.notify_policy = np.value;
            var ap = root.querySelector('[data-pf="axfr_policy"]:checked');   if (ap) abody.axfr_policy   = ap.value;
        }
        var res = await api('secondary/servers', 'POST', abody);
        var s = res && res.data;
        if (s) { s.last_by = DATA.user; s.last_at = utcStamp(); s.catalog_ids = []; (DATA.servers = DATA.servers || []).unshift(s); render(); }   // apply now: if the catalogs call fails, the server is already in the table
        if (s && canCat() && cids.length) { await api('secondary/servers/' + s.id + '/catalogs', 'PUT', { catalog_ids: cids }); s.catalog_ids = cids; syncServerCatalogsLocal(s.id, cids); render(); }
    }
    async function fetchSecret(kid) { var res = await api('secondary/tsig-keys/' + kid + '/secret', 'GET'); return (res && res.data) || null; }
    // Fall back to server truth only on error; otherwise updates are local, without a full refresh.
    async function refreshKeepDraft() { await refresh(); renderModal(); }
    function localGroup(gid) { return byId(DATA.groups, gid); }
    async function gmSave(gid) {   // saves group fields only; keys apply immediately
        var d = GM.draft; if (!d) return;
        var name = (d.name || '').trim(); if (!name) { window.DNSPanel.alert({ message: 'Group name is required.' }); return; }
        var body = { name: name, description: (d.description || '').trim() };
        if (canDist()) { body.axfr_auth_mode = d.requireTsig ? 'tsig_only' : 'ip_only'; body.send_notify = d.sendNotify ? 1 : 0; body.zone_axfr = d.zoneAxfr ? 1 : 0; body.prefixes = prefixList(d.prefixes); }
        var res = await api('secondary/groups/' + gid, 'PATCH', body);
        var g = localGroup(gid); if (g) { g.name = name; g.description = body.description; if (body.axfr_auth_mode) g.axfr_auth_mode = body.axfr_auth_mode; if ('send_notify' in body) g.send_notify = body.send_notify; if ('zone_axfr' in body) g.zone_axfr = body.zone_axfr; if (res && res.data && res.data.prefixes) g.prefixes = res.data.prefixes; }
        (DATA.servers || []).forEach(function (s) { (s.groups || []).forEach(function (x) { if (+x.id === +gid) x.name = name; }); });   // sync group chips on servers
        if (body.axfr_auth_mode) await refreshServers();   // mode change → refresh effective_auth of its default members
        GM.draft = null; if (g) initDraft(g); renderModal();
    }
    async function gmDelGroup(gid) {
        if (!(await window.DNSPanel.confirm({ title: 'Delete group', message: 'Delete this group? Servers are removed from it but not deleted.', okText: 'Delete', danger: true }))) return;
        await api('secondary/groups/' + gid, 'DELETE');
        DATA.groups = (DATA.groups || []).filter(function (x) { return +x.id !== +gid; });
        (DATA.servers || []).forEach(function (s) { s.groups = (s.groups || []).filter(function (x) { return +x.id !== +gid; }); });   // drop the deleted group from servers
        await refreshServers();   // members' default_group_id was nulled (FK SET NULL) → re-read effective_auth
        GM.edit = null; GM.draft = null; renderModal();
    }
    async function gmNewGroup() {
        var d = GM.draft; if (!d) return;
        var name = (d.name || '').trim(); if (!name) { window.DNSPanel.alert({ message: 'Group name is required.' }); return; }
        var body = { name: name, description: (d.description || '').trim(), axfr_auth_mode: d.requireTsig ? 'tsig_only' : 'ip_only', send_notify: d.sendNotify ? 1 : 0, zone_axfr: d.zoneAxfr ? 1 : 0 };
        var res = await api('secondary/groups', 'POST', body);
        var id = res && res.data && res.data.id, pfx = [];
        // Networks go with the delivery settings (PATCH), after the group exists.
        if (id && canDist() && prefixList(d.prefixes).length) { var pr = await api('secondary/groups/' + id, 'PATCH', { prefixes: prefixList(d.prefixes) }); pfx = (pr && pr.data && pr.data.prefixes) || []; }
        if (id) (DATA.groups = DATA.groups || []).push({ id: +id, name: name, description: body.description, axfr_auth_mode: body.axfr_auth_mode, send_notify: body.send_notify, zone_axfr: body.zone_axfr, node_count: 0, tsig_keys: [], ip_groups: [], prefixes: pfx, axfr_status: {} });
        GM.newG = false; GM.edit = id || GM.edit; GM.draft = null;
        var g = localGroup(GM.edit); if (g) initDraft(g); renderModal();
    }
    // ---- group TSIG keys: immediate actions (local DATA update, no full refresh) ----
    async function tkAdd(gid) {
        var d = GM.draft, nm = (d.addName || '').trim(), sec = (d.addSecret || '').trim();
        if (!nm) { window.DNSPanel.alert({ message: 'Key name is required.' }); return; }
        if (!sec) { window.DNSPanel.alert({ message: 'Enter a secret or click Generate.' }); return; }
        var kres = await api('secondary/groups/' + gid + '/tsig-keys', 'POST', { name: nm, algorithm: d.addAlgo || 'hmac-sha256', secret: sec });   // create+bind atomically (no orphan)
        var kid = kres && kres.data && kres.data.tsig_key_id; if (!kid) throw new Error('Key creation failed');
        var g = localGroup(gid); if (g) { g.tsig_keys = g.tsig_keys || []; var first = g.tsig_keys.length === 0; g.tsig_keys.push({ id: +kid, name: nm, algorithm: d.addAlgo || 'hmac-sha256', is_primary: first ? 1 : 0 }); }
        await refreshServers();   // the first key becomes active → effective_auth of the group's tsig_only default members
        d.addOpen = false; d.addName = ''; d.addSecret = ''; renderModal();
    }
    async function tkRemove(gid, kid) {
        if (!(await window.DNSPanel.confirm({ title: 'Remove TSIG key', message: 'Remove this key from the group? Secondaries using it will no longer be authorized by it.', okText: 'Remove', danger: true }))) return;
        await api('secondary/groups/' + gid + '/tsig-keys/' + kid, 'DELETE');
        var g = localGroup(gid); if (g) { var was = (g.tsig_keys || []).filter(function (k) { return +k.id === +kid; })[0]; var wasPrim = was && was.is_primary; g.tsig_keys = (g.tsig_keys || []).filter(function (k) { return +k.id !== +kid; }); if (wasPrim && g.tsig_keys.length) g.tsig_keys[0].is_primary = 1; }
        await refreshServers();   // active key changed → effective_auth of default members
        delete GM.draft.revealed[kid]; renderModal();
    }
    async function tkSetPrimary(gid, kid) {
        // Optimistic: move Active locally right away, POST in the background.
        var g = byId(DATA.groups, gid);
        if (g) (g.tsig_keys || []).forEach(function (k) { k.is_primary = (+k.id === +kid) ? 1 : 0; });
        renderModal();
        try { await api('secondary/groups/' + gid + '/tsig-keys/' + kid + '/primary', 'POST'); await refreshServers(); renderModal(); }
        catch (err) { await refreshKeepDraft(); throw err; }   // on failure, restore server truth
    }
    async function tkReveal(kid) {
        if (GM.draft.revealed[kid] != null) { delete GM.draft.revealed[kid]; renderModal(); return; }
        var s = await fetchSecret(kid); if (s) GM.draft.revealed[kid] = s.secret; renderModal();
    }
    async function tkCopy(gid, kid) {
        var key = (byId(DATA.groups, gid).tsig_keys || []).filter(function (k) { return +k.id === +kid; })[0]; if (!key) return;
        var sec = GM.draft.revealed[kid]; if (sec == null) { var s = await fetchSecret(kid); if (!s) return; sec = s.secret; }
        await copyText(bindConfig(key.name, key.algorithm, sec)); window.DNSPanel.alert({ message: 'BIND key configuration copied to clipboard.' });
    }

    // ---------- events ----------
    function closeGrpPops() { document.querySelectorAll('.grp-ms-pop:not([hidden])').forEach(function (p) { p.setAttribute('hidden', ''); p.style.left = p.style.top = ''; var m = p.closest('.grp-ms'); if (m) m.classList.remove('open'); }); }
    // Place the fixed popover below the trigger, or above if it doesn't fit; clamp horizontally. Measure it
    // while shown but invisible.
    function placeGrpPop(ms, pop) {
        var r = ms.getBoundingClientRect(), pad = 8;
        pop.style.visibility = 'hidden';
        pop.removeAttribute('hidden');
        var pw = pop.offsetWidth, ph = pop.offsetHeight;
        var left = Math.min(r.left, window.innerWidth - pw - pad);
        if (left < pad) left = pad;
        var fitsBelow = (window.innerHeight - r.bottom) >= (ph + pad);
        var fitsAbove = r.top >= (ph + pad);
        var top = (fitsBelow || !fitsAbove) ? (r.bottom + 4) : (r.top - ph - 4);
        if (top < pad) top = pad;
        pop.style.left = Math.round(left) + 'px';
        pop.style.top  = Math.round(top) + 'px';
        pop.style.visibility = '';
    }
    // Scrolling anywhere (capture, to include .content and .table-wrap) moves the trigger away, so close;
    // scrolling the popover's own list doesn't count.
    window.addEventListener('scroll', function (e) {
        if (!onPage()) return;
        var t = e.target;
        if (t && t.closest && t.closest('.grp-ms-pop')) return;
        closeGrpPops();
    }, true);
    window.addEventListener('resize', function () {
        if (!onPage()) return;
        var pop = document.querySelector('.grp-ms-pop:not([hidden])');
        if (pop) { var ms = pop.closest('.grp-ms'); if (ms) placeGrpPop(ms, pop); }
    });
    document.addEventListener('click', async function (e) {
        if (!onPage()) return;
        var t = e.target;
        // click outside an open multi-select closes it (no return: other handlers still run)
        if (!(t.closest && t.closest('.grp-ms'))) closeGrpPops();
        // Same for the ⋯ menu: a native <details> doesn't close on outside click.
        if (!(t.closest && t.closest('.cat-menu'))) closeCatMenus();

        var gmst = t.closest && t.closest('[data-grp-ms-toggle]');
        if (gmst) { e.preventDefault(); var ms = gmst.closest('.grp-ms'), pop = ms.querySelector('.grp-ms-pop'), open = pop.hasAttribute('hidden');
            closeGrpPops();
            if (open) { placeGrpPop(ms, pop); ms.classList.add('open'); var si = pop.querySelector('.grp-ms-search'); if (si) si.focus(); }
            return; }


        if (t.id === 'prop-hist' || (t.closest && t.closest('[data-hist-close]'))) { e.preventDefault(); closeHist(); return; }
        // ---- personal TSIG modal ----
        if (t.id === 'prop-ntsig' || (t.closest && t.closest('[data-nt-close]'))) { e.preventDefault(); closeNtsig(); return; }
        if (NT) {
            var nto = t.closest && t.closest('[data-nt-add-open]'); if (nto) { e.preventDefault(); NT.addOpen = true; NT.addSecret = randomSecret(); var sv = byId(DATA.servers, NT.nodeId); NT.addName = suggestKeyName(sv ? sv.name : 'srv', NT.addSecret); NT.addAlgo = 'hmac-sha256'; renderNtsig(); return; }
            var ntc = t.closest && t.closest('[data-nt-add-cancel]'); if (ntc) { e.preventDefault(); NT.addOpen = false; renderNtsig(); return; }
            var ntgn = t.closest && t.closest('[data-nt-add-gen]'); if (ntgn) { e.preventDefault(); NT.addSecret = randomSecret(); renderNtsig(); return; }
            var ntsv = t.closest && t.closest('[data-nt-add-save]'); if (ntsv) { e.preventDefault(); try { await ntAdd(NT.nodeId); } catch (err) { fail(err); } return; }
            var ntrv = t.closest && t.closest('[data-nt-reveal]'); if (ntrv) { e.preventDefault(); try { await ntReveal(+ntrv.getAttribute('data-nt-reveal')); } catch (err) { fail(err); } return; }
            var ntcp = t.closest && t.closest('[data-nt-copy]'); if (ntcp) { e.preventDefault(); try { await ntCopy(NT.nodeId, +ntcp.getAttribute('data-nt-copy')); } catch (err) { fail(err); } return; }
            var ntrm = t.closest && t.closest('[data-nt-remove]'); if (ntrm) { e.preventDefault(); try { await ntRemove(NT.nodeId, +ntrm.getAttribute('data-nt-remove')); } catch (err) { fail(err); } return; }
            var ntim = t.closest && t.closest('[data-nt-import]'); if (ntim) { e.preventDefault(); var txt = window.prompt('Paste a BIND key { … } block:'); if (txt == null) return; var p = parseBindKey(txt); if (!p) { window.DNSPanel.alert({ message: 'Could not parse a TSIG key from that text.' }); return; } var s2 = byId(DATA.servers, NT.nodeId); NT.addOpen = true; NT.addName = p.name || suggestKeyName(s2 ? s2.name : 'srv', p.secret); NT.addAlgo = p.algorithm; NT.addSecret = p.secret; renderNtsig(); return; } }
        if (t.id === 'prop-modal' || (t.closest && t.closest('[data-gm-close]'))) { e.preventDefault(); closeModal(); return; }
        if (MODAL) {
            var gme = t.closest && t.closest('[data-gm-edit]'); if (gme) { e.preventDefault(); GM.edit = +gme.getAttribute('data-gm-edit'); GM.newG = false; GM.draft = null; renderModal(); return; }
            var gmc = t.closest && t.closest('[data-gm-cancel]'); if (gmc) { e.preventDefault(); GM.edit = null; GM.draft = null; renderModal(); return; }
            var gms = t.closest && t.closest('[data-gm-save]'); if (gms) { e.preventDefault(); try { await gmSave(+gms.getAttribute('data-gm-save')); } catch (err) { fail(err); } return; }
            var gmd = t.closest && t.closest('[data-gm-del]'); if (gmd) { e.preventDefault(); try { await gmDelGroup(+gmd.getAttribute('data-gm-del')); } catch (err) { fail(err); } return; }
            var gno = t.closest && t.closest('[data-gm-new-open]'); if (gno) { e.preventDefault(); GM.newG = true; GM.draft = null; renderModal(); return; }
            var gnc = t.closest && t.closest('[data-gm-new-cancel]'); if (gnc) { e.preventDefault(); GM.newG = false; GM.draft = null; renderModal(); return; }
            var gns = t.closest && t.closest('[data-gm-new-save]'); if (gns) { e.preventDefault(); try { await gmNewGroup(); } catch (err) { fail(err); } return; }
            // ---- TSIG keys (list, immediate) ----
            if (GM.draft && GM.edit) {
                var gid = +GM.edit, d = GM.draft;
                var tkr = t.closest && t.closest('[data-tk-reveal]'); if (tkr) { e.preventDefault(); try { await tkReveal(+tkr.getAttribute('data-tk-reveal')); } catch (err) { fail(err); } return; }
                var tkc = t.closest && t.closest('[data-tk-copy]'); if (tkc) { e.preventDefault(); try { await tkCopy(gid, +tkc.getAttribute('data-tk-copy')); } catch (err) { fail(err); } return; }
                var tkrm = t.closest && t.closest('[data-tk-remove]'); if (tkrm) { e.preventDefault(); try { await tkRemove(gid, +tkrm.getAttribute('data-tk-remove')); } catch (err) { fail(err); } return; }
                var tao = t.closest && t.closest('[data-tk-add-open]'); if (tao) { e.preventDefault(); d.addOpen = true; d.addSecret = randomSecret(); d.addName = suggestKeyName(d.name, d.addSecret); d.addAlgo = 'hmac-sha256'; renderModal(); return; }
                var tac = t.closest && t.closest('[data-tk-add-cancel]'); if (tac) { e.preventDefault(); d.addOpen = false; renderModal(); return; }
                var tag = t.closest && t.closest('[data-tk-add-gen]'); if (tag) { e.preventDefault(); d.addSecret = randomSecret(); renderModal(); return; }
                var tas = t.closest && t.closest('[data-tk-add-save]'); if (tas) { e.preventDefault(); try { await tkAdd(gid); } catch (err) { fail(err); } return; }
                var tim = t.closest && t.closest('[data-tk-import]'); if (tim) { e.preventDefault();
                    var txt = window.prompt('Paste a BIND key { … } block:'); if (txt == null) return;
                    var p = parseBindKey(txt); if (!p) { window.DNSPanel.alert({ message: 'Could not parse a TSIG key from that text.' }); return; }
                    d.addOpen = true; d.addName = p.name || suggestKeyName(d.name, p.secret); d.addAlgo = p.algorithm; d.addSecret = p.secret; renderModal(); return; }
            }
        }

        // click outside an open zone-table filter menu closes it (DOM only: a re-render would race with checkboxes)
        if (zTable() && zst().menu && !(t.closest && t.closest('.filter-wrap'))) {
            document.querySelectorAll('.filter-wrap.open').forEach(function (w) { w.classList.remove('open'); var mm = w.querySelector('.filter-menu'); if (mm) mm.remove(); });
            zst().menu = null;   // no return: the click (e.g. a checkbox) continues
        }
        // ---- Catalogs: picker modal (zones/groups) ----
        if (t.id === 'prop-cat-modal' || (t.closest && t.closest('[data-cat-modal-close]'))) { e.preventDefault(); CMODAL = null; renderCatModal(); return; }
        if (t.id === 'prop-sub-modal') { e.preventDefault(); CSUBM = null; renderSubModal(); return; }
        var cms = t.closest && t.closest('[data-cat-modal-save]');
        if (cms) { e.preventDefault(); try { if (CMODAL && CMODAL.kind === 'zones') await catZonesSave(); else if (CMODAL && CMODAL.kind === 'servers') await catNodesSave(); else await catGroupsSave(); } catch (err) { fail(err); } return; }
        // Zone table filters/sort, shared by the catalog picker and the Direct AXFR tab.
        if (zTable()) {
            var zs0 = zst();
            var zfb = t.closest && t.closest('[data-zfilter]');
            if (zfb) { e.preventDefault(); var nm = zfb.getAttribute('data-zfilter'); zs0.menu = (zs0.menu === nm) ? null : nm; zRerender(); return; }
            var zvo = t.closest && t.closest('[data-zval]');
            if (zvo) { e.preventDefault(); zs0[zvo.getAttribute('data-zfor')] = zvo.getAttribute('data-zval'); zs0.menu = null; zRerender(); return; }
            var zso = t.closest && t.closest('[data-zsort]');
            if (zso) { e.preventDefault(); var sk = zso.getAttribute('data-zsort'); if (zs0.sort.k === sk) zs0.sort.d = -zs0.sort.d; else zs0.sort = { k: sk, d: 1 }; zRerender(); return; }
        }
        // ---- Catalogs: master-detail ----
        var csel = t.closest && t.closest('[data-cat-sel]');
        if (csel) { e.preventDefault(); CSEL = +csel.getAttribute('data-cat-sel'); CNEW = null; CHEAD = null; render(); return; }
        var ctab = t.closest && t.closest('[data-ctab]');
        if (ctab) { e.preventDefault(); CTAB = ctab.getAttribute('data-ctab'); render(); return; }
        var cno = t.closest && t.closest('[data-cat-new-open]');
        if (cno) { e.preventDefault(); CNEW = { name: '', fqdn: '' }; CHEAD = null; render(); return; }
        var cnc = t.closest && t.closest('[data-cat-new-cancel]');
        if (cnc) { e.preventDefault(); CNEW = null; render(); return; }
        var cns = t.closest && t.closest('[data-cat-new-save]');
        if (cns) { e.preventDefault(); try { await catNewSave(); } catch (err) { fail(err); } return; }
        var che = t.closest && t.closest('[data-cat-head-edit]');
        if (che) { e.preventDefault(); var hc = catById(+che.getAttribute('data-cat-head-edit')); if (hc) CHEAD = { aid: +hc.catalog_id, name: hc.name, fqdn: hc.fqdn || '' }; render(); return; }
        var chc = t.closest && t.closest('[data-cat-head-cancel]');
        if (chc) { e.preventDefault(); CHEAD = null; render(); return; }
        var chs = t.closest && t.closest('[data-cat-head-save]');
        if (chs) { e.preventDefault(); try { await catHeadSave(+chs.getAttribute('data-cat-head-save')); } catch (err) { fail(err); } return; }
        var cdl = t.closest && t.closest('[data-cat-del]');
        if (cdl) { e.preventDefault(); try { await catDelete(+cdl.getAttribute('data-cat-del')); } catch (err) { fail(err); } return; }
        var crt = t.closest && t.closest('[data-cat-retry]');
        if (crt) { e.preventDefault(); await catRetry(+crt.getAttribute('data-cat-retry')); return; }
        var gtg = t.closest && t.closest('[data-cat-grp-toggle]');
        if (gtg) { e.preventDefault(); var gk = +gtg.getAttribute('data-aud') + ':' + +gtg.getAttribute('data-cat-grp-toggle'); if (CEXP[gk]) delete CEXP[gk]; else CEXP[gk] = true; render(); return; }
        var sop = t.closest && t.closest('[data-sub-open]');
        if (sop) { e.preventDefault(); openSubModal(+sop.getAttribute('data-aud'), +sop.getAttribute('data-sub-open')); return; }
        var srk = t.closest && t.closest('[data-sub-recheck]');
        if (srk) { e.preventDefault(); try { await subRecheck(+srk.getAttribute('data-aud'), +srk.getAttribute('data-sub-recheck')); } catch (err) { fail(err); } return; }
        var sclz = t.closest && t.closest('[data-sub-close]');
        if (sclz) { e.preventDefault(); CSUBM = null; renderSubModal(); return; }
        var ssec = t.closest && t.closest('[data-sub-secret]');
        if (ssec) { e.preventDefault(); if (CSUBM) { CSUBM.showSecret = !CSUBM.showSecret; renderSubModal(); } return; }
        var scc = t.closest && t.closest('[data-sub-copy]');
        if (scc) { e.preventDefault(); subCopy(+scc.getAttribute('data-sub-copy')); return; }
        var scf = t.closest && t.closest('[data-sub-cfg-refresh]');
        if (scf) { e.preventDefault(); if (CSUBM) { CSUBM.state = 'loading'; renderSubModal(); loadSubConfig(); } return; }
        // AXFR sources manager
        var cza = t.closest && t.closest('[data-cat-zones-add]');
        if (cza) { e.preventDefault(); var zaid = +cza.getAttribute('data-cat-zones-add');
            CMODAL = { kind: 'zones', aid: zaid, search: '', mKind: '', mLabel: '', mShow: 'all',
                       sort: { k: 'zone', d: 1 }, menu: null, includes: {}, focused: false,
                       onlyMaster: true };
            // Ticks mirror the catalog's contents, exactly what the list shows.
            catShownZones(catById(zaid)).forEach(function (d) { CMODAL.includes[+d] = 1; });
            renderCatModal(); return; }
        var dxb = t.closest && t.closest('[data-dx-bulk]');
        if (dxb) { e.preventDefault(); try { await directBulk(dxb.getAttribute('data-dx-bulk')); } catch (err) { fail(err); } return; }
        var cga = t.closest && t.closest('[data-cat-groups-add]');
        if (cga) { e.preventDefault(); CMODAL = { kind: 'groups', aid: +cga.getAttribute('data-cat-groups-add') }; renderCatModal(); return; }
        var cna = t.closest && t.closest('[data-cat-nodes-add]');
        if (cna) { e.preventDefault(); CMODAL = { kind: 'servers', aid: +cna.getAttribute('data-cat-nodes-add') }; renderCatModal(); return; }
        var czr = t.closest && t.closest('[data-cat-zone-rm]');
        if (czr) { e.preventDefault(); try { await catZoneRemove(+czr.getAttribute('data-cat-zone-rm')); } catch (err) { fail(err); } return; }
        var cgr = t.closest && t.closest('[data-cat-group-rm]');
        if (cgr) { e.preventDefault(); try { await catGroupRemove(+cgr.getAttribute('data-cat-group-rm')); } catch (err) { fail(err); } return; }
        var cnr = t.closest && t.closest('[data-cat-node-rm]');
        if (cnr) { e.preventDefault(); try { await catNodeRemove(+cnr.getAttribute('data-cat-node-rm')); } catch (err) { fail(err); } return; }

        var tab = t.closest && t.closest('[data-tab]');
        if (tab) { e.preventDefault(); TAB = tab.getAttribute('data-tab'); render(); return; }
        var sortTh = t.closest && t.closest('[data-sort]');
        if (sortTh) { e.preventDefault(); var k = sortTh.getAttribute('data-sort'); if (SORT.k === k) SORT.d = -SORT.d; else SORT = { k: k, d: 1 }; render(); return; }
        var gopen = t.closest && t.closest('[data-groups-open]');
        if (gopen) { e.preventDefault(); openGroupsModal(); return; }
        var grow = t.closest && t.closest('[data-grp-row]');
        if (grow && (canSec() || canDist())) { e.preventDefault(); openGroupsModal(); GM.edit = +grow.getAttribute('data-grp-row'); renderModal(); return; }
        var hst = t.closest && t.closest('[data-srv-hist]');
        if (hst) { e.preventDefault(); openHistory(+hst.getAttribute('data-srv-hist')); return; }
        var stg = t.closest && t.closest('[data-srv-tsig]');
        if (stg) { e.preventDefault(); openNtsig(+stg.getAttribute('data-srv-tsig')); return; }

        var se = t.closest && t.closest('[data-srv-edit]');
        if (se) { e.preventDefault(); EDIT = +se.getAttribute('data-srv-edit'); DRAFT = null; render(); return; }
        var sc = t.closest && t.closest('[data-srv-cancel]');
        if (sc) { e.preventDefault(); EDIT = null; DRAFT = null; render(); return; }
        var ss = t.closest && t.closest('[data-srv-save]');
        if (ss) { e.preventDefault(); try { await saveServer(+ss.getAttribute('data-srv-save')); } catch (err) { fail(err); } return; }
        var sd = t.closest && t.closest('[data-srv-del]');
        if (sd) { e.preventDefault(); var did = +sd.getAttribute('data-srv-del');
            if (!(await window.DNSPanel.confirm({ title: 'Delete secondary server', message: 'Delete this secondary server?', okText: 'Delete', danger: true }))) return;
            try { await api('secondary/servers/' + did, 'DELETE'); DATA.servers = (DATA.servers || []).filter(function (x) { return +x.id !== did; }); syncServerCatalogsLocal(did, []); render(); } catch (err) { fail(err); } return; }
        var sas = t.closest && t.closest('[data-srv-add-save]');
        if (sas) { e.preventDefault(); try { await addServer(); } catch (err) { fail(err); } return; }
    });

    document.addEventListener('change', function (e) {
        if (!onPage()) return;
        var t = e.target;
        if (t.name === 'prop-flt-group')  { FILTER.group = t.value; render(); return; }
        if (t.name === 'prop-flt-status') { FILTER.status = t.value; render(); return; }
        // Direct AXFR is edited inline. The previous value comes from page data, which is updated only on the
        // server's response, so it is still the old one to revert to.
        if (/^dx-\d+$/.test(t.name || '')) {
            var dxid = +t.name.slice(3);
            var prev = directOn(dxid);
            directSet(dxid, t.value === '1', prev).catch(function (err) { fail(err); });
            return;
        }
        // Row selection lives in state, without a full re-render that would lose scroll and search focus.
        if (zTable()) {
            var set0 = zSelSet();
            var zp = t.closest && t.closest('[data-zpick], [data-dxsel]');
            if (zp) { set0[+zp.getAttribute('data-domain')] = zp.checked ? 1 : 0; updateZbulk(); return; }
            var za = t.closest && t.closest('[data-zselall]');
            if (za) { var on = za.checked;
                zRows().forEach(function (r) { set0[+r.domain_id] = on ? 1 : 0; });
                rebuildZbody(); return; }
        }

        if (NT) {
            if (t.hasAttribute && t.hasAttribute('data-nt-src')) {
                if (t.checked) { var v = t.getAttribute('data-nt-src'), sep = v.indexOf(':'), kind = v.slice(0, sep), sid = +v.slice(sep + 1);
                    (async function () { try { if (kind === 'group') await ntSetGroup(NT.nodeId, sid); else await ntSetPrimary(NT.nodeId, sid); } catch (err) { fail(err); } })(); }
                return;
            }
            if (t.name === 'nt-add-algo') { NT.addAlgo = t.value; return; }
        }
        if (MODAL && GM.draft) {
            if (t.hasAttribute && t.hasAttribute('data-gm-req')) { GM.draft.requireTsig = t.checked; renderModal(); return; }
            if (t.hasAttribute && t.hasAttribute('data-gm-notify')) { GM.draft.sendNotify = t.checked; renderModal(); return; }
            if (t.hasAttribute && t.hasAttribute('data-gm-zaxfr')) { GM.draft.zoneAxfr = t.checked; renderModal(); return; }
            if (t.hasAttribute && t.hasAttribute('data-tk-primary')) { if (t.checked) { (async function () { try { await tkSetPrimary(+GM.edit, +t.getAttribute('data-tk-primary')); } catch (err) { fail(err); } })(); } return; }
            if (t.name === 'tk-add-algo') { GM.draft.addAlgo = t.value; return; }
        }
        // AXFR/NOTIFY: the trigger label shows the chosen value
        var pf = t.closest && t.closest('.grp-ms [data-pf]');
        if (pf && t.checked) { var pms = pf.closest('.grp-ms'), pc = pms.querySelector('.grp-ms-count');
            if (pc) pc.textContent = (t.parentNode.textContent || '').trim();
            pms.setAttribute('data-picked', '1');   // user picked it: group-based defaults leave this field alone
            return; }
        // group/catalog multi-select: update the trigger count
        var gc = t.closest && t.closest('.grp-ms [data-g], .grp-ms [data-c]');
        if (gc) { var ms = gc.closest('.grp-ms'), isCat = t.hasAttribute && t.hasAttribute('data-c');
            var base = isCat ? (+ms.getAttribute('data-cat-base') || 0) : 0;   // via-group catalogs are a fixed base
            var n = base + ms.querySelectorAll(isCat ? '[data-c]:checked' : '[data-g]:checked').length;
            var c = ms.querySelector('.grp-ms-count'); if (c) c.textContent = msLabel(isCat ? 'catalog' : 'group', n);
            // Add row only: default policies follow group presence — with a group Inherit, without one Allow/On
            // (Inherit with no groups would read as off). Fields the user picked are left alone.
            if (!isCat && ms.closest('.srv-tbl-add')) {
                var root = ms.closest('.srv-tbl-add'), lone = { axfr_policy: 'allow', notify_policy: 'on' };
                ['axfr_policy', 'notify_policy'].forEach(function (f) {
                    var box = root.querySelector('.grp-ms[data-ms-kind="' + f + '"]');
                    if (!box || box.getAttribute('data-picked')) return;
                    var want = n > 0 ? 'inherit' : lone[f];
                    var inp = box.querySelector('[data-pf="' + f + '"][value="' + want + '"]');
                    if (!inp || inp.checked) return;
                    inp.checked = true;
                    var trg = box.querySelector('.grp-ms-count');
                    if (trg) trg.textContent = (inp.parentNode.textContent || '').trim();
                });
            }
            return; }
    });

    document.addEventListener('input', function (e) {
        if (!onPage()) return;
        // Catalogs: form drafts (new/header) and picker zone search update without re-render (keeps focus/caret)
        var cnf = e.target.getAttribute && e.target.getAttribute('data-catnf');
        if (cnf && CNEW) { CNEW[cnf] = e.target.value; return; }
        var chf = e.target.getAttribute && e.target.getAttribute('data-cathf');
        if (chf && CHEAD) { CHEAD[chf] = e.target.value; return; }
        if (NT) {
            if (e.target.hasAttribute && e.target.hasAttribute('data-nt-add-name')) { NT.addName = e.target.value; return; }
            if (e.target.hasAttribute && e.target.hasAttribute('data-nt-add-secret')) { NT.addSecret = e.target.value; return; }
        }
        var czs = e.target.closest && e.target.closest('[data-zsearch]');
        if (czs && zTable()) { zst().search = czs.value; rebuildZbody(); return; }   // body only: search keeps focus
        var gms = e.target.closest && e.target.closest('[data-grp-ms-search]');   // filters the popover's group list
        if (gms) { var q = gms.value.toLowerCase(); gms.closest('.grp-ms-pop').querySelectorAll('.gms-opt').forEach(function (o) { o.style.display = o.textContent.toLowerCase().indexOf(q) >= 0 ? '' : 'none'; }); return; }
        // group-editor draft inputs update the draft without re-render (keeps focus/caret)
        if (MODAL && GM.draft) {
            var te = e.target, d = GM.draft, dm = te.getAttribute && te.getAttribute('data-gm');
            if (dm === 'name') { d.name = te.value; return; }
            if (dm === 'description') { d.description = te.value; return; }
            if (dm === 'prefixes') { d.prefixes = te.value; return; }
            if (te.hasAttribute && te.hasAttribute('data-add-name')) { d.addName = te.value; return; }
            if (te.hasAttribute && te.hasAttribute('data-add-secret')) { d.addSecret = te.value; return; }
        }
        if (MODAL || HIST) return;
        var s = e.target.closest && e.target.closest('[data-search]');
        if (s) {
            SEARCH = s.value;
            var tb = document.querySelector('.srv-table tbody'); if (!tb) return;
            var rows = sortedServers();
            tb.innerHTML = rows.length ? rows.map(serverRow).join('') : '<tr><td colspan="' + srvCols() + '" class="text-dim" style="padding:1rem;">No servers match the filters.</td></tr>';
            localizeTimes(tb);
        }
    });

    document.addEventListener('keydown', function (e) {
        if (!onPage()) return;
        if (e.key === 'Escape') {
            if (document.querySelector('.cat-menu[open]')) { e.preventDefault(); closeCatMenus(); return; }
            if (document.querySelector('.grp-ms-pop:not([hidden])')) { e.preventDefault(); closeGrpPops(); return; }
            if (CSUBM) { e.preventDefault(); CSUBM = null; renderSubModal(); return; }
            if (NT) { e.preventDefault(); closeNtsig(); return; }
            if (CMODAL && CMODAL.menu) { e.preventDefault(); CMODAL.menu = null; renderCatModal(); return; }
            if (CMODAL) { e.preventDefault(); CMODAL = null; renderCatModal(); return; }
            if (HIST) { e.preventDefault(); closeHist(); } else if (MODAL) { e.preventDefault(); closeModal(); }
        }
    });

    // ?catalog=<catalog_id>: deterministic deep link (badge on the Zones table); wins over localStorage.
    function restoreFromUrl() {
        try {
            var q = new URLSearchParams(window.location.search);
            var c = q.get('catalog');
            if (c && /^\d+$/.test(c) && catById(+c)) { TAB = 'catalogs'; CSEL = +c; CTAB = 'zones'; return; }
            // ?tab=direct: link from the zone list for a zone distributed directly.
            if (q.get('tab') === 'direct') TAB = 'direct';
        } catch (e) {}
    }
    function init() { readData(); if (!DATA) return; restore(); restoreFromUrl(); render(); }
    // Single entry point, pageLoaded (F5 and menu navigation): the page is server-rendered, so a direct call
    // would initialize twice.
    document.addEventListener('pageLoaded', function (ev) { if (ev.detail && ev.detail.page === 'propagation') init(); });
})();
