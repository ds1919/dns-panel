/* DNS Panel — Settings → Import: migrating zones from an old BIND (docs/26).

   The `named-checkconf -p` file is parsed once into the DB (import_sources/import_zones); from then on the
   screen works with that list, not the file. Migrating hundreds of zones takes weeks, so the operator must
   see what was taken, what was skipped and what newly appeared on the old server. Re-uploading an export of
   the same master updates the list instead of starting over.

   Two stages:
     parsed — from the file itself: role, masters, ACL, also-notify, dynamic, TSIG, zone file path;
     probed — only known by querying the old server: its serial, record count, AXFR, diff.
   An empty Serial/Records cell means "not probed", not zero.

   Filters, row selection and styling are shared panel components (app.js). */
(function () {
    'use strict';

    var M = null;     // tab state
    var FILTERS = ['state', 'kind', 'type', 'dynamic', 'dnssec', 'master', 'review', 'since'];

    function esc(s) { return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'); }
    function api(path, method, body) { return window.DNSPanel.api(path, { method: method, body: body ? JSON.stringify(body) : undefined }); }
    function sel(name, opts, value) { return window.DNSPanel.selectHtml(name, opts, value); }
    function help(id, spec) { return window.DNSPanel.helpDot('imp-' + id, spec); }
    function root() { return document.getElementById('import-root'); }

    var STATE_LABEL = {
        pending: 'Pending', imported: 'Imported', imported_gone: 'Imported, zone deleted',
        exists: 'Conflict — already exists', reviewed: 'Kept current', failed: 'Failed'
    };

    // The source's TSIG is for an old server that transfers only with a key. It appears only once a probe shows
    // such a refusal (or a key is already chosen): a server that allows us by address, like most, needs nothing.
    function tsigShown() {
        if (M.tsigSel) return true;
        return (M.inv && M.inv.zones || []).some(function (z) {
            return z.probe_state === 'failed' && /refused the transfer \((REFUSED|NOTAUTH)\)|rejected the TSIG key/.test(z.probe_error || '');
        });
    }
    function probeQueued() { return (M.inv && M.inv.zones || []).filter(function (z) { return z.probe_state === 'queued'; }).length; }
    function probeProgress() { var n = probeQueued(); return n ? 'Probing the source: ' + n + ' zone(s) left' : ''; }
    // While zones wait for the probe the list follows the worker by itself (the worker probes as soon as they
    // are queued); it stops once none is queued or the tab is left. Selection and open rows stay.
    var probeTimer = null;
    function followProbe() {
        clearTimeout(probeTimer);
        if (!M || M.step !== 'list' || !probeQueued()) return;
        probeTimer = setTimeout(async function () {
            if (!document.getElementById('imp-probe')) return;
            try { var r = await api('import/sources/' + M.inv.source.id, 'GET'); M.inv = (r && r.data) || r; renderList(); } catch (e) { return; }
            followProbe();
        }, 2000);
    }
    // The same control as a secondary zone's upstream TSIG. The list re-renders while the probe runs, so the
    // choice and a half-typed new key live in M and are put back.
    function tsigBlock() {
        return '<div class="imp-tsig"><label class="field-label">TSIG for transfers from this server'
             + help('tsig', 'Zones this server is the primary for are created with this key; Probe source and Compare sign with it too. Zones it only mirrored come from their own masters and keep their own key.') + '</label>'
             + window.DNSPanel.upstreamTsigHtml('imp', M.tsigSel.indexOf('k:') === 0 ? M.tsigSel.slice(2) : '', M.upKeys) + '</div>';
    }
    function tsigRestore() {
        var r = root(); if (!r || !r.querySelector('[name="imp-tsig"]')) return;
        window.DNSPanel.upstreamTsigBind(r, 'imp');
        if (M.tsigSel !== 'new') return;
        window.DNSPanel.setSelect('imp-tsig', 'new');
        r.querySelector('#imp-tsig-name').value = M.tsigNew.name || '';
        r.querySelector('#imp-tsig-secret').value = M.tsigNew.secret || '';
        window.DNSPanel.setSelect('imp-tsig-algo', M.tsigNew.algorithm || 'hmac-sha256');
    }
    function renderLoad() {
        var list = (M.sources || []).map(function (s) {
            return '<tr><td class="mono"><a href="#" class="link imp-src" data-id="' + s.id + '">' + esc(s.master) + '</a></td>'
                 + '<td class="right">' + s.zone_count + '</td><td class="right">' + s.imported + '</td>'
                 + '<td class="mono">' + esc(window.DNSPanel.fmtTime(s.loaded_at)) + '</td></tr>';
        }).join('');
        root().innerHTML = '<div class="card imp-load">'
            + '<div class="zform-row"><label>BIND export' + help('file', {
                text: 'On the BIND server run:',
                code: 'named-checkconf -p > bind-export.conf',
                after: 'It expands every include and normalises the config. The file itself is not stored — the zone list it describes is.' }) + '</label>'
            +   '<input type="file" id="imp-file" accept=".conf,.txt,text/plain"></div>'
            + '<div class="zform-row"><label>Source DNS' + help('source',
                'Where the zones are pulled from. Addresses are taken from listen-on in the file itself; pick the one this PowerDNS can reach.') + '</label>'
            +   '<span id="imp-source-box">' + sourceField() + '</span></div>'
            + '<div class="login-error" id="imp-err" style="display:none;"></div>'
            + '<div class="imp-load-actions"><button type="button" class="btn btn-primary" id="imp-load">Load configuration</button></div>'
            + (list ? '<div class="zform-sec-title" style="margin-top:1.2rem;">Loaded servers</div>'
                    + '<div class="table-wrap"><table class="data-table"><thead><tr><th>Source</th>'
                    + '<th class="right">Zones</th><th class="right">Imported</th><th>Last loaded</th></tr></thead>'
                    + '<tbody>' + list + '</tbody></table></div>' : '')
            + '</div>';
    }
    function sourceField() {
        var found = M.sources_found || [];
        if (found.length > 1) return sel('imp-source-pick', found.map(function (a) { return { value: a, label: a }; }), M.master);
        return '<input class="field-input mono" id="imp-master" value="' + esc(M.master)
             + '" placeholder="' + (found.length ? '' : 'choose the file first, or type the address') + '">';
    }

    function keyList(dk) { return dk.map(function (k) { return k.tag + (k.flags === 257 ? " KSK" : " ZSK"); }).join(", "); }
    function flags(z) {
        var f = [];
        if (z.is_new)  f.push('<span class="badge master" data-tip="Appeared in the configuration loaded last">new</span>');
        if (z.changed) f.push('<span class="badge warn" data-tip="Its configuration changed in the last load">changed</span>');
        if (z.dynamic) f.push('<span class="badge slave" data-tip="Dynamic DNS updates (RFC 2136) are enabled on the source server">dynamic</span>');
        if (z.dnssec) {   // a button: its modal loads the key files or chooses "import unsigned"
            var dk = (z.config || {}).dnssec_keys || [], un = (z.config || {}).dnssec_unsigned;
            f.push('<a href="#" class="badge ' + (un || dk.length ? 'muted' : 'err') + ' imp-dnssec" data-id="' + z.id + '" data-tip="'
                   + (un ? 'Import unsigned' : dk.length ? 'Keys: ' + esc(keyList(dk)) : 'Key files required') + '">DNSSEC' + (un ? ' off' : '') + '</a>');
        }
        if (z.needs_review) f.push('<span class="badge err" data-tip="' + esc(((z.config || {}).review || []).join('; ') || 'unusual configuration') + '">review</span>');
        var zk = (z.config || {}).keys || [];
        if (/^(slave|secondary)$/.test(z.type || '') && zk.length)
            f.push('<span class="badge warn" data-tip="The source server pulled this zone from its masters with this key. The zone takes a key of that name if PowerDNS has it; otherwise add it in zone settings.">TSIG key required: ' + esc(zk.join(', ')) + '</span>');
        if (z.gone) f.push('<span class="badge err" data-tip="Not in the latest configuration of this server">gone</span>');
        // Probe of the old server: waiting for the worker / zone not served (reason in tooltip) / serial differs from ours.
        if (z.probe_state === 'queued') f.push('<span class="badge muted" data-tip="Waiting for the probe of the source server">probing</span>');
        if (z.probe_state === 'failed') f.push('<span class="badge err" data-tip="' + esc(z.probe_error || 'the source server did not give the zone') + '">no transfer</span>');
        if (z.panel && z.panel.serial && z.source_serial && String(z.panel.serial) !== String(z.source_serial))
            f.push('<span class="badge warn" data-tip="Import ' + esc(z.source_serial) + ', current ' + esc(z.panel.serial) + '">serial differs</span>');
        return f.join(' ');
    }
    // Conflict: a zone with this name exists in the panel and was not created by the import. Resolved in Compare
    // (source version or current); "Kept current" is that decision made earlier and can be changed there.
    function conflict(z) { return (z.state === 'exists' || z.state === 'reviewed') && !z.gone && z.importable; }
    // Only what the panel will actually migrate is selectable: a zone still present on the source (not gone)
    // whose type can be transferred by AXFR.
    function canPick(z) { return !z.gone && z.importable && (z.state === 'pending' || z.state === 'failed'); }
    // The header checkbox skips rows flagged "review": those are selected by hand.
    function bulkPick(z) { return canPick(z) && !z.needs_review; }
    var TYPE_LABEL = { master: 'Primary', primary: 'Primary', slave: 'Secondary', secondary: 'Secondary',
                       forward: 'Forward', hint: 'Hint', stub: 'Stub', 'static-stub': 'Static stub',
                       redirect: 'Redirect', mirror: 'Mirror' };
    function typeLabel(z) { return TYPE_LABEL[z.type] || (z.type || '—'); }
    // Same colours as Zones: Primary = master, Secondary = slave; types the panel cannot migrate are muted.
    function typeBadge(z) {
        var cls = (z.role === 'slave') ? 'slave' : (/^(master|primary)$/.test(z.type || '') ? 'master' : 'muted');
        var tip = (z.role === 'slave')
            ? ' data-tip="The source server is a secondary here too — the panel will pull the zone from its own masters and keep it Secondary, so it keeps updating after the source server is switched off"' : '';
        return '<span class="badge ' + cls + '"' + tip + '>' + esc(typeLabel(z)) + '</span>';
    }
    function kindBadge(z) {
        return z.kind === 'reverse4' ? ' <span class="badge kind-rev">REVERSE</span>'
             : z.kind === 'reverse6' ? ' <span class="badge kind-rev">REVERSE&nbsp;v6</span>' : '';
    }
    // Where the zone will come from: the old server for a master zone, its own masters for a slave zone (the
    // real owner is a third server). One function for both the column and the filter, so filtering by
    // "Source: <addr>" finds exactly the rows that show that address.
    function mastersOf(z) { return (z.role === 'slave') ? (z.masters || []) : [M.inv.source.master]; }
    function masterCell(z) {
        var m = mastersOf(z);
        if (!m.length) return '<span class="text-mute">—</span>';
        return esc(m[0]) + (m.length > 1 ? ' <span class="text-mute">+' + (m.length - 1) + '</span>' : '');
    }
    // Zone role in the same words as the Zones list (_role_label), not the raw PowerDNS type.
    function panelRole(t) { t = String(t || '').toUpperCase(); return t === 'SLAVE' ? 'Secondary' : t === 'NATIVE' ? 'Native' : 'Primary'; }
    function detail(z) {
        var c = z.config || {};
        function line(k, v) { return v ? '<div class="imp-d"><span>' + k + '</span><b class="mono">' + esc(v) + '</b></div>' : ''; }
        function list(k, a) { return (a && a.length) ? line(k, a.join(', ')) : ''; }
        var body = line('Zone file', c.file) + line('notify', c.notify)
                 + list('masters', c.masters) + list('also-notify', c.also_notify)
                 + list('allow-query', c.allow_query) + list('allow-transfer', c.allow_transfer)
                 + list('allow-update', c.allow_update)
                 + (c.update_from ? list('updates from', [].concat(c.update_from.cidrs || [], (c.update_from.keys || []).map(function (k) { return 'key ' + k; }), c.update_from.other || [])) : '') + (c.update_policy ? line('update-policy', 'present') : '')
                 + list('forwarders', c.forwarders) + list('TSIG keys', c.keys)
                 + (c.dnssec_keys && c.dnssec_keys.length ? line('DNSSEC keys', keyList(c.dnssec_keys)) : '') + list('needs review', c.review)
                 + (z.panel ? line('in the panel', panelRole(z.panel.type) + ' · serial ' + (z.panel.serial || '—') + ' · '
                                   + z.panel.records + ' records' + (z.panel.profile ? ' · profile ' + z.panel.profile : '')
                                   + (z.panel.ours ? ' · imported from here' : ' · existed independently')) : '')
                 + (z.note ? line('note', z.note) : '');
        // A zone with this name already exists in the panel: decide in Compare, where the difference is visible.
        var act = z.panel ? '<div class="imp-dact"><button type="button" class="btn btn-ghost sm imp-diff" data-id="' + z.id + '">'
                          + 'Compare' + '</button></div>' : '';
        return '<tr class="imp-detail"><td></td><td colspan="6">' + (body || '<span class="text-mute">Nothing besides the basics.</span>') + act + '</td></tr>';
    }
    // Serial and Records show only the SOURCE side, as of the last probe. Our zone is in the row
    // expansion ("in the panel: …") and in Compare.
    function probed(v) {
        return (v == null || v === '') ? '<span class="text-mute" data-tip="Not probed yet \u2014 Probe source">\u2014</span>' : esc(v);
    }
    function row(z) {
        var serial  = probed(z.source_serial);
        var records = probed(z.source_records);
        return '<tr data-z="' + esc(z.name) + '"><td class="th-check">'
            + (canPick(z) ? '<input type="checkbox" class="imp-cb" data-z="' + esc(z.name) + '"' + (M.chosen[z.name] ? ' checked' : '') + '>' : '')
            + '</td>'
        // Name, REVERSE badge and type badge exactly as in the Zones list.
            + '<td class="zone-name"><a href="#" class="zone-name-link imp-open" data-z="' + esc(z.name) + '">' + esc(z.name) + '</a>' + kindBadge(z) + '</td>'
            + '<td>' + typeBadge(z) + '</td>'
            + '<td class="mono">' + masterCell(z) + '</td>'
            + '<td class="mono right">' + serial + '</td><td class="right">' + records + '</td>'
            + '<td>' + esc(STATE_LABEL[z.state] || z.state) + ' ' + flags(z) + '</td></tr>'
            + (M.open[z.name] ? detail(z) : '');
    }
    function tbEl() { return root().querySelector('.imp-toolbar'); }
    // Before the toolbar exists (first render after F5) the saved choice is used.
    function fsaved(n) { return (window.DNSPanel.store('impFilters') || {})[n]; }
    function fval(n) { var t = tbEl(); if (t) return window.DNSPanel.filterValue(t, n); var s = fsaved(n); return s ? s.val : 'all'; }
    function ftext(n) {
        var t = tbEl(), b = t && t.querySelector('.filter[data-filter="' + n + '"]'), s = b ? { text: b.textContent } : fsaved(n);
        return s ? (s.text.split(':')[1] || 'all').replace(/\u25be/, '').trim() : null;
    }
    function visible() {
        var q = (M.q || '').toLowerCase();
        var fs = fval('state'), fk = fval('kind'), ft = fval('type'), fd = fval('dynamic'), fm = fval('master'), fr = fval('review'), fx = fval('dnssec');
        return (M.inv.zones || []).filter(function (z) {
            if (q && z.name.toLowerCase().indexOf(q) < 0) return false;
            if (fs !== 'all' && z.state !== fs) return false;
            if (fk !== 'all' && (fk === 'reverse' ? z.kind === 'forward' : z.kind !== fk)) return false;
            if (ft !== 'all' && (z.type || '') !== ft) return false;
            if (fd !== 'all' && (fd === 'yes' ? !z.dynamic : !!z.dynamic)) return false;
            if (fr !== 'all' && (fr === 'yes' ? !z.needs_review : !!z.needs_review)) return false;
            if (fx !== 'all' && (fx === 'yes' ? !z.dnssec : !!z.dnssec)) return false;
            if (fm !== 'all' && mastersOf(z).indexOf(fm) < 0) return false;
            var fsi = fval('since');
            if (fsi === 'new' && !z.is_new) return false;
            if (fsi === 'changed' && !z.changed) return false;
            return true;
        });
    }
    function optsFor(name) {
        var seen = {};
        if (name === 'state') {
            (M.inv.zones || []).forEach(function (z) { seen[z.state] = 1; });
            return [['all', 'all']].concat(Object.keys(seen).sort().map(function (s) { return [s, STATE_LABEL[s] || s]; }));
        }
        if (name === 'type') {
            (M.inv.zones || []).forEach(function (z) { seen[z.type || ''] = 1; });
            return [['all', 'all']].concat(Object.keys(seen).sort().map(function (t) {
                return [t, TYPE_LABEL[t] || t || '—']; }));
        }
        if (name === 'kind')    return [['all', 'all'], ['forward', 'Forward'], ['reverse', 'Reverse']];   // as on Zones
        if (name === 'dynamic') return [['all', 'all'], ['yes', 'Dynamic'], ['no', 'Static']];
        if (name === 'review')  return [['all', 'all'], ['yes', 'Needs review'], ['no', 'Clean']];
        if (name === 'dnssec')  return [['all', 'all'], ['yes', 'Signed'], ['no', 'Unsigned']];
        if (name === 'since')   return [['all', 'all'], ['new', 'New in last load'], ['changed', 'Changed in last load']];
        (M.inv.zones || []).forEach(function (z) { mastersOf(z).forEach(function (m) { seen[m] = 1; }); });
        return [['all', 'all']].concat(Object.keys(seen).sort().map(function (m) { return [m, m]; }));
    }
    function anyFilter() { return !!(M.q || '').trim() || window.DNSPanel.filtersActive(tbEl(), FILTERS); }
    function summary() {
        var c = M.inv.counts || {}, out = [];
        ['pending', 'imported', 'exists', 'reviewed', 'failed', 'imported_gone'].forEach(function (k) {
            if (c[k]) out.push(c[k] + ' ' + (STATE_LABEL[k] || k).toLowerCase());
        });
        if (c.dynamic) out.push(c.dynamic + ' dynamic');
        if (c.review)  out.push(c.review + ' need review');
        if (c.gone)    out.push(c.gone + ' not in the latest config');
        if (c.is_new)  out.push(c.is_new + ' new in last load');
        if (c.changed) out.push(c.changed + ' changed in last load');
        if (c.dnssec)  out.push(c.dnssec + ' signed (DNSSEC)');
        return out.join(' · ');
    }
    function renderList() {
        var rows = visible(), n = Object.keys(M.chosen).length;
        var fh = window.DNSPanel.filterHtml;
        root().innerHTML = '<div class="card imp-card">'
            + '<div class="imp-head"><div><b>' + esc(M.inv.source.master) + '</b>'
            +   '<div class="text-dim" style="font-size:12.5px;margin-top:.2rem;">' + esc(summary())
            +   ' · loaded ' + esc(window.DNSPanel.fmtTime(M.inv.source.loaded_at)) + '</div></div>'
            +   '<span class="imp-head-acts"><button type="button" class="btn btn-ghost sm" id="imp-probe">Probe source</button>'
            +   '<button type="button" class="btn btn-ghost sm" id="imp-back">Load a configuration</button></span></div>'
            + '<div class="toolbar imp-toolbar">'
            +   '<div class="search"><input id="imp-q" placeholder="Search zones…" value="' + esc(M.q) + '"></div>'
            +   fh('state', 'Status', fval('state'), ftext('state')) + fh('kind', 'Kind', fval('kind'), ftext('kind')) + fh('type', 'Type', fval('type'), ftext('type'))
            +   fh('dynamic', 'Dynamic', fval('dynamic'), ftext('dynamic')) + fh('master', 'Source', fval('master'), ftext('master'))
            +   fh('dnssec', 'DNSSEC', fval('dnssec'), ftext('dnssec')) + fh('review', 'Review', fval('review'), ftext('review')) + fh('since', 'Since last load', fval('since'), ftext('since'))
            +   '<button class="filter" type="button" id="imp-clear" style="display:none;">✕ Clear</button>'
            + '</div>'
            + '<div class="imp-scroll"><table class="data-table imp-table"><thead><tr>'
            +   '<th class="th-check"><input type="checkbox" id="imp-all" aria-label="Select / clear all shown"></th>'
            +   '<th>Zone</th><th>Type</th><th>Source</th>'
            +   '<th class="right" data-tip="SOA serial on the source server. Filled in once it can be asked; what the panel has is in the row details.">Source serial</th>'
            +   '<th class="right" data-tip="Number of records on the source server. Filled in once it can be asked.">Source records</th>'
            +   '<th>Status</th></tr></thead><tbody>'
            +   (rows.length ? rows.map(row).join('') : '<tr><td colspan="7" class="text-mute" style="padding:1rem;">No zones match.</td></tr>')
            + '</tbody></table></div>'
            + '<div class="login-error" id="imp-err" style="display:none;"></div>'
            + '<div class="imp-bar">'
            +   '<span class="imp-count" id="imp-selected">' + n + ' selected</span>'
            +   '<span class="text-mute" id="imp-progress">' + esc(probeProgress()) + '</span>'
            +   '<button type="button" class="btn btn-primary" id="imp-go"' + (n ? '' : ' disabled') + '>Import ' + n + ' as Secondary</button>'
            + '</div>'
            + (tsigShown() ? tsigBlock() : '')
            + '</div>';
        window.DNSPanel.store('impFilters', window.DNSPanel.filtersGet(tbEl(), FILTERS)); window.DNSPanel.store('impQ', M.q);
        tsigRestore();
        window.DNSPanel.filterInit(tbEl(), { opts: optsFor, onChange: renderList });
        syncPick(rows);
    }
    // Header checkbox selects the VISIBLE selectable rows (same as Users & access); partial selection is
    // shown as indeterminate. Zones hidden by a filter stay selected.
    function syncPick(rows) {
        rows = rows || visible();
        var pick = rows.filter(bulkPick), on = pick.filter(function (z) { return M.chosen[z.name]; });
        var all = document.getElementById('imp-all');
        if (all) {
            all.checked = pick.length > 0 && on.length === pick.length;
            all.indeterminate = on.length > 0 && on.length < pick.length;
            all.disabled = !pick.length;
        }
        var n = Object.keys(M.chosen).length;
        var go = document.getElementById('imp-go'), cnt = document.getElementById('imp-selected');
        if (go) { go.textContent = 'Import ' + n + ' as Secondary'; go.disabled = !n; }
        if (cnt) cnt.textContent = n + ' selected';
        var cl = document.getElementById('imp-clear');
        if (cl) cl.style.display = anyFilter() ? '' : 'none';
    }
    // ok: an outcome to note, not an error (neutral colour).
    function showErr(msg, ok) {
        var el = document.getElementById('imp-err'); if (!el) return;
        el.style.display = ''; el.textContent = msg; el.classList.toggle('is-ok', !!ok);
    }

    async function loadSources() {
        try { var r = await api('import/sources', 'GET'); M.sources = ((r && r.data) || r).sources || []; }
        catch (e) { M.sources = []; }
    }
    async function readFile(file) {
        var text = await new Promise(function (res, rej) {
            var fr = new FileReader();
            fr.onload  = function () { res(String(fr.result || '')); };
            fr.onerror = function () { rej(new Error('could not read the file')); };
            fr.readAsText(file);
        });
        M.text = text;
        var r = await api('zones/import/sources', 'POST', { export: text });
        M.sources_found = ((r && r.data) || r).sources || [];
        if (M.sources_found.length === 1 || (M.sources_found.length && !M.master)) M.master = M.sources_found[0];
        var box = document.getElementById('imp-source-box');
        if (box) box.innerHTML = sourceField();
    }
    async function loadConfig() {
        if (M.reading) { try { await M.reading; } catch (e) {} }
        if (!M.text) { showErr('Choose the bind-export.conf file'); return; }
        var el = document.getElementById('imp-master');
        if (el) M.master = el.value.trim();
        try {
            var r = await api('import/sources', 'POST', { master: M.master || undefined, export: M.text });
            var src = (r && r.data) || r;
            await openSource(src.id);
        } catch (e) { showErr((e && e.message) || 'Could not read the file'); }
    }
    async function openSource(id) {
        try {
            var r = await api('import/sources/' + id, 'GET');
            M.inv = (r && r.data) || r;
            M.upKeys = await window.DNSPanel.upstreamKeys();
            M.chosen = {}; M.open = {}; M.step = 'list';
            renderList();
            followProbe();
        } catch (e) { showErr((e && e.message) || 'Could not open the list'); }
    }
    // -> '' or an error; sets M.tsig (existing key) or M.tsigMode 'new' with M.tsigNew.
    function readTsig() {
        M.tsig = ''; M.tsigMode = 'none';
        var r = root(); if (!r || !r.querySelector('[name="imp-tsig"]')) return '';
        var ut = window.DNSPanel.upstreamTsigRead(r, 'imp');
        if (ut.err) return ut.err;
        if (ut.tsig_new) { M.tsigMode = 'new'; M.tsigNew = ut.tsig_new; }
        else M.tsig = ut.tsig || '';
        return '';
    }
    // Create in batches: the core limits a request to 200 zones. A failure of the request itself stops the run;
    // per-zone failures arrive inside a successful response.
    async function run() {
        var terr = readTsig();
        if (terr) { showErr(terr); return; }
        var names = Object.keys(M.chosen), done = 0, created = 0, failed = [], stopped = null, warn = null;
        var kept = 0, notes = [];
        var go = document.getElementById('imp-go'), prog = document.getElementById('imp-progress');
        if (go) go.disabled = true;
        while (names.length) {
            var chunk = names.splice(0, 50);
            try {
                var r = await api('zones/import', 'POST', {
                    source_id: M.inv.source.id,
                    tsig: M.tsig || undefined, tsig_new: (M.tsigMode === 'new') ? M.tsigNew : undefined,
                    // The panel knows each zone's source and old role from its own list; we only name the zones.
                    zones: chunk
                });
                var d = (r && r.data) || r;
                if (d.tsig_created && !d.tsig_removed) { M.tsigMode = 'none'; M.tsig = d.tsig_created.name; M.tsigSel = 'k:' + M.tsig; M.tsigNew = { algorithm: M.tsigNew.algorithm }; }
                if (d.tsig_warning) warn = d.tsig_warning;
                created += (d.created || []).length;
                (d.created || []).forEach(function (z) {
                    if (z.kept_secondary) kept++;
                    if (z.note) notes.push(z.name + ' — ' + z.note);
                });
                failed = failed.concat(d.failed || []);
            } catch (e) { stopped = (e && e.message) || 'request failed'; break; }
            done += chunk.length;
            if (prog) prog.textContent = done + ' / ' + (done + names.length);
        }
        await openSource(M.inv.source.id);
        var msg = [];
        if (stopped) msg.push('Stopped after ' + created + ' zone(s): ' + stopped + '. The list shows the current state.');
        else if (failed.length) msg.push('Imported ' + created + ', with problems ' + failed.length + ': '
                + failed.slice(0, 5).map(function (f) { return (f.name || f.id) + ' — ' + f.error; }).join('; '));
        else msg.push('Imported ' + created + ' zone(s) as Secondary.');
        if (kept) msg.push(kept + ' pull from their own masters.');
        if (notes.length) msg.push('Needs attention: ' + notes.slice(0, 5).join('; ') + '.');
        if (warn) msg.push(warn);
        showErr(msg.join(' '), !stopped && !failed.length && !notes.length && !warn);
    }

    // Probe and Compare query the same server as the migration and sign with the same key. A key not yet in
    // PowerDNS ("new" mode) cannot be used for probing: the form's secret is not stored. Returns {tsig} | {err}.
    function probeKey() {
        var e = readTsig(); if (e) return { err: e };
        if (M.tsigMode === 'new') return { err: 'Probe and Compare sign only with a key already in PowerDNS — choose an existing key, or import a zone first: that adds the key.' };
        return { tsig: M.tsig || '' };
    }

    // Compare: Import (source server) and Current (zone in the panel) side by side.
    // One list, one row per name+type in zone order. A switch on top (All changes / Different / Import only /
    // Current only / Identical) and a name search pick what is shown; only the middle of the window scrolls.
    // Copy: the → arrow copies a whole RRset (name+type) from Import to Current, only in the window so far:
    // the Import version appears on the right and × undoes that copy. Checkboxes + "Copy selected" copy several.
    // Only Apply changes writes to the zone; the server takes the content from a live AXFR, the browser sends keys.
    // Apex SOA and NS are never copied (zone structure). A Secondary has nowhere to copy to: its records come by AXFR.
    // A zone in conflict is resolved here as a whole: Import this version / Keep current.
    // DNSSEC of a signed zone: the key files its live DNSKEY set needs (Make primary keeps them), or import it
    // unsigned. Mirroring it as Secondary needs neither.
    async function openDnssec(id) {
        var ov = document.getElementById('modal-overlay'); if (!ov) return;
        var changed = false;
        async function close() {
            ov.style.display = 'none'; ov.innerHTML = '';
            if (!changed) return;
            try { var r = await api('import/sources/' + M.inv.source.id, 'GET'); M.inv = (r && r.data) || r; renderList(); } catch (e) {}
        }
        function render(d, err) {
            var keys = d.keys || [], missing = keys.filter(function (k) { return !k.have; });
            var rows = keys.map(function (k) {
                return '<tr><td>' + (k.have ? '✓' : '<span style="color:var(--danger)">✕</span>') + '</td><td class="mono">' + k.tag + ' ' + k.role + '</td>'
                     + '<td class="mono">' + k.files.map(esc).join('<br>') + '</td></tr>';
            }).join('');
            // One line says what Make primary will do; the choice below changes it.
            var outcome = d.done ? (d.done === 'signed' ? 'Done: the panel signs this zone with these keys.' : 'Done: the zone is primary and unsigned.')
                : d.unsigned ? 'Make primary drops DNSSEC. Remove the DS at the registrar first.'
                : d.error ? d.error
                : missing.length ? 'Missing key files: ' + missing.map(function (k) { return k.tag; }).join(', ') + '. Make primary is refused until they are loaded.'
                : 'All keys loaded: Make primary keeps DNSSEC.';
            var choice = d.done ? '' : '<div class="zform-row"><label>On Make primary</label><div class="zform-grow">'
                + '<label class="chk block"><input type="radio" name="imp-dk-mode" value="keep"' + (d.unsigned ? '' : ' checked') + '> Keep signing with these keys</label>'
                + '<label class="chk block"><input type="radio" name="imp-dk-mode" value="drop"' + (d.unsigned ? ' checked' : '') + '> Drop DNSSEC</label></div></div>';
            ov.innerHTML = '<div class="modal"><div class="modal-card zs-card">'
                + '<h2 class="modal-title">DNSSEC — ' + esc(d.zone) + '</h2>'
                + (rows ? '<table class="data-table"><tbody>' + rows + '</tbody></table>' : '')
                + (!d.done && !d.unsigned ? '<div class="zform-row"><label>Key files</label><input type="file" id="imp-dk-files" multiple accept=".key,.private"></div>' : '')
                + choice
                + '<p class="zform-note">' + esc(outcome) + '</p>'
                + '<div class="login-error" id="imp-dk-err"' + (err ? '' : ' style="display:none;"') + '>' + esc(err || '') + '</div>'
                + '<div class="modal-actions"><button type="button" class="btn btn-ghost" id="imp-dk-close">Close</button></div></div></div>';
            ov.querySelector('#imp-dk-close').onclick = close;
            ov.querySelectorAll('[name="imp-dk-mode"]').forEach(function (rb) {
                rb.onchange = async function () {
                    try { var r = await api('import/zones/' + id + '/dnssec', 'PUT', { unsigned: rb.value === 'drop' }); changed = true; render((r && r.data) || r); }
                    catch (e) { render(d, (e && e.message) || 'Failed'); }
                };
            });
            var fi = ov.querySelector('#imp-dk-files');
            if (fi) fi.onchange = async function () {
                try {
                    var files = await Promise.all(Array.prototype.map.call(fi.files, function (f) { return f.text().then(function (c) { return { name: f.name, content: c }; }); }));
                    var r = await api('import/zones/' + id + '/dnssec/keys', 'POST', { keys: files }); changed = true; render((r && r.data) || r);
                } catch (e) { render(d, (e && e.message) || 'Upload failed'); }
            };
        }
        ov.innerHTML = '<div class="modal"><div class="modal-card"><div class="spinner"></div></div></div>';
        ov.style.display = 'block';
        try { var r = await api('import/zones/' + id + '/dnssec', 'GET'); render((r && r.data) || r); }
        catch (e) { ov.style.display = 'none'; ov.innerHTML = ''; showErr((e && e.message) || 'Could not open DNSSEC'); }
    }
    async function openDiff(id, note) {
        var ov = document.getElementById('modal-overlay'); if (!ov) return;
        var pk = probeKey(); if (pk.err) { showErr(pk.err); return; }
        var z = (M.inv.zones || []).filter(function (x) { return x.id === id; })[0] || {};
        var changed = !!note;   // something was written: reload the list behind the window on close
        var close = function () { ov.style.display = 'none'; ov.innerHTML = ''; if (changed) openSource(M.inv.source.id); };
        if (!ov.querySelector('.imp-cmp')) ov.innerHTML = '<div class="modal"><div class="modal-card"><div class="spinner"></div></div></div>';
        ov.style.display = 'block';
        var d;
        try { var r = await api('import/zones/' + id + '/diff' + (pk.tsig ? '?tsig=' + encodeURIComponent(pk.tsig) : ''), 'GET'); d = (r && r.data) || r; }
        catch (err) { close(); showErr((err && err.message) || 'Compare failed'); return; }
        var zone = String(d.zone || '').toLowerCase().replace(/\.$/, '');
        var canCopy = !!(z.panel && z.panel.type !== 'slave');
        function rel(n) { return n === zone ? '@' : (n.slice(-(zone.length + 1)) === '.' + zone ? n.slice(0, -(zone.length + 1)) : n); }
        function key(x) { return x.name + ' ' + x.type; }
        function copyable(x) {
            return canCopy && x.old && x.status !== 'same' && x.status !== 'panel_only'
                && x.type !== 'SOA' && !(x.type === 'NS' && x.name === zone);
        }
        var list = d.rows || [];
        function grp(x) { return x.status === 'ttl' ? 'differs' : x.status; }
        var cnt = { differs: 0, same: 0, panel_only: 0, old_only: 0 };
        list.forEach(function (x) { cnt[grp(x)]++; });
        var SHOW = [['changes', 'All changes', cnt.differs + cnt.old_only + cnt.panel_only], ['differs', 'Different', cnt.differs],
                    ['old_only', 'Import only', cnt.old_only], ['panel_only', 'Current only', cnt.panel_only], ['same', 'Identical', cnt.same]];
        if (!M.cmpShow) M.cmpShow = 'changes';
        var q = '';
        // Whether a row is visible under the current switch and search. A copied row stays in place and visible.
        function shown(x) {
            var g = grp(x);
            if (M.cmpShow === 'changes' ? g === 'same' : g !== M.cmpShow) return false;
            return !q || x.name.indexOf(q) >= 0;
        }
        var staged = {}, picked = {};
        function bulkView() { return M.cmpShow === 'changes' || M.cmpShow === 'old_only'; }

        // Three cells of one side. Values missing on the other side are highlighted; a differing TTL is labelled.
        function side(s, other, cls) {
            if (!s) return '<td class="' + cls + '"></td><td></td><td></td>';
            var has = {}; ((other && other.values) || []).forEach(function (v) { has[v] = 1; });
            var vals = s.values.map(function (v) { return other && !has[v] ? '<b class="text-warn">' + esc(v) + '</b>' : esc(v); }).join('<br>');
            if (other && other.ttl !== s.ttl) vals += ' <span class="text-warn">TTL ' + s.ttl + '</span>';
            return '<td class="mono ' + cls + '">' + esc(rel(s.name)) + '</td><td>' + esc(s.type) + '</td><td class="mono">' + vals + '</td>';
        }
        function sideOf(x, which) { var s = x[which]; return s ? { name: x.name, type: x.type, ttl: s.ttl, values: s.values } : null; }
        function rowHtml(i) {
            var x = list[i], k = key(x), st = !!staged[k], a = sideOf(x, 'old'), b = sideOf(x, 'panel'), can = copyable(x);
            var cls = st ? ' class="imp-cmp-staged"' : (x.status === 'differs' || x.status === 'ttl') ? ' class="imp-cmp-diff"' : '';
            var right = st
                ? '<td class="mono imp-cmp-r">' + esc(rel(x.name)) + '</td><td>' + esc(x.type) + '</td><td class="mono imp-cmp-new">'
                  + a.values.map(esc).join('<br>') + (b && b.ttl !== a.ttl ? ' TTL ' + a.ttl : '') + '</td>'
                : side(b, a, 'imp-cmp-r');
            return '<tr data-i="' + i + '"' + cls + (shown(x) ? '' : ' hidden') + '>'
                 + '<td class="imp-cmp-cb">' + (can && !st && x.status === 'old_only' ? '<input type="checkbox" class="imp-cmp-pick" data-i="' + i + '"' + (picked[k] ? ' checked' : '') + '>' : '') + '</td>'
                 + side(a, b, '')
                 + '<td class="imp-cmp-mid">' + (can && !st ? '<button type="button" class="btn btn-ghost sm imp-cmp-copy" data-i="' + i + '" data-tip="Copy to Current">→</button>' : '') + '</td>'
                 + right
                 + '<td class="imp-cmp-x">' + (st ? '<button type="button" class="btn btn-ghost sm imp-cmp-undo" data-i="' + i + '" data-tip="Undo">×</button>' : '') + '</td></tr>';
        }
        var body = list.length ? '<tbody>' + list.map(function (x, i) { return rowHtml(i); }).join('') + '</tbody>' : '';
        var ndiff = cnt.differs + cnt.old_only + cnt.panel_only;
        var decide = conflict(z);
        var big = '';
        if (decide) {
            big += '<button type="button" class="btn btn-danger" id="imp-take">Import this version</button>';
            if (z.state !== 'reviewed') big += '<button type="button" class="btn btn-ghost" id="imp-keep">Keep current</button>';
        }
        big += '<button type="button" class="btn btn-ghost" id="imp-diff-close">Close</button>';
        ov.innerHTML = '<div class="modal"><div class="modal-card imp-cmp">'
            + '<h2 class="modal-title">' + esc(d.zone) + '</h2>'
            + '<div class="imp-cmp-head text-dim">'
            +   '<div class="seg" id="imp-cmp-show">' + SHOW.map(function (s) {
                    return '<button type="button" class="seg-btn' + (M.cmpShow === s[0] ? ' active' : '') + '" data-show="' + s[0] + '">' + s[1] + ' · ' + s[2] + '</button>'; }).join('') + '</div>'
            +   '<input class="imp-cmp-q" id="imp-cmp-q" placeholder="Filter by name…" autocomplete="off">'
            +   '<span id="imp-cmp-empty" hidden>Nothing to show</span>'
            +   (z.state === 'reviewed' ? '<span>You chose to keep the current version.</span>' : '')
            +   (!canCopy && z.panel ? '<span>The current zone is a Secondary — records cannot be copied into it.</span>' : '')
            +   (note ? '<span class="text-warn">' + esc(note) + '</span>' : '')
            + '</div>'
            + '<div class="imp-cmp-body"><table><colgroup><col style="width:30px"><col style="width:15%"><col style="width:66px"><col>'
            +   '<col style="width:46px"><col style="width:15%"><col style="width:66px"><col><col style="width:40px"></colgroup>'
            +   '<thead><tr><th class="imp-cmp-cb">' + (cnt.old_only && canCopy ? '<input type="checkbox" class="imp-cmp-all" aria-label="Select all shown"' + (bulkView() ? '' : ' hidden') + '>' : '') + '</th><th colspan="3">Import · ' + esc(d.source) + ' <span class="text-mute">serial ' + esc(d.source_serial) + '</span></th><th></th>'
            +   '<th colspan="3" class="imp-cmp-r">Current <span class="text-mute">serial ' + esc(d.our_serial) + '</span></th><th></th></tr></thead>'
            +   body + '</table>'
            +   (body ? '' : '<p class="text-dim" style="padding:1rem;">Nothing to show.</p>') + '</div>'
            + '<div class="login-error" id="imp-cmp-err" style="display:none;"></div>'
            + '<div id="imp-take-box"></div>'
            + '<div class="imp-cmp-foot" id="imp-diff-acts">'
            +   '<span class="imp-cmp-copybar">'
            +     '<button type="button" class="btn btn-ghost" id="imp-cmp-copysel" hidden></button>'
            +     '<span class="text-dim" id="imp-cmp-n"></span>'
            +     '<button type="button" class="btn btn-primary" id="imp-cmp-apply" hidden>Apply changes</button>'
            +     '<button type="button" class="btn btn-ghost" id="imp-cmp-discard" hidden>Discard changes</button>'
            +   '</span>' + big + '</div></div></div>';

        var tbl = ov.querySelector('.imp-cmp-body table');
        function redraw(i) { var tr = tbl.querySelector('tr[data-i="' + i + '"]'); if (tr) tr.outerHTML = rowHtml(i); }
        function nStaged() { return Object.keys(staged).length; }
        function bar() {
            var np = Object.keys(picked).length, ns = nStaged();
            var cs = ov.querySelector('#imp-cmp-copysel'); if (!cs) return;
            // Bulk copy is on All changes and Import only (checkboxes only on Import-only rows). Selection survives
            // filter and search changes: everything selected is copied, as the button count says. Different uses arrows.
            cs.hidden = !np; cs.textContent = 'Copy ' + np + ' selected →';
            cs.disabled = !bulkView();
            cs.setAttribute('data-tip', cs.disabled ? 'Switch to All changes or Import only to copy the selected records' : '');
            ov.querySelector('#imp-cmp-n').textContent = ns ? ns + ' change' + (ns === 1 ? '' : 's') + ' to apply' : '';
            ov.querySelector('#imp-cmp-apply').hidden = !ns;
            ov.querySelector('#imp-cmp-discard').hidden = !ns;
            // A whole-zone decision on top of unapplied copies would silently drop them: Apply or Discard first.
            ['#imp-take', '#imp-keep'].forEach(function (sel) {
                var b = ov.querySelector(sel); if (!b) return;
                b.disabled = !!ns; b.setAttribute('data-tip', ns ? 'Apply or discard the copied records first' : '');
            });
            var cl = ov.querySelector('#imp-diff-close'); cl.textContent = 'Close'; cl.removeAttribute('data-sure');
        }
        function stage(i, on) {
            var k = key(list[i]);
            if (on) { staged[k] = 1; delete picked[k]; } else delete staged[k];
            redraw(i);
        }
        tbl.addEventListener('click', function (e) {
            var b = e.target.closest && e.target.closest('.imp-cmp-copy, .imp-cmp-undo');
            if (!b) return;
            stage(+b.getAttribute('data-i'), b.classList.contains('imp-cmp-copy'));
            bar();
        });
        tbl.addEventListener('change', function (e) {
            var t = e.target;
            if (t.classList.contains('imp-cmp-pick')) {
                var k = key(list[+t.getAttribute('data-i')]);
                if (t.checked) picked[k] = 1; else delete picked[k];
            } else if (t.classList.contains('imp-cmp-all')) {
                // "Select all" takes only visible rows; rows hidden by a filter are never selected blindly.
                tbl.querySelectorAll('tr[data-i]:not([hidden]) .imp-cmp-pick').forEach(function (cb) {
                    cb.checked = t.checked;
                    var k = key(list[+cb.getAttribute('data-i')]);
                    if (t.checked) picked[k] = 1; else delete picked[k];
                });
            } else return;
            bar();
        });
        ov.querySelector('#imp-cmp-copysel').addEventListener('click', function () {
            list.forEach(function (x, i) { if (picked[key(x)]) stage(i, true); });
            var all = tbl.querySelector('.imp-cmp-all'); if (all) all.checked = false;
            bar();
        });
        ov.querySelector('#imp-cmp-discard').addEventListener('click', function () {
            list.forEach(function (x, i) { if (staged[key(x)]) stage(i, false); });
            bar();
        });
        ov.querySelector('#imp-cmp-apply').addEventListener('click', async function () {
            var go = this, err = ov.querySelector('#imp-cmp-err');
            var keys = list.filter(function (x) { return staged[key(x)]; }).map(function (x) { return { name: x.name, type: x.type }; });
            go.disabled = true; err.style.display = 'none';
            try { await api('import/zones/' + id + '/copy', 'POST', { rrsets: keys, tsig: pk.tsig || undefined }); }
            catch (e) { err.textContent = (e && e.message) || 'Could not copy the records'; err.style.display = ''; go.disabled = false; return; }
            // Compare again against what the zone now holds.
            openDiff(id, 'Copied ' + keys.length + ' record set' + (keys.length === 1 ? '' : 's') + ' to Current.');
        });
        // Closing with unapplied copies takes a second click: the first warns they will be lost.
        ov.querySelector('#imp-diff-close').addEventListener('click', function () {
            var ns = nStaged();
            if (ns && !this.getAttribute('data-sure')) { this.setAttribute('data-sure', '1'); this.textContent = 'Discard ' + ns + ' change' + (ns === 1 ? '' : 's') + '?'; return; }
            close();
        });
        // Switch and search only change row visibility; the table is not re-rendered.
        function refilter() {
            var any = false;
            tbl.querySelectorAll('tr[data-i]').forEach(function (tr) { var v = shown(list[+tr.getAttribute('data-i')]); tr.hidden = !v; any = any || v; });
            var all = tbl.querySelector('.imp-cmp-all'); if (all) all.checked = false;
            ov.querySelector('#imp-cmp-empty').hidden = any;
        }
        ov.querySelector('#imp-cmp-show').addEventListener('click', function (e) {
            var b = e.target.closest && e.target.closest('.seg-btn'); if (!b) return;
            M.cmpShow = b.getAttribute('data-show');
            this.querySelectorAll('.seg-btn').forEach(function (x) { x.classList.toggle('active', x === b); });
            var all = tbl.querySelector('.imp-cmp-all'); if (all) all.hidden = !bulkView();
            refilter(); bar();
        });
        ov.querySelector('#imp-cmp-q').addEventListener('input', function () { q = this.value.trim().toLowerCase(); refilter(); });
        refilter();
        var keep = ov.querySelector('#imp-keep');
        if (keep) keep.addEventListener('click', function () {
            api('import/zones/' + id + '/mark', 'POST', { status: 'reviewed' })
                .then(function () { changed = false; close(); return openSource(M.inv.source.id); })
                .catch(function (err) { close(); showErr((err && err.message) || 'Could not save'); });
        });
        var take = ov.querySelector('#imp-take');
        if (take) take.addEventListener('click', function () { confirmTake(ov, id, d, pk.tsig, close); });
    }
    // Confirmation goes in the same window above the buttons, so what gets replaced stays visible. The zone
    // name must be typed, as for Make secondary: current records are deleted.
    function confirmTake(ov, id, d, tsig, close) {
        var box = ov.querySelector('#imp-take-box'), name = String(d.zone);
        box.innerHTML = '<div class="imp-cmp-confirm"><p class="zform-note">Zone <b>' + esc(name) + '</b> becomes a Secondary of <b>' + esc(d.source)
            + '</b>, the same as any imported zone. <b>Its current records are deleted</b> and replaced by what ' + esc(d.source) + ' sends'
            + (tsig ? ' (signed with <b>' + esc(tsig) + '</b>)' : '') + '. If it is in a catalog, it is taken out. '
            + 'Promote it in Zone settings when you are ready.</p>'
            + '<label class="field-label">Type the zone name to confirm</label>'
            + '<input class="field-input" id="imp-take-name" placeholder="' + esc(name) + '" autocomplete="off">'
            + '<div class="login-error" id="imp-take-err" style="display:none;"></div></div>';
        ov.querySelector('#imp-diff-acts').innerHTML = '<button type="button" class="btn btn-danger" id="imp-take-go" disabled>Replace current with Import</button>'
            + '<button type="button" class="btn btn-ghost" id="imp-take-cancel">Cancel</button>';
        var inp = ov.querySelector('#imp-take-name'), go = ov.querySelector('#imp-take-go'), err = ov.querySelector('#imp-take-err');
        inp.focus();
        inp.addEventListener('input', function () { go.disabled = inp.value.trim().toLowerCase() !== name.toLowerCase(); });
        ov.querySelector('#imp-take-cancel').addEventListener('click', close);
        go.addEventListener('click', async function () {
            go.disabled = true;
            var r;
            try { r = await api('import/zones/' + id + '/take', 'POST', { confirm_name: inp.value.trim(), tsig: tsig || undefined }); r = (r && r.data) || r; }
            catch (e) { err.textContent = (e && e.message) || 'Could not replace the zone'; err.style.display = ''; go.disabled = false; return; }
            close();
            await openSource(M.inv.source.id);
            var msg = [name + ' is now a Secondary of ' + d.source + '; it shows Active once the transfer arrives.'];
            if (r.catalog_removed) msg.push('It was taken out of its catalog.');
            if (r.note) msg.push(r.note + '.');
            (r.warnings || []).forEach(function (w) { msg.push(w + '.'); });
            showErr(msg.join(' '), !(r.warnings || []).length);
        });
    }

    document.addEventListener('change', function (e) {
        if (!M || !e.target || !root()) return;
        var t = e.target;
        if (t.id === 'imp-file') {
            var f = t.files[0]; if (!f) return;
            M.reading = readFile(f);
            M.reading.catch(function (err) { showErr((err && err.message) || 'could not read the file'); });
            return;
        }
        if (t.id === 'imp-all') {
            var rows = visible().filter(bulkPick);
            if (t.checked) rows.forEach(function (z) { M.chosen[z.name] = 1; });
            else           rows.forEach(function (z) { delete M.chosen[z.name]; });
            root().querySelectorAll('.imp-cb').forEach(function (cb) { cb.checked = !!M.chosen[cb.getAttribute('data-z')]; });
            syncPick(); return;
        }
        if (t.type !== 'hidden') return;
        var n = t.getAttribute('name');
        if (n === 'imp-source-pick') { M.master = t.value; return; }
        if (n === 'imp-tsig-algo') { M.tsigNew.algorithm = t.value; return; }
        if (n === 'imp-tsig')      { M.tsigSel = t.value; return; }
    });
    document.addEventListener('input', function (e) {
        if (M && e.target && /^imp-tsig-(name|secret)$/.test(e.target.id)) {   // a pasted key block fills both
            M.tsigNew.name   = document.getElementById('imp-tsig-name').value;
            M.tsigNew.secret = document.getElementById('imp-tsig-secret').value;
            return;
        }
        if (!M || !e.target || e.target.id !== 'imp-q') return;
        M.q = e.target.value;
        renderList();
        var el = document.getElementById('imp-q');
        if (el) { el.focus(); el.setSelectionRange(el.value.length, el.value.length); }
    });
    document.addEventListener('click', function (e) {
        if (!M || !root()) return;
        var t = e.target;
        if (t.closest && t.closest('#imp-load'))  { e.preventDefault(); loadConfig(); return; }
        if (t.closest && t.closest('#imp-go'))    { e.preventDefault(); run(); return; }
        if (t.closest && t.closest('#imp-back'))  { e.preventDefault(); M.step = 'file'; loadSources().then(renderLoad); return; }
        if (t.closest && t.closest('#imp-clear')) {
            e.preventDefault();
            M.q = '';
            window.DNSPanel.filtersClear(tbEl(), FILTERS);
            renderList(); return;
        }
        var src = t.closest && t.closest('.imp-src');
        if (src) { e.preventDefault(); openSource(+src.getAttribute('data-id')); return; }
        // Probe source: queue the zones; the worker probes them at once, and the list follows by itself.
        if (t.closest && t.closest('#imp-probe')) {
            e.preventDefault();
            var pk = probeKey(); if (pk.err) { showErr(pk.err); return; }
            api('import/sources/' + M.inv.source.id + '/probe', 'POST', pk.tsig ? { tsig: pk.tsig } : {})
                .then(function () { return openSource(M.inv.source.id); })
                .catch(function (err) { showErr((err && err.message) || 'Could not queue the probe'); });
            return;
        }
        var dn = t.closest && t.closest('.imp-dnssec');
        if (dn) { e.preventDefault(); openDnssec(+dn.getAttribute('data-id')); return; }
        var df = t.closest && t.closest('.imp-diff');
        if (df) { e.preventDefault(); openDiff(+df.getAttribute('data-id')); return; }
        var op = t.closest && t.closest('.imp-open');
        if (op) {   // expand in place: re-rendering hundreds of rows for one is expensive
            e.preventDefault();
            var name = op.getAttribute('data-z');
            var tr = root().querySelector('.imp-table tr[data-z="' + CSS.escape(name) + '"]');
            if (!tr) return;
            if (M.open[name]) {
                delete M.open[name];
                var nx = tr.nextElementSibling;
                if (nx && nx.classList.contains('imp-detail')) nx.remove();
            } else {
                M.open[name] = 1;
                var z = (M.inv.zones || []).filter(function (x) { return x.name === name; })[0];
                if (z) tr.insertAdjacentHTML('afterend', detail(z));
            }
            return;
        }
        var cb = t.closest && t.closest('.imp-cb');
        if (cb) {
            var zn = cb.getAttribute('data-z');
            if (cb.checked) M.chosen[zn] = 1; else delete M.chosen[zn];
            syncPick();
            return;
        }
    });

    // Mounted by the Settings tab like Users & access: own root and own state.
    window.ImportTab = {
        mount: async function () {
            M = { step: 'file', text: '', sources: [], sources_found: [], master: '', reading: null,
                  inv: null, chosen: {}, open: {}, q: window.DNSPanel.store('impQ') || '',
                  tsigMode: 'none', tsig: '', tsigSel: '', tsigNew: { algorithm: 'hmac-sha256' }, upKeys: [] };
            await loadSources();
            if (!root()) return;
            // A single source is opened right away: usually it is the whole job.
            if (M.sources.length === 1) await openSource(M.sources[0].id);
            else renderLoad();
        },
        destroy: function () { M = null; }
    };
})();
