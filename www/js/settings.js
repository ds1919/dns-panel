/* DNS Panel — Settings. Tabs: Zone profiles | Import | Dynamic DHCP profiles | Pinger & Pulse | Users & access | External access.| Import | Dynamic DHCP profiles | Pinger & Pulse | Users & access.
   Zone profiles and Pinger & Pulse live here; Import is js/import.js, Users & access is js/users_access.js.
   Data comes as embedded JSON (#settings-data).
   The tab list in availTabs() must also be allowed in initTab(): a tab missing there is saved but a reload
   returns the user to the first tab. */
(function () {
    'use strict';

    var ST = null;      // { can, load_err, profiles[], catalogs[], pulse, users, editing }
    var SOA_DEF = { soa_ttl: 3600, soa_refresh: 7200, soa_retry: 3600, soa_expire: 1209600, soa_minimum: 3600 };

    function esc(s) { return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'); }
    function api(path, method, body) { return window.DNSPanel.api(path, { method: method, body: body ? JSON.stringify(body) : undefined }); }
    function fail(err) { window.DNSPanel.alert({ message: (err && err.message) ? err.message : 'Request failed' }); }
    function sel(name, opts, value) { return window.DNSPanel.selectHtml(name, opts, value); }

    function readData() { var el = document.getElementById('settings-data'); try { return el ? JSON.parse(el.textContent) : null; } catch (e) { return null; } }
    function catOpts() { return [{ value: '', label: 'None' }].concat((ST.catalogs || []).map(function (c) { return { value: String(c.id), label: c.name }; })); }

    function availTabs() {
        var t = [];
        if (ST.can) t.push({ id: 'profiles', label: 'Zone profiles' });
        if (ST.can) t.push({ id: 'import',   label: 'Import' });
        if (ST.can) t.push({ id: 'dynamic',  label: 'Dynamic DHCP profiles' });
        if (ST.pulse && ST.pulse.can) t.push({ id: 'pulse', label: 'Pinger & Pulse' });
        if (ST.users && ST.users.can) t.push({ id: 'users', label: 'Users & access' });
        if (ST.users && ST.users.can) t.push({ id: 'external', label: 'External access' });
        return t;
    }
    function saveTab() { try { localStorage.setItem('settingsTab', ST.tab); } catch (e) {} }
    function syncUrl() {   // keep ?tab=<id> in sync (replaceState, no new history entries)
        try { var u = new URL(window.location.href); u.searchParams.set('tab', ST.tab); history.replaceState(history.state, '', u.pathname + u.search + u.hash); } catch (e) {}
    }
    function render() {
        var root = document.getElementById('settings-root'); if (!root) return;
        if (ST.load_err) { root.innerHTML = '<div class="card"><p style="margin:0;color:var(--danger)">Failed to load: ' + esc(ST.load_err) + '</p></div>'; return; }
        var tabs = availTabs();
        if (!tabs.length) { root.innerHTML = '<div class="card"><p class="text-dim" style="margin:0;">No settings available for your capabilities.</p></div>'; return; }
        if (!tabs.some(function (t) { return t.id === ST.tab; })) ST.tab = tabs[0].id;   // fall back to the first available tab
        var bar = '<div class="dist-tabs" style="margin:.25rem 0 1rem;">'
            + tabs.map(function (t) { return '<button class="dist-tab' + (ST.tab === t.id ? ' active' : '') + '" data-stab="' + t.id + '">' + esc(t.label) + '</button>'; }).join('')
            + '</div>';
        var content = (ST.tab === 'users') ? usersCard()
                    : (ST.tab === 'pulse') ? pulseCard()
                    : (ST.tab === 'import') ? '<div id="import-root"></div>'
                    : (ST.tab === 'dynamic') ? '<div id="dynamic-root"></div>'
                    : (ST.tab === 'external') ? '<div id="external-root"></div>' : profilesCard();
        root.innerHTML = bar + content;
        if (ST.tab === 'users') mountUsers();
        // Import and Users & access are separate modules with their own state and lifecycle;
        // Settings only knows where to mount them.
        if (ST.tab === 'import' && window.ImportTab) window.ImportTab.mount();
        else if (window.ImportTab) window.ImportTab.destroy();
        if (ST.tab === 'dynamic' && window.DynamicTab) window.DynamicTab.mount();
        else if (window.DynamicTab) window.DynamicTab.destroy();
        if (ST.tab === 'external' && window.ExternalTab) window.ExternalTab.mount();
        else if (window.ExternalTab) window.ExternalTab.destroy();
        saveTab(); syncUrl();
    }
    function profilesCard() {
        var rows = (ST.profiles || []).map(function (p) {
            var del = p.used_by > 0
                ? '<span class="link" style="color:var(--text-mute);cursor:not-allowed" data-tip="Disable the profile instead — used by ' + p.used_by + ' zone(s)">Delete</span>'
                : '<a href="#" class="link" data-zp-del="' + p.id + '" style="color:var(--danger)">Delete</a>';
            return '<tr>'
                + '<td><b>' + esc(p.name) + '</b></td>'
                + '<td class="mono">' + esc(p.primary_ns || '') + '</td>'
                + '<td>' + (p.enabled ? '<span class="chip">Enabled</span>' : '<span class="chip" style="opacity:.6">Disabled</span>') + '</td>'
                + '<td>' + (p.used_by || 0) + '</td>'
                + '<td class="right nowrap"><a href="#" class="link" data-zp-edit="' + p.id + '">Edit</a> ' + del + '</td>'
                + '</tr>';
        }).join('') || '<tr><td colspan="5" class="text-dim" style="padding:1rem;">No zone profiles yet. A profile fills SOA and name servers of a new zone so they don’t have to be typed each time — <b>Add profile</b>.</td></tr>';
        return '<div class="card">'
            + '<div class="cat-tabc-head" style="display:flex;justify-content:space-between;align-items:center;margin-bottom:.6rem;">'
            + '<span style="font-weight:600">Zone profiles</span>'
            + '<span><button class="btn btn-primary sm" data-zp-add>+ Add profile</button></span></div>'
            + '<div class="table-wrap"><table class="data-table"><thead><tr>'
            + '<th>Name</th><th>Primary NS</th><th>Enabled</th><th>Used by</th><th class="right">Actions</th>'
            + '</tr></thead><tbody>' + rows + '</tbody></table></div></div>';
    }
    // ---------- Pinger & Pulse ----------
    // Changes apply at once; defaults apply only to the NEXT check, existing entries keep their own numbers.
    var PP_SECTIONS = [
        { title: 'Pinger', fields: [
            [ 'pulse_sweep_interval',   'Minimum recheck interval, s' ],
            [ 'pulse_sweep_batch',      'Addresses per batch' ],
            [ 'pulse_sweep_parallel',   'Parallel probes' ],
            [ 'pulse_sweep_probes',     'Probes per address' ],
            [ 'pulse_sweep_timeout_ms', 'Probe timeout, ms' ],
            [ 'pulse_sweep_secondary',  'Include secondary zones', 'check' ] ] },
        { title: 'New check defaults', fields: [
            [ 'pulse_check_interval',   'Every, s' ],
            [ 'pulse_check_timeout_ms', 'Timeout, ms' ],
            [ 'pulse_check_probes',     'Probes per run' ],
            [ 'pulse_check_ok_probes',  'OK probes needed' ],
            [ 'pulse_check_fail_runs',  'Runs to fail' ],
            [ 'pulse_check_ok_runs',    'Runs to recover' ] ] },
        { title: 'History', fields: [
            [ 'pulse_history_days',     'Keep history, days' ] ] }
    ];
    function pulseCard() {
        var p = (ST.pulse && ST.pulse.policy) || {};
        var card = function (sec) {
            return '<div class="card pp-card"><div class="pp-title">' + esc(sec.title) + '</div>'
                + sec.fields.map(function (f) {
                    if (f[2] === 'check') return '<div class="pp-row"><label for="pp-' + esc(f[0]) + '">' + esc(f[1]) + '</label>'
                        + '<input type="checkbox" id="pp-' + esc(f[0]) + '" data-pp="' + esc(f[0]) + '"' + (+p[f[0]] ? ' checked' : '') + '></div>';
                    return '<div class="pp-row"><label>' + esc(f[1]) + '</label>'
                        + '<input class="field-input" data-pp="' + esc(f[0]) + '" inputmode="numeric" value="'
                        + esc(p[f[0]] == null ? '' : p[f[0]]) + '"></div>';
                }).join('') + '</div>';
        };
        return '<div class="pp-grid">' + card(PP_SECTIONS[0]) + card(PP_SECTIONS[1]) + '</div>'
            + card(PP_SECTIONS[2])
            + '<div class="login-error" id="pp-err" style="display:none;"></div>'
            + window.DNSPanel.formActionsHtml({ act: 'pp', cancel: 'Reset' });
    }
    async function pulseSave() {
        var body = {}, err = document.getElementById('pp-err');
        document.querySelectorAll('[data-pp]').forEach(function (i) {
            body[i.getAttribute('data-pp')] = i.type === 'checkbox' ? (i.checked ? '1' : '0') : i.value.trim();
        });
        if (err) { err.style.display = 'none'; err.textContent = ''; }
        try {
            var r = await api('pulse/settings', 'PUT', body);
            ST.pulse.policy = (r && r.data) || ST.pulse.policy;
            render();
        } catch (e) {
            // Show the refusal next to the fields, not in a popup, so the user sees which number failed.
            if (err) { err.textContent = (e && e.message) ? e.message : 'Request failed'; err.style.display = ''; }
        }
    }

    // Users & access: only a mount point here, implemented in js/users_access.js.
    function usersCard() { return '<div id="ua-root"></div>'; }
    function mountUsers() {
        var el = document.getElementById('ua-root');
        if (el && window.UsersAccess) window.UsersAccess.mount(el, ST.users || {});
        else if (el) el.innerHTML = '<div class="card"><p class="text-dim" style="margin:0;">Users & access module failed to load.</p></div>';
    }

    function blankPreset() { return { default_catalog_id: null, primary_ns: '', hostmaster: '', nameservers: [''], soa_ttl: SOA_DEF.soa_ttl, soa_refresh: SOA_DEF.soa_refresh, soa_retry: SOA_DEF.soa_retry, soa_expire: SOA_DEF.soa_expire, soa_minimum: SOA_DEF.soa_minimum }; }
    function normPreset(v) {
        if (!v) return blankPreset();
        return {
            default_catalog_id: (v.default_catalog_id != null ? v.default_catalog_id : null),
            primary_ns: v.primary_ns || '', hostmaster: v.hostmaster || '',
            nameservers: (v.nameservers && v.nameservers.length ? v.nameservers.slice() : ['']),
            soa_ttl: v.soa_ttl, soa_refresh: v.soa_refresh, soa_retry: v.soa_retry, soa_expire: v.soa_expire, soa_minimum: v.soa_minimum
        };
    }

    async function openEditor(id) {
        if (id) {
            try {
                var res = await api('zone-profiles/' + id, 'GET');
                var p = (res && res.data && res.data.profile) || null; if (!p) return;
                ST.editing = { id: p.id, code: p.code, name: p.name, enabled: !!p.enabled, preset: normPreset(p) };
            } catch (e) { fail(e); return; }
        } else {
            ST.editing = { id: null, code: '', name: '', enabled: true, preset: blankPreset() };
        }
        renderModal();
    }

    function overlay() { return document.getElementById('modal-overlay'); }
    function closeModal() { ST.editing = null; var ov = overlay(); if (ov) { ov.style.display = 'none'; ov.innerHTML = ''; } }

    function presetForm() {
        var v = ST.editing.preset;
        var nsRows = v.nameservers.map(function (ns, i) {
            return '<div class="frow" data-ns-row="' + i + '"><input class="field-input sm mono" data-ns="' + i + '" value="' + esc(ns) + '" placeholder="ns1.example.">'
                + ' <a href="#" class="link sm" data-ns-del="' + i + '" style="color:var(--danger)">remove</a></div>';
        }).join('');
        return '<div class="zform-row"><label>Default distribution</label>' + sel('v-catalog', catOpts(), (v.default_catalog_id != null ? String(v.default_catalog_id) : '')) + '</div>'
            + '<div class="zform-row"><label>Primary NS</label><input class="field-input mono" data-v="primary_ns" value="' + esc(v.primary_ns) + '" placeholder="ns1.example."></div>'
            + '<div class="zform-row"><label>Hostmaster</label><input class="field-input mono" data-v="hostmaster" value="' + esc(v.hostmaster) + '" placeholder="hostmaster.example."></div>'
            + '<div class="zform-row"><label>Nameservers</label><div style="flex:1">' + nsRows + '<a href="#" class="link sm" data-ns-add>+ Add nameserver</a></div></div>'
            + '<div class="zform-row"><label>TTL</label><input class="field-input" data-v="soa_ttl" value="' + esc(v.soa_ttl) + '"></div>'
            + '<div class="zform-row"><label>Refresh</label><input class="field-input" data-v="soa_refresh" value="' + esc(v.soa_refresh) + '"></div>'
            + '<div class="zform-row"><label>Retry</label><input class="field-input" data-v="soa_retry" value="' + esc(v.soa_retry) + '"></div>'
            + '<div class="zform-row"><label>Expire</label><input class="field-input" data-v="soa_expire" value="' + esc(v.soa_expire) + '"></div>'
            + '<div class="zform-row"><label>Minimum</label><input class="field-input" data-v="soa_minimum" value="' + esc(v.soa_minimum) + '"></div>';
    }
    function renderModal() {
        var ov = overlay(); if (!ov || !ST.editing) return;
        var ed = ST.editing, isNew = !ed.id;
        ov.style.display = '';
        ov.innerHTML = '<div class="modal"><div class="modal-card zform-wide">'
            + '<div class="modal-head"><h2 class="modal-title">' + (isNew ? 'Add zone profile' : 'Edit zone profile') + '</h2>'
            + '<button type="button" class="modal-x" data-zp-close aria-label="Close">×</button></div>'
            + '<div class="dm-body">'
            + '<div class="zform-row"><label>Name</label><input class="field-input" id="zp-name" value="' + esc(ed.name) + '" placeholder="ITOS"></div>'
            + '<div class="zform-row"><label>Enabled</label><label class="chk"><input type="checkbox" id="zp-enabled"' + (ed.enabled ? ' checked' : '') + '> offered for new zones</label></div>'
            + '<div id="zp-preset" style="margin-top:.8rem;">' + presetForm() + '</div>'
            + '<div class="login-error" id="zp-err" style="display:none;"></div>'
            + '</div>'
            + '<div class="modal-actions"><button type="button" class="btn btn-ghost" data-zp-close>Cancel</button>'
            + '<button type="button" class="btn btn-primary" data-zp-save>' + (isNew ? 'Create profile' : 'Save') + '</button></div>'
            + '</div></div>';
    }

    function collectHeader() {
        var ed = ST.editing; if (!ed) return;
        var n = document.getElementById('zp-name'), en = document.getElementById('zp-enabled');
        if (n) ed.name = n.value.trim();
        if (en) ed.enabled = en.checked;
    }
    function collectPreset() {
        var ed = ST.editing; if (!ed) return; var v = ed.preset;
        var body = document.getElementById('zp-preset'); if (!body) return;
        var cat = document.querySelector('[name="v-catalog"]');
        v.default_catalog_id = (cat && cat.value !== '') ? +cat.value : null;
        body.querySelectorAll('[data-v]').forEach(function (el) { v[el.getAttribute('data-v')] = el.value.trim(); });
        var ns = []; body.querySelectorAll('[data-ns]').forEach(function (el) { ns.push(el.value.trim()); });
        v.nameservers = ns.length ? ns : [''];
    }
    function collectAll() { collectHeader(); collectPreset(); }

    async function reloadProfiles() {
        try { var res = await api('zone-profiles', 'GET'); ST.profiles = (res && res.data && res.data.profiles) || []; } catch (e) { fail(e); }
        render();
    }

    async function saveProfile() {
        collectAll(); var ed = ST.editing; if (!ed) return;
        // Show the error inside the form so the entered values stay and can be fixed in place.
        var errEl = document.getElementById('zp-err');
        var showErr = function (m) { if (errEl) { errEl.textContent = m; errEl.style.display = ''; } };
        if (!ed.name) { showErr('Name is required.'); return; }
        var v = ed.preset;
        var body = { name: ed.name, enabled: ed.enabled ? 1 : 0, preset: {
            default_catalog_id: v.default_catalog_id,
            primary_ns: v.primary_ns, hostmaster: v.hostmaster,
            nameservers: (v.nameservers || []).filter(function (x) { return x && x.trim(); }),
            soa_ttl: +v.soa_ttl, soa_refresh: +v.soa_refresh, soa_retry: +v.soa_retry, soa_expire: +v.soa_expire, soa_minimum: +v.soa_minimum
        } };
        try {
            if (ed.id) await api('zone-profiles/' + ed.id, 'PUT', body);
            else       await api('zone-profiles', 'POST', body);
            closeModal(); await reloadProfiles();
        } catch (e) { showErr((e && e.message) ? e.message : 'Request failed'); }
    }
    async function delProfile(id) {
        if (!(await window.DNSPanel.confirm({ title: 'Delete zone profile', message: 'Delete this profile? Its nameservers are removed. Existing zones keep their profile code label.', okText: 'Delete', danger: true }))) return;
        try { await api('zone-profiles/' + id, 'DELETE'); await reloadProfiles(); } catch (e) { fail(e); }
    }

    document.addEventListener('click', function (e) {
        if (!ST) return;
        var t = e.target;
        var add = t.closest && t.closest('[data-zp-add]');   if (add) { e.preventDefault(); openEditor(null); return; }
        var ed  = t.closest && t.closest('[data-zp-edit]');  if (ed)  { e.preventDefault(); openEditor(+ed.getAttribute('data-zp-edit')); return; }
        var dl  = t.closest && t.closest('[data-zp-del]');   if (dl)  { e.preventDefault(); delProfile(+dl.getAttribute('data-zp-del')); return; }
        var stb = t.closest && t.closest('[data-stab]');     if (stb) { e.preventDefault(); ST.tab = stb.getAttribute('data-stab'); render(); return; }
        var pps = t.closest && t.closest('[data-act="pp-save"]');   if (pps) { e.preventDefault(); pulseSave(); return; }
        var ppc = t.closest && t.closest('[data-act="pp-cancel"]'); if (ppc) { e.preventDefault(); render(); return; }
        if (!ST.editing) return;
        var cl  = t.closest && t.closest('[data-zp-close]'); if (cl)  { e.preventDefault(); closeModal(); return; }
        var sv  = t.closest && t.closest('[data-zp-save]');  if (sv)  { e.preventDefault(); saveProfile(); return; }
        var na  = t.closest && t.closest('[data-ns-add]');   if (na)  { e.preventDefault(); collectAll(); ST.editing.preset.nameservers.push(''); renderModal(); return; }
        var nd  = t.closest && t.closest('[data-ns-del]');   if (nd)  { e.preventDefault(); collectAll(); var arr = ST.editing.preset.nameservers; arr.splice(+nd.getAttribute('data-ns-del'), 1); if (!arr.length) arr.push(''); renderModal(); return; }
    });

    function initTab() {   // priority: ?tab= in URL → localStorage → 'profiles'
        var tab = null;
        // Must match availTabs(): a tab missing here is saved, but a reload returns to the first tab
        // and it looks like the panel forgot.
        var ok = { profiles: 1, import: 1, dynamic: 1, pulse: 1, users: 1, external: 1 };
        try { var u = new URLSearchParams(window.location.search).get('tab'); if (ok[u]) tab = u; } catch (e) {}
        if (!tab) { try { var s = localStorage.getItem('settingsTab'); if (ok[s]) tab = s; } catch (e) {} }
        return tab || 'profiles';
    }
    document.addEventListener('pageLoaded', function (e) {
        if (!e.detail || e.detail.page !== 'settings') return;
        ST = readData(); if (!ST) return;
        ST.tab = initTab();
        render();
    });
})();
