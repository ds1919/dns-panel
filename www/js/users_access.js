/* DNS Panel — Settings → Users & access: near-fullscreen modal.
   User: Profile | Access. Group: Members | Access. The Access tab is one DRAFT with a single Save changes and an
   atomic PUT (user: group_ids+capabilities+zone_rules; group: capabilities+zone_rules). A user's group membership
   is edited here in the same draft, without opening the group editor. Terms: No access/View/Manage; per-zone
   inherit = "From groups" (user) / "No rule" (group). Modal ?user/?group params do not reload the Settings background. */
(function () {
    'use strict';

    function esc(s) { return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'); }
    function api(path, method, body) { return window.DNSPanel.api(path, { method: method, body: body ? JSON.stringify(body) : undefined }); }
    function fail(err) { window.DNSPanel.alert({ message: (err && err.message) ? err.message : 'Request failed' }); }
    function sel(name, opts, value) { return window.DNSPanel.selectHtml(name, opts, value); }
    function val(id) { var e = document.getElementById(id); return e ? e.value.trim() : ''; }
    function selVal(name) { var e = document.querySelector('[name="' + name + '"]'); return e ? e.value : ''; }
    function q1(s) { var b = document.querySelector('#ua-modal .ua-modal-box'); return b ? b.querySelector(s) : null; }

    var ACC = { none: 'No access', read: 'View', write: 'Manage' };
    function accLabel(v) { return v == null ? '—' : (ACC[v] || v); }
    var accOpts = [{ value: 'none', label: 'No access' }, { value: 'read', label: 'View' }, { value: 'write', label: 'Manage' }];
    // In the GROUP editor 'none' means "no access from THIS group" (access is additive: another group may still
    // grant it). For a user 'none' is a personal override of the result, so it stays "No access".
    var accOptsGroup = [{ value: 'none', label: 'No access from this group' }, { value: 'read', label: 'View' }, { value: 'write', label: 'Manage' }];
    // The "no own rule" label depends on context: user — "From groups" everywhere;
    // group per-zone — "Use group defaults", all zones — "No default access".
    function ovrOpts(mode, level) {
        var inh = (mode === 'group')
            ? (level === 'all' ? 'No default access' : 'Use group defaults')
            : 'From groups';
        return [{ value: 'inherit', label: inh }].concat(mode === 'group' ? accOptsGroup : accOpts);
    }

    var D = {};
    var rootEl = null, sub = (window.DNSPanel && window.DNSPanel.store('uaSub')) || 'ulist', panel = null, wired = false;

    window.UsersAccess = { mount: mount, destroy: destroy };

    function mount(el, data) {
        D = data || {}; rootEl = el; wire(); renderList();
        var qp = new URLSearchParams(location.search), uid = qp.get('user'), gid = qp.get('group');
        if (uid && /^\d+$/.test(uid)) openUser(+uid, { restore: true });
        else if (gid && /^\d+$/.test(gid)) openGroup(+gid, { restore: true });
    }
    function destroy() { closeModalDom(); closeDialog(); }

    function setUrl(kind, id, mode) {
        try {
            var u = new URL(location.href); u.searchParams.set('tab', 'users');
            u.searchParams.delete('user'); u.searchParams.delete('group');
            if (kind) u.searchParams.set(kind, id);
            var url = u.pathname + u.search + u.hash;
            if (mode === 'push') history.pushState(history.state, '', url); else history.replaceState(history.state, '', url);
        } catch (e) {}
    }
    function fmtWhen(v) { if (!v) return '<span class="text-mute">never</span>'; return esc(window.DNSPanel.fmtTime(v)); }

    async function reload() {
        try { var r = await api('users', 'GET'); D.list = (r && r.data && r.data.users) || []; } catch (e) { fail(e); }
        try { var g = await api('permission-groups', 'GET'); D.groups = (g && g.data && g.data.groups) || []; } catch (e) {}
        renderList();
    }
    function renderList() {
        if (!rootEl) return;
        var subBtn = function (id, label) { return '<button class="dist-tab' + (sub === id ? ' active' : '') + '" data-ua-sub="' + id + '">' + label + '</button>'; };
        rootEl.innerHTML = '<div class="card"><div class="dist-tabs" style="margin:.1rem 0 .9rem;">' + subBtn('ulist', 'Users') + subBtn('glist', 'Groups') + '</div>'
            + (sub === 'glist' ? groupsTable() : usersTable()) + '</div>';
    }
    function authChips(u) {
        var b = []; if (u.has_password) b.push('password'); if (u.has_totp) b.push('2FA'); if (u.cert_count) b.push('cert');
        return b.length ? b.map(function (x) { return '<span class="chip">' + x + '</span>'; }).join(' ') : '<span class="text-mute">none</span>';
    }
    function userRowHtml(u) {
        return '<tr class="ua-row" data-ua-open-user="' + u.id + '"><td><b>' + esc(u.username) + '</b>'
            + (u.display_name ? '<div class="text-mute" style="font-size:12px">' + esc(u.display_name) + '</div>' : '') + '</td>'
            + '<td>' + (u.is_active ? '<span class="chip">Active</span>' : '<span class="chip" style="opacity:.6">Disabled</span>') + '</td>'
            + '<td>' + authChips(u) + '</td><td>' + (u.group_count || 0) + '</td>'
            + '<td>' + (u.is_admin ? '<span class="chip">Admin</span>' : '<span class="text-mute">—</span>') + '</td>'
            + '<td>' + fmtWhen(u.last_login) + '</td>'
            + '<td class="right nowrap"><a href="#" class="link" data-ua-open-user="' + u.id + '">Manage</a></td></tr>';
    }
    function groupRowHtml(g) {
        return '<tr class="ua-row" data-ua-open-group="' + g.id + '"><td><b>' + esc(g.name) + '</b></td><td>' + esc(g.description || '') + '</td>'
            + '<td>' + (g.member_count || 0) + '</td><td>' + (g.cap_count || 0) + '</td>'
            + '<td class="right nowrap"><a href="#" class="link" data-ua-open-group="' + g.id + '">Manage</a></td></tr>';
    }
    function usersTable() {
        var rows = (D.list || []).map(userRowHtml).join('') || '<tr><td colspan="7" class="text-dim" style="padding:1rem;">No users yet — click <b>Add user</b>.</td></tr>';
        return '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:.6rem;">'
            + '<span style="font-weight:600">Users</span><button class="btn btn-primary sm" data-ua-add-user>+ Add user</button></div>'
            + '<div class="table-wrap"><table class="data-table"><thead><tr><th>User</th><th>Status</th><th>Auth</th><th>Groups</th><th>Access</th><th>Last login</th><th class="right">Actions</th></tr></thead><tbody>' + rows + '</tbody></table></div>';
    }
    function groupsTable() {
        var rows = (D.groups || []).map(groupRowHtml).join('') || '<tr><td colspan="5" class="text-dim" style="padding:1rem;">No permission groups yet — click <b>Add group</b>.</td></tr>';
        return '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:.6rem;">'
            + '<span style="font-weight:600">Permission groups</span><button class="btn btn-primary sm" data-ua-add-group>+ Add group</button></div>'
            + '<div class="table-wrap"><table class="data-table"><thead><tr><th>Name</th><th>Description</th><th>Members</th><th>Capabilities</th><th class="right">Actions</th></tr></thead><tbody>' + rows + '</tbody></table></div>';
    }

    function dialog(title, bodyHtml, actions) {
        var ov = document.getElementById('modal-overlay'); if (!ov) return;
        ov.style.display = ''; ov.innerHTML = '<div class="modal"><div class="modal-card"><div class="modal-head">'
            + '<h2 class="modal-title">' + esc(title) + '</h2><button type="button" class="modal-x" data-ua-dlg-close aria-label="Close">×</button></div>'
            + '<div class="dm-body">' + bodyHtml + '</div><div class="modal-actions">' + actions + '</div></div></div>';
    }
    function closeDialog() { var ov = document.getElementById('modal-overlay'); if (ov) { ov.style.display = 'none'; ov.innerHTML = ''; } }
    function addUserDialog() {
        dialog('Add user',
            '<div class="zform-row"><label>Username</label><input class="field-input mono" id="ua-nu-username" placeholder="jdoe"></div>'
            + '<div class="zform-row"><label>Display name</label><input class="field-input" id="ua-nu-display" placeholder="John Doe"></div>'
            + '<div class="zform-row"><label>Email</label><input class="field-input" id="ua-nu-email" placeholder="jdoe@example.com"></div>',
            '<button class="btn btn-ghost" data-ua-dlg-close>Cancel</button><button class="btn btn-primary" data-ua-dlg-save-user>Create user</button>');
    }
    function addGroupDialog() {
        dialog('Add permission group',
            '<div class="zform-row"><label>Name</label><input class="field-input" id="ua-ng-name" placeholder="DNS Operators"></div>'
            + '<div class="zform-row"><label>Description</label><input class="field-input" id="ua-ng-desc" placeholder="Manage zones only"></div>',
            '<button class="btn btn-ghost" data-ua-dlg-close>Cancel</button><button class="btn btn-primary" data-ua-dlg-save-group>Create group</button>');
    }
    async function saveNewUser() {
        var un = val('ua-nu-username'); if (!un) { window.DNSPanel.alert({ message: 'Username is required.' }); return; }
        try { var r = await api('users', 'POST', { username: un, display_name: val('ua-nu-display'), email: val('ua-nu-email') }); closeDialog(); await reload(); openUser(r.data.id); } catch (e) { fail(e); }
    }
    async function saveNewGroup() {
        var nm = val('ua-ng-name'); if (!nm) { window.DNSPanel.alert({ message: 'Name is required.' }); return; }
        try { var r = await api('permission-groups', 'POST', { name: nm, description: val('ua-ng-desc') }); closeDialog(); await reload(); openGroup(r.data.id); } catch (e) { fail(e); }
    }

    function ensureModal() {
        var w = document.getElementById('ua-modal'); if (w) return w;
        w = document.createElement('div'); w.id = 'ua-modal';
        w.innerHTML = '<div class="ua-backdrop" data-ua-close></div><div class="ua-modal-box" role="dialog" aria-modal="true"></div>';
        document.body.appendChild(w); return w;
    }
    function closeModalDom() { panel = null; var w = document.getElementById('ua-modal'); if (w) w.remove(); }
    function accessDirty() { return panel && panel.draft && panel.origJson && JSON.stringify(panel.draft) !== panel.origJson; }
    function guardLeave() {
        if (!accessDirty()) return Promise.resolve(true);
        return window.DNSPanel.confirm({ title: 'Discard changes?', message: 'You have unsaved access changes. Discard them?', okText: 'Discard', cancelText: 'Keep editing', danger: true });
    }
    function closePanel() {
        guardLeave().then(function (ok) {
            if (!ok) return; if (panel) panel.draft = null;
            // Closing does not call history.back, so the Settings background never reloads. Opening uses
            // replaceState (no history entry), so dropping ?user/?group is enough.
            closeModalDom(); setUrl(null, null, 'replace');
        });
    }
    async function openUser(id, opts) {
        opts = opts || {};
        try { var r = await api('users/' + id, 'GET'); } catch (e) { fail(e); return; }
        panel = { kind: 'user', id: id, data: r.data.user, tab: (panel && panel.kind === 'user' && panel.id === id ? panel.tab : 'profile'), draft: null };
        histMode('user', id, opts); renderPanel();
    }
    async function openGroup(id, opts) {
        opts = opts || {};
        try { var r = await api('permission-groups/' + id, 'GET'); } catch (e) { fail(e); return; }
        panel = { kind: 'group', id: id, data: r.data.group, tab: (panel && panel.kind === 'group' && panel.id === id ? panel.tab : 'members'), draft: null };
        histMode('group', id, opts); renderPanel();
    }
    function histMode(kind, id, opts) {
        // The modal uses replaceState, so closing needs no history.back. fromPop: URL is already current (popstate).
        if (!opts.fromPop) setUrl(kind, id, 'replace');
    }
    // Refetch the object's data in place (no re-render). Returns true/false.
    async function reloadData() {
        if (!panel) return false;
        try {
            if (panel.kind === 'user') { var r = await api('users/' + panel.id, 'GET'); panel.data = r.data.user; }
            else { var g = await api('permission-groups/' + panel.id, 'GET'); panel.data = g.data.group; }
        } catch (e) { fail(e); return false; }
        return true;
    }
    function headTitle() { return panel.kind === 'user' ? esc(panel.data.username) : esc(panel.data.name); }
    function headStatus() {
        if (panel.kind === 'user') return panel.data.is_active ? '<span class="chip">Active</span>' : '<span class="chip" style="opacity:.6">Disabled</span>';
        var n = panel.data.members ? panel.data.members.length : 0;
        return '<span class="chip">' + n + ' member' + (n === 1 ? '' : 's') + '</span>';
    }
    function bodyFor() {
        if (panel.kind === 'user') return panel.tab === 'access' ? { html: accessTab('user', panel.data), cls: ' ua-body-wide' } : { html: userProfile(panel.data), cls: ' ua-body-blocks' };
        return panel.tab === 'access' ? { html: accessTab('group', panel.data), cls: ' ua-body-wide' } : { html: groupMembers(panel.data), cls: '' };
    }
    function afterBody() {
        if (panel.kind === 'user' && panel.tab === 'profile') loadProfileSessions();
        if (panel.tab === 'access') loadZoneData(panel.kind);
    }
    // FULL render of the shell (head + tabs + save controls) and body; only on open or tab switch.
    function renderPanel() {
        var w = ensureModal(), box = w.querySelector('.ua-modal-box');
        // Height follows content everywhere except Access, which scrolls inside and needs a tall window.
        box.classList.toggle('ua-box-fit', panel.tab !== 'access');
        var tabs = panel.kind === 'user' ? [['profile', 'Profile'], ['access', 'Access']] : [['members', 'Members'], ['access', 'Access']];
        var b = bodyFor();
        var tabBar = tabs.map(function (t) { return '<button class="ua-tab' + (panel.tab === t[0] ? ' active' : '') + '" data-ua-tab="' + t[0] + '">' + t[1] + '</button>'; }).join('');
        // Access save controls sit on the right of the tab row to avoid an extra row.
        var saveCtl = (panel.tab === 'access')
            ? '<div class="ua-tabsave"><span id="ua-dirty" class="text-mute" style="font-size:12px"></span>'
                + '<button class="btn btn-ghost sm" data-ua-revert disabled>Revert</button>'
                + '<button class="btn btn-primary sm" data-ua-save-access disabled>Save changes</button></div>'
            : '';
        box.innerHTML = '<div class="ua-head"><div class="ua-head-main"><h2>' + headTitle() + '</h2>' + headStatus() + '</div>'
            + '<button type="button" class="modal-x" data-ua-close aria-label="Close">×</button></div>'
            + '<div class="ua-tabs">' + tabBar + saveCtl + '</div><div class="ua-body' + (b.cls || '') + '">' + b.html + '</div>';
        afterBody();
    }
    // USER: Profile. Sections have ids so they can be updated in place.
    // 2FA is optional and has three states, each with its own actions:
    //   enrolled          → Reset (lost phone: unbind and ask to enroll again) | Turn off;
    //   not enrolled, required → asked to enroll at next sign-in | stop requiring;
    //   not enrolled      → the user enables it in Account | Require.
    function authRowsHtml(u) {
        var pw = u.password && u.password.set ? (u.password.must_change ? 'Configured — change required' : 'Configured') : 'Not set';
        var t  = u.totp || {}, on = !!t.enrolled, req = !!t.required;
        var tip = 'Optional. People turn it on for themselves on their Account page. Reset unbinds the current '
                + 'app and asks for a new one at next sign-in — that is the fix for a lost phone. Turn off stops '
                + 'asking for it at all.';
        var state = on   ? 'Enabled — asked at sign-in'
                  : req  ? 'Not set up — asked to set up an app at next sign-in'
                         : 'Off — sign-in asks for the password only';
        var acts  = on   ? '<button class="btn btn-ghost sm" data-ua-totp-reset>Reset</button>'
                         + '<button class="btn btn-ghost sm" data-ua-totp-off>Turn off</button>'
                  : req  ? '<button class="btn btn-ghost sm" data-ua-totp-require="0">Stop asking</button>'
                         : '<button class="btn btn-ghost sm" data-ua-totp-require="1">Require</button>';
        return '<div class="ua-secrow"><div><b>Password</b><div class="text-mute" style="font-size:12px">' + esc(pw) + '</div></div><button class="btn btn-ghost sm" data-ua-pw>Reset</button></div>'
            + '<div class="ua-secrow"><div><b data-tip="' + esc(tip) + '">Two-factor</b><div class="text-mute" style="font-size:12px">'
            + state + '</div></div><span class="ua-secacts">' + acts + '</span></div>';
    }
    function certListHtml(u) {
        var certs = (u.identities || []).filter(function (i) { return i.type === 'cert'; });
        return certs.map(function (i) { return '<div class="ua-line"><span class="mono">CN: ' + esc(i.principal) + '</span><a href="#" class="link" data-ua-ident-del="' + i.id + '" style="color:var(--danger);margin-left:auto">remove</a></div>'; }).join('') || '<div class="text-mute" style="font-size:13px">None.</div>';
    }
    // The profile answers two questions, WHO and HOW THEY SIGN IN: two columns, with current sessions full
    // width below (session rows are long). Groups are deliberately absent: they explain permissions and are
    // configured on the Access tab. Certificates are a sign-in method, so they are part of "Sign-in".
    function block(title, body, cls) {
        return '<section class="ua-block' + (cls ? ' ' + cls : '') + '"><div class="ua-block-hd">' + title + '</div>' + body + '</section>';
    }
    function userProfile(u) {
        var profile = '<div class="zform-row"><label>Username</label><input class="field-input mono" value="' + esc(u.username) + '" readonly></div>'
            + '<div class="zform-row"><label>Display name</label><input class="field-input" id="ua-p-display" value="' + esc(u.display_name || '') + '"></div>'
            + '<div class="zform-row"><label>Email</label><input class="field-input" id="ua-p-email" value="' + esc(u.email || '') + '"></div>'
            + '<div class="zform-row"><label>Status</label><label class="chk"><input type="checkbox" id="ua-p-active"' + (u.is_active ? ' checked' : '') + '> active</label></div>'
            + '<div class="ua-actions-row"><button class="btn btn-primary" data-ua-save-profile>Save</button>'
            + '<button class="btn btn-danger" data-ua-del-user style="margin-left:auto">Delete user</button></div>';
        var signin = '<div id="ua-auth-block">' + authRowsHtml(u) + '</div>'
            + '<div class="ua-secrow"><div><b>Session lifetime</b><div class="text-mute" style="font-size:12px">How long a sign-in stays valid</div></div><span id="ua-sesspol-box"></span></div>'
            + '<div class="ua-block-sub">Client certificates (mTLS)</div>'
            + '<div id="ua-cert-list">' + certListHtml(u) + '</div>'
            + '<div class="ua-inline"><input class="field-input sm mono" id="ua-ident-cn" placeholder="client-cert CN"> <button class="btn btn-ghost sm" data-ua-ident-add>Add cert CN</button></div>';
        var sess = '<div class="ua-secrow"><div class="text-mute" style="font-size:12px" id="ua-sess-count">…</div>'
            + '<button class="btn btn-ghost sm" data-ua-sess-revokeall>Revoke all</button></div>'
            + '<div id="ua-sesslist"></div>';
        return '<div class="ua-blocks">'
            + block('Profile', profile)
            + block('Sign-in', signin)
            + block('Active sessions', sess, 'ua-block-wide')
            + '</div>'
            + '<div style="margin-top:1rem"><a href="#" class="link" data-ua-audit>View activity in Audit log →</a></div>';
    }
    var TTL_OPTS = [{ value: '', label: 'System default' }, { value: '86400', label: '1 day' }, { value: '604800', label: '7 days' }, { value: '2592000', label: '30 days' }, { value: '31536000', label: '1 year' }, { value: '157680000', label: '5 years' }];
    function deviceLabel(ua) {
        if (!ua) return 'unknown device';
        var b = /Edg\//.test(ua) ? 'Edge' : /Chrome\//.test(ua) ? 'Chrome' : /Firefox\//.test(ua) ? 'Firefox' : /Safari\//.test(ua) ? 'Safari' : /curl|wget|Perl/.test(ua) ? 'CLI' : 'Browser';
        var os = /Windows/.test(ua) ? 'Windows' : /Mac OS X|Macintosh/.test(ua) ? 'macOS' : /Android/.test(ua) ? 'Android' : /iPhone|iPad/.test(ua) ? 'iOS' : /Linux/.test(ua) ? 'Linux' : '';
        return b + (os ? ' · ' + os : '');
    }
    async function loadProfileSessions() {
        var cnt = q1('#ua-sess-count'), listEl = q1('#ua-sesslist'), polBox = q1('#ua-sesspol-box'); if (!cnt) return;
        try {
            var r = await api('users/' + panel.id + '/sessions', 'GET'), d = r.data || {}, rows = d.sessions || [];
            var ovr = d.session_ttl_override, opts = TTL_OPTS.slice(), curTtl = (ovr == null) ? '' : String(ovr);
            if (ovr != null && !opts.some(function (o) { return o.value === curTtl; })) opts.push({ value: curTtl, label: Math.round(ovr / 86400) + ' days' });
            if (polBox) polBox.innerHTML = sel('ua-sesspol', opts, curTtl);
            cnt.textContent = rows.length + (rows.length === 1 ? ' active session' : ' active sessions');
            if (listEl) listEl.innerHTML = rows.length ? ('<div class="ua-sesslist">' + rows.map(function (s) {
                var when = s.created_at ? new Date(s.created_at * 1000).toISOString().replace('T', ' ').replace(/:\d\d\..*$/, '') : '';
                var exp = s.expires_at ? new Date(s.expires_at * 1000).toISOString().slice(0, 10) : '';
                return '<div class="ua-line"><span><b>' + esc(deviceLabel(s.user_agent)) + '</b>' + (s.is_current ? ' <span class="chip">this session</span>' : '') + (s.remember ? ' <span class="text-mute" style="font-size:11px">remembered</span>' : '') + '</span>'
                    + '<span class="text-mute mono" style="font-size:12px">' + esc(s.ip || '—') + '</span>'
                    + '<span class="text-mute" style="font-size:12px">' + esc(when) + ' · exp ' + esc(exp) + '</span>'
                    + '<a href="#" class="link" data-ua-sess-revoke="' + s.id + '" style="margin-left:auto' + (s.is_current ? ';color:var(--text-mute)' : ';color:var(--danger)') + '">Revoke</a></div>';
            }).join('') + '</div>') : '<div class="text-mute" style="font-size:13px">No active sessions.</div>';
        } catch (e) { cnt.textContent = 'failed to load'; }
    }

    // ACCESS (user + group): a single draft.
    function buildDraft() {
        var d = { caps: {}, denied: {}, all: null, zones: {} };
        var o = panel.data;
        if (panel.kind === 'user') { d.groups = {}; (o.groups || []).forEach(function (g) { d.groups[g.id] = true; }); (o.direct_capabilities || []).forEach(function (c) { d.caps[c] = true; }); (o.denied_capabilities || []).forEach(function (c) { d.denied[c] = true; }); (o.zone_overrides || []).forEach(applyRule); }
        else { (o.capabilities || []).forEach(function (c) { d.caps[c] = true; }); (o.zone_access || []).forEach(applyRule); }
        function applyRule(r) { if (r.scope === 'all') d.all = r.access; else if (r.scope === 'zone') d.zones[r.zone_id] = r.access; }
        panel.draft = d; panel.origJson = JSON.stringify(d);
    }
    function draftPayload() {
        var d = panel.draft;
        return { group_ids: Object.keys(d.groups).filter(function (k) { return d.groups[k]; }).map(Number),
                 capabilities: Object.keys(d.caps).filter(function (k) { return d.caps[k]; }),
                 denied_capabilities: Object.keys(d.denied).filter(function (k) { return d.denied[k]; }),
                 zone_rules: draftRules(d) };
    }
    // Canonical preview from the server (one resolver, none in JS). Fills panel.eff (zones: group/group_source/
    // effective, additive) and panel.capsrc (sources of panel permissions). Returns true/false.
    // seq guard: only the latest request's response is applied, so a stale one cannot overwrite a newer one.
    var _pvSeq = 0;
    async function runPreview() {
        var seq = ++_pvSeq;
        try { var r = await api('users/' + panel.id + '/access/preview', 'POST', draftPayload()); }
        catch (e) { return false; }
        if (seq !== _pvSeq) return false;   // stale response: ignore
        var dd = (r && r.data) || {};
        panel.capsrc = (dd.capabilities && dd.capabilities.sources) || {};
        panel.eff = dd.zones || { zones: [] };
        return true;
    }
    var _pvTimer = null;
    // Draft changed: mark dirty, (user) debounce a server preview, then update IN PLACE the permission sources
    // (left panel) and the Access-from-groups/Effective/counter cells in existing rows. The table is not rebuilt
    // (scroll and open dropdowns survive) and the background is not refreshed.
    function schedulePreview() {
        updateDirty();
        if (!panel || panel.kind !== 'user') return;
        clearTimeout(_pvTimer);
        _pvTimer = setTimeout(function () {
            if (!panel || panel.kind !== 'user' || panel.tab !== 'access') return;
            runPreview().then(function (ok) { if (!ok) return; renderLeft(); updateZoneCells('user'); });
        }, 250);
    }
    function accessTab(mode, o) {
        if (!panel.draft) buildDraft();
        // Save controls are in the tab row (renderPanel). Settings (sticky) on the left, zone table on the right.
        return '<div class="ua-access"><div class="ua-access-l" id="ua-accessleft"></div>'
            + '<div class="ua-access-r"><div class="ua-toolbar" id="ua-ztoolbar"></div><div id="ua-zrows"></div></div></div>';
    }
    function zoneDefaultsHtml(mode) {
        var d = panel.draft;
        return '<div class="ua-sect">Zone defaults</div>'
            + '<div class="ua-zline"><span class="ua-zlabel">All zones</span>' + sel('ua-zdefault', ovrOpts(mode, 'all'), d.all == null ? 'inherit' : d.all) + '</div>';
    }
    function renderLeft() {
        var box = q1('#ua-accessleft'); if (!box) return; var d = panel.draft, _lt = box.scrollTop;
        if (panel.kind === 'user') {
            var capsrc = panel.capsrc || {};   // {cap:{groups:[{id,name}], direct?}} from the draft preview
            // Access groups: chips with × plus one "Add group…" dropdown.
            var chips = Object.keys(d.groups).filter(function (k) { return d.groups[k]; }).map(function (gid) {
                var g = (D.groups || []).filter(function (x) { return x.id === +gid; })[0]; if (!g) return '';
                return '<span class="ua-chip">' + esc(g.name) + ' <a href="#" class="ua-x" data-ua-grp-del="' + g.id + '">×</a></span>';
            }).join(' ') || '<span class="text-mute" style="font-size:13px">No groups</span>';
            var addable = (D.groups || []).filter(function (g) { return !d.groups[g.id]; }).map(function (g) { return { value: String(g.id), label: g.name }; });
            var addRow = addable.length ? sel('ua-addgrp', [{ value: '', label: 'Add group…' }].concat(addable), '') : '';
            // One list of panel permissions, in blocks as for a group. Checked = the permission is actually held.
            // A group-granted permission can be removed for this person (a personal deny; "Denied ×" undoes it).
            // Unchecked → checking creates a personal grant. Personal → checked and editable.
            var permBlocks = (D.cap_groups || []).map(function (grp) {
                var rows = grp.caps.map(function (c) {
                    var s = capsrc[c.key] || {}, gn = (s.groups || []).map(function (g) { return g.name; });
                    var byGroup = gn.length > 0, personal = !!d.caps[c.key], denied = !!d.denied[c.key];
                    var checked = !denied && (byGroup || personal);
                    var from = byGroup ? '<span class="text-mute">From: ' + esc(gn.join(', ')) + '</span>' : '';
                    var meta = denied ? (from + ' <a href="#" class="ua-x" data-ua-cap-undeny="' + c.key + '">Denied ×</a>')
                             : byGroup && personal ? (from + ' <a href="#" class="ua-x" data-ua-cap-rmpersonal="' + c.key + '">Personal grant ×</a>')
                             : byGroup ? from
                             : personal ? '<span class="text-mute">Personal</span>' : '';
                    return '<label class="chk ua-perm"><input type="checkbox" data-ua-dcap="' + c.key + '"' + (checked ? ' checked' : '') + '>'
                        + '<span' + (c.hint ? ' data-tip="' + esc(c.hint) + '"' : '') + '>' + esc(c.label) + '</span>'
                        + '<span class="ua-perm-meta" style="margin-left:auto">' + meta + '</span></label>';
                }).join('');
                return '<div class="ua-perm-group"><div class="ua-perm-grouphd">' + esc(grp.group) + '</div>' + rows + '</div>';
            }).join('');
            box.innerHTML = '<div class="ua-sect">Access groups</div><div class="ua-list" style="margin-bottom:.4rem">' + chips + '</div>' + addRow
                + '<p class="text-mute" style="font-size:12px;margin:.4rem 0 .2rem">Permissions from selected groups are combined. Personal access can override the result.</p>'
                + zoneDefaultsHtml('user')
                + '<div class="ua-sect">Panel permissions</div>' + permBlocks;
        } else {
            var gp = (D.cap_groups || []).map(function (grp) {
                var rows = grp.caps.map(function (c) { return '<label class="chk ua-perm"><span' + (c.hint ? ' data-tip="' + esc(c.hint) + '"' : '') + '>' + esc(c.label) + '</span><input type="checkbox" data-ua-dcap="' + c.key + '"' + (d.caps[c.key] ? ' checked' : '') + ' style="margin-left:auto"></label>'; }).join('');
                return '<div class="ua-perm-group"><div class="ua-perm-grouphd">' + esc(grp.group) + '</div>' + rows + '</div>';
            }).join('');
            box.innerHTML = '<div class="ua-sect">Panel permissions</div>' + gp + zoneDefaultsHtml('group')
                + '<p class="text-mute" style="font-size:12px;margin:.5rem 0 0">‘No access’ here only removes access <b>from this group</b> — another group may still grant it.</p>';
        }
        box.scrollTop = _lt;   // keep left column scroll across the in-place repaint
    }
    async function loadZoneData(mode) {
        var box = q1('#ua-zrows'); if (box) box.innerHTML = '<div class="ua-loading text-mute">Computing…</div>';
        if (mode === 'user') {
            if (!(await runPreview())) { renderLeft(); if (box) box.innerHTML = '<div class="text-mute">Failed to compute access.</div>'; return; }
        } else {
            panel.eff = { zones: (D.zones || []).map(function (z) { return { zone_id: z.id, name: z.name }; }) };
        }
        renderLeft();
        panel.zsel = {}; panel.zf = panel.zf || { q: '', eff: '', ovr: '', sort: 'name', dir: 1 };
        renderToolbar(mode); renderZoneRows(mode); updateDirty();
    }
    function renderToolbar(mode) {
        var box = q1('#ua-ztoolbar'); if (!box) return; var f = panel.zf;
        var pLabel = mode === 'group' ? 'Group rule' : 'Personal';
        box.innerHTML = '<input class="field-input" id="ua-zq" placeholder="Search zones…" value="' + esc(f.q) + '">'
            + sel('ua-feff', [{ value: '', label: 'Effective: all' }, { value: 'write', label: 'Effective: Manage' }, { value: 'read', label: 'Effective: View' }, { value: 'none', label: 'Effective: No access' }], f.eff)
            + sel('ua-fovr', [{ value: '', label: pLabel + ': all' }, { value: 'set', label: pLabel + ': set' }, { value: 'inherit', label: pLabel + ': ' + (mode === 'group' ? 'group defaults' : 'from groups') }], f.ovr);
    }
    function ovrOf(z) { var p = panel.draft.zones[z.zone_id]; return p == null ? 'inherit' : p; }
    // USER: the only client-side logic is that a personal zone override shows immediately (it always wins);
    // everything else (additive groups + personal all-zones rule) is computed by the SERVER (z.effective from preview).
    // GROUP: its own rules.
    function resultOf(z, mode) {
        var p = panel.draft.zones[z.zone_id]; if (p != null) return p;
        if (mode === 'user') return (z.effective == null ? 'none' : z.effective);
        if (panel.draft.all != null) return panel.draft.all;
        return 'none';
    }
    function renderZoneRows(mode) {
        var box = q1('#ua-zrows'); if (!box || !panel.eff) return; var f = panel.zf, d = panel.draft;
        var zones = (panel.eff.zones || []).slice().filter(function (z) {
            if (f.q && z.name.toLowerCase().indexOf(f.q) < 0) return false;
            if (f.eff && resultOf(z, mode) !== f.eff) return false;
            if (f.ovr === 'set' && d.zones[z.zone_id] == null) return false;
            if (f.ovr === 'inherit' && d.zones[z.zone_id] != null) return false;
            return true;
        });
        var rank = function (a) { return ['none', 'read', 'write'].indexOf(a); };
        zones.sort(function (a, b) { var av, bv; if (f.sort === 'eff') { av = rank(resultOf(a, mode)); bv = rank(resultOf(b, mode)); } else if (f.sort === 'group') { av = rank(a.group); bv = rank(b.group); } else { av = a.name; bv = b.name; } return (av < bv ? -1 : av > bv ? 1 : 0) * f.dir; });
        panel.zfilteredIds = zones.map(function (z) { return z.zone_id; });   // visible after filtering, for select-all
        var head = mode === 'user'
            ? '<th data-ua-sort="name">Zone</th><th data-ua-sort="group">Access from groups</th><th>Personal access</th><th data-ua-sort="eff">Effective</th>'
            : '<th data-ua-sort="name">Zone</th><th>Group setting</th><th data-ua-sort="eff">Effective</th>';
        var body = zones.map(function (z) {
            var groupCell = mode === 'user' ? '<td data-ua-cell-group="' + z.zone_id + '">' + groupCellHtml(z) + '</td>' : '';
            var cols = '<td class="mono">' + esc(z.name) + '</td>'
                + groupCell
                + '<td>' + sel('ua-zovr-' + z.zone_id, ovrOpts(mode, 'zone'), ovrOf(z)) + '</td>'
                + '<td data-ua-cell-eff="' + z.zone_id + '"><b>' + accLabel(resultOf(z, mode)) + '</b></td>';
            return '<tr data-ua-zrow="' + z.zone_id + '"' + (zoneRowChanged(z) ? ' class="ua-changed"' : '') + '><td><input type="checkbox" data-ua-zsel="' + z.zone_id + '"' + (panel.zsel[z.zone_id] ? ' checked' : '') + '></td>' + cols + '</tr>';
        }).join('') || '<tr><td colspan="6" class="text-mute" style="padding:.8rem">No zones match.</td></tr>';
        box.innerHTML = '<div class="ua-zone-status"><div class="ua-summary">' + countersHtml(mode) + '</div>'
            + '<div id="ua-bulkbar">' + bulkHtml(mode) + '</div></div>'
            + '<div class="ua-zone-scroll"><table class="data-table ua-ztbl"><thead><tr><th style="width:24px"><input type="checkbox" data-ua-zselall></th>' + head + '</tr></thead><tbody>' + body + '</tbody></table></div>';
        applySelHeader();   // indeterminate cannot be set via an attribute
    }
    // "Changed" = draft per-zone override differs from the SAVED one (not from the preview echo of the draft).
    function zoneRowChanged(z) { return (panel.draft.zones[z.zone_id] == null ? 'inherit' : panel.draft.zones[z.zone_id]) !== zoneOrigOverride(z.zone_id); }
    function groupCellHtml(z) {
        return (z.group === 'none' || z.group == null) ? '<span class="text-mute">No access</span>'
            : (accLabel(z.group) + (z.group_source ? ' <span class="text-mute" style="font-size:12px">· ' + esc(z.group_source) + '</span>' : ''));
    }
    function countersHtml(mode) {
        var cnt = { write: 0, read: 0, none: 0 }; (panel.eff.zones || []).forEach(function (z) { var rr = resultOf(z, mode); cnt[rr] = (cnt[rr] || 0) + 1; });
        return '<span class="chip">' + cnt.write + ' Manage</span> <span class="chip">' + cnt.read + ' View</span> <span class="chip">' + cnt.none + ' No access</span>';
    }
    // In place after preview: update Access-from-groups / Effective cells and counters without rebuilding the
    // table (keeps .ua-zone-scroll and open dropdowns). Full re-render only for filter/sort.
    function updateZoneCells(mode) {
        var byId = {}; (panel.eff.zones || []).forEach(function (z) { byId[z.zone_id] = z; });
        var sm = q1('.ua-summary'); if (sm) sm.innerHTML = countersHtml(mode);
        document.querySelectorAll('#ua-modal [data-ua-cell-eff]').forEach(function (td) {
            var z = byId[td.getAttribute('data-ua-cell-eff')]; if (z) td.innerHTML = '<b>' + accLabel(resultOf(z, mode)) + '</b>';
        });
        if (mode === 'user') document.querySelectorAll('#ua-modal [data-ua-cell-group]').forEach(function (td) {
            var z = byId[td.getAttribute('data-ua-cell-group')]; if (z) td.innerHTML = groupCellHtml(z);
        });
    }
    // In-place repaint after a draft edit (zone override / defaults / bulk): eff cells, counters, changed-row
    // highlight and selection, without rebuilding <table>. A full rebuild only when an eff/personal filter is
    // active (the edit may add or drop a row) or on sort.
    function repaintZones(mode) {
        if (panel.zf.eff || panel.zf.ovr) { renderZoneRows(mode); return; }
        updateZoneCells(mode);
        document.querySelectorAll('#ua-modal tr[data-ua-zrow]').forEach(function (tr) {
            tr.classList.toggle('ua-changed', zoneRowChanged({ zone_id: tr.getAttribute('data-ua-zrow') }));
        });
        syncSelection();
    }
    function bulkHtml(mode) {
        var selN = Object.keys(panel.zsel).filter(function (k) { return panel.zsel[k]; }).length;
        return selN ? ('<div class="ua-bulk"><b>' + selN + ' selected</b> · Set ' + sel('ua-bulkval', ovrOpts(mode || panel.kind, 'zone'), 'inherit') + ' <button class="btn btn-ghost sm" data-ua-bulk-apply>Apply</button> <a href="#" class="link" data-ua-bulk-clear>clear</a></div>') : '';
    }
    // Header checkbox state from VISIBLE rows: all → checked, some → indeterminate.
    function applySelHeader() {
        var h = document.querySelector('#ua-modal [data-ua-zselall]'); if (!h) return;
        var ids = panel.zfilteredIds || [], selN = ids.filter(function (id) { return panel.zsel[id]; }).length;
        h.checked = ids.length > 0 && selN === ids.length;
        h.indeterminate = selN > 0 && selN < ids.length;
    }
    // Update the selection (checkboxes + header + bulk bar) without re-rendering hundreds of rows.
    function syncSelection() {
        document.querySelectorAll('#ua-modal [data-ua-zsel]').forEach(function (c) { c.checked = !!panel.zsel[c.getAttribute('data-ua-zsel')]; });
        applySelHeader();
        var bb = document.querySelector('#ua-modal #ua-bulkbar'); if (bb) bb.innerHTML = bulkHtml(panel.kind);
    }
    // SAVED per-zone override (for the "changed" mark): zone_access for a group, zone_overrides for a user.
    function zoneOrigOverride(zid) {
        var src = panel.kind === 'group' ? (panel.data.zone_access || []) : (panel.data.zone_overrides || []);
        var r = src.filter(function (x) { return x.scope === 'zone' && x.zone_id === +zid; })[0];
        return r ? r.access : 'inherit';
    }
    function updateDirty() {
        var dirty = accessDirty(); var lbl = q1('#ua-dirty'), sv = q1('[data-ua-save-access]'), rv = q1('[data-ua-revert]');
        if (lbl) lbl.textContent = dirty ? 'Unsaved changes' : 'All changes saved';
        if (sv) sv.disabled = !dirty; if (rv) rv.disabled = !dirty;
    }
    function draftRules(d) {
        var rules = [];
        if (d.all != null) rules.push({ scope: 'all', access: d.all });
        Object.keys(d.zones).forEach(function (z) { if (d.zones[z] != null) rules.push({ scope: 'zone', zone_id: +z, access: d.zones[z] }); });
        return rules;
    }
    async function saveAccess() {
        var caps = Object.keys(panel.draft.caps).filter(function (k) { return panel.draft.caps[k]; }), rules = draftRules(panel.draft);
        try {
            if (panel.kind === 'user') { var r = await api('users/' + panel.id + '/access', 'PUT', draftPayload()); panel.data = r.data.user; }   // canonical object, no second GET
            else { await api('permission-groups/' + panel.id + '/access', 'PUT', { capabilities: caps, zone_rules: rules }); if (!(await reloadData())) return; }
        } catch (e) { fail(e); return; }
        // In place: draft == saved, so reset origJson and clear changed-row highlight. Access is not rebuilt
        // (zone list scroll stays); update the header and the background list row.
        panel.origJson = JSON.stringify(panel.draft); updateDirty();
        document.querySelectorAll('#ua-modal tr[data-ua-zrow]').forEach(function (tr) {
            var z = { zone_id: tr.getAttribute('data-ua-zrow') }; tr.classList.toggle('ua-changed', zoneRowChanged(z));
        });
        refreshHead(); syncListRow();
    }

    // GROUP: Members. #ua-members-sect updates the list and counter in place.
    function membersSectionHtml(g) {
        var mem = (g.members || []).map(function (m) {
            return '<div class="ua-line"><span><b>' + esc(m.username) + '</b>' + (m.display_name ? ' <span class="text-mute">' + esc(m.display_name) + '</span>' : '') + '</span><a href="#" class="link" data-ua-gm-del="' + m.id + '" style="color:var(--danger);margin-left:auto">remove</a></div>';
        }).join('') || '<div class="text-mute" style="font-size:13px">No members.</div>';
        var addable = (D.list || []).filter(function (u) { return !(g.members || []).some(function (m) { return m.id === u.id; }); }).map(function (u) { return { value: String(u.id), label: u.username }; });
        var add = addable.length ? ('<div class="ua-inline">' + sel('ua-gm-user', addable, String(addable[0].value)) + ' <button class="btn btn-ghost sm" data-ua-gm-add>Add member</button></div>') : '<div class="text-mute" style="font-size:13px">All users are already members.</div>';
        return mem + add;
    }
    function groupMembers(g) {
        return '<div class="ua-sect">Group</div>'
            + '<div class="zform-row"><label>Name</label><input class="field-input" id="ua-g-name" value="' + esc(g.name) + '"></div>'
            + '<div class="zform-row"><label>Description</label><input class="field-input" id="ua-g-desc" value="' + esc(g.description || '') + '"></div>'
            + '<div class="ua-actions-row" style="border-top:none;padding-top:0"><button class="btn btn-primary" data-ua-save-group>Save</button>'
            + '<button class="btn btn-danger" data-ua-del-group style="margin-left:auto">Delete group</button></div>'
            + '<div class="ua-sect">Members</div><div id="ua-members-sect">' + membersSectionHtml(g) + '</div>';
    }

    // Background list row: update one row, not renderList.
    function listRowFromUser(u) {
        return { id: u.id, username: u.username, display_name: u.display_name, is_active: u.is_active,
                 has_password: (u.password && u.password.set) ? 1 : 0, has_totp: (u.totp && u.totp.enrolled) ? 1 : 0,
                 cert_count: (u.identities || []).filter(function (i) { return i.type === 'cert'; }).length,
                 group_count: (u.groups || []).length,
                 is_admin: (u.effective_capabilities || []).indexOf('users.manage') >= 0 ? 1 : 0, last_login: u.last_login };
    }
    function listRowFromGroup(g) {
        return { id: g.id, name: g.name, description: g.description, member_count: (g.members || []).length, cap_count: (g.capabilities || []).length };
    }
    function syncListRow() {
        if (!panel) return; var isU = panel.kind === 'user';
        var row = isU ? listRowFromUser(panel.data) : listRowFromGroup(panel.data);
        var arr = isU ? (D.list || (D.list = [])) : (D.groups || (D.groups = []));
        for (var i = 0; i < arr.length; i++) { if (arr[i].id === row.id) { arr[i] = row; break; } }
        var tr = rootEl && rootEl.querySelector('tr[data-ua-open-' + (isU ? 'user' : 'group') + '="' + row.id + '"]');
        if (tr) tr.outerHTML = (isU ? userRowHtml(row) : groupRowHtml(row));
    }
    function refreshHead() { var h = q1('.ua-head-main'); if (h) h.innerHTML = '<h2>' + headTitle() + '</h2>' + headStatus(); }
    function refreshSection(sel, html) { var el = q1(sel); if (el) el.innerHTML = html; }

    // Mutations update in place, no generic renderBody.
    async function saveProfile() {
        try { await api('users/' + panel.id, 'PUT', { display_name: val('ua-p-display'), email: val('ua-p-email'), is_active: q1('#ua-p-active').checked ? 1 : 0 }); }
        catch (e) { fail(e); return; }
        if (!(await reloadData())) return;
        refreshHead(); syncListRow();   // a profile edit changes nothing else on screen
    }
    async function saveGroupMeta() {
        try { await api('permission-groups/' + panel.id, 'PUT', { name: val('ua-g-name'), description: val('ua-g-desc') }); }
        catch (e) { fail(e); return; }
        if (!(await reloadData())) return;
        refreshHead(); syncListRow();   // the fields already show the input
    }
    async function delMember(mid) { try { await api('permission-groups/' + panel.id + '/members/' + mid, 'DELETE'); } catch (e) { fail(e); return; } if (!(await reloadData())) return; refreshSection('#ua-members-sect', membersSectionHtml(panel.data)); refreshHead(); syncListRow(); }
    async function addMember() { try { await api('permission-groups/' + panel.id + '/members', 'POST', { user_id: +selVal('ua-gm-user') }); } catch (e) { fail(e); return; } if (!(await reloadData())) return; refreshSection('#ua-members-sect', membersSectionHtml(panel.data)); refreshHead(); syncListRow(); }
    async function delIdentity(iid) { try { await api('identities/' + iid, 'DELETE'); } catch (e) { fail(e); return; } if (!(await reloadData())) return; refreshSection('#ua-cert-list', certListHtml(panel.data)); syncListRow(); }
    async function delUser(uid) {
        if (!(await window.DNSPanel.confirm({ title: 'Delete user', message: 'Delete this user with identities, password, grants and memberships? Cannot be undone. The last administrator is protected.', okText: 'Delete', danger: true }))) return;
        try { await api('users/' + uid, 'DELETE'); closeModalDom(); setUrl(null, null, 'replace'); await reload(); } catch (e) { fail(e); }
    }
    async function delGroup(gid) {
        if (!(await window.DNSPanel.confirm({ title: 'Delete group', message: 'Delete this group? Members lose its permissions and zone access.', okText: 'Delete', danger: true }))) return;
        try { await api('permission-groups/' + gid, 'DELETE'); closeModalDom(); setUrl(null, null, 'replace'); await reload(); } catch (e) { fail(e); }
    }
    async function userPassword(uid) {
        // 2FA is turned off only by an explicit checkbox: without it a user who also lost the phone would hit
        // the code screen right after the password change and be locked out again.
        var vals = await window.DNSPanel.dialog({
            title: 'Reset password',
            message: 'A temporary password is generated and shown once. The user must change it at next sign-in, '
                + 'and all their sessions are signed out.'
                + '<label class="chk" style="margin-top:.7rem"><input type="checkbox" name="reset-totp"> '
                + 'Also turn off two-factor (do this only if the authenticator is lost too)</label>',
            okText: 'Reset password'
        });
        if (!vals) return;
        try {
            var r = await api('users/' + uid + '/password', 'POST', { reset_totp: !!vals['reset-totp'] });
            window.DNSPanel.alert({ title: 'Temporary password', message: 'Give this to the user (shown once):<br><code style="font-size:15px">' + esc(r.data.temp_password) + '</code><br>They must change it at first login. All their sessions were signed out.'
                + (r.data.totp_reset ? '<br>Two-factor was turned off — they can set it up again on their Account page.' : '') });
            if (!(await reloadData())) return;
            refreshSection('#ua-auth-block', authRowsHtml(panel.data)); loadProfileSessions(); syncListRow();
        } catch (e) { fail(e); }
    }
    // Three different actions on another user's 2FA, hence three buttons.
    async function resetTotp(uid) {
        if (!(await window.DNSPanel.confirm({ title: 'Reset two-factor',
                message: 'For a lost or reinstalled authenticator. The current app and the recovery codes stop '
                    + 'working, and at the next sign-in this person is asked to set up a new app. All their '
                    + 'sessions are signed out.',
                okText: 'Reset', danger: true }))) return;
        try { await api('users/' + uid + '/totp/reset', 'POST', {}); } catch (e) { fail(e); return; }
        await afterTotpChange();
    }
    async function requireTotp(uid, on) {
        try { await api('users/' + uid + '/totp/required', 'PUT', { required: !!on }); } catch (e) { fail(e); return; }
        await afterTotpChange();
    }
    async function afterTotpChange() {
        if (!(await reloadData())) return;
        refreshSection('#ua-auth-block', authRowsHtml(panel.data)); loadProfileSessions(); syncListRow();
    }
    async function turnTotpOff(uid) {
        if (!(await window.DNSPanel.confirm({ title: 'Turn off two-factor',
                message: 'Sign-in will ask for the password only, and this person is not asked to set up an app. '
                    + 'The current app and recovery codes stop working, and all their sessions are signed out. '
                    + 'They can turn it back on themselves on their Account page.',
                okText: 'Turn off', danger: true }))) return;
        try { await api('users/' + uid + '/totp', 'DELETE'); } catch (e) { fail(e); return; }
        if (!(await reloadData())) return;
        refreshSection('#ua-auth-block', authRowsHtml(panel.data)); loadProfileSessions(); syncListRow();
    }
    async function addIdentity() {
        var cn = val('ua-ident-cn'); if (!cn) { window.DNSPanel.alert({ message: 'Certificate CN is required.' }); return; }
        try { await api('users/' + panel.id + '/identities', 'POST', { type: 'cert', provider: '', principal: cn }); } catch (e) { fail(e); return; }
        if (!(await reloadData())) return;
        refreshSection('#ua-cert-list', certListHtml(panel.data)); syncListRow();
    }
    async function revokeSession(sid) { try { await api('users/' + panel.id + '/sessions/' + sid, 'DELETE'); } catch (e) { fail(e); return; } loadProfileSessions(); }
    async function revokeAllSessions() {
        if (!(await window.DNSPanel.confirm({ title: 'Revoke all sessions', message: 'Sign this user out of every device? Any active session is ended immediately.', okText: 'Revoke all', danger: true }))) return;
        try { await api('users/' + panel.id + '/sessions', 'DELETE'); } catch (e) { fail(e); return; } loadProfileSessions();
    }
    async function setSessionPolicy(ttl) { try { await api('users/' + panel.id + '/session-policy', 'PUT', { ttl: (ttl === '' ? null : +ttl) }); } catch (e) { fail(e); } loadProfileSessions(); }

    function wire() {
        if (wired) return; wired = true;
        document.addEventListener('click', function (e) {
            var t = e.target, el, hit = function (a) { return t.closest ? t.closest('[' + a + ']') : null; };
            if ((el = hit('data-ua-sub'))) { sub = el.getAttribute('data-ua-sub'); window.DNSPanel.store('uaSub', sub); renderList(); return; }
            if (hit('data-ua-add-user')) { e.preventDefault(); addUserDialog(); return; }
            if (hit('data-ua-add-group')) { e.preventDefault(); addGroupDialog(); return; }
            if ((el = hit('data-ua-open-user'))) { e.preventDefault(); openUser(+el.getAttribute('data-ua-open-user')); return; }
            if ((el = hit('data-ua-open-group'))) { e.preventDefault(); openGroup(+el.getAttribute('data-ua-open-group')); return; }
            if (hit('data-ua-dlg-close')) { e.preventDefault(); closeDialog(); return; }
            if (hit('data-ua-dlg-save-user')) { e.preventDefault(); saveNewUser(); return; }
            if (hit('data-ua-dlg-save-group')) { e.preventDefault(); saveNewGroup(); return; }
            if (!panel) return;
            if (hit('data-ua-close')) { e.preventDefault(); closePanel(); return; }
            if ((el = hit('data-ua-tab'))) { e.preventDefault(); panel.tab = el.getAttribute('data-ua-tab'); renderPanel(); return; }
            if (hit('data-ua-save-access')) { e.preventDefault(); saveAccess(); return; }
            if (hit('data-ua-revert')) { e.preventDefault(); buildDraft(); loadZoneData(panel.kind); return; }
            if ((el = hit('data-ua-grp-del'))) { e.preventDefault(); delete panel.draft.groups[el.getAttribute('data-ua-grp-del')]; renderLeft(); schedulePreview(); return; }
            if ((el = hit('data-ua-cap-rmpersonal'))) { e.preventDefault(); delete panel.draft.caps[el.getAttribute('data-ua-cap-rmpersonal')]; renderLeft(); updateDirty(); return; }
            // "Denied ×" removes the personal deny: the permission comes from the group again.
            if ((el = hit('data-ua-cap-undeny'))) { e.preventDefault(); delete panel.draft.denied[el.getAttribute('data-ua-cap-undeny')]; renderLeft(); updateDirty(); return; }
            if (hit('data-ua-save-profile')) { e.preventDefault(); saveProfile(); return; }
            if (hit('data-ua-del-user')) { e.preventDefault(); delUser(panel.id); return; }
            if (hit('data-ua-del-group')) { e.preventDefault(); delGroup(panel.id); return; }
            if (hit('data-ua-save-group')) { e.preventDefault(); saveGroupMeta(); return; }
            if (hit('data-ua-pw')) { e.preventDefault(); userPassword(panel.id); return; }
            if (hit('data-ua-totp-off'))   { e.preventDefault(); turnTotpOff(panel.id); return; }
            if (hit('data-ua-totp-reset')) { e.preventDefault(); resetTotp(panel.id); return; }
            { var rq = hit('data-ua-totp-require');
              if (rq) { e.preventDefault(); requireTotp(panel.id, rq.getAttribute('data-ua-totp-require') === '1'); return; } }
            if (hit('data-ua-ident-add')) { e.preventDefault(); addIdentity(); return; }
            if ((el = hit('data-ua-ident-del'))) { e.preventDefault(); delIdentity(el.getAttribute('data-ua-ident-del')); return; }
            if ((el = hit('data-ua-sess-revoke'))) { e.preventDefault(); revokeSession(+el.getAttribute('data-ua-sess-revoke')); return; }
            if (hit('data-ua-sess-revokeall')) { e.preventDefault(); revokeAllSessions(); return; }
            if (hit('data-ua-audit')) { e.preventDefault(); gotoAudit(); return; }
            if (hit('data-ua-bulk-apply')) { e.preventDefault(); var bv = selVal('ua-bulkval'); Object.keys(panel.zsel).forEach(function (k) { if (panel.zsel[k]) { if (bv === 'inherit') delete panel.draft.zones[k]; else panel.draft.zones[k] = bv; } }); panel.zsel = {}; repaintZones(panel.kind); schedulePreview(); return; }
            if (hit('data-ua-bulk-clear')) { e.preventDefault(); panel.zsel = {}; syncSelection(); return; }
            if ((el = hit('data-ua-sort'))) { e.preventDefault(); var s = el.getAttribute('data-ua-sort'); if (panel.zf.sort === s) panel.zf.dir *= -1; else { panel.zf.sort = s; panel.zf.dir = 1; } renderZoneRows(panel.kind); return; }
            if ((el = hit('data-ua-gm-del'))) { e.preventDefault(); delMember(el.getAttribute('data-ua-gm-del')); return; }
            if (hit('data-ua-gm-add')) { e.preventDefault(); addMember(); return; }
        });
        document.addEventListener('change', function (e) {
            if (!panel) return; var t = e.target, nm = t.getAttribute && t.getAttribute('name');
            if (t.hasAttribute && t.hasAttribute('data-ua-dcap')) {
                var dc = t.getAttribute('data-ua-dcap');
                var fromGroup = ((panel.capsrc || {})[dc] || {}).groups;
                var byGroup = !!(fromGroup && fromGroup.length);
                if (t.checked) { delete panel.draft.denied[dc]; if (!byGroup) panel.draft.caps[dc] = true; }
                // A group-granted permission is removed ONLY via a personal deny; the group's grant is shared
                // by all its members and is not touched here.
                else if (byGroup) { panel.draft.denied[dc] = true; delete panel.draft.caps[dc]; }
                else { delete panel.draft.caps[dc]; }
                renderLeft(); updateDirty(); return;
            }
            if (nm && nm.indexOf('ua-zovr-') === 0) { var zid = nm.slice(8); if (t.value === 'inherit') delete panel.draft.zones[zid]; else panel.draft.zones[zid] = t.value; repaintZones(panel.kind); schedulePreview(); return; }
            if (nm === 'ua-zdefault') { panel.draft.all = (t.value === 'inherit' ? null : t.value); repaintZones(panel.kind); schedulePreview(); return; }
            if (nm === 'ua-addgrp') { if (t.value) { panel.draft.groups[t.value] = true; renderLeft(); schedulePreview(); } return; }
            if (nm === 'ua-feff') { panel.zf.eff = t.value; renderZoneRows(panel.kind); return; }
            if (nm === 'ua-fovr') { panel.zf.ovr = t.value; renderZoneRows(panel.kind); return; }
            if (t.hasAttribute && t.hasAttribute('data-ua-zsel')) { panel.zsel[t.getAttribute('data-ua-zsel')] = t.checked; syncSelection(); return; }
            if (t.hasAttribute && t.hasAttribute('data-ua-zselall')) { var on = t.checked; (panel.zfilteredIds || []).forEach(function (id) { panel.zsel[id] = on; }); syncSelection(); return; }
            if (nm === 'ua-sesspol') { setSessionPolicy(t.value); return; }
        });
        document.addEventListener('input', function (e) { if (panel && panel.eff && e.target.id === 'ua-zq') { panel.zf.q = e.target.value.toLowerCase(); renderZoneRows(panel.kind); } });
        document.addEventListener('keydown', function (e) { if (e.key === 'Escape' && panel && !document.querySelector('#modal-overlay .modal')) closePanel(); });
        window.addEventListener('popstate', function () {
            if (!rootEl || !document.getElementById('ua-root')) { closeModalDom(); return; }
            var qp = new URLSearchParams(location.search), uid = qp.get('user'), gid = qp.get('group');
            var goingTo = uid ? ('user:' + uid) : gid ? ('group:' + gid) : 'none', cur = panel ? (panel.kind + ':' + panel.id) : 'none';
            if (accessDirty() && goingTo !== cur) { setUrl(panel.kind, panel.id, 'replace'); guardLeave().then(function (ok) { if (ok) { panel.draft = null; if (uid && /^\d+$/.test(uid)) openUser(+uid, { fromPop: true }); else if (gid && /^\d+$/.test(gid)) openGroup(+gid, { fromPop: true }); else closeModalDom(); } }); return; }
            if (uid && /^\d+$/.test(uid)) openUser(+uid, { fromPop: true });
            else if (gid && /^\d+$/.test(gid)) openGroup(+gid, { fromPop: true });
            else if (panel) closeModalDom();
        });
        document.addEventListener('pageLoaded', function (e) { if (!e.detail || e.detail.page !== 'settings') destroy(); });
    }
    function gotoAudit() {
        var u = panel.data.username; closeModalDom(); setUrl(null, null, 'replace');
        var path = '/audit?actor=' + encodeURIComponent(u);
        if (window.DNSPanel && window.DNSPanel.navigate) window.DNSPanel.navigate(path); else location.href = path;
    }
})();
