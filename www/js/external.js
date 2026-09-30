/* DNS Panel — Settings → External access: switches for remote MCP and anonymous read, API tokens, OIDC
   providers. Data: GET /dns-api/external (users.manage). */
(function () {
    'use strict';
    var D = null;   // { settings, tokens[], oidc[], users[] }

    function esc(s) { return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'); }
    function api(path, method, body) { return window.DNSPanel.api(path, { method: method, body: body ? JSON.stringify(body) : undefined }); }
    function root() { return document.getElementById('external-root'); }
    function fail(e) { window.DNSPanel.alert({ message: (e && e.message) || 'Request failed' }); }
    function shown() { var s = {}; try { s = JSON.parse(sessionStorage.getItem('extShown') || '{}'); } catch (e) {} return s; }
    function setShown(s) { try { sessionStorage.setItem('extShown', JSON.stringify(s)); } catch (e) {} }
    function byId(list, id) { return (list || []).filter(function (x) { return String(x.id) === String(id); })[0]; }

    async function load() {
        var r = root(); if (!r) return;
        try { var res = await api('external', 'GET'); D = (res && res.data) || {}; }
        catch (e) { r.innerHTML = '<div class="card"><p style="margin:0;color:var(--danger)">Failed to load: ' + esc(e && e.message) + '</p></div>'; return; }
        render();
    }

    function head(title, btn) {
        return '<div class="ext-head"><span>' + esc(title) + '</span>' + (btn || '') + '</div>';
    }
    function switchesCard() {
        var s = D.settings || {};
        var c = function (k, label) { return '<label class="chk"><input type="checkbox" data-ext-flag="' + k + '"' + (s[k] ? ' checked' : '') + '> ' + esc(label) + '</label>'; };
        return '<div class="card">' + head('API & MCP')
            + '<div class="chks">' + c('mcp_http', 'Remote MCP') + c('anonymous_read', 'Anonymous read') + c('mcp_readonly', 'MCP read-only') + '</div></div>';
    }
    function tokenCell(t) {
        var tok = t.token || '', vis = shown()[t.id];
        return '<span class="mono ext-token">' + esc(vis ? tok : tok.slice(0, 9) + '…' + tok.slice(-4)) + '</span> '
            + '<a href="#" class="link sm" data-tok-show="' + t.id + '">' + (vis ? 'Hide' : 'Show') + '</a> '
            + '<a href="#" class="link sm" data-tok-copy="' + t.id + '">Copy</a>';
    }
    function tokensCard() {
        var rows = (D.tokens || []).map(function (t) {
            return '<tr' + (t.enabled ? '' : ' class="text-dim"') + '>'
                + '<td><b>' + esc(t.name) + '</b></td><td>' + esc(t.username) + '</td>'
                + '<td class="nowrap">' + tokenCell(t) + '</td>'
                + '<td>' + esc(t.expires_at || '—') + '</td>'
                + '<td>' + esc(t.last_used_at ? window.DNSPanel.fmtTime(t.last_used_at) : '—') + '</td>'
                + '<td><label class="chk"><input type="checkbox" data-tok-en="' + t.id + '"' + (t.enabled ? ' checked' : '') + '> enabled</label></td>'
                + '<td class="right"><a href="#" class="link" data-tok-del="' + t.id + '" style="color:var(--danger)">Delete</a></td></tr>';
        }).join('') || '<tr><td colspan="7" class="text-dim" style="padding:1rem;">No tokens</td></tr>';
        return '<div class="card">' + head('API tokens', '<button class="btn btn-primary sm" data-tok-add>+ New token</button>')
            + '<div class="table-wrap"><table class="data-table"><thead><tr><th>Name</th><th>User</th><th>Token</th><th>Expires</th><th>Last used</th><th>Status</th><th></th></tr></thead>'
            + '<tbody>' + rows + '</tbody></table></div></div>';
    }
    function oidcCard() {
        var rows = (D.oidc || []).map(function (p) {
            return '<tr' + (p.enabled ? '' : ' class="text-dim"') + '>'
                + '<td class="nowrap"><b>' + esc(p.name) + '</b></td><td class="mono">' + esc(p.issuer) + '</td>'
                + '<td class="mono nowrap">' + esc(p.audience) + '</td><td class="mono nowrap">' + esc(p.username_claim) + '</td>'
                + '<td>' + (p.enabled ? 'Enabled' : 'Disabled') + '</td>'
                + '<td class="right nowrap"><a href="#" class="link" data-oidc-edit="' + p.id + '">Edit</a> '
                + '<a href="#" class="link" data-oidc-del="' + p.id + '" style="color:var(--danger)">Delete</a></td></tr>';
        }).join('') || '<tr><td colspan="6" class="text-dim" style="padding:1rem;">No providers</td></tr>';
        return '<div class="card">' + head('OIDC providers', '<button class="btn btn-primary sm" data-oidc-add>+ Add provider</button>')
            + '<div class="table-wrap"><table class="data-table"><thead><tr><th>Name</th><th>Issuer</th><th>Audience</th><th>Username claim</th><th>Status</th><th></th></tr></thead>'
            + '<tbody>' + rows + '</tbody></table></div></div>';
    }
    function render() {
        var r = root(); if (!r || !D) return;
        r.innerHTML = '<div class="ext-stack">' + switchesCard() + tokensCard() + oidcCard() + '</div>';
    }

    async function setFlag(key, on, box) {
        var body = {}; body[key] = on;
        try { var r = await api('external', 'PUT', body); D.settings = r.data; }
        catch (e) { box.checked = !on; fail(e); }
    }
    async function addToken() {
        var users = (D.users || []).map(function (u) { return { value: String(u.id), label: u.username }; });
        var v = await window.DNSPanel.dialog({ title: 'New API token', okText: 'Create',
            message: '<div class="zform-row"><label>Name</label><input class="field-input" name="name" autocomplete="off"></div>'
                + '<div class="zform-row"><label>User</label>' + window.DNSPanel.selectHtml('user_id', users, users.length ? users[0].value : '') + '</div>'
                + '<div class="zform-row"><label>Expires</label><input class="field-input" type="date" name="expires_at"></div>' });
        if (!v) return;
        try {
            var r = await api('external/tokens', 'POST', { name: v.name, user_id: +v.user_id, expires_at: v.expires_at || null });
            var s = shown(); s[r.data.id] = 1; setShown(s);
            await load();
        } catch (e) { fail(e); }
    }
    async function editOidc(p) {
        p = p || { username_claim: 'preferred_username', enabled: 1 };
        var f = function (k, label, ph) { return '<div class="zform-row"><label>' + label + '</label><input class="field-input" name="' + k + '" value="' + esc(p[k] || '') + '" placeholder="' + esc(ph || '') + '" autocomplete="off"></div>'; };
        var v = await window.DNSPanel.dialog({ title: p.id ? 'Edit OIDC provider' : 'Add OIDC provider', okText: p.id ? 'Save' : 'Add', wide: true,
            message: f('name', 'Name', 'Microsoft Entra') + f('issuer', 'Issuer', 'https://login.microsoftonline.com/<tenant>/v2.0')
                + f('audience', 'Audience', 'api://dns-panel') + f('username_claim', 'Username claim', 'preferred_username')
                + '<div class="zform-row"><label>Enabled</label><label class="chk"><input type="checkbox" name="enabled"' + (p.enabled ? ' checked' : '') + '></label></div>' });
        if (!v) return;
        try {
            if (p.id) await api('external/oidc/' + p.id, 'PATCH', v); else await api('external/oidc', 'POST', v);
            await load();
        } catch (e) { fail(e); }
    }

    document.addEventListener('change', function (e) {
        var r = root(); if (!r || !D || !r.contains(e.target)) return;
        var f = e.target.getAttribute('data-ext-flag');
        if (f) { setFlag(f, e.target.checked, e.target); return; }
        var en = e.target.getAttribute('data-tok-en');
        if (en) {
            var box = e.target, t = byId(D.tokens, en);
            api('external/tokens/' + en, 'PATCH', { enabled: box.checked })
                .then(function () { t.enabled = box.checked ? 1 : 0; box.closest('tr').classList.toggle('text-dim', !box.checked); })
                .catch(function (err) { box.checked = !box.checked; fail(err); });
        }
    });
    document.addEventListener('click', async function (e) {
        var r = root(); if (!r || !D || !r.contains(e.target)) return;
        var t = e.target, a;
        if (t.closest('[data-tok-add]')) { e.preventDefault(); addToken(); return; }
        if (t.closest('[data-oidc-add]')) { e.preventDefault(); editOidc(null); return; }
        if ((a = t.closest('[data-oidc-edit]'))) { e.preventDefault(); editOidc(byId(D.oidc, a.getAttribute('data-oidc-edit'))); return; }
        if ((a = t.closest('[data-tok-show]'))) {
            e.preventDefault();
            var s = shown(), id = a.getAttribute('data-tok-show');
            if (s[id]) delete s[id]; else s[id] = 1;
            setShown(s);
            a.closest('td').innerHTML = tokenCell(byId(D.tokens, id));
            return;
        }
        if ((a = t.closest('[data-tok-copy]'))) {
            e.preventDefault();
            try { await navigator.clipboard.writeText(byId(D.tokens, a.getAttribute('data-tok-copy')).token); a.textContent = 'Copied'; }
            catch (x) { fail({ message: 'Copy failed' }); }
            return;
        }
        if ((a = t.closest('[data-tok-del]'))) {
            e.preventDefault();
            var tk = byId(D.tokens, a.getAttribute('data-tok-del'));
            if (!await window.DNSPanel.confirm({ title: 'Delete token', danger: true, okText: 'Delete', message: 'Delete <b>' + esc(tk.name) + '</b> of ' + esc(tk.username) + '?' })) return;
            try { await api('external/tokens/' + tk.id, 'DELETE'); D.tokens = D.tokens.filter(function (x) { return x !== tk; }); render(); }
            catch (x) { fail(x); }
            return;
        }
        if ((a = t.closest('[data-oidc-del]'))) {
            e.preventDefault();
            var p = byId(D.oidc, a.getAttribute('data-oidc-del'));
            if (!await window.DNSPanel.confirm({ title: 'Delete provider', danger: true, okText: 'Delete', message: 'Delete <b>' + esc(p.name) + '</b>?' })) return;
            try { await api('external/oidc/' + p.id, 'DELETE'); D.oidc = D.oidc.filter(function (x) { return x !== p; }); render(); }
            catch (x) { fail(x); }
        }
    });

    // Mounted by the Settings tab like Import: own root and own state.
    window.ExternalTab = {
        mount: function () { D = null; return load(); },
        destroy: function () { D = null; }
    };
})();
