/* DNS Panel — dynamic updates (RFC 2136).
   Who may update a zone (DHCP server addresses and/or one TSIG key) is a property of the zone. There is no
   mode switch: addresses given means by address, a key means by key, both means both. Zones sharing settings
   can follow a Dynamic DHCP profile; editing the profile reaches all following zones.
   Contains the shared form (zone and profile), the zone modal ("Dynamic updates" in the zone header) and the
   Settings → Dynamic DHCP profiles tab. The key is shown in clear: this is an internal panel and operators need to see it. */
(function () {
    'use strict';
    // Generated key length equals the algorithm's hash output size (as tsig-keygen does).
    var ALGOS = [['hmac-sha256', 32], ['hmac-sha512', 64], ['hmac-sha384', 48], ['hmac-sha224', 28], ['hmac-sha1', 20], ['hmac-md5', 16]];
    var ALGO_OPTS = ALGOS.map(function (a) { return { value: a[0], label: a[0] }; });

    function esc(s) { return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'); }
    function api(path, method, body) { return window.DNSPanel.api(path, { method: method, body: body ? JSON.stringify(body) : undefined }); }
    function overlay() { return document.getElementById('modal-overlay'); }
    function closeModal() { var ov = overlay(); if (ov) { ov.style.display = 'none'; ov.innerHTML = ''; } }

    // Shared form: addresses + one key. v = { cidrs[], key{name,algorithm,secret}|null }; p is the element id prefix.
    function formHtml(p, v) {
        v = v || {};
        var k = v.key || {};
        return '<div class="dyn-form" id="' + p + 'form">'
            + '<div class="zform-row"><label>DHCP addresses</label><div class="zform-grow">'
            +   '<textarea class="field-input mono dyn-cidrs" id="' + p + 'cidrs" rows="2" placeholder="10.20.1.10, 10.20.1.0/24">'
            +   esc((v.cidrs || []).join(', ')) + '</textarea></div></div>'
            + '<div class="zform-row"><label>TSIG key</label><div class="zform-grow"><div class="dyn-key">'
            +   '<input class="field-input mono" id="' + p + 'kname" placeholder="key name" value="' + esc(k.name || '') + '" autocomplete="off">'
            +   window.DNSPanel.selectHtml(p + 'kalgo', ALGO_OPTS, k.algorithm || 'hmac-sha256')
            + '</div><div class="dyn-key">'
            +   '<input class="field-input mono" id="' + p + 'ksecret" placeholder="key (base64)" value="' + esc(k.secret || '') + '" autocomplete="off" spellcheck="false">'
            +   '<button type="button" class="btn btn-ghost" data-dyn-gen="' + p + '">Generate</button></div></div></div>'
            + '</div>';
    }
    function formRead(root, p) {
        var cidrs = (root.querySelector('#' + p + 'cidrs').value || '').split(/[\s,;]+/).map(function (s) { return s.trim(); }).filter(Boolean);
        var out = { cidrs: cidrs };
        var n = (root.querySelector('#' + p + 'kname').value || '').trim(), s = (root.querySelector('#' + p + 'ksecret').value || '').trim();
        if (n || s) out.key = { name: n, algorithm: (root.querySelector('[name="' + p + 'kalgo"]') || {}).value || 'hmac-sha256', secret: s };
        return out;
    }
    function formSet(root, p, v) {   // fill values (e.g. from a profile) without rebuilding the form
        var k = v.key || {};
        root.querySelector('#' + p + 'cidrs').value = (v.cidrs || []).join(', ');
        root.querySelector('#' + p + 'kname').value = k.name || '';
        root.querySelector('#' + p + 'ksecret').value = k.secret || '';
        window.DNSPanel.setSelect(p + 'kalgo', k.algorithm || 'hmac-sha256');
    }
    function edited(el) { var f = el.closest && el.closest('.dyn-form'); if (f) f.dispatchEvent(new CustomEvent('dyn-edit', { bubbles: true })); }
    document.addEventListener('input', function (e) { if (e.target.closest && e.target.closest('.dyn-form')) edited(e.target); });
    document.addEventListener('change', function (e) { if (e.target.name && /kalgo$/.test(e.target.name) && e.target.closest('.dyn-form')) edited(e.target); });
    document.addEventListener('click', function (e) {
        var g = e.target.closest && e.target.closest('[data-dyn-gen]'); if (!g) return;
        e.preventDefault();
        var p = g.getAttribute('data-dyn-gen'), f = g.closest('.dyn-form');
        var alg = (f.querySelector('[name="' + p + 'kalgo"]') || {}).value || 'hmac-sha256';
        var len = (ALGOS.filter(function (a) { return a[0] === alg; })[0] || [0, 32])[1];
        var b = new Uint8Array(len); window.crypto.getRandomValues(b);
        f.querySelector('#' + p + 'ksecret').value = btoa(String.fromCharCode.apply(null, b));
        edited(f);
    });
    function summary(v) {
        if (!v || (!(v.cidrs || []).length && !v.key)) return 'not set up';
        var parts = [];
        if ((v.cidrs || []).length) parts.push(v.cidrs.join(', '));
        if (v.key) parts.push('key ' + v.key.name);
        return parts.join(' · ');
    }

    async function openZone(zid, type) {
        var ov = overlay(); if (!ov) return false;
        ov.innerHTML = '<div class="modal"><div class="modal-card"><div class="spinner"></div></div></div>';
        ov.style.display = 'block';
        var data;
        try { var r = await api('zones/' + zid + '/dynamic', 'GET'); data = (r && r.data) || r; }
        catch (e) { closeModal(); window.DNSPanel.alert((e && e.message) || 'Failed to load'); return false; }
        var z = data.dynamic || {}, profiles = data.profiles || [];
        // What the old server allowed (import). A key its export did not define (an include left out) arrives
        // as a name only, so the operator types its secret once.
        var old = data.imported || null, oldKey = old && (old.keys || [])[0];
        var needKey = oldKey && !z.key && !z.profile_id;
        if (needKey) z.key = { name: oldKey, algorithm: ((old.key_defs || {})[oldKey] || {}).algorithm || 'hmac-sha256', secret: '' };
        var oldNote = old ? '<div class="zform-note">On the old server: ' + esc([].concat(old.cidrs || [], (old.keys || []).map(function (k) { return 'key ' + k; }), old.other || []).join(', ') || 'nothing')
            + (needKey ? '. Enter this key’s secret from the old server’s config.' : '.') + '</div>' : '';
        var prof = z.profile_id ? String(z.profile_id) : '';
        var popts = [{ value: '', label: '— none —' }].concat(profiles.map(function (p) { return { value: String(p.id), label: p.name }; }));
        ov.innerHTML = '<div class="modal"><form class="modal-card zs-card" id="zd-form">'
            + '<h2 class="modal-title">Dynamic updates</h2>'
            + '<div class="zform-row"><label>Profile</label><div class="zform-grow dyn-prof">'
            +   window.DNSPanel.selectHtml('zd-prof', popts, prof)
            +   '<label class="chk"><input type="checkbox" id="zd-follow"' + (prof ? ' checked' : '') + '> Follow changes</label></div></div>'
            + formHtml('zd-', z) + oldNote
            // Profile name is asked inline: the shared dialog would take the same overlay and close this modal.
            + '<div class="zform-row dyn-saveas-row" id="zd-saveas-row" hidden><label>Profile name</label><div class="dyn-key">'
            +   '<input class="field-input" id="zd-saveas-name" autocomplete="off">'
            +   '<button type="button" class="btn btn-primary" id="zd-saveas-ok">Save profile</button>'
            +   '<button type="button" class="btn btn-ghost" id="zd-saveas-cancel">Cancel</button></div></div>'
            + '<div class="login-error" id="zd-err" style="display:none;"></div>'
            + '<div class="modal-actions"><button type="button" class="btn btn-ghost dyn-saveas" id="zd-saveas">Save as profile\u2026</button>'
            + '<button type="button" class="btn btn-ghost" id="zd-cancel">Cancel</button>'
            + '<button type="submit" class="btn btn-primary">Save</button></div></form></div>';
        var form = ov.querySelector('#zd-form');
        function profOf(id) { return profiles.filter(function (p) { return String(p.id) === String(id); })[0]; }
        // Picking a profile loads its values and sets "follow"; "none" drops the link but keeps the values.
        form.addEventListener('change', function (e) {
            if (e.target.name === 'zd-prof') {
                var p = profOf(e.target.value);
                if (p) formSet(form, 'zd-', p);
                form.querySelector('#zd-follow').checked = !!p;
            } else if (e.target.id === 'zd-follow' && e.target.checked) {
                var pp = profOf((form.querySelector('[name="zd-prof"]') || {}).value);
                if (pp) formSet(form, 'zd-', pp);
                e.target.checked = !!pp;   // after formSet: filling values does not count as an edit
            }
        });
        // Any manual edit detaches the zone from its profile.
        form.addEventListener('dyn-edit', function () { form.querySelector('#zd-follow').checked = false; });
        return new Promise(function (resolve) {
            form.querySelector('#zd-cancel').addEventListener('click', function () { closeModal(); resolve(false); });
            // The accept flag lives in Zone settings; this modal does not touch it.
            function body() {
                var pv = (form.querySelector('[name="zd-prof"]') || {}).value || '';
                return (pv && form.querySelector('#zd-follow').checked) ? { profile_id: +pv } : formRead(form, 'zd-');
            }
            async function send(b) {
                var res = await api('zones/' + zid + '/dynamic', 'PUT', b);
                var w = ((res && res.data) || {}).warnings || [];
                if (w.length) window.DNSPanel.alert({ message: 'Saved, but ' + w.join('; ') + '.' });
            }
            form.addEventListener('submit', async function (e) {
                e.preventDefault();
                try { await send(body()); closeModal(); resolve(true); }
                catch (err) { var el = form.querySelector('#zd-err'); el.textContent = (err && err.message) || 'Save failed'; el.style.display = 'block'; }
            });
            // Save as profile: the zone's current values become a new profile that the zone then follows.
            var saRow = form.querySelector('#zd-saveas-row'), saName = form.querySelector('#zd-saveas-name');
            form.querySelector('#zd-saveas').addEventListener('click', function () { saRow.hidden = false; saName.focus(); });
            form.querySelector('#zd-saveas-cancel').addEventListener('click', function () { saRow.hidden = true; saName.value = ''; });
            saName.addEventListener('keydown', function (e) { if (e.key === 'Enter') { e.preventDefault(); form.querySelector('#zd-saveas-ok').click(); } });
            form.querySelector('#zd-saveas-ok').addEventListener('click', async function () {
                var name = (saName.value || '').trim();
                var el = form.querySelector('#zd-err');
                if (!name) { el.textContent = 'Enter a profile name.'; el.style.display = 'block'; return; }
                var b = formRead(form, 'zd-'); b.save_as_profile = name;
                try { await send(b); closeModal(); resolve(true); }
                catch (err) { el.textContent = (err && err.message) || 'Save failed'; el.style.display = 'block'; }
            });
        });
    }
    window.DNSPanel.dynForm = { html: formHtml, read: formRead, set: formSet, summary: summary, openZone: openZone };

    // ---------- Settings → Dynamic DHCP profiles ----------
    var D = null;   // { profiles[] }
    function root() { return document.getElementById('dynamic-root'); }
    function render() {
        var r = root(); if (!r || !D) return;
        var rows = D.profiles.map(function (p) {
            return '<tr><td><b>' + esc(p.name) + '</b></td>'
                 + '<td class="mono">' + esc(p.cidrs.join(', ') || 'any') + '</td>'
                 + '<td class="mono">' + esc(p.key ? p.key.name + ' (' + p.key.algorithm + ')' : '—') + '</td>'
                 + '<td>' + p.zones + '</td>'
                 + '<td class="right nowrap"><a href="#" class="link" data-dynp-edit="' + p.id + '">Edit</a> '
                 + '<a href="#" class="link" data-dynp-del="' + p.id + '" style="color:var(--danger)">Delete</a></td></tr>';
        }).join('') || '<tr><td colspan="5" class="text-dim" style="padding:1rem;">No profiles yet. A profile is optional: '
                    + 'set a zone up with its Dynamic updates button, or save shared settings here and let zones follow them.</td></tr>';
        r.innerHTML = '<div class="card">'
            + '<div class="cat-tabc-head" style="display:flex;justify-content:space-between;align-items:center;margin-bottom:.6rem;">'
            + '<span style="font-weight:600">Dynamic DHCP profiles</span>'
            + '<span><button class="btn btn-primary sm" data-dynp-add>+ Add profile</button></span></div>'
            + '<div class="table-wrap"><table class="data-table"><thead><tr>'
            + '<th>Name</th><th>DHCP addresses</th><th>TSIG key</th>'
            + '<th data-tip="Zones that follow this profile: a change here is applied to all of them">Zones</th><th class="right">Actions</th>'
            + '</tr></thead><tbody>' + rows + '</tbody></table></div></div>';
    }
    async function load() {
        try { var res = await api('dynamic/profiles', 'GET'); D = (res && res.data) || res; }
        catch (e) { var r = root(); if (r) r.innerHTML = '<div class="card"><p style="margin:0;color:var(--danger)">Failed to load: ' + esc(e && e.message) + '</p></div>'; return; }
        render();
    }
    function openEdit(p) {
        var ov = overlay(); if (!ov) return;
        ov.innerHTML = '<div class="modal"><form class="modal-card zs-card" id="dynp-form">'
            + '<h2 class="modal-title">' + (p ? 'Edit profile' : 'New profile') + '</h2>'
            + '<div class="zform-row"><label>Name</label><input class="field-input" id="dynp-name" value="' + esc(p ? p.name : '') + '" autocomplete="off"></div>'
            + formHtml('dynp-', p || {})
            + (p && p.zones ? '<div class="zform-note">Applies to ' + p.zones + ' zone(s) following it.</div>' : '')
            + '<div class="login-error" id="dynp-err" style="display:none;"></div>'
            + '<div class="modal-actions"><button type="button" class="btn btn-ghost" id="dynp-cancel">Cancel</button>'
            + '<button type="submit" class="btn btn-primary">Save</button></div></form></div>';
        ov.style.display = 'block';
        ov.querySelector('#dynp-cancel').addEventListener('click', closeModal);
        ov.querySelector('#dynp-form').addEventListener('submit', async function (e) {
            e.preventDefault();
            var body = formRead(ov, 'dynp-'); body.name = (ov.querySelector('#dynp-name').value || '').trim();
            try {
                var res = await api('dynamic/profiles' + (p ? '/' + p.id : ''), p ? 'PUT' : 'POST', body);
                closeModal();
                await load();
                var w = ((res && res.data) || {}).warnings || [];
                if (w.length) window.DNSPanel.alert({ message: 'Saved, but ' + w.join('; ') + '. The panel keeps retrying.' });
            } catch (err) { var el = ov.querySelector('#dynp-err'); el.textContent = (err && err.message) || 'Save failed'; el.style.display = 'block'; }
        });
    }
    document.addEventListener('click', async function (e) {
        var t = e.target;
        var zb = t.closest && t.closest('#zone-dynamic-btn');
        if (zb) {
            e.preventDefault();
            if (await openZone(zb.getAttribute('data-zone-id'), zb.getAttribute('data-type'))) {
                document.dispatchEvent(new CustomEvent('zoneChanged'));
            }
            return;
        }
        var r = root(); if (!r || !D || !r.contains(t)) return;
        if (t.closest('[data-dynp-add]')) { e.preventDefault(); openEdit(null); return; }
        var ed = t.closest('[data-dynp-edit]');
        if (ed) { e.preventDefault(); openEdit(D.profiles.filter(function (x) { return String(x.id) === ed.getAttribute('data-dynp-edit'); })[0]); return; }
        var dl = t.closest('[data-dynp-del]');
        if (dl) {
            e.preventDefault();
            var p = D.profiles.filter(function (x) { return String(x.id) === dl.getAttribute('data-dynp-del'); })[0] || {};
            if (!await window.DNSPanel.confirm({ title: 'Delete profile', danger: true, okText: 'Delete',
                    message: 'Delete <b>' + esc(p.name) + '</b>?' + (p.zones ? ' ' + p.zones + ' zone(s) follow it: they keep their current settings and stop following.' : '') })) return;
            try { await api('dynamic/profiles/' + p.id, 'DELETE'); await load(); }
            catch (err) { window.DNSPanel.alert((err && err.message) || 'Delete failed'); }
        }
    });

    // Mounted by the Settings tab like Import: own root and own state.
    window.DynamicTab = {
        mount: function () { D = null; return load(); },
        destroy: function () { D = null; }
    };
})();
