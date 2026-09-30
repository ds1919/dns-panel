/* DNS Panel — DNSSEC of a primary zone ("DNSSEC" in the zone header).
   PowerDNS signs the zone live from its keys; this modal only manages them: sign with one CSK, add a key
   (generated, or imported from a BIND .private file), activate/publish, delete, stop signing. The DS for the
   parent is shown with the KSK/CSK. */
(function () {
    'use strict';
    var ALGOS = ['ECDSAP256SHA256', 'ECDSAP384SHA384', 'ED25519', 'RSASHA256'].map(function (a) { return { value: a, label: a }; });
    var ROLES = [{ value: 'csk', label: 'CSK' }, { value: 'ksk', label: 'KSK' }, { value: 'zsk', label: 'ZSK' }];

    function esc(s) { return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'); }
    function api(path, method, body) { return window.DNSPanel.api(path, { method: method, body: body ? JSON.stringify(body) : undefined }); }
    function overlay() { return document.getElementById('modal-overlay'); }
    function closeModal() { var ov = overlay(); if (ov) { ov.style.display = 'none'; ov.innerHTML = ''; } }
    function sel(n, o, v) { return window.DNSPanel.selectHtml(n, o, v); }

    function keysHtml(d) {
        var rows = d.keys.map(function (k) {
            return '<tr data-kid="' + k.id + '"><td class="mono">' + esc(k.tag) + '</td><td>' + esc(k.keytype.toUpperCase()) + '</td>'
                + '<td class="mono">' + esc(k.algorithm) + '</td>'
                + '<td>' + (k.active ? 'Active' : '<span class="text-mute">Inactive</span>') + (k.published ? '' : ' · <span class="text-mute">not published</span>') + '</td>'
                + '<td class="right"><button type="button" class="btn btn-ghost btn-sm" data-k="active">' + (k.active ? 'Deactivate' : 'Activate') + '</button>'
                + '<button type="button" class="btn btn-ghost btn-sm" data-k="published">' + (k.published ? 'Unpublish' : 'Publish') + '</button>'
                + '<button type="button" class="btn btn-ghost btn-sm" data-k="delete">Delete</button></td></tr>';
        }).join('');
        // SHA-256 only: what registrars ask for.
        var ds = [];
        d.keys.forEach(function (k) { if (k.keytype !== 'zsk') (k.ds || []).forEach(function (x) { if (x.split(' ')[2] === '2') ds.push(x); }); });
        return '<table class="data-table dnssec-keys"><thead><tr><th>Tag</th><th>Role</th><th>Algorithm</th><th>State</th><th></th></tr></thead><tbody>' + rows + '</tbody></table>'
            + (ds.length ? '<div class="zform-row"><label>DS for the parent</label><div class="zform-grow">'
                + ds.map(function (x) { return '<div class="dnssec-ds"><code class="mono">' + esc(x) + '</code>'
                    + '<button type="button" class="btn btn-ghost btn-sm" data-copy="' + esc(x) + '">Copy</button></div>'; }).join('') + '</div></div>' : '');
    }
    function addHtml() {
        return '<div class="zform-row"><label>Add key</label><div class="zform-grow"><div class="dnssec-add">'
            + sel('dk-role', ROLES, 'zsk') + sel('dk-algo', ALGOS, 'ECDSAP256SHA256')
            + '<button type="button" class="btn btn-ghost" id="dk-gen">Generate</button>'
            + '<button type="button" class="btn btn-ghost" id="dk-imp-open">Import…</button></div>'
            + '<div id="dk-imp" hidden><textarea class="field-input mono" id="dk-priv" rows="4" placeholder="Contents of the BIND K….private file"></textarea>'
            + '<button type="button" class="btn btn-primary" id="dk-imp-ok">Import key</button></div></div></div>';
    }

    async function open(zid, name) {
        var ov = overlay(); if (!ov) return;
        ov.innerHTML = '<div class="modal"><div class="modal-card"><div class="spinner"></div></div></div>';
        ov.style.display = 'block';
        var changed = false;
        async function render() {
            var d;
            try { var r = await api('zones/' + zid + '/dnssec', 'GET'); d = (r && r.data) || r; }
            catch (e) { closeModal(); window.DNSPanel.alert((e && e.message) || 'Failed to load'); return; }
            var body = d.signed ? keysHtml(d) + addHtml()
                : '<p class="zform-note">Not signed.</p><div class="zform-row"><label>Algorithm</label>' + sel('dk-algo', ALGOS, 'ECDSAP256SHA256') + '</div>';
            ov.innerHTML = '<div class="modal"><div class="modal-card zs-card dnssec-card">'
                + '<h2 class="modal-title">DNSSEC — ' + esc(name) + '</h2>' + body
                + '<div class="login-error" id="dk-err" style="display:none;"></div>'
                + '<div class="modal-actions">'
                + (d.signed ? '<button type="button" class="btn btn-danger" id="dk-off">Stop signing</button>' : '')
                + '<button type="button" class="btn btn-ghost" id="dk-close">Close</button>'
                + (d.signed ? '' : '<button type="button" class="btn btn-primary" id="dk-on">Sign zone</button>')
                + '</div></div></div>';
            ov.querySelector('.dnssec-card').addEventListener('click', onClick);
        }
        function err(m) { var el = ov.querySelector('#dk-err'); if (el) { el.textContent = m; el.style.display = 'block'; } }
        async function act(fn) {
            try {
                var res = await fn(); changed = true;
                var s = ((res && res.data) || {}).sync;
                await render();
                if (s && s.pdns_state && s.pdns_state !== 'active') err('Saved, but ' + (s.detail || s.pdns_state) + '. The panel keeps retrying.');
            } catch (e) { err((e && e.message) || 'Failed'); }
        }
        function kinfo(tr) {
            return { id: tr.getAttribute('data-kid'), tag: tr.querySelector('td').textContent,
                     active: /^Active/.test(tr.children[3].textContent), published: !/not published/.test(tr.children[3].textContent) };
        }
        async function onClick(e) {
            var t = e.target;
            if (t.closest('#dk-close')) { closeModal(); if (changed) document.dispatchEvent(new CustomEvent('zoneChanged')); return; }
            if (t.closest('#dk-on')) return act(function () { return api('zones/' + zid + '/dnssec', 'PUT', { enabled: true, algorithm: ov.querySelector('[name="dk-algo"]').value }); });
            if (t.closest('#dk-off')) {
                var ok = await window.DNSPanel.confirm({ title: 'Stop signing', message: 'All keys of <b>' + esc(name) + '</b> are deleted. Remove the DS at the registrar first, or the zone stops resolving.', okText: 'Stop signing', danger: true });
                if (!ok) return;
                return act(function () { return api('zones/' + zid + '/dnssec', 'PUT', { enabled: false }); });
            }
            if (t.closest('#dk-gen')) return act(function () { return api('zones/' + zid + '/dnssec/keys', 'POST', { keytype: ov.querySelector('[name="dk-role"]').value, algorithm: ov.querySelector('[name="dk-algo"]').value }); });
            if (t.closest('#dk-imp-open')) { ov.querySelector('#dk-imp').hidden = false; ov.querySelector('#dk-priv').focus(); return; }
            if (t.closest('#dk-imp-ok')) return act(function () { return api('zones/' + zid + '/dnssec/keys', 'POST', { keytype: ov.querySelector('[name="dk-role"]').value, privatekey: ov.querySelector('#dk-priv').value }); });
            var cp = t.closest('[data-copy]');
            if (cp) { try { await navigator.clipboard.writeText(cp.getAttribute('data-copy')); cp.textContent = 'Copied'; } catch (x) {} return; }
            var b = t.closest('[data-k]'); if (!b) return;
            var k = kinfo(b.closest('tr')), what = b.getAttribute('data-k');
            if (what === 'delete') {
                var ok2 = await window.DNSPanel.confirm({ title: 'Delete key', message: 'Key <b>' + esc(k.tag) + '</b> is deleted from PowerDNS.', okText: 'Delete', danger: true });
                if (!ok2) return;
                return act(function () { return api('zones/' + zid + '/dnssec/keys/' + k.id, 'DELETE'); });
            }
            // Turning off a KSK/CSK can break the chain of trust at once (the DS points at it): ask first.
            var role = b.closest('tr').children[1].textContent;
            if (k[what] && (role === 'KSK' || role === 'CSK')) {
                var ok3 = await window.DNSPanel.confirm({ title: (what === 'active' ? 'Deactivate ' : 'Unpublish ') + role,
                    message: 'If the parent’s DS points at key <b>' + esc(k.tag) + '</b>, the zone stops validating.',
                    okText: what === 'active' ? 'Deactivate' : 'Unpublish', danger: true });
                if (!ok3) return;
            }
            var body = {}; body[what] = !k[what];
            return act(function () { return api('zones/' + zid + '/dnssec/keys/' + k.id, 'PUT', body); });
        }
        await render();
    }

    document.addEventListener('click', function (e) {
        var b = e.target.closest && e.target.closest('#zone-dnssec-btn');
        if (!b) return;
        e.preventDefault();
        open(b.getAttribute('data-zone-id'), b.getAttribute('data-name'));
    });
})();
