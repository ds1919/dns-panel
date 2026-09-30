/* DNS Panel — Manage Zone (records) logic.
   The edit unit is an RRset (name+type); writes go through /dns-api. */

(function () {
    'use strict';

    function esc(s) {
        return String(s == null ? '' : s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }
    function zoneId() {
        var el = document.getElementById('rr-add') || document.getElementById('soa-acc');
        if (el && el.getAttribute('data-zone-id')) return el.getAttribute('data-zone-id');
        var m = /[?&]zone=(\d+)/.exec(window.location.search); return m ? m[1] : null;
    }
    function zoneName() {
        var el = document.getElementById('rr-add') || document.getElementById('soa-acc');
        return el ? (el.getAttribute('data-zone-name') || el.getAttribute('data-zone') || '') : '';
    }
    function fqdn(name, zone) {
        name = (name || '').trim().replace(/\s+/g, '').replace(/\.$/, '');
        if (name === '' || name === '@') return zone;
        var ln = name.toLowerCase(), lz = zone.toLowerCase();
        return (ln === lz || ln.slice(-lz.length - 1) === '.' + lz) ? name : name + '.' + zone;
    }
    // Structured types (MX/SRV/CAA) build content from sub-fields; the rest use a single Value.
    function typeSpec(type) {
        type = (type || '').toUpperCase();
        if (type === 'MX') return {
            fields: [{ k: 'prio', label: 'Priority', ph: '10', num: 1, param: 1 }, { k: 'content', label: 'Mail server', ph: 'mail1.example.com.' }],
            compose: function (v) { return { prio: v.prio, content: v.content }; },
            parse: function (r) { return { prio: r.prio || '', content: r.content || '' }; }
        };
        if (type === 'SRV') return {
            fields: [{ k: 'prio', label: 'Priority', num: 1, param: 1 }, { k: 'weight', label: 'Weight', num: 1, param: 1 }, { k: 'port', label: 'Port', num: 1, param: 1 }, { k: 'target', label: 'Target', ph: 'server.example.com.' }],
            compose: function (v) { return { prio: v.prio, content: [v.weight, v.port, v.target].join(' ') }; },
            parse: function (r) { var p = (r.content || '').split(/\s+/); return { prio: r.prio || '', weight: p[0] || '', port: p[1] || '', target: p[2] || '' }; }
        };
        if (type === 'CAA') return {
            fields: [{ k: 'flags', label: 'Flags', ph: '0', num: 1, param: 1 }, { k: 'tag', label: 'Tag', options: ['issue', 'issuewild', 'iodef'], param: 1 }, { k: 'value', label: 'Value', ph: 'letsencrypt.org' }],
            // CAA value is double-quoted (PowerDNS/gmysql requirement; the backend canonicalizes too).
            compose: function (v) {
                var val = String(v.value == null ? '' : v.value).replace(/^"([\s\S]*)"$/, '$1').replace(/"/g, '\\"');
                return { prio: null, content: [v.flags, v.tag, '"' + val + '"'].join(' ') };
            },
            parse: function (r) {
                var m = (r.content || '').match(/^(\S+)\s+(\S+)\s+([\s\S]*)$/);
                if (!m) return { flags: '', tag: 'issue', value: r.content || '' };
                var val = m[3].replace(/^"([\s\S]*)"$/, '$1').replace(/\\"/g, '"');
                return { flags: m[1], tag: m[2], value: val };
            }
        };
        var ph = { A: '192.0.2.10', AAAA: '2001:db8::1', CNAME: 'host.example.com.', NS: 'ns1.example.com.', TXT: '"v=..."', DNAME: 'target.example.com.' }[type] || 'value';
        return {
            fields: [{ k: 'content', label: 'Value', ph: ph }],
            compose: function (v) { return { prio: null, content: v.content }; },
            parse: function (r) { return { content: r.content || '' }; }
        };
    }
    // compact=true: inline-edit styling; noLabels=true: no labels (the column header names the field).
    function fieldsHtml(fields, vals, compact, noLabels) {
        vals = vals || {};
        return fields.map(function (f) {
            var v = vals[f.k] == null ? '' : vals[f.k];
            var inp;
            if (f.options) {
                inp = window.DNSPanel.selectHtml(f.k, f.options.map(function (o) { return { value: o, label: o }; }), v || f.options[0]);
            } else {
                inp = '<input class="field-input ' + (compact ? 'rie-f ' : 'rai-f ') + (f.num ? 'f-num' : 'f-val') + '" data-k="' + f.k + '"' +
                      (f.num ? ' inputmode="numeric"' : '') + ' value="' + esc(v) + '"' + (f.ph ? ' placeholder="' + esc(f.ph) + '"' : '') + '>';
            }
            return (noLabels ? '' : '<label class="rai-lbl">' + esc(f.label) + '</label>') + inp;
        }).join('');
    }
    function readFields(spec, root) {
        var vals = {};
        spec.fields.forEach(function (f) {
            var el = f.options ? root.querySelector('[name="' + f.k + '"]') : root.querySelector('[data-k="' + f.k + '"]');
            vals[f.k] = el ? el.value.trim() : '';
        });
        return vals;
    }

    // Expand IPv6 into 32 hex nibbles (handles ::); null if invalid.
    function expandV6(ip) {
        if (ip.indexOf(':') < 0) return null;
        var halves = ip.split('::');
        if (halves.length > 2) return null;
        var head = halves[0] ? halves[0].split(':') : [];
        var groups;
        if (halves.length === 2) {
            var tail = halves[1] ? halves[1].split(':') : [];
            var mid = 8 - head.length - tail.length;
            if (mid < 0) return null;
            groups = head.concat(new Array(mid).fill('0'), tail);
        } else {
            groups = head;
            if (groups.length !== 8) return null;
        }
        var nib = '';
        for (var i = 0; i < 8; i++) {
            var g = groups[i] || '0';
            if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
            nib += ('000' + g.toLowerCase()).slice(-4);
        }
        return nib;   // 32 nibbles
    }
    // PTR owner FQDN from reverse-zone input: a full IPv4/IPv6 is expanded, anything else is a name
    // relative to the zone. null if the IP is outside this reverse zone.
    function revPtrOwner(input, zone, kind) {
        input = (input || '').trim();
        if (!input) return null;
        var zl = zone.toLowerCase();
        var m4 = input.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
        if (m4) {
            for (var i = 1; i <= 4; i++) { if (+m4[i] > 255) return null; }
            var owner = m4[4] + '.' + m4[3] + '.' + m4[2] + '.' + m4[1] + '.in-addr.arpa';
            return (owner === zl || owner.slice(-zl.length - 1) === '.' + zl) ? owner : null;
        }
        if (input.indexOf(':') >= 0) {
            var nib = expandV6(input);
            if (!nib) return null;
            var o6 = nib.split('').reverse().join('.') + '.ip6.arpa';
            return (o6 === zl || o6.slice(-zl.length - 1) === '.' + zl) ? o6 : null;
        }
        return fqdn(input, zone);   // relative name, e.g. "17" in a /24 zone
    }

    // Returns true only if the page was actually refreshed (same approach as js/zones.js).
    async function reload() {
        var main = document.getElementById('main-content');
        if (!main) return false;
        try {
            var res = await fetch('/ajax/records' + window.location.search, { credentials: 'same-origin' });
            if (res.status === 401 || res.redirected) { window.location.href = '/login'; return false; }
            // fetch rejects only on network errors; without this check a 500/403 page would be inserted as content.
            if (!res.ok) throw new Error('HTTP ' + res.status);
            var accOpen = (document.getElementById('soa-acc') || {}).open;
            var flt = captureRrFilters();   // filters survive reload
            main.innerHTML = await res.text();
            var acc = document.getElementById('soa-acc'); if (acc && accOpen) acc.open = true;
            initInlineAdd();
            localizeTimes();
            sortRows();
            restoreRrFilters(flt);
            applyRrFilters();
            fetchPtrStatus();
            return true;
        } catch (e) { console.error('records: reload failed', e); return false; }
    }
    // After an action: the fresh page comes from the server (the single renderer), but only what differs is
    // changed in the live one. Untouched rows, filters, selection, the open accordion and the half-typed add
    // form stay as they are. A zone whose role changed, or a secondary (its page has other blocks and no
    // record editing), takes the whole page as before.
    var PARTS = ['.zone-head', '#zone-labels-row', '#zs-cat-data', '#sync-banner', '.soa-acc-sum', '#soa-row', '#ns-table tbody'];
    async function refresh() {
        if (!document.getElementById('rr-tbody')) return reload();
        try {
            var changed = await window.DNSPanel.patchPage({
                url: '/ajax/records' + window.location.search,
                same: function (f) { return !!f.querySelector('#rr-tbody') && zoneType(f) === zoneType(document) && zoneType(f) !== 'SLAVE'; },
                // Rows by their data-* facts: the cells were already changed in place (PTR filled, times localized).
                lists: [{ sel: '#rr-tbody', item: 'tr.rr-row', key: 'data-id', by: 'attrs', keep: '.rr-check' }],
                parts: PARTS, after: { '#sync-banner': '#zs-cat-data' } });
            if (!changed) return reload();
            changed.forEach(function (el) { localizeTimes(el); });
            sortRows();
            applyRrFilters();
            updateBulk();   // removed rows take their selection with them
            fetchPtrStatus();
            return true;
        } catch (e) { console.error('records: refresh failed', e); return reload(); }
    }
    function zoneType(root) {
        var d = root.querySelector('#zs-cat-data');
        try { return (JSON.parse(d.textContent) || {}).zone_type || ''; } catch (e) { return ''; }
    }
    function overlay() { return document.getElementById('modal-overlay'); }
    function closeModal() { closeCopyPop(); var ov = overlay(); if (ov) { ov.style.display = 'none'; ov.innerHTML = ''; } }

    // Honest sync reporting: the DB write succeeded, but PowerDNS may not have confirmed serving the new
    // serial. data.sync is {pdns_state,notify_state,detail} or {forward:{...},reverse:{...}} (A+PTR).
    function syncPairs(sync) {
        if (!sync) return [];
        if (sync.forward || sync.reverse) {
            var out = [];
            if (sync.forward) out.push(['forward', sync.forward]);
            if (sync.reverse) out.push(['reverse', sync.reverse]);
            return out;
        }
        return [['zone', sync]];
    }
    function warnSync(res) {
        var d = (res && res.data) || res || {};
        var pairs = syncPairs(d.sync);
        var actFail = pairs.filter(function (s) { return s[1] && s[1].pdns_state === 'activation_failed'; });
        var ntFail  = pairs.filter(function (s) { return s[1] && s[1].pdns_state === 'active' && s[1].notify_state === 'notify_failed'; });
        var stErr   = pairs.filter(function (s) { return s[1] && s[1].state_error; });
        if (!actFail.length && !ntFail.length && !stErr.length) return;
        var msg = 'Saved to the database';
        if (actFail.length) {
            msg += ', but PowerDNS did not confirm serving the updated zone:<br>' +
                actFail.map(function (s) { return '<b>' + esc(s[0]) + '</b>: ' + esc((s[1] && s[1].detail) || 'activation failed'); }).join('<br>') +
                '<br><span style="color:var(--text-dim)">The change is durable; a controller/operator can retry activation.</span>';
        } else if (ntFail.length) {
            msg += ' and served by PowerDNS, but NOTIFY to secondaries failed:<br>' +
                ntFail.map(function (s) { return '<b>' + esc(s[0]) + '</b>'; }).join('<br>') +
                '<br><span style="color:var(--text-dim)">Secondaries will catch up on their refresh timer.</span>';
        }
        if (stErr.length) {
            // Sync state was not written, so the background worker will not retry this zone (no next_retry).
            msg += '<br><br><b style="color:var(--danger)">Sync state was not saved</b> for: ' +
                stErr.map(function (s) { return '<b>' + esc(s[0]) + '</b>'; }).join(', ') +
                '.<br><span style="color:var(--text-dim)">Automatic retry is NOT scheduled — retry manually once the state database is reachable.</span>';
        }
        window.DNSPanel.alert({ title: 'Sync not confirmed', message: msg });
    }

    // Copy popover for the full value (history cells are truncated).
    function closeCopyPop() { var p = document.getElementById('copy-pop'); if (p) p.remove(); }
    function openCopyPop(cell) {
        closeCopyPop();
        var full = cell.getAttribute('title') || cell.textContent || '';
        var p = document.createElement('div'); p.id = 'copy-pop'; p.className = 'copy-pop';
        var txt = document.createElement('div'); txt.className = 'copy-pop-txt'; txt.textContent = full;
        var btn = document.createElement('button'); btn.type = 'button'; btn.className = 'btn btn-primary btn-sm copy-pop-btn'; btn.textContent = 'Copy';
        p.appendChild(txt); p.appendChild(btn);
        document.body.appendChild(p);
        var r = cell.getBoundingClientRect();
        p.style.left = Math.max(8, Math.min(r.left, window.innerWidth - 340)) + 'px';
        p.style.top = (r.bottom + 4) + 'px';
        // Preselect the text so Ctrl+C works immediately.
        var range = document.createRange(); range.selectNodeContents(txt);
        var sel = window.getSelection(); sel.removeAllRanges(); sel.addRange(range);
        btn.addEventListener('click', function () {
            var ta = document.createElement('textarea'); ta.value = full;
            ta.style.position = 'fixed'; ta.style.left = '-9999px'; ta.setAttribute('readonly', '');
            document.body.appendChild(ta); ta.select();
            var ok = false; try { ok = document.execCommand('copy'); } catch (e) {}
            document.body.removeChild(ta);
            btn.textContent = ok ? 'Copied' : 'Ctrl+C';
            if (ok) setTimeout(closeCopyPop, 600);
        });
    }

    function fmtLocal(u) { return u ? window.DNSPanel.fmtTime(u) : ''; }
    function localizeTimes(root) {
        (root || document).querySelectorAll('.lc-time[data-utc]').forEach(function (el) {
            var u = el.getAttribute('data-utc'); if (u) el.textContent = fmtLocal(u);
        });
    }

    // ---------- Inline-add ----------
    function resetInlineAdd() {
        var host = document.getElementById('rr-add');
        if (host) { delete host.dataset.ready; initInlineAdd(); }
    }
    function initInlineAdd() {
        var host = document.getElementById('rr-add');
        if (!host || host.dataset.ready) return;
        host.dataset.ready = '1';
        var kind = host.getAttribute('data-kind') || 'forward';
        if (kind.indexOf('reverse') === 0) {
            // Reverse zone: the type is fixed to PTR.
            host.innerHTML =
                '<div class="rr-add-inline rr-add-ptr">' +
                '<label class="rai-lbl">IP or host</label><input class="field-input rai-ip" id="ra-ip" placeholder="10.20.30.17 or 17" autocomplete="off">' +
                '<label class="rai-lbl">PTR target</label><input class="field-input rai-val" id="ra-val" placeholder="host.example.corp." autocomplete="off">' +
                '<label class="rai-lbl">TTL</label><input class="field-input rai-ttl" id="ra-ttl" value="3600">' +
                '<button type="button" class="btn btn-primary" id="ra-add">+ Add PTR</button>' +
                '<span class="login-error" id="ra-err" style="display:none;"></span>' +
                '</div>';
            return;
        }
        var types = [];
        try { types = JSON.parse(host.getAttribute('data-types') || '[]'); } catch (e) {}
        if (!types.length) types = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SRV', 'CAA'];
        host.innerHTML =
            '<div class="rr-add-inline">' +
            // Zone suffix next to the name so the record can't land in the wrong zone. It is only a label:
            // the server still builds the FQDN.
            '<label class="rai-lbl">Name</label><input class="field-input rai-name" id="ra-name" placeholder="@ or www" autocomplete="off">' +
            '<span class="rai-zone mono">.' + esc(zoneName()) + '</span>' +
            '<label class="rai-lbl">Type</label>' +
              window.DNSPanel.selectHtml('ra-type', types.map(function (t) { return { value: t, label: t }; }), types[0]) +
            '<span id="ra-fields" class="rai-fields"></span>' +
            '<label class="rai-lbl">TTL</label><input class="field-input rai-ttl" id="ra-ttl" value="3600">' +
            // Create PTR is on by default: the reverse record is almost always wanted and easy to forget here.
            '<label class="rai-ptr" id="ra-ptr-wrap" style="display:none;"><input type="checkbox" id="ra-ptr" checked> Create PTR</label>' +
            '<button type="button" class="btn btn-primary" id="ra-add">+ Add</button>' +
            '<span class="login-error" id="ra-err" style="display:none;"></span>' +
            '</div>';
        var typeEl = host.querySelector('[name="ra-type"]');
        // Create PTR applies only to addresses (A and AAAA).
        function renderAddFields() {
            host.querySelector('#ra-fields').innerHTML = fieldsHtml(typeSpec(typeEl.value).fields, {}, false);
            host.querySelector('#ra-ptr-wrap').style.display = (typeEl.value === 'A' || typeEl.value === 'AAAA') ? '' : 'none';
        }
        typeEl.addEventListener('change', renderAddFields); renderAddFields();
    }

    async function submitInlineAdd() {
        var host = document.getElementById('rr-add'); if (!host) return;
        var zid = zoneId(), zn = zoneName();
        var kind = host.getAttribute('data-kind') || 'forward';
        var errEl = host.querySelector('#ra-err');
        var ttl = host.querySelector('#ra-ttl').value.trim();
        errEl.style.display = 'none';
        var payload = { ttl: ttl ? parseInt(ttl, 10) : undefined };
        if (kind.indexOf('reverse') === 0) {
            var ipin = host.querySelector('#ra-ip').value.trim();
            var tgt = host.querySelector('#ra-val').value.trim();
            if (!ipin) { errEl.textContent = 'IP or host required'; errEl.style.display = ''; return; }
            if (!tgt) { errEl.textContent = 'PTR target required'; errEl.style.display = ''; return; }
            var owner = revPtrOwner(ipin, zn, kind);
            if (!owner) { errEl.textContent = 'IP is not inside this reverse zone'; errEl.style.display = ''; return; }
            payload.name = owner; payload.type = 'PTR'; payload.content = tgt;
        } else {
            var type = host.querySelector('[name="ra-type"]').value;
            var spec = typeSpec(type);
            var comp = spec.compose(readFields(spec, host.querySelector('#ra-fields')));
            if (!comp.content || comp.content === undefined) { errEl.textContent = 'Value required'; errEl.style.display = ''; return; }
            payload.name = host.querySelector('#ra-name').value.trim(); payload.type = type; payload.content = comp.content;
            if (comp.prio != null && comp.prio !== '') payload.prio = comp.prio;
            // A + PTR has its own path (preflight, then a prompt on conflict/not-managed).
            var ptrEl = host.querySelector('#ra-ptr');
            if ((type === 'A' || type === 'AAAA') && ptrEl && ptrEl.checked) {
                payload.ptr_mode = 'auto';
                var btnP = host.querySelector('#ra-add'); btnP.disabled = true;
                addAddressWithPtr(payload).catch(function () {}).then(function () { btnP.disabled = false; });
                return;
            }
        }
        // One record per POST; the backend enforces RRset integrity.
        var btn = host.querySelector('#ra-add'); btn.disabled = true;
        try {
            var res = await window.DNSPanel.api('zones/' + zid + '/records', { method: 'POST', body: JSON.stringify(payload) });
            await refresh();
            resetInlineAdd();   // a clean form for the next record, as the full reload used to give
            warnSync(res);
        } catch (e) {
            errEl.textContent = e && e.message ? e.message : 'Add failed'; errEl.style.display = ''; btn.disabled = false;
        }
    }

    // A + PTR via POST /records/with-ptr; when blocked (conflict/not_managed) ask the user.
    async function addAddressWithPtr(payload) {
        var host = document.getElementById('rr-add'); var errEl = host && host.querySelector('#ra-err');
        try {
            var r = await window.DNSPanel.api('zones/' + zoneId() + '/records/with-ptr', { method: 'POST', body: JSON.stringify(payload) });
            var d = r.data || r;
            if (d && d.blocked) { openPtrPrompt(payload, d); return; }
            closeModal(); await refresh();
            resetInlineAdd();
            warnSync(r);
        } catch (e) {
            if (errEl) { errEl.textContent = e && e.message ? e.message : 'Add failed'; errEl.style.display = ''; }
        }
    }
    function openPtrPrompt(payload, d) {
        var ov = overlay(); if (!ov) return;
        var body, acts;
        // conflict: points elsewhere; multiple: this name is there among others; disabled: exists but is off.
        // Same actions, different news, so say which one it is.
        if (d.reason === 'conflict' || d.reason === 'multiple' || d.reason === 'disabled') {
            var lead = d.reason === 'multiple'
                ? 'Several PTR records at <b class="mono">' + esc(d.owner) + '</b>, and this name is already one of them.'
                : d.reason === 'disabled'
                ? 'A disabled PTR record already exists at <b class="mono">' + esc(d.owner) + '</b>.'
                : 'PTR conflict at <b class="mono">' + esc(d.owner) + '</b>.';
            body = '<p style="color:var(--text-dim);font-size:13px;line-height:1.5;">' + lead + '<br>' +
                'Already points to: <b class="mono">' + esc((d.existing || []).join(', ')) + '</b><br>' +
                'You are adding: <b class="mono">' + esc(d.target) + '</b></p>';
            acts = '<button type="button" class="btn btn-ghost" id="ptr-cancel">Cancel</button>' +
                '<button type="button" class="btn btn-ghost" id="ptr-aonly">Create address only</button>' +
                '<button type="button" class="btn btn-primary" id="ptr-replace">Replace PTR</button>';
        } else {
            body = '<p style="color:var(--text-dim);font-size:13px;line-height:1.5;">PTR cannot be created here.<br>' +
                'Reverse DNS for <b class="mono">' + esc(d.ip) + '</b> is not managed by this panel' +
                (d.reverse_zone ? ' (zone <b class="mono">' + esc(d.reverse_zone) + '</b> is not writable here)' : '') + '.<br>' +
                'Create the PTR on the authoritative external DNS service.</p>';
            acts = '<button type="button" class="btn btn-ghost" id="ptr-cancel">Cancel</button>' +
                '<button type="button" class="btn btn-primary" id="ptr-aonly">Create address only</button>';
        }
        ov.innerHTML = '<div class="modal"><div class="modal-card">' +
            '<div class="modal-head"><h2 class="modal-title">Create PTR</h2>' +
            '<button type="button" class="modal-x" id="ptr-x" aria-label="Close">×</button></div>' +
            body + '<div class="modal-actions">' + acts + '</div></div></div>';
        ov.style.display = 'block';
        ov.querySelector('#ptr-cancel').addEventListener('click', closeModal);
        ov.querySelector('#ptr-x').addEventListener('click', closeModal);
        var ao = ov.querySelector('#ptr-aonly'); if (ao) ao.addEventListener('click', function () { payload.ptr_mode = 'a_only'; addAddressWithPtr(payload); });
        var rp = ov.querySelector('#ptr-replace'); if (rp) rp.addEventListener('click', function () { payload.ptr_mode = 'replace'; addAddressWithPtr(payload); });
    }

    // ---------- SOA: in-place edit of the compact row ----------
    function openSoaInline() {
        var row = document.getElementById('soa-row'); if (!row || row.classList.contains('soa-editing')) return;
        row._bak = {};
        row.querySelectorAll('td.soa-f').forEach(function (td) {
            var f = td.getAttribute('data-f'); row._bak[f] = td.innerHTML;
            td.innerHTML = '<input class="field-input soa-inp" data-f="' + f + '" value="' + esc(td.textContent.trim()) + '">';
        });
        var act = row.querySelector('.soa-act'); row._bakAct = act.innerHTML;
        act.innerHTML = '<a href="#" class="link soa-save">Save</a> <a href="#" class="link soa-cancel" style="margin-left:.5rem;">Cancel</a>' +
            '<span class="login-error soa-err" style="display:none;margin-left:.5rem;"></span>';
        row.classList.add('soa-editing');
        var f = row.querySelector('.soa-inp'); if (f) { f.focus(); f.select(); }
    }
    function closeSoaInline() {
        var row = document.getElementById('soa-row'); if (!row || !row._bak) return;
        row.querySelectorAll('td.soa-f').forEach(function (td) { var f = td.getAttribute('data-f'); if (row._bak[f] != null) td.innerHTML = row._bak[f]; });
        if (row._bakAct != null) row.querySelector('.soa-act').innerHTML = row._bakAct;
        row.classList.remove('soa-editing'); delete row._bak; delete row._bakAct;
    }
    async function saveSoaInline() {
        var row = document.getElementById('soa-row'); if (!row) return;
        var payload = {};
        row.querySelectorAll('.soa-inp').forEach(function (i) { payload[i.getAttribute('data-f')] = i.value.trim(); });
        // serial is not sent: the server bumps it.
        var errEl = row.querySelector('.soa-err');
        try {
            var res = await window.DNSPanel.api('zones/' + zoneId() + '/soa', { method: 'PATCH', body: JSON.stringify(payload) });
            await refresh();
            warnSync(res);
        } catch (e) { if (errEl) { errEl.textContent = e && e.message ? e.message : 'Save failed'; errEl.style.display = ''; } }
    }

    // ---------- NS: per-row CRUD of apex NS (one record per NS; TTL applies to the whole RRset) ----------
    function openNsInline(row) {
        if (row.classList.contains('ns-editing')) return;
        var vcell = row.querySelector('.ns-v'), tcell = row.querySelector('.ns-ttl'), acell = row.querySelector('td:last-child');
        row._bakV = vcell.innerHTML; row._bakT = tcell.innerHTML; row._bakA = acell.innerHTML;
        vcell.innerHTML = '<input class="field-input ns-inp" value="' + esc(row.getAttribute('data-val')) + '">';
        tcell.innerHTML = '<input class="field-input ns-ttl-inp" value="' + esc(row.getAttribute('data-ttl') || '') + '" data-tip="TTL (applies to all NS)">';
        acell.innerHTML = '<a href="#" class="link ns-save">Save</a> <a href="#" class="link ns-cancel" style="margin-left:.5rem;">Cancel</a>';
        row.classList.add('ns-editing');
        var i = vcell.querySelector('.ns-inp'); if (i) { i.focus(); i.select(); }
    }
    function closeNsInline(row) {
        if (row._bakV == null) return;
        row.querySelector('.ns-v').innerHTML = row._bakV;
        row.querySelector('.ns-ttl').innerHTML = row._bakT;
        row.querySelector('td:last-child').innerHTML = row._bakA;
        row.classList.remove('ns-editing'); delete row._bakV; delete row._bakT; delete row._bakA;
    }
    async function saveNsInline(row) {
        var content = row.querySelector('.ns-inp').value.trim();
        var ttl = row.querySelector('.ns-ttl-inp').value.trim();
        if (!content) { window.DNSPanel.alert('Name server is required'); return; }
        try {
            var res = await window.DNSPanel.api('zones/' + zoneId() + '/name-servers/' + row.getAttribute('data-id'),
                { method: 'PATCH', body: JSON.stringify({ content: content, ttl: ttl || undefined }) });
            await refresh();
            warnSync(res);
        } catch (e) { window.DNSPanel.alert(e && e.message ? e.message : 'Save failed'); }
    }
    async function deleteNs(row) {
        if (!(await window.DNSPanel.confirm({ title: 'Delete name server', message: 'Delete name server <b class="mono">' + esc(row.getAttribute('data-val')) + '</b>?', okText: 'Delete', danger: true }))) return;
        try {
            var res = await window.DNSPanel.api('zones/' + zoneId() + '/name-servers/' + row.getAttribute('data-id'), { method: 'DELETE' });
            await refresh();
            warnSync(res);
        } catch (e) { window.DNSPanel.alert(e && e.message ? e.message : 'Delete failed'); }
    }
    async function addNs() {
        var inp = document.querySelector('.ns-add-input'), ttlEl = document.querySelector('.ns-add-ttl');
        var v = inp ? inp.value.trim() : ''; if (!v) { if (inp) inp.focus(); return; }
        var ttl = ttlEl ? ttlEl.value.trim() : '';
        try {
            var res = await window.DNSPanel.api('zones/' + zoneId() + '/name-servers',
                { method: 'POST', body: JSON.stringify({ content: v, ttl: ttl || undefined }) });
            await refresh();
            warnSync(res);
        } catch (e) { window.DNSPanel.alert(e && e.message ? e.message : 'Add failed'); }
    }

    // ---------- In-place edit of one record (only cell contents change; the row stays) ----------
    // Cells are found by class, not index: the Pulse column once shifted Actions by one and Save/Cancel
    // silently landed in "Last change". With names, a new column can't break this and a missing cell shows.
    var RIE_CELLS = ['rr-params', 'rr-val', 'rr-ttl', 'rr-status', 'rr-actions'];
    function cellOf(row, cls) { return row.querySelector('td.' + cls); }
    function restoreRow(row) {
        if (!row._rieBackup) return;
        var b = row._rieBackup;
        Object.keys(b).forEach(function (c) { var td = cellOf(row, c); if (td) td.innerHTML = b[c]; });
        row.classList.remove('rr-editing');
        delete row._rieBackup;
    }
    function closeInlineEditors() {
        document.querySelectorAll('tr.rr-editing').forEach(restoreRow);
    }
    function openInlineEdit(row) {
        if (row.classList.contains('rr-editing')) { restoreRow(row); return; }   // second click closes
        closeInlineEditors();
        var type = row.getAttribute('data-type');
        var spec = typeSpec(type);
        var vals = spec.parse({ content: row.getAttribute('data-content') || '', prio: row.getAttribute('data-prio') || '' });
        var ttl = row.getAttribute('data-ttl'), disabled = row.getAttribute('data-disabled') === '1';
        var paramF = spec.fields.filter(function (f) { return f.param; });
        var valueF = spec.fields.filter(function (f) { return !f.param; });
        row._rieBackup = {};
        RIE_CELLS.forEach(function (c) { var td = cellOf(row, c); if (td) row._rieBackup[c] = td.innerHTML; });
        cellOf(row, 'rr-params').innerHTML = paramF.length ? '<div class="rie-fields">' + fieldsHtml(paramF, vals, true) + '</div>' : '';
        cellOf(row, 'rr-val').innerHTML = '<div class="rie-fields">' + fieldsHtml(valueF, vals, true, true) + '</div>';
        cellOf(row, 'rr-ttl').innerHTML = '<input class="field-input rie-ttl" value="' + esc(ttl || '3600') + '">';
        cellOf(row, 'rr-status').innerHTML = window.DNSPanel.selectHtml('rie-status',
            [{ value: 'active', label: 'Enabled' }, { value: 'disabled', label: 'Disabled' }],
            disabled ? 'disabled' : 'active');
        cellOf(row, 'rr-actions').innerHTML =
            '<a href="#" class="link rie-save">Save</a>' +
            '<a href="#" class="link rie-cancel" style="margin-left:.6rem;">Cancel</a>' +
            '<span class="login-error rie-err" style="display:none;margin-left:.4rem;"></span>';
        row.classList.add('rr-editing');
        var f = cellOf(row, 'rr-val').querySelector('input,.ui-select-trigger'); if (f && f.focus) { f.focus(); if (f.select) f.select(); }
    }
    async function saveInlineEdit(row) {
        var type = row.getAttribute('data-type');
        var spec = typeSpec(type);
        var comp = spec.compose(readFields(spec, row));   // fields span two cells (Parameters + Value)
        var statusEl = row.querySelector('[name="rie-status"]');
        var dis = statusEl && statusEl.value === 'disabled';
        var ttl = row.querySelector('.rie-ttl').value.trim();
        var errEl = row.querySelector('.rie-err');
        if (!comp.content) { if (errEl) { errEl.textContent = 'Value required (use Delete to remove)'; errEl.style.display = ''; } return; }
        try {
            var res = await window.DNSPanel.api('zones/' + zoneId() + '/records/' + row.getAttribute('data-id'),
                { method: 'PATCH', body: JSON.stringify({ content: comp.content, ttl: ttl || undefined, prio: comp.prio, disabled: dis }) });
            await refresh();
            warnSync(res);
        } catch (err) {
            if (errEl) { errEl.textContent = err && err.message ? err.message : 'Save failed'; errEl.style.display = ''; }
        }
    }

    // ---------- Zone settings ----------
    // One form for zone settings: role, dynamic updates, downstream distribution and profile.
    // Editable address-list row; same markup as Add zone (.zform-list-row).
    function srcRow(v) {
        return '<div class="zform-list-row src-row"><input type="text" class="field-input src-input" value="' + esc(v || '') +
               '" placeholder="IPv4 or IPv6 address" autocomplete="off">' +
               '<button type="button" class="btn btn-ghost zform-x src-del">\u00d7</button></div>';
    }
    async function openZoneSettings(btn) {
        var ov = overlay(); if (!ov) return;
        var zid = btn.getAttribute('data-zone-id');
        var curProfile = btn.getAttribute('data-profile') || '';
        ov.innerHTML = '<div class="modal"><div class="modal-card"><div class="spinner"></div></div></div>';
        ov.style.display = 'block';
        var curCatalog = btn.getAttribute('data-catalog') || '';
        var zsc = {}; try { var ce = document.getElementById('zs-cat-data'); if (ce) zsc = JSON.parse(ce.textContent); } catch (e) {}
        // profiles = [{code,name}]; the zone's current code may be disabled or deleted, so add it as is.
        var profiles = [];
        try { var r = await window.DNSPanel.api('zones/defaults', { method: 'GET' }); profiles = ((r.data || r).profiles) || []; } catch (e) {}
        if (curProfile && !profiles.some(function (p) { return p.code === curProfile; })) profiles = [{ code: curProfile, name: curProfile }].concat(profiles);
        // None is valid: a migrated zone has no profile, and a wrong one must be removable.
        var profOpts = [{ value: '', label: 'None' }].concat(profiles.map(function (p) { return { value: p.code, label: p.name || p.code }; }));
        // Distribution is two independent facts, asked separately: served by direct AXFR, and which catalog
        // announces it. A zone can be in both, one or neither.
        var zcats = zsc.catalogs || [];
        var curDirect  = zsc.direct ? 1 : 0;
        var curCatId   = zsc.catalog_id ? String(zsc.catalog_id) : '';
        var curCatName = (function () { for (var i = 0; i < zcats.length; i++)
                                          if (String(zcats[i].catalog_id) === curCatId) return window.DNSPanel.catalogLabel(zcats[i]);
                                        return ''; })();
        var downRow;
        if (!zsc.can_change_delivery) {
            downRow = '<div class="zform-row"><label>Direct AXFR</label><div class="zform-grow">'
                    + '<div class="zs-role-ro">' + (curDirect ? 'Allow' : 'None') + '</div>'
                    + '<div class="zform-note">needs distribution.manage</div></div></div>';
        } else {
            downRow = '<div class="zform-row"><label>Direct AXFR' + window.DNSPanel.helpDot('zs-direct', 'Servers and groups in Propagation get this zone by AXFR and NOTIFY.') + '</label><div class="zform-grow">'
                    + '<label class="chk" style="margin-right:1.2rem;"><input type="radio" name="zs-down" value="1"'
                      + (curDirect ? ' checked' : '') + '> Allow</label>'
                    + '<label class="chk"><input type="radio" name="zs-down" value=""' + (curDirect ? '' : ' checked') + '> None</label></div></div>';
        }
        // Only primary zones go into a catalog (a PRODUCER announces only its own zones), so the control is
        // not offered otherwise.
        var ztype = String(zsc.zone_type || '').toUpperCase();
        var canCat = ztype === 'MASTER';
        var catRow;
        if (!canCat) {
            catRow = '<div class="zform-row"><label>Catalog</label><div class="zform-grow">'
                   + '<div class="zs-role-ro">None</div>'
                   + '<div class="zform-note">Primary zones only</div></div></div>';
        } else if (!zsc.can_change_catalog) {
            catRow = '<div class="zform-row"><label>Catalog</label><div class="zform-grow">'
                   + '<div class="zs-role-ro">' + (curCatName ? esc(curCatName) : 'None') + '</div>'
                   + '<div class="zform-note">needs distribution.manage and catalog.manage</div></div></div>';
        } else if (!zcats.length) {
            catRow = '<div class="zform-row"><label>Catalog</label><div class="zform-grow">'
                   + '<div class="zs-role-ro">None</div>'
                   + '<div class="zform-note">No catalogs yet (Propagation)</div></div></div>';
        } else {
            var copts = [{ value: '', label: 'None' }].concat(zcats.map(function (c) {
                return { value: String(c.catalog_id),
                         label: window.DNSPanel.catalogLabel(c) + (c.provisioned ? '' : ' — not created yet') }; }));
            catRow = '<div class="zform-row"><label>Catalog' + window.DNSPanel.helpDot('zs-cat', 'Announces the zone to the catalog\u2019s subscribers (RFC 9432). Independent of Direct AXFR.') + '</label><div class="zform-grow">'
                   + window.DNSPanel.selectHtml('zs-cat', copts, curCatId) + '</div></div>';
        }
        // The role change is irreversible, so the form says what will happen and, before the first AXFR,
        // why it is not available yet.
        var role = zsc.role || {};
        var roleType = String(role.type || '').toUpperCase();
        var roleSec = '';
        if (roleType === 'MASTER' || roleType === 'NATIVE') {
            var sact = !role.can_change
                ? '<div class="zform-note">needs zones.manage</div>'
                : '<button type="button" class="btn btn-ghost btn-sm" id="zs-make-secondary">Make secondary</button>'
                  + '<div class="zform-note">Records here are replaced by AXFR from another primary.</div>';
            roleSec = '<div class="zform-sec"><div class="zform-sec-title">Role</div>'
                    + '<div class="zform-row"><label>Current</label><div class="zform-grow">'
                    + '<div class="zs-role-ro">' + (roleType === 'MASTER' ? 'Primary' : 'Native') + '</div>' + sact + '</div></div></div>';
        }
        if (roleType === 'SLAVE') {
            var act = !role.can_change
                ? '<div class="zform-note">needs zones.manage</div>'
                : !role.transferred
                    ? '<div class="zform-note">Available after the first transfer.</div>'
                    : '<button type="button" class="btn btn-ghost btn-sm" id="zs-make-primary">Make primary</button>'
                      + '<div class="zform-note">Records and serial stay; the upstream is dropped.</div>';
            roleSec = '<div class="zform-sec"><div class="zform-sec-title">Role</div>'
                    + '<div class="zform-row"><label>Current</label><div class="zform-grow">'
                    + '<div class="zs-role-ro">Secondary</div>' + act + '</div></div></div>';
        }
        // RFC 2136 acceptance is only toggled here; who may send updates is set via "Dynamic updates" in the
        // zone header, shown once enabled. Secondaries can enable it in advance.
        var curDynOn = !!(zsc.dynamic && zsc.dynamic.on);
        var dynSec = ((roleType === 'MASTER' || roleType === 'SLAVE') && role.can_change)
            ? '<div class="zform-sec"><div class="zform-sec-title">Dynamic updates</div>'
              + '<div class="zform-row"><label>RFC 2136 (DHCP)</label><div class="zform-grow">'
              + '<label class="chk" style="margin-right:1.2rem;"><input type="radio" name="zs-dyn" value="1"' + (curDynOn ? ' checked' : '') + '> On</label>'
              + '<label class="chk"><input type="radio" name="zs-dyn" value=""' + (curDynOn ? '' : ' checked') + '> Off</label>'
              + '</div></div></div>'
            : '';
        ov.innerHTML =
            '<div class="modal"><form class="modal-card zs-card" id="zs-form">' +
            '<h2 class="modal-title">Zone settings</h2>' + roleSec + dynSec +
            '<div class="zform-sec"><div class="zform-sec-title">Downstream</div>' + downRow + catRow + '</div>' +
            '<div class="zform-sec"><div class="zform-sec-title">Profile</div>' +
              '<div class="zform-row"><label>Profile</label><div class="zform-grow">' +
                window.DNSPanel.selectHtml('zs-profile', profOpts, curProfile) +
                '<div class="zform-note">SOA and NS records stay as they are.</div></div></div>' +
            '</div>' +
            '<div class="login-error" id="zs-err" style="display:none;"></div>' +
            '<div class="modal-actions"><button type="button" class="btn btn-ghost" id="zs-cancel">Cancel</button>' +
            '<button type="submit" class="btn btn-primary">Save</button></div></form></div>';
        ov.querySelector('#zs-cancel').addEventListener('click', closeModal);
        { var msb = ov.querySelector('#zs-make-secondary');
          if (msb) msb.addEventListener('click', function () {
              closeModal();
              openMakeSecondary(btn.getAttribute('data-zone-id'), btn.getAttribute('data-name'));
          }); }
        { var mp = ov.querySelector('#zs-make-primary');
          // Close settings BEFORE confirming: the dialog uses the same overlay and would overwrite the form.
          if (mp) mp.addEventListener('click', function () {
              closeModal();
              openPromoteZone(btn.getAttribute('data-zone-id'), btn.getAttribute('data-name'));
          }); }
        var srcAdd = ov.querySelector('#zs-src-add');
        if (srcAdd) {
            srcAdd.addEventListener('click', function () {
                ov.querySelector('#zs-src-list').insertAdjacentHTML('beforeend', srcRow(''));
            });
            // Keep the last row: a secondary needs a primary, and the backend would reject an empty list.
            ov.querySelector('#zs-src-list').addEventListener('click', function (e) {
                var d = e.target.closest && e.target.closest('.src-del'); if (!d) return;
                var list = ov.querySelector('#zs-src-list'), row = d.closest('.src-row');
                if (row && list.querySelectorAll('.src-row').length > 1) list.removeChild(row);
                else if (row) row.querySelector('.src-input').value = '';
            });
        }
        ov.querySelector('#zs-form').addEventListener('submit', async function (e) {
            e.preventDefault();
            var errEl = ov.querySelector('#zs-err');
            // Each section is sent only if changed: an extra request is another way to fail after a neighbour
            // was saved (and the zone PATCH also recomputes distribution).
            var profV = ov.querySelector('[name="zs-profile"]').value;
            var payload = {};
            if (profV !== curProfile) payload.profile = profV;

            var wantDirect = curDirect;
            if (zsc.can_change_delivery) {
                var rb = ov.querySelector('input[name="zs-down"]:checked');
                if (rb) wantDirect = rb.value ? 1 : 0;
            }
            var wantCatId = curCatId;
            { var catEl = ov.querySelector('[name="zs-cat"]');
              if (catEl) wantCatId = catEl.value || ''; }

            // Ask BEFORE the first write, otherwise a refusal would leave the profile saved. The dialog is shared
            // with Propagation. Only removals are dangerous; enabling takes nothing away.
            if (curDirect && !wantDirect) {
                if (!await window.DNSPanel.confirmStopServing([+zid], 'by direct AXFR')) return;
            }
            if (curCatId && String(wantCatId) !== String(curCatId)) {
                if (!await window.DNSPanel.confirmStopServing([+zid], 'in this catalog')) return;
            }

            // Separate requests (different permissions and consequences); if a later one fails, the user must
            // learn what was already saved.
            var saved = [], notApplied = [];
            try {
                if (payload.profile != null) {
                    await window.DNSPanel.api('zones/' + zid, { method: 'PATCH', body: JSON.stringify(payload) });
                    curProfile = profV;
                    saved.push('profile');
                }
                { var dr0 = ov.querySelector('input[name="zs-dyn"]:checked');
                  if (dr0 && !!dr0.value !== curDynOn) {
                      var yres = await window.DNSPanel.api('zones/' + zid + '/dynamic', { method: 'PUT', body: JSON.stringify({ enabled: !!dr0.value }) });
                      curDynOn = !!dr0.value;
                      saved.push('dynamic updates');
                      ((yres && yres.data && yres.data.warnings) || []).forEach(function (w) { notApplied.push('dynamic updates \u2014 ' + w); });
                  } }
                if (wantDirect !== curDirect) {
                    var dres = await window.DNSPanel.api('zones/' + zid + '/direct-axfr',
                                              { method: 'PUT', body: JSON.stringify({ on: !!wantDirect }) });
                    curDirect = wantDirect;
                    saved.push('direct AXFR');
                    // HTTP success doesn't mean the ACL reached PowerDNS: the server reports failures per zone, and
                    // swallowing them would close the form silently.
                    ((dres && dres.data && dres.data.failed) || []).forEach(function (f) {
                        notApplied.push('direct AXFR \u2014 ' + (f.error || 'failed')); });
                }
                if (String(wantCatId) !== String(curCatId)) {
                    await window.DNSPanel.api('zones/' + zid + '/catalog',
                                              { method: 'PUT', body: JSON.stringify({ catalog_id: wantCatId ? +wantCatId : null }) });
                    curCatId = wantCatId;
                    saved.push('catalog');
                }
            } catch (err) {
                var msg = (err && err.message) ? err.message : 'Save failed';
                var full = saved.length ? ('Saved: ' + saved.join(', ') + '. Then failed: ' + msg) : msg;
                // The error field may be gone: the confirm dialog shares the overlay and clears the form on close.
                // Writing there would show the error to no one (a 500 looked like a dead button), so use a dialog.
                if (errEl && errEl.isConnected) { errEl.textContent = full; errEl.style.display = 'block'; }
                else window.DNSPanel.alert({ title: 'Zone settings not saved', message: full });
                return;
            }
            closeModal(); await refresh();
            // Saved but not applied is a separate message: not a failure, nothing to retry.
            if (notApplied.length) window.DNSPanel.alert({
                title: 'Saved, but not applied to PowerDNS',
                message: '<div>The choice is saved in the panel and the background sync will keep retrying.</div>'
                       + '<div style="margin-top:.4rem;">' + notApplied.map(esc).join('<br>') + '</div>' });
        });
    }

    // ---------- Edit upstream: only the source of a secondary zone ----------
    // A separate form because it answers a separate question: where the zone comes from.
    async function openUpstream() {
        var ov = overlay(); if (!ov) return;
        var btn = document.getElementById('zone-settings-btn'); if (!btn) return;
        var zid = btn.getAttribute('data-zone-id');
        var zsc = {}; try { var ce = document.getElementById('zs-cat-data'); if (ce) zsc = JSON.parse(ce.textContent); } catch (e) {}
        var src = zsc.secondary; if (!src) return;
        var mlist = (src.masters || []);
        var upKeys = zsc.can_change_source ? await window.DNSPanel.upstreamKeys() : [];
        var body = zsc.can_change_source
            ? '<div class="zform-row"><label>Upstream primaries</label><div class="zform-grow">' +
                '<div id="zs-src-list">' + (mlist.length ? mlist.map(srcRow).join('') : srcRow('')) + '</div>' +
                '<button type="button" class="btn btn-ghost" id="zs-src-add">+ Add primary</button></div></div>' +
              '<div class="zform-row"><label>Upstream TSIG</label><div class="zform-grow">' +
                window.DNSPanel.upstreamTsigHtml('zu', src.tsig || '', upKeys) +
                '<div class="zform-note">Saving starts a transfer.</div></div></div>'
            : '<div class="zform-row"><label>Upstream primaries</label><div class="zs-role-ro">' +
                (mlist.map(esc).join(', ') || '\u2014') + '</div></div>';
        ov.innerHTML =
            '<div class="modal"><form class="modal-card zs-card" id="zu-form">' +
            '<h2 class="modal-title">Upstream primaries</h2>' + body +
            '<div class="login-error" id="zu-err" style="display:none;"></div>' +
            '<div class="modal-actions"><button type="button" class="btn btn-ghost" id="zu-cancel">Cancel</button>' +
            (zsc.can_change_source ? '<button type="submit" class="btn btn-primary">Save</button>' : '') +
            '</div></form></div>';
        ov.style.display = 'block';
        ov.querySelector('#zu-cancel').addEventListener('click', closeModal);
        window.DNSPanel.upstreamTsigBind(ov, 'zu');
        var add = ov.querySelector('#zs-src-add');
        if (add) {
            add.addEventListener('click', function () { ov.querySelector('#zs-src-list').insertAdjacentHTML('beforeend', srcRow('')); });
            // Keep the last row: a secondary needs a primary, and the backend would reject an empty list.
            ov.querySelector('#zs-src-list').addEventListener('click', function (e) {
                var d = e.target.closest && e.target.closest('.src-del'); if (!d) return;
                var list = ov.querySelector('#zs-src-list'), row = d.closest('.src-row');
                if (row && list.querySelectorAll('.src-row').length > 1) list.removeChild(row);
                else if (row) row.querySelector('.src-input').value = '';
            });
        }
        ov.querySelector('#zu-form').addEventListener('submit', async function (e) {
            e.preventDefault();
            var errEl = ov.querySelector('#zu-err');
            var addrs = Array.prototype.map.call(ov.querySelectorAll('.src-input'), function (i) { return i.value.trim(); }).filter(Boolean);
            var ut = window.DNSPanel.upstreamTsigRead(ov, 'zu');
            if (ut.err) { errEl.textContent = ut.err; errEl.style.display = 'block'; return; }
            if (!ut.tsig_new && addrs.join(',') === (src.masters || []).join(',') && ut.tsig === (src.tsig || '')) { closeModal(); return; }
            if (!addrs.length) { errEl.textContent = 'A secondary zone needs at least one upstream primary.'; errEl.style.display = 'block'; return; }
            try {
                var res = await window.DNSPanel.api('zones/' + zid + '/secondary-source',
                                                    { method: 'PUT', body: JSON.stringify({ masters: addrs, tsig: ut.tsig || '', tsig_new: ut.tsig_new }) });
                var d = (res && res.data) || {};
                if ((d.warnings || []).length) window.DNSPanel.alert({ message: 'Upstream saved: ' + d.warnings.join('; ') });
            } catch (err) {
                errEl.textContent = (err && err.message) ? err.message : 'Save failed'; errEl.style.display = 'block'; return;
            }
            closeModal(); await refresh();
        });
    }

    // ---------- Make secondary (Primary → Secondary) ----------
    // Inverse of Make primary, with more friction on purpose: the zone's records are replaced by AXFR
    // data, so it asks for the zone name like zone deletion. Primaries, key and confirmation share one form.
    async function openMakeSecondary(id, name) {
        var ov = overlay(); if (!ov) return;
        var upKeys = await window.DNSPanel.upstreamKeys();
        var zsc = {}; try { var ce = document.getElementById('zs-cat-data'); if (ce) zsc = JSON.parse(ce.textContent); } catch (e) {}
        var catName = '';
        if (zsc.catalog_id) {
            (zsc.catalogs || []).forEach(function (c) {
                if (String(c.catalog_id) === String(zsc.catalog_id)) catName = window.DNSPanel.catalogLabel(c); });
            if (!catName) catName = 'its catalog';
        }
        ov.innerHTML =
            '<div class="modal"><form class="modal-card zs-card" id="ms-form">' +
            '<h2 class="modal-title">Make secondary</h2>' +
            '<p class="zform-note"><b>The records of ' + esc(name) + ' here are deleted</b> and replaced by AXFR from the primary below.' +
              (catName ? ' The zone leaves the catalog <b>' + esc(catName) + '</b>.' : '') + '</p>' +
            '<div class="zform-row"><label>Upstream primaries</label><div class="zform-grow">' +
              '<div id="ms-src-list">' + srcRow('') + '</div>' +
              '<button type="button" class="btn btn-ghost" id="ms-src-add">+ Add primary</button></div></div>' +
            '<div class="zform-row"><label>Upstream TSIG</label><div class="zform-grow">' +
              window.DNSPanel.upstreamTsigHtml('ms', '', upKeys) + '</div></div>' +
            '<label class="field-label">Type the zone name to confirm</label>' +
            '<input class="field-input" id="ms-confirm" placeholder="' + esc(name) + '" autocomplete="off">' +
            '<div class="login-error" id="ms-err" style="display:none;"></div>' +
            '<div class="modal-actions"><button type="button" class="btn btn-ghost" id="ms-cancel">Cancel</button>' +
            '<button type="submit" class="btn btn-danger" id="ms-btn" disabled>Make secondary</button></div></form></div>';
        ov.style.display = 'block';
        var conf = ov.querySelector('#ms-confirm'), okBtn = ov.querySelector('#ms-btn');
        conf.addEventListener('input', function () { okBtn.disabled = conf.value.trim().toLowerCase() !== name.toLowerCase(); });
        ov.querySelector('#ms-cancel').addEventListener('click', closeModal);
        window.DNSPanel.upstreamTsigBind(ov, 'ms');
        ov.querySelector('#ms-src-add').addEventListener('click', function () {
            ov.querySelector('#ms-src-list').insertAdjacentHTML('beforeend', srcRow(''));
        });
        // Keep the last row: a secondary needs a primary, and the backend would reject an empty list.
        ov.querySelector('#ms-src-list').addEventListener('click', function (e) {
            var dl = e.target.closest && e.target.closest('.src-del'); if (!dl) return;
            var list = ov.querySelector('#ms-src-list'), row = dl.closest('.src-row');
            if (row && list.querySelectorAll('.src-row').length > 1) list.removeChild(row);
            else if (row) row.querySelector('.src-input').value = '';
        });
        ov.querySelector('#ms-form').addEventListener('submit', async function (e) {
            e.preventDefault();
            var errEl = ov.querySelector('#ms-err');
            var addrs = Array.prototype.map.call(ov.querySelectorAll('#ms-src-list .src-input'),
                                                 function (i) { return i.value.trim(); }).filter(Boolean);
            if (!addrs.length) { errEl.textContent = 'A secondary zone needs at least one upstream primary.'; errEl.style.display = 'block'; return; }
            var ut = window.DNSPanel.upstreamTsigRead(ov, 'ms');
            if (ut.err) { errEl.textContent = ut.err; errEl.style.display = 'block'; return; }
            okBtn.disabled = true;
            var d;
            try {
                var res = await window.DNSPanel.api('zones/' + id + '/demote', { method: 'POST',
                    body: JSON.stringify({ confirm_name: conf.value.trim(), masters: addrs,
                                           tsig: ut.tsig || '', tsig_new: ut.tsig_new }) });
                d = (res && res.data) || {};
            } catch (err) {
                errEl.textContent = (err && err.message) ? err.message : 'Make secondary failed';
                errEl.style.display = 'block'; okBtn.disabled = false; return;
            }
            // The zone is ALREADY secondary; only the refresh can fail, and that must be said, or the page keeps
            // claiming the zone is ours.
            var notes = (d.warnings || []).slice();
            if (d.catalog_removed) notes.push('The zone was taken out of its catalog.');
            if (d.pdns_state && d.pdns_state !== 'active') {
                notes.push('The transfer has not finished yet (' + esc(d.pdns_state) +
                           (d.pdns_detail ? ': ' + esc(d.pdns_detail) : '') + '). The panel keeps retrying.');
            }
            closeModal();
            var shown = await reload();
            if (!shown) notes.unshift('Zone ' + esc(name) + ' is now a secondary, but the page could not be refreshed.');
            if (notes.length) window.DNSPanel.alert({ title: 'Zone is now a secondary', message: notes.join(' ') });
        });
    }

    // ---------- RRset change history (audit) ----------
    function parseJson(v) { if (v == null) return null; if (typeof v !== 'string') return v; try { return JSON.parse(v); } catch (e) { return null; } }
    // before_val is an RRset object {records:[...]}; after_val is an array of records; or null.
    function recList(x) { if (!x) return []; if (Array.isArray(x)) return x; if (x.records) return x.records; return []; }
    function valKey(r) {
        var c = (r && r.content != null) ? r.content : (typeof r === 'string' ? r : '');
        return (r && r.prio != null && r.prio !== '') ? (r.prio + ' ' + c) : String(c);
    }
    function valsStr(list) { return list.length ? list.map(valKey).join(', ') : '—'; }
    function allDisabled(list) { return list.length > 0 && list.every(function (r) { return r && r.disabled; }); }
    function histAction(h, bef, aft) {
        if (!bef.length && aft.length) return 'Created';
        if (bef.length && !aft.length) return 'Deleted';
        if (bef.length && aft.length) {
            var bk = bef.map(valKey).sort().join('\n'), ak = aft.map(valKey).sort().join('\n');
            if (bk === ak) {
                var bD = allDisabled(bef), aD = allDisabled(aft);
                if (bD !== aD) return aD ? 'Disabled' : 'Enabled';
            }
            return 'Updated';
        }
        return ({ replace_rrset: 'Updated', delete_rrset: 'Deleted' }[h.action] || 'Changed');
    }
    var ACT_CLASS = { Created: 'act-add', Deleted: 'act-del', Updated: 'act-upd', Enabled: 'act-add', Disabled: 'act-off', Changed: 'act-upd' };
    function objTtl(x) { return (x && !Array.isArray(x) && x.ttl != null) ? x.ttl : null; }
    function histRow(h) {
        var type = h._type || '';
        var beforeObj = parseJson(h.before_val), afterObj = parseJson(h.after_val);
        var bef = recList(beforeObj), aft = recList(afterObj);
        var act = histAction(h, bef, aft);
        var bT = objTtl(beforeObj), aT = objTtl(afterObj);
        var ttl = (bT != null && aT != null && String(bT) !== String(aT)) ? (esc(bT) + ' → ' + esc(aT))
                : (aT != null ? esc(aT) : (bT != null ? esc(bT) : '—'));
        var err = (h.result && h.result !== 'ok') ? ' <span class="badge slave" data-tip="' + esc(h.detail || '') + '">' + esc(h.result) + '</span>' : '';
        var bStr = valsStr(bef), aStr = valsStr(aft);
        return '<tr>' +
            '<td class="mono">' + esc(fmtLocal(h.ts)) + '</td>' +
            '<td>' + esc(h.actor || 'system') + '</td>' +
            '<td class="mono text-mute">' + esc(h.ip || '—') + '</td>' +
            '<td><span class="badge">' + esc(type) + '</span></td>' +
            '<td><span class="hist-badge ' + (ACT_CLASS[act] || 'act-upd') + '">' + esc(act) + '</span>' + err + '</td>' +
            '<td class="mono hist-val" data-tip="' + esc(bStr) + '">' + esc(bStr) + '</td>' +
            '<td class="mono hist-val" data-tip="' + esc(aStr) + '">' + esc(aStr) + '</td>' +
            '<td class="mono right">' + ttl + '</td>' +
            '</tr>';
    }
    async function fetchHistory(name, type) {
        try {
            var r = await window.DNSPanel.api('zones/' + zoneId() + '/audit?name=' + encodeURIComponent(name) +
                '&type=' + encodeURIComponent(type), { method: 'GET' });
            var h = (r.data && r.data.history) || [];
            h.forEach(function (x) { x._type = type; });
            return h;
        } catch (e) { return []; }
    }
    function changesHtml(hist) {
        return hist.length
            ? '<div class="hist-scroll"><table class="data-table hist-table"><thead><tr>' +
              '<th>Date</th><th>Who</th><th>IP</th><th>Type</th><th>Action</th><th>Before</th><th>After</th><th class="right">TTL</th>' +
              '</tr></thead><tbody>' + hist.map(histRow).join('') + '</tbody></table></div>'
            : '<p class="text-mute" style="font-size:13px;">No audit history yet.</p>';
    }

    // ---------- Record history: Changes, Pulse and Pinger tabs ----------
    // Three different questions with different sources and time semantics, so they are not merged into one feed.
    var HW = [['1d', 'Day'], ['1w', 'Week'], ['1m', 'Month']];
    // The sweep reports address state; map it onto the Pulse bar's vocabulary instead of a second palette.
    var SWEEP_TO_BAR = { available: 'healthy', unavailable: 'down', unknown: 'unknown' };
    function tms(x) { return Date.parse(String(x || '').replace(' ', 'T') + 'Z') || 0; }
    function barHtml(segs, from, to, who) {
        if (!window.PulseBar || !window.PulseBar.ticks) return '';
        return window.PulseBar.ticks(segs, tms(from), tms(to), 96, who || '');
    }
    function tabsHtml(st) {
        if (!st.able) return '';
        return '<div class="dist-tabs hist-tabs">' + ['changes', 'pulse', 'pinger'].map(function (k) {
            if (k !== 'changes' && !st.able[k]) return '';
            var lab = { changes: 'Changes', pulse: 'Pulse', pinger: 'Pinger' }[k];
            return '<button type="button" class="dist-tab' + (st.tab === k ? ' active' : '') +
                   '" data-rh-tab="' + k + '">' + lab + '</button>';
        }).join('') + '</div>';
    }
    function winHtml(st) {
        return '<div class="seg hist-win">' + HW.map(function (w) {
            return '<button type="button" class="seg-btn' + (st.win === w[0] ? ' active' : '') +
                   '" data-rh-win="' + w[0] + '">' + w[1] + '</button>';
        }).join('') + '</div>';
    }
    // Pulse: what was published under this name and why. The bar is the published set, the table the events.
    function pulseHtml(st) {
        var d = st.pulse;
        if (!d) return '<div class="spinner"></div>';
        if (!d.rule) return '<p class="text-mute" style="font-size:13px;">No NS Pulse rule for this record.</p>';
        var segs = (d.segments || []).map(function (s) {
            return { from: s.from, to: s.to, state: s.known ? (s.branch_no ? 'met' : 'not') : 'unknown' };
        });
        var rows = (d.events || []).slice().reverse().map(function (e) {
            return '<tr><td class="mono">' + esc(fmtLocal(e.at)) + '</td>' +
                '<td>' + (e.branch_no ? 'Branch ' + esc(e.branch_no) : 'Fallback set') + '</td>' +
                '<td class="mono hist-val" data-tip="' + esc(e.from_set || '') + '">' + esc(e.from_set || '—') + '</td>' +
                '<td class="mono hist-val" data-tip="' + esc(e.to_set || '') + '">' + esc(e.to_set || '—') + '</td>' +
                '<td>' + esc(e.reason || '') + '</td></tr>';
        }).join('');
        return winHtml(st) + '<div class="hist-bar">' + barHtml(segs, d.from, d.to, 'published set') + '</div>' +
            (rows
                ? '<div class="hist-scroll"><table class="data-table hist-table"><thead><tr>' +
                  '<th>Date</th><th>Published by</th><th>From</th><th>To</th><th>Why</th>' +
                  '</tr></thead><tbody>' + rows + '</tbody></table></div>'
                : '<p class="text-mute" style="font-size:13px;">No switches in this period.</p>');
    }
    // Pinger: whether the address itself answered, one bar per address. Only the period when the address
    // was actually in this record is shown.
    var SWEEP_WORD = { available: 'available', unavailable: 'unavailable', unknown: 'not measured' };
    // All bars first, then one shared transition table filterable by address. A table per bar let one
    // flapping address push the other bars off-screen; bars must stay put to be compared.
    function pingerHtml(st) {
        var d = st.pinger;
        if (!d) return '<div class="spinner"></div>';
        var list = d.addresses || [];
        if (!list.length) return winHtml(st) +
            '<p class="text-mute" style="font-size:13px;">This record had no addresses in this period.</p>';

        var strips = list.map(function (a) {
            var segs = (a.segments || []).map(function (s) {
                return { from: s.from, to: s.to, state: SWEEP_TO_BAR[s.state] || 'unknown' };
            });
            // Show both the state (and since when) and the last probe: an address can be down for a day while
            // the last probe was a minute ago.
            var head = a.last_checked_at
                ? [ esc(SWEEP_WORD[a.state] || a.state) +
                    (a.state_since ? ' since ' + esc(fmtLocal(a.state_since)) : ''),
                    'last checked ' + esc(fmtLocal(a.last_checked_at)) + (a.agent ? ' by ' + esc(a.agent) : '') ]
                : [ 'not checked yet' ];
            return '<div class="hist-ip' + (st.ip === a.ip ? ' is-sel' : '') + '" data-rh-ip="' + esc(a.ip) + '">' +
                '<div class="hist-ip-head"><span class="mono">' + esc(a.ip) + '</span>' +
                '<span class="text-mute">' + head.join(' · ') + '</span>' +
                (a.current ? '' : ' <span class="badge muted">no longer in this record</span>') + '</div>' +
                '<div class="hist-bar">' + barHtml(segs, d.from, d.to, esc(a.ip)) + '</div></div>';
        }).join('');

        var rows = [];
        list.forEach(function (a) {
            if (st.ip && st.ip !== a.ip) return;
            (a.transitions || []).forEach(function (t) { rows.push({ ip: a.ip, t: t }); });
        });
        rows.sort(function (x, y) { return String(y.t.at).localeCompare(String(x.t.at)); });
        var body = rows.map(function (r) {
            return '<tr><td class="mono">' + esc(fmtLocal(r.t.at)) + '</td>' +
                '<td class="mono">' + esc(r.ip) + '</td>' +
                '<td><span class="hist-badge ' + (r.t.state === 'unavailable' ? 'act-del' : 'act-add') + '">' +
                esc(SWEEP_WORD[r.t.state] || r.t.state) + '</span></td>' +
                '<td class="text-mute">' + esc(r.t.agent || '—') + '</td></tr>';
        }).join('');
        var pick = list.length > 1
            ? window.DNSPanel.selectHtml('rh-ip',
                [{ value: '', label: 'All addresses' }].concat(list.map(function (a) {
                    return { value: a.ip, label: a.ip };
                })), st.ip || '')
            : '';

        return winHtml(st) + strips + '<div class="hist-pick">' + pick + '</div>' +
            (body
                ? '<div class="hist-scroll"><table class="data-table hist-table"><thead><tr>' +
                  '<th>Time</th><th>Address</th><th>State</th><th>Seen by</th>' +
                  '</tr></thead><tbody>' + body + '</tbody></table></div>'
                : '<p class="text-mute" style="font-size:12.5px;">No state changes in this period.</p>');
    }
    function histBody(st) {
        if (st.tab === 'pulse') return pulseHtml(st);
        if (st.tab === 'pinger') return pingerHtml(st);
        return changesHtml(st.hist);
    }
    function renderHistoryModal(titleHtml, st) {
        var ov = overlay(); if (!ov) return;
        ov.innerHTML =
            '<div class="modal"><div class="modal-card hist-modal">' +
            '<div class="modal-head"><h2 class="modal-title">' + titleHtml + '</h2>' +
            '<button type="button" class="modal-x" id="hist-x" aria-label="Close">×</button></div>' +
            tabsHtml(st) + '<div id="hist-body">' + histBody(st) + '</div>' +
            '<div class="modal-actions"><button type="button" class="btn btn-ghost" id="hist-close">Close</button></div>' +
            '</div></div>';
        ov.querySelector('#hist-close').addEventListener('click', closeModal);
        ov.querySelector('#hist-x').addEventListener('click', closeModal);
        if (!st.able) return;
        ov.querySelectorAll('[data-rh-tab]').forEach(function (b) {
            b.addEventListener('click', function () { histGo(titleHtml, st, b.getAttribute('data-rh-tab'), st.win); });
        });
        ov.querySelectorAll('[data-rh-win]').forEach(function (b) {
            b.addEventListener('click', function () { histGo(titleHtml, st, st.tab, b.getAttribute('data-rh-win')); });
        });
        // The address filter only changes the table below; the data is already loaded.
        var sel = ov.querySelector('.ui-select[data-name="rh-ip"] input[type="hidden"]');
        if (sel) sel.addEventListener('change', function () {
            st.ip = sel.value || null; renderHistoryModal(titleHtml, st);
        });
        ov.querySelectorAll('[data-rh-ip]').forEach(function (b) {
            b.addEventListener('click', function () {
                var ip = b.getAttribute('data-rh-ip');
                st.ip = (st.ip === ip) ? null : ip;    // clicking the same bar again clears the filter
                renderHistoryModal(titleHtml, st);
            });
        });
    }
    // Tab and window data load on demand and stay cached; switching back doesn't refetch.
    async function histGo(titleHtml, st, tab, win) {
        var refetch = (win !== st.win);
        st.tab = tab; st.win = win;
        if (refetch) { st.pulse = null; st.pinger = null; }
        renderHistoryModal(titleHtml, st);
        if (tab === 'pulse' && !st.pulse) {
            st.pulse = await histFetch('rrset/history', st);
        } else if (tab === 'pinger' && !st.pinger) {
            st.pinger = await histFetch('rrset/sweep', st);
        } else { return; }
        renderHistoryModal(titleHtml, st);
    }
    async function histFetch(path, st) {
        try {
            var r = await window.DNSPanel.api('pulse/zones/' + zoneId() + '/' + path +
                '?name=' + encodeURIComponent(st.name) + '&type=' + encodeURIComponent(st.type) +
                '&window=' + encodeURIComponent(st.win), { method: 'GET' });
            return (r && r.data) || {};
        } catch (e) { return {}; }
    }
    // History of one RRset. Pulse and Pinger tabs appear only where relevant; the SERVER decides, since
    // the Pulse-manageable type list lives in functions.pm and a copy here would drift (that is how NS got lost).
    async function openHistory(row, tab) {
        var ov = overlay(); if (!ov) return;
        ov.innerHTML = '<div class="modal"><div class="modal-card hist-modal"><div class="spinner"></div></div></div>';
        ov.style.display = 'block';
        var name = row.getAttribute('data-name'), type = row.getAttribute('data-type');
        var t = String(type || '').toUpperCase();
        var able = { pulse: row.getAttribute('data-pulse-ok') === '1',
                     pinger: row.getAttribute('data-sweep-ok') === '1' };
        // Opened from a red dot: preselect that address, since that is what the user is asking about.
        var st = { name: name, type: t, tab: (able[tab] ? tab : 'changes'), win: '1d',
                   ip: (tab === 'pinger' ? row.getAttribute('data-value') : null),
                   hist: await fetchHistory(name, type), pulse: null, pinger: null, able: able };
        var title = 'History &mdash; ' + esc(type) + ' ' + esc(name);
        if (st.tab === 'changes') { renderHistoryModal(title, st); return; }
        await histGo(title, st, st.tab, st.win);
    }
    // Combined history of SOA + apex NS (one button in the accordion header).
    async function openApexHistory() {
        var ov = overlay(); if (!ov) return;
        ov.innerHTML = '<div class="modal"><div class="modal-card hist-modal"><div class="spinner"></div></div></div>';
        ov.style.display = 'block';
        var zn = zoneName();
        var parts = await Promise.all([fetchHistory(zn, 'SOA'), fetchHistory(zn, 'NS')]);
        var hist = parts[0].concat(parts[1]).sort(function (a, b) { return String(b.ts || '').localeCompare(String(a.ts || '')); });
        renderHistoryModal('History &mdash; SOA &amp; name servers · ' + esc(zn),
            { tab: 'changes', hist: hist, able: null });
    }

    // ---------- Zone labels (modal) ----------
    async function openZoneLabels() {
        var ov = overlay(); if (!ov) return;
        var zid = zoneId();
        ov.innerHTML = '<div class="modal"><div class="modal-card"><div class="spinner"></div></div></div>';
        ov.style.display = 'block';
        var cats = [], current = {};
        try {
            var lr = await window.DNSPanel.api('labels', { method: 'GET' });
            cats = (lr.data && lr.data.categories) || [];
            var zr = await window.DNSPanel.api('zones/' + zid, { method: 'GET' });
            ((zr.data && zr.data.zone && zr.data.zone.labels) || []).forEach(function (l) { current[l.value_id] = 1; });
        } catch (e) {}
        ov.innerHTML =
            '<div class="modal"><form class="modal-card" id="zl-form">' +
            '<h2 class="modal-title">Labels</h2>' +
            '<div class="zform-labels">' + cats.map(function (c) {
                return '<div class="lbl-cat" data-cardinality="' + esc(c.cardinality) + '"><label>' + esc(c.name) + '</label><div class="lbl-chips">' +
                    (c.values || []).map(function (v) {
                        return '<span class="lbl-chip' + (current[v.id] ? ' on' : '') + '" data-id="' + v.id + '"' +
                            (v.color ? ' style="--c:' + esc(v.color) + '"' : '') + '>' + esc(v.name) + '</span>';
                    }).join('') + '</div></div>';
            }).join('') + '</div>' +
            '<div class="login-error" id="zl-err" style="display:none;"></div>' +
            '<div class="modal-actions"><button type="button" class="btn btn-ghost" id="zl-cancel">Cancel</button>' +
            '<button type="submit" class="btn btn-primary">Save</button></div></form></div>';
        ov.querySelector('#zl-cancel').addEventListener('click', closeModal);
        ov.querySelector('#zl-form').addEventListener('submit', async function (e) {
            e.preventDefault();
            var ids = Array.prototype.map.call(ov.querySelectorAll('.lbl-chip.on'), function (c) { return parseInt(c.getAttribute('data-id'), 10); });
            try {
                await window.DNSPanel.api('zones/' + zid + '/labels', { method: 'PUT', body: JSON.stringify({ labels: ids }) });
                closeModal(); await refresh();
            } catch (err) { var el = ov.querySelector('#zl-err'); el.textContent = err.message || 'Save failed'; el.style.display = 'block'; }
        });
    }

    // ---------- Make primary / delete zone ----------
    // Make primary: the confirm dialog and success notes are shared with the zone list
    // (DNSPanel.confirmMakePrimary / makePrimaryNotes). No FQDN typing: records and serial stay, and
    // deletion-level friction would devalue it. Reloading the fragment keeps filters and open blocks.
    async function openPromoteZone(id, name) {
        // Dynamic updates stay on if the zone already has them or was dynamic on the old server.
        var zsd = {}; try { var ce2 = document.getElementById('zs-cat-data'); if (ce2) zsd = JSON.parse(ce2.textContent); } catch (e) {}
        var ans = await window.DNSPanel.confirmMakePrimary(name, { required: !!(zsd.dynamic && zsd.dynamic.imported) });
        if (!ans) return;
        var r;
        try {
            r = await window.DNSPanel.api('zones/' + id + '/promote', {
                method: 'POST', body: JSON.stringify({ confirm_name: name, dynamic: !!(ans.dynamic || (zsd.dynamic && zsd.dynamic.on)) }),
            });
        } catch (err) {
            window.DNSPanel.alert({ title: 'Make primary failed', message: (err && err.message) || 'Promote failed' });
            return;
        }
        // The zone is ALREADY primary; only the refresh can fail, and that must be said, or the page keeps
        // claiming the zone is secondary.
        var notes = window.DNSPanel.makePrimaryNotes((r && r.data) || {});
        var shown = await reload();
        if (!shown) {
            notes.unshift('Zone ' + name + ' is now primary, but the page could not be refreshed \u2014 ' +
                          'it still shows the previous state. Reload the page to see it.');
        }
        if (notes.length) window.DNSPanel.alert({ title: 'Zone is now primary', message: notes.join(' ') });
    }
    function openDeleteZone(id, name) {
        var ov = overlay(); if (!ov) return;
        ov.innerHTML =
            '<div class="modal"><form class="modal-card"><h2 class="modal-title">Delete zone</h2>' +
            '<p style="color:var(--text-dim);font-size:13px;">Zone <b>' + esc(name) + '</b> and all its records will be permanently deleted.</p>' +
            '<label class="field-label">Type the zone name to confirm</label>' +
            '<input class="field-input" id="dz-confirm" placeholder="' + esc(name) + '" autocomplete="off">' +
            '<div class="login-error" id="dz-err" style="display:none;"></div>' +
            '<div class="modal-actions"><button type="button" class="btn btn-ghost" id="dz-cancel">Cancel</button>' +
            '<button type="submit" class="btn btn-danger" id="dz-btn" disabled>Delete zone</button></div></form></div>';
        ov.style.display = 'block';
        var conf = ov.querySelector('#dz-confirm'), btn = ov.querySelector('#dz-btn');
        conf.addEventListener('input', function () { btn.disabled = conf.value.trim().toLowerCase() !== name.toLowerCase(); });
        ov.querySelector('#dz-cancel').addEventListener('click', closeModal);
        ov.querySelector('form').addEventListener('submit', async function (e) {
            e.preventDefault(); btn.disabled = true;
            try {
                await window.DNSPanel.api('zones/' + id, { method: 'DELETE', body: JSON.stringify({ confirm_name: conf.value.trim() }) });
                window.location.href = '/zones';
            } catch (err) { var el = ov.querySelector('#dz-err'); el.textContent = err.message || 'Delete failed'; el.style.display = 'block'; btn.disabled = false; }
        });
    }

    // ---------- Table filters ----------
    function rrRows() { return Array.prototype.slice.call(document.querySelectorAll('.rr-row')); }
    // Filter snapshot/restore so filters survive reload (add/edit/bulk).
    var FILTER_LABEL = { rtype: 'Type', rstatus: 'Status', rptr: 'PTR', rpulse: 'Pulse', rping: 'Pinger' };
    // One filter list for capture, restore and reset: with three copies, Pulse and Pinger survived a
    // record edit in only one of them.
    var RR_FILTERS = ['rtype', 'rstatus', 'rptr', 'rpulse', 'rping'];
    function captureRrFilters() {
        var s = document.getElementById('rr-search');
        var out = { q: s ? s.value : '', f: {} };
        RR_FILTERS.forEach(function (n) {
            var b = document.querySelector('.filter[data-filter="' + n + '"]');
            if (b) out.f[n] = { val: b.getAttribute('data-val') || 'all', text: b.textContent };
        });
        return out;
    }
    function restoreRrFilters(st) {
        if (!st) return;
        var s = document.getElementById('rr-search'); if (s) s.value = st.q || '';
        RR_FILTERS.forEach(function (n) {
            var b = document.querySelector('.filter[data-filter="' + n + '"]');
            if (b && st.f && st.f[n]) { b.setAttribute('data-val', st.f[n].val); b.textContent = st.f[n].text; }
        });
    }
    function saveRrFilters() { window.DNSPanel.store('rrFilters', window.DNSPanel.filtersGet(document, RR_FILTERS)); }
    function rfVal(n) { var b = document.querySelector('.filter[data-filter="' + n + '"]'); return b ? (b.getAttribute('data-val') || 'all') : 'all'; }
    function applyRrFilters() {
        var si = document.getElementById('rr-search'); var qq = si ? si.value.trim().toLowerCase() : '';
        var ft = rfVal('rtype'), fs = rfVal('rstatus'), fp = rfVal('rptr'),
            fpu = rfVal('rpulse'), fpg = rfVal('rping'), shown = 0;
        rrRows().forEach(function (r) {
            var ok = true;
            if (qq && (r.getAttribute('data-ndata').indexOf(qq) === -1 && r.getAttribute('data-vdata').indexOf(qq) === -1)) ok = false;
            if (ok && ft !== 'all' && r.getAttribute('data-type') !== ft) ok = false;
            if (ok && fs !== 'all') { var dis = r.getAttribute('data-disabled') === '1'; if ((fs === 'disabled') !== dis) ok = false; }
            if (ok && fp !== 'all' && (r.getAttribute('data-ptr') || '') !== fp) ok = false;   // non-A/AAAA rows (data-ptr='') are filtered out
            // Use the state attributes the server wrote, not badge text or the red dot, which drift with markup.
            // Rows the filter doesn't apply to (wrong type) are hidden, as with PTR.
            if (ok && fpu !== 'all' && (r.getAttribute('data-pulse-state') || '') !== fpu) ok = false;
            if (ok && fpg !== 'all' && (r.getAttribute('data-sweep-state') || '') !== fpg) ok = false;
            r.style.display = ok ? '' : 'none'; if (ok) shown++;
        });
        // Regroup by VISIBLE rows so a hidden first row doesn't take the group's Pulse badge with it.
        markRrsets(rrsetGroups(rrRows().filter(function (r) { return r.style.display !== 'none'; })));
        var cb = document.getElementById('rr-filter-clear');
        if (cb) cb.style.display = (qq || ft !== 'all' || fs !== 'all' || fp !== 'all' ||
                                    fpu !== 'all' || fpg !== 'all') ? '' : 'none';
        syncChecksFromSel();   // selection survives filtering (hidden rows stay selected)
        updateBulk();
    }
    function rrCloseMenus() { document.querySelectorAll('.rr-toolbar .filter-wrap.open').forEach(function (w) { w.classList.remove('open'); var m = w.querySelector('.filter-menu'); if (m) m.remove(); }); }
    function rrOpenMenu(btn) {
        var wrap = btn.closest('.filter-wrap'), name = btn.getAttribute('data-filter'), cur = btn.getAttribute('data-val') || 'all';
        var was = wrap.classList.contains('open'); rrCloseMenus(); if (was) return;
        var opts;
        if (name === 'rstatus') opts = [['all', 'all'], ['active', 'Active'], ['disabled', 'Disabled']];
        // "rule 2" and "rule 5" filter the same way: a rule holds the record.
        else if (name === 'rpulse') opts = [['all', 'all'], ['off', 'Off'], ['default', 'Default'],
                                            ['rule', 'Rule'], ['held', 'Held']];
        else if (name === 'rping') opts = [['all', 'all'], ['unavailable', 'Unavailable'],
                                           ['available', 'Available'], ['not_checked', 'Not checked']];
        else if (name === 'rptr') opts = [['all', 'all'], ['ok', 'OK'], ['multiple', 'Multiple'], ['missing', 'Missing'], ['different', 'Different'], ['disabled', 'Disabled'], ['external', 'External'], ['error', 'Error']];
        else { var s = {}; rrRows().forEach(function (r) { s[r.getAttribute('data-type')] = 1; }); opts = [['all', 'all']].concat(Object.keys(s).sort().map(function (t) { return [t, t]; })); }
        var menu = document.createElement('div'); menu.className = 'filter-menu'; menu.setAttribute('data-for', name);
        menu.innerHTML = opts.map(function (o) { return '<div class="filter-opt' + (o[0] === cur ? ' sel' : '') + '" data-val="' + esc(o[0]) + '">' + esc(o[1]) + '</div>'; }).join('');
        wrap.appendChild(menu); wrap.classList.add('open');
    }

    // ---------- Column sorting ----------
    var TYPE_ORDER = { A: 0, AAAA: 1, CNAME: 2, MX: 3, TXT: 4, SRV: 5, CAA: 6, NS: 7, DNAME: 8, DS: 9, NAPTR: 10, SSHFP: 11, TLSA: 12, PTR: 13, SOA: 99 };
    // PTR status sort order: ok first ascending, external/error last.
    var PTR_ORDER = { ok: 0, multiple: 1, missing: 2, different: 3, disabled: 4, external: 5, error: 6 };
    var PTR_LABEL = { ok: 'OK', multiple: 'Multiple', missing: 'Missing', different: 'Different',
                      disabled: 'Disabled', external: 'External', error: 'Error' };
    // PTR status badge; s is the /ptr-status object (ptr[], reverse_zone_id, owner). missing gives a
    // "Missing +" button; ok/multiple/different/disabled with a known reverse zone deep-link into it.
    function ptrBadge(st, s) {
        var label = PTR_LABEL[st] || st, title = '';
        var ptr = s && s.ptr; if (ptr && !Array.isArray(ptr)) ptr = [ptr];   // accept a string or an array
        var has = ptr && ptr.length;
        if (st === 'ok')             title = has ? 'PTR: ' + ptr.join(', ') : 'PTR points back to this name';
        // "Correct PTR present but not alone" differs from "no correct PTR": both used to read Different,
        // sending users hunting for an error on a record whose PTR they had just created.
        else if (st === 'multiple')  title = has ? 'PTR: ' + ptr.join(', ') + ' — this name is there, but not alone'
                                                : 'This name is among the PTR records, but not alone';
        else if (st === 'different') title = has ? 'Actual PTR: ' + ptr.join(', ') : 'PTR points to a different name';
        else if (st === 'missing')   title = 'No PTR record for this address';
        else if (st === 'disabled')  title = 'PTR record exists but is disabled';
        else if (st === 'external')  title = 'Reverse zone is not managed here';
        else if (st === 'error')     title = 'Could not determine PTR status';
        var t = title ? ' data-tip="' + esc(title) + '"' : '';
        if (st === 'missing') {
            // "+" only when the reverse zone is writable, otherwise a plain badge (no misleading 403).
            if (s && s.writable) return '<button type="button" class="ptr-badge ptr-missing js-ptr-add"' + t + '>' + esc(label) + ' +</button>';
            return '<span class="ptr-badge ptr-missing" data-tip="No PTR record (reverse zone is read-only)">' + esc(label) + '</span>';
        }
        if (s && s.reverse_zone_id && (st === 'ok' || st === 'multiple' || st === 'different' || st === 'disabled')) {
            var href = '/records?zone=' + encodeURIComponent(s.reverse_zone_id) +
                       '&type=PTR&search=' + encodeURIComponent(s.owner || '');
            return '<a class="ptr-badge ptr-' + st + ' ptr-link" href="' + href + '"' + t + '>' + esc(label) + '</a>';
        }
        return '<span class="ptr-badge ptr-' + st + '"' + t + '>' + esc(label) + '</span>';
    }
    // Set the row's PTR cell and data-ptr* attributes; rev/owner feed the deep link and "delete PTR with A".
    function setPtrCell(row, st, s) {
        row.setAttribute('data-ptr', st);
        if (s && s.reverse_zone_id) {
            row.setAttribute('data-ptr-rev', s.reverse_zone_id);
            row.setAttribute('data-ptr-owner', s.owner || '');
            if (s.writable) row.setAttribute('data-ptr-writable', '1'); else row.removeAttribute('data-ptr-writable');
        } else {
            row.removeAttribute('data-ptr-rev'); row.removeAttribute('data-ptr-owner'); row.removeAttribute('data-ptr-writable');
        }
        var c = row.querySelector('.rr-ptr'); if (c) c.innerHTML = ptrBadge(st, s);
    }
    // Create a missing PTR in place. The backend takes IP/target from the record and rechecks the PTR
    // under lock; blocked (conflict|multiple|disabled) offers Replace, not_managed shows external.
    async function createPtrForRow(row, mode) {
        var rid = row.getAttribute('data-id'); if (!rid) return;
        var cell = row.querySelector('.rr-ptr');
        if (cell) cell.innerHTML = '<span class="ptr-badge ptr-pending">…</span>';
        var res;
        try { res = await window.DNSPanel.api('zones/' + zoneId() + '/records/' + rid + '/ptr',
                  { method: 'POST', body: JSON.stringify(mode ? { mode: mode } : {}) }); }
        catch (e) { setPtrCell(row, 'error'); window.DNSPanel.alert({ title: 'PTR', message: (e && e.message) || 'Failed to create PTR' }); return; }
        var d = (res && res.data) || {};
        if (d.blocked) {
            if (d.reason === 'conflict' || d.reason === 'multiple' || d.reason === 'disabled') {
                // A different/disabled/extra PTR appeared under lock: ask rather than overwrite silently.
                setPtrCell(row, d.reason === 'disabled' ? 'disabled'
                              : d.reason === 'multiple' ? 'multiple' : 'different', d);
                var ex = (d.existing && d.existing.length) ? '<br><span style="color:var(--text-dim)">Existing: ' + esc(d.existing.join(', ')) + '</span>' : '';
                var msg = d.reason === 'disabled' ? 'A disabled PTR record already exists for this address.'
                        : d.reason === 'multiple' ? 'This address already has several PTR records, and this name is one of them. Replacing keeps only this one.'
                        : 'A different PTR record already exists for this address.';
                var okr = await window.DNSPanel.confirm({ title: 'PTR already exists',
                    message: msg + ex, okText: 'Replace', cancelText: 'Cancel' });
                if (okr) createPtrForRow(row, 'replace');
            } else {   // not_managed / not_writable
                setPtrCell(row, 'external', d);
                window.DNSPanel.alert({ title: 'PTR', message: 'The reverse zone for this address is not managed here.' });
            }
            return;
        }
        // d.ptr here is an action string ('created'/'replaced'/'exists'), not a target list, so build the
        // badge object explicitly.
        setPtrCell(row, 'ok', { reverse_zone_id: d.reverse_zone_id, owner: d.owner, writable: true, ptr: d.target ? [d.target] : null });
        warnSync(res);
        if (sortSpec.some(function (x) { return x.k === 'ptr'; })) sortRows();
        applyRrFilters();
    }
    // Row data for the delete modal. matching = exact active PTR (status ok, reverse zone writable);
    // only those can be deleted together with the record.
    function delInfoOfRow(row) {
        var type = (row.getAttribute('data-type') || '').toUpperCase();
        var isAddr = (type === 'A' || type === 'AAAA');
        return { id: row.getAttribute('data-id'), name: row.getAttribute('data-name'), type: type,
            content: row.getAttribute('data-content') || '', st: row.getAttribute('data-ptr'),
            isAddr: isAddr, owner: row.getAttribute('data-ptr-owner') || '',
            matching: !!(isAddr && row.getAttribute('data-ptr') === 'ok' && row.getAttribute('data-ptr-rev') && row.getAttribute('data-ptr-writable')) };
    }
    // Single delete path for single and bulk; ptrIds are the records whose PTR goes too.
    function doDelete(ids, ptrIds) {
        return window.DNSPanel.api('zones/' + zoneId() + '/records/delete',
            { method: 'POST', body: JSON.stringify({ ids: ids, ptr_ids: ptrIds || [] }) })
            .then(function (res) {
                return refresh().then(function () {
                    warnSync(res);
                    var d = (res && res.data) || {};
                    // Rare race: the record changed under lock, so the PTR was left alone; say so.
                    if (d.ptr_skipped) window.DNSPanel.alert({ title: 'PTR left in place',
                        message: '<b>' + d.ptr_skipped + '</b> PTR record(s) were not deleted because the address record changed during deletion. Check the reverse zone.' });
                });
            })
            .catch(function (err) { window.DNSPanel.alert(err && err.message ? err.message : 'Delete failed'); });
    }
    // Shared delete modal (single + bulk); rows is an array of <tr>.
    function openDeleteModal(rows) {
        rows = (rows || []).filter(Boolean);
        if (!rows.length) return;
        var infos = rows.map(delInfoOfRow);
        var ids = infos.map(function (i) { return parseInt(i.id, 10); });
        var matching = infos.filter(function (i) { return i.matching; });
        var n = rows.length, recWord = n === 1 ? 'record' : 'records';

        if (!matching.length) {
            var msg = (n === 1)
                ? 'Delete record <b class="mono">' + esc(infos[0].type + ' ' + infos[0].name + ' → ' + infos[0].content) + '</b>?'
                : 'Delete <b>' + n + '</b> records? This cannot be undone.';
            window.DNSPanel.confirm({ title: 'Delete ' + recWord, message: msg, okText: 'Delete ' + n + ' ' + recWord, danger: true })
                .then(function (yes) { if (yes) doDelete(ids, []); });
            return;
        }

        // PTR categories among deleted A/AAAA. other = has a PTR that is not deleted
        // (different/disabled, or ok in a read-only reverse zone).
        var ext = infos.filter(function (i) { return i.isAddr && i.st === 'external'; }).length;
        var miss = infos.filter(function (i) { return i.isAddr && i.st === 'missing'; }).length;
        var other = infos.filter(function (i) { return i.isAddr && !i.matching && i.st !== 'external' && i.st !== 'missing'; }).length;
        var parts = [matching.length + ' matching PTR' + (matching.length === 1 ? '' : 's')];
        if (ext) parts.push(ext + ' external');
        if (miss) parts.push(miss + ' without PTR');
        if (other) parts.push(other + ' other');

        var rowsHtml = matching.map(function (i) {
            return '<tr><td class="th-check"><input type="checkbox" class="dr-ptr-cb" data-id="' + esc(i.id) + '"></td>' +
                '<td><b>' + esc(i.name) + '</b><br><span class="text-dim mono">' + esc(i.content) + '</span></td>' +
                '<td class="mono">' + esc(i.owner) + '<br><span class="text-dim">&rarr; ' + esc(i.name) + '</span></td></tr>';
        }).join('');

        var ov = overlay(); if (!ov) return;
        ov.innerHTML = '<div class="modal"><div class="modal-card dlg-card dr-card">' +
            '<div class="modal-head"><h2 class="modal-title">Delete ' + n + ' ' + recWord + '</h2>' +
            '<button type="button" class="modal-x" id="dr-x" aria-label="Close">&times;</button></div>' +
            '<div class="dlg-body">' +
            '<p>The selected forward ' + recWord + ' will be deleted.</p>' +
            '<div class="dr-ptr-title">Also delete matching PTR records:</div>' +
            '<div class="dr-table-wrap"><table class="data-table dr-ptr-table">' +
            '<thead><tr><th class="th-check"><input type="checkbox" id="dr-all" aria-label="Select all"></th>' +
            '<th>Address record</th><th>Matching PTR</th></tr></thead>' +
            '<tbody>' + rowsHtml + '</tbody></table></div>' +
            '<div class="dr-summary text-dim">' + esc(parts.join(' · ')) + '</div>' +
            '</div><div class="modal-actions">' +
            '<button type="button" class="btn btn-ghost" id="dr-cancel">Cancel</button>' +
            '<button type="button" class="btn btn-danger" id="dr-ok"></button>' +
            '</div></div></div>';
        ov.style.display = 'block';

        var okBtn = ov.querySelector('#dr-ok'), allCb = ov.querySelector('#dr-all');
        var cbs = Array.prototype.slice.call(ov.querySelectorAll('.dr-ptr-cb'));
        function checkedIds() { return cbs.filter(function (c) { return c.checked; }).map(function (c) { return parseInt(c.getAttribute('data-id'), 10); }); }
        function refresh() {
            var p = checkedIds().length;
            okBtn.textContent = 'Delete ' + n + ' ' + recWord + (p ? ' + ' + p + ' PTR' + (p === 1 ? '' : 's') : '');
            allCb.checked = p > 0 && p === cbs.length;
            allCb.indeterminate = p > 0 && p < cbs.length;
        }
        allCb.addEventListener('change', function () { var on = allCb.checked; cbs.forEach(function (c) { c.checked = on; }); refresh(); });
        cbs.forEach(function (c) { c.addEventListener('change', refresh); });
        ov.querySelector('#dr-cancel').addEventListener('click', closeModal);
        ov.querySelector('#dr-x').addEventListener('click', closeModal);
        okBtn.addEventListener('click', function () { var ptrIds = checkedIds(); closeModal(); doDelete(ids, ptrIds); });
        refresh();
    }
    // PTR statuses for all A/AAAA in one request. The sequence counter stops a slow stale response
    // (from before a reload) from overwriting a newer one.
    var ptrFetchSeq = 0;
    async function fetchPtrStatus() {
        var addr = rrRows().filter(function (r) { var t = (r.getAttribute('data-type') || '').toUpperCase(); return t === 'A' || t === 'AAAA'; });
        if (!addr.length) return;
        var seq = ++ptrFetchSeq;
        var res;
        try { res = await window.DNSPanel.api('zones/' + zoneId() + '/ptr-status'); }
        catch (e) { if (seq !== ptrFetchSeq) return; addr.forEach(function (r) { setPtrCell(r, 'error'); }); return; }
        if (seq !== ptrFetchSeq) return;
        var by = {};
        // DNSPanel.api returns the whole envelope {success,data:{...}}.
        ((res && res.data && res.data.statuses) || []).forEach(function (s) { by[String(s.id)] = s; });
        addr.forEach(function (r) {
            var s = by[r.getAttribute('data-id')], st = s ? s.status : 'error';
            setPtrCell(r, st, s);
        });
        if (sortSpec.some(function (x) { return x.k === 'ptr'; })) sortRows();
        applyRrFilters();   // the PTR filter may be active
    }
    var SORT_LS = 'dnspanel.rrSort';
    var DEFAULT_SORT = [{ k: 'type', d: 1 }, { k: 'name', d: 1 }, { k: 'status', d: 1 }, { k: 'updated', d: -1 }];
    function loadSort() { try { var s = JSON.parse(localStorage.getItem(SORT_LS) || 'null'); if (s && s.length) return s; } catch (e) {} return DEFAULT_SORT.slice(); }
    var sortSpec = loadSort();
    function sortVal(r, k) {
        if (k === 'name') return r.getAttribute('data-name') || '';
        if (k === 'type') { var t = (r.getAttribute('data-type') || '').toUpperCase(); var o = TYPE_ORDER[t]; return (o == null ? 50 : o); }
        if (k === 'status') return r.getAttribute('data-disabled') === '1' ? 1 : 0;
        if (k === 'ptr') { var p = r.getAttribute('data-ptr') || ''; var po = PTR_ORDER[p]; return (po == null ? 9 : po); }
        if (k === 'ttl') return parseInt(r.getAttribute('data-ttl'), 10) || 0;
        if (k === 'updated') return r.getAttribute('data-updated') || '';
        if (k === 'value') {
            var v = r.getAttribute('data-value') || '';
            var m = v.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
            if (m) {   // IPv4 as a zero-padded integer; the 'A' prefix sorts IPs first
                var n = ((+m[1]) * 16777216 + (+m[2]) * 65536 + (+m[3]) * 256 + (+m[4]));
                return 'A' + ('0000000000' + n).slice(-10);
            }
            return 'Z' + v.toLowerCase();   // non-IP values sort lexically after IPs
        }
        return '';
    }
    function cmpRows(x, y) {
        for (var i = 0; i < sortSpec.length; i++) {
            var s = sortSpec[i], a = sortVal(x, s.k), b = sortVal(y, s.k);
            if (a < b) return -s.d; if (a > b) return s.d;
        }
        return 0;
    }
    // An RRset is name PLUS type: aaa/A and aaa/AAAA are separate sets with separate Pulse.
    function rrsetKey(r) {
        return (r.getAttribute('data-name') || '').toLowerCase() + '\u0000'
             + (r.getAttribute('data-type') || '').toUpperCase();
    }
    function rrsetGroups(rows) {
        var out = [], by = {};
        rows.forEach(function (r) {
            var k = rrsetKey(r);
            if (!by[k]) { by[k] = { key: k, rows: [] }; out.push(by[k]); }
            by[k].rows.push(r);
        });
        return out;
    }
    // An RRset never splits under any sort: Pulse manages it as a whole, and split rows would read as
    // separate records. So GROUPS are sorted by their first row, rows within by the same key.
    function markRrsets(groups) {
        groups.forEach(function (g) {
            var many = g.rows.length > 1, last = g.rows.length - 1;
            g.rows.forEach(function (r, i) {
                r.classList.toggle('rrset-many', many);
                r.classList.toggle('rrset-last', many && i === last);
                // One Pulse badge per set: repeating it per row would suggest a Pulse per address.
                var c = r.querySelector('.rr-pulse');
                if (c) c.classList.toggle('is-dup', i > 0);
            });
        });
    }
    function sortRows() {
        var tb = document.getElementById('rr-tbody'); if (!tb) return;
        var groups = rrsetGroups(Array.prototype.slice.call(tb.querySelectorAll('tr.rr-row')));
        groups.forEach(function (g) { g.rows.sort(cmpRows); });
        groups.sort(function (a, b) {
            return cmpRows(a.rows[0], b.rows[0]) || (a.key < b.key ? -1 : a.key > b.key ? 1 : 0);
        });
        groups.forEach(function (g) { g.rows.forEach(function (r) { tb.appendChild(r); }); });
        markRrsets(groups);
        updateSortHeaders();
    }
    function updateSortHeaders() {
        document.querySelectorAll('.rr-table th.th-sort').forEach(function (th) {
            var k = th.getAttribute('data-sort'), idx = -1;
            for (var i = 0; i < sortSpec.length; i++) { if (sortSpec[i].k === k) { idx = i; break; } }
            var base = th.getAttribute('data-label');
            if (base == null) { base = th.textContent.replace(/[\s↑↓]+$/, ''); th.setAttribute('data-label', base); }
            th.classList.toggle('sorted', idx >= 0);
            th.textContent = base + (idx >= 0 ? (sortSpec[idx].d === 1 ? ' ↑' : ' ↓') : '');
        });
    }
    function onSortClick(th, shift) {
        var k = th.getAttribute('data-sort'); if (!k) return;
        if (shift) {
            var found = null; for (var i = 0; i < sortSpec.length; i++) { if (sortSpec[i].k === k) { found = sortSpec[i]; break; } }
            if (found) found.d = -found.d; else sortSpec.push({ k: k, d: 1 });
        } else {
            if (sortSpec.length && sortSpec[0].k === k) sortSpec[0].d = -sortSpec[0].d;
            else sortSpec = [{ k: k, d: 1 }];
        }
        try { localStorage.setItem(SORT_LS, JSON.stringify(sortSpec)); } catch (e) {}
        sortRows();
    }

    // ---------- Multi-select + bulk bar ----------
    // Selection is kept by record_id across filters/reload. Enable/Disable keep it; Delete/Clear drop it
    // (deleted ids are removed by pruneSel).
    var selIds = Object.create(null);
    function pruneSel() {
        var present = Object.create(null);
        rrRows().forEach(function (r) { present[r.getAttribute('data-id')] = 1; });
        Object.keys(selIds).forEach(function (id) { if (!present[id]) delete selIds[id]; });
    }
    function syncChecksFromSel() {
        rrRows().forEach(function (r) { var c = r.querySelector('.rr-check'); if (c) c.checked = !!selIds[r.getAttribute('data-id')]; });
    }
    function updateBulk() {
        var bar = document.getElementById('rr-bulk'); if (!bar) return;
        pruneSel();
        var ids = Object.keys(selIds);
        if (!ids.length) { bar.style.display = 'none'; bar.innerHTML = ''; }
        else {
            var hidden = 0;
            rrRows().forEach(function (r) { if (selIds[r.getAttribute('data-id')] && r.style.display === 'none') hidden++; });
            bar.style.display = '';
            bar.innerHTML = '<span class="rr-bulk-count">Selected: ' + ids.length + '</span>' +
                (hidden ? '<span class="rr-bulk-hidden">· hidden by filters: ' + hidden + '</span>' : '') +
                '<button type="button" class="btn btn-ghost btn-sm" data-bulk="enable">Enable</button>' +
                '<button type="button" class="btn btn-ghost btn-sm" data-bulk="disable">Disable</button>' +
                '<button type="button" class="btn btn-ghost btn-sm rr-bulk-del" data-bulk="delete">Delete</button>' +
                '<button type="button" class="btn btn-ghost btn-sm" data-bulk="clear">Clear</button>';
        }
        var all = document.getElementById('rr-check-all');
        if (all) {
            var vis = rrRows().filter(function (r) { return r.style.display !== 'none'; });
            var chk = vis.filter(function (r) { return selIds[r.getAttribute('data-id')]; });
            all.checked = vis.length > 0 && chk.length === vis.length;
            all.indeterminate = chk.length > 0 && chk.length < vis.length;
        }
    }
    async function bulkAction(action) {
        var ids = Object.keys(selIds); if (!ids.length) return;
        // Delete goes through the shared modal (with the matching-PTR table).
        if (action === 'delete') {
            openDeleteModal(rrRows().filter(function (r) { return selIds[r.getAttribute('data-id')]; }));
            return;
        }
        var nids = ids.map(function (x) { return parseInt(x, 10); });
        try {
            var res = await window.DNSPanel.api('zones/' + zoneId() + '/records/batch', { method: 'POST', body: JSON.stringify({ ids: nids, action: action }) });
            await refresh();   // selection is kept (same ids remain)
            warnSync(res);
        } catch (e) { window.DNSPanel.alert(e && e.message ? e.message : 'Bulk action failed'); }
    }

    // ---------- Delegated handlers ----------
    // Deep link from the PTR badge and global search: type/search set filters, record points at a row.
    // SOA/apex NS have no filters, so their accordion is opened and the row highlighted.
    function presetFromQuery() {
        var p = new URLSearchParams(window.location.search || '');
        var tv = p.get('type'), qv = p.get('search'), rid = p.get('record'), any = false;
        if (tv) {
            tv = tv.toUpperCase();
            var b = document.querySelector('.filter[data-filter="rtype"]');
            if (b) { b.setAttribute('data-val', tv); b.textContent = 'Type: ' + tv + ' ▾'; any = true; }
        }
        if (qv) { var si = document.getElementById('rr-search'); if (si) { si.value = qv; any = true; } }
        return { filtered: any, recordId: /^\d+$/.test(rid || '') ? rid : '' };
    }
    function revealRecord(recordId) {
        if (!recordId) return;
        var row = document.querySelector('.rr-row[data-id="' + recordId + '"],.ns-row[data-id="' + recordId + '"],#soa-row[data-id="' + recordId + '"]');
        if (!row) return;
        var acc = row.closest && row.closest('details');
        if (acc) acc.open = true;
        row.classList.add('rr-search-hit');
        requestAnimationFrame(function () {
            row.scrollIntoView({ behavior: 'smooth', block: 'center' });
        });
        window.setTimeout(function () { row.classList.remove('rr-search-hit'); }, 5000);
    }
    function initRecords() {
        initInlineAdd(); localizeTimes(); sortRows(); updateBulk();
        window.DNSPanel.filtersSet(document, window.DNSPanel.store('rrFilters'));   // a link's preset below wins
        var preset = presetFromQuery();
        applyRrFilters();
        revealRecord(preset.recordId);
        // async-ok: until the reply the column shows the page-rendered "…" placeholder, not an invented status.
        fetchPtrStatus();
    }
    // Single entry point: pageLoaded, sent by navigation.js after both server render (F5) and menu
    // navigation. A DOMContentLoaded hook as well would initialize the page twice.
    document.addEventListener('pageLoaded', function (e) { if (e.detail && e.detail.page === 'records') initRecords(); });
    // The Dynamic updates modal (js/dynamic.js) asks for a zone reload after saving.
    document.addEventListener('zoneChanged', function () { if (document.getElementById('zone-settings-btn')) refresh(); });

document.addEventListener('click', function (e) {
        var t = e.target;
        // Retry now: retry zone activation/NOTIFY (sync problem banner).
        var sr = t.closest && t.closest('.sync-retry-btn');
        if (sr) {
            e.preventDefault();
            sr.disabled = true; sr.textContent = 'Retrying…';
            window.DNSPanel.api('zones/' + zoneId() + '/retry-sync', { method: 'POST', body: '{}' })
                .then(function (res) {
                    var d = (res && res.data) || {};
                    if (d.busy) { window.DNSPanel.alert({ title: 'Retry', message: 'A retry is already in progress for this zone.' }); sr.disabled = false; sr.textContent = 'Retry now'; return; }
                    return refresh();   // the banner re-renders with the new state
                })
                .catch(function (err) { window.DNSPanel.alert(err && err.message ? err.message : 'Retry failed'); sr.disabled = false; sr.textContent = 'Retry now'; });
            return;
        }
        // Refresh AXFR: ask PowerDNS to re-transfer from the primary. The reply means "requested", not
        // "arrived"; completion shows in Last check in the same block.
        var rf = t.closest && t.closest('#zone-refresh-btn');
        if (rf) {
            e.preventDefault();
            rf.disabled = true; rf.textContent = 'Requesting…';
            window.DNSPanel.api('zones/' + zoneId() + '/refresh-axfr', { method: 'POST', body: '{}' })
                .then(async function (res) {
                    var d = (res && res.data) || {};
                    var notes = ['AXFR requested from ' + ((d.masters || []).join(', ') || 'the primary') + '.',
                                 'Last check shows the time once the transfer completes.'].concat(d.warnings || []);
                    await refresh();
                    window.DNSPanel.alert({ title: 'Refresh AXFR', message: notes.join(' ') });
                })
                .catch(function (err) {
                    rf.disabled = false; rf.textContent = 'Refresh AXFR';
                    window.DNSPanel.alert(err && err.message ? err.message : 'Refresh failed');
                });
            return;
        }
        // Missing "+" creates the PTR in place (other PTR badges are plain links).
        var pa = t.closest && t.closest('.js-ptr-add');
        if (pa) { e.preventDefault(); var pr = pa.closest('.rr-row'); if (pr) createPtrForRow(pr); return; }
        // Header click sorts; Shift+click adds a secondary key.
        var th = t.closest && t.closest('.rr-table th.th-sort');
        if (th) { e.preventDefault(); onSortClick(th, e.shiftKey); return; }
        var bk = t.closest && t.closest('[data-bulk]');
        if (bk) {
            e.preventDefault(); var a = bk.getAttribute('data-bulk');
            if (a === 'clear') { selIds = Object.create(null); syncChecksFromSel(); updateBulk(); }
            else bulkAction(a);
            return;
        }
        // Copy popover: a click on a history value opens it, a click elsewhere closes it.
        var hv = t.closest && t.closest('.hist-val');
        if (hv) { e.preventDefault(); openCopyPop(hv); return; }
        if (!(t.closest && (t.closest('#copy-pop') || t.closest('.hist-val')))) closeCopyPop();
        if (t.closest && t.closest('#ra-add')) { e.preventDefault(); submitInlineAdd(); return; }
        // Accordion header button: preventDefault so the details element doesn't toggle.
        if (t.closest && t.closest('.acc-hist')) { e.preventDefault(); openApexHistory(); return; }
        // SOA in-place
        if (t.closest && t.closest('.soa-edit')) { e.preventDefault(); openSoaInline(); return; }
        if (t.closest && t.closest('.soa-save')) { e.preventDefault(); saveSoaInline(); return; }
        if (t.closest && t.closest('.soa-cancel')) { e.preventDefault(); closeSoaInline(); return; }
        // NS table
        var nse = t.closest && t.closest('.ns-edit'); if (nse) { e.preventDefault(); openNsInline(nse.closest('.ns-row')); return; }
        var nss = t.closest && t.closest('.ns-save'); if (nss) { e.preventDefault(); saveNsInline(nss.closest('.ns-row')); return; }
        var nsc = t.closest && t.closest('.ns-cancel'); if (nsc) { e.preventDefault(); closeNsInline(nsc.closest('.ns-row')); return; }
        var nsd = t.closest && t.closest('.ns-del'); if (nsd) { e.preventDefault(); deleteNs(nsd.closest('.ns-row')); return; }
        if (t.closest && t.closest('.ns-add-btn')) { e.preventDefault(); addNs(); return; }
        if (t.closest && t.closest('#zlabels-open')) { e.preventDefault(); openZoneLabels(); return; }
        var zsb = t.closest && t.closest('#zone-settings-btn'); if (zsb) { e.preventDefault(); openZoneSettings(zsb); return; }
        var zsrc = t.closest && t.closest('#zone-source-btn');
        if (zsrc) { e.preventDefault(); openUpstream(); return; }
        var dz = t.closest && t.closest('#zone-delete-btn'); if (dz) { e.preventDefault(); openDeleteZone(dz.getAttribute('data-id'), dz.getAttribute('data-name')); return; }
        // inline-edit: Save / Cancel
        var rsave = t.closest && t.closest('.rie-save'); if (rsave) { e.preventDefault(); saveInlineEdit(rsave.closest('tr')); return; }
        var rcanc = t.closest && t.closest('.rie-cancel'); if (rcanc) { e.preventDefault(); restoreRow(rcanc.closest('tr')); return; }
        // label chip toggle in the labels modal
        var chip = t.closest && t.closest('.lbl-chip');
        if (chip && chip.closest('#zl-form')) {
            var cat = chip.closest('.lbl-cat');
            if (!chip.classList.contains('on') && cat.getAttribute('data-cardinality') === 'single')
                cat.querySelectorAll('.lbl-chip.on').forEach(function (c) { c.classList.remove('on'); });
            chip.classList.toggle('on'); return;
        }
        var dot = t.closest && t.closest('[data-pinger-history]');
        if (dot) { e.preventDefault(); openHistory(dot.closest('tr'), 'pinger'); return; }
        var hist = t.closest && t.closest('.rr-hist');
        if (hist) { e.preventDefault(); openHistory(hist.closest('tr'), 'changes'); return; }
        var ed = t.closest && t.closest('.js-edit-rrset'); if (ed) { e.preventDefault(); openInlineEdit(ed.closest('tr')); return; }
        var del = t.closest && t.closest('.js-del-rrset');
        if (del) { e.preventDefault(); openDeleteModal([del.closest('tr')]); return; }
        if (t.closest && t.closest('#rr-filter-clear')) {
            e.preventDefault();
            var si = document.getElementById('rr-search'); if (si) si.value = '';
            RR_FILTERS.forEach(function (n) { var b = document.querySelector('.filter[data-filter="' + n + '"]'); if (b) { b.setAttribute('data-val', 'all'); b.textContent = FILTER_LABEL[n] + ': all ▾'; } });
            saveRrFilters(); applyRrFilters(); return;
        }
        var fb = t.closest && t.closest('.rr-toolbar .filter[data-filter]'); if (fb) { e.preventDefault(); rrOpenMenu(fb); return; }
        // Recognised by the menu's filter name, not by its place: the shared filter handler (app.js) runs first
        // and removes the open menu, so by now the option may no longer be inside .rr-toolbar.
        var fo = t.closest && t.closest('.filter-opt'), fm = fo && fo.closest('.filter-menu');
        if (fo && fm && RR_FILTERS.indexOf(fm.getAttribute('data-for')) >= 0) {
            e.preventDefault(); var nm = fm.getAttribute('data-for');
            var bb = document.querySelector('.filter[data-filter="' + nm + '"]');
            bb.setAttribute('data-val', fo.getAttribute('data-val'));
            bb.textContent = FILTER_LABEL[nm] + ': ' + fo.textContent + ' ▾';
            rrCloseMenus(); saveRrFilters(); applyRrFilters(); return;
        }
        if (!(t.closest && t.closest('.rr-toolbar .filter-menu'))) rrCloseMenus();
    });
    document.addEventListener('input', function (e) { if (e.target && e.target.id === 'rr-search') applyRrFilters(); });
    document.addEventListener('change', function (e) {
        if (e.target && e.target.id === 'rr-check-all') {
            var on = e.target.checked;
            rrRows().forEach(function (r) {
                if (r.style.display === 'none') return;               // visible rows only
                var c = r.querySelector('.rr-check'), id = r.getAttribute('data-id');
                if (c) c.checked = on;
                if (on) selIds[id] = 1; else delete selIds[id];
            });
            updateBulk(); return;
        }
        if (e.target && e.target.classList && e.target.classList.contains('rr-check')) {
            var row = e.target.closest('tr.rr-row'); var rid = row.getAttribute('data-id');
            if (e.target.checked) selIds[rid] = 1; else delete selIds[rid];
            updateBulk();
        }
    });
    document.addEventListener('keydown', function (e) {
        if (e.key !== 'Escape') return;
        var ov = overlay();
        if (ov && ov.style.display === 'block') { e.preventDefault(); closeModal(); return; }
        if (document.querySelector('tr.rr-editing')) { e.preventDefault(); closeInlineEditors(); return; }
        var soaRow = document.getElementById('soa-row');
        if (soaRow && soaRow.classList.contains('soa-editing')) { e.preventDefault(); closeSoaInline(); return; }
        var nsEd = document.querySelector('#ns-table .ns-row.ns-editing');
        if (nsEd) { e.preventDefault(); closeNsInline(nsEd); }
    });
})();
