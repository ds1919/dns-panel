/* DNS Panel — zones page: create (forward/reverse) and delete zones.
   Permissions are enforced by the server (zones.manage); the UI only hides buttons. */

(function () {
    'use strict';

    function esc(s) {
        return String(s == null ? '' : s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    // Same zone-name rules as dns_validate_zonename; record names (_sip._tcp etc.) are separate.
    function validateZoneName(value) {
        var name = value.trim();
        if (/[^\x00-\x7f]/.test(name)) return { error: 'Use ASCII letters and digits; international names must use Punycode (xn--).' };
        name = name.toLowerCase().replace(/\.$/, '');
        if (!name) return { error: 'Enter a zone name.' };
        if (name.length > 253) return { error: 'Zone name must not exceed 253 characters.' };
        if (/\s/.test(name)) return { error: 'Zone name must not contain spaces.' };
        var labels = name.split('.');
        for (var i = 0; i < labels.length; i++) {
            if (!labels[i]) return { error: 'Empty name parts are not allowed (for example, two dots in a row).' };
            if (labels[i].length > 63) return { error: 'Each name part must not exceed 63 characters.' };
            if (!/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(labels[i]))
                return { error: 'Use letters A-Z, digits and hyphens inside name parts. Underscores and other special characters are not allowed.' };
        }
        return { name: name };
    }

    // Returns true only if the list was actually refreshed, so callers can tell stale rows from fresh ones.
    async function reload() {
        var main = document.getElementById('main-content');
        if (!main) return false;
        try {
            var res = await fetch('/ajax/zones' + window.location.search, { credentials: 'same-origin' });
            if (res.status === 401 || res.redirected) { window.location.href = '/login'; return false; }
            // fetch rejects only on network errors; without this check a 500/403 page would be
            // inserted into #main-content.
            if (!res.ok) throw new Error('HTTP ' + res.status);
            main.innerHTML = await res.text();
            initZoneFilters();   // saved filters survive the reload
            return true;
        } catch (e) { console.error('zones: reload failed', e); return false; }
    }

    // After create/delete only the changed zone rows are touched (DNSPanel.patchPage); filters stay.
    async function refresh() {
        try {
            var changed = await window.DNSPanel.patchPage({ url: '/ajax/zones' + window.location.search,
                lists: [{ sel: '#zone-tbody', item: 'tr.zone-row', key: 'data-name', by: 'html' }] });
            if (!changed) return reload();
            applyZoneFilters();
            return true;
        } catch (e) { console.error('zones: refresh failed', e); return reload(); }
    }

    function overlay() { return document.getElementById('modal-overlay'); }
    function closeModal() { var ov = overlay(); if (ov) { ov.style.display = 'none'; ov.innerHTML = ''; } }

    // Warn about sync problems after create/reverse/delete. items: {zone?, pdns_state, notify_state?,
    // detail?, state_error?} or an array of them. state_error is reported separately: unlike a failed
    // activation, the worker will NOT retry it (no state row / next_retry), so a manual retry is needed.
    function warnZoneSync(items) {
        if (!items) return;
        if (!Array.isArray(items)) items = [items];
        var bad = items.filter(function (s) {
            return s && (s.pdns_state === 'activation_failed' || s.pdns_state === 'deactivation_failed'
                || s.pdns_state === 'still_served' || s.pdns_state === 'transfer_problem'
                || (s.pdns_state === 'active' && s.notify_state === 'notify_failed') || s.state_error);
        });
        if (!bad.length) return;
        var lines = bad.map(function (s) {
            var name = s.zone ? '<b>' + esc(s.zone) + '</b>: ' : '';
            var what;
            if (s.pdns_state === 'activation_failed')        what = 'PowerDNS did not confirm serving the zone';
            else if (s.pdns_state === 'deactivation_failed') what = 'could not confirm the zone was removed';
            else if (s.pdns_state === 'still_served')         what = 'PowerDNS still serves the deleted zone';
            else if (s.pdns_state === 'transfer_problem')     what = 'AXFR could not be started or completed';
            else if (s.notify_state === 'notify_failed')     what = 'NOTIFY to secondaries failed';
            else                                             what = 'applied';
            if (s.state_error) what += ' — <b style="color:var(--danger)">sync state was not saved, automatic retry is NOT scheduled</b>';
            else if (s.pdns_state === 'activation_failed')   what += ' — it will be retried automatically';
            else if (s.pdns_state === 'still_served' || s.pdns_state === 'deactivation_failed') what += ' — automatic deactivation retry is scheduled';
            else if (s.pdns_state === 'transfer_problem')     what += ' — automatic retry is scheduled; check masters/TSIG';
            else if (s.notify_state === 'notify_failed')     what += ' — secondaries catch up on refresh';
            return name + what;
        });
        window.DNSPanel.alert({ title: 'Sync not confirmed', message: 'Saved to the database, but:<br>' + lines.join('<br>') });
    }

    var selectHtml = window.DNSPanel.selectHtml;

    function listRowHtml(cls, value, placeholder) {
        return '<div class="zform-list-row ' + cls + '-row">' +
            '<input type="text" class="field-input ' + cls + '-input" value="' + esc(value || '') +
            '" placeholder="' + esc(placeholder || '') + '" autocomplete="off">' +
            '<button type="button" class="btn btn-ghost zform-x ' + cls + '-del">×</button>' +
            '</div>';
    }

    // -------- Create zone --------
    async function openCreateModal() {
        var ov = overlay(); if (!ov) return;
        ov.innerHTML = '<div class="modal"><div class="modal-card"><div class="spinner"></div></div></div>';
        ov.style.display = 'block';

        var defaults, categories = [], dynProfiles = [];
        // Dynamic DHCP profiles let a new zone accept updates right away; if they fail to load, the form
        // works without them.
        try { var dpr = await window.DNSPanel.api('dynamic/profiles', { method: 'GET' }); dynProfiles = ((dpr.data || dpr).profiles) || []; } catch (e) {}
        var upKeys = await window.DNSPanel.upstreamKeys();
        function dynOpts() { return [{ value: '', label: 'Off' }].concat(dynProfiles.map(function (p) { return { value: String(p.id), label: 'Follow profile: ' + p.name }; })); }
        var dynNote = '';
        try {
            var r = await window.DNSPanel.api('zones/defaults', { method: 'GET' });
            defaults = r.data || r;
            var lr = await window.DNSPanel.api('labels', { method: 'GET' });
            categories = (lr.data && lr.data.categories) || [];
        } catch (e) {
            ov.innerHTML = '<div class="modal"><div class="modal-card"><h2 class="modal-title">Add zone</h2>' +
                '<div class="login-error" style="display:block;">' + esc(e && e.message ? e.message : 'Failed to load defaults') +
                '</div><div class="modal-actions"><button type="button" class="btn btn-ghost" id="zone-cancel">Close</button></div></div></div>';
            ov.querySelector('#zone-cancel').addEventListener('click', closeModal);
            return;
        }

        var soa = defaults.soa || {};
        // Allowed roles come from /zones/defaults, the backend's single source of truth.
        var ROLE_LABEL = { primary: 'Primary', secondary: 'Secondary' };
        var roleOpts  = (defaults.roles  || []).map(function (r) { return { value: r, label: ROLE_LABEL[r]  || r }; });
        // Delivery is two independent questions, worded as in Zone settings:
        //   1) serve the zone directly by AXFR;  2) which catalog announces it (primary only).
        var CATS = defaults.catalogs || [], CAN_CAT = !!defaults.can_change_catalog;
        function wantDirect(pfx) {
            var r = ov.querySelector('input[name="' + pfx + 'dist-r"]:checked');
            return r ? !!r.value : false;
        }
        // Only primary zones can be in a catalog; other roles get no control, since the server would refuse.
        function wantCatalog(pfx) {
            var h = q(pfx + 'cat');
            return (h && h.value) ? +h.value : null;
        }
        function distField(pfx) {
            if (!CAN_CAT) return '';
            // Allow by default: direct delivery is the normal case.
            var body = '<label class="chk" style="margin-right:1.2rem;"><input type="radio" name="' + pfx + 'dist-r" value="1" checked> Allow</label>' +
                       '<label class="chk"><input type="radio" name="' + pfx + 'dist-r" value=""> None</label>';
            return '<div class="zform-row"><label>Direct AXFR' + window.DNSPanel.helpDot(pfx + 'az-direct', 'Servers and groups in Propagation get this zone by AXFR and NOTIFY.') + '</label><div class="zform-grow">' + body + '</div></div>' +
                   '<div class="zform-row"><label>Catalog' + window.DNSPanel.helpDot(pfx + 'az-cat', 'Announces the zone to the catalog\u2019s subscribers (RFC 9432). Independent of Direct AXFR.') + '</label><div class="zform-grow" id="' + pfx + 'cat-row"></div></div>';
        }
        // Re-render only the catalog row so the rest of the form keeps what was typed. The role is read from
        // the form because it can be changed right here.
        function renderCatRow(pfx) {
            if (!CAN_CAT) return;
            var box = ov.querySelector('#' + pfx + 'cat-row'); if (!box) return;
            var roleEl = q(pfx === 'rev-' ? 'rev-role' : 'role');
            var role = roleEl ? roleEl.value : 'primary';       // reverse zones are always primary and have no role field
            if (role !== 'primary') {
                box.innerHTML = '<div class="zs-role-ro">None</div>' +
                                '<div class="zform-note">Primary zones only</div>';
                return;
            }
            var cur = catDefault[pfx] || '';
            var opts = [{ value: '', label: 'None' }].concat(CATS.map(function (c) {
                return { value: String(c.catalog_id),
                         label: window.DNSPanel.catalogLabel(c) + (c.provisioned ? '' : ' — not created yet') }; }));
            box.innerHTML = selectHtml(pfx + 'cat', opts, cur);
        }
        var catDefault = {};   // the profile's default catalog
        // Delivery is set with the same two per-zone requests used later for editing. The zone already exists,
        // so a failure here is "pending", not "Create failed", and is reported separately.
        async function applyDelivery(ids, direct, catId) {
            var failed = [];
            for (var i = 0; i < ids.length; i++) {
                var zid = +ids[i];
                try {
                    if (direct) {
                        var dres = await window.DNSPanel.api('zones/' + zid + '/direct-axfr',
                                                             { method: 'PUT', body: JSON.stringify({ on: true }) });
                        // A 2xx response may still carry per-zone failures; report them instead of
                        // claiming the zone is being served.
                        ((dres && dres.data && dres.data.failed) || []).forEach(function (f) {
                            failed.push({ error: 'direct AXFR: ' + (f.error || 'failed') });
                        });
                    }
                    if (catId)  await window.DNSPanel.api('zones/' + zid + '/catalog',
                                                          { method: 'PUT', body: JSON.stringify({ catalog_id: catId }) });
                } catch (e) { failed.push({ error: (e && e.message) || 'failed' }); }
            }
            return { failed: failed, pending: [], policy_warnings: [] };
        }

        var soaRow = function (label, name, value, ph) {
            return '<div class="zform-row"><label>' + label + '</label>' +
                '<input type="text" name="' + name + '" class="field-input"' +
                (value != null && value !== '' ? ' value="' + esc(value) + '"' : '') +
                (ph ? ' placeholder="' + esc(ph) + '"' : '') + ' autocomplete="off"></div>';
        };

        var labelsBody = categories.length ? (
            '<div class="zform-labels">' +
            categories.map(function (c) {
                var chips = (c.values || []).map(function (v) {
                    return '<span class="lbl-chip" data-id="' + v.id + '" data-cat="' + c.id + '"' +
                        ' data-name="' + esc(v.name) + '"' + (v.color ? ' style="--c:' + esc(v.color) + '"' : '') +
                        '>' + esc(v.name) + '</span>';
                }).join('');
                return '<div class="lbl-cat" data-cardinality="' + esc(c.cardinality) + '">' +
                    '<label>' + esc(c.name) + '</label><div class="lbl-chips">' + chips + '</div></div>';
            }).join('') + '</div>'
        ) : '<div class="text-mute" style="font-size:12px;">No label categories. Create them in Labels.</div>';

        // Profiles are {code,name}: value=code (immutable), label=name. "None" means SOA and NS are filled in by hand.
        var PROFILES = defaults.profiles || [];
        function profileOpts() { return [{ value: '', label: 'None — fill SOA below' }].concat(PROFILES.map(function (p) { return { value: p.code, label: p.name }; })); }
        // Without a profile, typed values are kept and empty timers get the standard values (same as the server).
        var SOA_STD = { ttl: 3600, refresh: 7200, retry: 3600, expire: 1209600, minimum: 3600 };
        function fillStdTimers(prefix) {
            Object.keys(SOA_STD).forEach(function (k) { var el = q(prefix + k); if (el && !el.value) el.value = SOA_STD[k]; });
        }
        var profileDefault = PROFILES[0] ? PROFILES[0].code : '';
        var revProfiles = profileOpts();
        var revBody =
            '<div id="rev-body" class="zform-split" style="display:none;">' +
              '<div class="zform-main">' +
              '<div class="zform-sec-title">Reverse zone</div>' +
              '<div class="zform-row"><label>Network</label>' +
                '<input type="text" name="rev-cidr" class="field-input" placeholder="10.20.30.0/24 or 2001:db8::/48" autocomplete="off"></div>' +
              '<div class="zform-row"><label>Role</label>' + selectHtml('rev-role', roleOpts, 'primary') + '</div>' +
              '<div class="zform-row" id="rev-profile-row"><label>Profile</label>' + selectHtml('rev-profile', revProfiles, profileDefault) + '</div>' +
              distField('rev-') +
              // Applies to every zone created for the network, as in forward.
              '<div class="zform-row" id="rev-dyn-row"><label>Dynamic DHCP</label>' +
                '<div class="zform-grow">' + selectHtml('rev-dynamic', dynOpts(), '') + dynNote + '</div></div>' +
              '<div class="zform-row"><label>Labels</label>' +
                '<div class="lbl-rowval"><span class="lbl-selected-box" id="rev-lbl-selected"></span>' +
                '<button type="button" class="btn btn-ghost lbl-open">+ Add labels</button></div></div>' +
              '<hr class="zform-div">' +
              '<div class="zform-sec-title">Plan</div>' +
              '<div id="rev-plan" class="rev-plan"><span class="text-mute">Enter a network to see which reverse zones will be created.</span></div>' +
              '</div>' /* .zform-main */ +
              // SOA / NS overrides apply to every zone created for the network.
              '<div class="zform-side">' +
              // Secondary: each zone of the network is mirrored from these primaries, like a forward secondary.
              '<div id="rev-sec-secondary" style="display:none;">' +
                '<div class="zform-sec-title">Secondary source</div>' +
                '<div class="zform-row"><label>Primaries</label><div class="zform-grow">' +
                '<div id="rev-master-list"></div>' +
                '<button type="button" class="btn btn-ghost" id="rev-master-add">+ Add primary</button></div></div>' +
                '<div class="zform-row"><label>Upstream TSIG</label><div class="zform-grow">' +
                window.DNSPanel.upstreamTsigHtml('azr', '', upKeys) + '</div></div>' +
              '</div>' +
              '<div class="zform-cols" id="rev-cols">' +
                '<div class="zform-col-left"><div id="rev-sec-soa">' +
                  '<div class="zform-sec-title">SOA</div>' +
                  soaRow('Primary NS', 'rev-primary_ns', '') +
                  soaRow('Hostmaster', 'rev-hostmaster', '') +
                  soaRow('TTL', 'rev-ttl', soa.ttl) +
                  soaRow('Serial', 'rev-serial', '', 'auto (YYYYMMDD01)') +
                  soaRow('Refresh', 'rev-refresh', soa.refresh) +
                  soaRow('Retry', 'rev-retry', soa.retry) +
                  soaRow('Expire', 'rev-expire', soa.expire) +
                  soaRow('Minimum', 'rev-minimum', soa.minimum) +
                '</div></div>' +
                '<div class="zform-col-right"><div id="rev-sec-ns">' +
                  '<div class="zform-sec-title">Name servers</div>' +
                  '<div id="rev-ns-list"></div>' +
                  '<button type="button" class="btn btn-ghost" id="rev-ns-add">+ Add NS</button>' +
                '</div></div>' +
              '</div>' +
              '</div>' /* .zform-side */ +
            '</div>';

        ov.innerHTML =
            '<div class="modal"><div class="zform-shell">' +
            '<form class="modal-card zform-wide" id="zone-create-form">' +
            '<div class="modal-head"><h2 class="modal-title">Add zone</h2>' +
              '<button type="button" class="modal-x" id="zone-close-x" aria-label="Close">×</button></div>' +
            '<div class="modal-body">' +
            '<div class="zform-row"><label>Kind</label>' +
              selectHtml('kind', [{ value: 'forward', label: 'Forward' }, { value: 'reverse', label: 'Reverse (PTR)' }], 'forward') + '</div>' +
            '<hr class="zform-div">' +

            // Two halves: the zone's own settings on the left, SOA/NS (or the secondary source) on the right,
            // so the whole form fits one screen.
            '<div id="fwd-body" class="zform-split">' +
            '<div class="zform-main">' +
            '<div class="zform-sec-title">Zone</div>' +
            '<div class="zform-row"><label for="zone-name">Name</label>' +
              '<div class="zone-name-field"><input type="text" id="zone-name" name="name" class="field-input" placeholder="example.corp" autocomplete="off" spellcheck="false" aria-describedby="zone-name-error">' +
              '<div id="zone-name-error" class="zone-name-error" role="alert" hidden></div></div></div>' +
            // Profile presets SOA/NS for primaries; a secondary gets them via AXFR, so the row is hidden.
            '<div class="zform-row" id="profile-row"><label>Profile</label>' +
              selectHtml('profile', profileOpts(), profileDefault) + '</div>' +

            '<div class="zform-row"><label>Role</label>' +
              selectHtml('role', roleOpts, (defaults.roles || [])[0]) + '</div>' +
            distField('') +
            // Primary only: a secondary is updated by its master. Per-zone settings go in Zone settings later.
            '<div class="zform-row" id="dyn-row"><label>Dynamic DHCP</label>' +
              '<div class="zform-grow">' + selectHtml('zone-dynamic', dynOpts().concat([{ value: 'own', label: 'Own settings' }]), '') + dynNote +
                '<div id="az-dyn-own" hidden>' + window.DNSPanel.dynForm.html('azd-', {}) + '</div></div></div>' +
            '<div class="zform-row" id="dnssec-row"><label>DNSSEC</label>' +
              '<label class="chk"><input type="checkbox" id="zone-dnssec" name="zone-dnssec"> Sign the zone</label></div>' +
            '<div class="zform-row"><label>Labels</label>' +
              '<div class="lbl-rowval"><span class="lbl-selected-box" id="lbl-selected"></span>' +
              '<button type="button" class="btn btn-ghost lbl-open" id="lbl-open">+ Add labels</button></div></div>' +

            '</div>' /* .zform-main */ +
            '<div class="zform-side">' +
            '<div class="zform-cols">' +
              '<div class="zform-col-left">' +
                '<div id="sec-soa">' +
                  '<div class="zform-sec-title">SOA</div>' +
                  soaRow('Primary NS', 'primary_ns', '') +
                  soaRow('Hostmaster', 'hostmaster', '') +
                  soaRow('TTL', 'ttl', soa.ttl) +
                  soaRow('Serial', 'serial', '', 'auto (YYYYMMDD01)') +
                  soaRow('Refresh', 'refresh', soa.refresh) +
                  soaRow('Retry', 'retry', soa.retry) +
                  soaRow('Expire', 'expire', soa.expire) +
                  soaRow('Minimum', 'minimum', soa.minimum) +
                '</div>' +
                '<div id="sec-secondary" style="display:none;">' +
                  '<div class="zform-sec-title">Secondary source</div>' +
                  '<div class="zform-row"><label>Primaries</label><div class="zform-grow">' +
                  '<div id="master-list"></div>' +
                  '<button type="button" class="btn btn-ghost" id="master-add">+ Add primary</button></div></div>' +
                  '<div class="zform-row"><label>Upstream TSIG</label><div class="zform-grow">' +
                  window.DNSPanel.upstreamTsigHtml('az', '', upKeys) + '</div></div>' +
                '</div>' +
              '</div>' +
              '<div class="zform-col-right">' +
                '<div id="sec-ns">' +
                  '<div class="zform-sec-title">Name servers</div>' +
                  '<div id="ns-list"></div>' +
                  '<button type="button" class="btn btn-ghost" id="ns-add">+ Add NS</button>' +
                '</div>' +
              '</div>' +
            '</div>' +
            '</div>' /* .zform-side */ +
            '</div>' /* #fwd-body */ +
            revBody +
            '</div>' /* .modal-body */ +

            '<div class="login-error" id="zone-create-err" style="display:none;"></div>' +
            '<div class="modal-actions">' +
            '<button type="button" class="btn btn-ghost" id="zone-cancel">Cancel</button>' +
            '<button type="submit" class="btn btn-primary" id="zone-create-btn">Create zone</button>' +
            '</div></form>' +

            '<div class="labels-panel" id="labels-panel" style="display:none;">' +
              '<div class="lp-head"><span class="zform-sec-title" style="margin:0;">Labels</span>' +
                '<button type="button" class="btn btn-ghost" id="lbl-done">Done</button></div>' +
              '<input type="text" class="field-input" id="lbl-search" placeholder="Search…" autocomplete="off" style="margin:.6rem 0;">' +
              '<div class="lp-body">' + labelsBody + '</div>' +
            '</div>' +

            '</div></div>';

        var q = function (n) { return ov.querySelector('[name="' + n + '"]'); };
        var errEl = ov.querySelector('#zone-create-err');
        var nameInput = q('name'), nameError = ov.querySelector('#zone-name-error');
        var createButton = ov.querySelector('#zone-create-btn');
        var submitting = false;
        function checkName(showError) {
            var reverse = q('kind').value === 'reverse';
            var result = validateZoneName(nameInput.value);
            var error = reverse ? '' : (result.error || '');
            nameInput.disabled = reverse; // A hidden forward field must not block reverse-zone creation.
            nameInput.setCustomValidity(error);
            nameInput.setAttribute('aria-invalid', showError && error ? 'true' : 'false');
            nameError.textContent = error;
            nameError.hidden = !showError || !error;
            createButton.disabled = submitting || !!error;
            return result;
        }
        nameInput.addEventListener('input', function () { checkName(true); });
        nameInput.addEventListener('blur', function () { checkName(true); });
        checkName(false);
        var nsList = ov.querySelector('#ns-list');
        var masterList = ov.querySelector('#master-list');
        // Listeners go on the fresh shell (recreated on every open), not on the persistent #modal-overlay,
        // where they would pile up between openings and break select toggles.
        var formRoot = ov.querySelector('.zform-shell');

        var revNsList = ov.querySelector('#rev-ns-list');
        function addNs(v) { nsList.insertAdjacentHTML('beforeend', listRowHtml('ns', v, 'ns1.example.com.')); }
        function addMaster(v) { masterList.insertAdjacentHTML('beforeend', listRowHtml('master', v, '10.20.30.40')); }
        var revMasterList = ov.querySelector('#rev-master-list');
        function addRevMaster(v) { revMasterList.insertAdjacentHTML('beforeend', listRowHtml('rev-master', v, '10.20.30.40')); }
        function toggleRevRole() {
            var sec = q('rev-role').value === 'secondary';
            ['#rev-profile-row', '#rev-dyn-row', '#rev-cols'].forEach(function (s) { ov.querySelector(s).style.display = sec ? 'none' : ''; });
            ov.querySelector('#rev-sec-secondary').style.display = sec ? '' : 'none';
            if (sec && !revMasterList.children.length) addRevMaster('');
            renderCatRow('rev-');
        }
        function addRevNs(v) { revNsList.insertAdjacentHTML('beforeend', listRowHtml('rev-ns', v, 'ns1.example.com.')); }

        // Selected-labels summary; the selection is shared by forward and reverse.
        function renderSelectedSummary() {
            var boxes = ov.querySelectorAll('.lbl-selected-box');
            if (!boxes.length) return;
            var on = ov.querySelectorAll('#labels-panel .lbl-chip.on');
            var html = Array.prototype.map.call(on, function (c) {
                var col = c.style.getPropertyValue('--c');
                return '<span class="lbl-tag"' + (col ? ' style="--c:' + col + '"' : '') + '>' + esc(c.getAttribute('data-name')) + '</span>';
            }).join('');
            Array.prototype.forEach.call(boxes, function (b) { b.innerHTML = html; });
            Array.prototype.forEach.call(ov.querySelectorAll('.lbl-open'), function (btn) {
                btn.textContent = on.length ? 'Edit labels' : 'Choose labels…';
            });
        }

        async function applyPreset() {
            if (!q('profile').value) { fillStdTimers(''); if (!nsList.children.length) addNs(''); return; }
            try {
                var pr = await window.DNSPanel.api('zones/defaults?profile=' + encodeURIComponent(q('profile').value), { method: 'GET' });
                var d = pr.data || pr, p = d.preset || {}, s = p.soa || {};
                q('primary_ns').value = p.primary_ns || '';
                q('hostmaster').value = p.hostmaster || '';
                if (q('ttl'))     q('ttl').value     = (s.ttl != null ? s.ttl : '');
                if (q('refresh')) q('refresh').value = (s.refresh != null ? s.refresh : '');
                if (q('retry'))   q('retry').value   = (s.retry != null ? s.retry : '');
                if (q('expire'))  q('expire').value  = (s.expire != null ? s.expire : '');
                if (q('minimum')) q('minimum').value = (s.minimum != null ? s.minimum : '');
                if (CAN_CAT) applyCatDefault('', p.default_catalog_id);
                nsList.innerHTML = '';
                (p.nameservers || []).forEach(addNs);
                if (!nsList.children.length) addNs('');
            } catch (e) { /* keep the fields as they are */ }
        }

        // Profile preset for the reverse SOA/NS (loaded lazily; applies to every zone of the network).
        async function applyRevPreset() {
            if (!q('rev-profile').value) { fillStdTimers('rev-'); return; }
            try {
                var pr = await window.DNSPanel.api('zones/defaults?profile=' + encodeURIComponent(q('rev-profile').value), { method: 'GET' });
                var d = pr.data || pr, p = d.preset || {}, s = p.soa || {};
                q('rev-primary_ns').value = p.primary_ns || '';
                q('rev-hostmaster').value = p.hostmaster || '';
                if (q('rev-ttl'))     q('rev-ttl').value     = (s.ttl != null ? s.ttl : '');
                if (q('rev-refresh')) q('rev-refresh').value = (s.refresh != null ? s.refresh : '');
                if (q('rev-retry'))   q('rev-retry').value   = (s.retry != null ? s.retry : '');
                if (q('rev-expire'))  q('rev-expire').value  = (s.expire != null ? s.expire : '');
                if (q('rev-minimum')) q('rev-minimum').value = (s.minimum != null ? s.minimum : '');
                if (CAN_CAT) applyCatDefault('rev-', p.default_catalog_id);
                revNsList.innerHTML = '';
                (p.nameservers || []).forEach(addRevNs);
                if (!revNsList.children.length) addRevNs('');
            } catch (e) { /* keep the fields as they are */ }
        }

        // A profile may name a default catalog: zones of that profile are created announced in it, as before,
        // but the choice is shown in the form and can be changed.
        function applyCatDefault(pfx, aid) {
            catDefault[pfx] = (aid != null && aid !== '') ? String(aid) : '';
            renderCatRow(pfx);
        }
        function toggleRole() {
            var sec = q('role').value === 'secondary';
            ov.querySelector('#sec-soa').style.display = sec ? 'none' : '';
            ov.querySelector('#sec-ns').style.display  = sec ? 'none' : '';
            ov.querySelector('#sec-secondary').style.display = sec ? '' : 'none';
            ov.querySelector('#profile-row').style.display = sec ? 'none' : '';
            ov.querySelector('#dyn-row').style.display = sec ? 'none' : '';
            ov.querySelector('#dnssec-row').style.display = sec ? 'none' : '';
            if (sec && !masterList.children.length) addMaster('');
        }

        var revPresetLoaded = false;
        function toggleKind() {
            var rev = q('kind').value === 'reverse';
            ov.querySelector('#fwd-body').style.display = rev ? 'none' : '';
            ov.querySelector('#rev-body').style.display = rev ? '' : 'none';
            checkName(!!nameInput.value);
            if (rev) {
                if (!revPresetLoaded) { revPresetLoaded = true; applyRevPreset(); }
                var c = q('rev-cidr'); if (c) c.focus();
            }
        }
        // Local shape check for the CIDR, so the backend isn't queried on every keystroke. Matches
        // reverse_zones_for_cidr: IPv4 octets 0-255, prefix 8-24; IPv6 prefix 4-64, multiple of 4.
        // The server still validates values and canonicalisation.
        function revShapeGate(s) {
            var m = s.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/);
            if (m) {
                for (var i = 1; i <= 4; i++) { if (+m[i] > 255) return { msg: 'Octets must be 0–255.' }; }
                var p = +m[5];
                if (p < 8 || p > 24) return { msg: 'IPv4 prefix must be between /8 and /24.' };
                return { ok: true };
            }
            var m6 = s.match(/^([0-9a-fA-F:]+)\/(\d{1,3})$/);
            if (m6 && /:/.test(m6[1])) {
                var p6 = +m6[2];
                if (p6 < 4 || p6 > 64 || p6 % 4) return { msg: 'IPv6 prefix must be 4–64, multiple of 4.' };
                return { ok: true };
            }
            return { msg: 'Enter a full network, e.g. 10.20.30.0/24 or 2001:db8::/48.' };
        }
        var revTimer = null;
        function renderRevPlan() {
            var planEl = ov.querySelector('#rev-plan');
            var cidr = (q('rev-cidr').value || '').trim();
            if (!cidr) { planEl.innerHTML = '<span class="text-mute">Enter a network to see which reverse zones will be created.</span>'; return; }
            var gate = revShapeGate(cidr);
            if (!gate.ok) { planEl.innerHTML = '<span class="text-mute">' + esc(gate.msg) + '</span>'; return; }
            planEl.innerHTML = '<span class="text-mute">Checking…</span>';
            window.DNSPanel.api('reverse/preview?cidr=' + encodeURIComponent(cidr), { method: 'GET' })
                .then(function (r) {
                    var d = r.data || r, hasCovered = false;
                    var rows = (d.zones || []).map(function (z) {
                        var badge = z.status === 'exists' ? '<span class="badge muted">Exists</span>'
                                  : z.status === 'covered' ? '<span class="badge kind-rev">Covered</span>'
                                  : '<span class="badge master">Will create</span>';
                        if (z.status === 'covered') hasCovered = true;
                        return '<div class="rev-plan-row"><span class="mono">' + esc(z.name) + '</span>' + badge +
                            (z.covered_by ? '<span class="text-mute" style="font-size:11px;">by ' + esc(z.covered_by) + '</span>' : '') + '</div>';
                    }).join('');
                    var cov = hasCovered
                        ? '<div class="rev-cov" style="margin-top:.7rem;"><div class="text-dim" style="font-size:12px;margin-bottom:.3rem;">Covered zones:</div>' +
                          '<label style="display:block;font-size:13px;margin-bottom:.2rem;"><input type="radio" name="cov" value="use_parent" checked> Use parent zone (PTR stored in the /16)</label>' +
                          '<label style="display:block;font-size:13px;"><input type="radio" name="cov" value="create"> Create separate /24 (with delegation)</label></div>'
                        : '';
                    var sum = '<div class="text-mute" style="font-size:12px;margin-bottom:.5rem;">Will create: ' + d.create + ' · exists: ' + d.exists + ' · covered: ' + d.covered + '</div>';
                    planEl.innerHTML = sum + rows + cov;
                })
                .catch(function (e) { planEl.innerHTML = '<span class="login-error" style="display:inline;">' + esc(e && e.message ? e.message : 'Invalid network') + '</span>'; });
        }
        function onProfileChange() { applyPreset(); }
        function onRevProfileChange() { applyRevPreset(); }
        q('kind').addEventListener('change', toggleKind);
        q('rev-cidr').addEventListener('input', function () { clearTimeout(revTimer); revTimer = setTimeout(renderRevPlan, 300); });
        q('rev-profile').addEventListener('change', onRevProfileChange);
        ov.querySelector('#rev-ns-add').addEventListener('click', function () { addRevNs(''); });

        q('profile').addEventListener('change', onProfileChange);
        q('role').addEventListener('change', function () { toggleRole(); renderCatRow(''); });
        ov.querySelector('#ns-add').addEventListener('click', function () { addNs(''); });
        ov.querySelector('#master-add').addEventListener('click', function () { addMaster(''); });
        window.DNSPanel.upstreamTsigBind(ov, 'az');
        ov.addEventListener('change', function (e) {
            if (e.target && e.target.name === 'zone-dynamic') ov.querySelector('#az-dyn-own').hidden = e.target.value !== 'own';
        });
        // The catalog row is drawn at once, not only when a profile brings a default catalog.
        renderCatRow(''); renderCatRow('rev-');
        q('rev-role').addEventListener('change', toggleRevRole);
        ov.querySelector('#rev-master-add').addEventListener('click', function () { addRevMaster(''); });
        window.DNSPanel.upstreamTsigBind(ov, 'azr');
        formRoot.addEventListener('click', function (e) {
            var d = e.target.closest && e.target.closest('.ns-del, .master-del, .rev-ns-del, .rev-master-del');
            if (d) { var row = d.parentNode; row.parentNode.removeChild(row); return; }
            if (e.target.closest && e.target.closest('.lbl-open')) {
                ov.querySelector('#labels-panel').style.display = 'flex';
                var si = ov.querySelector('#lbl-search'); if (si) si.focus();
                return;
            }
            if (e.target.closest && e.target.closest('#lbl-done')) {
                ov.querySelector('#labels-panel').style.display = 'none'; return;
            }
            // Single-cardinality categories allow one chip at a time.
            var chip = e.target.closest && e.target.closest('.lbl-chip');
            if (chip) {
                var cat = chip.closest('.lbl-cat');
                if (!chip.classList.contains('on') && cat.getAttribute('data-cardinality') === 'single') {
                    cat.querySelectorAll('.lbl-chip.on').forEach(function (c) { c.classList.remove('on'); });
                }
                chip.classList.toggle('on');
                renderSelectedSummary();
            }
        });
        var lblSearch = ov.querySelector('#lbl-search');
        if (lblSearch) lblSearch.addEventListener('input', function () {
            var qv = this.value.trim().toLowerCase();
            ov.querySelectorAll('#labels-panel .lbl-chip').forEach(function (c) {
                c.style.display = (!qv || c.getAttribute('data-name').toLowerCase().indexOf(qv) !== -1) ? '' : 'none';
            });
            ov.querySelectorAll('#labels-panel .lbl-cat').forEach(function (cat) {
                var any = Array.prototype.some.call(cat.querySelectorAll('.lbl-chip'), function (c) { return c.style.display !== 'none'; });
                cat.style.display = any ? '' : 'none';
            });
        });
        ov.querySelector('#zone-cancel').addEventListener('click', closeModal);
        ov.querySelector('#zone-close-x').addEventListener('click', closeModal);

        renderSelectedSummary();
        await applyPreset();
        q('name').focus();

        ov.querySelector('#zone-create-form').addEventListener('submit', async function (e) {
            e.preventDefault();
            if (submitting) return;
            errEl.style.display = 'none';
            var btn = ov.querySelector('#zone-create-btn');

            if (q('kind').value === 'reverse' && q('rev-role').value === 'secondary') {
                // Each zone the network maps to (the same plan as for a primary) is mirrored from the primaries;
                // zones that already exist are left alone.
                var rmasters = Array.prototype.map.call(ov.querySelectorAll('.rev-master-input'), function (i) { return i.value.trim(); }).filter(Boolean);
                if (!rmasters.length) { errEl.textContent = 'Enter at least one primary.'; errEl.style.display = 'block'; return; }
                var rut = window.DNSPanel.upstreamTsigRead(ov, 'azr');
                if (rut.err) { errEl.textContent = rut.err; errEl.style.display = 'block'; return; }
                var rlabels = Array.prototype.map.call(ov.querySelectorAll('.lbl-chip.on'), function (c) { return parseInt(c.getAttribute('data-id'), 10); });
                submitting = true; btn.disabled = true;
                try {
                    var pv = await window.DNSPanel.api('reverse/preview?cidr=' + encodeURIComponent(q('rev-cidr').value.trim()), { method: 'GET' });
                    var names = (((pv.data || pv).zones) || []).filter(function (z) { return z.status !== 'exists'; }).map(function (z) { return z.name; });
                    if (!names.length) throw new Error('All zones of this network already exist');
                    var made = [];
                    for (var ri = 0; ri < names.length; ri++) {
                        var sp = { name: names[ri], role: 'secondary', masters: rmasters, labels: rlabels };
                        if (rut.tsig) sp.tsig = rut.tsig;
                        if (rut.tsig_new && ri === 0) sp.tsig_new = rut.tsig_new;   // created once, then reused by name
                        else if (rut.tsig_new) sp.tsig = rut.tsig_new.name;
                        var sr = await window.DNSPanel.api('zones', { method: 'POST', body: JSON.stringify(sp) });
                        var sid = ((sr.data || {}).zone || {}).id; if (sid) made.push(+sid);
                    }
                    var rsw = CAN_CAT && made.length ? await applyDelivery(made, wantDirect('rev-'), null) : null;
                    closeModal(); await refresh();
                    if (rsw && rsw.failed.length) window.DNSPanel.alert({ message: 'Zones created, but Direct AXFR was not set: ' + rsw.failed.map(function (f) { return f.error || 'failed'; }).join('; ') });
                } catch (err) {
                    errEl.textContent = err && err.message ? err.message : 'Create failed'; errEl.style.display = 'block';
                } finally { submitting = false; btn.disabled = false; }
                return;
            }
            if (q('kind').value === 'reverse') {
                var covEl = ov.querySelector('input[name="cov"]:checked');
                var revPayload = {
                    cidr: q('rev-cidr').value.trim(),
                    profile: q('rev-profile').value,
                    covered_action: covEl ? covEl.value : 'use_parent',
                };
                var revLabels = Array.prototype.map.call(ov.querySelectorAll('.lbl-chip.on'),
                    function (c) { return parseInt(c.getAttribute('data-id'), 10); });
                if (revLabels.length) revPayload.labels = revLabels;
                if (q('rev-dynamic').value) revPayload.dynamic_profile_id = +q('rev-dynamic').value;
                var revSoa = {
                    primary_ns: q('rev-primary_ns').value.trim(),
                    hostmaster: q('rev-hostmaster').value.trim(),
                    ttl: q('rev-ttl').value.trim(),
                    refresh: q('rev-refresh').value.trim(), retry: q('rev-retry').value.trim(),
                    expire: q('rev-expire').value.trim(), minimum: q('rev-minimum').value.trim(),
                };
                if (q('rev-serial').value.trim()) revSoa.serial = q('rev-serial').value.trim();
                revPayload.soa = revSoa;
                revPayload.nameservers = Array.prototype.map.call(ov.querySelectorAll('.rev-ns-input'),
                    function (i) { return i.value.trim(); }).filter(Boolean);
                submitting = true; btn.disabled = true;
                try {
                    var rr = await window.DNSPanel.api('reverse', { method: 'POST', body: JSON.stringify(revPayload) });
                    var rd = rr.data || rr;
                    if (rd && rd.message === 'Nothing to create') { window.DNSPanel.alert('Nothing to create — all zones already exist or are covered.'); return; }
                    var rCatWarn = null;
                    if (CAN_CAT && rd.created && rd.created.length) {
                        var rIds = rd.created.map(function (c) { return c.id; }).filter(Boolean);
                        rCatWarn = await applyDelivery(rIds, wantDirect('rev-'), wantCatalog('rev-'));
                    }
                    closeModal(); await refresh();
                    warnZoneSync(rd && rd.sync);   // covers each created zone and the delegating parents
                    if (rCatWarn && rCatWarn.failed.length) window.DNSPanel.alert({ message: 'Zones created, but distribution assignment failed: ' + rCatWarn.failed.map(function (f) { return f.error || 'failed'; }).join('; ') });
                    else if (rCatWarn && rCatWarn.pending.length) window.DNSPanel.alert({ message: 'Zones created, but delivery is pending: ' + rCatWarn.pending.join('; ') });
                    else if (rCatWarn && rCatWarn.policy_warnings && rCatWarn.policy_warnings.length) window.DNSPanel.alert({ message: 'Zones created, but downstream policy was not applied: ' + rCatWarn.policy_warnings.join('; ') + '. The panel keeps retrying in the background.' });
                    else if ((rd.warnings || []).length) window.DNSPanel.alert({ message: 'Zones created, but ' + rd.warnings.join('; ') + '.' });
                } catch (err) {
                    errEl.textContent = err && err.message ? err.message : 'Create failed'; errEl.style.display = 'block';
                } finally {
                    submitting = false;
                    if (ov.contains(nameInput)) checkName(false);
                }
                return;
            }

            var checkedName = checkName(true);
            if (checkedName.error) { nameInput.reportValidity(); return; }
            var role = q('role').value;
            var payload = { name: checkedName.name, role: role };
            if (role !== 'secondary') payload.profile = q('profile').value;
            var dynOwn = null;
            if (role !== 'secondary' && q('zone-dynamic').value === 'own') {
                dynOwn = window.DNSPanel.dynForm.read(ov, 'azd-');
                if (!dynOwn.cidrs.length && !dynOwn.key) { errEl.textContent = 'Dynamic DHCP: enter the DHCP addresses, a TSIG key, or both'; errEl.style.display = 'block'; return; }
            } else if (role !== 'secondary' && q('zone-dynamic').value) payload.dynamic_profile_id = +q('zone-dynamic').value;
            payload.labels = Array.prototype.map.call(ov.querySelectorAll('.lbl-chip.on'),
                function (c) { return parseInt(c.getAttribute('data-id'), 10); });

            if (role === 'secondary') {
                payload.masters = Array.prototype.map.call(ov.querySelectorAll('.master-input'),
                    function (i) { return i.value.trim(); }).filter(Boolean);
                var ut = window.DNSPanel.upstreamTsigRead(ov, 'az');
                if (ut.err) { errEl.textContent = ut.err; errEl.style.display = 'block'; return; }
                if (ut.tsig) payload.tsig = ut.tsig;
                if (ut.tsig_new) payload.tsig_new = ut.tsig_new;
            } else {
                var soaObj = {
                    primary_ns: q('primary_ns').value.trim(),
                    hostmaster: q('hostmaster').value.trim(),
                    ttl: q('ttl').value.trim(),
                    refresh: q('refresh').value.trim(), retry: q('retry').value.trim(),
                    expire: q('expire').value.trim(), minimum: q('minimum').value.trim(),
                };
                if (q('serial').value.trim()) soaObj.serial = q('serial').value.trim();
                payload.soa = soaObj;
                payload.nameservers = Array.prototype.map.call(ov.querySelectorAll('.ns-input'),
                    function (i) { return i.value.trim(); }).filter(Boolean);
            }

            submitting = true; btn.disabled = true;
            try {
                var res = await window.DNSPanel.api('zones', { method: 'POST', body: JSON.stringify(payload) });
                var rcd = res.data || {};
                // The zone already exists, so a delivery failure is reported as pending, not "Create failed".
                var fNewId = rcd.zone && rcd.zone.id, catWarn = null;
                if (CAN_CAT && fNewId) catWarn = await applyDelivery([+fNewId], wantDirect(''), wantCatalog(''));
                // Own dynamic settings go in with the same request Zone settings uses, once the zone exists.
                if (fNewId && dynOwn) {
                    try { await window.DNSPanel.api('zones/' + fNewId + '/dynamic', { method: 'PUT', body: JSON.stringify({ enabled: true, cidrs: dynOwn.cidrs, key: dynOwn.key }) }); }
                    catch (de) { window.DNSPanel.alert({ message: 'Zone created, but dynamic updates were not set: ' + ((de && de.message) || 'failed') }); }
                }
                var signWarn = null;
                if (fNewId && role !== 'secondary' && q('zone-dnssec').checked) {
                    try { await window.DNSPanel.api('zones/' + fNewId + '/dnssec', { method: 'PUT', body: JSON.stringify({ enabled: true }) }); }
                    catch (se) { signWarn = (se && se.message) || 'failed'; }
                }
                closeModal();
                await refresh();
                warnZoneSync({ zone: payload.name, pdns_state: rcd.pdns_state, notify_state: rcd.notify_state,
                               detail: rcd.pdns_detail, state_error: rcd.state_error });
                if (signWarn) window.DNSPanel.alert({ message: 'Zone created, but not signed: ' + signWarn });
                else                 if (catWarn && catWarn.failed.length) window.DNSPanel.alert({ message: 'Zone created, but distribution assignment failed: ' + catWarn.failed.map(function (f) { return f.error || 'failed'; }).join('; ') });
                else if (catWarn && catWarn.pending.length) window.DNSPanel.alert({ message: 'Zone created, but delivery is pending: ' + catWarn.pending.join('; ') });
                else if (catWarn && catWarn.policy_warnings && catWarn.policy_warnings.length) window.DNSPanel.alert({ message: 'Zone created, but downstream policy was not applied: ' + catWarn.policy_warnings.join('; ') + '. The panel keeps retrying in the background.' });
                else if ((rcd.warnings || []).length) window.DNSPanel.alert({ message: 'Zone created, but ' + rcd.warnings.join('; ') + '.' });
            } catch (err) {
                errEl.textContent = err && err.message ? err.message : 'Create failed';
                errEl.style.display = 'block';
            } finally {
                submitting = false;
                if (ov.contains(nameInput)) checkName(true);
            }
        });
    }

    // -------- Delete zone --------
    function openDeleteModal(meta) {
        var ov = overlay(); if (!ov) return;
        ov.innerHTML =
            '<div class="modal"><form class="modal-card" id="zone-delete-form">' +
            '<h2 class="modal-title">Delete zone</h2>' +
            '<p style="color:var(--text-dim);font-size:13px;margin:.2rem 0 .8rem;">' +
            'Zone <b>' + esc(meta.name) + '</b> will be deleted entirely: all records, metadata and related data. ' +
            'This action cannot be undone.</p>' +
            '<div class="mono" style="font-size:12px;color:var(--text-dim);margin-bottom:.8rem;">' +
            'records: ' + esc(meta.records) +
            '<span id="zone-del-children"></span></div>' +
            '<label class="field-label">Type the zone name to confirm: <b>' + esc(meta.name) + '</b></label>' +
            '<input type="text" name="confirm" class="field-input" placeholder="' + esc(meta.name) + '" autocomplete="off">' +
            '<div class="login-error" id="zone-delete-err" style="display:none;"></div>' +
            '<div class="modal-actions">' +
            '<button type="button" class="btn btn-ghost" id="zone-del-cancel">Cancel</button>' +
            '<button type="submit" class="btn btn-danger" id="zone-del-btn" disabled>Delete zone</button>' +
            '</div></form></div>';
        ov.style.display = 'block';

        var confEl = ov.querySelector('[name="confirm"]');
        var delBtn = ov.querySelector('#zone-del-btn');
        var errEl = ov.querySelector('#zone-delete-err');

        window.DNSPanel.api('zones/' + meta.id + '/subdomains', { method: 'GET' })
            .then(function (r) {
                var kids = (r.data && r.data.delegated_zones) || [];
                if (kids.length) {
                    var el = ov.querySelector('#zone-del-children');
                    if (el) el.textContent = '  ·  delegated child zones: ' +
                        kids.map(function (k) { return k.name; }).join(', ');
                }
            }).catch(function () {});

        confEl.addEventListener('input', function () {
            delBtn.disabled = confEl.value.trim().toLowerCase() !== String(meta.name).toLowerCase();
        });
        ov.querySelector('#zone-del-cancel').addEventListener('click', closeModal);
        confEl.focus();

        ov.querySelector('#zone-delete-form').addEventListener('submit', async function (e) {
            e.preventDefault();
            delBtn.disabled = true;
            try {
                var dres = await window.DNSPanel.api('zones/' + meta.id, {
                    method: 'DELETE', body: JSON.stringify({ confirm_name: confEl.value.trim() }),
                });
                closeModal();
                await refresh();
                var dd = dres.data || {};
                warnZoneSync({ zone: meta.name, pdns_state: dd.pdns_state, state_error: dd.state_error });
            } catch (err) {
                errEl.textContent = err && err.message ? err.message : 'Delete failed';
                errEl.style.display = 'block';
                delBtn.disabled = false;
            }
        });
    }

    // -------- Client-side filters and search --------
    function zoneRows() { return Array.prototype.slice.call(document.querySelectorAll('tr.zone-row')); }
    var FILTERS = ['kind', 'type', 'feat', 'labels', 'sync'];
    function filterVal(name) { var b = document.querySelector('.filter[data-filter="' + name + '"]'); return b ? (b.getAttribute('data-val') || 'all') : 'all'; }
    function cap(s) { return s.charAt(0).toUpperCase() + s.slice(1); }

    function applyZoneFilters() {
        var si = document.getElementById('zone-search');
        var qq = si ? si.value.trim().toLowerCase() : '';
        var ft = filterVal('type'), fl = filterVal('labels'), fk = filterVal('kind'), fsy = filterVal('sync'), ff = filterVal('feat'), shown = 0;
        zoneRows().forEach(function (r) {
            var ok = true;
            if (qq && r.getAttribute('data-name').indexOf(qq) === -1) ok = false;
            if (ok && fsy === 'issue' && r.getAttribute('data-sync') !== 'issue') ok = false;
            if (ok && fk !== 'all') {
                var k = r.getAttribute('data-kind') || 'forward';
                if (fk === 'reverse' ? k.indexOf('reverse') !== 0 : k !== fk) ok = false;
            }
            if (ok && ft !== 'all' && r.getAttribute('data-type') !== ft) ok = false;
            if (ok && ff !== 'all') {
                var fe = (r.getAttribute('data-feat') || '').split(' ');
                if (ff.split('+').some(function (x) { return fe.indexOf(x) === -1; })) ok = false;
            }
            if (ok && fl !== 'all') {
                var l = (r.getAttribute('data-labels') || '').split(',').filter(Boolean);
                if (l.indexOf(fl) === -1) ok = false;
            }
            r.style.display = ok ? '' : 'none';
            if (ok) shown++;
        });
        var sub = document.querySelector('.page-head .sub');
        if (sub) sub.textContent = shown + ' zone(s)';
        updateClearBtn();
    }

    function optsFor(name) {
        if (name === 'kind') return [['all', 'all'], ['forward', 'Forward'], ['reverse', 'Reverse']];
        if (name === 'sync') return [['all', 'all'], ['issue', 'Issues only']];
        if (name === 'feat') return [['dnssec', 'DNSSEC'], ['dynamic', 'Dynamic DHCP']];
        if (name === 'type') {
            var s = {}; zoneRows().forEach(function (r) { s[r.getAttribute('data-type')] = 1; });
            var RL = { master: 'Primary', slave: 'Secondary', native: 'Native' };
            return [['all', 'all']].concat(Object.keys(s).sort().map(function (t) { return [t, RL[t] || t.toUpperCase()]; }));
        }
        var set = {}; zoneRows().forEach(function (r) {
            (r.getAttribute('data-labels') || '').split(',').filter(Boolean).forEach(function (v) { set[v] = 1; });
        });
        return [['all', 'all']].concat(Object.keys(set).sort().map(function (v) { return [v, v]; }));
    }

    // Filters persist in localStorage (survive F5 and coming back from Manage).
    var LS_KEY = 'dnspanel.zoneFilters';
    function currentSearch() { var s = document.getElementById('zone-search'); return s ? s.value : ''; }
    function saveFilters() {
        var st = { q: currentSearch(), f: {} };
        FILTERS.forEach(function (n) {
            var b = document.querySelector('.filter[data-filter="' + n + '"]');
            if (b) st.f[n] = { val: b.getAttribute('data-val') || 'all',
                               label: (b.textContent.split(':')[1] || 'all').replace(/▾/, '').trim() };
        });
        try { localStorage.setItem(LS_KEY, JSON.stringify(st)); } catch (e) {}
    }
    function restoreFilters() {
        var st; try { st = JSON.parse(localStorage.getItem(LS_KEY) || 'null'); } catch (e) {}
        if (!st) return;
        var s = document.getElementById('zone-search'); if (s) s.value = st.q || '';
        FILTERS.forEach(function (n) {
            var b = document.querySelector('.filter[data-filter="' + n + '"]');
            if (b && st.f && st.f[n]) {
                var val = st.f[n].val || 'all';
                // A saved value may no longer exist (e.g. Type: PRODUCER once producer zones were hidden);
                // reset to 'all', otherwise the table is silently empty.
                var valid = optsFor(n).some(function (o) { return o[0] === val; });
                if (!valid) val = 'all';
                b.setAttribute('data-val', val);
                b.textContent = cap(n) + ': ' + (valid ? (st.f[n].label || 'all') : 'all') + ' ▾';
            }
        });
    }
    function toolbarEl() { return document.querySelector('.toolbar:not(.rr-toolbar)'); }
    function anyFilterActive() {
        if (currentSearch().trim()) return true;
        return window.DNSPanel.filtersActive(toolbarEl(), FILTERS);
    }
    function updateClearBtn() {
        var b = document.getElementById('zone-filter-clear');
        if (b) b.style.display = anyFilterActive() ? '' : 'none';
    }
    function clearFilters() {
        var s = document.getElementById('zone-search'); if (s) s.value = '';
        window.DNSPanel.filtersClear(toolbarEl(), FILTERS);
        try { localStorage.removeItem(LS_KEY); } catch (e) {}
        applyZoneFilters();
    }
    function initZoneFilters() {
        if (!document.querySelector('.zones-table')) return;   // not the zones page
        window.DNSPanel.filterInit(toolbarEl(), {
            opts: optsFor, multi: { feat: 1 },
            onChange: function () { applyZoneFilters(); saveFilters(); }
        });
        restoreFilters();
        applyZoneFilters();
    }
    // The table header sticks right under the sticky head, whose height depends on how the filters wrap.
    function zonesHeadHeight() {
        var h = document.querySelector('.zones-head');
        if (h) document.documentElement.style.setProperty('--zones-head-h', h.offsetHeight + 'px');
    }
    window.addEventListener('resize', zonesHeadHeight);
    document.addEventListener('pageLoaded', function (e) {
        if (e.detail && e.detail.page === 'zones') { initZoneFilters(); zonesHeadHeight(); }
    });

    document.addEventListener('click', function (e) {
        var t = e.target;
        if (t.closest && t.closest('#add-zone-btn')) { e.preventDefault(); openCreateModal(); return; }
        var del = t.closest && t.closest('.js-del-zone');
        if (del) {
            e.preventDefault();
            openDeleteModal({
                id: del.getAttribute('data-id'), name: del.getAttribute('data-name'),
                records: del.getAttribute('data-records'),
            });
            return;
        }
        if (t.closest && t.closest('#zone-filter-clear')) { e.preventDefault(); clearFilters(); return; }
    });
    document.addEventListener('input', function (e) {
        if (e.target && e.target.id === 'zone-search') { applyZoneFilters(); saveFilters(); }
    });
    document.addEventListener('keydown', function (e) {
        if (e.key !== 'Escape') return;
        var ov = overlay();
        if (ov && ov.style.display === 'block') { e.preventDefault(); closeModal(); }
    });
})();
