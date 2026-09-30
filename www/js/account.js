/* DNS Panel — Account: own password, authenticator app, sessions and appearance.
 *
 * The server renders the page fully populated (2FA state, sessions, current settings); this script
 * only performs actions and patches exactly what changed, it never re-renders.
 */
(function () {
    'use strict';

    function esc(s) {
        return String(s == null ? '' : s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }
    function api(path, opts) { return window.DNSPanel.api(path, opts); }
    // The themed select keeps its value in a hidden input with this name.
    function prefValue(name) { var el = document.querySelector('[name="' + name + '"]'); return el ? el.value : ''; }
    function show(el, msg) { if (!el) return; el.textContent = msg; el.hidden = !msg; }

    // The server prints times in UTC (and labels them so); convert to the chosen zone here, since the
    // browser knows about DST and the current date.
    function applyTimeZone(tz) {
        [].slice.call(document.querySelectorAll('#acct-sessions .ts')).forEach(function (td) {
            var ts = parseInt(td.getAttribute('data-ts'), 10);
            if (ts) td.textContent = window.DNSPanel.fmtTime(ts, { tz: tz || '' });
        });
    }

    // Recovery codes are shown only once, so show them as plain text that can be selected in one go.
    function showCodes(codes, title) {
        var html = '<div class="acct-codes">' + codes.map(function (c) { return esc(c); }).join('<br>') + '</div>'
                 + '<div class="zform-note">Each code works once. Keep them somewhere safe — '
                 + 'they are the only way in if you lose the app. They are shown once.</div>';
        return window.DNSPanel.alert({ title: title || 'Recovery codes', message: html });
    }

    function bindPassword() {
        var form = document.getElementById('acct-pw-form');
        if (!form) return;
        form.addEventListener('submit', async function (e) {
            e.preventDefault();
            var err = document.getElementById('pw-err');
            var cur = document.getElementById('pw-cur').value;
            var nw  = document.getElementById('pw-new').value;
            var nw2 = document.getElementById('pw-new2').value;
            show(err, '');
            if (nw !== nw2) { show(err, 'The two new passwords do not match.'); return; }
            if (nw.length < 8) { show(err, 'The new password must be at least 8 characters.'); return; }
            var btn = form.querySelector('button[type="submit"]');
            btn.disabled = true;
            try {
                await api('account/password', { method: 'POST',
                    body: JSON.stringify({ current_password: cur, new_password: nw }) });
            } catch (ex) {
                show(err, (ex && ex.message) || 'Could not change the password'); btn.disabled = false; return;
            }
            btn.disabled = false;
            form.reset();
            window.DNSPanel.alert({ title: 'Password changed',
                message: 'Your other sessions have been signed out. This one stays.' });
        });
    }

    // Enrolling and replacing the app are the same flow (show QR, ask for a code); on replace the old
    // app keeps working until the new code is confirmed.
    function bindTotp() {
        var btn = document.getElementById('totp-setup');
        if (!btn) return;
        btn.addEventListener('click', async function () {
            btn.disabled = true;
            var d;
            try { d = (await api('account/totp/begin', { method: 'POST' })).data || {}; }
            catch (ex) {
                btn.disabled = false;
                window.DNSPanel.alert({ title: 'Could not start', message: (ex && ex.message) || 'Failed' });
                return;
            }
            btn.disabled = false;
            var ov = document.getElementById('modal-overlay');
            if (!ov) return;
            ov.innerHTML =
                '<div class="modal"><form class="modal-card" id="totp-form">' +
                '<h2 class="modal-title">Authenticator app</h2>' +
                '<p class="zform-note">Scan this with your authenticator app, then type the six-digit code it shows. ' +
                'Your previous app keeps working until you do.</p>' +
                (d.qr_png_base64 ? '<div class="acct-qr"><img alt="QR code" src="data:image/png;base64,' + esc(d.qr_png_base64) + '"></div>' : '') +
                '<label class="field-label">Or type the key by hand</label>' +
                '<div class="acct-secret">' + esc(d.secret || '') + '</div>' +
                '<label class="field-label" for="totp-code">Code from the app</label>' +
                '<input class="field-input" id="totp-code" inputmode="numeric" autocomplete="one-time-code" placeholder="000000">' +
                '<div class="login-error" id="totp-err" hidden></div>' +
                '<div class="modal-actions"><button type="button" class="btn btn-ghost" id="totp-cancel">Cancel</button>' +
                '<button type="submit" class="btn btn-primary">Confirm</button></div></form></div>';
            ov.style.display = 'block';
            var code = document.getElementById('totp-code');
            code.focus();
            document.getElementById('totp-cancel').addEventListener('click', async function () {
                ov.style.display = 'none'; ov.innerHTML = '';
                try { await api('account/totp/pending', { method: 'DELETE' }); } catch (ex) { /* already abandoned */ }
            });
            document.getElementById('totp-form').addEventListener('submit', async function (ev) {
                ev.preventDefault();
                var err = document.getElementById('totp-err');
                show(err, '');
                var r;
                try { r = (await api('account/totp/confirm', { method: 'POST',
                                     body: JSON.stringify({ code: code.value }) })).data || {}; }
                catch (ex) { show(err, (ex && ex.message) || 'Could not confirm'); return; }
                ov.style.display = 'none'; ov.innerHTML = '';
                await showCodes(r.recovery_codes || [], 'Authenticator app is set up');
                window.DNSPanel.reload();     // 2FA state is server-rendered
            });
        });
    }

    function bindRecovery() {
        var btn = document.getElementById('codes-new');
        if (!btn) return;
        btn.addEventListener('click', async function () {
            var code = await window.DNSPanel.prompt({
                title: 'New recovery codes',
                message: 'The current codes stop working. Type the code from your authenticator app to confirm.',
                placeholder: '000000', okText: 'Generate',
            });
            if (code == null) return;
            var r;
            try { r = (await api('account/recovery-codes', { method: 'POST',
                                 body: JSON.stringify({ code: code }) })).data || {}; }
            catch (ex) {
                window.DNSPanel.alert({ title: 'Not generated', message: (ex && ex.message) || 'Failed' });
                return;
            }
            await showCodes(r.recovery_codes || []);
            window.DNSPanel.reload();
        });
    }

    // Disabling 2FA asks for an app code, as does regenerating recovery codes: an unattended screen
    // must not be enough to turn protection off.
    function bindTotpOff() {
        var btn = document.getElementById('totp-off');
        if (!btn) return;
        btn.addEventListener('click', async function () {
            var code = await window.DNSPanel.prompt({
                title: 'Turn off two-factor',
                message: 'Signing in will ask for your password only. Your recovery codes stop working too. '
                       + 'Type the code from your authenticator app to confirm.',
                placeholder: '000000', okText: 'Turn off',
            });
            if (code == null) return;
            try { await api('account/totp', { method: 'DELETE', body: JSON.stringify({ code: code }) }); }
            catch (ex) {
                window.DNSPanel.alert({ title: 'Not turned off', message: (ex && ex.message) || 'Failed' });
                return;
            }
            window.DNSPanel.reload();   // 2FA state is server-rendered
        });
    }

    function bindPrefs() {
        var form = document.getElementById('acct-prefs-form');
        if (!form) return;
        form.addEventListener('submit', async function (e) {
            e.preventDefault();
            var err = document.getElementById('prefs-err');
            show(err, '');
            // The themed select keeps its value in a hidden input.
            var theme = prefValue('pref-theme');
            var tz    = prefValue('pref-tz');
            var df    = prefValue('pref-df');
            try {
                await api('account/preferences', { method: 'PUT',
                    body: JSON.stringify({ theme: theme, timezone: tz, date_format: df }) });
            } catch (ex) { show(err, (ex && ex.message) || 'Could not save'); return; }
            // The theme is applied server-side, so reload to get the new theme without a flash of the old
            // one. Table times are converted immediately, no reload needed for them.
            applyTimeZone(tz);
            window.DNSPanel.reload();
        });
    }

    function bindSessions() {
        var body = document.getElementById('acct-sessions-body');
        if (body) body.addEventListener('click', async function (e) {
            var b = e.target.closest && e.target.closest('.sess-kill');
            if (!b) return;
            var id = b.getAttribute('data-id');
            b.disabled = true;
            try { await api('account/sessions/' + id, { method: 'DELETE' }); }
            catch (ex) {
                b.disabled = false;
                window.DNSPanel.alert({ title: 'Not signed out', message: (ex && ex.message) || 'Failed' });
                return;
            }
            var tr = b.closest('tr');
            if (tr && tr.parentNode) tr.parentNode.removeChild(tr);   // remove just this row, no re-render
            if (body && !body.querySelector('tr')) {
                body.innerHTML = '<tr><td colspan="5" class="text-dim">No active sessions.</td></tr>';
            }
        });
        var others = document.getElementById('sess-others');
        if (others) others.addEventListener('click', async function () {
            if (!(await window.DNSPanel.confirm({
                    title: 'Sign out other sessions',
                    message: 'Every other browser and device signed in as you will be signed out. This session stays.',
                    okText: 'Sign out others' }))) return;
            others.disabled = true;
            var r;
            try { r = (await api('account/sessions', { method: 'DELETE' })).data || {}; }
            catch (ex) {
                others.disabled = false;
                window.DNSPanel.alert({ title: 'Not signed out', message: (ex && ex.message) || 'Failed' });
                return;
            }
            others.disabled = false;
            [].slice.call(document.querySelectorAll('#acct-sessions-body .sess-kill')).forEach(function (b) {
                var tr = b.closest('tr'); if (tr && tr.parentNode) tr.parentNode.removeChild(tr);
            });
            window.DNSPanel.alert({ title: 'Done', message: 'Closed ' + (r.closed || 0) + ' other session(s).' });
        });
    }

    document.addEventListener('pageLoaded', function (e) {
        if (e.detail.page !== 'account') return;
        applyTimeZone(prefValue('pref-tz'));
        bindPassword();
        bindTotp();
        bindTotpOff();
        bindRecovery();
        bindPrefs();
        bindSessions();
    });
})();
