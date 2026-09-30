/* DNS Panel — core bootstrap, loaded on every page (defer). */

(function () {
    'use strict';

    window.DNSPanel = window.DNSPanel || {};

    // Busy cursor for the whole site, so a click never looks ignored. Any change (a non-GET request) turns it
    // on; a GET started while a change is in flight belongs to it (the reload after saving), so the cursor
    // holds until the new data is there. Background polls started in a quiet moment do not touch it. The
    // flag drops one task after the last response body is read: the caller's own continuation (typically the
    // reload) runs before that and joins in.
    var busyN = 0, held = false, rawFetch = window.fetch.bind(window);
    function busy(d) {
        busyN += d;
        document.documentElement.classList.toggle('is-busy', busyN > 0);
    }
    window.fetch = function (input, init) {
        var method = ((init && init.method) || (input && input.method) || 'GET').toUpperCase();
        if (method === 'GET' && busyN === 0) return rawFetch(input, init);
        busy(1);
        var p = rawFetch(input, init);
        var done = function () { setTimeout(function () { busy(-1); }, 0); };
        p.then(function (r) { return r.clone().text(); }).then(done, done);
        return p;
    };
    // After an action a page is not reloaded whole. The server renders it again (it stays the one renderer),
    // and only what differs replaces the live elements; filters, selection, open blocks and half-typed inputs
    // elsewhere stay. spec:
    //   url    the page's /ajax/... address
    //   lists  [{ sel, item, key, by: 'attrs'|'html', keep }]: keyed items inside a container, compared by
    //          their attributes (when cells were changed in place, e.g. times localized) or by their HTML;
    //          keep = a checkbox whose state survives replacement
    //   parts  selectors replaced whole when they differ; after: { sel: anchor } for parts that may appear
    //   same   (fresh) -> false when the fresh page has another shape (then the caller reloads whole)
    // Returns the changed elements, or null when the caller should reload the page whole.
    window.DNSPanel.patchPage = async function (spec) {
        var main = document.getElementById('main-content');
        if (!main) return null;
        var res = await fetch(spec.url, { credentials: 'same-origin' });
        if (res.status === 401 || res.redirected) { window.location.href = '/login'; return []; }
        if (!res.ok) throw new Error('HTTP ' + res.status);
        var tpl = document.createElement('template');
        tpl.innerHTML = await res.text();
        var fresh = tpl.content, changed = [];
        // Times in the fresh HTML are formatted like the live ones, or every patch would see a change.
        if (window.DNSPanel.localizeTimes) window.DNSPanel.localizeTimes(fresh);
        if (spec.same && !spec.same(fresh)) return null;
        for (var i = 0; i < (spec.lists || []).length; i++) {
            var L = spec.lists[i], box = main.querySelector(L.sel), fbox = fresh.querySelector(L.sel);
            if (!box || !fbox) return null;
            patchList(box, fbox, L, changed);
        }
        (spec.parts || []).forEach(function (sel) {
            var live = main.querySelector(sel), nw = fresh.querySelector(sel);
            if (live && nw) { if (live.outerHTML !== nw.outerHTML) { live.replaceWith(nw); changed.push(nw); } }
            else if (live) live.remove();
            else if (nw && spec.after && spec.after[sel]) {
                var at = main.querySelector(spec.after[sel]);
                if (at) { at.after(nw); changed.push(nw); }
            }
        });
        return changed;
    };
    // style/hidden on the item itself are how filters hide it, not data.
    function sigOf(el, by) {
        var c = el.cloneNode(by === 'html');
        c.removeAttribute('style'); c.removeAttribute('hidden');
        if (by === 'html') return c.outerHTML;
        return Array.prototype.map.call(c.attributes, function (a) { return a.name + '=' + a.value; }).sort().join('\n');
    }
    function patchList(box, fbox, L, changed) {
        var live = {}, seen = {};
        Array.prototype.forEach.call(box.querySelectorAll(L.item), function (el) { live[el.getAttribute(L.key)] = el; });
        var prev = null;
        Array.prototype.forEach.call(fbox.querySelectorAll(L.item), function (nw) {
            var k = nw.getAttribute(L.key), old = live[k]; seen[k] = 1;
            if (old && sigOf(old, L.by) === sigOf(nw, L.by)) { prev = old; return; }
            if (old) {
                var cb = L.keep && old.querySelector(L.keep), was = cb && cb.checked;
                old.replaceWith(nw);
                var ncb = was && nw.querySelector(L.keep); if (ncb) ncb.checked = true;
            } else if (prev) prev.after(nw);
            else box.insertBefore(nw, box.firstChild);
            changed.push(nw); prev = nw;
        });
        Object.keys(live).forEach(function (k) { if (!seen[k]) live[k].remove(); });
        // Unkeyed children ("No records yet" and the like) follow the fresh page.
        var rest = function (b) { return Array.prototype.filter.call(b.children, function (c) { return !c.matches(L.item); }); };
        var lr = rest(box), fr = rest(fbox);
        if (lr.map(function (e) { return e.outerHTML; }).join('') !== fr.map(function (e) { return e.outerHTML; }).join('')) {
            lr.forEach(function (e) { e.remove(); });
            fr.forEach(function (e) { box.appendChild(e); changed.push(e); });
        }
    }

    // Upstream TSIG of a secondary zone: the key it signs its transfer from the primary with. One control
    // wherever a secondary's source is set (Add zone, Zone settings, Make secondary): None, a key already in
    // PowerDNS, or "+ Add key…" (name, algorithm, secret; a pasted BIND key block fills all three). The zone
    // stores only the key's name, so one key serves every zone that uses it.
    var UP_ALGOS = ['hmac-sha256', 'hmac-sha512', 'hmac-sha384', 'hmac-sha224', 'hmac-sha1', 'hmac-md5'];
    window.DNSPanel.upstreamKeys = function () {
        return window.DNSPanel.api('zones/upstream-keys').then(function (r) { return ((r && r.data) || {}).keys || []; },
                                                               function () { return []; });
    };
    window.DNSPanel.upstreamTsigHtml = function (p, current, keys) {
        var names = (keys || []).map(function (k) { return k.name; });
        var opts = [{ value: '', label: 'None' }]
            .concat((keys || []).map(function (k) { return { value: 'k:' + k.name, label: k.name + ' (' + k.algorithm + ')' }; }))
            .concat(current && names.indexOf(current) < 0 ? [{ value: 'k:' + current, label: current + ' (not in PowerDNS)' }] : [])
            .concat([{ value: 'new', label: '+ Add key…' }]);
        return window.DNSPanel.selectHtml(p + '-tsig', opts, current ? 'k:' + current : '')
            + '<div class="up-tsig-new" id="' + p + '-tsig-new" hidden>'
            + '<input class="field-input mono" id="' + p + '-tsig-name" placeholder="key name" autocomplete="off">'
            + window.DNSPanel.selectHtml(p + '-tsig-algo', UP_ALGOS.map(function (a) { return { value: a, label: a }; }), 'hmac-sha256')
            + '<input class="field-input mono" id="' + p + '-tsig-secret" placeholder="secret (base64), or paste the BIND key block" autocomplete="off">'
            + '</div>';
    };
    window.DNSPanel.upstreamTsigBind = function (root, p) {
        var sel = root.querySelector('[name="' + p + '-tsig"]'), box = root.querySelector('#' + p + '-tsig-new');
        if (!sel || !box) return;
        sel.addEventListener('change', function () { box.hidden = sel.value !== 'new'; });
        var sec = root.querySelector('#' + p + '-tsig-secret');
        sec.addEventListener('input', function () {   // a pasted BIND key block fills name and algorithm too
            var t = sec.value;
            if (!/secret\s+"/i.test(t)) return;
            var n = (t.match(/key\s+"?([^"\s{]+)"?/i) || [])[1], a = (t.match(/algorithm\s+"?([a-z0-9-]+)"?/i) || [])[1];
            var s = (t.match(/secret\s+"([^"]+)"/i) || [])[1];
            if (n) root.querySelector('#' + p + '-tsig-name').value = n;
            if (a && UP_ALGOS.indexOf(a.toLowerCase()) >= 0) window.DNSPanel.setSelect(p + '-tsig-algo', a.toLowerCase());
            if (s) sec.value = s;
        });
    };
    // -> { tsig: '' | name } | { tsig_new: { name, algorithm, secret } } | { err }
    window.DNSPanel.upstreamTsigRead = function (root, p) {
        var v = (root.querySelector('[name="' + p + '-tsig"]') || {}).value || '';
        if (v !== 'new') return { tsig: v.indexOf('k:') === 0 ? v.slice(2) : '' };
        var name = (root.querySelector('#' + p + '-tsig-name').value || '').trim();
        var secret = (root.querySelector('#' + p + '-tsig-secret').value || '').trim();
        if (!name || !secret) return { err: 'Enter the key name and its secret, or choose an existing key' };
        return { tsig_new: { name: name, algorithm: (root.querySelector('[name="' + p + '-tsig-algo"]') || {}).value || 'hmac-sha256', secret: secret } };
    };

    // For waits that are not a request (an HA operation followed by polling): hold the cursor explicitly.
    window.DNSPanel.busyHold = function (on) {
        if (!!on === held) return;
        held = !!on;
        busy(held ? 1 : -1);
    };

    // Double-submit CSRF: csrf_token is a non-HttpOnly cookie set by index.pl/login.pl.
    function csrfToken() {
        var m = document.cookie.match(/(?:^|;\s*)csrf_token=([^;]+)/);
        return m ? decodeURIComponent(m[1]) : '';
    }

    // JSON API wrapper. The prefix is /dns-api/, not /api/: /api on this host belongs to Starman (app.psgi).
    window.DNSPanel.api = async function (path, options) {
        options = options || {};
        var method = (options.method || 'GET').toUpperCase();
        var headers = { 'Content-Type': 'application/json' };
        // Only mutating methods carry the token; the server checks cookie == header.
        if (['POST', 'PUT', 'PATCH', 'DELETE'].indexOf(method) >= 0) headers['X-CSRF-Token'] = csrfToken();
        const res = await fetch('/dns-api/' + path.replace(/^\//, ''), {
            headers: headers,
            credentials: 'same-origin',
            ...options,
        });
        // 401 means the session is over, not that the page failed: redirect to login exactly once (several
        // polls may hit it at the same time) and return here afterwards.
        if (res.status === 401) {
            if (!window.DNSPanel.__authRedirect) {
                window.DNSPanel.__authRedirect = true;
                const back = window.location.pathname + window.location.search;
                window.location.replace('/login?return=' + encodeURIComponent(back));
            }
            // Never settle: the page is already leaving, and any error handling would briefly flash a
            // failure that isn't real.
            return new Promise(function () { });
        }
        const text = await res.text();
        let data;
        try { data = text ? JSON.parse(text) : {}; } catch (e) { data = { raw: text }; }
        if (!res.ok) {
            const err = new Error(data && data.error ? data.error : ('HTTP ' + res.status));
            err.status = res.status;
            err.data = data;
            throw err;
        }
        return data;
    };

    // Confirmation before zones stop being served. Only removals ask, and they name the servers that will
    // lose the zone. Recipients come from the same GET /zones/:id/distribution the screen renders, so the
    // two can't disagree.
    function escHtml(t) {
        return String(t == null ? '' : t).replace(/[&<>"]/g, function (c) {
            return ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c];
        });
    }
    async function recipientsOf(domainId) {
        try {
            var r = await window.DNSPanel.api('zones/' + domainId + '/distribution');
            return ((r && r.data && r.data.recipients) || []).map(function (x) { return x.name; });
        } catch (e) { return null; }
    }
    // domainIds: zones that stop being served this way. Resolves to bool.
    window.DNSPanel.confirmStopServing = async function (domainIds, what) {
        var ids = (domainIds || []).map(Number).filter(Boolean);
        if (!ids.length) return true;
        // All zones in parallel: a sequential round-trip per zone meant seconds of silence before the dialog.
        var got = await Promise.all(ids.map(recipientsOf));
        var names = {}, unknown = 0;
        for (var i = 0; i < got.length; i++) {
            if (got[i] === null) { unknown++; continue; }
            for (var j = 0; j < got[i].length; j++) names[got[i][j]] = 1;
        }
        var list = Object.keys(names);
        var msg = '<div>' + ids.length + ' zone(s) will stop being served ' + escHtml(what || 'this way') + '.</div>';
        if (list.length) msg += '<div style="margin-top:.4rem;">These servers get it right now: <b>' + escHtml(list.join(', ')) + '</b></div>';
        else if (!unknown) msg += '<div style="margin-top:.4rem;">No server is receiving it right now.</div>';
        if (unknown) msg += '<div style="margin-top:.4rem;">The panel could not check ' + unknown + ' zone(s) — consequences unverified.</div>';
        return await window.DNSPanel.confirm({
            title: list.length ? 'Some servers will lose this zone' : 'Stop serving?',
            message: msg, okText: 'Apply' });
    };

    // Themed select used site-wide. The value lives in a hidden input[name] (read .value, listen for 'change').
    // The menu is position:fixed at the trigger, so tables/modals with overflow:hidden don't clip it.
    function esc(s) {
        return String(s == null ? '' : s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }
    window.DNSPanel.selectHtml = function (name, opts, value) {
        var cur = null, i;
        for (i = 0; i < opts.length; i++) { if (opts[i].value === value) { cur = opts[i]; break; } }
        if (!cur) cur = opts[0] || { value: '', label: '' };
        var menu = opts.map(function (o) {
            return '<div class="ui-select-opt' + (o.value === cur.value ? ' sel' : '') +
                '" data-val="' + esc(o.value) + '">' + esc(o.label) + '</div>';
        }).join('');
        return '<div class="ui-select" data-name="' + esc(name) + '">' +
            '<input type="hidden" name="' + esc(name) + '" value="' + esc(cur.value) + '">' +
            '<div class="ui-select-trigger"><span class="ui-select-label">' + esc(cur.label) + '</span>' +
            '<span class="chev"></span></div>' +
            '<div class="ui-select-menu">' + menu + '</div></div>';
    };
    // Shared form actions, so every page has the same buttons in the same order: Cancel, then Save.
    // opts: { save, cancel } button text; { act } data-act prefix (act-save / act-cancel); { danger }.
    window.DNSPanel.formActionsHtml = function (opts) {
        opts = opts || {};
        var act = opts.act || 'form';
        var attrs = opts.attrs || '';
        return '<div class="form-actions">'
            + '<button type="button" class="btn btn-ghost" data-act="' + esc(act) + '-cancel"' + attrs + '>'
            + esc(opts.cancel || 'Cancel') + '</button>'
            + '<button type="button" class="btn ' + (opts.danger ? 'btn-danger' : 'btn-primary')
            + '" data-act="' + esc(act) + '-save"' + attrs + '>' + esc(opts.save || 'Save') + '</button>'
            + '</div>';
    };
    // Sets a themed select by data-val (hidden input, label, .sel, 'change'). False if there is no such option.
    window.DNSPanel.setSelect = function (name, value) {
        var v = value == null ? '' : String(value);
        var sel = document.querySelector('.ui-select[data-name="' + name + '"]'); if (!sel) return false;
        var opts = sel.querySelectorAll('.ui-select-opt'), match = null, i;
        for (i = 0; i < opts.length; i++) { if (opts[i].getAttribute('data-val') === v) { match = opts[i]; break; } }
        if (!match) return false;
        sel.querySelectorAll('.ui-select-opt.sel').forEach(function (o) { o.classList.remove('sel'); });
        match.classList.add('sel');
        sel.querySelector('.ui-select-label').textContent = match.textContent;
        var inp = sel.querySelector('input[type="hidden"]');
        if (inp && inp.value !== v) { inp.value = v; inp.dispatchEvent(new Event('change', { bubbles: true })); }
        return true;
    };
    function positionSelectMenu(sel) {
        var menu = sel.querySelector('.ui-select-menu'); if (!menu) return;
        var r = sel.getBoundingClientRect();
        var vw = window.innerWidth, vh = window.innerHeight;
        menu.style.position = 'fixed';
        menu.style.right = 'auto';                      // otherwise CSS right:0 stretches the menu
        menu.style.width = r.width + 'px';
        menu.style.zIndex = '10001';                    // above #modal-overlay (9990)
        // Open upward if it doesn't fit below (max-height ~240px).
        var menuH = Math.min(menu.scrollHeight, 240);
        var left = Math.max(8, Math.min(r.left, vw - r.width - 8));
        var top = r.bottom + 4;
        if (top + menuH > vh - 8 && r.top - menuH - 4 > 8) top = r.top - menuH - 4;
        menu.style.left = left + 'px';
        menu.style.top = top + 'px';
    }
    // Closing only removes .open: writing position from scroll handlers triggers Firefox's
    // "scroll-linked positioning" warning. positionSelectMenu sets the inline styles on open.
    function closeSelects(except) {
        document.querySelectorAll('.ui-select.open').forEach(function (s) {
            if (s !== except) s.classList.remove('open');
        });
    }
    document.addEventListener('click', function (e) {
        var opt = e.target.closest && e.target.closest('.ui-select-opt');
        if (opt) {
            var sel = opt.closest('.ui-select');
            sel.querySelectorAll('.ui-select-opt.sel').forEach(function (o) { o.classList.remove('sel'); });
            opt.classList.add('sel');
            sel.querySelector('.ui-select-label').textContent = opt.textContent;
            var inp = sel.querySelector('input[type="hidden"]');
            if (inp && inp.value !== opt.getAttribute('data-val')) {
                inp.value = opt.getAttribute('data-val');
                inp.dispatchEvent(new Event('change', { bubbles: true }));
            }
            closeSelects();
            return;
        }
        var trg = e.target.closest && e.target.closest('.ui-select-trigger');
        var sel2 = trg ? trg.closest('.ui-select') : null;
        if (sel2) {
            var willOpen = !sel2.classList.contains('open');
            closeSelects(willOpen ? sel2 : null);
            if (willOpen) { sel2.classList.add('open'); positionSelectMenu(sel2); }
            else { closeSelects(); }
            return;
        }
        // A menu may hold a small form (e.g. the audit date range): clicks inside it keep it open.
        if (e.target.closest && e.target.closest('.ui-select-menu')) return;
        closeSelects();
    });
    // Scrolling closes the menu (a fixed menu would lag behind), except scrolling inside the menu itself.
    window.addEventListener('scroll', function (e) {
        var t = e.target;
        if (t && t.nodeType === 1 && t.closest && t.closest('.ui-select-menu')) return;
        closeSelects();
    }, true);
    window.addEventListener('resize', function () { closeSelects(); });
    document.addEventListener('keydown', function (e) { if (e.key === 'Escape') closeSelects(); });

    // Each dialog gets its own layer on top, so e.g. an input-error alert doesn't wipe the form beneath it.
    function dlgLayer() {
        var el = document.createElement('div');
        el.className = 'dlg-layer';
        document.body.appendChild(el);
        return el;
    }

    // Themed confirm/alert instead of window.confirm/alert.
    // DNSPanel.confirm(opts) -> Promise<bool>; DNSPanel.alert(msg|opts) -> Promise (OK only).
    // opts: { title, message (trusted HTML), okText, cancelText, danger, cancel:false }.
    window.DNSPanel.confirm = function (opts) {
        opts = opts || {};
        var withCancel = opts.cancel !== false;
        return new Promise(function (resolve) {
            var ov = dlgLayer();
            var okCls = opts.danger ? 'btn btn-danger' : 'btn btn-primary';
            ov.innerHTML = '<div class="modal"><div class="modal-card dlg-card">' +
                '<div class="modal-head"><h2 class="modal-title">' + esc(opts.title || (withCancel ? 'Confirm' : 'Notice')) + '</h2>' +
                '<button type="button" class="modal-x" data-dlg="cancel" aria-label="Close">×</button></div>' +
                '<div class="dlg-body">' + (opts.message || '') + '</div>' +
                '<div class="modal-actions">' +
                (withCancel ? '<button type="button" class="btn btn-ghost" data-dlg="cancel">' + esc(opts.cancelText || 'Cancel') + '</button>' : '') +
                '<button type="button" class="' + okCls + '" data-dlg="ok">' + esc(opts.okText || 'OK') + '</button>' +
                '</div></div></div>';
            ov.style.display = 'block';
            function cleanup() { ov.removeEventListener('click', onClick); document.removeEventListener('keydown', onKey, true); ov.remove(); }
            function done(v) { cleanup(); resolve(v); }
            function onClick(e) { var b = e.target.closest && e.target.closest('[data-dlg]'); if (b) done(b.getAttribute('data-dlg') === 'ok'); }
            function onKey(e) { if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); done(!withCancel ? true : false); } else if (e.key === 'Enter') { e.preventDefault(); done(true); } }
            ov.addEventListener('click', onClick);
            document.addEventListener('keydown', onKey, true);
            var okb = ov.querySelector('[data-dlg="ok"]'); if (okb) okb.focus();
        });
    };
    // DNSPanel.dialog(opts) -> Promise<null | values>: the themed dialog with form fields inside.
    // Values are collected before the markup is removed.
    // opts: { title, message (trusted HTML), okText, cancelText, danger, wide, size }.
    // wide: for picking from a long list; size:'xl': for two lists side by side (e.g. Pulse checks | agents).
    window.DNSPanel.dialog = function (opts) {
        opts = opts || {};
        return new Promise(function (resolve) {
            var ov = dlgLayer();
            var okCls = opts.danger ? 'btn btn-danger' : 'btn btn-primary';
            var sz = (opts.size === 'xl') ? ' dlg-wide dlg-xl' : (opts.wide ? ' dlg-wide' : '');
            ov.innerHTML = '<div class="modal"><div class="modal-card dlg-card' + sz + '">' +
                '<div class="modal-head"><h2 class="modal-title">' + esc(opts.title || 'Confirm') + '</h2>' +
                '<button type="button" class="modal-x" data-dlg="cancel" aria-label="Close">×</button></div>' +
                '<div class="dlg-body">' + (opts.message || '') + '</div>' +
                '<div class="modal-actions">' +
                '<button type="button" class="btn btn-ghost" data-dlg="cancel">' + esc(opts.cancelText || 'Cancel') + '</button>' +
                '<button type="button" class="' + okCls + '" data-dlg="ok">' + esc(opts.okText || 'OK') + '</button>' +
                '</div></div></div>';
            ov.style.display = 'block';
            function collect() {
                var out = {};
                ov.querySelectorAll('[name]').forEach(function (el) {
                    if (el.type === 'radio') { if (el.checked) out[el.name] = el.value; }
                    else if (el.type === 'checkbox') { out[el.name] = !!el.checked; }
                    else { out[el.name] = el.value; }
                });
                return out;
            }
            function cleanup() { ov.removeEventListener('click', onClick); document.removeEventListener('keydown', onKey, true); ov.remove(); }
            function done(v) { var vals = v ? collect() : null; cleanup(); resolve(vals); }
            function onClick(e) { var b = e.target.closest && e.target.closest('[data-dlg]'); if (b) done(b.getAttribute('data-dlg') === 'ok'); }
            function onKey(e) { if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); done(false); } }
            ov.addEventListener('click', onClick);
            document.addEventListener('keydown', onKey, true);
            var okb = ov.querySelector('[data-dlg="ok"]'); if (okb) okb.focus();
        });
    };
    // Custom tooltip (data-tip) instead of the native title, which ignores the theme. One floating node
    // lives in body: .table-wrap has overflow:hidden and would clip a tooltip placed inside a cell.
    var tipEl = null, tipFor = null, tipTimer = null;
    function tipNode() {
        if (!tipEl) {
            tipEl = document.createElement('div');
            tipEl.className = 'ui-tip';
            tipEl.setAttribute('role', 'tooltip');
            tipEl.hidden = true;
            document.body.appendChild(tipEl);
        }
        return tipEl;
    }
    function tipHide() {
        clearTimeout(tipTimer);
        if (tipEl) { tipEl.hidden = true; tipEl.classList.remove('below'); }
        tipFor = null;
    }
    // While a modal is open, only its own elements show tooltips; otherwise one could linger over it.
    function tipBlocked(el) {
        var ov = document.getElementById('modal-overlay');
        if (!ov || ov.style.display === 'none' || !ov.firstChild) return false;
        return !ov.contains(el);
    }
    function tipShow(el) {
        var text = el.getAttribute('data-tip');
        if (!text || tipBlocked(el)) return;
        var n = tipNode();
        n.textContent = text;
        n.hidden = false;
        tipFor = el;
        var r = el.getBoundingClientRect(), t = n.getBoundingClientRect();
        var left = r.left + r.width / 2 - t.width / 2;
        left = Math.max(6, Math.min(left, window.innerWidth - t.width - 6));   // keep on screen
        var top = r.top - t.height - 8;
        if (top < 6) { top = r.bottom + 8; n.classList.add('below'); }         // no room above: show below
        else n.classList.remove('below');
        n.style.left = Math.round(left) + 'px';
        n.style.top  = Math.round(top) + 'px';
    }
    function tipTarget(e) { return e.target && e.target.closest ? e.target.closest('[data-tip]') : null; }
    document.addEventListener('mouseover', function (e) {
        var el = tipTarget(e);
        if (!el) { if (tipFor) tipHide(); return; }
        if (el === tipFor) return;
        clearTimeout(tipTimer);
        // Delay, so casual mouse movement over a table doesn't pop tooltips.
        tipTimer = setTimeout(function () { tipShow(el); }, 250);
    });
    document.addEventListener('mouseout', function (e) { if (tipTarget(e)) tipHide(); });
    // Keyboard focus is deliberate: show immediately.
    document.addEventListener('focusin',  function (e) { var el = tipTarget(e); if (el) tipShow(el); });
    document.addEventListener('focusout', tipHide);
    document.addEventListener('keydown',  function (e) { if (e.key === 'Escape') tipHide(); });
    window.addEventListener('scroll', tipHide, true);
    // Hide on any press, in the capture phase, before a page handler opens a modal under the tooltip.
    document.addEventListener('mousedown', tipHide, true);
    document.addEventListener('click', tipHide, true);
    // Icon-only elements need an accessible name too.
    window.DNSPanel.tipAttrs = function (text) {
        return ' data-tip="' + esc(text) + '" aria-label="' + esc(text) + '"';
    };

    // Catalog display name: "name (fqdn)". Mirrors functions::catalog_label.
    window.DNSPanel.catalogLabel = function (c) {
        if (!c) return '';
        if (!c.name) return c.fqdn || '';
        return c.fqdn ? (c.name + ' (' + c.fqdn + ')') : c.name;
    };

    // Actor as an icon with a tooltip (a long name widens narrow columns). Mirrors functions::actor_icon_html.
    window.DNSPanel.actorIcon = function (name) {
        if (!name) return '<span class="text-mute">—</span>';
        return '<span class="lc-who" data-tip="' + esc(name) + '" aria-label="' + esc(name) + '">' +
            '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">' +
            '<path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg></span>';
    };

    // Single reload point: after state-changing actions re-reading the server-rendered page is simpler than
    // patching the DOM, and tests can stub it.
    window.DNSPanel.reload = function () { window.location.reload(); };

    // Single-field dialog instead of window.prompt. Resolves to the value, or null if cancelled.
    window.DNSPanel.prompt = function (opts) {
        opts = opts || {};
        return new Promise(function (resolve) {
            var ov = document.getElementById('modal-overlay');
            if (!ov) { resolve(window.prompt(String(opts.message || '').replace(/<[^>]*>/g, ''))); return; }
            ov.innerHTML = '<div class="modal"><form class="modal-card dlg-card" data-dlg="form">' +
                '<div class="modal-head"><h2 class="modal-title">' + esc(opts.title || 'Enter a value') + '</h2>' +
                '<button type="button" class="modal-x" data-dlg="cancel" aria-label="Close">×</button></div>' +
                '<div class="dlg-body">' + (opts.message || '') + '</div>' +
                '<input class="field-input" data-dlg="input" autocomplete="off"' +
                (opts.placeholder ? ' placeholder="' + esc(opts.placeholder) + '"' : '') + '>' +
                '<div class="modal-actions">' +
                '<button type="button" class="btn btn-ghost" data-dlg="cancel">' + esc(opts.cancelText || 'Cancel') + '</button>' +
                '<button type="submit" class="btn btn-primary">' + esc(opts.okText || 'OK') + '</button>' +
                '</div></form></div>';
            ov.style.display = 'block';
            var input = ov.querySelector('[data-dlg="input"]');
            function cleanup() { ov.style.display = 'none'; ov.innerHTML = ''; document.removeEventListener('keydown', onKey, true); }
            function done(v) { cleanup(); resolve(v); }
            function onKey(e) { if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); done(null); } }
            ov.addEventListener('click', function (e) {
                var b = e.target.closest && e.target.closest('[data-dlg="cancel"]');
                if (b) done(null);
            });
            ov.querySelector('[data-dlg="form"]').addEventListener('submit', function (e) {
                e.preventDefault(); done(input.value);
            });
            document.addEventListener('keydown', onKey, true);
            input.focus();
        });
    };
    window.DNSPanel.alert = function (opts) {
        if (typeof opts === 'string') opts = { message: esc(opts) };
        opts = opts || {};
        return window.DNSPanel.confirm({ title: opts.title || 'Notice', message: opts.message, okText: opts.okText || 'OK', cancel: false });
    };

    // Make primary (Secondary -> Primary): the wording lives here so every entry point says the same thing.
    // confirm_name is still sent because the API gate protects direct calls and MCP. Dynamic updates are set
    // in Zone settings; only a zone the old server accepted updates for (opt.required) keeps them on, or
    // promoting it would silently cut off DHCP. Resolves to null or { dynamic }.
    window.DNSPanel.confirmMakePrimary = async function (name, opt) {
        opt = opt || {};
        var ok = await window.DNSPanel.confirm({
            title: 'Make primary',
            message: 'Zone <b>' + esc(name) + '</b> becomes primary here: records and serial stay, the upstream is dropped.' +
                (opt.required ? '<div style="margin-top:.5rem;">Dynamic updates stay on: the old server accepted them.</div>' : ''),
            okText: 'Make primary',
        });
        return ok ? { dynamic: !!opt.required } : null;
    };
    // Notes after success. delivery_preserved: promote keeps the previous delivery method, so the zone does
    // not end up in a catalog nobody chose.
    window.DNSPanel.makePrimaryNotes = function (d) {
        d = d || {};
        var notes = (d.warnings || []).slice();
        if (!notes.length && d.policy_warning) notes.push(d.policy_warning);
        if (d.delivery_preserved) {
            notes.push('Delivery stays Direct AXFR, as it was before \u2014 the zone is not announced in a catalog. ' +
                       'Pick a catalog in Zone settings if you want it announced.');
        }
        return notes;
    };

    // Table filters shared by all pages (.filter/.filter-menu, styled in main.css). A page supplies only
    // its values (opts) and onChange; the current value lives on the button (data-val).
    window.DNSPanel.filterHtml = function (name, label, value, text) {
        return '<span class="filter-wrap"><button class="filter" type="button" data-filter="' + escHtml(name) + '"'
             + ' data-val="' + escHtml(value || 'all') + '">' + escHtml(label) + ': '
             + escHtml(text || 'all') + ' \u25be</button></span>';
    };
    // Per-browser view state (filters, tabs) that survives F5. store(key) reads, store(key, value) writes.
    window.DNSPanel.store = function (key, value) {
        try {
            if (arguments.length < 2) return JSON.parse(localStorage.getItem('dnspanel.' + key) || 'null');
            localStorage.setItem('dnspanel.' + key, JSON.stringify(value));
        } catch (e) {}
        return null;
    };
    // Filter buttons of a toolbar as {name: {val, text}}, and back.
    window.DNSPanel.filtersGet = function (container, names) {
        var out = {};
        (names || []).forEach(function (n) {
            var b = container && container.querySelector('.filter[data-filter="' + n + '"]');
            if (b) out[n] = { val: b.getAttribute('data-val') || 'all', text: b.textContent };
        });
        return out;
    };
    window.DNSPanel.filtersSet = function (container, saved) {
        Object.keys(saved || {}).forEach(function (n) {
            var b = container && container.querySelector('.filter[data-filter="' + n + '"]');
            if (b && saved[n]) { b.setAttribute('data-val', saved[n].val); b.textContent = saved[n].text; }
        });
    };
    window.DNSPanel.filterInit = function (container, spec) {
        if (!container) return;
        container.setAttribute('data-filters', '1');
        container.__filters = spec || {};
    };
    window.DNSPanel.filterValue = function (container, name) {
        var b = container && container.querySelector('.filter[data-filter="' + name + '"]');
        return b ? (b.getAttribute('data-val') || 'all') : 'all';
    };
    window.DNSPanel.filtersActive = function (container, names) {
        if (!container) return false;
        return (names || []).some(function (n) { return window.DNSPanel.filterValue(container, n) !== 'all'; });
    };
    window.DNSPanel.filtersClear = function (container, names) {
        (names || []).forEach(function (n) {
            var b = container.querySelector('.filter[data-filter="' + n + '"]');
            if (!b) return;
            var label = (b.textContent.split(':')[0] || n).trim();
            b.setAttribute('data-val', 'all');
            b.textContent = label + ': all \u25be';
        });
    };
    function closeFilterMenus(except) {
        document.querySelectorAll('.filter-wrap.open').forEach(function (w) {
            if (w === except) return;
            w.classList.remove('open');
            var m = w.querySelector('.filter-menu'); if (m) m.remove();
        });
    }
    window.DNSPanel.closeFilterMenus = closeFilterMenus;
    document.addEventListener('click', function (e) {
        var t = e.target;
        var opt = t.closest && t.closest('.filter-opt');
        if (opt) {
            var menu = opt.closest('.filter-menu'), wrap = opt.closest('.filter-wrap');
            var cont = opt.closest('[data-filters]');
            var btn  = wrap && wrap.querySelector('.filter');
            // A multi filter (spec.multi[name]) is a set of checkboxes: its value is "a+b", the menu stays open.
            if (btn && menu.classList.contains('multi')) {
                var on = opt.classList.toggle('sel');
                opt.querySelector('input').checked = on;
                var picked = Array.prototype.filter.call(menu.querySelectorAll('.filter-opt'), function (o) { return o.classList.contains('sel'); });
                btn.setAttribute('data-val', picked.map(function (o) { return o.getAttribute('data-val'); }).join('+') || 'all');
                btn.textContent = (btn.textContent.split(':')[0] || '').trim() + ': '
                    + (picked.map(function (o) { return o.textContent; }).join(' + ') || 'all') + ' ▾';
                if (cont && cont.__filters && cont.__filters.onChange) cont.__filters.onChange();
                return;
            }
            if (btn) {
                var label = (btn.textContent.split(':')[0] || '').trim();
                btn.setAttribute('data-val', opt.getAttribute('data-val'));
                btn.textContent = label + ': ' + opt.textContent + ' \u25be';
            }
            closeFilterMenus();
            if (cont && cont.__filters && cont.__filters.onChange) cont.__filters.onChange();
            return;
        }
        var fb = t.closest && t.closest('.filter[data-filter]');
        if (fb) {
            var w = fb.closest('.filter-wrap'), c = fb.closest('[data-filters]');
            var wasOpen = w.classList.contains('open');
            closeFilterMenus();
            if (wasOpen || !c || !c.__filters || !c.__filters.opts) return;
            var name = fb.getAttribute('data-filter'), cur = fb.getAttribute('data-val') || 'all';
            var list = c.__filters.opts(name) || [];
            var m2 = document.createElement('div');
            var multi = c.__filters.multi && c.__filters.multi[name];
            m2.className = 'filter-menu' + (multi ? ' multi' : ''); m2.setAttribute('data-for', name);
            if (multi) {
                var curSet = cur === 'all' ? [] : cur.split('+');
                list = list.filter(function (o) { return o[0] !== 'all'; });
                m2.innerHTML = list.map(function (o) {
                    var on = curSet.indexOf(o[0]) >= 0;
                    return '<div class="filter-opt' + (on ? ' sel' : '') + '" data-val="' + escHtml(o[0]) + '">'
                         + '<input type="checkbox" tabindex="-1"' + (on ? ' checked' : '') + '>' + escHtml(o[1]) + '</div>';
                }).join('');
                w.appendChild(m2); w.classList.add('open');
                return;
            }
            m2.innerHTML = list.map(function (o) {
                return '<div class="filter-opt' + (o[0] === cur ? ' sel' : '') + '" data-val="' + escHtml(o[0]) + '">'
                     + escHtml(o[1]) + '</div>';
            }).join('');
            w.appendChild(m2);
            w.classList.add('open');
            return;
        }
        if (!(t.closest && t.closest('.filter-menu'))) closeFilterMenus();
    });

    // "?" help popover: opens on click and stays open (unlike a tooltip), so a command in it can be selected
    // and copied. Closed by the same button, an outside click or Esc.
    var HELP = null;
    // helpDot(id, text) or helpDot(id, {text, code, after}); code is shown as a separate monospace block.
    window.DNSPanel.helpDot = function (id, spec) {
        // Content rides in attributes and the popover is created on click, so it stays out of page search.
        var o = (typeof spec === 'string') ? { text: spec } : (spec || {});
        return '<span class="help-wrap"><button type="button" class="help-dot" data-help="' + escHtml(id) + '"'
             + ' data-help-text="' + escHtml(o.text || '') + '"'
             + (o.code  ? ' data-help-code="'  + escHtml(o.code)  + '"' : '')
             + (o.after ? ' data-help-after="' + escHtml(o.after) + '"' : '')
             + ' aria-label="What this means">?</button></span>';
    };
    window.DNSPanel.closeHelp = function () {
        if (!HELP) return false;
        HELP = null;
        document.querySelectorAll('.help-pop').forEach(function (p) { p.remove(); });
        document.querySelectorAll('.help-wrap.open').forEach(function (w) {
            w.classList.remove('open');
            var b = w.querySelector('.help-dot'); if (b) b.removeAttribute('aria-expanded');
        });
        return true;
    };
    document.addEventListener('click', function (e) {
        var t = e.target;
        var hb = t.closest && t.closest('[data-help]');
        if (hb) {
            e.preventDefault();
            var hid = hb.getAttribute('data-help'), was = (HELP === hid);
            window.DNSPanel.closeHelp();
            if (was) return;
            HELP = hid;
            var wrap = hb.parentNode;
            wrap.classList.add('open');
            hb.setAttribute('aria-expanded', 'true');
            // The popover lives in body with position:fixed: a modal card's own scroll would clip it.
            var pop = document.createElement('span');
            pop.className = 'help-pop'; pop.setAttribute('role', 'note');
            pop.setAttribute('data-help-for', hid);
            var put = function (cls, txt) {
                if (!txt) return;
                var el = document.createElement(cls ? 'code' : 'span');
                if (cls) el.className = cls;
                el.textContent = txt;
                pop.appendChild(el);
            };
            put('', hb.getAttribute('data-help-text'));
            put('help-code', hb.getAttribute('data-help-code'));
            put('', hb.getAttribute('data-help-after'));
            document.body.appendChild(pop);
            var r = hb.getBoundingClientRect();
            var vw = document.documentElement.clientWidth, vh = document.documentElement.clientHeight;
            var pr = pop.getBoundingClientRect();
            var left = Math.min(Math.max(8, r.left), vw - pr.width - 8);
            var top = r.bottom + 6;
            if (top + pr.height > vh - 8 && r.top - pr.height - 6 > 8) top = r.top - pr.height - 6;
            pop.style.left = left + 'px';
            pop.style.top = top + 'px';
            return;
        }
        // Clicks inside the popover don't close it, so the command can be selected.
        if (HELP && !(t.closest && (t.closest('.help-wrap') || t.closest('.help-pop')))) window.DNSPanel.closeHelp();
    });
    document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape' && HELP) { e.preventDefault(); window.DNSPanel.closeHelp(); }
    });

    document.addEventListener('DOMContentLoaded', function () {
        console.log('DNS Panel ready');
    });
})();

// Documentation page: Copy next to a code block copies the block's text.
document.addEventListener('click', function (e) {
    var b = e.target.closest && e.target.closest('[data-doc-copy]');
    if (!b) return;
    var pre = b.parentNode.querySelector('pre');
    if (!pre || !navigator.clipboard) return;
    navigator.clipboard.writeText(pre.textContent).then(function () {
        b.textContent = 'Copied';
        setTimeout(function () { b.textContent = 'Copy'; }, 1200);
    }).catch(function () {});
});

// Times: the database gives UTC; every page shows them through DNSPanel.fmtTime, in the person's time zone
// and date format (Account → Display, window.DNSPANEL_PREFS: tz = IANA zone or '' for the browser's,
// df = dmy | iso | mdy or '' for the browser's). Server-rendered times are <span data-utc="…">, converted
// by localizeTimes() when a page loads.
(function () {
    'use strict';
    var P = window.DNSPANEL_PREFS || {};
    // 'YYYY-MM-DD HH:MM:SS[.ffffff]' (UTC), ISO with a zone, or epoch seconds -> Date | null.
    function toDate(v) {
        if (v == null || v === '') return null;
        if (typeof v === 'number' || /^\d+$/.test(String(v))) return new Date(+v * 1000);
        var s = String(v).trim();
        if (/^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(:\d{2})?(\.\d+)?$/.test(s)) s = s.replace(' ', 'T').replace(/\.\d+$/, '') + 'Z';
        var d = new Date(s);
        return isNaN(d.getTime()) ? null : d;
    }
    function parts(d, tz) {
        var o = { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23' };
        if (tz) o.timeZone = tz;
        var p = {};
        try { new Intl.DateTimeFormat('en-GB', o).formatToParts(d).forEach(function (x) { p[x.type] = x.value; }); }
        catch (e) { return parts(d, null); }   // unknown zone: the browser's
        return p;
    }
    function ymd(p, df) {
        if (df === 'dmy') return p.day + '.' + p.month + '.' + p.year;
        if (df === 'mdy') return p.month + '/' + p.day + '/' + p.year;
        return p.year + '-' + p.month + '-' + p.day;
    }
    // opts: { seconds, date (no time), tz (override) }
    window.DNSPanel.fmtTime = function (v, opts) {
        opts = opts || {};
        var d = toDate(v); if (!d) return v == null ? '' : String(v);
        var tz = opts.tz !== undefined ? opts.tz : P.tz;
        if (!P.df) {   // the browser's own format
            var o = { year: 'numeric', month: '2-digit', day: '2-digit' };
            if (!opts.date) { o.hour = '2-digit'; o.minute = '2-digit'; if (opts.seconds) o.second = '2-digit'; }
            if (tz) o.timeZone = tz;
            try { return new Intl.DateTimeFormat(undefined, o).format(d); } catch (e) { delete o.timeZone; return new Intl.DateTimeFormat(undefined, o).format(d); }
        }
        var p = parts(d, tz);
        return ymd(p, P.df) + (opts.date ? '' : ' ' + p.hour + ':' + p.minute + (opts.seconds ? ':' + p.second : ''));
    };
    // A calendar date 'YYYY-MM-DD' in the person's format (no zone involved).
    window.DNSPanel.fmtDay = function (s) {
        var m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(s || ''); if (!m) return s || '';
        if (!P.df) return new Date(+m[1], +m[2] - 1, +m[3]).toLocaleDateString(undefined, { year: 'numeric', month: '2-digit', day: '2-digit' });
        return ymd({ year: m[1], month: m[2], day: m[3] }, P.df);
    };
    // UTC 'YYYY-MM-DDTHH:MM:SS' of the start of calendar day s in the person's zone (for date filters).
    window.DNSPanel.dayStartUtc = function (s) {
        var m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(s || ''); if (!m) return '';
        var guess = Date.UTC(+m[1], +m[2] - 1, +m[3]);
        for (var i = 0; i < 2; i++) {   // the zone offset at that moment, twice for DST edges
            var p = parts(new Date(guess), P.tz);
            var wall = Date.UTC(+p.year, +p.month - 1, +p.day, +p.hour, +p.minute, +p.second);
            guess -= wall - Date.UTC(+m[1], +m[2] - 1, +m[3]);
        }
        return new Date(guess).toISOString().slice(0, 19);
    };
    window.DNSPanel.localizeTimes = function (root) {
        (root || document).querySelectorAll('[data-utc]').forEach(function (el) {
            el.textContent = window.DNSPanel.fmtTime(el.getAttribute('data-utc'), { seconds: el.hasAttribute('data-sec') });
        });
    };
    document.addEventListener('pageLoaded', function () { window.DNSPanel.localizeTimes(document.getElementById('main-content')); });
})();

// Date field in the person's format (Account → Display). A native <input type="date"> always shows the
// browser language's order (e.g. mm/dd/yyyy), so the text is ours; the calendar button opens the native
// picker of a hidden date input and writes the picked day back in our format.
(function () {
    'use strict';
    var P = window.DNSPANEL_PREFS || {};
    function esc(s) { return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'); }
    // Order of day/month/year for the person's format ('dmy' / 'ymd' / 'mdy'), the browser's when none is set.
    function order() {
        if (P.df === 'dmy') return 'dmy';
        if (P.df === 'mdy') return 'mdy';
        if (P.df === 'iso') return 'ymd';
        var o = '';
        new Intl.DateTimeFormat(undefined, { year: 'numeric', month: '2-digit', day: '2-digit' }).formatToParts(new Date(2026, 10, 22))
            .forEach(function (x) { if (x.type === 'day') o += 'd'; if (x.type === 'month') o += 'm'; if (x.type === 'year') o += 'y'; });
        return o.length === 3 ? o : 'ymd';
    }
    function placeholder() {
        if (P.df === 'dmy') return 'DD.MM.YYYY';
        if (P.df === 'mdy') return 'MM/DD/YYYY';
        if (P.df === 'iso') return 'YYYY-MM-DD';
        return window.DNSPanel.fmtDay('2026-11-22').replace('2026', 'YYYY').replace('11', 'MM').replace('22', 'DD');
    }
    var CAL = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="5" width="18" height="16" rx="2"/><path d="M3 10h18M8 3v4M16 3v4"/></svg>';
    window.DNSPanel.dateFieldHtml = function (id, ymd) {
        return '<span class="date-field"><input class="field-input" id="' + esc(id) + '" value="' + esc(ymd ? window.DNSPanel.fmtDay(ymd) : '')
            + '" placeholder="' + esc(placeholder()) + '" autocomplete="off" inputmode="numeric">'
            + '<button type="button" class="date-pick" data-date-pick tabindex="-1" aria-label="Calendar">' + CAL + '</button>'
            + '<input type="date" class="date-native" tabindex="-1" aria-hidden="true" value="' + esc(ymd || '') + '"></span>';
    };
    // Text of a date field -> 'YYYY-MM-DD', '' when empty, null when it is not a date.
    window.DNSPanel.dateFieldValue = function (input) {
        var s = (input && input.value || '').trim(); if (!s) return '';
        var n = s.split(/[^\d]+/).filter(Boolean); if (n.length !== 3) return null;
        var o = order(), v = {};
        for (var i = 0; i < 3; i++) v[o[i]] = +n[i];
        var d = new Date(Date.UTC(v.y, v.m - 1, v.d));
        if (v.y < 1000 || d.getUTCMonth() !== v.m - 1 || d.getUTCDate() !== v.d) return null;
        return d.toISOString().slice(0, 10);
    };
    document.addEventListener('click', function (e) {
        var b = e.target.closest && e.target.closest('[data-date-pick]'); if (!b) return;
        e.preventDefault();
        var f = b.closest('.date-field'), nat = f.querySelector('.date-native'), txt = f.querySelector('input.field-input');
        nat.value = window.DNSPanel.dateFieldValue(txt) || '';
        try { nat.showPicker(); } catch (x) { nat.focus(); }
    });
    document.addEventListener('change', function (e) {
        var nat = e.target; if (!nat.classList || !nat.classList.contains('date-native')) return;
        var txt = nat.closest('.date-field').querySelector('input.field-input');
        txt.value = nat.value ? window.DNSPanel.fmtDay(nat.value) : '';
        txt.classList.remove('is-invalid');
    });
})();
