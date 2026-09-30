/* DNS Panel — Audit log. Filters (actor/action/result/target_type/source + target LIKE) and paging
   via /dns-api/audit. Permissions are enforced server-side (audit.read). Filter options come from #audit-data. */
(function () {
    'use strict';

    var ST = null;   // { can, options, filters, offset, limit, total, rows }
    var LIMIT = 50;
    var FILTERS = ['actor', 'action', 'result', 'target_type', 'source', 'target', 'from', 'to'];

    function esc(s) { return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'); }
    function sel(name, opts, value) { return window.DNSPanel.selectHtml(name, opts, value); }
    function readData() { var el = document.getElementById('audit-data'); try { return el ? JSON.parse(el.textContent) : null; } catch (e) { return null; } }

    // Prefer the target_label snapshot; link audience to its catalog and zone to its records.
    function targetCell(r) {
        var tt = r.target_type || '', tg = r.target, lbl = (r.target_label != null && r.target_label !== '') ? r.target_label : null;
        if (tt === 'catalog' && /^\d+$/.test(String(tg))) return '<a class="link" href="/propagation?catalog=' + tg + '">' + esc(lbl || ('catalog ' + tg)) + '</a>';
        if (tt === 'zone' && r.target_id != null)          return '<a class="link" href="/records?zone=' + r.target_id + '">' + esc(lbl || tg) + '</a>';
        if (lbl) return esc(lbl);
        if (tg == null || tg === '') return '<span class="text-dim">' + esc(tt || '—') + '</span>';
        return esc((tt ? tt + ' ' : '') + tg);
    }
    function fmtJson(v) { if (v == null || v === '') return null; try { return JSON.stringify(typeof v === 'string' ? JSON.parse(v) : v, null, 2); } catch (e) { return String(v); } }
    function detailHtml(r) {
        var meta = [];
        meta.push('<span class="text-dim">Action:</span> <span class="mono">' + esc(r.action || '') + '</span>');
        if (r.target_type || r.target != null) meta.push('<span class="text-dim">Target:</span> ' + esc((r.target_type ? r.target_type + ' ' : '') + (r.target != null ? r.target : '')));
        if (r.source) meta.push('<span class="text-dim">Source:</span> ' + esc(r.source) + (r.via ? ' · ' + esc(r.via) : ''));
        if (r.ip) meta.push('<span class="text-dim">IP:</span> <span class="mono">' + esc(r.ip) + '</span>');
        if (r.result) meta.push('<span class="text-dim">Result:</span> ' + esc(r.result));
        if (r.detail) meta.push('<span class="text-dim">Detail:</span> ' + esc(r.detail));
        var b = fmtJson(r.before_val), a = fmtJson(r.after_val), diff = '';
        if (b) diff += '<div><div class="text-dim" style="font-size:11px;margin-bottom:.2rem">Before</div><pre class="audit-json">' + esc(b) + '</pre></div>';
        if (a) diff += '<div><div class="text-dim" style="font-size:11px;margin-bottom:.2rem">After</div><pre class="audit-json">' + esc(a) + '</pre></div>';
        return '<div class="audit-detail"><div class="audit-meta">' + meta.join('<span class="audit-sep">·</span>') + '</div>'
            + (diff ? '<div class="audit-diff">' + diff + '</div>' : '') + '</div>';
    }

    function optList(name, label, values) {
        // values are strings or {value,label} (actions come with human-readable labels).
        var opts = [{ value: '', label: label }].concat((values || []).map(function (v) { return (v && typeof v === 'object') ? v : { value: v, label: v }; }));
        return sel(name, opts, (ST.filters[name] || ''));
    }

    // "Date: all" / "Sep 1 – Sep 29" / "From Sep 1" / "Until Sep 29"; the year only when it is not this one.
    function dateLabel() {
        var f = ST.filters.from, t = ST.filters.to;
        var fmt = window.DNSPanel.fmtDay;
        if (f && t) return f === t ? fmt(f) : fmt(f) + ' – ' + fmt(t);
        if (f) return 'From ' + fmt(f);
        if (t) return 'Until ' + fmt(t);
        return 'Date: all';
    }
    function render() {
        var root = document.getElementById('audit-root'); if (!root) return;
        if (!ST.can) { root.innerHTML = '<div class="card"><p class="text-dim" style="margin:0;">Audit log requires the <b>audit.read</b> capability.</p></div>'; return; }
        var o = ST.options || {};
        var bar = '<div class="toolbar" style="flex-wrap:wrap;gap:.5rem;">'
            + '<div class="search"><svg class="ic" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/></svg>'
            + '<input placeholder="Search…" id="af-target" value="' + esc(ST.filters.target || '') + '"></div>'
            + optList('actor', 'All actors', o.actors)
            + optList('action', 'All actions', o.actions)
            + optList('result', 'All results', o.results)
            + optList('target_type', 'All types', o.target_types)
            + optList('source', 'All sources', o.sources)
            + '<div class="ui-select audit-date"><div class="ui-select-trigger"><span class="ui-select-label">' + esc(dateLabel()) + '</span><span class="chev"></span></div>'
            + '<div class="ui-select-menu"><div class="audit-date-form">'
            + '<label>From ' + window.DNSPanel.dateFieldHtml('af-from', ST.filters.from) + '</label>'
            + '<label>To ' + window.DNSPanel.dateFieldHtml('af-to', ST.filters.to) + '</label>'
            + '<div class="audit-date-acts"><button type="button" class="btn btn-ghost sm" id="af-date-clear">Clear</button>'
            + '<button type="button" class="btn btn-primary sm" id="af-date-apply">Apply</button></div></div></div></div>'
            + '<button class="btn btn-ghost" id="af-clear">Clear</button>'
            + '</div>';
        var rowsHtml = (ST.rows || []).map(function (r, i) {
            var res = (r.result && r.result !== 'ok')
                ? '<span style="color:var(--danger)" data-tip="' + esc(r.detail || '') + '">' + esc(r.result) + '</span>'
                : '<span class="text-dim">ok</span>';
            return '<tr class="audit-row" data-audit-idx="' + i + '">'
                + '<td class="mono text-dim nowrap">' + esc(window.DNSPanel.fmtTime(r.ts, { seconds: true })) + '</td>'
                + '<td>' + esc(r.actor == null ? '—' : r.actor) + (r.source ? ' <span class="chip" style="opacity:.7"' + (r.via ? ' title="' + esc(r.via) + '"' : '') + '>' + esc(r.source) + (r.via ? ' · ' + esc(r.via.split(' ')[0]) : '') + '</span>' : '') + '</td>'
                + '<td>' + esc(r.action_label || r.action || '') + '</td>'
                + '<td>' + targetCell(r) + '</td>'
                + '<td>' + res + '</td>'
                + '</tr>'
                + '<tr class="audit-detail-row" data-audit-detail="' + i + '" hidden><td colspan="5">' + detailHtml(r) + '</td></tr>';
        }).join('') || '<tr><td colspan="5" class="text-dim" style="padding:1rem;">' + (ST.rows ? 'No audit entries match the filters.' : 'Loading…') + '</td></tr>';
        var from = ST.total ? (ST.offset + 1) : 0, to = Math.min(ST.offset + ST.limit, ST.total);
        var page = Math.floor(ST.offset / ST.limit) + 1, pages = Math.max(1, Math.ceil(ST.total / ST.limit));
        var first = ST.offset > 0, last = ST.offset + ST.limit < ST.total;
        var sizes = [25, 50, 100, 200].map(function (n) { return { value: String(n), label: n + ' per page' }; });
        var pager = '<div class="audit-pager">'
            + '<span class="text-dim">' + from + '–' + to + ' of ' + ST.total + '</span>'
            + '<span class="audit-pager-nav">' + sel('af-size', sizes, String(ST.limit))
            + '<button class="btn btn-ghost sm" data-af-page="first"' + (first ? '' : ' disabled') + '>«</button>'
            + '<button class="btn btn-ghost sm" data-af-page="prev"' + (first ? '' : ' disabled') + '>← Prev</button>'
            + '<span class="text-dim nowrap">Page ' + page + ' of ' + pages + '</span>'
            + '<button class="btn btn-ghost sm" data-af-page="next"' + (last ? '' : ' disabled') + '>Next →</button>'
            + '<button class="btn btn-ghost sm" data-af-page="last"' + (last ? '' : ' disabled') + '>»</button>'
            + '</span></div>';
        root.innerHTML = '<div class="card">' + bar
            + '<div class="table-wrap"><table class="data-table"><thead><tr>'
            + '<th>When</th><th>Actor</th><th>Action</th><th>Target</th><th>Result</th>'
            + '</tr></thead><tbody>' + rowsHtml + '</tbody></table></div>' + pager + '</div>';
    }

    async function load() {
        window.DNSPanel.store('auditFilters', ST.filters);
        var qs = [];
        window.DNSPanel.store('auditPageSize', ST.limit);
        FILTERS.forEach(function (k) {
            var v = ST.filters[k]; if (!v) return;
            // Days are the person's days: their bounds go to the server as UTC moments, the end exclusive.
            if (k === 'from') v = window.DNSPanel.dayStartUtc(v);
            if (k === 'to') { var n = new Date(v + 'T00:00:00Z'); n.setUTCDate(n.getUTCDate() + 1); v = window.DNSPanel.dayStartUtc(n.toISOString().slice(0, 10)); }
            qs.push(k + '=' + encodeURIComponent(v));
        });
        qs.push('limit=' + ST.limit); qs.push('offset=' + ST.offset);
        try {
            var res = await window.DNSPanel.api('audit?' + qs.join('&'), { method: 'GET' });
            var d = res.data || res;
            ST.rows = d.rows || []; ST.total = d.total || 0;
        } catch (e) { ST.rows = []; ST.total = 0; window.DNSPanel.alert({ message: (e && e.message) || 'Failed to load audit' }); }
        render();
    }

    // themed-select writes to hidden input[name] and dispatches change.
    document.addEventListener('change', function (e) {
        if (!ST || !ST.can) return;
        var t = e.target; if (!t) return;

        if (!t.name) return;
        if (t.name === 'af-size') { ST.limit = +t.value || LIMIT; ST.offset = 0; load(); return; }
        if (['actor', 'action', 'result', 'target_type', 'source'].indexOf(t.name) < 0) return;
        ST.filters[t.name] = t.value; ST.offset = 0; load();
    });
    document.addEventListener('click', function (e) {
        if (!ST || !ST.can) return;
        var t = e.target;
        if (t.closest && t.closest('#af-clear')) { e.preventDefault(); ST.filters = {}; ST.offset = 0; load(); return; }
        var da = t.closest && t.closest('#af-date-apply, #af-date-clear');
        if (da) {
            e.preventDefault();
            var clear = da.id === 'af-date-clear', vals = {}, bad = false;
            ['from', 'to'].forEach(function (k) {
                var inp = document.getElementById('af-' + k);
                vals[k] = clear ? '' : window.DNSPanel.dateFieldValue(inp);
                inp.classList.toggle('is-invalid', vals[k] === null);
                if (vals[k] === null) bad = true;
            });
            if (bad) return;   // the menu stays open with the wrong field marked
            ['from', 'to'].forEach(function (k) { if (vals[k]) ST.filters[k] = vals[k]; else delete ST.filters[k]; });
            ST.offset = 0; load();
            return;
        }
        var pg = t.closest && t.closest('[data-af-page]');
        if (pg) {
            e.preventDefault();
            var lastOff = Math.max(0, (Math.ceil(ST.total / ST.limit) - 1) * ST.limit);
            var to = { first: 0, prev: Math.max(0, ST.offset - ST.limit), next: Math.min(lastOff, ST.offset + ST.limit), last: lastOff }[pg.getAttribute('data-af-page')];
            if (to !== ST.offset) { ST.offset = to; load(); }
            return;
        }
        if (t.closest && t.closest('a')) return;   // a link click must not toggle the row
        var row = t.closest && t.closest('.audit-row');
        if (row) { var d = document.querySelector('#audit-root .audit-detail-row[data-audit-detail="' + row.getAttribute('data-audit-idx') + '"]'); if (d) { d.hidden = !d.hidden; row.classList.toggle('expanded', !d.hidden); } }
    });
    // target filter applies on Enter, not on every keystroke.
    document.addEventListener('keydown', function (e) {
        if (!ST || !ST.can || e.key !== 'Enter') return;
        var t = e.target; if (!t || t.id !== 'af-target') return;
        e.preventDefault(); ST.filters.target = t.value.trim(); ST.offset = 0; load();
    });

    document.addEventListener('pageLoaded', function (e) {
        if (!e.detail || e.detail.page !== 'audit') return;
        ST = readData(); if (!ST) return;
        ST.filters = window.DNSPanel.store('auditFilters') || {};
        var url = {};
        try { var qp = new URLSearchParams(location.search); FILTERS.forEach(function (k) { var v = qp.get(k); if (v) { ST.filters[k] = v; url[k] = v; } }); } catch (x) {}
        // The first page of rows is embedded in the page itself. Rendering an empty table and filling it
        // a moment later would briefly claim "no records"; later pages and filter changes are user-driven.
        ST.offset = 0;
        var embedded = ST.limit || LIMIT;
        ST.limit = +window.DNSPanel.store('auditPageSize') || embedded;
        ST.rows = ST.rows || [];
        ST.total = ST.total || 0;
        // The embedded page was made for the URL filters only; saved filters or another page size need a load,
        // shown as "Loading…" rather than as the wrong rows.
        var same = ST.limit === embedded && FILTERS.every(function (k) { return (ST.filters[k] || '') === (url[k] || ''); });
        if (!same) { ST.rows = null; ST.total = 0; render(); load(); return; }
        render();
    });
})();
