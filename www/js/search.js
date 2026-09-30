/* DNS Panel — global search in the top bar: "where is this address / name used?".
 *
 * The server does the search (`GET /dns-api/records/search`) and applies permissions: accessible zones go
 * into the SQL before LIMIT, so foreign matches neither show nor take result slots. The client does no
 * filtering or counting of its own.
 *
 * For an address the server returns: exact A/AAAA matches (a substring would match 203.0.113.10 for
 * 203.0.113.1), PTR by reverse name, mentions in text (TXT/SPF) and ONE level of references (CNAME/MX/SRV/NS
 * pointing to a name holding the address). Deeper resolution would need graph traversal with loop protection.
 */
(function () {
    'use strict';

    var MIN_CHARS = 2, DELAY = 260, SHOW = 40;
    var timer = null, seq = 0, lastQuery = '', lastData = null, activeType = '';
    // Group order goes from most used to auxiliary, not alphabetical; SOA shows up only incidentally
    // (its content contains hostmaster.<zone>).
    var TYPE_ORDER = ['A', 'AAAA', 'CNAME', 'MX', 'PTR', 'SRV', 'NS', 'TXT', 'SOA'];

    function esc(s) {
        return String(s == null ? '' : s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }
    function menu() { return document.getElementById('gsearch-menu'); }

    // Of SOA's seven fields only two help in search results; the full value stays in the field's tooltip.
    function shownVal(r) {
        var c = String(r.content == null ? '' : r.content);
        if (String(r.type || '').toUpperCase() !== 'SOA') return c;
        var p = c.split(/\s+/);
        return p.length >= 2 ? p[0] + ' \u00b7 ' + p[1] : c;
    }

    function close() {
        var m = menu();
        if (m) { m.hidden = true; m.innerHTML = ''; }
    }
    function show(html) {
        var m = menu();
        if (!m) return;
        m.innerHTML = html;
        m.hidden = false;
    }

    // Each row is a link, not a div, so it is reachable by Tab and opens on Enter; navigation.js handles it.
    // Disabled records are marked: they do not answer in DNS and must not look live in the results.
    // Compare with `+`: 0/1 come as numbers, but a string '0' would be truthy.
    function rowHtml(r) {
        var off = +r.disabled === 1;
        var type = String(r.type || '').toUpperCase();
        var apex = type === 'SOA' || (type === 'NS' && String(r.name || '').toLowerCase() === String(r.zone || '').toLowerCase());
        // For a regular record, pre-set the zone's name + type filters so the RRset stays visible, and point
        // record at the row to highlight. SOA and apex NS live in a separate accordion and need no filter.
        var href = '/records?zone=' + encodeURIComponent(r.domain_id) + '&record=' + encodeURIComponent(r.id);
        if (!apex) href += '&type=' + encodeURIComponent(type) + '&search=' + encodeURIComponent(r.name || '');
        // Zone goes as a dimmed second line under the name, not a column: the menu is narrow.
        // Apex records have name == zone, so the "Zone: …" line would just repeat it. Compare
        // case-insensitively and without the trailing dot: gmysql stores names without it, but input may have one.
        var bare = function (v) { return String(v == null ? '' : v).toLowerCase().replace(/\.$/, ''); };
        var sameAsZone = bare(r.name) === bare(r.zone);
        // Each field has its own tooltip, so hovering a truncated value shows that value, not the zone.
        return '<a class="gs-row' + (off ? ' gs-off' : '') + '" href="' + esc(href) + '">'
             + '<span class="badge">' + esc(r.type) + '</span>'
             + '<span class="gs-main">'
             +   '<span class="gs-name" data-tip="' + esc(r.name) + '">' + esc(r.name_unicode || r.name) + '</span>'
             +   (sameAsZone ? ''
                  : '<span class="gs-zone" data-tip="' + esc(r.zone) + '">Zone: ' + esc(r.zone_unicode || r.zone) + '</span>')
             + '</span>'
             + (off ? '<span class="badge muted">Disabled</span>' : '')
             + '<span class="gs-val" data-tip="' + esc(r.content) + '">' + esc(shownVal(r)) + '</span>'
             + '</a>';
    }

    // Group by record type: grouping by whether the query hit the name put the A record itself under
    // "References" when searching by address.
    function groupsOf(rows) {
        var by = {};
        rows.forEach(function (r) {
            var t = String(r.type || '').toUpperCase() || '?';
            (by[t] = by[t] || []).push(r);
        });
        var known = TYPE_ORDER.filter(function (t) { return by[t]; });
        var rest = Object.keys(by).filter(function (t) { return TYPE_ORDER.indexOf(t) < 0; }).sort();
        return { by: by, order: known.concat(rest) };
    }

    // Buttons only for types found, plus All. No counts on purpose: results are capped by the limit,
    // so a count would falsely suggest a total.
    function typeBar(order) {
        if (order.length < 2) return '';                 // a single type: nothing to filter
        var btn = function (t, label) {
            var on = (activeType === t);
            return '<button type="button" class="badge badge-btn gs-type-btn" data-type="' + esc(t) + '"'
                 + ' aria-pressed="' + (on ? 'true' : 'false') + '">' + esc(label) + '</button>';
        };
        return '<div class="gs-types">' + btn('', 'All')
             + order.map(function (t) { return btn(t, t); }).join('') + '</div>';
    }

    // Renders from already fetched data; type filter buttons call it too, so filtering makes no request.
    function paint(q, data) {
        var all = (data && data.records) || [];
        if (!all.length) { show('<div class="gs-note">Nothing found for &laquo;' + esc(q) + '&raquo;.</div>'); return; }

        // The server returns one row more than shown, so "first N shown" is a fact, not a guess.
        // Counted on the full result, before the type filter.
        var more = all.length > SHOW;
        if (more) all = all.slice(0, SHOW);

        // Buttons come from the full result so the set of types does not jump when one is selected.
        var groups = groupsOf(all);
        var html = typeBar(groups.order);
        var shown = activeType ? groups.order.filter(function (t) { return t === activeType; }) : groups.order;
        shown.forEach(function (t) {
            html += '<div class="gs-group">' + esc(t) + '</div>' + groups.by[t].map(rowHtml).join('');
        });
        if (!shown.length) html += '<div class="gs-note">No ' + esc(activeType) + ' records among the matches.</div>';

        // Why a PTR without the typed "10.99" in its text shows up: the address is reversed in the PTR
        // name, and the record was matched by network, not substring.
        if (data && data.ptr_network) {
            html += '<div class="gs-note">PTR records under ' + esc(data.ptr_network) + '.&lowast;</div>';
        }
        // Why CNAME/MX without the address show up: they point to a name that holds it.
        var owners = (data && data.ref_names) || [];
        if (owners.length) {
            html += '<div class="gs-note">Records pointing at ' + owners.slice(0, 3).map(esc).join(', ')
                  + (owners.length > 3 ? ' and ' + (owners.length - 3) + ' more' : '') + '.</div>';
        }
        if (more) html += '<div class="gs-note">First ' + SHOW + ' matches shown — narrow the query.</div>';
        show(html);
    }

    // New data resets the type filter, which belonged to the previous result.
    function render(q, data) {
        lastQuery = q;
        lastData = data;
        activeType = '';
        paint(q, data);
    }

    async function run(q, my) {
        try {
            var res = await window.DNSPanel.api(
                'records/search?q=' + encodeURIComponent(q) + '&limit=' + (SHOW + 1), { method: 'GET' });
            if (my !== seq) return;                    // superseded while in flight
            render(q, (res && res.data) || {});
        } catch (err) {
            if (my !== seq) return;
            lastQuery = '';
            lastData = null;
            show('<div class="gs-note">Search failed: ' + esc((err && err.message) || 'error') + '</div>');
        }
    }

    function schedule(q, delay) {
        var my = ++seq;
        if (timer) { clearTimeout(timer); timer = null; }
        if (q.length < MIN_CHARS) { close(); return; }
        // Refocusing shows the cached result at once. If the value appeared after page load with no cache
        // yet, run the same search without waiting for new input.
        if (q === lastQuery && lastData) { paint(q, lastData); return; }   // same list, same filter
        timer = setTimeout(function () { timer = null; run(q, my); }, delay);
    }

    function dismiss() {
        ++seq;                                      // an in-flight request must not reopen the closed list
        if (timer) { clearTimeout(timer); timer = null; }
        close();                                    // data is kept for the next focus
    }

    document.addEventListener('input', function (e) {
        if (!e.target || e.target.id !== 'gsearch') return;
        var q = e.target.value.trim();
        schedule(q, DELAY);                         // the sequence number grows now, before the delay
    });

    document.addEventListener('focusin', function (e) {
        if (!e.target || e.target.id !== 'gsearch') return;
        schedule(e.target.value.trim(), 0);
    });

    document.addEventListener('click', function (e) {
        // A type button filters the already fetched result: no request, list stays open.
        var tb = e.target.closest && e.target.closest('.gs-type-btn');
        if (tb) {
            e.preventDefault();
            activeType = tb.getAttribute('data-type') || '';
            if (lastData) paint(lastQuery, lastData);
            return;
        }
        // Row click: close the results and let navigation.js handle the link.
        if (e.target.closest && e.target.closest('.gs-row')) { dismiss(); return; }
        // A click outside the field and the list closes the results; a click on the field does not.
        if (!(e.target.closest && e.target.closest('.gsearch'))) dismiss();
    });

    document.addEventListener('keydown', function (e) {
        if (e.key !== 'Escape') return;
        var m = menu();
        if (m && !m.hidden) { e.preventDefault(); e.stopPropagation(); dismiss(); }
    });
})();
