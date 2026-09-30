/* NS Pulse: Agents / Checks / Rules / History tabs plus the rule builder.
 *
 * A rule belongs to a record and is opened from the record page; it is created only on the first save,
 * opening the builder creates nothing.
 *
 * Branch order is behaviour: the first matching branch from the top wins and shadows everything below,
 * so the builder always shows which branch is chosen, which are shadowed and what the record gets.
 *
 * "Unavailable" and "no data" are different: an undecided branch on top blocks the ones below and leaves
 * the record as is. There is deliberately no NOT: negating a two-state value cannot express the third
 * (docs/25-ns-pulse.md §6).
 */
(function () {
    'use strict';

    var D = null;         // page payload: testers, groups, checks, rules, zones, server
    var TAB = 'agents';
    var RULE = null;      // the open rule: the builder's draft
    var CLEAN = null;     // server snapshot, used to detect unsaved changes
    var PREVIEW = {};     // 'check:tester' -> 'up' | 'degraded' | 'down' | 'unknown' (what-if only, never touches DNS)
    var BUSY = false;

    var P = function () { return window.DNSPanel; };
    function esc(s) {
        return String(s == null ? '' : s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }
    function plural(n, word) { return n + ' ' + word + (n === 1 ? '' : 's'); }
    function byId(list, id) {
        for (var i = 0; i < (list || []).length; i++) if (String(list[i].id) === String(id)) return list[i];
        return null;
    }
    function api(path, opts) { return P().api(path, opts); }
    function fail(err) { P().alert({ title: 'NS Pulse', message: esc((err && err.message) || 'Request failed') }); }

    // A condition refers to a (check, tester) pair; pairs are derived from check -> groups -> members
    // plus directly assigned agents.
    function checkLabel(c) {
        return c ? (c.kind.toUpperCase() + ' ' + c.target_ip + (c.port ? ':' + c.port : '')) : '?';
    }
    function pairsFor(check) {
        var out = [], seen = {};
        var take = function (tid) {
            if (seen[tid]) return;                     // an agent in two groups runs the check once
            seen[tid] = 1;
            var t = byId(D.testers, tid);
            if (t) out.push({ key: check.id + ':' + t.id, check_id: check.id, tester_id: t.id,
                              label: t.name + ' · ' + checkLabel(check) });
        };
        (check.group_ids || []).forEach(function (gid) {
            var g = byId(D.groups, gid);
            ((g && g.member_ids) || []).forEach(take);
        });
        (check.agent_ids || []).forEach(take);
        return out;
    }
    function allPairs() {
        var out = [];
        (D.checks || []).forEach(function (c) { out = out.concat(pairsFor(c)); });
        return out;
    }

    // Rule evaluation: must match the server logic (docs/25 §6).
    var DAYS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
    // "Now" is taken in the rule's time zone, not the browser's, so the preview matches what the server does.
    function nowInRuleTz() {
        var tz = (RULE && RULE.schedule_tz) || 'UTC';
        var f;
        try {
            f = new Intl.DateTimeFormat('en-GB', { timeZone: tz, hour12: false, weekday: 'short',
                year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' });
        } catch (e) { return null; }
        var p = {};
        f.formatToParts(new Date()).forEach(function (x) { p[x.type] = x.value; });
        return { day: DAYS.indexOf(p.weekday), hm: p.hour + ':' + p.minute,
                 date: p.year + '-' + p.month + '-' + p.day };
    }
    function scheduleTrue(cond) {
        var n = nowInRuleTz();
        if (!n) return 'unknown';                      // unknown time zone: don't invent an answer
        if (cond.days_mask != null && n.day >= 0 && !((cond.days_mask >> n.day) & 1)) return 'false';
        var tf = (cond.time_from || '').slice(0, 5), tt = (cond.time_to || '').slice(0, 5);
        if (tf && tt) {
            var inside = (tf <= tt) ? (n.hm >= tf && n.hm < tt)     // window within one day
                                    : (n.hm >= tf || n.hm < tt);    // window across midnight
            if (!inside) return 'false';
        }
        if (cond.date_from && n.date < cond.date_from) return 'false';
        if (cond.date_to   && n.date > cond.date_to)   return 'false';
        return 'true';
    }
    // Keyed by content: identical schedules in different branches are one condition with one answer.
    function schedKey(c) {
        return 's:' + (c.days_mask == null ? '*' : c.days_mask) + '|' + (c.time_from || '') + '|'
             + (c.time_to || '') + '|' + (c.date_from || '') + '|' + (c.date_to || '');
    }
    // Start from the live state in pulse_results, not from "no data": otherwise the preview would call the
    // rule undecided while the server is actually switching the record.
    function liveState(x) {
        var st = x && x.live_state;
        if (st === 'healthy') return 'up';
        if (st === 'degraded') return 'degraded';
        if (st === 'down') return 'down';
        return 'unknown';
    }
    // The server sends observer objects (name, live state, assigned); bare ids come from cloning.
    function condTesters(cond) {
        return (cond.testers || []).map(function (x) {
            if (x && typeof x === 'object') return x;
            var t = byId(D.testers, x);
            return { tester_id: +x, name: t ? t.name : '#' + x, assigned: 1 };
        });
    }
    function pairKey(cond, tid) { return cond.check_id + ':' + tid; }
    // real=true ignores the what-if preview.
    function pairState(cond, x, real) {
        return (!real && PREVIEW[pairKey(cond, x.tester_id)]) || liveState(x);
    }
    function pairVerdict(st, expect) {
        if (st === 'unknown') return 'unknown';
        var actual = (st === 'up') ? 'available' : (st === 'degraded' ? 'degraded' : 'unavailable');
        return actual === expect ? 'true' : 'false';
    }
    // Shared by the preview and the "right now" badge so their numbers always agree.
    function condTally(cond, real) {
        var out = { yes: 0, no: 0, unknown: 0, total: 0 };
        condTesters(cond).forEach(function (x) {
            out.total++;
            var v = pairVerdict(pairState(cond, x, real), cond.expect);
            if (v === 'true') out.yes++; else if (v === 'false') out.no++; else out.unknown++;
        });
        return out;
    }
    // Same three-valued aggregation as internal/rules/rules.go: a silent agent votes neither way.
    function condVerdict(cond) {
        if (cond.kind === 'schedule') {
            // Schedules can be previewed too; if not overridden, the clock answers.
            var sv = PREVIEW[schedKey(cond)];
            return sv ? (sv === 'in' ? 'true' : 'false') : scheduleTrue(cond);
        }
        var t = condTally(cond);
        if (!t.total) return 'unknown';                  // no observers, nobody to answer
        if (cond.agg === 'all') {
            if (t.no) return 'false';                    // one "no" already rules out "all"
            return t.unknown ? 'unknown' : 'true';
        }
        if (cond.agg === 'at_least') {
            var n = +cond.agg_n || 1;
            if (t.yes >= n) return 'true';               // reached; silent ones can't undo it
            if (t.yes + t.unknown < n) return 'false';   // even all silent ones can't reach N
            return 'unknown';
        }
        if (t.yes) return 'true';
        return t.unknown ? 'unknown' : 'false';
    }
    // ANY: true if one is true, false if all are false, otherwise unknown. ALL mirrors it.
    function branchVerdict(br) {
        var t = 0, f = 0, u = 0;
        (br.conditions || []).forEach(function (c) {
            var v = condVerdict(c);
            if (v === 'true') t++; else if (v === 'false') f++; else u++;
        });
        // An empty branch is unknown, not false: its conditions may have cascaded away with a deleted
        // check, and deleting a check must not move DNS (docs/25 §6).
        if (!(br.conditions || []).length) return 'unknown';
        if (br.match_mode === 'all') return f ? 'false' : (u ? 'unknown' : 'true');
        return t ? 'true' : (u ? 'unknown' : 'false');
    }
    function setLabel(vals) {
        return (vals || []).map(function (v) {
            return (v.prio != null && v.prio !== '' ? v.prio + ' ' : '') + (v.content || '');
        }).join(' | ');
    }
    function decide() {
        var out = { winner: null, shadowed: [], undecidedAt: null, address: null, why: '' };
        var brs = RULE.branches || [];
        for (var i = 0; i < brs.length; i++) {
            var v = branchVerdict(brs[i]);
            if (v === 'true') {
                out.winner = i;
                out.address = setLabel(brs[i].values);
                out.set = brs[i].values;
                out.why = 'Rule ' + (i + 1) + ' matches.' + (i < brs.length - 1 ? ' Rules below are shadowed.' : '');
                for (var j = i + 1; j < brs.length; j++) out.shadowed.push(j);
                return out;
            }
            if (v === 'unknown') {
                // Unknown on top shadows everything below: a lost agent is missing data, not an event.
                out.undecidedAt = i;
                out.why = 'Rule ' + (i + 1) + ' is undecided — not enough fresh data. Nothing below is applied.';
                for (var k = i + 1; k < brs.length; k++) out.shadowed.push(k);
                return out;
            }
        }
        out.address = setLabel(RULE.values);
        out.set = RULE.values;
        out.why = 'No rule matches — the default set applies.';
        return out;
    }

    // "Agents" rather than "Testers": the user manages the agent program; a tester is just its DB row.
    var TABS = [ ['agents', 'Agents'], ['checks', 'Checks'], ['rules', 'Rules'], ['history', 'History'] ];
    function tabsHtml() {
        return '<div class="dist-tabs">' + TABS.map(function (t) {
            return '<button class="dist-tab' + (TAB === t[0] ? ' active' : '') + '" data-pl-tab="'
                 + t[0] + '">' + t[1] + '</button>';
        }).join('') + '</div>';
    }
    // Rules can be edited without the Pulse server running; say plainly that nothing is being switched.
    function downHtml() {
        if (!D.server || D.server.running) return '';
        return '<p class="pl-warn">The Pulse server is not running on this node — nothing is being '
             + 'switched. Rules can be set up; they take effect once it runs.</p>';
    }
    // The rule builder opens as an overlay over the page it was opened from, which stays underneath.
    function sheet() { return document.getElementById('pulse-overlay'); }
    function render() {
        var ov = sheet();
        // async-ok: the day bar next to conditions is simply absent until loaded, never drawn empty.
        if (RULE) dayEnsure();
        if (RULE && ov) {
            ov.innerHTML = '<div class="pl-sheet">' + builderHtml() + '</div>';
            ov.style.display = 'block';
            document.body.classList.add('pl-open');
        } else if (ov) {
            ov.style.display = 'none'; ov.innerHTML = '';
            document.body.classList.remove('pl-open');
        }
        var root = document.getElementById('pulse-root');
        if (!root || !D) return;
        root.innerHTML = tabsHtml() + downHtml()
            + (TAB === 'checks' ? checksTab() : TAB === 'rules' ? rulesTab()
               : TAB === 'history' ? historyTab() : testersTab());
        if (TAB === 'rules') rulesFilter();   // the filter survives re-render; apply it to the new rows
        // async-ok: history is not in the page payload (large for a month); "Loading…" shows meanwhile.
        if (TAB === 'history') histEnsure();
        // async-ok: likewise the 24h overview bar; the cell shows "…" meanwhile.
        if (TAB === 'checks' || TAB === 'agents') dayEnsure();
    }

    // Sorting, remembered per tab as on Propagation.
    function sortKey(tab) { return 'pulse.sort.' + tab; }
    function getSort(tab, def) {
        try { return JSON.parse(localStorage.getItem(sortKey(tab))) || def; } catch (e) { return def; }
    }
    function setSort(tab, by) {
        var cur = getSort(tab, { by: by, dir: 'asc' });
        var next = { by: by, dir: (cur.by === by && cur.dir === 'asc') ? 'desc' : 'asc' };
        try { localStorage.setItem(sortKey(tab), JSON.stringify(next)); } catch (e) {}
        render();
    }
    function sorted(rows, tab, def, pick) {
        var s = getSort(tab, def);
        var out = rows.slice();
        out.sort(function (a, b) {
            var x = pick(a, s.by), y = pick(b, s.by);
            if (typeof x === 'number' && typeof y === 'number') return x - y;
            return String(x == null ? '' : x).toLowerCase()
                .localeCompare(String(y == null ? '' : y).toLowerCase());
        });
        if (s.dir === 'desc') out.reverse();
        return out;
    }
    function th(tab, def, by, label, cls) {
        var s = getSort(tab, def);
        var mark = s.by === by ? (s.dir === 'asc' ? ' ↑' : ' ↓') : '';
        return '<th class="th-sort' + (cls ? ' ' + cls : '') + '" data-pl-sort="' + tab + ':' + by + '">'
            + esc(label) + mark + '</th>';
    }

    function agoText(sec) {
        sec = +sec;
        if (!isFinite(sec) || sec < 0) return '';
        if (sec < 60) return sec + 's ago';
        if (sec < 3600) return Math.round(sec / 60) + 'm ago';
        if (sec < 86400) return Math.round(sec / 3600) + 'h ago';
        return Math.round(sec / 86400) + 'd ago';
    }
    // State of the agent, not of the checked host. "silent" = no confirmation within its freshness time;
    // its results then count as unknown, not unavailable, so rules don't switch on it (docs/25 §6).
    function stateBadge(t) {
        if (!t.enabled) return '<span class="pill muted" data-tip="Switched off in the panel. It is not '
                             + 'given any checks, and its answers count as no data.">disabled</span>';
        // Never connected is "waiting", not "silent": the fix is starting the agent, not finding a break.
        if (!t.last_seen_at) return '<span class="pill muted" data-tip="Approved, but has never connected '
                                  + 'yet — start the agent on that machine.">waiting</span>';
        var ago = agoText(t.last_seen_age);
        if (t.state === 'online') {
            return '<span class="pill ok" data-tip="Confirming its work on time' + (ago ? ' — last heard '
                 + esc(ago) : '') + '.">online</span>';
        }
        return '<span class="pill warn" data-tip="Not reporting for longer than its «confirm within» time. '
             + 'Results from this agent count as no data — conditions that use it are undecided, and a rule '
             + 'does not switch because an observer went missing.">silent</span>'
             + (ago ? ' <span class="text-mute">' + esc(ago) + '</span>' : '');
    }
    function rulesCell(n) {
        n = +n || 0;
        return n ? '<b>' + n + '</b>' : '<span class="text-mute">0</span>';
    }

    // Pending agents get their own card, shown only when there are any.
    function pendingCard(rows) {
        if (!rows.length) return '';
        return '<div class="pl-card"><div class="plist-head"><span>Waiting for approval</span></div>'
            + '<div class="table-wrap"><table class="data-table"><thead><tr>'
            + '<th>Host name</th><th>Code</th><th>Address</th><th>Version</th><th>Last seen</th>'
            + '<th class="right">Actions</th></tr></thead><tbody>'
            + rows.map(function (t) {
                return '<tr><td><b>' + esc(t.hostname || '—') + '</b></td>'
                    + '<td class="mono">' + esc(t.code || '—') + '</td>'
                    + '<td class="mono">' + esc(t.addr || '—') + '</td>'
                    + '<td>' + esc(t.agent_version || '—') + '</td>'
                    + '<td class="mono">' + esc(t.last_seen_at || '—') + '</td>'
                    + '<td class="right">'
                    + '<a href="#" class="link" data-t-approve="' + t.id + '">Approve</a>'
                    + '<a href="#" class="link" data-t-del="' + t.id + '" style="margin-left:.6rem;color:var(--danger);">Delete</a>'
                    + '</td></tr>';
            }).join('')
            + '</tbody></table></div></div>';
    }
    function testersTab() {
        var def = { by: 'name', dir: 'asc' };
        var all = D.testers || [];
        var pend = all.filter(function (t) { return t.pending; });
        var live = all.filter(function (t) { return !t.pending; });
        var rows = sorted(live, 'testers', def, function (t, by) {
            if (by === 'rules') return +t.in_rules || 0;
            if (by === 'state') return t.enabled ? t.state : 'disabled';
            return t[by];
        }).map(function (t) {
            return '<tr><td><b>' + esc(t.name) + '</b></td>'
                + '<td>' + esc(t.location || '—') + '</td>'
                + '<td>' + stateBadge(t) + '</td>'
                + '<td>' + agentDayCell(t.id) + '</td>'
                + '<td class="mono">' + esc(t.addr || '—') + '</td>'
                + '<td>' + esc(t.groups_label || '—') + '</td>'
                + '<td>' + rulesCell(t.in_rules) + '</td>'
                + '<td class="right">'
                + '<a href="#" class="link" data-t-edit="' + t.id + '">Edit</a>'
                + '<a href="#" class="link" data-t-del="' + t.id + '" style="margin-left:.6rem;color:var(--danger);">Delete</a>'
                + '</td></tr>';
        }).join('') || '<tr><td colspan="8" class="text-dim">No agents yet — install one and it '
                     + 'appears here.</td></tr>';

        return pendingCard(pend)
            + '<div class="pl-card"><div class="plist-head"><span>Agents</span><span>'
            + '<button class="btn btn-ghost sm" data-g-manage>Manage groups</button> '
            + '<button class="btn btn-primary sm" data-t-config>Agent config</button></span></div>'
            + '<div class="table-wrap"><table class="data-table"><thead><tr>'
            + th('testers', def, 'name', 'Name') + th('testers', def, 'location', 'Location')
            + th('testers', def, 'state', 'State')
            + '<th data-tip="On air, silent or switched off over the last day">24h</th>'
            + '<th>Address</th>' + '<th>Groups</th>' + th('testers', def, 'rules', 'In rules')
            + '<th class="right">Actions</th>'
            + '</tr></thead><tbody>' + rows + '</tbody></table></div></div>';
    }

    // Rules tab lists every saved rule, including turned-off ones; it opens the same builder as the
    // record page. The filter lives in module state so it survives re-renders.
    var RF = { q: '', zone: 'all', type: 'all', state: 'all' };
    // Filter key drops the branch number: users filter by "switched", not by "on rule 2".
    function ruleStateKey(r) {
        var st = ruleStateLabel(r);
        return st.indexOf('rule ') === 0 ? 'rule' : (st === 'switched' ? 'rule' : st);
    }
    function rulesFilter() {
        var q = RF.q.toLowerCase(), shown = 0;
        document.querySelectorAll('[data-rf-row]').forEach(function (tr) {
            var ok = (!q || tr.getAttribute('data-hay').indexOf(q) >= 0)
                  && (RF.zone === 'all' || tr.getAttribute('data-zone') === RF.zone)
                  && (RF.type === 'all' || tr.getAttribute('data-type') === RF.type)
                  && (RF.state === 'all' || tr.getAttribute('data-state') === RF.state);
            tr.hidden = !ok; if (ok) shown++;
        });
        var none = document.querySelector('[data-rf-empty]');
        if (none) none.hidden = shown > 0;
    }
    function rulesTab() {
        var def = { by: 'record', dir: 'asc' };
        var all = D.rules || [];
        var rows = sorted(all, 'rules', def, function (r, by) {
            if (by === 'zone') return r.zone || '';
            if (by === 'type') return r.rr_type;
            if (by === 'state') return ruleStateLabel(r);
            return r.rr_name;
        }).map(function (r) {
            var st = ruleStateLabel(r);
            return '<tr data-rf-row data-zone="' + esc(r.zone || '') + '" data-type="' + esc(r.rr_type) + '"'
                + ' data-state="' + esc(ruleStateKey(r)) + '" data-hay="'
                + esc(((r.zone || '') + ' ' + r.rr_name + ' ' + r.rr_type).toLowerCase()) + '">'
                + '<td>' + esc(r.zone || '—') + '</td>'
                + '<td class="mono"><a href="#" class="link" data-r-open="' + r.id + '">'
                + esc(r.rr_name) + '</a></td>'
                + '<td>' + esc(r.rr_type) + '</td>'
                + '<td><span class="pill ' + (st === 'off' ? 'muted' : 'ok') + '">' + esc(st) + '</span></td>'
                + '<td class="mono text-dim">' + esc(r.primary_label || '—') + '</td>'
                + '<td class="text-mute">' + plural(+r.branches || 0, 'rule') + ' · '
                + plural(+r.conditions || 0, 'condition') + '</td>'
                + '<td class="mono text-dim">' + esc(r.last_switch_at || '—') + '</td></tr>';
        }).join('') || '<tr><td colspan="7" class="text-dim">Nothing is set up yet — open a record and '
                     + 'click its Pulse badge.</td></tr>';
        var states = uniq(all, function (r) { return ruleStateKey(r); });
        var bar = '<div class="pl-pick-bar">'
            + '<input class="field-input pl-pick-q" data-rf-q value="' + esc(RF.q)
            + '" placeholder="Search zone or record…">'
            + pickSelect('rf_zone', uniq(all, function (r) { return r.zone; }), 'Zone: all', RF.zone)
            + pickSelect('rf_type', uniq(all, function (r) { return r.rr_type; }), 'Type: all', RF.type)
            + pickSelect('rf_state', states, 'Pulse state: all', RF.state)
            + '</div>';
        return '<div class="pl-card"><div class="plist-head"><span>Rules</span></div>'
            + '<div class="pl-card-bar">' + bar + '</div>'
            + '<div class="table-wrap"><table class="data-table"><thead><tr>'
            + th('rules', def, 'zone', 'Zone') + th('rules', def, 'record', 'Record')
            + th('rules', def, 'type', 'Type') + th('rules', def, 'state', 'State')
            + '<th>Default set</th><th>Logic</th><th>Last switch</th>'
            + '</tr></thead><tbody>' + rows
            + '<tr data-rf-empty hidden><td colspan="7" class="text-dim">Nothing matches.</td></tr>'
            + '</tbody></table></div></div>';
    }

    // History: stored state segments and rule events laid out on one time scale; nothing is recomputed.
    var HIST = { window: '1d', data: null, loading: false, err: '', open: {} };
    var HIST_WINDOWS = [ ['1d', 'Day'], ['1w', 'Week'], ['1m', 'Month'] ];
    function tms(x) { return Date.parse(String(x).replace(' ', 'T') + 'Z'); }
    function whenText(x) { return isNaN(tms(x)) ? String(x) : window.DNSPanel.fmtTime(new Date(tms(x)).toISOString()); }
    function lastText(ms) {
        var s = Math.round(ms / 1000);
        if (s < 60) return s + 's';
        if (s < 3600) return Math.round(s / 60) + 'm';
        if (s < 86400) return (Math.round(s / 360) / 10) + 'h';
        return (Math.round(s / 8640) / 10) + 'd';
    }
    // Same state words as the rest of the section.
    var SEG_LABEL = { healthy: 'available', degraded: 'degraded', down: 'unavailable',
                      unknown: 'no data', none: 'not measured',
                      // agent's own state
                      online: 'online', silent: 'silent', disabled: 'switched off',
                      // condition outcomes, same words as the branch verdict
                      met: 'condition met', not: 'not met', undecided: 'undecided' };
    // The bar is a fixed number of ticks (a time grid, as on status pages), not one span per transition.
    function tickState(segs, a, b) {
        var by = {}, seen = false, best = null;
        (segs || []).forEach(function (s) {
            var x = Math.max(tms(s.from), a), y = Math.min(tms(s.to), b);
            if (y <= x) return;
            seen = true;
            by[s.state] = (by[s.state] || 0) + (y - x);
            if (best === null || WORST[s.state] > WORST[best]) best = s.state;
        });
        return { state: seen ? (best || 'unknown') : 'none', by: by, mixed: Object.keys(by).length > 1 };
    }
    function ticksHtml(segs, from, to, count, who) {
        var span = (to - from) || 1, step = span / count, out = '';
        for (var i = 0; i < count; i++) {
            var a = from + step * i, b = (i === count - 1) ? to : from + step * (i + 1);
            var t = tickState(segs, a, b);
            // Tooltip: states in this tick with durations first, then whose it is, then the interval.
            var lines = [];
            if (t.state === 'none') lines.push(SEG_LABEL.none);
            else {
                Object.keys(t.by).sort(function (x, y) { return t.by[y] - t.by[x]; }).forEach(function (st) {
                    lines.push((SEG_LABEL[st] || st) + ' · ' + lastText(t.by[st]));
                });
            }
            if (who) lines.push(who);
            lines.push(whenText(isoOf(a)) + ' – ' + whenText(isoOf(b)).split(/,?\s+/).pop());
            out += '<span class="pl-tick st-' + esc(t.state) + (t.mixed ? ' is-mixed' : '') + '"'
                 + ' data-tip="' + esc(lines.join('\n')) + '"></span>';
        }
        return '<div class="pl-bar">' + out + '</div>';
    }
    // Which state wins when a tick or moment has several: the worst for a check, "met" for a condition.
    // One table covers all state kinds; a missing key would silently compare undefined with undefined.
    // A check's bar is the worst answer among its agents; it is grey only when all are silent.
    var WORST = { unknown: 0, healthy: 1, degraded: 2, down: 3,
                  not: 0, undecided: 1, met: 2,
                  // silent matters; disabled was a deliberate action
                  disabled: 0, online: 1, silent: 2 };
    function mergeAgents(agents, from, to) {
        var marks = {};
        (agents || []).forEach(function (a) {
            (a.segments || []).forEach(function (s) {
                marks[Math.max(tms(s.from), from)] = 1;
                marks[Math.min(tms(s.to), to)] = 1;
            });
        });
        var pts = Object.keys(marks).map(Number).filter(function (t) { return t >= from && t <= to; })
            .sort(function (x, y) { return x - y; });
        if (!pts.length || pts[0] > from) pts.unshift(from);
        if (pts[pts.length - 1] < to) pts.push(to);
        var out = [];
        for (var i = 0; i < pts.length - 1; i++) {
            var a = pts[i], b = pts[i + 1], best = null, seen = false;
            (agents || []).forEach(function (ag) {
                (ag.segments || []).forEach(function (s) {
                    if (tms(s.from) > a || tms(s.to) <= a) return;
                    seen = true;
                    if (best === null || WORST[s.state] > WORST[best]) best = s.state;
                });
            });
            if (!seen) continue;                       // nobody observed: leave a "not measured" gap
            var st = best || 'unknown';
            var last = out[out.length - 1];
            if (last && last.state === st && tms(last.to) === a) { last.to = isoOf(b); continue; }
            out.push({ state: st, from: isoOf(a), to: isoOf(b) });
        }
        return out;
    }
    function isoOf(ms) { return new Date(ms).toISOString().replace('T', ' ').slice(0, 19); }
    // DNS switches drawn as marks over the bar. onlyRule limits them to one rule (inside the builder a check
    // may serve many rules); on the History tab all are shown and the tooltip names the record.
    function marksHtml(events, from, to, onlyRule) {
        var span = to - from || 1;
        return (events || []).filter(function (e) {
            return !onlyRule || +e.rule_id === +onlyRule;
        }).map(function (e) {
            var at = tms(e.at);
            if (at < from || at > to) return '';
            var left = (at - from) / span * 100;
            // Multi-line tooltip: sets with several values are unreadable on one line.
            var lines = [ whenText(e.at) ];
            if (!onlyRule) lines.push(e.rr_name + ' / ' + e.rr_type);   // several records share this bar
            if (e.reason) lines.push('', e.reason);
            lines.push('', 'Before', setLines(e.from_set), 'After', setLines(e.to_set));
            return '<span class="pl-mark" style="left:' + left.toFixed(4) + '%" data-tip="'
                + esc(lines.join('\n')) + '"></span>';
        }).join('');
    }
    // Events store a set as "a | b"; show one value per line.
    function setLines(set) {
        var v = String(set == null ? '' : set).split('|').map(function (x) { return x.trim(); })
            .filter(function (x) { return x.length; });
        return v.length ? v.join('\n') : '—';
    }
    function histRow(c, from, to) {
        var open = !!HIST.open[c.id];
        var agents = c.agents || [];
        return '<div class="pl-hrow">'
            + '<button type="button" class="pl-hname" data-hist-open="' + c.id + '">'
            + '<span class="pl-hchev">' + (open ? '▾' : '▸') + '</span><b>' + esc(c.name) + '</b> '
            + '<span class="mono text-mute">' + esc(checkLabel(c)) + '</span> '
            + '<span class="text-mute">' + plural(agents.length, 'agent') + '</span></button>'
            + '<div class="pl-htrack">' + ticksHtml(mergeAgents(agents, from, to), from, to, 96,
                                                    plural(agents.length, 'agent'))
            + marksHtml(c.events, from, to) + '</div>'
            + (open ? agents.map(function (a) {
                return '<div class="pl-hsub"><span class="pl-hname2">' + esc(a.name) + '</span>'
                     + '<div class="pl-htrack">' + ticksHtml(a.segments, from, to, 96, a.name)
                     + '</div></div>';
              }).join('') : '')
            + '</div>';
    }
    // 24h overview bar for tables; a separate fetch because the History tab window is user-selected.
    var DAY = { data: null, loading: false };
    async function dayLoad() {
        DAY.loading = true;
        try {
            var res = await api('pulse/history?window=1d');
            DAY.data = (res && res.data) || res;
        } catch (e) { DAY.data = null; }
        DAY.loading = false;
        if (TAB === 'checks' || TAB === 'agents' || RULE) render();
    }
    function dayEnsure() { if (!DAY.data && !DAY.loading) dayLoad(); }
    // The agent's own online/silent/disabled bar, separate from check history.
    function agentDayCell(id) {
        if (!DAY.data) return '<span class="text-mute">…</span>';
        var t = byId(DAY.data.testers, id);
        if (!t) return '<span class="text-mute">—</span>';
        var from = tms(DAY.data.from), to = tms(DAY.data.to);
        return '<div class="pl-htrack pl-mini">' + ticksHtml(t.segments, from, to, 48, '') + '</div>';
    }
    function dayCell(id) {
        if (!DAY.data) return '<span class="text-mute">…</span>';
        var c = byId(DAY.data.checks, id);
        if (!c) return '<span class="text-mute">—</span>';
        var from = tms(DAY.data.from), to = tms(DAY.data.to);
        return '<div class="pl-htrack pl-mini">'
             + ticksHtml(mergeAgents(c.agents, from, to), from, to, 48,
                          plural((c.agents || []).length, 'agent'))
             + marksHtml(c.events, from, to) + '</div>';
    }

    function historyTab() {
        var bar = '<div class="pl-pick-bar"><div class="seg">'
            + HIST_WINDOWS.map(function (w) {
                return '<button type="button" class="seg-btn' + (HIST.window === w[0] ? ' active' : '')
                     + '" data-hist-win="' + w[0] + '">' + w[1] + '</button>';
            }).join('') + '</div>'
            + '<span class="pl-hlegend">' + ['healthy', 'degraded', 'down', 'unknown', 'none'].map(function (st) {
                return '<span class="pl-lg"><i class="pl-tick st-' + st + '"></i>' + SEG_LABEL[st] + '</span>';
            }).join('') + '</span></div>';
        var body;
        if (HIST.err) body = '<p class="pl-note">' + esc(HIST.err) + '</p>';
        else if (!HIST.data) body = '<p class="pl-note">Loading…</p>';
        else {
            var from = tms(HIST.data.from), to = tms(HIST.data.to);
            body = (HIST.data.checks || []).map(function (c) { return histRow(c, from, to); }).join('')
                || '<p class="pl-note">No checks yet.</p>';
            body += '<div class="pl-hscale"><span>' + esc(whenText(HIST.data.from)) + '</span>'
                 + '<span>now</span></div>';
        }
        return '<div class="pl-card"><div class="plist-head"><span>History</span></div>'
            + '<div class="pl-card-bar">' + bar + '</div>'
            + '<div class="pl-hist">' + body + '</div></div>';
    }
    async function histLoad() {
        HIST.loading = true; HIST.err = '';
        try {
            var res = await api('pulse/history?window=' + encodeURIComponent(HIST.window));
            HIST.data = (res && res.data) || res;
        } catch (e) { HIST.err = (e && e.message) || 'Could not read the history'; }
        HIST.loading = false;
        if (TAB === 'history') render();
    }
    function histEnsure() { if (!HIST.data && !HIST.loading) histLoad(); }

    function checksTab() {
        var def = { by: 'name', dir: 'asc' };
        var rows = sorted(D.checks || [], 'checks', def, function (c, by) {
            if (by === 'rules') return +c.in_rules || 0;
            if (by === 'target') return c.target_ip;
            if (by === 'every') return +c.interval_seconds || 0;
            return c[by];
        }).map(function (c) {
            var who = pairsFor(c).length;
            return '<tr><td><b>' + esc(c.name) + '</b></td>'
                + '<td>' + esc(c.kind.toUpperCase()) + '</td>'
                + '<td class="mono">' + esc(c.target_ip) + (c.port ? ':' + c.port : '') + '</td>'
                + '<td>' + esc(c.interval_seconds) + 's</td>'
                + '<td>' + dayCell(c.id) + '</td>'
                + '<td>' + rulesCell(c.in_rules) + '</td>'
                + '<td>' + esc(c.groups_label || '—')
                + (who ? '' : ' <span class="pill warn" data-tip="Nobody runs this check: its groups have no agents.">nobody runs it</span>')
                + '</td>'
                + '<td class="right">'
                + '<a href="#" class="link" data-c-groups="' + c.id + '">Runs on</a>'
                + '<a href="#" class="link" data-c-edit="' + c.id + '" style="margin-left:.6rem;">Edit</a>'
                + '<a href="#" class="link" data-c-del="' + c.id + '" style="margin-left:.6rem;color:var(--danger);">Delete</a>'
                + '</td></tr>';
        }).join('') || '<tr><td colspan="7" class="text-dim">No checks yet.</td></tr>';

        return '<div class="pl-card"><div class="plist-head"><span>Checks</span>'
            + '<button class="btn btn-primary sm" data-c-add>+ Add check</button></div>'
            + '<div class="table-wrap"><table class="data-table"><thead><tr>'
            + th('checks', def, 'name', 'Name') + th('checks', def, 'kind', 'Type')
            + th('checks', def, 'target', 'Target') + th('checks', def, 'every', 'Every')
            + '<th data-tip="What its agents answered over the last day. Worst answer of them at each '
            + 'moment; hatched means nobody measured. Ticks are DNS switches of rules that use it.">24h</th>'
            + th('checks', def, 'rules', 'In rules') + '<th>Runs on</th>'
            + '<th class="right">Actions</th>'
            + '</tr></thead><tbody>' + rows + '</tbody></table></div></div>';
    }

    function condText(cond) {
        if (cond.kind === 'schedule') {
            var bits = [];
            if (cond.days_mask != null) {
                var d = [];
                for (var i = 0; i < 7; i++) if ((cond.days_mask >> i) & 1) d.push(DAYS[i]);
                bits.push(d.length === 7 ? 'every day' : d.join(' '));
            }
            if (cond.time_from) bits.push(cond.time_from.slice(0, 5) + '–' + (cond.time_to || '').slice(0, 5));
            if (cond.date_from || cond.date_to) bits.push((cond.date_from || '…') + ' → ' + (cond.date_to || '…'));
            return 'Schedule: ' + bits.join(', ');
        }
        return checkLabel(byId(D.checks, cond.check_id)) + ' · ' + aggText(cond);
    }
    // Aggregation must be visible in the branch line: "any of 20" and "all of 20" are different conditions.
    function aggText(cond) {
        var ts = condTesters(cond), n = ts.length;
        if (!n) return 'no agents';
        // "All agents running the check" follows the check's membership, unlike the same list picked by hand.
        var who = cond.all_testers ? 'its ' + n + ' agents' : (n === 1 ? '1 agent' : n + ' agents');
        if (n === 1 && !cond.all_testers) return ts[0].name || ('#' + ts[0].tester_id);
        if (cond.agg === 'all') return 'all of ' + who;
        if (cond.agg === 'at_least') return 'at least ' + (+cond.agg_n || 1) + ' of ' + who;
        return 'any of ' + who;
    }
    // Live answer right now. The what-if preview must never leak in here: this is the only place that
    // shows the real state; the preview changes the conclusion, not the observation.
    var NOW_LABEL = { up: 'available', degraded: 'degraded', down: 'unavailable', unknown: 'no data' };
    function nowBadge(cond) {
        var ts = condTesters(cond);
        if (!ts.length) return '';
        // Show what is observed, not how many match the condition ("0/2 unavailable" read as a failure).
        var by = {}, order = [];
        ts.forEach(function (x) {
            var st = NOW_LABEL[pairState(cond, x, true)] || 'no data';
            if (!by[st]) { by[st] = 0; order.push(st); }
            by[st]++;
        });
        var text = (ts.length === 1) ? order[0]
            : (order.length === 1 ? ts.length + '/' + ts.length + ' ' + order[0]
                                  : order.map(function (st) { return by[st] + ' ' + st; }).join(' · '));
        var per = ts.map(function (x) {
            return (x.name || ('#' + x.tester_id)) + ': ' + (NOW_LABEL[pairState(cond, x, true)] || '');
        }).join(', ');
        return ' <span class="pl-now" data-tip="What this check reports right now — ' + esc(per)
             + '. Trying other states in «Check the logic» does not change it.">' + esc(text) + '</span>';
    }
    // A previewed branch's verdict is hypothetical; flag it next to the verdict.
    function branchPreviewed(br) {
        return (br.conditions || []).some(function (c) {
            if (c.kind === 'schedule') return !!PREVIEW[schedKey(c)];
            return condTesters(c).some(function (x) { return !!PREVIEW[pairKey(c, x.tester_id)]; });
        });
    }
    // The bar inside a condition shows whether THIS condition held, not the worst agent answer: with
    // "all of 2" one down agent is red on the check bar but the condition is not met. Uses the engine's
    // three-valued aggregation.
    function condSeries(cond, agents, from, to) {
        var marks = {};
        (agents || []).forEach(function (a) {
            (a.segments || []).forEach(function (sg) {
                marks[Math.max(tms(sg.from), from)] = 1;
                marks[Math.min(tms(sg.to), to)] = 1;
            });
        });
        var pts = Object.keys(marks).map(Number).filter(function (t) { return t >= from && t <= to; })
            .sort(function (x, y) { return x - y; });
        if (!pts.length || pts[0] > from) pts.unshift(from);
        if (pts[pts.length - 1] < to) pts.push(to);
        var n = +cond.agg_n || 1, out = [];
        for (var i = 0; i < pts.length - 1; i++) {
            var a = pts[i], b = pts[i + 1], yes = 0, no = 0, unknown = 0, seen = false;
            (agents || []).forEach(function (ag) {
                var st = null;
                (ag.segments || []).forEach(function (sg) {
                    if (tms(sg.from) <= a && tms(sg.to) > a) st = sg.state;
                });
                if (st === null) return;            // this pair did not exist at that moment
                seen = true;
                var v = pairVerdict(liveState({ live_state: st }), cond.expect);
                if (v === 'true') yes++; else if (v === 'false') no++; else unknown++;
            });
            if (!seen) continue;                    // nobody observed: leave an empty cell
            var st2;
            if (cond.agg === 'all')      st2 = no ? 'not' : (unknown ? 'undecided' : 'met');
            else if (cond.agg === 'at_least') st2 = (yes >= n) ? 'met'
                                                  : ((yes + unknown < n) ? 'not' : 'undecided');
            else                         st2 = yes ? 'met' : (unknown ? 'undecided' : 'not');
            var last = out[out.length - 1];
            if (last && last.state === st2 && tms(last.to) === a) { last.to = isoOf(b); continue; }
            out.push({ state: st2, from: isoOf(a), to: isoOf(b) });
        }
        return out;
    }
    function dayStrip(cond) {
        if (!DAY.data) return '';
        var c = byId(DAY.data.checks, cond.check_id);
        if (!c) return '';
        var from = tms(DAY.data.from), to = tms(DAY.data.to);
        // No tooltip on the strip itself: in the gaps between ticks it would hide the tick's own tooltip.
        return '<span class="pl-htrack pl-strip">'
             + ticksHtml(condSeries(cond, c.agents, from, to), from, to, 48,
                          aggText(cond) + ' · when ' + cond.expect)
             + marksHtml(c.events, from, to, RULE && RULE.id) + '</span>';
    }
    function condHtml(bi, ci, cond) {
        var v = condVerdict(cond);
        var right = cond.kind === 'schedule'
            ? '<span class="pl-state ' + (v === 'true' ? 'ok' : 'bad') + '" data-tip="The clock in '
              + esc(RULE.schedule_tz) + ' answers this, and «Check the logic» below can try the other answer. '
              + 'A schedule is always decidable — there is no «no data» in a clock.">'
              + (v === 'true' ? 'in window' : 'outside') + '</span>'
            // Requirement ("when ...") and the live answer side by side, so the former isn't read as the state.
            : '<button type="button" class="pl-state ' + (cond.expect === 'available' ? 'ok' : 'bad') + '"'
              + ' data-cond-flip="' + bi + ':' + ci + '"'
              + ' data-tip="Which state of this check makes the condition true. There is no NOT here on purpose:'
              + ' «no data» is a third state, and negation cannot express it.">when ' + esc(cond.expect) + '</button>'
              + nowBadge(cond);
        // Flag orphaned conditions: they wait for a result that will never come.
        var lost = condTesters(cond).filter(function (x) { return x.assigned === 0; }).length;
        var broken = cond.orphaned
            ? ' <span class="pill err" data-tip="No agent of this condition runs this check any more — it can '
              + 'never become true. Open the condition and pick agents that run it.">orphaned</span>'
            // Some observers no longer run the check: "any of 20" silently became "any of 3".
            : lost ? ' <span class="pill muted" data-tip="These agents no longer run this check, so they never '
                   + 'answer. Open the condition to fix the list.">' + lost + ' not running</span>' : '';
        return '<div class="pl-cond" data-b="' + bi + '" data-c="' + ci + '">'
            + '<button type="button" class="pl-cond-what mono" data-cond-edit="' + bi + ':' + ci + '"'
            + '>' + esc(condText(cond)) + '</button>' + broken
            + (cond.kind === 'check' ? dayStrip(cond) : '') + right
            + '<button type="button" class="icon-btn pl-x" data-cond-del="' + bi + ':' + ci + '" aria-label="Remove condition">×</button>'
            + '</div>';
    }
    // "Applies" differs from "matches": a shadowed branch may match too; only one is the winner.
    function branchHtml(bi, br, verdict, shadowed, winner) {
        var cls = 'pl-branch' + (winner ? ' is-winner' : '') + (verdict === 'true' ? ' is-match' : '')
                + (shadowed ? ' is-shadowed' : '');
        var conds = (br.conditions || []).map(function (c, ci) { return condHtml(bi, ci, c); }).join('')
            || '<div class="pl-empty">No conditions yet — undecided, so nothing below is applied. '
               + 'A branch with no conditions cannot be saved.</div>';
        // draggable only on the grip: on the whole card it breaks text selection inside the inputs.
        return '<section class="' + cls + '" data-branch="' + bi + '">'
            + '<div class="pl-branch-head">'
            + '<span class="pl-grip" draggable="true">⠿</span>'
            + '<span class="pl-num">' + (bi + 1) + '</span>'
            + '<b>If</b>'
            + '<span class="pl-verdict pl-v-' + verdict + '">'
            + (winner ? 'applies' : verdict.replace('true', 'matches').replace('false', 'does not match').replace('unknown', 'undecided'))
            + '</span>'
            + (branchPreviewed(br) ? '<span class="pl-now" data-tip="This verdict comes from states tried '
                                   + 'in «Check the logic», not from what is happening now.">⚗ preview</span>' : '')
            + '<span class="pl-head-act">'
            + '<button type="button" class="icon-btn" data-branch-up="' + bi + '" aria-label="Move up">↑</button>'
            + '<button type="button" class="icon-btn" data-branch-down="' + bi + '" aria-label="Move down">↓</button>'
            + '<button type="button" class="icon-btn" data-branch-del="' + bi + '" aria-label="Remove rule">×</button>'
            + '</span></div>'
            + '<div class="pl-match">'
            + '<div class="seg">'
            + '<button type="button" class="seg-btn' + (br.match_mode === 'any' ? ' active' : '') + '" data-branch-match="' + bi + ':any">Any · OR</button>'
            + '<button type="button" class="seg-btn' + (br.match_mode === 'all' ? ' active' : '') + '" data-branch-match="' + bi + ':all">All · AND</button>'
            + '</div><span class="text-mute">of the conditions are true</span></div>'
            + '<div class="pl-conds">' + conds + '</div>'
            + '<button type="button" class="btn btn-ghost sm pl-add-cond" data-cond-add="' + bi + '">+ Add check</button> '
            + '<button type="button" class="btn btn-ghost sm pl-add-cond" data-sched-add="' + bi + '">+ Add schedule</button>'
            + '<div class="pl-then"><span>Publish ' + esc(RULE.rr_type) + '</span>'
            + valuesHtml(bi, br.values)
            + '<div class="pl-hold"><span>after</span>'
            + '<input class="field-input sm pl-sec" value="' + esc(br.hold_seconds) + '" data-branch-hold="' + bi + '" inputmode="numeric">'
            + '<span class="text-mute">s of the same state</span></div></div>'
            + '</section>';
    }
    // Value set editor: fields per type (MX: pref + host, SRV: four fields, others: one value).
    function valuesHtml(bi, vals) {
        vals = (vals && vals.length) ? vals : [ { content: '' } ];
        var t = RULE.rr_type;
        var rows = vals.map(function (v, vi) {
            var fields = '';
            if (t === 'MX') {
                fields = '<input class="field-input sm pl-prio" value="' + esc(v.prio == null ? '' : v.prio)
                       + '" data-val="' + bi + ':' + vi + ':prio" inputmode="numeric" placeholder="pref">'
                       + '<input class="field-input sm mono pl-ip" value="' + esc(v.content || '')
                       + '" data-val="' + bi + ':' + vi + ':content" placeholder="mail host">';
            } else if (t === 'SRV') {
                var x = String(v.content || '').split(/\s+/);
                var f = function (k, val, ph, num) {
                    return '<input class="field-input sm ' + (num ? 'pl-prio' : 'mono pl-ip') + '" value="'
                         + esc(val == null ? '' : val) + '" data-val="' + bi + ':' + vi + ':' + k + '"'
                         + (num ? ' inputmode="numeric"' : '') + ' placeholder="' + ph + '">';
                };
                fields = f('prio', v.prio, 'prio', 1) + f('w', x[0], 'weight', 1)
                       + f('p', x[1], 'port', 1) + f('t', x[2], 'target');
            } else {
                fields = '<input class="field-input sm mono pl-ip" value="' + esc(v.content || '')
                       + '" data-val="' + bi + ':' + vi + ':content" placeholder="' + esc(placeholderFor(t)) + '">';
            }
            return '<div class="pl-val">' + fields
                + (vals.length > 1
                    ? '<button type="button" class="icon-btn pl-x" data-val-del="' + bi + ':' + vi + '" aria-label="Remove value">×</button>'
                    : '')
                + '</div>';
        }).join('');
        // CNAME is always a single value.
        var more = (t === 'CNAME') ? ''
            : '<button type="button" class="btn btn-ghost sm" data-val-add="' + bi + '">+ value</button>';
        return '<div class="pl-vals">' + rows + more + '</div>';
    }
    function placeholderFor(t) {
        if (t === 'A') return '10.0.0.1';
        if (t === 'AAAA') return '2001:db8::1';
        if (t === 'TXT') return 'text';
        return 'host name';
    }

    // Show a value set split into labelled parts, with the same labels as the records page Parameters column.
    function valueParts(type, v) {
        var c = String(v.content == null ? '' : v.content);
        var p = (v.prio == null || v.prio === '') ? '' : v.prio;
        if (type === 'MX')  return [ ['Priority', p], ['Target', c] ];
        if (type === 'SRV') {
            var x = c.split(/\s+/);
            return [ ['Priority', p], ['Weight', x[0]], ['Port', x[1]], ['Target', x[2]] ];
        }
        return [ ['', c] ];
    }
    function valueSetHtml(type, values, tip) {
        var rows = (values || []).map(function (v) {
            return '<div class="pl-setline">' + valueParts(type, v).map(function (kv) {
                return (kv[0] ? '<span class="pl-set-k">' + esc(kv[0]) + '</span>' : '')
                     + '<span class="pl-set-v mono">' + esc((kv[1] == null || kv[1] === '') ? '—' : kv[1])
                     + '</span>';
            }).join(' ') + '</div>';
        }).join('');
        return '<div class="pl-set"' + (tip ? ' data-tip="' + esc(tip) + '"' : '') + '>'
             + (rows || '<span class="text-mute">—</span>') + '</div>';
    }

    function defaultHtml(active) {
        return '<section class="pl-branch pl-default' + (active ? ' is-winner' : '') + '">'
            + '<div class="pl-branch-head"><span class="pl-lock" data-tip="This one is always last">🔒</span>'
            + '<b>Otherwise — the default set</b>'
            + '<span class="text-mute">always last</span>'
            + (RULE.state === 'default' ? '<span class="pill ok" data-tip="The record holds the default '
                                        + 'set right now.">published now</span>' : '')
            + '<span class="pl-q" data-tip="Applies only when every rule above is proven false. '
            + 'When data is missing the record stays as it is: losing sight of an agent is not an event.">?</span>'
            + '</div>'
            + '<div class="pl-then"><span>Publish</span>'
            + valueSetHtml(RULE.rr_type, RULE.values,
                'The default set is the record as it was when the rule was created. '
              + 'Change the record itself to change it.')
            + '<span>after</span>'
            + '<input class="field-input sm pl-sec" value="' + esc(RULE.default_hold_seconds) + '" data-default-hold inputmode="numeric">'
            + '<span class="text-mute">s of the same state</span></div>'
            + '</section>';
    }
    // Preview inputs are only what this rule's conditions ask about, not everything measured in the panel.
    var CHECK_OPTS = [ ['up', 'Available'], ['degraded', 'Degraded'],
                       ['down', 'Unavailable'], ['unknown', 'No data'] ];
    var SCHED_OPTS = [ ['in', 'In window'], ['out', 'Outside'] ];
    function ruleInputs() {
        var seen = {}, out = [];
        (RULE.branches || []).forEach(function (br) {
            (br.conditions || []).forEach(function (c) {
                var sched = c.kind === 'schedule';
                var key = sched ? schedKey(c) : (c.check_id + '#' + condTesters(c).map(function (x) {
                    return x.tester_id; }).sort().join(','));
                if (seen[key]) return;
                seen[key] = 1;
                // Preview is per observer ("what if 3 of 20 say down"): a switch for all plus a chip for each.
                out.push({ key: key, label: condText(c), sched: sched, cond: c,
                           opts: sched ? SCHED_OPTS : CHECK_OPTS,
                           now: sched ? (scheduleTrue(c) === 'true' ? 'in' : 'out') : null });
            });
        });
        return out;
    }
    // Live pair state by key; rule conditions are the only source of live answers in the builder.
    function realPairState(key) {
        var found = 'unknown';
        (RULE.branches || []).forEach(function (br) {
            (br.conditions || []).forEach(function (c) {
                if (c.kind === 'schedule') return;
                condTesters(c).forEach(function (x) {
                    if (pairKey(c, x.tester_id) === key) found = liveState(x);
                });
            });
        });
        return found;
    }
    function chipHtml(cond, x) {
        var st = pairState(cond, x), real = pairState(cond, x, true);
        return '<button type="button" class="pl-chip pl-st-' + st + (st === real ? '' : ' is-tried') + '"'
            + ' data-prev-cycle="' + esc(pairKey(cond, x.tester_id)) + '"'
            + ' data-tip="' + esc((x.name || ('#' + x.tester_id)) + ' reports ' + (NOW_LABEL[real] || real)
                + ' right now') + '">'
            + esc(x.name || ('#' + x.tester_id)) + '<span class="pl-chip-st">' + esc(NOW_LABEL[st] || st)
            + '</span></button>';
    }
    function prowHtml(p) {
        var keys, st;
        if (p.sched) { keys = [p.key]; st = PREVIEW[p.key] || p.now; }
        else {
            keys = condTesters(p.cond).map(function (x) { return pairKey(p.cond, x.tester_id); });
            // The "all" switch is active only when every observer is in the same state.
            var all = condTesters(p.cond).map(function (x) { return pairState(p.cond, x); });
            st = all.length && all.every(function (v) { return v === all[0]; }) ? all[0] : null;
        }
        var seg = '<div class="seg">' + p.opts.map(function (o) {
            return '<button type="button" class="seg-btn' + (st === o[0] ? ' active' : '')
                 // Comma separator: schedule keys already contain "|".
                 + '" data-prev-keys="' + esc(keys.join(',')) + '" data-prev-to="' + o[0] + '">'
                 + o[1] + '</button>';
        }).join('') + '</div>';
        var chips = (!p.sched && keys.length > 1)
            ? '<div class="pl-chips">' + condTesters(p.cond).map(function (x) {
                  return chipHtml(p.cond, x); }).join('') + '</div>'
            : '';
        return '<div class="pl-prow"><span class="mono">' + esc(p.label) + '</span>' + seg + '</div>' + chips;
    }
    function previewHtml(d) {
        var rows = ruleInputs().map(prowHtml).join('')
            || '<p class="pl-note">This rule has no conditions yet — there is nothing to try.</p>';
        var line = d.address
            ? '<span class="pl-out">→ ' + valueSetHtml(RULE.rr_type, d.set) + '</span> · ' + esc(d.why)
            : '<b>→ no change</b> · ' + esc(d.why);
        var reset = Object.keys(PREVIEW).length
            ? '<button type="button" class="btn btn-ghost sm pl-reset" data-pl-reset>Back to reality</button>' : '';
        return '<section class="pl-preview"><div class="pl-branch-head"><span>⚗</span><b>Check the logic</b>'
            + '<span class="pl-q" data-tip="Outcome for steady states. Timers are not counted here and DNS '
            + 'is not changed.">?</span>' + (reset ? '<span class="pl-head-act">' + reset + '</span>' : '')
            + '</div>'
            + rows
            + '<div class="pl-outcome">' + line + '</div>'
            + '</section>';
    }
    // Snapshot of the whole form, including the default hold: one form, one save.
    function draftJSON() { return JSON.stringify({ b: RULE.branches, h: RULE.default_hold_seconds }); }
    function dirty() { return draftJSON() !== CLEAN; }
    // Clone candidates: any other rule; with a different record type only the logic is copied.
    function cloneCandidates() {
        return (D.rules || []).filter(function (r) { return r.id !== RULE.id; });
    }
    function actionsHtml() {
        var d = dirty(), out = '';
        // Save is always shown (disabled when clean). Toggles are disabled while dirty: they reload the rule
        // from the server and would silently drop the edits.
        if (cloneCandidates().length) out += '<button class="btn btn-ghost sm" data-r-clone>Clone from…</button> ';
        if (RULE.id && (RULE.branches || []).length) {
            out += '<button class="btn btn-ghost sm" data-r-clone-to' + (d ? ' disabled' : '') + '>Clone to…</button> ';
        }
        if (RULE.id) {
            out += '<button class="btn btn-ghost sm" data-r-drop' + (d ? ' disabled' : '') + '>Remove setup</button> '
                 + '<button class="btn btn-ghost sm" data-r-toggle' + (d ? ' disabled' : '') + '>'
                 + (RULE.enabled ? 'Turn off' : 'Turn on') + '</button> ';
        }
        return out + '<button class="btn btn-primary sm" data-r-save' + ((BUSY || !d) ? ' disabled' : '') + '>'
             + (BUSY ? 'Saving…' : 'Save') + '</button>';
    }
    function headRightHtml() { return actionsHtml(); }
    // Field edits don't re-render the builder (Tab would lose focus); only buttons and the preview update.
    function syncDerived() {
        var a = document.getElementById('pl-acts');
        if (a) a.innerHTML = headRightHtml();
        var p = document.getElementById('pl-prev');
        if (p) p.innerHTML = previewHtml(decide());
    }
    function builderHtml() {
        var d = decide();
        var brs = (RULE.branches || []).map(function (br, i) {
            return branchHtml(i, br, branchVerdict(br), d.shadowed.indexOf(i) >= 0, d.winner === i);
        }).join('');
        return '<div class="pl-builder">' + downHtml() + '<div class="pl-head"><div><div class="pl-crumb">'
            + '<button class="btn btn-ghost sm" data-r-back>← Close</button></div>'
            + '<h1 class="pl-title">' + esc(RULE.rr_name) + ' <span class="text-mute">/ ' + esc(RULE.rr_type) + '</span></h1></div>'
            + '<div class="pl-head-right" id="pl-acts">' + headRightHtml() + '</div></div>'
            + '<p class="pl-hint">↓ First match from the top wins'
            + '<span class="pl-q" data-tip="Drag by the handle or use the arrows to reorder. The order is '
            + 'behaviour, not layout: a matching rule keeps the ones below it shadowed.">?</span></p>'
            + '<div class="pl-branches">' + brs + '</div>'
            + '<button type="button" class="btn btn-ghost pl-add" data-branch-add>+ Add rule</button>'
            + defaultHtml(d.winner === null && d.undecidedAt === null)
            + '<div id="pl-prev">' + previewHtml(d) + '</div></div>';
    }

    // Closing just removes the overlay; the originating page is still underneath.
    async function closeRule() {
        if (dirty() && !(await P().confirm({ title: 'Unsaved changes', danger: true, okText: 'Discard',
                message: 'The logic was changed but not saved. Close and discard it?' }))) return;
        RULE = null; CLEAN = null; PREVIEW = {};
        try { if (document.getElementById('pulse-root')) await reload(); } catch (e) {}
        render();
    }

    // Draft edits stay local until Save.
    function move(from, to) {
        var b = RULE.branches;
        if (to < 0 || to >= b.length) return;
        b.splice(to, 0, b.splice(from, 1)[0]);
        render();
    }
    function num(v, def) { var n = parseInt(v, 10); return (isFinite(n) && n >= 0) ? n : def; }

    // Opened from the records page there is no section payload yet; fetch it once.
    async function ensureData() {
        if (D) return;
        var res = await api('pulse');
        D = (res && res.data) || res;
    }
    async function reload() {
        var res = await api('pulse');
        D = (res && res.data) || res;
        render();
    }
    // For an RRset without a rule the server returns a draft; nothing is stored until the first save.
    async function openRule(path) {
        var res = await api(path);
        RULE = ((res && res.data) || res).rule;
        RULE.branches = RULE.branches || [];
        CLEAN = draftJSON();
        PREVIEW = {};
        render();
    }
    async function saveBranches() {
        BUSY = true; render();
        try {
            // The only place a rule gets created.
            if (!RULE.id) {
                var made = await api('pulse/rules', { method: 'POST', body: JSON.stringify({
                    domain_id: RULE.domain_id, rr_name: RULE.rr_name, rr_type: RULE.rr_type,
                    default_hold_seconds: RULE.default_hold_seconds }) });
                RULE.id = ((made && made.data) || made).id;
            }
            // Branches and the default hold are saved together.
            var res = await api('pulse/rules/' + RULE.id + '/branches',
                { method: 'PUT', body: JSON.stringify({ branches: RULE.branches,
                    default_hold_seconds: RULE.default_hold_seconds }) });
            RULE = ((res && res.data) || res).rule;
            RULE.branches = RULE.branches || [];
            CLEAN = draftJSON();
        } catch (e) { fail(e); }
        BUSY = false; render();
    }

    // Copies the logic (branches, conditions, modes, holds). The default set is never copied, it comes from
    // the record itself; branch values are copied only for the same record type.
    function cloneBranches(src, sameType) {
        return (src || []).map(function (b) {
            return {
                match_mode: b.match_mode === 'all' ? 'all' : 'any',
                hold_seconds: b.hold_seconds,
                values: sameType
                    ? (b.values || []).map(function (v) { return { content: v.content, prio: v.prio }; })
                    : [ { content: '' } ],
                conditions: (b.conditions || []).map(function (c) {
                    return c.kind === 'schedule'
                        ? { kind: 'schedule', days_mask: c.days_mask, time_from: c.time_from,
                            time_to: c.time_to, date_from: c.date_from, date_to: c.date_to }
                        : { kind: 'check', check_id: c.check_id, expect: c.expect,
                            agg: c.agg || 'any', agg_n: c.agg_n || 1, all_testers: c.all_testers ? 1 : 0,
                            testers: condTesters(c).map(function (x) { return x.tester_id; }) };
                }),
            };
        });
    }
    // Same state words as the records table.
    function ruleStateLabel(r) {
        if (!r.enabled) return 'off';
        if (r.state === 'held') return 'held';
        if (r.state === 'switched') return r.active_branch_no ? 'rule ' + r.active_branch_no : 'switched';
        return 'default';
    }
    // Show the source rule's logic before it overwrites the current one.
    function ruleSummaryHtml(r) {
        var brs = (r.branches || []).map(function (b, i) {
            var conds = (b.conditions || []).map(function (c) {
                return '<li>' + esc(condText(c)) + (c.kind === 'check' ? ' · is ' + esc(c.expect) : '') + '</li>';
            }).join('') || '<li class="text-mute">no conditions</li>';
            return '<h4>Rule ' + (i + 1) + ' · ' + (b.match_mode === 'all' ? 'all of' : 'any of') + '</h4>'
                 + '<ul>' + conds + '</ul>'
                 + '<div class="pl-setrow">→ ' + valueSetHtml(r.rr_type, b.values)
                 + '<span class="text-mute">after ' + esc(b.hold_seconds) + ' s</span></div>';
        }).join('');
        return '<h4>' + esc(r.rr_name) + ' / ' + esc(r.rr_type) + '</h4>'
             + (brs || '<p class="text-mute">This setup has no rules yet.</p>')
             + '<h4>Otherwise</h4><div class="mono">→ the default set after '
             + esc(r.default_hold_seconds) + ' s</div>';
    }
    // Both clone dialogs share one layout: search + filters, table, selection preview.
    function pickSelect(name, vals, label, cur) {
        var opts = [ { value: 'all', label: label } ].concat(
            vals.map(function (v) { return { value: v, label: v }; }));
        return P().selectHtml(name, opts, cur || 'all');
    }
    function uniq(list, f) {
        var seen = {}, out = [];
        list.forEach(function (x) { var v = f(x); if (v && !seen[v]) { seen[v] = 1; out.push(v); } });
        return out.sort();
    }
    function pickBarHtml(inner) {
        return '<div class="pl-pick-bar">'
            + '<input class="field-input pl-pick-q" data-pick-q placeholder="Search zone or record…">'
            + inner + '</div>';
    }
    function pickVal(ov, name) {
        var el = ov && ov.querySelector('input[name="' + name + '"]');
        return el ? el.value : 'all';
    }
    function pickFilter(ov) {
        var q = ((ov.querySelector('[data-pick-q]') || {}).value || '').trim().toLowerCase();
        var z = pickVal(ov, 'pick_zone_f'), t = pickVal(ov, 'pick_type_f'), shown = 0;
        ov.querySelectorAll('tbody tr[data-hay]').forEach(function (tr) {
            var ok = (!q || tr.getAttribute('data-hay').indexOf(q) >= 0)
                  && (z === 'all' || tr.getAttribute('data-zone') === z)
                  && (t === 'all' || tr.getAttribute('data-type') === t);
            tr.hidden = !ok; if (ok) shown++;
        });
        var none = ov.querySelector('[data-pick-empty]');
        if (none) none.hidden = shown > 0;
    }

    async function cloneFromForm() {
        var cand = cloneCandidates();
        var rows = cand.map(function (r) {
            var same = r.rr_type === RULE.rr_type;
            return '<tr data-pick-row="' + r.id + '" data-zone="' + esc(r.zone || '') + '"'
                + ' data-type="' + esc(r.rr_type) + '" data-hay="'
                + esc(((r.zone || '') + ' ' + r.rr_name + ' ' + r.rr_type).toLowerCase()) + '">'
                + '<td><label><input type="radio" name="src" value="' + r.id + '" data-pick="' + r.id + '"> '
                + esc(r.zone || '—') + '</label></td>'
                + '<td class="mono">' + esc(r.rr_name) + '</td>'
                + '<td>' + esc(r.rr_type) + '</td>'
                + '<td>' + (same ? 'Full' : '<span class="pill muted">Logic only</span>') + '</td>'
                + '<td><span class="pill muted">' + esc(ruleStateLabel(r)) + '</span></td>'
                + '<td class="text-mute">' + plural(+r.branches || 0, 'rule') + ' · '
                + plural(+r.conditions || 0, 'condition') + '</td>'
                + '</tr>';
        }).join('');
        var v = await P().dialog({
            title: 'Clone from', okText: 'Clone', wide: true,
            message: pickBarHtml(
                    pickSelect('pick_zone_f', uniq(cand, function (r) { return r.zone; }), 'Zone: all')
                  + pickSelect('pick_type_f', uniq(cand, function (r) { return r.rr_type; }), 'Type: all'))
                + '<div class="pl-pick-list"><table><thead><tr>'
                + '<th>Zone</th><th>Record</th><th>Type</th><th>Copy</th><th>State</th><th>Logic</th>'
                + '</tr></thead><tbody>' + rows + '</tbody></table>'
                + '<div class="pl-pick-none" hidden data-pick-empty>Nothing matches.</div></div>'
                + '<div class="pl-pick-prev" data-pick-prev><span class="text-mute">Pick a record to see its '
                + 'setup.</span></div>',
        });
        if (!v || !v.src) return;
        try {
            var res = await api('pulse/rules/' + v.src);
            var src = ((res && res.data) || res).rule;
            RULE.branches = cloneBranches(src.branches, src.rr_type === RULE.rr_type);
            RULE.default_hold_seconds = src.default_hold_seconds;
            PREVIEW = {};
            render();
        } catch (e) { fail(e); }
    }

    // Clone to many records; values are copied only for the same type, and each row says what will be copied.
    var CLONE_TO = [], PICKED_TO = [];
    async function loadCloneTargets(zoneId) {
        var box = document.querySelector('[data-pick-body]');
        if (!box) return;
        box.innerHTML = '<tr><td colspan="5" class="text-mute">Loading…</td></tr>';
        try {
            var res = await api('pulse/zones/' + zoneId + '/records');
            var all = ((res && res.data) || res).records || [];
            var zone = byId(D.zones, zoneId) || {};
            CLONE_TO = all.filter(function (c) {
                return !(c.name === RULE.rr_name && c.type === RULE.rr_type && +zoneId === +RULE.domain_id);
            }).map(function (c) { c.domain_id = +zoneId; c.zone = zone.name; return c; });
        } catch (e) { CLONE_TO = []; fail(e); }
        box.innerHTML = CLONE_TO.map(function (c, i) {
            var busy = !!c.rule_id, same = c.type === RULE.rr_type;
            return '<tr data-type="' + esc(c.type) + '" data-hay="'
                + esc((c.name + ' ' + c.type).toLowerCase()) + '">'
                + '<td><label><input type="checkbox" data-pick-to="' + i + '"' + (busy ? ' disabled' : '') + '> '
                + '<span class="mono">' + esc(c.name) + '</span></label></td>'
                + '<td>' + esc(c.type) + '</td>'
                + '<td>' + (same ? 'Full' : '<span class="pill muted">Logic only</span>') + '</td>'
                + '<td class="mono text-mute">' + esc(c.values || '—') + '</td>'
                + '<td>' + (busy ? '<span class="pill warn">configured</span>'
                                 : '<span class="pill muted">off</span>') + '</td>'
                + '</tr>';
        }).join('') || '<tr><td colspan="5" class="text-mute">No other records here that Pulse can manage.</td></tr>';
        var ov = document.getElementById('modal-overlay');
        if (ov) pickFilter(ov);
    }
    async function cloneToForm() {
        var zopts = (D.zones || []).map(function (z) { return { value: String(z.id), label: z.name }; });
        if (!zopts.length) { P().alert({ title: 'Clone to', message: 'No zone here can be written.' }); return; }
        PICKED_TO = [];
        var dlg = P().dialog({
            title: 'Clone this setup to', okText: 'Clone', wide: true,
            message: pickBarHtml(P().selectHtml('pick_zone', zopts, String(RULE.domain_id))
                  + pickSelect('pick_type_f', D.rr_types || [], 'Type: all'))
                + '<div class="pl-pick-list"><table><thead><tr>'
                + '<th><label><input type="checkbox" data-pick-all> Record</label></th>'
                + '<th>Type</th><th>Copy</th><th>Now published</th><th>Pulse</th>'
                + '</tr></thead><tbody data-pick-body><tr><td colspan="5" class="text-mute">Loading…</td></tr>'
                + '</tbody></table>'
                + '<div class="pl-pick-none" hidden data-pick-empty>Nothing matches.</div></div>'
                + '<label class="pl-pick-over"><input type="checkbox" name="__over" data-pick-over> '
                + 'Also replace the setups already there</label>',
        });
        // Don't await the dialog first: its promise resolves only on close, but its markup is already in the DOM.
        loadCloneTargets(RULE.domain_id);
        var over = false, v = await dlg;
        if (!v) { CLONE_TO = []; PICKED_TO = []; return; }
        over = !!v.__over;
        var targets = PICKED_TO.map(function (i) { return CLONE_TO[i]; }).filter(Boolean)
            .map(function (c) {
                return { domain_id: c.domain_id, rr_name: c.name, rr_type: c.type, overwrite: over ? 1 : 0 };
            });
        CLONE_TO = []; PICKED_TO = [];
        if (!targets.length) return;
        try {
            // One server operation for all targets: it decides what is copied and logs a single audit event.
            var res = await api('pulse/rules/' + RULE.id + '/clone',
                { method: 'POST', body: JSON.stringify({ targets: targets }) });
            var out = (res && res.data) || res;
            await reload().catch(function () {});
            render();
            P().alert({ title: 'Cloned',
                message: (out.done.length ? 'Copied to <b>' + esc(out.done.join(', ')) + '</b>.'
                                          : 'Nothing was copied.')
                       + (out.failed.length ? '<p class="pl-note">Left alone: '
                            + esc(out.failed.map(function (f) { return f.target + ' — ' + f.error; }).join('; '))
                            + '</p>' : '')
                       + '<p class="pl-note">Each copy is switched off until you turn it on.</p>' });
        } catch (e) { fail(e); }
    }

    // Forms: no explanatory paragraphs; at most a one-sentence "?" tip. Details are in docs/25-ns-pulse.md.
    function fieldRow(label, html, tip) {
        return '<div class="dlg-row"><label class="dlg-lbl">' + esc(label)
            + (tip ? ' <span class="pl-q" data-tip="' + esc(tip) + '">?</span>' : '')
            + '</label>' + html + '</div>';
    }
    function textField(name, value, extra) {
        return '<input class="field-input" name="' + name + '" value="' + esc(value == null ? '' : value) + '"'
            + (extra || '') + '>';
    }
    function checkList(prefix, items, chosen) {
        var have = {}; (chosen || []).forEach(function (x) { have[x] = 1; });
        if (!items.length) return '<p class="text-dim">Nothing to pick yet.</p>';
        return '<div class="pl-picklist">' + items.map(function (i) {
            return '<label class="pl-pick"><input type="checkbox" name="' + prefix + i.id + '"'
                + (have[i.id] ? ' checked' : '') + '> ' + esc(i.name) + '</label>';
        }).join('') + '</div>';
    }
    function picked(vals, prefix) {
        var out = [];
        Object.keys(vals || {}).forEach(function (k) {
            if (k.indexOf(prefix) === 0 && vals[k]) out.push(+k.slice(prefix.length));
        });
        return out;
    }

    // One form for editing an agent and approving a pending one.
    async function testerForm(t, approving) {
        var v = await P().dialog({
            title: approving ? 'Approve agent' : 'Edit agent',
            okText: approving ? 'Approve' : 'Save',
            message: (approving
                    ? '<p class="pl-note">Host name <b class="mono">' + esc(t.hostname || '—') + '</b>'
                      + ' · code <b class="mono">' + esc(t.code || '—') + '</b>'
                      + ' · from <b class="mono">' + esc(t.addr || '—') + '</b></p>'
                    : '')
                + fieldRow('Name', textField('name', approving ? (t.hostname || '') : t.name,
                                             ' placeholder="frankfurt-1"'))
                + fieldRow('Location', textField('location', t && t.location, ' placeholder="DE, Frankfurt"'))
                + fieldRow('Confirm within, s',
                    textField('confirm_max_age_seconds', (t && t.confirm_max_age_seconds) || 90, ' inputmode="numeric"'),
                    'How long rules may decide on this agent\'s last data once it goes quiet. '
                  + 'Longer tolerates worse links; shorter keeps decisions from running on stale data.'),
        });
        if (!v) return;
        try {
            await api('pulse/testers/' + t.id + (approving ? '/approve' : ''),
                { method: approving ? 'POST' : 'PUT', body: JSON.stringify({
                    name: (v.name || '').trim(), location: (v.location || '').trim(),
                    confirm_max_age_seconds: num(v.confirm_max_age_seconds, 90) }) });
            await reload();
        } catch (e) { fail(e); }
    }

    // The agent config is the same on every machine (no per-agent secret; the agent generates its own key),
    // so it can be shown at any time.
    function agentConfText(srv) {
        return 'server      = "' + (srv.address || '<set the server address above>') + '"\n'
             + 'enroll_key  = "' + (srv.enroll_key || '') + '"\n'
             + 'fingerprint = "' + (srv.fingerprint || '') + '"\n'
             + 'log_level   = "info"';
    }
    async function copyText(txt) {
        try { if (navigator.clipboard && navigator.clipboard.writeText) { await navigator.clipboard.writeText(txt); return; } } catch (e) {}
        var ta = document.createElement('textarea'); ta.value = txt; ta.style.position = 'fixed'; ta.style.opacity = '0';
        document.body.appendChild(ta); ta.focus(); ta.select();
        try { document.execCommand('copy'); } catch (e) {}
        document.body.removeChild(ta);
    }
    async function configModal() {
        var srv = (D && D.server) || {};
        var v = await P().dialog({
            title: 'Agent config', okText: 'Save',
            message: fieldRow('Server address',
                    textField('address', srv.address, ' placeholder="pulse.example.net:7902" data-pl-addr'),
                    'Where agents dial in. One address for the pair — the service address, not a node.')
                + '<pre class="pl-token mono" id="pl-conf">' + esc(agentConfText(srv)) + '</pre>'
                + '<div class="pl-conf-act">'
                + '<button type="button" class="btn btn-ghost sm" data-pl-copy>Copy</button> '
                + '<button type="button" class="btn btn-ghost sm" data-pl-newkey>New key</button></div>'
                + '<p class="pl-note">The same file goes on every probing machine: there is nothing personal '
                + 'in it. An agent makes its own key on first start, dials in and waits here to be approved — '
                + 'its address and version appear then. A new key does not touch agents already approved.</p>',
        });
        if (!v) return;
        if ((v.address || '').trim() === (srv.address || '')) return;
        try {
            await api('pulse/server/address',
                { method: 'PUT', body: JSON.stringify({ address: (v.address || '').trim() }) });
            await reload();
        } catch (e) { fail(e); }
    }
    // Agent groups: list on the left, members and settings on the right, as server groups on Propagation.
    var GM = null;
    function gmGroups() { return D.groups || []; }
    function gmInit(sel) {
        var g = (sel === 'new') ? null : byId(gmGroups(), sel);
        GM.sel = g ? g.id : (sel === 'new' ? 'new' : null);
        GM.draft = { name: g ? g.name : '', description: (g && g.description) || '',
                     tids: g ? (g.member_ids || []).slice() : [] };
        GM.err = '';
    }
    function gmSideRow(g) {
        var n = (g.member_ids || []).length;
        return '<button type="button" class="gm-side-row' + (String(GM.sel) === String(g.id) ? ' selected' : '')
            + '" data-gm-sel="' + g.id + '">'
            + '<div class="gm-side-name">' + esc(g.name) + '</div>'
            + '<div class="gm-side-sub">' + plural(n, 'agent') + ' · ' + plural(+g.checks || 0, 'check')
            + '</div></button>';
    }
    function gmMembersHtml() {
        // Pending agents cannot be group members.
        var live = (D.testers || []).filter(function (t) { return !t.pending; });
        if (!live.length) return '<p class="text-mute">No approved agents yet.</p>';
        var rows = live.map(function (t) {
            var on = GM.draft.tids.indexOf(t.id) >= 0;
            return '<tr class="' + (on ? 'is-picked' : '') + '">'
                + '<td><label><input type="checkbox" data-gm-mem="' + t.id + '"' + (on ? ' checked' : '') + '> '
                + '<b>' + esc(t.name) + '</b></label></td>'
                + '<td class="text-dim">' + esc(t.location || '—') + '</td>'
                + '<td>' + stateBadge(t) + '</td></tr>';
        }).join('');
        return '<div class="pl-pick-list gm-tbl"><table><thead><tr>'
            + '<th>Agent</th><th>Location</th><th>State</th></tr></thead><tbody>'
            + rows + '</tbody></table></div>';
    }
    function gmChecksHtml(g) {
        var used = (D.checks || []).filter(function (c) {
            return (c.group_ids || []).indexOf(g.id) >= 0;
        });
        if (!used.length) {
            return '<p class="text-mute">No check is assigned to this group yet — agents in it measure '
                 + 'nothing.</p>';
        }
        return '<div class="pl-pick-list gm-tbl"><table><thead><tr>'
            + '<th>Name</th><th>Type</th><th>Target</th></tr></thead><tbody>'
            + used.map(function (c) {
                return '<tr><td><b>' + esc(c.name) + '</b></td>'
                     + '<td>' + esc(c.kind.toUpperCase()) + '</td>'
                     + '<td class="mono">' + esc(c.target_ip) + (c.port ? ':' + c.port : '') + '</td></tr>';
            }).join('') + '</tbody></table></div>';
    }
    function gmDetailHtml() {
        if (GM.sel === null) return '<div class="gm-empty">Pick a group, or use <b>+ New</b>.</div>';
        var isNew = GM.sel === 'new', g = isNew ? null : byId(gmGroups(), GM.sel);
        if (!isNew && !g) return '<div class="gm-empty">This group no longer exists.</div>';
        return '<div class="gm-edit">'
            + '<div class="frow"><label>Name</label>'
            + '<input class="field-input" data-gm="name" value="' + esc(GM.draft.name) + '" placeholder="europe"></div>'
            + '<div class="frow"><label>Description</label>'
            + '<input class="field-input" data-gm="description" value="' + esc(GM.draft.description)
            + '" placeholder="optional"></div>'
            + '<h4>Members</h4>'
            + '<p class="mini text-mute">Every agent here runs every check assigned to this group.</p>'
            + gmMembersHtml()
            + (isNew ? '' : '<h4>Checks assigned to this group</h4>' + gmChecksHtml(g))
            + (GM.err ? '<p class="pl-ce-err">' + esc(GM.err) + '</p>' : '')
            + '<div class="gm-foot' + (isNew ? ' end' : '') + '">'
            + (isNew ? '' : '<button type="button" class="btn btn-danger" data-gm-del="' + g.id + '">Delete group</button>')
            + '<button type="button" class="btn btn-primary" data-gm-save>'
            + (isNew ? 'Create group' : 'Save') + '</button></div></div>';
    }
    function gmRender() {
        var ov = document.getElementById('pulse-modal');
        if (!GM) { if (ov) ov.remove(); return; }
        if (!ov) {
            ov = document.createElement('div');
            ov.id = 'pulse-modal'; ov.className = 'dm-overlay';
            document.body.appendChild(ov);
        }
        var rows = gmGroups().map(gmSideRow).join('')
            || '<div class="text-mute" style="padding:.6rem;">No groups yet.</div>';
        ov.innerHTML = '<div class="dm-panel wide" role="dialog" aria-modal="true">'
            + '<div class="dm-head"><div class="dm-title">Agent groups</div>'
            + '<button class="icon-btn" data-gm-close aria-label="Close">×</button></div>'
            + '<div class="dm-body"><div class="gm-split">'
            + '<div class="gm-side"><div class="gm-side-head"><span>Groups</span>'
            + '<button type="button" class="btn btn-primary sm" data-gm-new>+ New</button></div>'
            + '<div class="gm-side-list">' + rows + '</div></div>'
            + '<div class="gm-detail">' + gmDetailHtml() + '</div>'
            + '</div></div>'
            + '<div class="dm-foot"><button type="button" class="btn btn-ghost" data-gm-close>Close</button></div></div>';
    }
    function groupsModal() {
        GM = { sel: null, draft: null, err: '' };
        gmInit(gmGroups().length ? gmGroups()[0].id : 'new');
        gmRender();
    }
    // One Save for name, description and members together.
    async function gmSave() {
        if (GM.busy) return;
        GM.busy = true; GM.err = '';
        var body = { name: (GM.draft.name || '').trim(), description: (GM.draft.description || '').trim() };
        try {
            var id = GM.sel;
            if (id === 'new') {
                var made = await api('pulse/groups', { method: 'POST', body: JSON.stringify(body) });
                id = ((made && made.data) || made || {}).id;
            } else {
                await api('pulse/groups/' + id, { method: 'PUT', body: JSON.stringify(body) });
            }
            await api('pulse/groups/' + id + '/members',
                { method: 'PUT', body: JSON.stringify({ testers: GM.draft.tids }) });
            await refreshData();
            GM.busy = false;
            gmInit(id);
        } catch (e) {
            GM.busy = false;
            GM.err = (e && e.message) || 'Could not save the group';
        }
        gmRender(); render();
    }
    async function gmDelete(id) {
        var g = byId(gmGroups(), id);
        if (!g) return;
        if (!(await P().confirm({ title: 'Delete group', danger: true, okText: 'Delete',
                message: 'Delete <b>' + esc(g.name) + '</b>? Checks assigned to it lose these agents, and '
                       + 'conditions that ask those agents stop being decidable until you fix them.' }))) return;
        try {
            await api('pulse/groups/' + id, { method: 'DELETE' });
            await refreshData();
            gmInit(gmGroups().length ? gmGroups()[0].id : 'new');
        } catch (e) { GM.err = (e && e.message) || 'Could not delete the group'; }
        gmRender(); render();
    }
    async function checkForm(c) {
        var kinds = [{ value: 'icmp', label: 'ICMP' }, { value: 'tcp', label: 'TCP' }];
        var v = await P().dialog({
            title: c ? 'Edit check' : 'Add check',
            okText: c ? 'Save' : 'Add',
            message: fieldRow('Name', textField('name', c && c.name, ' placeholder="gateway"'))
                + fieldRow('Type', P().selectHtml('kind', kinds, (c && c.kind) || 'icmp'))
                + fieldRow('Address', textField('target_ip', c && c.target_ip, ' placeholder="10.0.0.1"'),
                    'An address, not a name: a name is resolved by the very DNS this is meant to fix.')
                + fieldRow('Port (TCP only)', textField('port', c && c.port, ' inputmode="numeric"'))
                + fieldRow('Every, s', textField('interval_seconds', tim(c, 'interval_seconds'), ' inputmode="numeric"'))
                + fieldRow('Timeout, ms', textField('timeout_ms', tim(c, 'timeout_ms'), ' inputmode="numeric"'))
                + fieldRow('Probes per run', textField('probes_per_run', tim(c, 'probes_per_run'), ' inputmode="numeric"'))
                + fieldRow('OK probes needed', textField('ok_probes_required', tim(c, 'ok_probes_required'), ' inputmode="numeric"'))
                + fieldRow('Runs to fail', textField('fail_threshold', tim(c, 'fail_threshold'), ' inputmode="numeric"'))
                + fieldRow('Runs to recover', textField('ok_threshold', tim(c, 'ok_threshold'), ' inputmode="numeric"')),
        });
        if (!v) return;
        var body = { name: (v.name || '').trim(), kind: v.kind, target_ip: (v.target_ip || '').trim() };
        CE_TIMING_KEYS.forEach(function (k) { body[k] = num(v[k], tim(c, k)); });
        if (v.kind === 'tcp') body.port = num(v.port, 0);
        try {
            await api(c ? 'pulse/checks/' + c.id : 'pulse/checks',
                { method: c ? 'PUT' : 'POST', body: JSON.stringify(body) });
            await reload();
        } catch (e) { fail(e); }
    }
    // "Runs on" from the Checks tab reuses the same runners tree as the condition dialog.
    async function checkGroupsForm(c) {
        asgInit(c.id);
        var asked = P().dialog({
            title: 'Run «' + c.name + '» on', okText: 'Save', size: 'xl',
            message: '<div id="pl-ce-box"><div class="pl-ce-col" data-ce-col="agent">'
                   + '<p class="pl-note">Who runs this check. It belongs to the check, so saving this '
                   + 'changes every rule that uses it.</p>' + runnersTreeHtml({ save: false })
                   + '</div><div class="pl-ce-err" data-ce-err hidden></div></div>',
        });
        var v = await asked;
        if (v) await ceAssign();
        ASG = null;
        await reload();
    }
    // The same dialog both creates and edits a condition.
    function putCond(bi, ci, cond) {
        if (ci == null) RULE.branches[bi].conditions.push(cond);
        else            RULE.branches[bi].conditions[ci] = cond;
        render();
    }
    // Condition dialog: a condition is one check and any number of observers. Left: the check; right: who
    // runs it; bottom: expected state and aggregation.
    var CE = null;
    function ceCheck() { return byId(D.checks, CE.check_id); }
    function ceRunners() {
        var c = asgCheck() || (CE ? ceCheck() : null);
        return c ? pairsFor(c).map(function (p) { return byId(D.testers, p.tester_id); })
                       .filter(function (t) { return !!t; }) : [];
    }
    var CE_KINDS = [{ value: 'icmp', label: 'ICMP' }, { value: 'tcp', label: 'TCP' }];
    function ceChecksHtml() {
        // Edit inline in the row, add in the last row: the dialog has no second mode.
        var rows = (D.checks || []).map(function (c) {
            return String(CE.editing) === String(c.id) ? ceEditRow(c) : ceViewRow(c);
        }).join('');
        return '<input class="field-input sm" data-ce-q="check" placeholder="Search checks" autocomplete="off">'
            + '<div class="pl-pick-list pl-ce-table"><table><thead><tr>'
            + '<th>Name</th><th>Type</th><th>Target</th><th>Runs on</th><th></th>'
            + '</tr></thead><tbody>' + rows + ceNewRow() + '</tbody></table></div>'
            + '<p class="pl-note">A new check takes the usual timings — change them in Checks if needed. '
            + 'Press Edit on a row to change where a check runs.</p>';
    }
    // Groups and by-name agents are listed separately, then the total runner count.
    function runsLabel(c) {
        var bits = [];
        (c.group_ids || []).forEach(function (gid) {
            var g = byId(D.groups, gid);
            if (g) bits.push(g.name);
        });
        var named = (c.agent_ids || []).length;
        if (named) bits.push(plural(named, 'agent') + ' by name');
        return (bits.join(' + ') || '—') + ' · ' + plural(pairsFor(c).length, 'agent');
    }
    function ceViewRow(c) {
        var runs = pairsFor(c).length;
        return '<tr class="' + (String(CE.check_id) === String(c.id) ? 'is-picked' : '') + '"'
            + ' data-ce-hay="' + esc((c.name + ' ' + checkLabel(c) + ' '
                                      + (c.groups_label || '')).toLowerCase()) + '">'
            + '<td><label><input type="radio" name="ce_check" data-ce-check="' + c.id + '"'
            + (String(CE.check_id) === String(c.id) ? ' checked' : '') + '> '
            + '<b>' + esc(c.name) + '</b></label></td>'
            + '<td>' + esc(c.kind.toUpperCase()) + '</td>'
            + '<td class="mono">' + esc(c.target_ip) + (c.port ? ':' + c.port : '') + '</td>'
            + '<td class="text-dim">'
            + (runs ? esc(runsLabel(c)) : '<span class="pill warn">nobody runs it</span>') + '</td>'
            + '<td class="right"><button type="button" class="btn btn-ghost sm" data-ce-edit="' + c.id
            + '">Edit</button></td></tr>';
    }
    // Edit and add rows share field names, differing only by prefix.
    function ceFieldsHtml(pre, v) {
        return '<td>' + textField(pre + 'name', v.name, ' placeholder="name"') + '</td>'
            + '<td>' + P().selectHtml(pre + 'kind', CE_KINDS, v.kind || 'icmp') + '</td>'
            // Address and port share a cell via a wrapper (the cell itself must not become flex).
            // The port field is hidden for ICMP rather than silently discarding a typed value.
            + '<td><div class="pl-ce-target">' + textField(pre + 'ip', v.target_ip, ' placeholder="10.0.0.1"')
            + textField(pre + 'port', v.port, ' placeholder="port" inputmode="numeric" data-ce-port'
                        + (v.kind === 'tcp' ? '' : ' hidden'))
            + '</div></td>';
    }
    function ceEditRow(c) {
        // "Used by N rules" is a tooltip so it doesn't grow the row.
        var used = +c.in_rules || 0;
        var warn = used ? ' data-tip="This check is used by ' + plural(used, 'rule')
                        + ' — changing it changes them all."' : '';
        // Runners are edited in the tree on the right, not in the row.
        return '<tr class="is-editing" data-ce-hay=""' + warn + '>' + ceFieldsHtml('ce_e_', c)
            + '<td class="text-dim">' + esc(runsLabel(c)) + '</td>'
            + '<td class="right nowrap"><button type="button" class="btn btn-primary sm" data-ce-edit-save="'
            + c.id + '">Save</button> '
            + '<button type="button" class="icon-btn" data-ce-edit-cancel aria-label="Cancel">×</button>'
            + '</td></tr>';
    }
    function ceNewRow() {
        var d = CE.draft || {};
        d.kind = d.kind || 'icmp';
        return '<tr class="is-new" data-ce-hay="">' + ceFieldsHtml('ce_n_', d)
            + '<td class="text-mute">assign below</td>'
            + '<td class="right"><button type="button" class="btn btn-primary sm" data-ce-add>Add</button></td>'
            + '</tr>';
    }
    // Keep the half-typed add row across column re-renders.
    function ceReadDraft() {
        var g = function (n) { var el = document.querySelector('[name="' + n + '"]'); return el ? el.value : ''; };
        if (document.querySelector('[name="ce_n_name"]')) {
            CE.draft = { name: g('ce_n_name'), kind: g('ce_n_kind'), target_ip: g('ce_n_ip'), port: g('ce_n_port') };
        }
    }
    // Runners tree: groups with their agents, then agents in no group. A ticked group includes future
    // members. Every runner is an observer; there is no separate "who we listen to" list.
    function ceTree() {
        var seen = {}, groups = [];
        (D.groups || []).forEach(function (g) {
            var mem = (g.member_ids || []).map(function (tid) { return byId(D.testers, tid); })
                .filter(function (t) { return t && !t.pending; });
            mem.forEach(function (t) { seen[t.id] = 1; });
            groups.push({ id: g.id, name: g.name, members: mem });
        });
        var loose = (D.testers || []).filter(function (t) { return !t.pending && !seen[t.id]; });
        return { groups: groups, loose: loose };
    }
    // The assignment is a draft saved by a button, since it affects every rule using the check. The draft
    // lives in module state so the condition dialog and the Checks tab share one copy.
    var ASG = null, BUSY_ASG = false;
    function asgCheck() { return ASG ? byId(D.checks, ASG.check_id) : null; }
    function asgInit(cid) {
        var c = byId(D.checks, cid) || {};
        ASG = { check_id: cid, gids: (c.group_ids || []).slice(), tids: (c.agent_ids || []).slice() };
        return ASG;
    }
    function ceSaved() {
        var c = asgCheck() || {};
        return { gids: (c.group_ids || []).slice(), tids: (c.agent_ids || []).slice() };
    }
    function ceAssigned() {
        var want = CE ? CE.check_id : (ASG && ASG.check_id);
        if (!ASG || ASG.check_id !== want) asgInit(want);
        return ASG;
    }
    function ceAsgDirty() {
        var a = ceAssigned(), sv = ceSaved(), same = function (x, y) {
            return x.length === y.length && !x.some(function (v) { return y.indexOf(v) < 0; });
        };
        return !(same(a.gids, sv.gids) && same(a.tids, sv.tids));
    }
    // Same union as the server computes.
    function ceRunnersNow() { var c = ceCheck(); return c ? pairsFor(c).length : 0; }
    function ceAgentRow(t, viaName) {
        var a = ceAssigned();
        var on = viaName || a.tids.indexOf(t.id) >= 0;
        return '<label class="pl-ce-row pl-ce-leaf' + (on ? ' is-picked' : '') + (viaName ? ' is-off' : '')
            + '" data-ce-hay="' + esc(((t.name || '') + ' ' + (t.location || '')).toLowerCase()) + '">'
            + '<input type="checkbox" data-ce-agt="' + t.id + '"' + (on ? ' checked' : '')
            + (viaName ? ' disabled' : '') + '>'
            + '<span class="pl-ce-name">' + esc(t.name) + '</span>'
            + '<span class="text-mute">' + esc(t.location || '') + '</span>'
            + stateBadge(t)
            + (viaName ? ' <span class="text-mute">via ' + esc(viaName) + '</span>' : '') + '</label>';
    }
    // Own Save button only inside the condition dialog; in the standalone dialog the dialog's OK saves.
    function runnersTreeHtml(opt) {
        // Resolve the draft first: it determines which check this is about.
        var a = ceAssigned(), c = asgCheck();
        if (!c) return '<p class="text-mute">Pick a check first.</p>';
        var tree = ceTree();
        var html = tree.groups.map(function (g) {
            var on = a.gids.indexOf(g.id) >= 0;
            return '<div class="pl-ce-grp">'
                + '<label class="pl-ce-row pl-ce-head' + (on ? ' is-picked' : '') + '" data-ce-hay="'
                + esc(g.name.toLowerCase()) + '">'
                + '<input type="checkbox" data-ce-grp="' + g.id + '"' + (on ? ' checked' : '') + '>'
                + '<span class="pl-ce-name">' + esc(g.name) + '</span>'
                + '<span class="text-mute">' + plural(g.members.length, 'agent') + '</span>'
                + (on ? '<span class="mini text-mute">and whoever joins it later</span>' : '') + '</label>'
                + g.members.map(function (t) { return ceAgentRow(t, on ? g.name : null); }).join('')
                + '</div>';
        }).join('');
        if (tree.loose.length) {
            html += '<div class="pl-ce-grp"><div class="gms-sep">In no group</div>'
                 + tree.loose.map(function (t) { return ceAgentRow(t, null); }).join('') + '</div>';
        }
        if (!html) html = '<p class="text-mute">No agents yet — enrol one on the Agents tab.</p>';
        var d = ceAsgDirty();
        return '<input class="field-input sm" data-ce-q="agent" placeholder="Search agents" autocomplete="off">'
            + '<div class="pl-ce-act"><button type="button" class="btn btn-ghost sm" data-ce-all>All</button> '
            + '<button type="button" class="btn btn-ghost sm" data-ce-none>None</button></div>'
            + '<div class="pl-ce-list">' + html + '</div>'
            + ((opt && opt.save) ? '<div class="pl-ce-save">'
                + (d ? '<span class="pill warn">not saved</span> ' : '')
                + '<button type="button" class="btn btn-primary sm" data-ce-asg-save' + (d ? '' : ' disabled')
                + ' data-tip="Saves who runs this check. It belongs to the check, so it applies to every '
                + 'rule that uses it. The name, type and address are saved in the row on the left."'
                + '>Save assignment</button></div>' : '');
    }
    function ceAgentsHtml() { return runnersTreeHtml({ save: true }); }
    // Summary uses the same wording as the branch line.
    function ceSummaryHtml() {
        var cond = ceCond();
        var mark = ceDirty() ? ' <span class="pill warn" data-tip="This is not the condition you opened '
                             + 'any more. Save applies it; Cancel leaves the rule as it was.">changed</span>'
                             : '';
        if (!cond.check_id || !cond.testers.length) {
            return '<span class="text-mute">Pick a check and at least one agent.</span>' + mark;
        }
        return 'Reads as <b class="mono">' + esc(condText(cond)) + '</b> · when ' + esc(cond.expect) + mark;
    }
    function ceError(msg) {
        var el = document.querySelector('[data-ce-err]');
        if (!el) return;
        el.textContent = msg || '';
        el.hidden = !msg;
    }
    // Why the condition can't be applied yet, or null; recomputed on every change to disable OK inline.
    function ceWhyNot() {
        if (!CE.check_id) return 'Pick the check this condition is about.';
        // The condition uses the saved runners; applying with an unsaved tree would not match the screen.
        if (ceAsgDirty()) return 'Save assignment first — this condition uses the saved set of agents.';
        var n = ceRunnersNow();
        if (!n) return 'Nobody runs this check yet — tick a group or an agent on the right.';
        if (CE.agg === 'at_least' && CE.agg_n > n) {
            return '«At least ' + CE.agg_n + '» needs that many agents — this check runs on ' + n + '.';
        }
        return null;
    }
    function ceSync() {
        if (!CE) return;                          // summary and OK belong to the condition, not the tree
        var why = ceWhyNot();
        ceError(why);
        var ok = document.querySelector('#modal-overlay [data-dlg="ok"]');
        if (ok) ok.disabled = !!why;
        ceSum();
    }
    // Snapshot to tell "looked" from "changed", so the dialog can mark the condition as changed.
    function ceKey() {
        return JSON.stringify([ +CE.check_id || 0, CE.expect, CE.agg, +CE.agg_n || 1 ]);
    }
    function ceDirty() { return CE.clean != null && ceKey() !== CE.clean; }
    function ceCond() {
        // Observers are the check's runners; the server derives the same set.
        var c = ceCheck();
        return { kind: 'check', check_id: +CE.check_id || 0, expect: CE.expect, agg: CE.agg,
                 agg_n: CE.agg_n,
                 // Sorted by name so the condition reads the same regardless of group order.
                 testers: (c ? pairsFor(c) : []).slice().sort(function (x, y) {
                     var a = byId(D.testers, x.tester_id), b = byId(D.testers, y.tester_id);
                     return String(a ? a.name : x.tester_id).localeCompare(String(b ? b.name : y.tester_id));
                 }).map(function (p) {
                     var t = byId(D.testers, p.tester_id), was = (CE.live || {})[p.tester_id];
                     return { tester_id: p.tester_id, name: t ? t.name : '#' + p.tester_id,
                              live_state: was ? was.live_state : null, assigned: 1 };
                 }) };
    }
    function ceFootHtml() {
        var states = [{ value: 'unavailable', label: 'is unavailable' },
                      { value: 'degraded', label: 'is degraded' },
                      { value: 'available', label: 'is available' }];
        var aggs = [{ value: 'any', label: 'any agent' }, { value: 'all', label: 'all agents' },
                    { value: 'at_least', label: 'at least N agents' }];
        return '<div class="pl-ce-foot">'
            + '<div class="pl-ce-fld"><span class="dlg-lbl">True when the check</span>'
            + P().selectHtml('ce_expect', states, CE.expect) + '</div>'
            + '<div class="pl-ce-fld"><span class="dlg-lbl">and that is reported by</span>'
            + P().selectHtml('ce_agg', aggs, CE.agg)
            + '<input class="field-input sm pl-sec" name="ce_n" value="' + esc(CE.agg_n) + '"'
            + ' inputmode="numeric"' + (CE.agg === 'at_least' ? '' : ' hidden') + '>'
            + '<span class="pl-q" data-tip="One check asked of several agents. «No data» stays a third '
            + 'answer: a silent agent votes neither way, and until enough agents have answered the '
            + 'condition is undecided — it does not become false.">?</span></div>'
            + '<div class="pl-ce-sum" data-ce-sum>' + ceSummaryHtml() + '</div>'
            // Explain which button saves what: the assignment is shared, OK applies the condition to this rule.
            + '<div class="pl-ce-hint">«Save assignment» changes who runs this check — for every rule '
            + 'that uses it. This button applies the condition to the rule you opened.</div>'
            // Errors are shown inline: the shared alert renders into the same #modal-overlay and would
            // replace this dialog, losing the condition.
            + '<div class="pl-ce-err" data-ce-err hidden></div></div>';
    }
    var CE_HEAD = { check: 'Check', agent: 'Run this check on' };
    var CE_NOTE = 'Who runs this check — and therefore who answers this condition: the two are the same '
                + 'set. It belongs to the check, not to this condition, so saving it changes every rule '
                + 'that uses the check.';
    function ceHtml() {
        return '<div class="pl-ce">'
            + '<div class="pl-ce-col" data-ce-col="check"><h4>' + CE_HEAD.check + '</h4>'
            + ceChecksHtml() + '</div>'
            + '<div class="pl-ce-col" data-ce-col="agent"><h4>' + CE_HEAD.agent + '</h4>'
            + '<p class="pl-note">' + CE_NOTE + '</p>' + ceAgentsHtml() + '</div></div>' + ceFootHtml();
    }
    // Redraw inside the open dialog to keep scroll and search.
    function ceRedraw(what, opts) {
        var box = document.getElementById('pl-ce-box');
        if (!box) return;
        if (!CE && what !== 'agent') return;      // the standalone dialog has only the tree column
        if (!what) { box.innerHTML = ceHtml(); return; }
        var col = box.querySelector('[data-ce-col="' + what + '"]');
        if (!col) return;
        // Read the add-row draft before redrawing, except right after adding: then the row must be cleared.
        if (what === 'check' && !(opts && opts.freshDraft)) ceReadDraft();
        if (opts && opts.freshDraft) CE.draft = {};
        col.innerHTML = '<h4>' + CE_HEAD[what] + '</h4>'
            + (what === 'check' ? ceChecksHtml() : '<p class="pl-note">' + CE_NOTE + '</p>' + ceAgentsHtml());
        // Keep the search across the redraw.
        var q = col.querySelector('[data-ce-q]');
        if (q) { q.value = CE.q[what] || ''; ceFilter(what); }
        ceSync();
    }
    function ceSum() {
        var el = document.querySelector('[data-ce-sum]');
        if (el) el.innerHTML = ceSummaryHtml();
    }
    function ceFilter(kind) {
        var box = document.getElementById('pl-ce-box');
        var q = (CE.q[kind] || '').toLowerCase();
        if (!box) return;
        box.querySelectorAll('[data-ce-col="' + kind + '"] [data-ce-hay]').forEach(function (row) {
            row.hidden = !!q && row.getAttribute('data-ce-hay').indexOf(q) < 0;
        });
    }
    // Refetch without re-rendering the page under the dialog.
    async function refreshData() {
        var res = await api('pulse');
        D = (res && res.data) || res;
    }
    // Timings are not shown in the row, so the row must not change them: edits keep the check's own values,
    // new checks take the panel defaults (Settings -> Pinger & Pulse), never a copy hardcoded here.
    var CE_TIMING_KEYS = [ 'interval_seconds', 'timeout_ms', 'probes_per_run', 'ok_probes_required',
                           'fail_threshold', 'ok_threshold' ];
    function ceDefaults() { return (D && D.check_defaults) || {}; }
    function tim(c, k) { return (c && c[k] != null) ? c[k] : ceDefaults()[k]; }
    function ceBody(pre, cur) {
        var g = function (n) { var el = document.querySelector('[name="' + pre + n + '"]'); return el ? el.value : ''; };
        var body = { name: (g('name') || '').trim(), kind: g('kind') || 'icmp',
                     target_ip: (g('ip') || '').trim() };
        var def = ceDefaults();
        CE_TIMING_KEYS.forEach(function (k) {
            body[k] = (cur && cur[k] != null) ? +cur[k] : def[k];
        });
        if (body.kind === 'tcp') body.port = num(g('port'), 0);
        return body;
    }
    // Disable the buttons while the request runs so a double click doesn't create a duplicate check.
    function ceBusy(on) {
        CE.busy = on;
        document.querySelectorAll('[data-ce-add],[data-ce-edit-save]').forEach(function (b) {
            b.disabled = on;
            if (b.hasAttribute('data-ce-add')) b.textContent = on ? 'Adding…' : 'Add';
        });
    }
    // Saves the check's runners; this belongs to the check and applies to every rule using it.
    async function ceAssign() {
        var a = ceAssigned(), c = asgCheck();
        if (!c || BUSY_ASG) return;
        BUSY_ASG = true; ceError('');
        try {
            await api('pulse/checks/' + c.id + '/groups',
                { method: 'PUT', body: JSON.stringify({ groups: a.gids, agents: a.tids }) });
            await refreshData();
            ASG = null;                     // saved: drop the draft, read server state
        } catch (err) {
            BUSY_ASG = false; ceError((err && err.message) || 'Could not change who runs this check');
            ceRedraw('agent'); return;
        }
        BUSY_ASG = false;
        if (CE) ceRedraw('check');
        ceRedraw('agent');
        if (CE) ceSync();
    }
    async function ceCreateCheck() {
        if (CE.busy) return;
        ceBusy(true); ceError('');
        try {
            var made = await api('pulse/checks', { method: 'POST', body: JSON.stringify(ceBody('ce_n_')) });
            await refreshData();
            // Select the new check; it has no runners until assigned.
            CE.check_id = ((made && made.data) || made || {}).id || CE.check_id;
        } catch (err) {
            ceBusy(false); ceError((err && err.message) || 'Could not add the check'); return;
        }
        CE.busy = false;
        // freshDraft clears the add row; reading it back would restore the old DOM values.
        ceRedraw('check', { freshDraft: true }); ceRedraw('agent');
    }
    // Inline edit changes the shared check itself, not the condition.
    async function ceSaveCheck(id) {
        if (CE.busy) return;
        ceBusy(true); ceError('');
        try {
            await api('pulse/checks/' + id,
                { method: 'PUT', body: JSON.stringify(ceBody('ce_e_', byId(D.checks, id))) });
            await refreshData();
            CE.editing = null;
        } catch (err) {
            ceBusy(false); ceError((err && err.message) || 'Could not save the check'); return;
        }
        CE.busy = false;
        ceRedraw('check'); ceRedraw('agent');
    }
    async function condCheckForm(bi, ci) {
        var cur = (ci == null) ? null : RULE.branches[bi].conditions[ci];
        if (!(D.testers || []).length) {
            P().alert({ title: 'No agents yet',
                        message: 'A condition is a check asked of agents. Enrol an agent first — the Agents '
                               + 'tab has the command and the key.' });
            return;
        }
        var live = {};
        condTesters(cur || {}).forEach(function (x) { live[x.tester_id] = x; });
        CE = { check_id: cur ? cur.check_id : ((D.checks || [])[0] || {}).id,
               gids: (cur && cur.groups) ? cur.groups.slice() : [],
               tids: condTesters(cur || {})
                   .filter(function (x) { return !x.via_group; })
                   .map(function (x) { return x.tester_id; }),
               expect: cur ? cur.expect : 'unavailable',
               // Default "all": safer for DNS switching; one site's local trouble must not move the record.
               agg: (cur && cur.agg) || 'all', agg_n: (cur && cur.agg_n) || 1,
               live: live, q: {}, editing: null, draft: {}, clean: null, by: {} };
        if (cur) CE.clean = ceKey();
        // An invalid condition keeps OK disabled with the reason inline (an alert would replace the dialog).
        var asked = P().dialog({
            title: cur ? 'Check condition' : 'New check condition',
            okText: cur ? 'Apply to condition' : 'Add condition',
            size: 'xl', message: '<div id="pl-ce-box">' + ceHtml() + '</div>',
        });
        ceSync();                       // dialog is in the DOM now: disable OK if not valid yet
        var v = await asked;
        if (!v || ceWhyNot()) { CE = null; return; }
        putCond(bi, ci, ceCond());
        CE = null;
    }
    async function condSchedForm(bi, ci) {
        var cur = (ci == null) ? null : RULE.branches[bi].conditions[ci];
        var mask = (cur && cur.days_mask != null) ? cur.days_mask : 127;
        var hhmm = function (x) { return (x || '').slice(0, 5); };
        var days = DAYS.map(function (d, i) {
            return '<label class="pl-pick"><input type="checkbox" name="d_' + i + '"'
                 + (((mask >> i) & 1) ? ' checked' : '') + '> ' + d + '</label>';
        }).join('');
        var v = await P().dialog({
            title: cur ? 'Edit schedule condition' : 'Add schedule condition', okText: cur ? 'Save' : 'Add',
            message: fieldRow('Days', '<div class="pl-picklist">' + days + '</div>')
                // Native browser time/date inputs.
                + fieldRow('From', textField('time_from', cur ? hhmm(cur.time_from) : '', ' type="time"'))
                + fieldRow('To', textField('time_to', cur ? hhmm(cur.time_to) : '', ' type="time"'))
                + fieldRow('Date from', textField('date_from', cur && cur.date_from, ' type="date"'))
                + fieldRow('Date to', textField('date_to', cur && cur.date_to, ' type="date"')),
        });
        if (!v) return;
        var mask = 0;
        for (var i = 0; i < 7; i++) if (v['d_' + i]) mask |= (1 << i);
        var cond = { kind: 'schedule' };
        if (mask !== 127) cond.days_mask = mask;
        ['time_from', 'time_to', 'date_from', 'date_to'].forEach(function (k) {
            if ((v[k] || '').trim()) cond[k] = v[k].trim();
        });
        if (!cond.time_from !== !cond.time_to) {
            P().alert({ title: 'Half a window',
                        message: 'A time window needs both «from» and «to». One border alone applies to '
                               + 'nothing and the condition would quietly do nothing.' });
            return;
        }
        if (cond.days_mask == null && !cond.time_from && !cond.date_from && !cond.date_to) {
            P().alert({ title: 'Empty schedule',
                        message: 'A schedule condition needs at least one of: days, a time range, dates. Otherwise '
                               + 'it says nothing.' });
            return;
        }
        putCond(bi, ci, cond);
    }

    function attr(el, name) { var v = el.getAttribute(name); return v === null ? undefined : v; }

    document.addEventListener('click', async function (e) {
        var t = e.target.closest && e.target.closest('button, a.link, th[data-pl-sort]');
        if (!t) return;
        var v, p;

        // Condition dialog lives in the shared modal, so it uses the shared listener.
        if (ASG) {
            if (t.hasAttribute('data-ce-all') || t.hasAttribute('data-ce-none')) {
                var onAll = t.hasAttribute('data-ce-all'), tr = ceTree(), a3 = ceAssigned();
                a3.gids = onAll ? tr.groups.map(function (g) { return g.id; }) : [];
                a3.tids = onAll ? tr.loose.map(function (x) { return x.id; }) : [];
                ceRedraw('agent'); return;
            }
            if (t.hasAttribute('data-ce-asg-save')) { await ceAssign(); return; }
        }
        if (CE) {
            if (t.hasAttribute('data-ce-add')) { await ceCreateCheck(); return; }
            if ((v = attr(t, 'data-ce-edit')) !== undefined) { CE.editing = +v; ceRedraw('check'); return; }
            if (t.hasAttribute('data-ce-edit-cancel')) { CE.editing = null; ceRedraw('check'); return; }
            if ((v = attr(t, 'data-ce-edit-save')) !== undefined) { await ceSaveCheck(+v); return; }
        }

        // The record's Pulse badge opens the builder in place over the table; the link stays real for
        // middle-click.
        if ((v = attr(t, 'data-pulse-open')) !== undefined) {
            e.preventDefault();
            p = v.split('|');
            try {
                await ensureData();
                await openRule('pulse/zones/' + p[0] + '/rrset?name=' + encodeURIComponent(p[1])
                             + '&type=' + encodeURIComponent(p[2]));
            } catch (err) { fail(err); }
            return;
        }
        if (!D) return;
        if (t.tagName === 'A') e.preventDefault();

        if ((v = attr(t, 'data-pl-tab')) !== undefined) {
            TAB = v;
            try { localStorage.setItem('pulse.tab', v); } catch (e) {}
            render(); return;
        }
        if ((v = attr(t, 'data-pl-sort')) !== undefined) { p = v.split(':'); setSort(p[0], p[1]); return; }
        if (t.hasAttribute('data-g-manage')) { groupsModal(); return; }
        // History window is a query range, not a polling timer.
        if ((v = attr(t, 'data-hist-win')) !== undefined) {
            if (HIST.window !== v) { HIST.window = v; HIST.data = null; render(); histLoad(); }
            return;
        }
        if ((v = attr(t, 'data-hist-open')) !== undefined) {
            HIST.open[v] = !HIST.open[v]; render(); return;
        }

        if (t.hasAttribute('data-t-config')) { await configModal(); return; }
        if ((v = attr(t, 'data-t-edit')) !== undefined) { await testerForm(byId(D.testers, v)); return; }
        if ((v = attr(t, 'data-t-approve')) !== undefined) { await testerForm(byId(D.testers, v), true); return; }
        // Only one modal at a time, so "New key" is confirmed by a second click on the same button.
        if (t.hasAttribute('data-pl-copy')) {
            var pre = document.getElementById('pl-conf');
            if (pre) { await copyText(pre.textContent); t.textContent = 'Copied'; }
            return;
        }
        if (t.hasAttribute('data-pl-newkey')) {
            if (t.textContent !== 'Replace it?') { t.textContent = 'Replace it?'; return; }
            try {
                var nk = await api('pulse/enrollment/key', { method: 'POST' });
                D.server = ((nk && nk.data) || nk).server || D.server;
                var pc = document.getElementById('pl-conf');
                if (pc) pc.textContent = agentConfText(D.server);
                t.textContent = 'New key';
            } catch (err) { fail(err); }
            return;
        }
        if ((v = attr(t, 'data-t-del')) !== undefined) {
            var td = byId(D.testers, v);
            var msg = td.pending
                ? 'Drop the request from <b>' + esc(td.hostname || td.code || 'this host') + '</b>? While that '
                  + 'agent keeps running it will show up here again — stop it, or replace the enrollment key.'
                : 'Delete <b>' + esc(td.name) + '</b>? Conditions naming it are removed with it.';
            if (!(await P().confirm({ title: td.pending ? 'Drop request' : 'Delete agent', danger: true,
                                      okText: 'Delete', message: msg }))) return;
            try {
                var out = await api('pulse/testers/' + v, { method: 'DELETE' });
                var hit = (((out && out.data) || out).affected_rules || []);
                if (hit.length) P().alert({ title: 'Rules changed',
                    message: 'Conditions were removed from: <b>' + esc(hit.join(', ')) + '</b>. Check their logic.' });
                await reload();
            } catch (err) { fail(err); }
            return;
        }

        if (GM) {
            if (t.hasAttribute('data-gm-close')) { GM = null; gmRender(); return; }
            if (t.hasAttribute('data-gm-new'))   { gmInit('new'); gmRender(); return; }
            if ((v = attr(t, 'data-gm-sel')) !== undefined) { gmInit(+v); gmRender(); return; }
            if (t.hasAttribute('data-gm-save'))  { await gmSave(); return; }
            if ((v = attr(t, 'data-gm-del')) !== undefined) { await gmDelete(+v); return; }
        }

        if (t.hasAttribute('data-c-add')) { await checkForm(null); return; }
        if ((v = attr(t, 'data-c-edit')) !== undefined)   { await checkForm(byId(D.checks, v)); return; }
        if ((v = attr(t, 'data-c-groups')) !== undefined) { await checkGroupsForm(byId(D.checks, v)); return; }
        if ((v = attr(t, 'data-c-del')) !== undefined) {
            var cd = byId(D.checks, v);
            if (!(await P().confirm({ title: 'Delete check', danger: true, okText: 'Delete',
                    message: 'Delete <b>' + esc(cd.name) + '</b>? Conditions using it are removed with it.' }))) return;
            try {
                var gone = await api('pulse/checks/' + v, { method: 'DELETE' });
                var hurt = (((gone && gone.data) || gone).affected_rules || []);
                if (hurt.length) P().alert({ title: 'Rules changed',
                    message: 'Conditions were removed from: <b>' + esc(hurt.join(', ')) + '</b>. A branch left '
                           + 'with no conditions is undecided and holds the rule — check their logic.' });
                await reload();
            } catch (err) { fail(err); }
            return;
        }

        if (t.hasAttribute('data-r-back')) { await closeRule(); return; }
        if ((v = attr(t, 'data-r-open')) !== undefined) {
            try { await openRule('pulse/rules/' + v); } catch (err) { fail(err); }
            return;
        }
        if (t.hasAttribute('data-r-clone')) { await cloneFromForm(); return; }
        if (t.hasAttribute('data-r-clone-to')) { await cloneToForm(); return; }
        if (t.hasAttribute('data-r-save')) { if (!BUSY) await saveBranches(); return; }
        if (t.hasAttribute('data-r-drop')) {
            if (!(await P().confirm({ title: 'Remove Pulse setup', danger: true, okText: 'Remove',
                    message: 'The record keeps whatever value it has right now and goes back to being '
                           + 'edited by hand.' }))) return;
            try {
                await api('pulse/rules/' + RULE.id, { method: 'DELETE' });
                window.location.href = '/records?zone=' + RULE.domain_id;
            } catch (err) { fail(err); }
            return;
        }
        if (t.hasAttribute('data-r-toggle')) {
            // Turning off does not touch the record: it may hold the failover set, and reverting it to a
            // dead address is the worst thing a switch could do.
            if (RULE.enabled && !(await P().confirm({ title: 'Turn NS Pulse off', okText: 'Turn off',
                    message: 'The record keeps the value it has right now — Pulse just stops managing it '
                           + 'and it can be edited by hand again.' }))) return;
            try {
                await api('pulse/rules/' + RULE.id,
                    { method: 'PUT', body: JSON.stringify({ enabled: RULE.enabled ? 0 : 1 }) });
                await openRule('pulse/rules/' + RULE.id);
            } catch (err) { fail(err); }
            return;
        }

        if ((v = attr(t, 'data-branch-up')) !== undefined)   { move(+v, +v - 1); return; }
        if ((v = attr(t, 'data-branch-down')) !== undefined) { move(+v, +v + 1); return; }
        if ((v = attr(t, 'data-branch-del')) !== undefined)  { RULE.branches.splice(+v, 1); render(); return; }
        if ((v = attr(t, 'data-branch-match')) !== undefined) {
            p = v.split(':'); RULE.branches[+p[0]].match_mode = p[1]; render(); return;
        }
        if ((v = attr(t, 'data-cond-add')) !== undefined)  { await condCheckForm(+v); return; }
        if ((v = attr(t, 'data-sched-add')) !== undefined) { await condSchedForm(+v); return; }
        if ((v = attr(t, 'data-cond-edit')) !== undefined) {
            p = v.split(':');
            var ce = RULE.branches[+p[0]].conditions[+p[1]];
            if (ce.kind === 'schedule') await condSchedForm(+p[0], +p[1]);
            else                        await condCheckForm(+p[0], +p[1]);
            return;
        }
        if ((v = attr(t, 'data-cond-del')) !== undefined) {
            p = v.split(':'); RULE.branches[+p[0]].conditions.splice(+p[1], 1); render(); return;
        }
        if ((v = attr(t, 'data-cond-flip')) !== undefined) {
            p = v.split(':');
            var c = RULE.branches[+p[0]].conditions[+p[1]];
            c.expect = (c.expect === 'available') ? 'unavailable' : 'available';
            render(); return;
        }
        if (t.hasAttribute('data-branch-add')) {
            RULE.branches.push({ match_mode: 'any', conditions: [], values: [ { content: '' } ], hold_seconds: 30 });
            render(); return;
        }
        if ((v = attr(t, 'data-val-add')) !== undefined) {
            var b0 = RULE.branches[+v];
            b0.values = b0.values && b0.values.length ? b0.values : [];
            b0.values.push({ content: '' });
            render(); return;
        }
        if ((v = attr(t, 'data-val-del')) !== undefined) {
            p = v.split(':');
            RULE.branches[+p[0]].values.splice(+p[1], 1);
            render(); return;
        }
        // Preview for all observers of the row; the keys are carried on the button.
        if ((v = attr(t, 'data-prev-keys')) !== undefined) {
            var to = attr(t, 'data-prev-to');
            v.split(',').forEach(function (k) { if (k) PREVIEW[k] = to; });
            render(); return;
        }
        // A chip cycles states; landing on the real state clears the preview.
        if ((v = attr(t, 'data-prev-cycle')) !== undefined) {
            var order = CHECK_OPTS.map(function (o) { return o[0]; });
            var cur = PREVIEW[v] || realPairState(v);
            var next = order[(order.indexOf(cur) + 1) % order.length];
            if (next === realPairState(v)) delete PREVIEW[v]; else PREVIEW[v] = next;
            render(); return;
        }
        if (t.hasAttribute('data-pl-reset')) { PREVIEW = {}; render(); return; }
    });

    // Fields edit the draft only; the server is written on Save.
    function setField(t) {
        var v, q;
        if ((v = attr(t, 'data-val')) !== undefined) {
            q = v.split(':');
            var br = RULE.branches[+q[0]];
            br.values = br.values && br.values.length ? br.values : [ { content: '' } ];
            var val = br.values[+q[1]] || (br.values[+q[1]] = { content: '' });
            if (q[2] === 'prio') { val.prio = t.value.trim() === '' ? null : num(t.value, 0); }
            // SRV content is "weight port target", assembled from the sibling fields.
            else if (q[2] === 'w' || q[2] === 'p' || q[2] === 't') {
                var box = t.closest('.pl-val');
                var get = function (k) {
                    var el = box && box.querySelector('[data-val$=":' + k + '"]');
                    return el ? el.value.trim() : '';
                };
                val.content = [ get('w'), get('p'), get('t') ].join(' ').replace(/\s+$/, '');
            }
            else                 { val.content = t.value.trim(); }
            return true;
        }
        if ((v = attr(t, 'data-branch-hold')) !== undefined) {
            RULE.branches[+v].hold_seconds = num(t.value, 0); return true;
        }
        if (t.hasAttribute('data-default-hold')) { RULE.default_hold_seconds = num(t.value, 0); return true; }
        return false;
    }
    document.addEventListener('input', function (e) {
        var gm = GM && GM.draft && e.target.getAttribute && e.target.getAttribute('data-gm');
        if (gm) { GM.draft[gm] = e.target.value; return; }   // no re-render: it would lose the caret
        var q = e.target.getAttribute && e.target.getAttribute('data-ce-q');
        if (q && CE) { CE.q[q] = e.target.value.trim(); ceFilter(q); return; }
        if (e.target.hasAttribute && e.target.hasAttribute('data-rf-q')) {
            RF.q = e.target.value.trim(); rulesFilter(); return;
        }
        if (!e.target.getAttribute || !e.target.hasAttribute('data-pick-q')) return;
        var ov = document.getElementById('modal-overlay');
        if (ov) pickFilter(ov);
    });
    function pickToggle(cb, on) {
        if (cb.disabled || cb.checked === on) return;
        cb.checked = on;
        cb.dispatchEvent(new Event('change', { bubbles: true }));
    }
    document.addEventListener('change', async function (e) {
        var t = e.target, v;
        if (!t.getAttribute) return;
        var ov = document.getElementById('modal-overlay');
        if (GM && GM.draft) {
            if ((v = attr(t, 'data-gm-mem')) !== undefined) {
                var i = GM.draft.tids.indexOf(+v);
                if (t.checked && i < 0) GM.draft.tids.push(+v);
                if (!t.checked && i >= 0) GM.draft.tids.splice(i, 1);
                return;
            }
        }
        if (ASG) {
            // A ticked group covers its members, so drop them from the by-name list.
            if ((v = attr(t, 'data-ce-grp')) !== undefined) {
                var ag = ceAssigned(), gid2 = +v, gi = ag.gids.indexOf(gid2);
                if (t.checked && gi < 0) ag.gids.push(gid2);
                if (!t.checked && gi >= 0) ag.gids.splice(gi, 1);
                if (t.checked) {
                    var gg = byId(D.groups, gid2);
                    ((gg && gg.member_ids) || []).forEach(function (tid) {
                        var j = ag.tids.indexOf(tid);
                        if (j >= 0) ag.tids.splice(j, 1);
                    });
                }
                ceRedraw('agent'); return;
            }
            if ((v = attr(t, 'data-ce-agt')) !== undefined) {
                var ag2 = ceAssigned(), tid2 = +v, k2 = ag2.tids.indexOf(tid2);
                if (t.checked && k2 < 0) ag2.tids.push(tid2);
                if (!t.checked && k2 >= 0) ag2.tids.splice(k2, 1);
                ceRedraw('agent'); return;
            }
        }
        if (CE) {
            if ((v = attr(t, 'data-ce-check')) !== undefined) {
                CE.check_id = +v; ASG = null;      // another check has its own assignment
                ceRedraw('check'); ceRedraw('agent'); return;
            }
            if (t.getAttribute('name') === 'ce_expect') { CE.expect = t.value; ceSync(); return; }
            if (t.getAttribute('name') === 'ce_agg') {
                CE.agg = t.value;
                var n = document.querySelector('[name="ce_n"]');
                if (n) n.hidden = (CE.agg !== 'at_least');
                ceSync(); return;
            }
            if (t.getAttribute('name') === 'ce_n') { CE.agg_n = num(t.value, 1) || 1; t.value = CE.agg_n; ceSync(); return; }
            // ICMP has no port: hide and clear the field.
            if (/^ce_[ne]_kind$/.test(t.getAttribute('name') || '')) {
                var row = t.closest('tr'), pf = row && row.querySelector('[data-ce-port]');
                if (pf) { pf.hidden = (t.value !== 'tcp'); if (pf.hidden) pf.value = ''; }
                if (t.getAttribute('name') === 'ce_n_kind') CE.draft.kind = t.value;
                return;
            }
        }
        // Rules filter hides rows in place instead of re-rendering (no flicker, search keeps focus).
        var rf = { rf_zone: 'zone', rf_type: 'type', rf_state: 'state' }[t.getAttribute('name')];
        if (rf) { RF[rf] = t.value; rulesFilter(); return; }
        if ((v = attr(t, 'data-pick')) !== undefined) {
            if (ov) ov.querySelectorAll('[data-pick-row]').forEach(function (tr) {
                tr.classList.toggle('is-picked', tr.getAttribute('data-pick-row') === v);
            });
            var box = ov && ov.querySelector('[data-pick-prev]');
            if (!box) return;
            box.innerHTML = '<span class="text-mute">Loading…</span>';
            try {
                var res = await api('pulse/rules/' + v);
                box.innerHTML = ruleSummaryHtml(((res && res.data) || res).rule);
            } catch (err) { box.innerHTML = '<span class="text-mute">Could not read this setup.</span>'; }
            return;
        }
        if ((v = attr(t, 'data-pick-to')) !== undefined) {
            var i = PICKED_TO.indexOf(+v);
            if (t.checked && i < 0) PICKED_TO.push(+v);
            if (!t.checked && i >= 0) PICKED_TO.splice(i, 1);
            var row = t.closest('tr'); if (row) row.classList.toggle('is-picked', t.checked);
            return;
        }
        // The zone pick arrives via the shared select component's hidden input.
        if (t.getAttribute('name') === 'pick_zone') { PICKED_TO = []; await loadCloneTargets(t.value); return; }
        if (t.getAttribute('name') === 'pick_zone_f' || t.getAttribute('name') === 'pick_type_f') {
            if (ov) pickFilter(ov); return;
        }
        // "Select all" only picks visible (filtered) rows.
        if (t.hasAttribute('data-pick-all')) {
            if (!ov) return;
            ov.querySelectorAll('tbody tr[data-hay]').forEach(function (tr) {
                if (tr.hidden) return;
                var cb = tr.querySelector('[data-pick-to]');
                if (cb) pickToggle(cb, t.checked);
            });
            return;
        }
        if (t.hasAttribute('data-pick-over')) {
            // Overwriting existing setups requires this explicit checkbox.
            if (!ov) return;
            ov.querySelectorAll('[data-pick-to]').forEach(function (cb) {
                var busy = CLONE_TO[+cb.getAttribute('data-pick-to')];
                if (!busy || !busy.rule_id) return;
                if (!t.checked) pickToggle(cb, false);
                cb.disabled = !t.checked;
            });
            return;
        }
    });

    // On every keystroke, so Save enables immediately.
    document.addEventListener('input', function (e) {
        var t = e.target;
        if (!t.getAttribute) return;
        // Keep the config preview in sync with the address being typed.
        if (t.hasAttribute('data-pl-addr')) {
            var pre = document.getElementById('pl-conf');
            var srv = (D && D.server) || {};
            if (pre) pre.textContent = agentConfText({ address: t.value.trim(),
                enroll_key: srv.enroll_key, fingerprint: srv.fingerprint });
            return;
        }
        if (!RULE) return;
        if (setField(t)) syncDerived();
    });
    // On blur, normalise: an empty hold falls back to the default, not zero seconds.
    document.addEventListener('change', function (e) {
        if (!RULE || !e.target.getAttribute) return;
        var t = e.target, v;
        if (!setField(t)) return;
        if ((v = attr(t, 'data-branch-hold')) !== undefined) {
            var b = RULE.branches[+v];
            b.hold_seconds = b.hold_seconds || 30; t.value = b.hold_seconds;
        } else if (t.hasAttribute('data-default-hold')) {
            RULE.default_hold_seconds = RULE.default_hold_seconds || 300;
            t.value = RULE.default_hold_seconds;
        }
        syncDerived();
    });

    // Drag and drop does the same as the arrow buttons.
    var DRAG = null;
    document.addEventListener('dragstart', function (e) {
        var s = e.target.closest && e.target.closest('[data-branch]');
        if (!s) return;
        DRAG = +s.getAttribute('data-branch');
        e.dataTransfer.effectAllowed = 'move';
        try { e.dataTransfer.setData('text/plain', String(DRAG)); } catch (x) {}
        // Dragged by the grip, but show the whole branch as the drag image.
        try { e.dataTransfer.setDragImage(s, 16, 16); } catch (x) {}
        s.classList.add('is-dragging');
    });
    document.addEventListener('dragover', function (e) {
        if (DRAG === null) return;
        var s = e.target.closest && e.target.closest('[data-branch]');
        if (s) e.preventDefault();
    });
    document.addEventListener('drop', function (e) {
        if (DRAG === null) return;
        var s = e.target.closest && e.target.closest('[data-branch]');
        if (!s) return;
        e.preventDefault();
        var to = +s.getAttribute('data-branch');
        if (to !== DRAG) move(DRAG, to);
        DRAG = null;
    });
    document.addEventListener('dragend', function () {
        DRAG = null;
        var d = document.querySelector('.is-dragging');
        if (d) d.classList.remove('is-dragging');
    });

    // In a checks table row, Enter saves and Esc cancels the row edit. Capture phase, so it runs before the
    // dialog's Esc handler and doesn't close the whole dialog.
    document.addEventListener('keydown', function (e) {
        if (!CE || (e.key !== 'Escape' && e.key !== 'Enter')) return;
        var row = e.target.closest && e.target.closest('tr.is-editing, tr.is-new');
        if (!row) return;
        var editing = row.classList.contains('is-editing');
        if (e.key === 'Escape' && !editing) return;      // in the add row Esc belongs to the dialog
        e.preventDefault(); e.stopPropagation();
        if (e.key === 'Escape') { CE.editing = null; ceRedraw('check'); return; }
        if (editing) ceSaveCheck(CE.editing); else ceCreateCheck();
    }, true);
    // Esc closes the builder, unless a dialog is open over it.
    document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape' && GM) { e.preventDefault(); GM = null; gmRender(); return; }
        if (e.key !== 'Escape' || !RULE) return;
        var ov = document.getElementById('modal-overlay');
        if (ov && ov.style.display !== 'none' && ov.innerHTML) return;
        e.preventDefault();
        closeRule();
    });

    function boot() {
        var el = document.getElementById('pulse-data');
        if (!el) return;
        try { D = JSON.parse(el.textContent); } catch (e) { return; }
        try { TAB = localStorage.getItem('pulse.tab') || TAB; } catch (e) {}
        if (TAB !== 'agents' && TAB !== 'checks' && TAB !== 'rules') TAB = 'agents';
        render();
    }

    // Open a rule named in the URL. Rule branches are not in the page payload (it would carry every rule's
    // sets); the tabs page is shown meanwhile.
    function openFromUrl() {
        var q = new URLSearchParams(window.location.search);
        var path = null;
        if (q.get('rule')) {
            path = 'pulse/rules/' + q.get('rule');
        } else if (q.get('zone') && q.get('name') && q.get('type')) {
            path = 'pulse/zones/' + q.get('zone') + '/rrset?name=' + encodeURIComponent(q.get('name'))
                 + '&type=' + encodeURIComponent(q.get('type'));
        }
        if (!path) return;
        // async-ok: requested by the URL, not part of the first frame
        openRule(path).catch(fail);
    }
    document.addEventListener('pageLoaded', function (e) {
        if (!e.detail || e.detail.page !== 'pulse') return;
        boot();
        openFromUrl();
    });
    // Entry point for tests: same path as the page, without the navigation event.
    window.PulseBuilder = { boot: boot, open: function (id) { return openRule('pulse/rules/' + id); },
                            openFromUrl: openFromUrl };
    // One availability bar for the whole panel; js/records.js reuses it.
    window.PulseBar = { ticks: ticksHtml };
})();
