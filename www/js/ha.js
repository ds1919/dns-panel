/* HA: pair state, operations and configuration.
 *
 * Main rule of this file: markup is built ONCE, polling only changes values.
 *
 * No `innerHTML = render(state)` on a timer. A full rerender destroys what belongs to the browser,
 * not the server: an open diagnostics panel, the selected row, scroll position and, worst of all,
 * what the user is typing in a form.
 *
 *   skeleton()  markup, once;
 *   apply(st)   targeted update: setText/setState touch a node only when the value changed;
 *   lists       keyed update by operation_id, not a table rebuild;
 *   form        untouched by polling; synced only after Save.
 *
 * No HA logic here. Buttons are hidden by permissions and role, but whether a switch is allowed right
 * now is the manager's call: 409 is shown as its refusal, 503 as "state unknown".
 */
(function () {
    'use strict';

    var DATA = {};          // page bootstrap data (mode, permissions, service_url)
    var ST = null;          // latest state from the manager
    var CFG = null;         // latest configuration read
    var TIMER = null, BUSY = false;
    // Long requests (Configure HA, switchover) take minutes: show a page-wide busy cursor, since the
    // button may already be out of view.
    function setBusy(v) { BUSY = v; window.DNSPanel.busyHold(v); }
    var SAVING = false;     // configuration save in progress: form is locked
    var RECONNECTING = false;  // role moved: reopening the page via the service address
    var FLASH = null;       // timer for the short success note
    var CUR_OP = null;      // details of the operation being shown
    var STARTING = null;    // clicked but no operation yet: the console is open under this label

    function esc(s) {
        return String(s == null ? '' : s).replace(/[&<>"]/g, function (c) {
            return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c];
        });
    }
    // Panel responses come both wrapped ({success, data}) and bare. Unwrap once here; per-call handling
    // once caused "Revision undefined" after a successful save.
    function api(path, method, body) {
        return window.DNSPanel.api(path, { method: method, body: body ? JSON.stringify(body) : undefined })
            .then(function (r) {
                return (r && r.success === true && Object.prototype.hasOwnProperty.call(r, 'data')) ? r.data : r;
            });
    }
    // Session expired: the page is already leaving for login, so this response must not be read as pair
    // state (a 401 used to show up as "State unknown" with no switch button).
    function authGone(e) { return !!(e && (e.authExpired || e.status === 401)); }

    function $(id) { return document.getElementById(id); }
    function pair()  { return (ST || {}).pair || {}; }
    function selfN() { return pair().self || {}; }
    function peerN() { return pair().peer || {}; }
    function busyOp() { return ((ST || {}).execution || {}).operation || ''; }

    // Write to the DOM only when the value actually differs: a redundant write resets text selection
    // and forces needless repaint.
    function setText(id, v) {
        var el = $(id); if (!el) return;
        var s = (v === null || v === undefined || v === '') ? '—' : String(v);
        if (el.textContent !== s) el.textContent = s;
    }
    // Optional note: empty means empty. A dash here would read as "value unknown".
    function setNote(id, v) {
        var el = $(id); if (!el) return;
        var s = v == null ? '' : String(v);
        if (el.textContent !== s) el.textContent = s;
    }
    function setHtml(id, html) {
        var el = $(id); if (!el) return;
        if (el.innerHTML !== html) el.innerHTML = html;
    }
    function setClass(id, cls) {
        var el = $(id); if (!el) return;
        if (el.className !== cls) el.className = cls;
    }
    function setShown(id, on) {
        var el = $(id); if (!el) return;
        if (el.hidden === !on) return;
        el.hidden = !on;
    }
    function setAttr(id, name, v) {
        var el = $(id); if (!el) return;
        if (el.getAttribute(name) !== v) el.setAttribute(name, v);
    }

    // UUID is the machine identity (peer, safety, operation journal); it is not a human-facing title.
    // Order: configured name -> hostname -> short id. The UUID is shown only where needed, always
    // shortened, with the full value in a tooltip.
    function shortId(id) {
        var v = String(id == null ? '' : id);
        return v.length > 12 ? v.slice(0, 8) + '…' : v;
    }
    // n is either a node_id string or a node object from the pair state.
    function nodeName(n) {
        var o = (typeof n === 'string' || n == null) ? nodeOf(n) : n;
        var id = (typeof n === 'string') ? n : (o && o.node_id);
        var cn = cfgNode(id) || {};
        return o && o.name || cn.name || (o && o.hostname) || cn.hostname || shortId(id) || '—';
    }
    // Card order: HA channel address as a number, so .68 always sits left of .69 regardless of role.
    function nodeOrder(n) {
        var cn = cfgNode(n && n.node_id) || {};
        var host = cn.peer_listen_host || '';
        var m = host.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
        if (m) return ((+m[1] * 256 + +m[2]) * 256 + +m[3]) * 256 + +m[4];
        return host ? host.charCodeAt(0) * 1e6 : (String(n && n.node_id || '').charCodeAt(0) || 0);
    }

    function nodeOf(id) {
        if (!id) return null;
        if (selfN().node_id === id) return selfN();
        if (peerN().node_id === id) return peerN();
        return null;
    }

    // There are deliberately no "Standalone | Floating IP | Anycast" tabs: these are mutually exclusive
    // states chosen when the pair is created, not screens to switch between.
    var MODE_NAMES = { floating_ip: 'Floating IP', anycast: 'Anycast', marker: 'External' };

    // Mode is determined by OBSERVATION, not only by config: the revision's provider is the intent, while
    // what actually runs shows in where the node holds the address (interface vs loopback).
    function pubMode() {
        var pub = pair().publication || '';
        if (MODE_NAMES[pub]) return pub;
        var dev = selfN().publication_device || peerN().publication_device || '';
        return dev === 'lo' ? 'anycast' : 'floating_ip';
    }

    // Reading and editing are the same screen: Edit turns specific values into fields in place and adds
    // Save/Cancel, so Name/Hostname/Location/Description rows are always shown, even empty.
    // If a label does not make clear what a field changes, the field does not belong here.
    function row(id, label, extra) {
        return '<div class="ha-row' + (extra ? ' ' + extra : '') + '"><label>' + label + '</label>'
            + '<div class="ha-val" id="' + id + '"></div></div>';
    }

    function nodeCardHtml(side) {
        var p = 'ha-' + side;
        return '<article class="ha-node" id="' + p + '">'
            + '<header><span class="ha-role" id="' + p + '-role">—</span>'
            + '<span class="ha-strip-gap"></span>'
            + '<span class="ha-you" id="' + p + '-you" hidden>you are here</span>'
            + '</header>'
            + '<div class="ha-node-alert" id="' + p + '-alert" hidden></div>'

            + row(p + '-name', 'Name')
            + row(p + '-host', 'Hostname')
            + row(p + '-loc', 'Location')
            + row(p + '-desc', 'Description')

            + '<div class="ha-row-sep"></div>'
            // Anycast is the first and only highlighted network row: it is the key object of such a setup.
            // Same format as the other addresses (interface, address, service) so it reads as network config.
            + '<div class="ha-row ha-anycast" id="' + p + '-anycast-row" hidden><label>Anycast</label>'
            + '  <div class="ha-val ha-anycast-val" id="' + p + '-anycast"></div></div>'
            + row(p + '-addr', 'IP address')
            + row(p + '-repl', 'Replication')

            + '<div class="ha-row-sep"></div>'
            + row(p + '-pdns', 'PowerDNS')
            + row(p + '-db', 'MariaDB')
            + row(p + '-notify', 'NOTIFY')
            + row(p + '-axfr', 'AXFR / IXFR')

            + '<div class="ha-row-sep"></div>'
            + '<div class="ha-row ha-row-id"><label>Node ID</label><div class="ha-val">'
            + '<b id="' + p + '-uuid" data-tip="">—</b>'
            + '<button class="lnk" data-act="copy-id" data-side="' + side + '">copy</button></div></div>'

            // Footer: node action on the left, edit on the right. Positions are fixed so nothing moves
            // when editing starts; Switch just gets disabled.
            + '<div class="ha-node-foot"><span id="' + p + '-act"></span>'
            + '<span id="' + p + '-edit-act"></span></div>'
            + '</article>';
    }

    function skeleton() {
        return ''
            + '<section class="ha-bar" id="ha-hero">'
            + '  <span class="ha-bar-mode" id="ha-mode-name">—</span>'
            // Publication is edited here, not in the cards: address and port belong to the PAIR, not a node.
            + '  <button class="lnk" data-act="edit-pub" id="ha-pub-edit" hidden>Edit</button>'
            + '  <span class="ha-bar-item" id="ha-addr-item"><label>Address</label><span class="ha-val" id="ha-addr">—</span></span>'
            + '  <span class="ha-bar-item" id="ha-dev-item"><label>Interface</label><span class="ha-val" id="ha-dev">—</span></span>'
            // Anycast: the interface is always loopback and says nothing; what matters is whether the probe
            // port is open, since the router uses it to pick where to send traffic.
            + '  <span class="ha-bar-item" id="ha-probe-item" hidden><label>Health probe</label>'
            + '    <span class="ha-val" id="ha-probe">—</span></span>'
            // Owner is shown only where the address MOVES. With anycast it is on both nodes, and
            // "on dns-a" would read as "not on the other one".
            + '  <span class="ha-bar-owner" id="ha-owner"></span>'
            + '  <span class="ha-strip-gap"></span>'
            + '  <span class="ha-pill" id="ha-verdict">—</span>'
            + '  <span class="ha-mute" id="ha-meta"></span>'
            + '  <span class="ha-mute" id="ha-config-note"></span>'
            + '</section>'
            + '<section class="ha-topo">' + nodeCardHtml('left')
            + '  <div class="ha-flow" id="ha-flow"><span class="ha-flow-label" id="ha-flow-label">MariaDB replication</span>'
            + '  <span class="ha-flow-arrow" aria-hidden="true"></span>'
            + '  <span class="ha-flow-note" id="ha-flow-note"></span></div>'
            + nodeCardHtml('right') + '</section>'

            + '<section class="ha-card ha-trouble" id="ha-trouble" hidden>'
            + '  <header class="ha-card-head"><b>Needs attention</b></header>'
            + '  <p id="ha-trouble-why"></p><div class="ha-card-foot" id="ha-trouble-act"></div>'
            + '</section>'
            + '<section class="ha-strip" id="ha-op-strip" hidden>'
            + '  <span class="ha-strip-label">Last operation</span><b id="ha-op-strip-title"></b>'
            + '  <span class="ha-pill sm" id="ha-op-strip-state"></span><span class="ha-mute" id="ha-op-strip-when"></span>'
            + '  <span class="ha-strip-gap"></span><button class="lnk" data-act="op-open">Details</button>'
            + '</section>'
            // Operation console: lines stay on screen so the whole switchover is visible as it happens.
            + '<section class="ha-console" id="ha-op" hidden>'
            + '  <header class="ha-console-head"><span class="ha-spin" id="ha-op-spin" hidden></span>'
            + '  <b id="ha-op-title"></b><span class="ha-pill sm" id="ha-op-state"></span>'
            + '  <span class="ha-mute" id="ha-op-meta"></span>'
            + '  <span class="ha-strip-gap"></span><span class="ha-mute" id="ha-op-id"></span>'
            + '  <button class="lnk" data-act="op-close" id="ha-op-hide">Hide</button></header>'
            + '  <div class="ha-op-reason" id="ha-op-reason" hidden></div>'
            + '  <ol class="ha-steps" id="ha-op-steps"></ol>'
            + '  <div class="ha-card-foot" id="ha-op-foot" hidden>'
            + '    <button class="btn btn-ghost" data-act="resume">Resume operation</button>'
            + '    <span class="ha-mute">Completed steps are not repeated — fix the cause first.</span></div>'
            + '</section>'
            + '<div class="ha-more"><button class="lnk" data-act="history" id="ha-history-toggle">History</button>'
            + '  <button class="lnk" data-act="diag">Diagnostics</button></div>'
            + '<section class="ha-card" id="ha-history" hidden>'
            + '  <header class="ha-card-head"><b>Operation history</b></header>'
            + '  <table class="data-table"><thead><tr><th>Operation</th><th>Epoch</th><th>By</th><th>When</th><th>Result</th></tr></thead>'
            + '  <tbody id="ha-history-rows"></tbody></table>'
            + '</section>'
            // Dismantle is a single button with no explanation card: the consequences are spelled out in
            // the modal, right before the action.
            + '<div class="ha-teardown" id="ha-teardown" hidden>'
            + '  <span class="ha-mute" id="ha-teardown-note"></span>'
            + '  <button class="btn btn-danger" data-act="dismantle" id="ha-teardown-btn">Dismantle HA</button>'
            + '</div>';
    }

    // Pairing screen. Built once like everything else here: the user is reading six digits and typing
    // the peer address, and a rerender would take both away.
    // The user makes exactly two decisions: confirm the digits match, and choose whose data survives.
    function pairingSkeleton() {
        return ''
            // Title depends on TRUST, not on whether HA is on: a paired node with HA off is not alone.
            // Default text is NEUTRAL: a hardcoded "runs alone" could be false, "unavailable" cannot.
            + '<section class="ha-card"><header class="ha-card-head"><b id="pr-title">Pairing status unavailable</b>'
            + '<span class="ha-strip-gap"></span><span class="ha-chip" id="pr-node">—</span></header>'
            // Address the user dictates to the other node. Chosen from this node's addresses and saved;
            // guessing the first non-loopback address used to pick the LXC bridge.
            + '<div class="ha-cfg-row"><label>Address for the other node</label><span id="pr-ip">—</span></div>'
            + '<div class="ha-cfg-row"><label>Pairing</label><span id="pr-state">—</span></div>'
            + '</section>'

            // Step 1: introduction. Two equal sides: one opens the window, the other asks to join.
            + '<section class="ha-card" id="pr-start" hidden>'
            + '  <header class="ha-card-head"><b>Create an HA pair</b></header>'
            + '  <p>Two single nodes become a pair: one opens pairing, the other asks to join, and a person '
            + 'confirms the same six digits on both. Nothing changes on either node until then.</p>'
            + '  <div class="ha-card-foot">'
            + '    <button class="btn btn-primary" data-act="pair-create">Open pairing on this node</button>'
            + '    <span class="ha-mute">then press Join on the other node</span></div>'
            + '  <div class="ha-cfg-row ha-pr-join"><label>Join existing pair</label>'
            + '    <input id="pr-addr" placeholder="192.0.2.11">'
            + '    <button class="btn btn-ghost" data-act="pair-join">Join</button></div>'
            + '  <p class="ha-mute">Address of the node where pairing is already open.</p>'
            + '</section>'

            // Step 2: window open, no peer yet.
            + '<section class="ha-card" id="pr-wait" hidden>'
            + '  <header class="ha-card-head"><b>Waiting for the other node</b></header>'
            + '  <p>Open High availability on the second node and join this one '
            + '(<b id="pr-selfip">—</b>). The window closes by itself.</p>'
            + '  <div class="ha-card-foot"><button class="btn btn-ghost" data-act="pair-reject">Cancel</button>'
            + '  <span class="ha-mute" id="pr-expires"></span></div>'
            + '</section>'

            // Step 3: the code, the only place where the user actually verifies something.
            + '<section class="ha-card" id="pr-code" hidden>'
            + '  <header class="ha-card-head"><b>Confirm the code</b>'
            + '  <span class="ha-strip-gap"></span><span class="ha-pill sm" id="pr-role">—</span></header>'
            + '  <div class="ha-code" id="pr-digits">——————</div>'
            + '  <p id="pr-code-note"></p>'
            + '  <ul class="ha-facts">'
            + '    <li><span>Node</span><b id="pr-peer-id">—</b></li>'
            + '    <li><span>Hostname (claimed)</span><b id="pr-peer-host">—</b></li>'
            + '    <li><span>Address (observed)</span><b id="pr-peer-addr">—</b></li>'
            + '  </ul>'
            + '  <div class="ha-card-foot" id="pr-code-act" hidden>'
            + '    <button class="btn btn-primary" data-act="pair-approve">Codes match — approve</button>'
            + '    <button class="btn btn-ghost" data-act="pair-reject">They differ</button></div>'
            + '</section>'

            // Step 4: pair from trust; choose whose data survives.
            + '<section class="ha-card" id="pr-build" hidden>'
            + '  <header class="ha-card-head"><b>Configure high availability</b>'
            + '  <span class="ha-strip-gap"></span><span class="ha-chip">nodes trust each other</span></header>'
            + '  <p>One node keeps its data; the other is rebuilt from it. Two databases are never merged.</p>'
            + '  <div class="ha-inv"><div class="ha-inv-col"><header>This node <span id="pr-inv-self-id"></span></header>'
            + '    <ul class="ha-facts" id="pr-inv-self"></ul></div>'
            + '  <div class="ha-inv-col"><header>Other node <span id="pr-inv-peer-id"></span></header>'
            + '    <ul class="ha-facts" id="pr-inv-peer"></ul></div></div>'
            + '  <div class="ha-cfg-row"><label>Keep the data of</label>'
            + '    <label class="chk"><input type="radio" name="pr-donor" value="self" checked> this node</label>'
            + '    <label class="chk"><input type="radio" name="pr-donor" value="peer"> the other node</label></div>'
            + '  <div id="pr-donor-peer" hidden><p class="ha-mute">The pair is created from the node whose data '
            + 'is kept — open High availability <a id="pr-peer-link" href="#">on that node</a> and press '
            + '“Configure HA” there.</p></div>'
            + '  <div id="pr-donor-self">'
            + '    <div class="ha-cfg-row"><label>Publication</label>'
            + '      <span class="ha-val" id="pr-pub-prov"></span></div>'
            + '    <div class="ha-cfg-row"><label>Service address</label>'
            + '      <input id="pr-pub-addr" placeholder="192.0.2.10/32">'
            + '      <button class="btn btn-ghost" data-act="pair-devices" id="pr-dev-check">Check</button></div>'
            // Interface is not asked: NIC names need not match across machines. Each node finds its own,
            // and this row shows what it found.
            + '    <div class="ha-cfg-row" id="pr-devs-row"><label>Interfaces</label>'
            + '      <span class="ha-val" id="pr-devs">—</span></div>'
            // Anycast: no interface, the address is permanently on both loopbacks; instead ask for the
            // probe port the router uses to judge readiness.
            + '    <div class="ha-cfg-row" id="pr-probe-row" hidden><label>Health probe</label>'
            + '      <input id="pr-probe-port" placeholder="17901" inputmode="numeric">'
            + '      <span class="ha-mute">TCP port 1024-65535, open only on the node serving the address</span></div>'
            + '    <div class="ha-card-foot">'
            + '      <button class="btn btn-primary" data-act="pair-build">Configure HA</button>'
            + '      <span class="ha-mute" id="pr-build-warn"></span></div>'
            + '  </div>'
            + '  <div class="ha-card-foot"><button class="lnk" data-act="pair-reset">Undo pairing</button>'
            + '  <span class="ha-mute">Removes the trust between the nodes. Data is not touched.</span></div>'
            + '</section>';
    }

    var PAIR_STATE_TEXT = {
        unpaired: 'not started', open: 'waiting for the other node', pending: 'code confirmation',
        committing: 'finishing', trusted: 'nodes trust each other', unknown: 'unknown'
    };

    function pairing() { return DATA.pairing || {}; }
    function pairState() {
        if (DATA.pairing_err) return 'unknown';
        return pairing().state || 'unpaired';
    }

    // Inventory is fetched on demand, not on a timer: it goes to the peer over the network and is only
    // needed when choosing the donor.
    function loadInventory() {
        if (DATA.inv_loading) return;
        DATA.inv_loading = true;
        api('/ha/pair/inventory', 'GET').then(function (r) {
            DATA.inventory = r || {}; DATA.inv_loading = false; applyPairing();
        }).catch(function () { DATA.inv_loading = false; });
    }

    // What matters is how many zones and users would be lost, not just "database not empty".
    function invRows(side) {
        var inv = (DATA.inventory || {})[side];
        if (!inv) return '<li><span>loading…</span></li>';
        if (inv.error) return '<li><span class="ha-warn-text">' + esc(inv.error) + '</span></li>';
        var out = [];
        (inv.databases || []).forEach(function (db) {
            if (!db.present) { out.push('<li><span>' + esc(db.name) + '</span><b>not installed</b></li>'); return; }
            var rows = db.rows || {}, keys = Object.keys(rows).sort();
            if (!keys.length) { out.push('<li><span>' + esc(db.name) + '</span><b>empty</b></li>'); return; }
            var pick = ['domains', 'records', 'users', 'catalogs', 'zone_access'];
            var shown = pick.filter(function (k) { return rows[k]; }).map(function (k) { return k + ' ' + rows[k]; });
            if (!shown.length) shown = keys.slice(0, 3).map(function (k) { return k + ' ' + rows[k]; });
            out.push('<li><span>' + esc(db.name) + '</span><b>' + esc(shown.join(' · ')) + '</b></li>');
        });
        return out.join('') || '<li><span>—</span></li>';
    }

    // What each node found for the entered address. Not asked yet: dash; asked and not found: say so,
    // because a pair with an address that cannot be brought up must not be created.
    function devicesHtml() {
        var d = DATA.devices;
        if (!d) return '—';
        function one(label, dev, err) {
            return '<span class="ha-dev">' + esc(label) + ' '
                + (dev ? '<b>' + esc(dev) + '</b>'
                       : '<span class="ha-warn-text">' + esc(err || 'not determined') + '</span>') + '</span>';
        }
        var peerLabel = d.peer_node_id ? nodeName(d.peer_node_id) : 'other node';
        return one('this node', d.local, d.local_error) + one(peerLabel, d.peer, d.peer_error);
    }
    function devicesReady() {
        var d = DATA.devices;
        return !!(d && d.local && d.peer);
    }

    // Address for the other node: a dropdown of THIS node's addresses. Until chosen, say so; picking the
    // first one would be a lie (it may be a bridge address).
    var PAIR_IP_SAVING = false;
    function renderPairIp() {
        var box = $('pr-ip'); if (!box) return;
        var ips = DATA.node_ips || [], cur = DATA.pair_ip || '';
        if (!DATA.can_manage) { box.textContent = cur || 'not chosen'; return; }
        var opts = [{ value: '', label: ips.length ? 'not chosen' : 'no addresses found' }]
            .concat(ips.map(function (ip) { return { value: ip, label: ip }; }));
        box.innerHTML = window.DNSPanel.selectHtml('pr_pair_ip', opts, cur)
                      + (PAIR_IP_SAVING ? ' <span class="mini text-mute">saving…</span>' : '');
    }
    async function savePairIp(ip) {
        if (PAIR_IP_SAVING) return;
        PAIR_IP_SAVING = true; renderPairIp();
        try {
            var r = await window.DNSPanel.api('ha/pair-address', { method: 'PUT', body: JSON.stringify({ address: ip }) });
            DATA.pair_ip = ((r && r.data) || {}).address || '';
        } catch (e) { window.DNSPanel.alert({ message: (e && e.message) || 'Could not save the address' }); }
        PAIR_IP_SAVING = false; renderPairIp();
        var self = $('pr-selfip'); if (self) self.textContent = DATA.pair_ip || 'this node';
    }
    // Listen on document (the page is rebuilt), but react only to our own control, which exists only on
    // this page's pairing card.
    document.addEventListener('change', function (e) {
        var t = e.target;
        if (t && t.name === 'pr_pair_ip' && $('pr-ip')) savePairIp(t.value);
    });

    function applyPairing() {
        if (!$('pr-state')) return;
        var p = pairing(), st = pairState();
        var mine = DATA.pair_ip || '';
        setText('pr-node', shortId(DATA.node_id));
        setAttr('pr-node', 'title', DATA.node_id || '');
        renderPairIp();
        setText('pr-state', PAIR_STATE_TEXT[st] || st);
        setText('pr-selfip', mine || 'this node');
        void 0;

        // Two independent questions, each with a third answer "unknown", which is never a synonym for "no":
        //
        //	HA:       true on | false proven off | null undetermined
        //	pairing:  trusted | unpaired | open/pending/committing | unknown (not read)
        //
        // Showing "unknown" as "no" turned an unreachable manager into a confident "alone" claim, with
        // pairing buttons offered to a node that might already be paired.
        var haUnknown = DATA.ha_configured !== true && DATA.ha_configured !== false;
        setText('pr-title', haUnknown ? 'HA configuration status unavailable'
            : st === 'trusted' ? 'Nodes are paired · high availability is not configured'
            : st === 'unpaired' ? 'This node runs alone'
            : 'Pairing status unavailable');
        // While HA state is unknown, offer NOTHING: any action here is a blind choice with data at stake.
        // Re-pairing is offered only to a node proven to be alone.
        setShown('pr-start', !haUnknown && st === 'unpaired');
        setShown('pr-wait', !haUnknown && st === 'open' && !p.peer_node_id);
        setShown('pr-code', !haUnknown && ((st === 'open' && !!p.peer_node_id) || st === 'pending' || st === 'committing'));
        setShown('pr-build', !haUnknown && st === 'trusted');

        setNote('pr-expires', p.expires ? ('window closes ' + new Date(p.expires).toLocaleTimeString()) : '');
        setText('pr-digits', p.code || '——————');
        setText('pr-role', p.role === 'initiator' ? 'you asked to join' : 'you decide');
        setText('pr-peer-id', shortId(p.peer_node_id));
        setAttr('pr-peer-id', 'title', p.peer_node_id || '');
        setText('pr-peer-host', p.peer_hostname);
        setText('pr-peer-addr', p.peer_address);
        // The side that opened the window approves: the initiator asked to join, so its "yes" adds nothing.
        setShown('pr-code-act', st === 'pending' && p.role !== 'initiator');
        setText('pr-code-note', st === 'committing' ? 'Finishing pairing…'
            : p.role === 'initiator'
                ? 'The same six digits must be shown on the other node — confirm them there.'
                : 'Compare these digits with the ones shown on the other node.');

        if (st !== 'trusted') return;
        setText('pr-inv-self-id', shortId(DATA.node_id));
        setText('pr-inv-peer-id', shortId(p.peer_node_id));
        setHtml('pr-inv-self', invRows('local'));
        setHtml('pr-inv-peer', invRows('peer'));
        var host = String(p.peer_address || '').replace(/:\d+$/, '');
        setAttr('pr-peer-link', 'href', host ? ('http://' + host + '/?page=ha') : '#');
        // async-ok: the inventory is gathered on both nodes over the peer channel; until it arrives the
        // list shows "loading…", not invented database contents.
        if (!DATA.inventory && !DATA.inv_loading) loadInventory();
        var donor = document.querySelector('input[name="pr-donor"]:checked');
        var self = !donor || donor.value === 'self';
        setShown('pr-donor-self', self);
        setShown('pr-donor-peer', !self);
        // Site dropdown component rather than native <select>: the OS draws native dropdowns, which look
        // out of place in the dark theme.
        if (!$('pr-pub-prov').firstChild) {
            setHtml('pr-pub-prov', window.DNSPanel.selectHtml('pr_pub_prov', [
                { value: 'floating_ip', label: 'Floating IP — the address moves with the role' },
                // Wording matters: the address does NOT move; it is permanently on both loopbacks.
                // Readiness is expressed by the probe, open only on ACTIVE.
                { value: 'anycast', label: 'Anycast — address on loopback of both nodes; the readiness probe is open only on ACTIVE' },
                { value: 'marker', label: 'External — the address is handled outside' }
            ], 'floating_ip'));
        }
        var prov = selVal('pr_pub_prov') || 'floating_ip';
        setShown('pr-pub-addr', prov !== 'marker');
        // Anycast: the address is on both loopbacks, so no interface to pick or detect; ask for the probe
        // port instead.
        setShown('pr-devs-row', prov === 'floating_ip');
        setShown('pr-dev-check', prov === 'floating_ip');
        setShown('pr-probe-row', prov === 'anycast');
        setHtml('pr-devs', devicesHtml());
        // While working, say WHAT is running and block a second click: Configure HA rewrites the target
        // database entirely, so a repeat would mean a second reseed.
        // The manager reports the step a running build is on; it also marks a build started before an F5.
        var build = pairing().build;
        var acting = BUSY || !!build;
        setNote('pr-build-warn', build
            ? 'Configuring high availability — step ' + build.step + ' of ' + build.total + ': ' + build.label + '…'
            : acting ? 'Configuring high availability: starting…'
            : 'the other node’s data will be replaced');
        { var bw = $('pr-build-warn'); if (bw) bw.classList.toggle('ha-building', acting); }
        document.querySelectorAll('#ha-body [data-act^="pair-"]').forEach(function (b) {
            b.disabled = acting;
        });
    }

    function verdict() {
        // The page is served by the very address that moves between nodes. During a switchover a lost
        // request is expected (address removed from one node, not yet up on the other), not "unknown".
        if (DATA.status_err && (busyOp() || RECONNECTING)) return { cls: 'busy', text: 'Reconnecting' };
        if (DATA.status_err) return { cls: 'unknown', text: 'State unknown' };
        if (busyOp()) return { cls: 'busy', text: 'Switching' };
        if (pair().fenced_node) return { cls: 'err', text: 'Fenced' };
        if (!(ST || {}).ha_healthy) return { cls: 'warn', text: 'Degraded' };
        return { cls: 'ok', text: 'Healthy' };
    }
    function ownerNode() {
        if (selfN().route_announced) return selfN().node_id;
        if (peerN().route_announced) return peerN().node_id;
        return null;
    }
    function serviceAddr() {
        var a = selfN().publication_address || peerN().publication_address;
        if (a) return String(a).replace(/\/\d+$/, '');
        if (DATA.service_url) { try { return new URL(DATA.service_url).hostname; } catch (e) { return DATA.service_url; } }
        return null;
    }

    function applyHero() {
        var tab = pubMode();
        var v = verdict(), own = ownerNode();
        var pub = pubParts((CFG && CFG.payload) || {});
        // The header shows the CONFIGURED address with its interface as one setting; the cards confirm it
        // by observation.
        var addr = pub.address || serviceAddr();
        setText('ha-mode-name', MODE_NAMES[tab] || tab);
        // "Not configured" and "unknown" differ: until config is read, the first cannot be claimed.
        setVal('ha-addr', addr || (CFG ? 'not configured' : 'configuration unavailable'));
        // Interface comes from the node currently HOLDING the address: it is a node property, not a pair one.
        var holder = own === selfN().node_id ? selfN() : (own === peerN().node_id ? peerN() : null);
        setVal('ha-dev', (holder && holder.publication_device) || cfgNode(own).publication_device || pub.device);
        // The panel knows nothing about the route: the router announces it. Show only what the node
        // controls: whether the port the router checks is open.
        var pr = (ST || {}).probe;
        // Publication can be edited only where a revision is accepted: on ACTIVE, with a live peer and no
        // running operation.
        setShown('ha-pub-edit', tab === 'anycast' && !!(CFG && CFG.editable));
        setShown('ha-addr-item', tab !== 'anycast');
        setShown('ha-dev-item', tab !== 'anycast');
        setShown('ha-probe-item', false);
        // The header shows the CONFIGURED probe port; open/closed is per node and shown in its card.
        var cfgProbe = pub.probePort || (pr && pr.port) || '';
        setVal('ha-probe', cfgProbe ? 'TCP ' + cfgProbe : (CFG ? 'not configured' : 'configuration unavailable'));
        // Probe errors must not be hidden: this is a failure on THIS node, not a setting.
        setNote('ha-config-note', pr && pr.error ? 'probe on this node: ' + pr.error : '');
        // Owner is shown only for floating_ip; with anycast the address is on both nodes.
        setShown('ha-owner', tab !== 'anycast');
        setHtml('ha-owner', own ? 'on <b>' + esc(nodeName(own)) + '</b>'
            : '<span class="ha-warn-text">no node is serving this address</span>');
        setText('ha-verdict', v.text);
        setClass('ha-verdict', 'ha-pill ' + v.cls);
        var meta = [];
        if (selfN().epoch != null) meta.push('Epoch ' + selfN().epoch);
        if (pair().config_revision != null) meta.push('Config rev ' + pair().config_revision);
        setNote('ha-meta', meta.join(' · '));
    }

    // A row value is either text or a field in the SAME place. While a row is being edited, polling
    // leaves it alone: what the user types belongs to the user.
    function setVal(id, text) {
        var el = $(id); if (!el || el.querySelector('input, select')) return;
        var s = (text === null || text === undefined || text === '') ? '—' : String(text);
        if (el.textContent !== s) el.textContent = s;
    }
    function setField(id, html) {
        var el = $(id); if (!el) return;
        if (el.innerHTML !== html) el.innerHTML = html;
    }
    // The shared select keeps its value in a hidden input, so one querySelector serves both plain fields
    // and the site component.
    function selVal(name) {
        var el = document.querySelector('.ui-select[data-name="' + name + '"] input[type="hidden"]');
        return el ? el.value : '';
    }

    function applyNode(side, n) {
        var p = 'ha-' + side;
        var active = n.role === 'active';
        var cn = cfgNode(n.node_id) || {};
        setClass(p, 'ha-node ' + (active ? 'is-active' : n.role === 'standby' ? 'is-standby' : 'is-unknown')
            + (n.reachable === false ? ' is-lost' : ''));
        setText(p + '-role', (n.stale || n.reachable === false) ? 'UPDATING…'
            : (active ? 'ACTIVE' : n.role === 'standby' ? 'STANDBY' : 'UNKNOWN'));
        // Node identity lives in an attribute: the label is for people, the attribute is for code that
        // matches the card to a config entry.
        setAttr(p, 'data-node', n.node_id || '');

        setVal(p + '-name', n.name || cn.name);
        setVal(p + '-host', n.hostname || cn.hostname);
        setVal(p + '-loc', n.location || cn.location);
        setVal(p + '-desc', n.description || cn.description);

        // IP address: what the nodes actually talk over (peer channel), and the default replication path.
        // Not editable here: changing it on a live pair would move the peer listener out from under itself.
        // It is changed in the "Paired · HA not configured" state.
        setVal(p + '-addr', ipLine(n, cn));
        var sameRepl = !cn.replication_host || cn.replication_host === cn.peer_listen_host;
        setVal(p + '-repl', sameRepl ? 'Same as IP address' : cn.replication_host);

        // The agent does not report node state if pdns did not answer rping, so a known notifier role
        // proves PowerDNS is reachable.
        setVal(p + '-pdns', n.notifier_on == null ? 'not observed' : 'Online' + (n.pdns_version ? ' \u00b7 ' + n.pdns_version : ''));
        setVal(p + '-db', n.read_only == null ? 'not observed'
            : (n.read_only ? 'Replica · Read-only' : 'Primary · Read-write'));
        // Only ACTIVE sends NOTIFY: on STANDBY the notifier is off because it writes notified_serial and
        // the replica is read-only. STANDBY still serves AXFR from its copy; secondaries list both nodes.
        setVal(p + '-notify', n.notifier_on == null ? 'not observed' : (n.notifier_on ? 'Enabled' : 'Disabled'));
        setVal(p + '-axfr', n.read_only == null ? 'not observed' : 'Available');
        // Anycast row: interface, address, probe, and whether it is open HERE.
        //
        //	Anycast   lo:  10.0.0.53/32   TCP 17900   [OPEN / READY]
        //
        // The address is on BOTH nodes (it really is on each loopback); only the probe tells them apart,
        // so it carries the visual weight. The dot is drawn by CSS on the badge, not in the text.
        var pub2 = pubParts((CFG && CFG.payload) || {});
        var anycast = pubMode() === 'anycast' && !!pub2.address;
        setShown(p + '-anycast-row', anycast);
        if (anycast) {
            // "OPEN" refers to the OBSERVED port, not the configured one. Right after a port change the
            // config has the new port while the old one is still listening: report APPLYING until they match.
            var cfgPort = +pub2.probePort || 0;
            var openPort = +n.probe_open_port || 0;
            var applying = cfgPort > 0 && openPort > 0 && openPort !== cfgPort;
            var known = n.route_announced != null;
            var open = n.route_announced === 1 && (!cfgPort || openPort === cfgPort);
            var state = applying ? 'APPLYING…'
                : !known ? 'not observed'
                    : open ? (n.service_ready ? 'OPEN / READY' : 'OPEN') : 'CLOSED';
            setField(p + '-anycast',
                '<span class="ha-if">' + esc(n.publication_device || cfgNode(n.node_id).publication_device || 'lo') + ':</span>'
                + '<b class="ha-anycast-addr">' + esc(pub2.address) + '</b>'
                + (pub2.probePort ? '<span class="ha-anycast-port">TCP ' + esc(pub2.probePort) + '</span>' : '')
                + '<span class="ha-strip-gap"></span>'
                + '<span class="ha-state ' + (applying || !known ? '' : open ? 'on' : 'off') + '">'
                + state + '</span>');
            setClass(p + '-anycast-row', 'ha-row ha-anycast ' + (applying || !known ? '' : open ? 'on' : 'off'));
        }
        setClass(p + '-db', 'ha-val ' + (n.read_only == null ? '' : (n.read_only ? 'idle' : 'ok')));
        setClass(p + '-notify', 'ha-val ' + (n.notifier_on ? 'ok' : (active ? 'err' : 'off')));

        setText(p + '-uuid', shortId(n.node_id));
        setAttr(p + '-uuid', 'title', n.node_id || '');

        // "You are here" means the node answering NOW, not at page load: after the service address moves,
        // another node serves the page.
        var me = (ST && ST.node_id) || DATA.node_id;
        var here = n.node_id === me;
        setShown(p + '-you', here);
        setText(p + '-you', here && !active ? 'you are here · read-only' : 'you are here');

        var lost = n.reachable === false;
        setShown(p + '-alert', lost || !!n.stale);
        setNote(p + '-alert', lost
            ? 'No answer' + (n.error ? ': ' + n.error : '') + ' — values below are the last known state'
            : (n.stale ? 'Snapshot is stale' : ''));

        // Actions: card edit and role switch. The switch starts on ACTIVE, so the button sits on that card.
        var editing = CFG_MODE === 'node:' + side;
        var canSwitch = active && here && DATA.can_manage && !DATA.status_err && !SAVING;
        setHtml(p + '-act', canSwitch
            ? '<button class="btn btn-primary" data-act="switchover"'
              + (busyOp() || editing || BUSY ? ' disabled' : '') + '>Switch to '
              + esc(nodeName(peerN()) || 'the peer') + '</button>'
            : '');
        var canEdit = !!CFG && !(CFG && !CFG.editable) && DATA.can_manage;
        setHtml(p + '-edit-act', editing
            ? window.DNSPanel.formActionsHtml({ act: 'node', attrs: ' data-side="' + side + '"' })
            : (!CFG_MODE && canEdit
                ? '<button class="lnk" data-act="node-edit" data-side="' + side + '">Edit</button>' : ''));
    }

    // Entering edit: same rows, values become fields; nothing appears or disappears.
    function editNode(side) {
        var card = $('ha-' + side);
        var cn = cfgNode(card ? card.getAttribute('data-node') : '') || {};
        function input(id, v, ph) {
            setField(id, '<input id="' + id + '-i" value="' + esc(v == null ? '' : v) + '"'
                + (ph ? ' placeholder="' + esc(ph) + '"' : '') + '>');
        }
        // "e.g." makes placeholders unmistakable: plain example values looked like the edit had invented
        // current values, however faintly the theme draws placeholders.
        input('ha-' + side + '-name', cn.name, 'e.g. DE DNS');
        input('ha-' + side + '-loc', cn.location, 'e.g. Frankfurt');
        input('ha-' + side + '-desc', cn.description, 'e.g. what this node is for');
        // Replication: same address or a separate network; a two-way choice, not a free-form field.
        var same = !cn.replication_host || cn.replication_host === cn.peer_listen_host;
        setField('ha-' + side + '-repl',
            window.DNSPanel.selectHtml('ha_repl_mode_' + side, [
                { value: 'same', label: 'Same as IP address' },
                { value: 'separate', label: 'Separate network' }
            ], same ? 'same' : 'separate')
            + '<input id="ha-' + side + '-repl-i" value="' + esc(same ? '' : cn.replication_host) + '"'
            + ' placeholder="10.20.0.68"' + (same ? ' hidden' : '') + '>');
    }

    // Replication flow: label, state and DIRECTION in a single className assignment. Two writers of the
    // same element's class once wiped `is-rtl`, so there is only one.
    function applyFlow(left) {
        var r = pair().replication || {}, s = selfN(), p = peerN();
        var line = 'replication', note = 'not observed', cls = 'warn';
        if (s.role === 'standby' && r.observed) {
            var running = r.io === 'Yes' && r.sql === 'Yes';
            cls = running ? 'ok' : 'err'; line = 'replicating';
            note = running ? (r.behind_seconds != null ? r.behind_seconds + ' s behind' : 'running')
                : 'stopped (IO=' + (r.io || '?') + ' SQL=' + (r.sql || '?') + ')';
        } else if (s.role === 'active') {
            line = 'replicating';
            cls = p.ha_healthy ? 'ok' : 'warn';
            note = p.ha_healthy ? 'peer reports healthy' : 'peer state degraded';
        }
        // Arrow points FROM source TO replica; cards stay put since they belong to nodes, not roles.
        var rtl = left && left.role !== 'active' ? ' is-rtl' : '';
        setClass('ha-flow', 'ha-flow ' + cls + rtl);
        setText('ha-flow-label', line);
        setText('ha-flow-note', note);
    }

    function recoveryButtons() {
        if (!DATA.can_emerg) return '';
        var s = selfN(), dis = busyOp() ? ' disabled' : '', out = [];
        if (s.role !== 'active') out.push('<button class="btn btn-danger" data-act="emergency"' + dis + '>Emergency promote</button>');
        if (s.role !== 'active' || pair().fenced_node === s.node_id)
            out.push('<button class="btn btn-danger" data-act="reseed"' + dis + '>Reseed this node</button>');
        return out.join(' ');
    }

    // The confirmation phrase names THIS pair, so it cannot be typed blindly. Hostnames, not names: names
    // are free text, hostnames identify machines. Sorted so the phrase does not change with the role.
    function teardownPhrase() {
        var hosts = [selfN().hostname || '', peerN().hostname || ''].filter(Boolean).sort();
        if (hosts.length !== 2) return '';
        return 'dismantle ' + hosts[0] + ' - ' + hosts[1];
    }

    // Dismantle is offered only where it can run: on ACTIVE of a healthy pair, with a live peer and no
    // running operation.
    function applyTeardown() {
        var s = selfN(), p = peerN();
        var can = DATA.can_emerg && !DATA.status_err && s.role === 'active' && !busyOp();
        setShown('ha-teardown', !!DATA.can_emerg && !DATA.status_err);
        if (!DATA.can_emerg || DATA.status_err) return;
        var why = '';
        if (busyOp()) why = 'an operation is running';
        else if (s.role !== 'active') why = 'dismantling is started from the active node';
        else if (!p.reachable) why = nodeName(p.node_id) + ' is not reachable';
        var btn = $('ha-teardown-btn');
        if (btn) btn.disabled = !can || !!why;
        setNote('ha-teardown-note', why);
    }

    function applyTrouble() {
        var st = ST || {}, p = pair();
        var show = !DATA.status_err && !busyOp() && (!st.ha_healthy || !!p.fenced_node);
        setShown('ha-trouble', show);
        if (!show) return;
        setHtml('ha-trouble-why', p.fenced_node
            ? 'Node <b>' + esc(p.fenced_node) + '</b> is fenced: it lost the right to be ACTIVE and must be reseeded '
              + 'before it can rejoin.'
            : 'The pair is degraded' + (st.reason ? ': ' + esc(st.reason) : '')
              + '. Diagnostics below shows the failing check.');
        setHtml('ha-trouble-act', recoveryButtons());
    }

    function opTitle(o) {
        var kind = { planned_switchover: 'Switchover', emergency_promote: 'Emergency promote',
            reseed: 'Reseed', dismantle: 'Dismantle HA' }[o.kind] || o.kind;
        var dir = o.source_node && o.target_node && o.source_node !== o.target_node
            ? ' ' + nodeName(o.source_node) + ' → ' + nodeName(o.target_node)
            : (o.target_node ? ' ' + nodeName(o.target_node) : '');
        return kind + dir;
    }
    // Operation id contains the node UUID and generation: the full value is needed for commands, while
    // people scan for the row. Show head and tail, full value in the tooltip.
    function shortOp(id) {
        var v = String(id == null ? '' : id);
        var m = v.match(/^([a-z]+)-([0-9a-f-]{8})[0-9a-f-]*-(\d+.*)$/);
        return m ? (m[1] + '-' + m[2] + '…-' + m[3]) : v;
    }
    function actorName(v) {
        if (!v) return '—';
        return /^[0-9a-f]{8}-[0-9a-f]{4}-/.test(String(v)) ? nodeName(String(v)) : v;
    }

    function stateCls(s) {
        return s === 'COMPLETED' ? 'ok' : (s === 'RUNNING' || s === 'PENDING' ? 'busy'
            : s === 'COMPLETED_WITH_WARNINGS' ? 'warn' : 'err');
    }
    function when(ts) { return ts ? window.DNSPanel.fmtTime(ts) : ''; }

    // Markup for ONE new row: creating markup is legitimate for an element not yet on screen. All other
    // updates only change values.
    function newStepRow(key) {
        var li = document.createElement('li');
        li.setAttribute('data-step', key);
        li.innerHTML = '<span class="ha-step-at"></span><span class="ha-step-mark"></span>'
            + '<span class="ha-step-name"></span><span class="ha-step-node"></span>'
            + '<span class="ha-step-note"></span>';
        return li;
    }
    function newHistoryRow(id) {
        var tr = document.createElement('tr');
        tr.className = 'clickable';
        tr.setAttribute('data-op', id);
        tr.innerHTML = '<td><span class="ha-hist-title"></span><div class="ha-mute ha-hist-id"></div></td>'
            + '<td class="ha-hist-epoch"></td><td class="ha-hist-by"></td>'
            + '<td class="ha-mute ha-hist-when"></td><td><span class="ha-pill sm ha-hist-state"></span></td>';
        return tr;
    }

    // Journal row cell. Deliberately not a generic name: a same-named function for input fields in this
    // scope would win as the last declaration (this once left the journal empty with all data present).
    function setCell(el, v) { if (el && el.textContent !== String(v)) el.textContent = String(v); }

    // Operation steps are a JOURNAL: rows are appended and never removed until the user closes the card.
    // Removing rows absent from the current response made lines flicker during a switchover.
    // Placeholder row: an empty console looks broken, so until real steps arrive it says what we wait for.
    function setPlaceholder(box, text) {
        var li = box.querySelector('[data-step="_wait"]');
        if (!text) { if (li) box.removeChild(li); return; }
        if (!li) { li = newStepRow('_wait'); li.className = 'busy'; box.appendChild(li); }
        setCell(li.children[1], '·');
        setCell(li.children[2], text);
    }

    function applySteps(steps) {
        var box = $('ha-op-steps'); if (!box) return;
        if ((steps || []).length) setPlaceholder(box, '');
        (steps || []).forEach(function (s, i) {
            var key = 'step-' + i + '-' + s.step;
            var li = box.querySelector('[data-step="' + key + '"]');
            if (!li) { li = newStepRow(key); box.appendChild(li); }
            var cls = s.error ? 'err' : (s.ok ? 'ok' : 'busy');
            if (li.className !== cls) li.className = cls;
            setCell(li.children[0], s.at || '');
            setCell(li.children[1], s.error ? '✕' : (s.ok ? '✓' : '·'));
            setCell(li.children[2], String(s.step).replace(/_/g, ' '));
            // Name, not UUID.
            setCell(li.children[3], s.node_id ? nodeName(s.node_id) : '');
            setCell(li.children[4], s.error || (s.noop ? 'already done' : ''));
            li.children[4].className = 'ha-step-note' + (s.error ? ' err' : '');
        });
    }

    // Steps restart only when the card switches to a DIFFERENT operation.
    function resetSteps(opID) {
        var box = $('ha-op-steps'); if (!box) return;
        if (box.getAttribute('data-op') === opID) return;
        box.setAttribute('data-op', opID || '');
        box.innerHTML = '';
    }

    function applyOperation() {
        var cur = CUR_OP, o = cur && cur.operation;
        if (!o && (DATA.operations || []).length) { o = DATA.operations[0]; cur = { operation: o, steps: [] }; }
        // No operation yet but the user already clicked: open the console IMMEDIATELY, otherwise nothing
        // happens between the click and the manager's first reply and it looks hung.
        if (!o) {
            if (!STARTING) { setShown('ha-op-strip', false); setShown('ha-op', false); return; }
            setShown('ha-op-strip', false); setShown('ha-op', true);
            setText('ha-op-title', STARTING);
            setText('ha-op-state', 'starting'); setClass('ha-op-state', 'ha-pill sm busy');
            setShown('ha-op-spin', true); setShown('ha-op-hide', false); setShown('ha-op-foot', false);
            setText('ha-op-id', ''); setHtml('ha-op-meta', ''); setShown('ha-op-reason', false);
            var wbox = $('ha-op-steps');
            if (wbox) setPlaceholder(wbox, 'requesting the operation…');
            return;
        }
        STARTING = null;
        var running = o.state === 'RUNNING' || o.state === 'PENDING' || !!busyOp();
        // Operation reached a terminal state: only now is the page free again.
        if (BUSY && !running && CUR_OP && CUR_OP.operation && CUR_OP.operation.operation_id === o.operation_id) {
            setBusy(false);
        }
        // Dismantle is not resumed. It aborts BEFORE the first mutation, and the journal keeps a completed
        // drain_gtid as proof the peer applied everything. A resume would skip that step with a stale proof
        // (the node is a normal ACTIVE again and accepts writes); a fresh dismantle rechecks drain and state.
        var canResume = DATA.can_manage && o.kind !== 'dismantle'
            && (o.state === 'FAILED' || o.state === 'ABORTED');
        // Once opened, the console stays open after the operation ends so the journal can be read; the
        // user closes it.
        if (running) rememberConsole(o.operation_id, true);
        // Only a RUNNING operation expands by itself. An old failed one expanding after reload looked like
        // a fresh breakage on a healthy pair; it stays collapsed in "Last operation" and History.
        var expanded = running || DATA.op_open || consoleRemembered(o.operation_id);

        setShown('ha-op-strip', !expanded);
        setShown('ha-op', expanded);
        if (!expanded) {
            setText('ha-op-strip-title', opTitle(o));
            setText('ha-op-strip-state', String(o.state).replace(/_/g, ' ').toLowerCase());
            setClass('ha-op-strip-state', 'ha-pill sm ' + stateCls(o.state));
            setNote('ha-op-strip-when', when(o.finished_at || o.started_at));
            return;
        }
        resetSteps(o.operation_id);
        setText('ha-op-title', opTitle(o));
        setText('ha-op-state', running ? 'running' : String(o.state).replace(/_/g, ' ').toLowerCase());
        setClass('ha-op-state', 'ha-pill sm ' + (running ? 'busy' : stateCls(o.state)));
        setShown('ha-op-spin', running);
        setText('ha-op-id', shortOp(o.operation_id));
        setAttr('ha-op-id', 'title', o.operation_id);
        setShown('ha-op-hide', !running);
        setHtml('ha-op-meta', 'epoch ' + esc(o.epoch) + ' · by ' + esc(actorName(o.requested_by))
            + (o.accept_relay_loss ? ' · <span class="ha-warn-text">relay tail loss accepted by operator</span>' : ''));
        setShown('ha-op-reason', !!(o.reason || DATA.journal_err));
        setText('ha-op-reason', o.reason || (DATA.journal_err ? 'Journal is temporarily unavailable — the lines '
            + 'above are what has been read so far.' : ''));
        applySteps(cur.steps);
        var sbox = $('ha-op-steps');
        if (sbox) {
            setPlaceholder(sbox, (cur.steps || []).length ? ''
                : (DATA.journal_err ? 'journal unavailable — retrying…'
                    : (running ? 'waiting for the first step…' : 'reading the operation journal…')));
        }
        setShown('ha-op-foot', canResume);
        var btn = document.querySelector('#ha-op-foot [data-act="resume"]');
        if (btn) btn.setAttribute('data-id', o.operation_id);
    }

    // History is keyed by operation_id: existing rows are updated, new ones added, gone ones removed.
    function applyHistory() {
        // Only an array counts; any other type means "nothing to show", not a broken page.
        var rows = Array.isArray(DATA.operations) ? DATA.operations : [];
        setText('ha-history-toggle', (DATA.history_open ? 'Hide history' : 'History')
            + (DATA.ops_err ? ' (unavailable)' : ' (' + rows.length + ')'));
        setShown('ha-history', !!DATA.history_open && rows.length > 0);
        if (!DATA.history_open) return;
        var tb = $('ha-history-rows'); if (!tb) return;
        var seen = {};
        rows.forEach(function (o) {
            seen[o.operation_id] = true;
            var tr = tb.querySelector('[data-op="' + o.operation_id + '"]');
            if (!tr) { tr = newHistoryRow(o.operation_id); tb.appendChild(tr); }
            function put(sel, v) { var e = tr.querySelector(sel); if (e && e.textContent !== String(v)) e.textContent = v; }
            put('.ha-hist-title', opTitle(o));
            put('.ha-hist-id', shortOp(o.operation_id));
            var idc = tr.querySelector('.ha-hist-id');
            if (idc && idc.getAttribute('title') !== o.operation_id) idc.setAttribute('title', o.operation_id);
            put('.ha-hist-epoch', o.epoch);
            // Initiator is either a person or a node; a node UUID in the "By" column says nothing.
            put('.ha-hist-by', actorName(o.requested_by));
            put('.ha-hist-when', when(o.finished_at || o.started_at));
            put('.ha-hist-state', String(o.state).replace(/_/g, ' ').toLowerCase());
            var st = tr.querySelector('.ha-hist-state');
            var cls = 'ha-pill sm ha-hist-state ' + stateCls(o.state);
            if (st && st.className !== cls) st.className = cls;
        });
        Array.prototype.slice.call(tb.children).forEach(function (tr) {
            if (!seen[tr.getAttribute('data-op')]) tb.removeChild(tr);
        });
    }

    function diagRows() {
        var st = ST || {}, p = pair(), r = p.replication || {}, d = st.decision || {}, s = selfN(), pe = peerN();
        return [
            ['Control', [
                ['Epoch', s.epoch], ['Authority', (p.authority || '—') + (p.authority_state ? ' / ' + p.authority_state : '')],
                ['Decision', (d.action || '—') + (d.reason ? ' / ' + d.reason : '')],
                ['Fencing', p.fenced_node || 'none'],
                ['Config revision', p.config_revision], ['Config hash', p.config_hash ? String(p.config_hash).slice(0, 24) + '…' : '—']
            ]],
            ['Peer', [
                ['Node', pe.node_id], ['Reachable', pe.reachable ? 'yes' : 'no'],
                ['Role', pe.role], ['Epoch', pe.epoch],
                ['Snapshot', pe.stale ? 'stale' : 'fresh'], ['Error', pe.error || 'none']
            ]],
            ['Replication', [
                ['Observed', r.observed ? 'yes' : 'no'], ['Source', r.source], ['IO', r.io], ['SQL', r.sql],
                ['Lag', r.behind_seconds == null ? '—' : r.behind_seconds + ' s'], ['Error', r.error || 'none']
            ]],
            ['Publication', [
                ['Address', s.publication_address], ['Interface', s.publication_device],
                ['Provider', p.publication]
            ]],
            ['Peer channel', peerChannelRows()]
        ];
    }
    // Diagnostics is a regular site modal; while open it is not recreated, polling only updates values.
    function openDiagnostics() {
        var ov = document.getElementById('modal-overlay');
        if (!ov) return;
        ov.innerHTML = '<div class="modal"><div class="modal-card ha-diag-card">'
            + '<div class="modal-head"><h2 class="modal-title">Diagnostics</h2>'
            + '<button type="button" class="modal-x" data-act="diag-close" aria-label="Close">×</button></div>'
            + '<div id="ha-diag-body"></div>'
            + '<div class="modal-actions"><button type="button" class="btn btn-ghost" data-act="diag-close">Close</button></div>'
            + '</div></div>';
        ov.style.display = 'block';
        Array.prototype.forEach.call(ov.querySelectorAll('[data-act="diag-close"]'), function (b) {
            b.addEventListener('click', closeDiagnostics);
        });
        ov.addEventListener('click', function (ev) { if (ev.target === ov) closeDiagnostics(); });
        document.addEventListener('keydown', diagEsc, true);
        DATA.diag_open = true;
        applyDiagnostics();
    }
    function diagEsc(ev) { if (ev.key === 'Escape') { ev.preventDefault(); closeDiagnostics(); } }
    function closeDiagnostics() {
        DATA.diag_open = false;
        document.removeEventListener('keydown', diagEsc, true);
        var ov = document.getElementById('modal-overlay');
        if (ov) { ov.style.display = 'none'; ov.innerHTML = ''; }
    }
    // The peer channel is changed by a separate rotation procedure, so it is shown only here, not in the form.
    function peerChannelRows() {
        return ((CFG && CFG.payload && CFG.payload.nodes) || []).map(function (n) {
            return [n.node_id, n.peer_listen_host + ':' + n.peer_listen_port];
        });
    }

    function applyDiagnostics() {
        if (!DATA.diag_open) return;
        var groups = diagRows().map(function (g) {
            return '<section class="ha-diag-group"><div class="ha-diag-title">' + esc(g[0]) + '</div>'
                + g[1].map(function (kv) {
                    return '<div class="ha-diag-row"><span>' + esc(kv[0]) + '</span><b>'
                        + esc(kv[1] == null || kv[1] === '' ? '—' : kv[1]) + '</b></div>';
                }).join('') + '</section>';
        }).join('');
        // Passing checks are a counter: a green row takes as much space as a real problem and hides it.
        // Only non-ok checks are expanded.
        var checks = [['Service checks', (ST || {}).service_checks], ['HA checks', (ST || {}).ha_checks]]
            .map(function (c) {
                var list = c[1] || [];
                if (!list.length) return '';
                var bad = list.filter(function (x) { return x.state !== 'ok'; });
                return '<section class="ha-diag-group"><div class="ha-diag-title">' + c[0] + '</div>'
                    + '<div class="ha-diag-row"><span>' + (list.length - bad.length) + ' of ' + list.length
                    + ' passed</span><b class="' + (bad.length ? 'ha-warn-text' : '') + '">'
                    + (bad.length ? bad.length + ' failing' : 'all ok') + '</b></div>'
                    + bad.map(function (x) {
                        return '<div class="ha-check ' + (x.state === 'fail' ? 'err' : 'warn') + '">'
                            + '<span>' + esc(String(x.name).replace(/_/g, ' ')) + '</span>'
                            + '<span class="ha-mute">' + esc(x.detail || '') + '</span></div>';
                    }).join('') + '</section>';
            }).join('');
        setHtml('ha-diag-body', '<div class="ha-diag-cols">' + groups + checks + '</div>');
    }

    // There is no separate Configuration block: configuration is the same rows the user already reads
    // (pair address in the header, node addresses in their cards). Edit turns them into fields in place;
    // Save commits one revision.
    var CFG_MODE = null;   // null | 'service' | 'node:left' | 'node:right': what is being edited

    function pubParts(p) {
        var addr = '', dev = '', probe = '';
        ((p.publication && p.publication.params) || '').split(',').forEach(function (kv) {
            var i = kv.indexOf('=');
            if (i < 0) return;
            var k = kv.slice(0, i).trim();
            if (k === 'address') addr = kv.slice(i + 1).trim();
            else if (k === 'device') dev = kv.slice(i + 1).trim();
            // Probe port is PAIR config, identical on both nodes; ST.probe only knows about this node.
            else if (k === 'probe_port') probe = kv.slice(i + 1).trim();
        });
        return { address: addr, device: dev, probePort: probe };
    }
    // Node address in the same form as anycast: interface, then address. Interface and prefix are the
    // node's own OBSERVATION; until present, show the bare address rather than a made-up "eth0".
    function ipLine(n, cn) {
        var host = cn.peer_listen_host || '';
        if (!host) return null;
        var cidr = n.ip_cidr || host;
        return (n.ip_device ? n.ip_device + ': ' : '') + cidr;
    }

    function cfgNode(id) {
        var nodes = (CFG && CFG.payload && CFG.payload.nodes) || [];
        for (var i = 0; i < nodes.length; i++) if (nodes[i].node_id === id) return nodes[i];
        return {};
    }

    // Read/edit mode switch; values are set by apply(). Only one node is edited at a time: two open forms
    // over one revision are two versions of the config, and the user should not have to guess which wins.
    function applyConfigMode() {
        var locked = !!(CFG && !CFG.editable);
        if (!FLASH) {
            setNote('ha-config-note', locked && CFG ? (CFG.reason || '') : (CFG && CFG.staged
                ? 'Revision ' + CFG.staged.revision + ' is staged but not committed.' : ''));
        }
    }

    // Service address editing is deliberately ABSENT. One revision cannot change it: convergence would
    // bring up the NEW address while the old one stays on the interface, answering on both. Changing
    // publication is an operation (remove old -> apply revision -> bring up new -> verify).

    function val(id) { var e = $(id); return e ? e.value.trim() : ''; }

    // Leaving edit: fields become text again in the same cells; markup is not rebuilt.
    function rebuildValues() {
        ['left', 'right'].forEach(function (side) {
            ['-name', '-loc', '-desc', '-repl'].forEach(function (f) { setField('ha-' + side + f, ''); });
        });
    }

    // Build the revision from what is on screen: start from the read payload and replace ONLY the fields
    // shown in the open form, so unknown fields survive and untouched halves are not overwritten.
    function nodeFromForm(side) {
        var p = JSON.parse(JSON.stringify((CFG && CFG.payload) || {}));
        var card = $('ha-' + side);
        var id = card ? card.getAttribute('data-node') : '';
        (p.nodes || []).forEach(function (n) {
            if (n.node_id !== id) return;
            n.name = val('ha-' + side + '-name-i');
            n.location = val('ha-' + side + '-loc-i');
            n.description = val('ha-' + side + '-desc-i');
            var sep = selVal('ha_repl_mode_' + side) === 'separate';
            // No separate network: replication uses the same address; no point storing a copy that could
            // go stale.
            n.replication_host = sep ? val('ha-' + side + '-repl-i') : n.peer_listen_host;
        });
        return p;
    }

    // Success is not a modal: fields turning back into text and the revision number going up is enough.
    // The modal is for REFUSAL, where there is something to read and decide.
    // The form is locked during the request: two concurrent edits of one revision would race.
    function saveConfig(payload) {
        if (SAVING) return;
        SAVING = true;
        applySaving();
        api('/ha/config', 'PUT', { payload: payload }).then(function (r) {
            SAVING = false;
            CFG_MODE = null;
            rebuildValues();          // fields become text again, in the same cells
            flash(r && r.unchanged ? 'Nothing changed' : 'Saved');
            applySaving();            // buttons live again
            return loadConfig().then(apply);   // values from the freshly read revision, same markup
        }).catch(function (e) {
            SAVING = false;
            // Keep the form and input: the user must see what was rejected and fix it.
            var msg = (e && e.data && (e.data.message || e.data.error)) || (e && e.message) || 'Request failed';
            window.DNSPanel.alert({ title: 'Not applied', message: String(msg) });
            applySaving();
            apply();
        });
    }

    // Form busy state: controls disabled and the action named. Otherwise a 20 s wait looks like a hung
    // page and a second click sends a second request.
    function applySaving() {
        ['left', 'right'].forEach(function (side) {
            var host = $('ha-' + side + '-edit-act');
            if (!host) return;
            host.querySelectorAll('button').forEach(function (b) { b.disabled = SAVING; });
            var save = host.querySelector('[data-act="node-save"]');
            if (save) save.textContent = SAVING ? 'Saving…' : 'Save';
            var card = $('ha-' + side);
            if (card) card.querySelectorAll('input, select').forEach(function (c) { c.disabled = SAVING; });
        });
    }

    // Short success note next to the pair state: visible, nothing to close.
    function flash(text) {
        setNote('ha-config-note', text);
        if (FLASH) clearTimeout(FLASH);
        FLASH = setTimeout(function () { setNote('ha-config-note', ''); FLASH = null; }, 3000);
    }

    function loadConfig() {
        if (DATA.mode !== 'pair' || !DATA.can_manage) return Promise.resolve();
        return api('/ha/config', 'GET').then(function (c) { CFG = c; applyConfigMode(); apply(); })
            .catch(function () { });
    }

    function ackDialog() {
        var acks = [
            ['old_active_database_stopped', 'Database on the former ACTIVE is stopped (verified)'],
            ['old_active_host_down', 'Host is powered off or unreachable at infrastructure level'],
            ['operator_isolated', 'I isolated the former ACTIVE manually']
        ];
        var html = '<p>Emergency promote makes <b>this node</b> active and <b>fences</b> the peer. '
            + 'It never happens automatically: a two-node pair cannot tell «the peer died» from «the link broke».</p>'
            + '<p>Confirm the grounds — they are recorded in the operation journal:</p>'
            + acks.map(function (a, i) {
                return '<label class="chk block"><input type="radio" name="ha-ack" value="' + a[0] + '"'
                    + (i === 0 ? ' checked' : '') + '> ' + esc(a[1]) + '</label>';
            }).join('');
        return window.DNSPanel.dialog({ title: 'Emergency promote', message: html, danger: true, okText: 'Promote node' })
            .then(function (vals) { return vals ? vals['ha-ack'] : null; });
    }

    // BUSY lasts until the operation's TERMINAL state, not the POST reply: the reply only means "created",
    // and in between a second click used to send a second intent.
    function send(path, body, label) {
        setBusy(true);
        STARTING = label || 'Operation';
        DATA.op_open = true;
        apply();
        return api(path, 'POST', body || {}).then(function (r) {
            DATA.op_open = true;
            if (r && r.operation_id) { rememberConsole(r.operation_id, true); loadOperation(r.operation_id); }
            schedule(1200);
        }).catch(function (e) {
            setBusy(false); STARTING = null;
            var msg = (e && e.data && (e.data.message || e.data.error)) || (e && e.message) || 'Request failed';
            window.DNSPanel.alert({ title: e && e.status === 503 ? 'State unknown' : 'Refused', message: String(msg) });
            refresh();
        });
    }

    // Pairing step: like send, but the reply is the new state rather than an operation, so poll at once.
    function pairSend(path, body) {
        setBusy(true);
        // Redraw IMMEDIATELY, not on reply: Configure HA reseeds the peer and replies after minutes, and
        // without this nothing changed on screen, so people clicked again.
        applyPairing();
        return api(path, 'POST', body || {}).then(function (r) {
            setBusy(false);
            if (r && typeof r === 'object' && r.state) DATA.pairing = r;
            DATA.inventory = null;
            applyPairing();
            schedule(1200);
        }).catch(function (e) {
            setBusy(false);
            var msg = (e && e.data && (e.data.message || e.data.error)) || (e && e.message) || 'Request failed';
            window.DNSPanel.alert({ title: e && e.status === 503 ? 'State unknown' : 'Refused', message: String(msg) });
            refresh();
        });
    }

    function onPairAction(act) {
        var p = pairing();
        if (act === 'pair-create') {
            pairSend('/ha/pair/create', {});
        } else if (act === 'pair-join') {
            var addr = ($('pr-addr') || {}).value || '';
            if (!addr.trim()) { window.DNSPanel.alert({ title: 'Address required',
                message: 'Enter the address of the node where pairing is open.' }); return; }
            pairSend('/ha/pair/join', { address: addr.trim() });
        } else if (act === 'pair-approve') {
            // Code confirmation is a human decision, so ask directly whether the digits match.
            window.DNSPanel.confirm({
                title: 'Confirm pairing',
                message: 'Node <b>' + esc(p.peer_node_id || 'the other node') + '</b> at <b>'
                    + esc(p.peer_address || '?') + '</b> shows the code <b>' + esc(p.code || '') + '</b>.<br>'
                    + 'Approve only if you see the same digits there.',
                okText: 'Codes match'
            }).then(function (ok) { if (ok) pairSend('/ha/pair/approve', {}); });
        } else if (act === 'pair-reject') {
            pairSend('/ha/pair/reject', {});
        } else if (act === 'pair-reset') {
            window.DNSPanel.confirm({
                title: 'Undo pairing', danger: true, okText: 'Undo pairing',
                message: 'The nodes stop trusting each other and the shared channel key is removed. '
                    + 'Data on both nodes is left untouched.'
            }).then(function (ok) { if (ok) pairSend('/ha/pair/reset', { force: true }); });
        } else if (act === 'pair-devices') {
            var a = (($('pr-pub-addr') || {}).value || '').trim();
            if (!a) { window.DNSPanel.alert({ title: 'Service address required',
                message: 'Enter the address with its prefix, for example 192.0.2.10/32.' }); return; }
            api('/ha/pair/devices?address=' + encodeURIComponent(a), 'GET').then(function (r) {
                DATA.devices = r || {}; applyPairing();
            }).catch(function (e) {
                DATA.devices = { local_error: (e && e.data && e.data.error) || 'not determined' }; applyPairing();
            });
        } else if (act === 'pair-build') {
            var prov = selVal('pr_pub_prov') || 'floating_ip';
            var addr2 = (($('pr-pub-addr') || {}).value || '').trim();
            // Anycast: the prefix is added for the user, since such an address can only be a single host on
            // loopback. The field is updated so the user submits exactly what they see.
            if (prov === 'anycast' && addr2 && addr2.indexOf('/') < 0) {
                addr2 += addr2.indexOf(':') >= 0 ? '/128' : '/32';
                var f = $('pr-pub-addr');
                if (f) f.value = addr2;
            }
            if (prov !== 'marker' && !addr2) {
                window.DNSPanel.alert({ title: 'Service address required',
                    message: 'Enter the service address, for example 192.0.2.10/32 (for Anycast the /32 is added for you).' });
                return;
            }
            var probe = (($('pr-probe-port') || {}).value || '').trim();
            // Lower bound 1024: the manager opens the probe as user dns-ha and cannot bind privileged ports.
            if (prov === 'anycast' && !(/^\d+$/.test(probe) && +probe >= 1024 && +probe <= 65535)) {
                window.DNSPanel.alert({ title: 'Health probe port required',
                    message: 'Anycast publishes readiness by opening a TCP port. Enter an unprivileged port (1024-65535) the external '
                        + 'health checker will probe, for example 17901.' });
                return;
            }
            // Do not create the pair until EACH node knows where it will bring up the address, or the first
            // switchover hits a missing interface. Anycast always uses loopback, nothing to check.
            if (prov === 'floating_ip' && !devicesReady()) {
                window.DNSPanel.alert({ title: 'Interfaces not confirmed',
                    message: 'Press Check: both nodes must report the interface they will use for this address.' });
                return;
            }
            // Pairing already exists at this point; what is created is the HA configuration.
            window.DNSPanel.confirm({
                title: 'Configure high availability', danger: true, okText: 'Configure HA',
                message: 'Data on <b>' + esc(p.peer_node_id || 'the other node') + '</b> will be ERASED and '
                    + 'replaced with the data of this node. This node keeps its data and becomes active.<br>'
                    + 'Rebuilding takes a minute or two.'
            }).then(function (ok) {
                if (ok) pairSend('/ha/pair/build', prov === 'anycast'
                    ? { provider: prov, address: addr2, probe_port: +probe }
                    : { provider: prov, address: addr2 });
            });
        } else { return false; }
        return true;
    }

    // Publication edit: two fields and one Save. Whether it is a plain revision or one that also cleans up
    // the previous address is the manager's concern.
    function editPublication() {
        var pub = pubParts((CFG && CFG.payload) || {});
        window.DNSPanel.dialog({
            title: 'Anycast publication', okText: 'Save',
            // Fields stacked, label ABOVE the field: `.ha-cfg-row` is sized for wide cards (10rem label +
            // 16rem field) and flex squeezes everything in the 26rem site dialog.
            message: '<div class="dlg-field"><label for="pub-addr">Anycast address</label>'
                + '<input id="pub-addr" name="address" value="' + esc(pub.address) + '" placeholder="10.0.0.53/32"></div>'
                + '<div class="dlg-field"><label for="pub-port">Health probe</label>'
                + '<input id="pub-port" name="probe_port" value="' + esc(pub.probePort) + '" inputmode="numeric" placeholder="17900"></div>'
                + '<p class="ha-mute">The address stays on the loopback of both nodes; the probe is open only '
                + 'on the ACTIVE one. Both nodes are checked before anything is applied.</p>'
        }).then(function (vals) {
            if (!vals) return;
            var addr = String(vals.address || '').trim();
            var port = String(vals.probe_port || '').trim();
            if (!addr) { window.DNSPanel.alert({ title: 'Address required',
                message: 'Enter the anycast address, for example 192.0.2.10 (the /32 is added for you).' }); return; }
            // Port is REQUIRED: an empty field was sent without probe_port, the manager read it as "keep
            // previous", and clearing the value silently changed nothing.
            if (!(/^\d+$/.test(port) && +port >= 1024 && +port <= 65535)) {
                window.DNSPanel.alert({ title: 'Health probe port required',
                    message: 'Anycast needs a readiness probe. Enter an unprivileged port (1024-65535) the '
                        + 'external health checker will probe.' });
                return;
            }
            setBusy(true); apply();
            api('/ha/publication', 'PUT', { address: addr, probe_port: port }).then(function () {
                setBusy(false);
                // Config changed: reread it now rather than waiting for revision reconciliation.
                return loadConfig().then(function () { schedule(1000); });
            }).catch(function (e) {
                setBusy(false);
                var msg = (e && e.data && (e.data.message || e.data.error)) || 'Request failed';
                window.DNSPanel.alert({ title: 'Refused', message: String(msg) });
                apply();
            });
        });
    }

    function onAction(act, id, el) {
        if (act === 'copy-id') {
            var card = $('ha-' + (el ? el.getAttribute('data-side') : ''));
            var full = card ? card.getAttribute('data-node') : '';
            if (full && navigator.clipboard) navigator.clipboard.writeText(full).catch(function () { });
            return;
        }
        if (act === 'edit-pub') { editPublication(); return; }
        if (act.indexOf('pair-') === 0) { onPairAction(act); return; }
        var s = selfN(), p = peerN();
        if (act === 'switchover') {
            window.DNSPanel.confirm({
                title: 'Switch role',
                message: '<b>' + esc(nodeName(s)) + '</b> → <b>' + esc(nodeName(p)) + '</b><br>'
                    + 'The service address moves with the role. Writes pause briefly during the handover.',
                okText: 'Switch role'
            }).then(function (ok) { if (ok) send('/ha/switchover', {}, 'Planned switchover'); });
        } else if (act === 'emergency') {
            ackDialog().then(function (ack) { if (ack) send('/ha/emergency', { ack: ack }, 'Emergency promotion'); });
        } else if (act === 'reseed') {
            window.DNSPanel.confirm({
                title: 'Reseed this node',
                message: 'Data on <b>' + esc(nodeName(s)) + '</b> will be ERASED and reloaded from <b>'
                    + esc(nodeName(p)) + '</b>. The role does not change.',
                okText: 'Reseed', danger: true
            }).then(function (ok) { if (ok) send('/ha/reseed', {}, 'Reseed from active'); });
        } else if (act === 'resume') {
            resumeDialog(id);
        } else if (act === 'history') {
            DATA.history_open = !DATA.history_open; applyHistory();
        } else if (act === 'dismantle') {
            teardownDialog();
        } else if (act === 'op-open') {
            DATA.op_open = true; applyOperation();
        } else if (act === 'op-close') {
            DATA.op_open = false; rememberConsole((CUR_OP && CUR_OP.operation || {}).operation_id, false);
            applyOperation();
        } else if (act === 'diag') {
            openDiagnostics();
        } else if (act === 'diag-close') {
            closeDiagnostics();
        } else if (act === 'node-edit') {
            var side = el ? el.getAttribute('data-side') : '';
            CFG_MODE = 'node:' + side; editNode(side); applyConfigMode(); apply();
        } else if (act === 'node-cancel') {
            CFG_MODE = null; rebuildValues(); applyConfigMode(); apply();
        } else if (act === 'node-save') {
            saveConfig(nodeFromForm(el ? el.getAttribute('data-side') : ''));
        }
    }

    // Dismantle confirmation: consequences are stated here, once, right before the action; the button
    // enables only when this pair's phrase is entered.
    function teardownDialog(resumeID) {
        var phrase = teardownPhrase();
        if (!phrase) {
            window.DNSPanel.alert({ title: 'Pair not identified',
                message: 'Both hostnames must be known before the pair can be dismantled.' });
            return;
        }
        var a = nodeName(selfN().node_id) || selfN().hostname || 'this node';
        var b = nodeName(peerN().node_id) || peerN().hostname || 'the other node';
        var p = window.DNSPanel.dialog({
            title: 'Dismantle HA', danger: true, okText: 'Dismantle HA',
            // Dismantle removes HA but NOT the pairing: nodes stay trusted and HA can be configured again
            // (e.g. as Anycast). Promising "Standalone" would be wrong; removing trust is a separate action.
            message: '<p>High availability is removed from ' + esc(a) + ' and ' + esc(b) + ': each node starts '
                + 'serving on its own and accepts writes. Their current data stays on both nodes, but further '
                + 'changes are no longer replicated.</p>'
                + '<p class="ha-mute">The nodes stay paired — you can configure high availability again '
                + 'without repeating the pairing. Removing the trust is a separate action.</p>'
                + '<p>To confirm, enter:</p>'
                + '<div class="dlg-phrase"><code id="dlg-phrase-text">' + esc(phrase) + '</code>'
                + '<button type="button" class="lnk" id="dlg-phrase-copy">Copy</button></div>'
                + '<input name="confirm" autocomplete="off" spellcheck="false">'
        });
        gatePhrase(phrase);
        return p.then(function (vals) {
            if (!vals || (vals.confirm || '').trim() !== phrase) return;
            if (resumeID) {
                return send('/ha/operations/' + encodeURIComponent(resumeID) + '/resume',
                    { confirm: phrase }, 'Dismantle HA');
            }
            send('/ha/dismantle', { confirm: phrase }, 'Dismantle HA');
        });
    }

    // The confirm button enables only on an exact phrase match, rather than letting the dangerous click
    // happen and then complaining.
    function gatePhrase(phrase) {
        var ov = $('modal-overlay'); if (!ov) return;
        var ok = ov.querySelector('[data-dlg="ok"]');
        var input = ov.querySelector('input[name="confirm"]');
        var copy = ov.querySelector('#dlg-phrase-copy');
        if (!ok || !input) return;
        ok.disabled = true;
        input.addEventListener('input', function () {
            ok.disabled = input.value.trim() !== phrase;
        });
        if (copy) {
            copy.addEventListener('click', function () {
                if (navigator.clipboard) navigator.clipboard.writeText(phrase).catch(function () { });
                copy.textContent = 'Copied';
            });
        }
        input.focus();
    }

    function resumeDialog(id) {
        var op = (CUR_OP || {}).operation || {};
        var dangerous = op.kind === 'emergency_promote';
            // Resuming a dismantle is the same decision as starting one; without the phrase, Resume would be
            // "dismantle without confirmation".
        if (op.kind === 'dismantle') {
            window.DNSPanel.alert({ title: 'Start a new dismantle',
                message: 'A dismantle is not resumed: the drain proof recorded in its journal is no longer '
                    + 'valid once the node keeps accepting writes. Press <b>Dismantle HA</b> to run it '
                    + 'again from the start.' });
            return;
        }
        var html = '<p>Operation <code>' + esc(id) + '</code> continues from the step where it stopped. '
            + 'Completed steps are not repeated.</p>'
            + (op.reason ? '<p class="ha-mute">Stop reason: ' + esc(op.reason) + '</p>' : '')
            + (dangerous ? '<label class="chk block"><input type="checkbox" name="relay_loss"> '
                + 'Allow losing received but unapplied transactions (the relay tail). '
                + 'This is <b>data loss</b>, and is needed only when the drain cannot be proven.</label>' : '');
        return window.DNSPanel.dialog({ title: 'Resume operation', message: html, okText: 'Resume' })
            .then(function (vals) {
                if (!vals) return;
                if (!vals['relay_loss']) return send('/ha/operations/' + encodeURIComponent(id) + '/resume', {}, 'Resume operation');
                return window.DNSPanel.confirm({
                    title: 'Confirm data loss', danger: true, okText: 'Yes, drop the tail',
                    message: 'Transactions received but not applied by this node will be discarded irrecoverably.'
                }).then(function (ok) {
                    if (ok) send('/ha/operations/' + encodeURIComponent(id) + '/resume', { accept_relay_loss: true }, 'Resume operation');
                });
            });
    }

    // build() runs ONLY on page entry and when the pair appears or disappears: on an event, not a timer.
    // One screen, derived from state: no pair -> pairing, pair -> the pair.
    function build() {
        var body = $('ha-body'); if (!body) return;
        if (!DATA.can_manage) {
            body.innerHTML = '<section class="ha-card"><p class="ha-mute">Capability <code>ha.manage</code> required.</p></section>';
            return;
        }
        // Which SCREEN depends on whether HA is on; which pairing section depends on trust. These are two
        // questions with two owners (status.pair.ha_configured and pair_status); collapsing them into one
        // flag once sent a paired node with HA off to the initial pairing screen.
        // Strictly `!== true`: the dashboard is drawn only for PROVEN HA. With null ("manager could not
        // tell") it would claim role, epoch and publication nobody verified.
        // Undetermined is neither screen: offering pairing to a node that may be half of a working pair (it
        // is, every time a switchover moves the address) would look like the pair fell apart.
        if (DATA.ha_configured !== true && DATA.ha_configured !== false) {
            body.innerHTML = '<section class="ha-card"><header class="ha-card-head"><b>Reading high availability state…</b></header>'
                + '<p class="ha-mute">The HA manager has not answered yet. This happens briefly while a switchover '
                + 'moves the service address; the page updates on its own.</p></section>';
            return;
        }
        if (DATA.ha_configured !== true) { body.innerHTML = pairingSkeleton(); applyPairing(); return; }
        body.innerHTML = skeleton();
        applyConfigMode();
        apply();
    }

    // apply() runs on EVERY poll. Values only.
    function apply() {
        if (!DATA.can_manage) return;
        if (DATA.ha_configured !== true) { applyPairing(); return; }
        if (DATA.mode !== 'pair') return;
        if (!$('ha-hero')) return;
        // Cards are pinned to PHYSICAL nodes and never swap places; role is a label inside the card.
        // (Keeping ACTIVE always on the left moved the whole screen after a switchover.)
        // Deterministic order by HA channel address; the id only breaks ties.
        var s = selfN(), p = peerN();
        var left = s, right = p;
        if (nodeOrder(p) < nodeOrder(s)) { left = p; right = s; }
        applyHero();
        applyNode('left', left);
        applyNode('right', right);
        applyFlow(left);
        applyTrouble();
        applyTeardown();
        applyOperation();
        applyHistory();
        applyDiagnostics();
        applyConfigMode();
    }

    // The expanded console survives page reload: after the service address moves the page reloads, and
    // the journal of the switchover that just happened must not vanish with it.
    function rememberConsole(id, open) {
        if (!id) return;
        try {
            if (open) window.sessionStorage.setItem('ha-console', id);
            else window.sessionStorage.removeItem('ha-console');
        } catch (e) { /* private mode: live without memory */ }
    }
    function consoleRemembered(id) {
        try { return !!id && window.sessionStorage.getItem('ha-console') === id; } catch (e) { return false; }
    }

    // The operation journal lives on the node that ran it and may be unreachable briefly during a role
    // move. Rows already shown are NOT cleared: losing the journal of the very switchover the user
    // started is the worst thing this screen could do.
    function loadOperation(id) {
        return api('/ha/operations/' + encodeURIComponent(id), 'GET').then(function (r) {
            // The journal may be partial: the operation is local but its steps live on a peer that did not
            // answer. HTTP still succeeds, so this field is the only sign of it.
            CUR_OP = r; DATA.journal_err = (r && r.journal_error) || null; applyOperation();
        }).catch(function (e) {
            if (authGone(e)) return;
            DATA.journal_err = (e && e.data && e.data.error) || 'journal unavailable';
            applyOperation();
        });
    }

    // The role moved and the page was opened via the SERVICE address, now held by another node; the old
    // one is read-only and no longer ACTIVE. Reload once, saying so.
    function reconnectIfRoleMoved() {
        // The address comes from the live node state: DATA.service_url is fixed at page load and is empty when
        // the page was opened before HA was configured (the donor's own tab).
        var host = serviceAddr();
        if (!host || RECONNECTING) return;
        var me = (ST && ST.node_id) || '';
        var role = (ST && ST.role) || '';
        // Opened via the NODE's own address and it stopped being ACTIVE: nothing to reconnect to, that
        // address stays with the node. Go to the "node is standby" page.
        if (window.location.hostname !== host) {
            if (me && role && role !== 'active' && !busyOp()) leaveStandby();
            return;
        }
        if (!me || role === 'active' || busyOp()) return;   // ACTIVE answering or an operation running: wait
        RECONNECTING = true;
        flash('Reconnecting to ' + (nodeName(peerN()) || 'the active node') + '…');
        setTimeout(function () { window.location.reload(); }, 1200);
    }

    // A node opened via its own address became STANDBY: leave for login, where the server shows
    // "this node is standby" with a link to the service address (and drops the session cookie).
    function leaveStandby() {
        if (RECONNECTING) return;
        RECONNECTING = true;
        window.location.href = '/login?return=' + encodeURIComponent(window.location.pathname);
    }

    function refresh() {
        if (DATA.mode !== 'pair' || !DATA.can_manage) return Promise.resolve();
        // While HA is off there is no pair state to ask for: poll pairing. Once HA appears (configured here
        // or on the peer) the page is rebuilt once, on the event.
        if (!DATA.ha_configured) {
            return api('/ha/pair', 'GET').then(function (pr) {
                DATA.pairing = pr || {}; DATA.pairing_err = null;
                DATA.paired = !!(pr && pr.state === 'trusted');
                applyPairing();
                // HA may have been enabled ON THE PEER: trust is unchanged here, only a new active revision
                // exists, known to our manager. (Checking a nonexistent 'paired' pairing state used to
                // leave the page on the pairing screen until F5.)
                return api('/ha/status', 'GET').then(function (st) {
                    ST = st; DATA.status_err = null;
                    var hc = (st && st.pair) ? st.pair.ha_configured : undefined;
                    if (hc === true) return refreshAfterHAConfigured();
                    // "Proven off" and "undetermined" are different screens; moving between them rebuilds.
                    haKnown(hc === false ? false : null);
                }).catch(function () {
                    haKnown(null);
                });
            }).catch(function (e) {
                if (authGone(e)) return;
                DATA.pairing_err = (e && e.data && e.data.error) || 'ha_manager_unavailable';
                applyPairing();
            });
        }
        // Operation history must NOT disable pair control: a failure here (even a wrongly typed empty list)
        // used to land in the shared catch as "state unknown" and hide the switch button on a healthy pair.
        return api('/ha/status', 'GET').then(function (st) {
            // HA may have been TURNED OFF (dismantled here or on the peer): only that proven answer leaves the
            // dashboard. "Undetermined" happens for a moment during every switchover, while the service
            // address moves and the manager answers again; the dashboard stays with the last confirmed values,
            // says "Reconnecting / State unknown" and offers no actions, instead of flashing a pairing screen
            // that reads as "HA is gone".
            var hc = (st && st.pair) ? st.pair.ha_configured : undefined;
            if (hc === false) { ST = st; return refreshWithoutHA(false); }
            if (hc !== true) { DATA.status_err = 'ha_state_unknown'; apply(); return; }
            ST = st; DATA.status_err = null;
            apply();
            reconnectIfRoleMoved();
            // The peer may have changed the config. The revision in status is always fresh, CFG is read
            // rarely; without this check an open tab would show stale addresses and names indefinitely.
            // Missing CFG also triggers a read: otherwise a page that reached the dashboard without
            // config would never load it.
            var rev = (pair() || {}).config_revision;
            if (rev != null && (!CFG || (CFG.revision != null && CFG.revision !== rev))) loadConfig();
            return api('/ha/operations', 'GET').then(function (ops) {
                var list = (ops && ops.result) || ops;
                DATA.operations = Array.isArray(list) ? list : [];
                DATA.ops_err = null;
                var running = DATA.operations.filter(function (o) {
                    return o.state === 'RUNNING' || o.state === 'PENDING';
                })[0];
                var showId = running ? running.operation_id
                    : ((CUR_OP || {}).operation || {}).operation_id || (DATA.operations[0] || {}).operation_id;
                applyHistory();
                applyOperation();
                if (showId) return loadOperation(showId);
            }).catch(function (e) {
                if (authGone(e)) return;
                // Say history is unavailable; say nothing about the pair, it is healthy.
                DATA.ops_err = (e && e.data && e.data.error) || 'unavailable';
                DATA.operations = [];
                applyHistory();
            });
        }).catch(function (e) {
            if (authGone(e)) return;
            DATA.status_err = (e && e.data && e.data.error) || 'ha_manager_unavailable';
            apply();
        });
    }

    // HA is not on (false) or not known (null): rebuild only when that answer changes, otherwise refresh values.
    function haKnown(v) {
        if (v === DATA.ha_configured) { applyPairing(); return; }
        DATA.ha_configured = v;
        build();
    }

    // HA was enabled: the pairing screen becomes the regular pair page.
    // Config is read BEFORE rebuilding: it did not exist until Configure HA, and switching first would
    // render the dashboard without addresses, names and card order (the two-phase first frame). Polling
    // cannot catch up, since revision reconciliation needs an already-read config.
    function refreshAfterHAConfigured() {
        return api('/ha/config', 'GET').then(function (c) {
            CFG = c;
        }).catch(function () {
            // No config returned: switch the screen anyway, HA is on. Polling fills in missing values
            // (it rereads config when there is none).
        }).then(function () {
            DATA.ha_configured = true;
            build();
        });
    }

    // HA is no longer CONFIRMED: dismantled (false) or undetermined (null). A one-time reverse transition
    // off the dashboard. The two cases show DIFFERENT screens ("Paired · HA not configured" vs "HA
    // configuration status unavailable"), carried by the argument.
    // Without this an open tab would keep the dashboard of a dismantled pair until F5. Config is cleared
    // with the screen: the revision is gone (or unknown), and keeping it would show addresses of a pair
    // that may not exist.
    function refreshWithoutHA(hc) {
        CFG = null;
        DATA.ha_configured = (hc === false) ? false : null;
        return api('/ha/pair', 'GET').then(function (pr) {
            DATA.pairing = pr || {}; DATA.pairing_err = null;
            DATA.paired = !!(pr && pr.state === 'trusted');
        }).catch(function (e) {
            DATA.pairing_err = (e && e.data && e.data.error) || 'ha_manager_unavailable';
        }).then(function () {
            build();
        });
    }

    // Polling is ALWAYS rescheduled: after success, refusal or exception. Rescheduling only on success
    // once froze the page on any unexpected error until F5; for a page served by a moving address that is
    // the worst behaviour, since the address comes back within seconds.
    function schedule(ms) {
        if (TIMER) clearTimeout(TIMER);
        TIMER = setTimeout(function () {
            var again = function () { schedule(busyOp() ? 1000 : 5000); };
            try {
                refresh().then(again, again);
            } catch (e) {
                again();
            }
        }, ms);
    }

    function bind() {
        var page = $('main-content');
        if (!page || page.__haBound) return;
        page.__haBound = true;
        page.addEventListener('click', function (ev) {
            var act = ev.target.closest ? ev.target.closest('[data-act]') : null;
            if (act && !act.disabled && !BUSY) { onAction(act.getAttribute('data-act'), act.getAttribute('data-id'), act); return; }
            if (ev.target && ev.target.name === 'pr-donor') { applyPairing(); return; }
            var row = ev.target.closest ? ev.target.closest('[data-op]') : null;
            if (row) { DATA.op_open = true; loadOperation(row.getAttribute('data-op')); }
        });
        page.addEventListener('change', function (ev) {
            if (!ev.target || !ev.target.id) return;
            if (ev.target.name === 'pr_pub_prov') { applyPairing(); return; }
            if (/-repl-mode$/.test(ev.target.id)) {
                var inp = $(ev.target.id.replace('-mode', '-i'));
                if (inp) inp.hidden = ev.target.value !== 'separate';
            }
        });
    }

    function init() {
        var el = $('ha-data');
        if (!el) return;
        try { DATA = JSON.parse(el.textContent) || {}; } catch (e) { DATA = {}; }
        ST = DATA.status && DATA.status.result ? DATA.status.result : DATA.status;
        // Config comes EMBEDDED in the page with the state, so the first frame has enough data. Without it
        // cards reordered and dashes turned into addresses a moment later when /ha/config arrived.
        CFG = DATA.config || null;
        CUR_OP = null; CFG_MODE = null;
        DATA.inventory = null; DATA.inv_loading = false;
        DATA.history_open = false; DATA.diag_open = false; DATA.op_open = false;
        bind();
        build();
        // Load config ONLY if the page arrived without it (manager was unavailable).
        // async-ok: fallback path; meanwhile the screen shows "configuration unavailable" ("unknown"),
        // not a made-up "not configured".
        if (DATA.ha_configured && !CFG) loadConfig();
        var running = (DATA.operations || []).filter(function (o) { return o.state === 'RUNNING' || o.state === 'PENDING'; })[0];
        // Read the journal now, not on the first poll tick, or the page opens with an empty console.
        var last = running || (DATA.operations || [])[0];
        if (running) DATA.op_open = true;
        // async-ok: the journal lives on the node that ran the operation and comes over the peer channel;
        // until then the console shows "reading the operation journal…".
        if (last) loadOperation(last.operation_id);
        // async-ok: polling starts AFTER the first frame and only changes values.
        schedule(running ? 1000 : 5000);
    }

    function destroy() { if (TIMER) { clearTimeout(TIMER); TIMER = null; } }

    window.DNSPanel = window.DNSPanel || {};
    window.DNSPanel.initHA = init;
    // Single entry point, pageLoaded: after server render on F5 and after menu navigation.
    document.addEventListener('pageLoaded', function (ev) {
        if (ev.detail && ev.detail.page === 'ha') init(); else destroy();
    });
})();
