/* DNS Panel — Labels management (Settings → Labels).
   CRUD for categories/values via /dns-api/labels/*. Permissions are enforced server-side (labels.manage). */

(function () {
    'use strict';

    async function reload() {
        var main = document.getElementById('main-content');
        if (!main) return;
        try {
            var res = await fetch('/ajax/labels' + window.location.search, { credentials: 'same-origin' });
            if (res.status === 401 || res.redirected) { window.location.href = '/login'; return; }
            // fetch rejects only on network errors; 500/403 arrive as normal responses and would
            // otherwise be inserted into #main-content as page content.
            if (!res.ok) throw new Error('HTTP ' + res.status);
            main.innerHTML = await res.text();
        } catch (e) { console.error('labels: reload failed', e); }
    }

    // After an action only the changed category cards are touched (DNSPanel.patchPage).
    async function refresh() {
        try {
            var changed = await window.DNSPanel.patchPage({ url: '/ajax/labels' + window.location.search,
                lists: [{ sel: '.lbl-cards', item: '.lbl-card', key: 'data-cat-id', by: 'html' }] });
            if (!changed) return reload();
        } catch (e) { console.error('labels: refresh failed', e); return reload(); }
    }

    function esc(s) { return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }
    function fail(err) { window.DNSPanel.alert(err && err.message ? err.message : 'Request failed'); }

    // Deleting a label can drop many zones from distribution. The backend counts this before deleting
    // and refuses above a threshold; show the operator that reason and let them confirm instead.
    async function deleteLabel(path) {
        try { await window.DNSPanel.api(path, { method: 'DELETE' }); return true; }
        catch (err) {
            var msg = (err && err.message) || '';
            if (!/lose or change delivery/.test(msg)) throw err;
            if (!(await window.DNSPanel.confirm({ title: 'Some zones will lose delivery', message: esc(msg),
                                                  okText: 'Delete anyway', danger: true }))) return false;
            await window.DNSPanel.api(path + '?confirm=1', { method: 'DELETE' });
            return true;
        }
    }

    document.addEventListener('click', async function (e) {
        var t = e.target;

        // + Add category
        if (t.closest && t.closest('#lc-add')) {
            e.preventDefault();
            var name = (document.getElementById('lc-name') || {}).value || '';
            // The themed select keeps its value in a hidden input.
            var card = (document.querySelector('[name="lc-card"]') || {}).value || 'multiple';
            if (!name.trim()) return;
            try {
                await window.DNSPanel.api('labels/categories',
                    { method: 'POST', body: JSON.stringify({ name: name.trim(), cardinality: card }) });
                await refresh();
                document.getElementById('lc-name').value = '';
            } catch (err) { fail(err); }
            return;
        }

        // Delete category
        var cd = t.closest && t.closest('.lbl-cat-del');
        if (cd) {
            e.preventDefault();
            var card2 = cd.closest('.lbl-card');
            var title = card2 ? (card2.querySelector('.lbl-card-title') || {}).textContent : '';
            if (!(await window.DNSPanel.confirm({ title: 'Delete category', message: 'Delete category <b>' + esc(title) + '</b> and all its values? Zone assignments will be removed.', okText: 'Delete', danger: true }))) return;
            try {
                if (await deleteLabel('labels/categories/' + cd.getAttribute('data-id'))) await refresh();
            } catch (err) { fail(err); }
            return;
        }

        // + Add value
        var va = t.closest && t.closest('.lbl-val-add');
        if (va) {
            e.preventDefault();
            var cardEl = va.closest('.lbl-card');
            var catId = cardEl.getAttribute('data-cat-id');
            var nameEl = cardEl.querySelector('.lbl-val-name');
            var colorEl = cardEl.querySelector('.lbl-val-color');
            if (!nameEl.value.trim()) return;
            try {
                await window.DNSPanel.api('labels/values', {
                    method: 'POST',
                    body: JSON.stringify({ category_id: parseInt(catId, 10), name: nameEl.value.trim(),
                                           color: colorEl ? colorEl.value : undefined }),
                });
                await refresh();
            } catch (err) { fail(err); }
            return;
        }

        // Delete value
        var vd = t.closest && t.closest('.lbl-val-del');
        if (vd) {
            e.preventDefault();
            try {
                if (await deleteLabel('labels/values/' + vd.getAttribute('data-id'))) await refresh();
            } catch (err) { fail(err); }
            return;
        }
    });
})();
