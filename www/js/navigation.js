/* DNS Panel — SPA-style navigation.
   Page content is loaded into #main-content via AJAX (/ajax/<page>); header/footer are not re-rendered. */

(function () {
    'use strict';

    // Closed list: an unknown path falls back to Dashboard, so a page missing here looks like a broken menu
    // item even though the server serves it. When adding a page, update .htaccess, index.pl and this list.
    const PAGES = ['dashboard', 'zones', 'labels', 'propagation', 'pulse', 'ha', 'audit', 'records', 'settings', 'account', 'documentation'];

    function pageFromPath(pathname) {
        let p = (pathname || '/').replace(/^\//, '').replace(/\/$/, '');
        if (p === '' || p === 'index') return 'dashboard';
        p = p.split('?')[0];
        return PAGES.indexOf(p) !== -1 ? p : 'dashboard';
    }

    function setActiveNav(page) {
        // Records is a sub-page of a zone: highlight Zones in the menu.
        var navPage = (page === 'records') ? 'zones' : page;
        document.querySelectorAll('.nav-link').forEach(function (el) {
            el.classList.toggle('active', el.getAttribute('data-page') === navPage);
        });
    }

    // View key = page + query without modal params (user/group belong to the Users & Access modal).
    // While the key is unchanged, popstate does not reload #main-content, so the Settings background stays.
    let lastViewKey = null;
    function viewKey(page, search) {
        const sp = new URLSearchParams(search || '');
        sp.delete('user'); sp.delete('group');
        return page + '|' + sp.toString();
    }

    // Navigation without reload. The old page stays until the response is ready: swapping in a spinner would
    // flash emptiness and then flash again; the content is replaced in one step.
    // Responses can arrive out of order (Zones then HA, HA answers first, the late Zones response would
    // overwrite the screen and URL), so only the latest navigation's response is applied.
    let navSeq = 0;

    async function loadPage(page, search, push) {
        const main = document.getElementById('main-content');
        if (!main) return;
        const seq = ++navSeq;
        lastViewKey = viewKey(page, search);
        setBusy(true);

        const qs = search || '';
        try {
            // /ajax/<page>?<query> → index.pl?page=<page>&ajax=1&<query> (QSA)
            const res = await fetch('/ajax/' + page + qs, {
                credentials: 'same-origin',
            });
            if (seq !== navSeq) return;   // superseded by a newer navigation
            if (res.redirected || res.status === 401) { window.location.href = '/login'; return; }
            // fetch rejects only on network errors. Without this check an error page (500/403) would replace
            // the content and the "navigation failed, keep the old page" branch below would never run.
            if (!res.ok) throw new Error('HTTP ' + res.status);
            const html = await res.text();
            if (seq !== navSeq) return;   // check again after reading the body, which also takes time
            main.innerHTML = html;
            setBusy(false);
            setActiveNav(page);
            if (push) {
                const url = (page === 'dashboard' ? '/' : '/' + page) + qs;
                history.pushState({ page: page }, '', url);
            }
            document.dispatchEvent(new CustomEvent('pageLoaded', { detail: { page: page } }));
        } catch (e) {
            if (seq !== navSeq) return;   // a superseded navigation failed: nothing to report
            // The old page is still shown; replacing it with an error text would take away what worked,
            // so the message goes alongside, not instead.
            setBusy(false);
            window.DNSPanel && window.DNSPanel.alert && window.DNSPanel.alert({
                title: 'Page did not load', message: 'The page could not be loaded. The current one is left as it is.'
            });
            console.error('navigation: load failed', e);
        }
    }

    // Busy indicator: cursor and dimmed content; nothing is cleared or re-rendered.
    function setBusy(on) {
        const main = document.getElementById('main-content');
        if (main) main.classList.toggle('is-loading', !!on);
    }

    function isInternalNav(a) {
        if (!a) return false;
        // A link with its own handler is not navigation. The Pulse badge in the records table is a real link
        // (middle-click opens it separately), but a normal click opens the editor over this page. Both handlers
        // are on document and this one runs first: navigation had already started, the other handler's
        // preventDefault() could not cancel it, and closing the editor left the user on NS Pulse.
        if (a.hasAttribute('data-pulse-open')) return false;
        const href = a.getAttribute('href') || '';
        if (!href.startsWith('/')) return false;
        if (href.startsWith('/login') || href.startsWith('/logout') || href.startsWith('/dns-api')) return false;
        return true;
    }

    document.addEventListener('click', function (e) {
        const a = e.target.closest && e.target.closest('a');
        if (!isInternalNav(a)) return;
        const url = new URL(a.href, window.location.origin);
        const page = pageFromPath(url.pathname);
        e.preventDefault();
        loadPage(page, url.search, true);
    });

    window.addEventListener('popstate', function () {
        const url = new URL(window.location.href);
        const page = pageFromPath(url.pathname);
        // Only the modal user/group changed on the same page: the modal handles it, no background reload.
        if (viewKey(page, url.search) === lastViewKey) return;
        loadPage(page, url.search, false);
    });

    document.addEventListener('DOMContentLoaded', function () {
        const url = new URL(window.location.href);
        const page = pageFromPath(url.pathname);
        setActiveNav(page);
        // The server already rendered the content into #main-content; fetching it again would show the
        // skeleton and then the real page. Just tell page scripts it is ready: same event as for menu
        // navigation, so F5 and SPA navigation share one lifecycle.
        document.dispatchEvent(new CustomEvent('pageLoaded', { detail: { page: page } }));
    });

    // Public SPA navigation (no full reload), for programmatic use from modals etc.
    window.DNSPanel = window.DNSPanel || {};
    window.DNSPanel.navigate = function (path) {
        try {
            const u = new URL(path, window.location.origin);
            loadPage(pageFromPath(u.pathname), u.search, true);
        } catch (e) { window.location.href = path; }
    };
})();
