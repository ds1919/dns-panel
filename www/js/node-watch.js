/* DNS Panel — login and standby pages: the node's HA state can change under an open page (a pair being
   created turns this node into a standby, a switchover makes it active). When mode or role changes, show the
   page again as the server now renders it; not while the user is typing, which would lose the input. */
(function () {
    'use strict';
    var seen = null;
    function watch() {
        fetch('/health/ready', { credentials: 'same-origin', cache: 'no-store' })
            .then(function (r) { return r.json(); })
            .then(function (h) {
                var now = (h.mode || '') + '/' + (h.role || '');
                if (seen === null) seen = now;
                var typing = Array.prototype.some.call(document.querySelectorAll('input'),
                    function (i) { return i.type !== 'hidden' && i.value; });
                if (now !== seen && !typing) { location.reload(); return; }
                setTimeout(watch, 5000);
            }, function () { setTimeout(watch, 5000); });
    }
    watch();
})();
