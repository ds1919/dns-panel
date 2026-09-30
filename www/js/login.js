/* Login flow. Drives the multi-step POST /login (JSON + X-CSRF-Token).
   Steps: login → (password_change) → (totp_enroll+recovery | totp_verify / recovery_use) → redirect.
   2FA is optional: users without an app who are not required to have one sign in with a password and get
   a redirect straight away. totp_enroll appears only when an app is required (an admin reset the old one or
   demanded 2FA); voluntary enrollment is on the Account page. */
(function () {
  'use strict';
  var boot = {};
  try { boot = JSON.parse(document.getElementById('login-boot').textContent) || {}; } catch (e) {}
  var CSRF = boot.csrf || '';

  var STEPS = ['method', 'login', 'password', 'enroll', 'recovery', 'verify', 'recuse'];
  var errEl = document.getElementById('login-error');

  function show(step) {
    STEPS.forEach(function (s) {
      var el = document.getElementById('step-' + s);
      if (el) el.hidden = (s !== step);
    });
    hideError();
    var box = document.getElementById('step-' + step);
    if (box) { var inp = box.querySelector('input'); if (inp) setTimeout(function () { inp.focus(); }, 0); }
  }
  function showError(msg) { errEl.textContent = msg; errEl.hidden = false; }
  function hideError() { errEl.hidden = true; errEl.textContent = ''; }

  // Backend messages are codes, not human text. Anything unmapped is shown as-is: an odd phrase is better
  // than silence that makes the form look broken.
  var MESSAGES = {
    'invalid credentials': 'Invalid username or password.',
    'too many attempts': 'Too many attempts. Try again later.',
    'sign-in temporarily unavailable': 'Sign-in is temporarily unavailable on this node.',
    // The secret exists but cannot be decrypted (auth.master_key changed). An app code cannot fix this, so
    // say a reset is needed rather than let the user keep entering valid codes.
    'totp secret unreadable': 'Your two-factor secret cannot be read on the server (the encryption key changed). '
      + 'An administrator must reset two-factor for this account.',
    'totp already enrolled': 'Two-factor is already set up for this account.'
  };

  // The node cannot create sessions (standby / unknown role); this is not a password problem, so point to the active node.
  function showNodeBlock(j) {
    var m = j.message || 'This node cannot sign you in';
    var parts = [/[.!?]$/.test(m) ? m : m + '.'];
    if (j.active_node) parts.push('Active node: ' + j.active_node + (j.active_addr ? ' (' + j.active_addr + ')' : '') + '.');
    if (j.service_url) parts.push('Sign in at ' + j.service_url);
    showError(parts.join(' '));
  }

  // Return target after sign-in. Sent with every step because any of them may be the final one
  // (password without 2FA, verify, recovery).
  function returnTo() {
    var m = /[?&]return=([^&]*)/.exec(window.location.search);
    return m ? decodeURIComponent(m[1]) : '';
  }

  function post(action, data) {
    var body = Object.assign({ action: action, return: returnTo() }, data || {});
    return fetch('/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': CSRF },
      body: JSON.stringify(body),
      credentials: 'same-origin'
    }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (j) {
        if (!r.ok || j.error) {
          var m = MESSAGES[j.error] || j.error || ('Error ' + r.status);
          if (r.status === 429) m = 'Too many attempts. Try again in ' + (j.retry_after || '?') + 's.';
          // Errors must be shown here: they used to be marked handled silently and the form just
          // "did nothing" while the backend refused.
          if (j.error === 'session invalid' || j.error === 'wrong step') {
            showError('Session expired — please sign in again.');
            setTimeout(function () { show('login'); }, 800);
          } else if (r.status === 409 && j.code) {
            showNodeBlock(j);
          } else {
            showError(m);
          }
          var e = new Error(m); e.handled = true; throw e;
        }
        return j;
      });
    });
  }
  function fail(err) { if (!err.handled) showError(err.message || 'Request failed'); }

  // Why sign-in by certificate did not happen (the server looked at what the browser sent).
  function certText() {
    var c = boot.cert_seen || {};
    if (c.state === 'unknown') return 'The certificate "' + c.cn + '" is valid but not assigned to any user. An administrator adds it in Settings → Users & access (client certificates); until then sign in with a password.';
    if (c.state === 'failed') return 'The certificate' + (c.cn ? ' "' + c.cn + '"' : '') + ' was not accepted (' + (c.reason || 'verification failed') + '): it is not issued by the CA this panel trusts.';
    if (c.state === 'none') return 'Your browser did not send a client certificate. Import it into the browser (with its key), reload the page and choose it when asked — or sign in with a password.';
    return '';
  }

  var codes = [];   // recovery codes of the current enrollment (for Copy/Download)

  // Route by server response. No next step (redirect in the response) means sign-in is complete, which is also
  // the plain password answer for users without 2FA.
  function route(j) {
    var next = j && j.next;
    if (next === 'password_change') return show('password');
    if (next === 'totp_enroll') return beginEnroll();
    if (next === 'totp_verify') return show('verify');
    if (j && j.redirect) return done(j);
    show('login');
  }

  function beginEnroll() {
    hideError();
    return post('totp_begin', {}).then(function (j) {
      document.getElementById('f-qr').src = 'data:image/png;base64,' + (j.qr || '');
      document.getElementById('f-secret').textContent = j.secret || '';
      show('enroll');
    }).catch(fail);
  }

  function renderCodes(list) {
    var ul = document.getElementById('f-codes');
    ul.innerHTML = '';
    (list || []).forEach(function (c) { var li = document.createElement('li'); li.textContent = c; ul.appendChild(li); });
  }

  function done(j) { window.location.href = (j && j.redirect) || '/'; }

  document.getElementById('step-login').addEventListener('submit', function (e) {
    e.preventDefault();
    var u = document.getElementById('f-username').value.trim();
    var p = document.getElementById('f-password').value;
    var rem = document.getElementById('f-remember') && document.getElementById('f-remember').checked ? 1 : 0;
    if (!u || !p) return showError('Enter username and password.');
    post('login', { username: u, password: p, remember: rem }).then(route).catch(fail);
  });

  document.getElementById('step-password').addEventListener('submit', function (e) {
    e.preventDefault();
    var a = document.getElementById('f-newpass').value, b = document.getElementById('f-newpass2').value;
    if (a.length < 8) return showError('Password must be at least 8 characters.');
    if (a !== b) return showError('Passwords do not match.');
    post('password', { new_password: a }).then(route).catch(fail);
  });

  document.getElementById('step-enroll').addEventListener('submit', function (e) {
    e.preventDefault();
    var code = document.getElementById('f-enrollcode').value.trim();
    // Confirmed enrollment means signed in; show the recovery codes (optional screen).
    post('totp_confirm', { code: code }).then(function (j) { codes = j.recovery_codes || []; renderCodes(codes); show('recovery'); }).catch(fail);
  });

  // Already signed in on the recovery screen: Copy / Download / Skip / Continue all go to the panel.
  document.getElementById('rc-continue').addEventListener('click', function () { done({}); });
  document.getElementById('rc-skip').addEventListener('click', function () { done({}); });
  document.getElementById('rc-copy').addEventListener('click', function () {
    var text = codes.join('\n');
    if (navigator.clipboard) navigator.clipboard.writeText(text).catch(function () {});
  });
  document.getElementById('rc-download').addEventListener('click', function () {
    var blob = new Blob([codes.join('\n') + '\n'], { type: 'text/plain' });
    var a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'dns-panel-recovery-codes.txt';
    document.body.appendChild(a); a.click(); document.body.removeChild(a); URL.revokeObjectURL(a.href);
  });

  document.getElementById('step-verify').addEventListener('submit', function (e) {
    e.preventDefault();
    var code = document.getElementById('f-verifycode').value.trim();
    post('totp_verify', { code: code }).then(done).catch(fail);
  });
  document.getElementById('use-recovery').addEventListener('click', function () { show('recuse'); });

  document.getElementById('step-recuse').addEventListener('submit', function (e) {
    e.preventDefault();
    var code = document.getElementById('f-reccode').value.trim();
    post('recovery_use', { code: code }).then(done).catch(fail);
  });
  document.getElementById('use-totp').addEventListener('click', function () { show('verify'); });

  document.getElementById('back-method').addEventListener('click', function () { show('method'); });
  Array.prototype.forEach.call(document.querySelectorAll('[data-method]'), function (b) {
    b.addEventListener('click', function () {
      var m = b.getAttribute('data-method');
      if (m === 'password') return show('login');
      // Client-certificate sign-in happens automatically on arrival if the browser presents a bound cert,
      // so being on the login page means there is no valid one.
      showError(certText() || 'Sign in with a password.');
    });
  });

  // Resume the step (reload with an active pending session), else the method choice — which exists only where
  // certificate sign-in is set up; without it the password form comes straight away.
  if (!boot.cert) { var bm = document.getElementById('back-method'); if (bm) bm.hidden = true; }
  if (boot.resume) route({ next: boot.resume }); else show(boot.cert ? 'method' : 'login');
  // A certificate that was sent but did not sign in: say why right away, the person expects it to work.
  if (!boot.resume && boot.cert_seen && (boot.cert_seen.state === 'unknown' || boot.cert_seen.state === 'failed')) showError(certText());

  // Node banner goes after show(): switching steps clears the error message, which would hide the
  // warning exactly when it is needed.
  if (boot.ha && boot.ha.code) showNodeBlock(boot.ha);
})();
