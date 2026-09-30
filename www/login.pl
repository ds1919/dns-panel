#!/usr/bin/perl
# Login entry point.
#   GET:  full session -> panel; valid client cert (mTLS) -> full session at once; else render the login page
#         (+ CSRF cookie; login.js drives the multi-step flow).
#   POST: JSON auth actions (login -> password_change/totp_enroll/recovery/totp_verify -> full cookie).
# Pending sessions live only here: the panel and API (resolve_current_user) reject them.
use strict;
use warnings;
use utf8;
use open ':std', ':encoding(UTF-8)';
use CGI;
use JSON qw(encode_json decode_json);
use CGI::Cookie;

use FindBin; use lib "$FindBin::RealBin/include";
use functions qw(
    resolve_current_user session_by_raw session_close session_open
    authenticate_cert clear_session_cookie user_session_ttl asset_version
    login_password auth_step_password auth_step_totp_begin auth_step_totp_confirm
    auth_step_totp_verify auth_step_recovery_use
    auth_throttle_guard auth_throttle_fail auth_throttle_ok ha_sign_in_hint theme_css_link
);

# Only REMOTE_ADDR for security decisions (throttle, session): X-Forwarded-For and CF headers are client-forged.
# A real proxy in front must set REMOTE_ADDR via mod_remoteip.
sub client_ip { return $ENV{REMOTE_ADDR}; }

my $method = $ENV{REQUEST_METHOD} || 'GET';

# Read the body before CGI->new: on POST CGI consumes STDIN itself and a second read returns nothing.
our $RAW_BODY = '';
if ($method eq 'POST') {
    my $len = $ENV{CONTENT_LENGTH} || 0;
    read(STDIN, $RAW_BODY, $len) if $len > 0 && $len < 100_000;
}

my $q = CGI->new;

my $COOKIE = 'session_token';
my $CSRF   = 'csrf_token';
my $secure = (($ENV{HTTPS} && lc($ENV{HTTPS}) eq 'on') || ($ENV{SERVER_PORT} || '') eq '443') ? 1 : 0;

# ---------------------------------------------------------------- POST (JSON) --
if ($method eq 'POST') { handle_post(); exit; }

# Where to send the user after login (`?return=/ha` when the session expired on an open page).
# Only a local path is accepted: "//evil.example" or "http://..." would make the login form an open redirect.
sub return_to {
    my $r = $q->param('return');
    return '/' unless defined $r && length $r;
    return '/' unless $r =~ m{^/[A-Za-z0-9_\-./?&=%]*$};
    return '/' if $r =~ m{^//};
    return $r;
}

# ----------------------------------------------------------------- GET --------
# STANDBY check comes before "session exists -> panel": index.pl sends STANDBY node-address visits back here,
# so without it the two would loop.
{
    my $ha = ha_sign_in_hint();
    if ($ha && ($ha->{code} // '') eq 'standby_read_only' && $ha->{service_url}) { render_standby_page($ha); exit; }
}

my $tok = $q->cookie($COOKIE);
if ($tok && resolve_current_user($tok)) { print $q->redirect(return_to()); exit; }

# mTLS: a valid client cert bound to a user gives a full session without password/TOTP.
# Not yet verified live (no client certs on the stand; needs only Apache SSLVerifyClient + mod_remoteip).
{
    my $user = authenticate_cert();
    if ($user && $user->{id}) {
        # cert = trusted device: persistent cookie with the user's policy TTL
        my ($raw, $e) = session_open(user_id => $user->{id}, stage => 'full', auth_type => 'cert',
                                     ip => client_ip(), user_agent => $ENV{HTTP_USER_AGENT}, remember => 1);
        if ($raw) { print $q->redirect(-uri => return_to(), -cookie => full_cookie($raw, user_session_ttl($user->{id}), 1)); exit; }
    }
}

# Otherwise render the login page, resuming the step of a pending session if there is one.
my $resume = '';
if ($tok) { my $s = session_by_raw($tok); $resume = $s->{pending_step} if $s && $s->{stage} eq 'pending'; }
render_login_page($resume);
exit;

# =============================================================================
sub respond {
    my ($status, $data, @cookies) = @_;
    my %msg = (200=>'OK',400=>'Bad Request',401=>'Unauthorized',403=>'Forbidden',409=>'Conflict',
               429=>'Too Many Requests',500=>'Internal Server Error',503=>'Service Unavailable');
    print "Status: $status " . ($msg{$status} || 'OK') . "\r\n";
    print "Set-Cookie: $_\r\n" for @cookies;
    print "Cache-Control: no-store\r\n";
    print "Content-Type: application/json; charset=utf-8\r\n\r\n";
    print encode_json($data);
}

# This CGI::Cookie version ignores -max_age, so Max-Age is appended by hand.
sub _cookie {
    my ($raw, $maxage) = @_;
    my $c = CGI::Cookie->new(-name=>$COOKIE, -value=>$raw, -path=>'/', -httponly=>1, -samesite=>'Lax', ($secure ? (-secure=>1) : ()));
    my $s = "$c";
    $s .= "; Max-Age=$maxage" if defined $maxage;
    return $s;
}
sub full_cookie {   # remember=1: persistent (policy Max-Age); remember=0: session cookie
    my ($raw, $ttl, $remember) = @_; $ttl ||= 86400;
    return _cookie($raw, ($remember ? $ttl : undef));
}
sub pending_cookie { return _cookie($_[0], 900); }

# Same `return` check as above, but for JSON login, where it comes in the request body.
sub _post_return {
    my ($in) = @_;
    my $r = ref $in eq 'HASH' ? $in->{return} : undef;
    return '/' unless defined $r && length $r;
    return '/' unless $r =~ m{^/[A-Za-z0-9_\-./?&=%]*$};
    return '/' if $r =~ m{^//};
    return $r;
}

sub handle_post {
    my $in = eval { decode_json($RAW_BODY || '{}') } || {};
    my $action = $in->{action} || '';

    # CSRF double-submit: cookie csrf_token must equal X-CSRF-Token.
    my $csrf_cookie = $q->cookie($CSRF) // '';
    my $csrf_hdr    = $ENV{HTTP_X_CSRF_TOKEN} // '';
    unless (length $csrf_cookie && $csrf_cookie eq $csrf_hdr) {
        return respond(403, { error => 'CSRF token mismatch' });
    }

    my $ip  = client_ip();
    my $tok = $q->cookie($COOKIE);

    # throttle key is the pending session's user_id (TOTP/recovery attempts)
    my $uid_bucket = sub {
        my $s = $tok ? session_by_raw($tok) : undef;
        return ($s && $s->{stage} eq 'pending') ? ('totp:' . $s->{user_id}) : undef;
    };

    if ($action eq 'login') {
        my $u = $in->{username} // ''; my $p = $in->{password} // '';
        my $bucket = 'pw:' . lc($u) . '|' . ($ip // '');
        my ($okg, $retry) = auth_throttle_guard($bucket);
        return respond(429, { error => 'too many attempts', retry_after => $retry }) unless $okg;
        my ($res, $err) = login_password($u, $p, $ip, $ENV{HTTP_USER_AGENT}, ($in->{remember} ? 1 : 0));
        if ($err) {
            # A wrong password is the only case that gets this answer.
            if ($err eq 'invalid credentials') {
                auth_throttle_fail($bucket, 5, 900, 900);
                return respond(401, { error => 'invalid credentials' });
            }
            # Anything else says nothing about the password: a session is a MariaDB row and cannot be created
            # on a standby node. Answering "invalid credentials" would have the user retype a correct password.
            my $ha = ha_sign_in_hint();
            return respond(409, { error => 'node cannot sign you in', code => $ha->{code},
                                  message => $ha->{message}, active_node => $ha->{active_node}, active_addr => $ha->{active_addr},
                                  service_url => $ha->{service_url} }) if $ha;
            return respond(503, { error => 'sign-in temporarily unavailable', detail => $err });
        }
        auth_throttle_ok($bucket);
        # No second factor: the password completes the login and the session is full.
        return respond(200, { ok => 1, redirect => _post_return($in) },
                       full_cookie($res->{session}, $res->{ttl}, $res->{remember}))
            if ($res->{stage} // '') eq 'full';
        return respond(200, { ok => 1, next => $res->{next} }, pending_cookie($res->{session}));
    }

    if ($action eq 'password') {
        my ($res, $err) = auth_step_password($tok, $in->{new_password} // '');
        return respond(step_status($err), { error => $err }) if $err;
        # Temporary password changed and nothing else to ask: same answer as a normal login.
        return respond(200, { ok => 1, redirect => _post_return($in) },
                       full_cookie($res->{session}, $res->{ttl}, $res->{remember}))
            if ($res->{stage} // '') eq 'full';
        return respond(200, { ok => 1, next => $res->{next} });
    }

    if ($action eq 'totp_begin') {
        my ($res, $err) = auth_step_totp_begin($tok, 'DNS Panel');
        return respond(step_status($err), { error => $err }) if $err;
        return respond(200, { ok => 1, otpauth => $res->{otpauth}, qr => $res->{qr_png_base64}, secret => $res->{secret} });
    }

    if ($action eq 'totp_confirm') {
        my $bucket = $uid_bucket->();
        if ($bucket) { my ($okg,$retry) = auth_throttle_guard($bucket); return respond(429,{error=>'too many attempts',retry_after=>$retry}) unless $okg; }
        my ($res, $err) = auth_step_totp_confirm($tok, $in->{code} // '');
        if ($err) { auth_throttle_fail($bucket, 5, 300, 300) if $bucket && $err eq 'invalid code'; return respond(step_status($err), { error => $err }); }
        auth_throttle_ok($bucket) if $bucket;
        # Enrollment done = full session; recovery codes are shown (Copy/Download/Skip) but login is complete.
        return respond(200, { ok => 1, recovery_codes => $res->{recovery_codes}, redirect => _post_return($in) }, full_cookie($res->{session}, $res->{ttl}, $res->{remember}));
    }

    if ($action eq 'totp_verify') {
        my $bucket = $uid_bucket->();
        if ($bucket) { my ($okg,$retry) = auth_throttle_guard($bucket); return respond(429,{error=>'too many attempts',retry_after=>$retry}) unless $okg; }
        my ($res, $err) = auth_step_totp_verify($tok, $in->{code} // '');
        if ($err) { auth_throttle_fail($bucket, 5, 300, 300) if $bucket && $err eq 'invalid code'; return respond(step_status($err), { error => $err }); }
        auth_throttle_ok($bucket) if $bucket;
        return respond(200, { ok => 1, redirect => _post_return($in) }, full_cookie($res->{session}, $res->{ttl}, $res->{remember}));
    }

    if ($action eq 'recovery_use') {
        my $bucket = $uid_bucket->();
        if ($bucket) { my ($okg,$retry) = auth_throttle_guard($bucket); return respond(429,{error=>'too many attempts',retry_after=>$retry}) unless $okg; }
        my ($res, $err) = auth_step_recovery_use($tok, $in->{code} // '');
        if ($err) { auth_throttle_fail($bucket, 5, 300, 300) if $bucket && $err eq 'invalid code'; return respond(step_status($err), { error => $err }); }
        auth_throttle_ok($bucket) if $bucket;
        return respond(200, { ok => 1, redirect => _post_return($in), remaining => $res->{remaining} }, full_cookie($res->{session}, $res->{ttl}, $res->{remember}));
    }

    return respond(400, { error => 'unknown action' });
}

# Step error -> HTTP status. A session problem is 401 (JS returns to the login step).
sub step_status {
    my ($err) = @_; $err ||= '';
    return 401 if $err =~ /session invalid|wrong step/;
    return 400;
}

sub render_login_page {
    my ($resume) = @_;
    require Crypt::URandom;
    my $csrf = unpack('H*', Crypt::URandom::urandom(32));
    my $csrf_cookie = CGI::Cookie->new(-name=>$CSRF, -value=>$csrf, -path=>'/', -httponly=>0,
                                       -samesite=>'Strict', -max_age=>900, ($secure ? (-secure=>1) : ()));
    # If this node cannot create a session, say so before the password is typed. Login stays available since
    # the role can change at any moment. STANDBY never reaches here (see start of GET).
    my $ha = ha_sign_in_hint();
    # Sign-in by client certificate is offered only where it can work: HTTPS, and the node takes client
    # certificates (deploy/tls.sh with etc/tls/client-ca.crt). Otherwise the password form comes straight away.
    my $cert = (($ENV{HTTPS} // '') eq 'on' && -e "$FindBin::RealBin/../etc/tls/client-ca.crt") ? 1 : 0;
    # What happened with a certificate, if the browser sent one (a valid, known one never gets here: it signs in).
    my %cs;
    if ($cert) {
        my $v = $ENV{SSL_CLIENT_VERIFY} // 'NONE';
        %cs = $v eq 'SUCCESS' ? (state => 'unknown', cn => ($ENV{SSL_CLIENT_S_DN_CN} // ''))
            : $v =~ /^FAILED:?(.*)/ ? (state => 'failed', reason => $1, cn => ($ENV{SSL_CLIENT_S_DN_CN} // ''))
            : (state => 'none');
    }
    my $boot = encode_json({ csrf => $csrf, resume => ($resume || ''), ha => $ha, cert => $cert, cert_seen => \%cs });
    my $v_css = asset_version('/css/main.css');
    my $v_js  = asset_version('/js/login.js');
    # User unknown yet: use the theme from the last login on this device (dp_theme, set by index.pl),
    # else the browser theme.
    my $theme_link = theme_css_link(scalar $q->cookie('dp_theme'));
    print "Status: 200 OK\r\n";
    print "Set-Cookie: $csrf_cookie\r\n";
    print "Cache-Control: no-store\r\n";
    print "Content-Type: text/html; charset=utf-8\r\n\r\n";
    print <<HTML;
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex, nofollow">
    <title>DNS Panel | Sign in</title>
    <link rel="icon" type="image/svg+xml" href="/img/favicon.svg">
    <link rel="stylesheet" href="/css/main.css?v=$v_css">
$theme_link    <script type="application/json" id="login-boot">$boot</script>
</head>
<body>
    <div class="login-wrap">
        <div class="login-card">
            <div class="brand"><div class="logo">D</div><div class="name">DNS&nbsp;Panel</div></div>
            <div id="login-error" class="login-error" hidden></div>

            <!-- step 0: choose sign-in method -->
            <div id="step-method" class="login-step" hidden>
                <h1 class="login-h">Sign in</h1>
                <p class="login-sub">Choose how to sign in.</p>
                <button type="button" class="btn btn-primary login-submit" data-method="password">Username &amp; password</button>
                <button type="button" class="btn btn-ghost login-submit" data-method="cert" style="margin-top:.5rem">Client certificate (mTLS)</button>
            </div>

            <!-- step 1: password -->
            <form id="step-login" class="login-step" autocomplete="on">
                <h1 class="login-h">Sign in</h1>
                <label class="login-lbl">Username</label>
                <input class="field-input" id="f-username" name="username" autocomplete="username" autofocus>
                <label class="login-lbl">Password</label>
                <input class="field-input" id="f-password" name="password" type="password" autocomplete="current-password">
                <label class="chk login-remember"><input type="checkbox" id="f-remember"> Remember this device</label>
                <button class="btn btn-primary login-submit" type="submit">Continue</button>
                <button class="btn-link login-link" id="back-method" type="button">← Other sign-in methods</button>
            </form>

            <!-- step 2: change temporary password -->
            <form id="step-password" class="login-step" hidden>
                <h1 class="login-h">Set a new password</h1>
                <p class="text-dim login-sub">Your temporary password must be changed.</p>
                <label class="login-lbl">New password</label>
                <input class="field-input" id="f-newpass" type="password" autocomplete="new-password">
                <label class="login-lbl">Confirm password</label>
                <input class="field-input" id="f-newpass2" type="password" autocomplete="new-password">
                <button class="btn btn-primary login-submit" type="submit">Save &amp; continue</button>
            </form>

            <!-- step 3: set up the authenticator. Two-factor is optional: this step appears only when the
                 person is expected to have one (an administrator reset it or asked for it). -->
            <form id="step-enroll" class="login-step" hidden>
                <h1 class="login-h">Set up authenticator</h1>
                <p class="text-dim login-sub">Scan the QR in Google/MS Authenticator, then enter the 6-digit code.</p>
                <div class="totp-qr"><img id="f-qr" alt="TOTP QR" width="180" height="180"></div>
                <div class="totp-secret">Manual key: <code id="f-secret"></code></div>
                <label class="login-lbl">6-digit code</label>
                <input class="field-input" id="f-enrollcode" inputmode="numeric" autocomplete="one-time-code" maxlength="6">
                <button class="btn btn-primary login-submit" type="submit">Verify</button>
            </form>

            <!-- step 4: recovery codes (already signed in — optional screen) -->
            <div id="step-recovery" class="login-step" hidden>
                <h1 class="login-h">Recovery codes</h1>
                <p class="text-dim login-sub">You're signed in. Optionally save these one-time codes to sign in if you lose your authenticator. Shown only once — no email recovery is configured, so without them a two-factor reset needs another administrator.</p>
                <ul id="f-codes" class="recovery-codes"></ul>
                <div class="ua-add" style="margin-bottom:.8rem;">
                    <button class="btn btn-ghost sm" id="rc-copy" type="button">Copy</button>
                    <button class="btn btn-ghost sm" id="rc-download" type="button">Download</button>
                </div>
                <button class="btn btn-primary login-submit" id="rc-continue" type="button">Continue to panel</button>
                <button class="btn-link login-link" id="rc-skip" type="button">Skip</button>
            </div>

            <!-- step 5: TOTP verify (returning sign-in) -->
            <form id="step-verify" class="login-step" hidden>
                <h1 class="login-h">Two-factor code</h1>
                <p class="text-dim login-sub">Enter the 6-digit code from your authenticator.</p>
                <input class="field-input" id="f-verifycode" inputmode="numeric" autocomplete="one-time-code" maxlength="6" autofocus>
                <button class="btn btn-primary login-submit" type="submit">Verify</button>
                <button class="btn-link login-link" id="use-recovery" type="button">Use a recovery code</button>
            </form>

            <!-- step 5b: recovery code -->
            <form id="step-recuse" class="login-step" hidden>
                <h1 class="login-h">Recovery code</h1>
                <p class="text-dim login-sub">Enter one of your saved recovery codes.</p>
                <input class="field-input" id="f-reccode" autocomplete="one-time-code" placeholder="xxxxx-xxxxx">
                <button class="btn btn-primary login-submit" type="submit">Verify</button>
                <button class="btn-link login-link" id="use-totp" type="button">Use authenticator instead</button>
            </form>
        </div>
    </div>
    <script src="/js/login.js?v=$v_js"></script>
    <script src="/js/node-watch.js?v=@{[ asset_version('/js/node-watch.js') ]}"></script>
</body>
</html>
HTML
}

# Login page on STANDBY: a message and a link to the pair's service address instead of a form that cannot work.
# The return path is carried along so the user lands on the same page after login.
sub render_standby_page {
    my ($ha) = @_;
    my $esc = sub { my $s = defined $_[0] ? "$_[0]" : ''; $s =~ s/&/&amp;/g; $s =~ s/</&lt;/g; $s =~ s/>/&gt;/g; $s =~ s/"/&quot;/g; $s };
    (my $base = $ha->{service_url}) =~ s{/+$}{};
    my $ret = $q->param('return') // '';
    $ret = '' unless $ret =~ m{^/[^/\\]};   # local panel path only
    my $href = $base . '/login' . (length $ret ? '?return=' . CGI::escape($ret) : '');
    my $active = $ha->{active_node}
        ? ' The active node is <b>' . $esc->($ha->{active_node}) . '</b>'
          . ($ha->{active_addr} ? ' (' . $esc->($ha->{active_addr}) . ')' : '') . '.'
        : '';
    my $v_css = asset_version('/css/main.css');
    my $theme_link = theme_css_link(scalar $q->cookie('dp_theme'));
    # Drop the session cookie: it is useless here and cannot be deleted from the read-only DB.
    print "Status: 200 OK\r\nSet-Cookie: " . clear_session_cookie() . "\r\nCache-Control: no-store\r\nContent-Type: text/html; charset=utf-8\r\n\r\n";
    print <<HTML;
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex, nofollow">
    <title>DNS Panel | Standby node</title>
    <link rel="icon" type="image/svg+xml" href="/img/favicon.svg">
    <link rel="stylesheet" href="/css/main.css?v=$v_css">
$theme_link</head>
<body>
    <div class="login-wrap">
        <div class="login-card">
            <div class="brand"><div class="logo">D</div><div class="name">DNS&nbsp;Panel</div></div>
            <h1 class="login-h">This node is standby</h1>
            <p class="login-sub">It keeps a read-only copy of the data and cannot sign you in.$active
               The panel works at the service address of the pair.</p>
            <a class="btn btn-primary login-submit" href="@{[ $esc->($href) ]}">Open @{[ $esc->($base) ]}</a>
        </div>
    </div>
    <script src="/js/node-watch.js?v=@{[ asset_version('/js/node-watch.js') ]}"></script>
</body>
</html>
HTML
}

1;
