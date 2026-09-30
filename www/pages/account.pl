#!/usr/bin/perl

use strict;
use warnings;
use utf8;
use open ':std', ':encoding(UTF-8)';

# Account page: the user manages only themselves. No admin capability is needed and no foreign id can be
# passed in: every request goes to /account and the server takes the user from the session.
# 2FA state, sessions and preferences are rendered server-side so the first frame is never empty.

my $USER = functions::request_user();
my ($ACC) = $USER ? functions::account_overview($USER->{id}, undef) : (undef);

sub _esc { my $t = shift; $t = '' unless defined $t; $t =~ s/&/&amp;/g; $t =~ s/</&lt;/g; $t =~ s/>/&gt;/g; $t =~ s/"/&quot;/g; return $t }

# Rendered in labelled UTC; the browser converts to the chosen zone (it knows DST rules and the current date).
sub _ts { my ($t) = @_; return "\x{2014}" unless $t; my @g = gmtime($t);
          return sprintf('%04d-%02d-%02d %02d:%02d UTC', $g[5]+1900, $g[4]+1, $g[3], $g[2], $g[1]) }

unless ($ACC) {
    print qq{<div class="page-head"><div><h1>Account</h1></div></div>\n};
    print qq{<div class="card"><p class="text-dim" style="margin:0;">Account data is unavailable.</p></div>\n};
    return 1;
}

my $tz_cur    = $ACC->{timezone} // '';
# Empty means "follow the browser"; the theme list lives in the core module.
my $theme_cur = $ACC->{theme} // '';
my $theme_sel = functions::ui_select_html('pref-theme', functions::account_themes(), $theme_cur);

# Time zones come from the system rather than a hardcoded list.
my @zones = grep { /\S/ } split /\n/, (`timedatectl list-timezones 2>/dev/null` || '');
unless (@zones) { @zones = qw(UTC Europe/London Europe/Moscow Europe/Nicosia Asia/Dubai Asia/Singapore America/New_York) }
my $tz_sel = functions::ui_select_html('pref-tz',
    [ { value => '', label => 'Same as this browser' }, map { { value => $_, label => $_ } } @zones ], $tz_cur);

my $df_sel = functions::ui_select_html('pref-df', [
    { value => '',    label => 'Same as this browser' },
    { value => 'dmy', label => 'DD.MM.YYYY' },
    { value => 'iso', label => 'YYYY-MM-DD' },
    { value => 'mdy', label => 'MM/DD/YYYY' } ], $ACC->{date_format} // '');

my $totp = $ACC->{totp};
my $totp_state = $totp->{enrolled}
    ? ($totp->{replacing}
        ? "On. A replacement is started but not confirmed yet \x{2014} the old app still works."
        : "On \x{2014} sign-in asks for a code.")
    : ($totp->{required}
        ? "Not set up. Your administrator asks for it \x{2014} the next sign-in will walk you through it."
        : "Off \x{2014} sign-in asks for your password only.");
my $codes_left = $ACC->{recovery_codes_left} + 0;
my $codes_note = $totp->{enrolled}
    ? ($codes_left ? "$codes_left recovery codes left." : "No recovery codes left \x{2014} generate new ones.")
    : '';

# Session rows are server-rendered; the script only performs actions and patches rows in place.
my $sess_rows = '';
for my $s (@{ $ACC->{sessions} || [] }) {
    my $cur = $s->{is_current} ? ' <span class="badge">this session</span>' : '';
    my $btn = $s->{is_current} ? ''
            : sprintf('<button type="button" class="btn btn-ghost btn-sm sess-kill" data-id="%d">Sign out</button>', $s->{id});
    $sess_rows .= sprintf(
        '<tr data-id="%d"><td class="ts" data-ts="%d">%s</td><td class="ts" data-ts="%d">%s</td><td>%s%s</td><td class="acct-ua">%s</td><td class="ta-right">%s</td></tr>',
        $s->{id}, $s->{created_at}, _ts($s->{created_at}),
        $s->{expires_at}, _ts($s->{expires_at}),
        _esc($s->{ip} // '—'), $cur, _esc($s->{user_agent} // '—'), $btn);
}
$sess_rows = '<tr><td colspan="5" class="text-dim">No active sessions.</td></tr>' unless length $sess_rows;

my $uname = _esc($ACC->{username});
# A user may belong to no groups; say so instead of inventing a role.
my $groups = join '', map { qq{<span class="badge muted">} . _esc($_) . qq{</span>} } @{ $ACC->{groups} || [] };
$groups = qq{<span class="text-mute">no groups</span>} unless length $groups;
my $email = _esc($ACC->{email} // "\x{2014}");

print <<HTML;
<div class="page-head">
    <div><h1>Account</h1></div>
</div>

<div class="acct-who">
    <span class="acct-who-name">$uname</span>
    <span class="acct-who-sep">\x{00b7}</span><span>$email</span>
    <span class="acct-who-sep">\x{00b7}</span>$groups
</div>
<div class="acct-grid">

<div class="card acct-card">
    <div class="acct-title">Password</div>
    <form id="acct-pw-form" class="acct-form" autocomplete="off">
        <div class="acct-row"><label class="acct-key" for="pw-cur">Current password</label>
            <input type="password" id="pw-cur" class="field-input" autocomplete="current-password"></div>
        <div class="acct-row"><label class="acct-key" for="pw-new">New password</label>
            <input type="password" id="pw-new" class="field-input" autocomplete="new-password"></div>
        <div class="acct-row"><label class="acct-key" for="pw-new2">Repeat</label>
            <input type="password" id="pw-new2" class="field-input" autocomplete="new-password"></div>
        <div class="zform-note">At least 8 characters. Your other sessions are signed out; this one stays.</div>
        <div class="login-error" id="pw-err" hidden></div>
        <div class="acct-actions"><button type="submit" class="btn btn-primary">Change password</button></div>
    </form>
</div>

<div class="card acct-card">
    <div class="acct-title">Two-factor authentication</div>
    <div class="acct-row"><span class="acct-key">Status</span><span id="totp-state">$totp_state</span></div>
    <div class="zform-note" id="totp-codes-note">$codes_note</div>
    <div class="acct-actions">
        <button type="button" class="btn btn-ghost" id="totp-setup">@{[ $totp->{enrolled} ? 'Replace authenticator app' : 'Set up authenticator app' ]}</button>
        <button type="button" class="btn btn-ghost" id="codes-new"@{[ $totp->{enrolled} ? '' : ' hidden' ]}>New recovery codes</button>
        <button type="button" class="btn btn-danger" id="totp-off"@{[ ($totp->{enrolled} && !$totp->{required}) ? '' : ' hidden' ]}>Turn off</button>
    </div>
    <div class="zform-note">@{[ $totp->{required}
        ? 'Two-factor is required for your account by an administrator, so it cannot be turned off here.'
        : 'Two-factor is optional: with it off, signing in asks for your password only.' ]}
        Replacing the app keeps the old one working until you confirm the new one with a code.</div>
</div>

</div>

<div class="card acct-card">
    <div class="acct-title">Display</div>
    <form id="acct-prefs-form" class="acct-form">
        <div class="acct-row"><span class="acct-key">Theme</span>
            $theme_sel</div>
        <div class="acct-row"><span class="acct-key">Time zone</span>
            $tz_sel</div>
        <div class="acct-row"><span class="acct-key">Date format</span>
            $df_sel</div>
        <div class="login-error" id="prefs-err" hidden></div>
        <div class="acct-actions"><button type="submit" class="btn btn-primary">Save</button></div>
    </form>
</div>

<div class="card acct-card">
    <div class="acct-title">Sessions</div>
    <table class="data-table acct-sessions" id="acct-sessions">
        <thead><tr><th>Started</th><th>Expires</th><th>Address</th><th>Client</th><th></th></tr></thead>
        <tbody id="acct-sessions-body">$sess_rows</tbody>
    </table>
    <div class="acct-actions"><button type="button" class="btn btn-ghost" id="sess-others">Sign out other sessions</button></div>
</div>
HTML

1;
