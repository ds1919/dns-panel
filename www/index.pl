#!/usr/bin/env perl

use warnings;
use strict;
use CGI ();   # no imports: CGI's html helpers include head(), which would replace header.pl's in a persistent process
use utf8;
use open ':std', ':encoding(UTF-8)';

use FindBin;
use lib "$FindBin::RealBin/include";
require "$FindBin::RealBin/header.pl";
use functions qw(resolve_current_user set_request_user has_capability csrf_token_new ha_sign_in_hint clear_session_cookie);

my $ROOT = "$FindBin::RealBin";

my $q = CGI->new;

my %KNOWN_PAGES = map { $_ => 1 } qw(dashboard zones records settings account labels propagation pulse ha audit documentation);
my %PUBLIC_PAGES = ();

my $page = $q->param('page');
if (!defined $page || $page eq '') {
    my $path_info = $ENV{'PATH_INFO'} || $ENV{'REQUEST_URI'} || '';
    $path_info =~ s/\?.*//;
    $path_info =~ s/^\///;
    $page = $KNOWN_PAGES{$path_info} ? $path_info : 'dashboard';
}
$page = 'dashboard' unless $KNOWN_PAGES{$page};

my $USER = resolve_current_user($q->cookie('session_token'));
set_request_user($USER);

# A pair STANDBY does not serve the panel on its node address. A session may linger from when this node was
# ACTIVE; it cannot be deleted (read-only DB), so just drop the cookie and send the user to the standby page.
if ($USER) {
    my $ha = ha_sign_in_hint();
    if ($ha && ($ha->{code} // '') eq 'standby_read_only' && $ha->{service_url}) {
        my $cookie = clear_session_cookie();
        if (($q->param('ajax') // '') eq '1') {
            # navigation.js turns 401 into /login, which shows the standby page
            print "Status: 401 Unauthorized\nSet-Cookie: $cookie\nContent-Type: application/json; charset=utf-8\n\n";
            print '{"error": "node is standby", "redirect": "/login"}';
        } else {
            my $ret = $page eq 'dashboard' ? '' : "/$page";
            print $q->redirect(-uri => '/login' . ($ret ? '?return=' . CGI::escape($ret) : ''), -cookie => $cookie);
        }
        exit;
    }
}

sub check_session {
    return undef unless $USER;
    return { user_id => $USER->{id}, username => $USER->{username} };
}

my %PAGE_FILE = (
    dashboard => "$ROOT/pages/dashboard.pl",
    zones     => "$ROOT/pages/zones.pl",
    labels    => "$ROOT/pages/labels.pl",
    propagation => "$ROOT/pages/propagation.pl",
    pulse     => "$ROOT/pages/pulse.pl",
    ha        => "$ROOT/pages/ha.pl",
    audit     => "$ROOT/pages/audit.pl",
    records   => "$ROOT/pages/records.pl",
    settings  => "$ROOT/pages/settings.pl",
    account   => "$ROOT/pages/account.pl",
    documentation => "$ROOT/pages/documentation.pl",
);

# AJAX: page content only, without head/shell.
if ($q->param('ajax') && $q->param('ajax') eq '1') {
    my $user_data = check_session();

    if ($q->param('auth_only') && $q->param('auth_only') eq '1') {
        print "Content-Type: text/html; charset=utf-8\n\n";
        print $user_data ? "OK" : "UNAUTHORIZED";
        exit;
    }

    if ($user_data || $PUBLIC_PAGES{$page}) {
        print "Content-Type: text/html; charset=utf-8\n\n";
        $ENV{AJAX_MODE} = '1';
        my $page_file = $PAGE_FILE{$page} || $PAGE_FILE{dashboard};
        do $page_file; die $@ if $@;   # do, not require: a persistent process runs the page on every request
        exit;
    } else {
            # 401 so navigation.js goes to /login instead of showing raw JSON
        print "Status: 401 Unauthorized\n";
        print "Content-Type: application/json; charset=utf-8\n\n";
        print '{"error": "Not authenticated", "redirect": "/login"}';
        exit;
    }
}

my $user_data = check_session();

if ($user_data || $PUBLIC_PAGES{$page}) {
    # CSRF double-submit: a non-HttpOnly cookie that js/app.js sends back as X-CSRF-Token on mutations.
    my @hdr = (-type => 'text/html', -charset => 'utf-8');
    my $secure = (($ENV{HTTPS} && lc($ENV{HTTPS}) eq 'on') || ($ENV{SERVER_PORT} || '') eq '443') ? 1 : 0;
    my @cookies;
    unless (defined $q->cookie('csrf_token') && length $q->cookie('csrf_token')) {
        push @cookies, $q->cookie(-name => 'csrf_token', -value => csrf_token_new(),
                                  -path => '/', -httponly => 0, -samesite => 'Lax', ($secure ? (-secure => 1) : ()));
    }
    # Mirror the profile theme into a cookie so the login page (no user known there) renders in it too.
    if ($USER) {
        my $t = (defined $USER->{theme} && length $USER->{theme}) ? $USER->{theme} : 'auto';
        push @cookies, $q->cookie(-name => 'dp_theme', -value => $t, -path => '/', -expires => '+1y',
                                  -samesite => 'Lax', ($secure ? (-secure => 1) : ()))
            unless ($q->cookie('dp_theme') // '') eq $t;
    }
    push @hdr, -cookie => \@cookies if @cookies;
    print $q->header(@hdr);

    # Theme is known server-side, so the page arrives already styled.
    head($page, ($USER ? $USER->{theme} : undef));
    # Role label is derived from capabilities (users.manage), not legacy users.role.
    my $role_label = $USER ? (has_capability($USER, 'users.manage') ? 'Administrator' : 'Member') : '';
    shell_start($user_data ? 1 : 0, $user_data ? $user_data->{username} : undef, $page, $role_label);

    # Render the page inline on full load (no second AJAX fetch): the first frame must be the real page.
    print qq{        <main id="main-content" class="content">\n};
    {
        my $page_file = $PAGE_FILE{$page} || $PAGE_FILE{dashboard};
        do $page_file; die $@ if $@;
    }
    print qq{        </main>\n};
    shell_end();
} else {
    print $q->redirect('/login');
    exit;
}

1;
