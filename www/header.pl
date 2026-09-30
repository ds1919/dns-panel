#!/usr/bin/env perl
use CGI ();
use strict;
use utf8;

use FindBin;
use lib "$FindBin::RealBin/include";   # paths relative to the entry script, not cwd
use functions ();                      # called by package name; no imports needed

my %PAGE_TITLE = (
    dashboard    => 'Dashboard',
    zones        => 'Zones',
    labels       => 'Labels',
    propagation  => 'Propagation',
    pulse        => 'NS Pulse',
    ha           => 'High availability',
    audit        => 'Audit log',
    records      => 'Records',
    settings     => 'Settings',
    account      => 'Account',
    documentation => 'Documentation',
);

# All scripts load up front (defer): SPA navigation needs every page's logic without reloading the shell.
sub load_all_js {
    my @js_files = (
        '/js/app.js',
        '/js/navigation.js',
        '/js/search.js',
        '/js/zones.js',
        '/js/records.js',
        '/js/labels.js',
        '/js/propagation.js',
        '/js/pulse.js',
        '/js/ha.js',
        '/js/audit.js',
        '/js/settings.js',
        '/js/import.js',
        '/js/dynamic.js',
        '/js/dnssec.js',
        '/js/users_access.js',
        '/js/external.js',
        '/js/account.js',
    );
    my $html = '';
    for my $f (@js_files) {
        my $v = functions::asset_version($f);
        $html .= "    <script src=\"$f?v=$v\" defer></script>\n";
    }
    return $html;
}

sub head {
    my ($page, $theme) = @_;
    $page ||= 'dashboard';
    my ($v_main, $v_dash, $v_ha) = map { functions::asset_version($_) }
        ('/css/main.css', '/css/dashboard.css', '/css/ha.css');
    my $theme_link = functions::theme_css_link($theme);
    my $doc_suffix = $PAGE_TITLE{$page} || 'Dashboard';
    my $doc_title  = "DNS Panel | $doc_suffix";
    # How this person wants times shown (Account → Display); app.js formats every time with it.
    require JSON;
    my $u = functions::request_user() || {};
    (my $prefs = JSON->new->encode({ tz => ($u->{timezone} // ''), df => ($u->{date_format} // '') })) =~ s{</}{<\\/}g;

    print <<HTML;
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex, nofollow">
    <title>$doc_title</title>
    <link rel="icon" type="image/svg+xml" href="/img/favicon.svg">
    <link rel="stylesheet" href="/css/main.css?v=$v_main">
    <link rel="stylesheet" href="/css/dashboard.css?v=$v_dash">
    <link rel="stylesheet" href="/css/ha.css?v=$v_ha">
$theme_link    <script>var BASE_URL='/'; window.DNSPANEL_PREFS=$prefs;</script>
HTML
    print load_all_js();
    print "</head>\n";
}

sub _nav_icon {
    my ($name) = @_;
    my %ic = (
        dashboard => '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>',
        zones     => '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.5 2.5 3.5 6 3.5 9s-1 6.5-3.5 9c-2.5-2.5-3.5-6-3.5-9s1-6.5 3.5-9z"/>',
        labels    => '<path d="M20.59 13.41l-7.17 7.17a2 2 0 0 1-2.83 0L2 12V2h10l8.59 8.59a2 2 0 0 1 0 2.82z"/><circle cx="7" cy="7" r="1.3"/>',
        records   => '<line x1="4" y1="6" x2="20" y2="6"/><line x1="4" y1="12" x2="20" y2="12"/><line x1="4" y1="18" x2="14" y2="18"/>',
        propagation =>'<circle cx="12" cy="12" r="2"/><path d="M8 8a5.5 5.5 0 0 0 0 8M16 8a5.5 5.5 0 0 1 0 8M5 5a10 10 0 0 0 0 14M19 5a10 10 0 0 1 0 14"/>',
        pulse => '<path d="M3 12h4l2.5-7 5 14 2.5-7h4"/>',
        audit => '<path d="M5 3h9l5 5v13H5z"/><path d="M14 3v5h5"/><path d="M8 13h8M8 17h5"/>',
        documentation => '<path d="M4 5a2 2 0 0 1 2-2h13v16H6a2 2 0 0 0-2 2z"/><path d="M4 21V5"/><path d="M8 7h7M8 11h7"/>',
        ha    => '<rect x="3" y="4" width="8" height="7" rx="1"/><rect x="13" y="13" width="8" height="7" rx="1"/><path d="M7 11v4a2 2 0 0 0 2 2h4"/><circle cx="7" cy="7.5" r="1"/><circle cx="17" cy="16.5" r="1"/>',
        settings  => '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-2.9 1.2V21a2 2 0 1 1-4 0v-.1A1.7 1.7 0 0 0 7 19.4a1.7 1.7 0 0 0-1.9.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0-1.2-2.9H1a2 2 0 1 1 0-4h.1A1.7 1.7 0 0 0 2.6 7a1.7 1.7 0 0 0-.3-1.9l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.9.3H7a1.7 1.7 0 0 0 1-1.5V1a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 2.9 1.2l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.9V7a1.7 1.7 0 0 0 1.5 1H23a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/>',
    );
    my $paths = $ic{$name} || $ic{dashboard};
    return qq{<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">$paths</svg>};
}

# Opens the shell (body, sidebar, main column, top bar); the caller prints #main-content, then shell_end().
sub shell_start {
    my ($is_authenticated, $username, $page, $role) = @_;
    $page ||= 'dashboard';
    $role ||= 'user';

    print '<body>';
    print '<div class="app" id="app">';

    print <<HTML;
    <aside class="sidebar">
        <div class="brand">
            <div class="logo">D</div>
            <div class="name">DNS&nbsp;Panel</div>
        </div>
        <nav class="nav">
HTML
    for my $p (qw(dashboard zones labels propagation pulse ha audit settings)) {
        my $href = $p eq 'dashboard' ? '/' : "/$p";
        my $icon = _nav_icon($p);
        my $label = $PAGE_TITLE{$p};
        print qq{            <a href="$href" class="nav-link" data-page="$p">$icon<span>$label</span></a>\n};
    }
    print "        </nav>\n";
    print '        <div class="nav-spacer"></div>';
    # Reference, not a work area: kept apart from the sections, just above the account.
    print qq{        <nav class="nav nav-foot"><a href="/documentation" class="nav-link" data-page="documentation">} . _nav_icon('documentation') . qq{<span>$PAGE_TITLE{documentation}</span></a></nav>\n};

    if ($is_authenticated) {
        my $name = $username || 'User';
        my $initial = uc(substr($name, 0, 1));
        print <<HTML;
        <div class="side-foot">
            <a href="/account" class="user-chip clickable" data-page="account">
                <div class="avatar">$initial</div>
                <div class="u-meta">
                    <div class="u-name">$name</div>
                    <div class="u-role">$role</div>
                </div>
            </a>
        </div>
HTML
    } else {
        print <<HTML;
        <div class="side-foot">
            <a href="/login" class="btn btn-primary" style="width:100%;justify-content:center;">Sign in</a>
        </div>
HTML
    }
    print "    </aside>\n";

# Top bar holds only global record search; it reuses the shared `.search` control.
    print <<HTML;
    <div class="main-col">
        <header class="topbar">
            <div class="search gsearch">
                <svg class="ic" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/></svg>
                <input id="gsearch" placeholder="Search DNS: name or IP&hellip;" autocomplete="off" spellcheck="false">
                <div class="gsearch-menu" id="gsearch-menu" hidden></div>
            </div>
        </header>
HTML
    _standby_banner();
}

# "This node is not active" banner. The write gate would refuse edits on standby anyway, but silently;
# the banner says so up front and names the service address where the panel actually works.
sub _standby_banner {
    return unless functions::ha_mode() eq 'pair';
    my $hint = functions::ha_sign_in_hint();
    return unless $hint;
    my $svc = $hint->{service_url};

    # No banner on the service address: it is printed once per page load, and the role can move a second
    # later, leaving a banner that contradicts the pair cards. The service address always reaches ACTIVE.
    if ($svc) {
        my ($svc_host) = $svc =~ m{^https?://([^/:]+)};
        my ($req_host) = ($ENV{HTTP_HOST} || '') =~ m{^([^:]+)};
        return if $svc_host && $req_host && lc($svc_host) eq lc($req_host);
    }

    my $esc = sub { my $s = defined $_[0] ? "$_[0]" : ''; $s =~ s/&/&amp;/g; $s =~ s/</&lt;/g; $s =~ s/>/&gt;/g; $s =~ s/"/&quot;/g; $s };
    my $where = $svc ? qq{ Manage the pair at <a href="@{[ $esc->($svc) ]}">@{[ $esc->($svc) ]}</a>.} : '';
    print qq{        <div class="node-banner">This node does not hold the service address, }
        . qq{so changes are refused here.$where</div>\n};
}

# Closes the shell. #modal-overlay is the shared dialog; #pulse-overlay is the NS Pulse rule workspace (a screen,
# not a dialog) and sits lower so confirmations and clone dialogs open on top of it.
sub shell_end {
    print <<HTML;
    </div><!-- /.main-col -->
    </div><!-- /.app -->
    <div id="pulse-overlay" style="display:none;"></div>
    <div id="modal-overlay" style="display:none;"></div>
</body>
</html>
HTML
}

1;
