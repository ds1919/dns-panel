#!/usr/bin/perl

use strict;
use warnings;
use utf8;
use open ':std', ':encoding(UTF-8)';

use FindBin; use lib "$FindBin::RealBin/include";
use functions qw(json_for_html request_user has_capability
                 pulse_testers_all pulse_groups_all pulse_checks_all pulse_rules_all pulse_zones_writable
                 pulse_server_hint pulse_check_defaults);

# NS Pulse page (tabs Testers | Checks, rendered by js/pulse.js). A record's rule is edited from the
# record's own page. Mutations go to /dns-api/pulse/*.
# The fields here must match the GET /pulse response: the client replaces data wholesale on refresh,
# so a field missing from the first frame stays missing until the first mutation.

sub _esc { my ($s) = @_; return '' unless defined $s;
    $s =~ s/&/&amp;/g; $s =~ s/</&lt;/g; $s =~ s/>/&gt;/g; $s =~ s/"/&quot;/g; return $s; }

my $USER = request_user();
my $CAN  = has_capability($USER, 'pulse.manage') ? 1 : 0;

unless ($CAN) {
    # Name the right as labelled in Users & access, not by its internal key.
    print qq{<div class="card"><p class="text-dim" style="margin:0;">This section needs }
        . qq{<b>Manage NS Pulse</b>.</p></div>\n};
    return 1;
}

my ($testers, $e1) = pulse_testers_all();
my ($groups,  $e2) = pulse_groups_all();
my ($checks,  $e3) = pulse_checks_all();
my ($rules,   $e4) = pulse_rules_all();
my ($zones,   $e5) = pulse_zones_writable();
my $load_err = $e1 || $e2 || $e3 || $e4 || $e5;

if ($load_err) {
    print qq{<div class="card banner-err"><p style="margin:0;">Failed to load NS Pulse: }
        . _esc($load_err) . qq{. The section is unavailable until this is resolved.</p></div>\n};
    return 1;
}

my $DATA = {
    testers => $testers || [],
    groups  => $groups  || [],
    checks  => $checks  || [],
    rules   => $rules   || [],
    # Only zones Pulse can write to (never SLAVE).
    zones   => $zones   || [],
    # Address, intake key and fingerprint to enter on the agent host.
    server  => pulse_server_hint(),
    # Sent from the server so the JS never keeps a second copy that could drift.
    rr_types => [ @functions::PULSE_RR_TYPES ],
    # New-check defaults come from panel settings.
    check_defaults => pulse_check_defaults(),
};

print qq{<div id="pulse-root"></div>\n};
print qq{<script type="application/json" id="pulse-data">} . json_for_html($DATA) . qq{</script>\n};
1;
