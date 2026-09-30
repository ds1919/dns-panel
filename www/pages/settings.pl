#!/usr/bin/perl

use strict;
use warnings;
use utf8;
use open ':std', ':encoding(UTF-8)';

use FindBin; use lib "$FindBin::RealBin/include";
use JSON qw(encode_json);
use functions qw(json_for_html request_user has_capability zone_profiles_all catalogs_all users_all perm_groups_all zone_access_domains
                 pulse_sweep_policy pulse_check_defaults);

# Settings page: Zone profiles, Import [zones.manage], Pinger & Pulse [pulse.manage],
# Users & access [users.manage]. Rendered by js/settings.js; edits go through /dns-api/*.

my $USER = request_user();
my $CAN  = ($USER && has_capability($USER, 'zones.manage')) ? 1 : 0;
my ($profiles, $perr) = $CAN ? zone_profiles_all() : ([], undef);
my ($auds,     $aerr) = $CAN ? catalogs_all()      : ([], undef);
$profiles ||= []; $auds ||= [];

my $CAN_USERS = ($USER && has_capability($USER, 'users.manage')) ? 1 : 0;
my ($ulist, $uerr) = $CAN_USERS ? users_all()       : ([], undef);
my ($pglist, $gerr) = $CAN_USERS ? perm_groups_all() : ([], undef);
$ulist ||= []; $pglist ||= [];
my @zones;
if ($CAN_USERS) {
    my $doms = zone_access_domains() || [];   # excludes catalog producer zones
    @zones = map { { id => $_->{id} + 0, name => $_->{name} } } @$doms;
}

# For the zone profile "Default catalog" dropdown.
my @catalogs = map { { id => $_->{id} + 0, name => $_->{name}, fqdn => $_->{fqdn} } } @$auds;

my $CAN_PULSE = ($USER && has_capability($USER, 'pulse.manage')) ? 1 : 0;
my $pulse_policy = {};
if ($CAN_PULSE) {
    # Use the same functions the panel uses at runtime, not raw settings rows: a value corrupted outside
    # the panel would otherwise be shown as-is while checks run with a different one.
    $pulse_policy = { %{ pulse_sweep_policy() } };
    my $d = pulse_check_defaults();
    my %map = (pulse_check_interval => 'interval_seconds', pulse_check_timeout_ms => 'timeout_ms',
               pulse_check_probes => 'probes_per_run', pulse_check_ok_probes => 'ok_probes_required',
               pulse_check_fail_runs => 'fail_threshold', pulse_check_ok_runs => 'ok_threshold');
    $pulse_policy->{$_} = $d->{ $map{$_} } for keys %map;
}

my %DATA = (
    can      => $CAN,
    pulse    => { can => $CAN_PULSE, policy => $pulse_policy },
    load_err => ($perr || $aerr || undef),
    profiles => $profiles,
    catalogs => \@catalogs,
    users    => {
        can          => $CAN_USERS,
        load_err     => ($uerr || $gerr || undef),
        list         => $ulist,
        groups       => $pglist,
        capabilities => [ @functions::CAPABILITIES ],
        cap_groups   => [
            { group => 'Zones', caps => [
                { key => 'zones.manage',  label => 'Manage zones' },
                { key => 'labels.manage', label => 'Manage labels' } ] },
            # Labels match the Propagation tabs; where a right is broader than its tab, the hint says so.
            { group => 'Propagation', caps => [
                { key => 'secondary.manage',    label => 'Manage servers',
                  hint  => 'Servers tab: secondary servers, their groups and addresses.' },
                { key => 'distribution.manage', label => 'Manage Direct AXFR',
                  hint  => 'Direct AXFR tab. Also covers TSIG keys, allowed-IP groups and putting a zone into a catalog.' },
                { key => 'catalog.manage',      label => 'Manage catalogs',
                  hint  => 'Catalog tab: creating and deleting catalogs, their subscribers and servers.' } ] },
            # One right for the whole section: testers and switching rules are a single decision.
            { group => 'NS Pulse', caps => [
                { key => 'pulse.manage', label => 'Manage NS Pulse',
                  hint  => 'Testers, checks and the rules that switch a record. A rule writes DNS, so this '
                         . 'right changes zones without zone write access.' } ] },
            { group => 'Administration', caps => [
                { key => 'users.manage',   label => 'Manage users & access' },
                { key => 'audit.read',     label => 'View audit log' },
                { key => 'ha.manage',      label => 'Manage HA' },
                { key => 'ha.emergency',   label => 'HA emergency actions' } ] },
        ],
        zones        => \@zones,
    },
);

print <<'HTML';
<div id="settings-root"></div>
HTML

print qq{<script type="application/json" id="settings-data">} . json_for_html(\%DATA) . qq{</script>\n};

1;
