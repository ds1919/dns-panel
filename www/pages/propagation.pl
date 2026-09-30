#!/usr/bin/perl

use strict;
use warnings;
use utf8;
use open ':std', ':encoding(UTF-8)';

use FindBin; use lib "$FindBin::RealBin/include";
use JSON qw(encode_json);
use functions qw(json_for_html request_user has_capability
                 secondary_servers_list secondary_groups_all secondary_group_get
                 secondary_nodes_last_change tsig_keys_all ip_groups_all
                 catalogs_all catalog_groups_get catalog_nodes_get catalog_zones distributable_zones
                 nodes_catalogs_map pdns_endpoints zone_direct_axfr_map ha_service_address);

# Propagation page (tabs rendered by js/propagation.js). Mutations go to /dns-api/secondary/* (RBAC server-side).

sub _esc { my ($s) = @_; return '' unless defined $s;
    $s =~ s/&/&amp;/g; $s =~ s/</&lt;/g; $s =~ s/>/&gt;/g; $s =~ s/"/&quot;/g; return $s; }

my $USER     = request_user();
my $CAN_SEC  = has_capability($USER, 'secondary.manage')    ? 1 : 0;
my $CAN_DIST = has_capability($USER, 'distribution.manage') ? 1 : 0;
my $CAN_CAT  = has_capability($USER, 'catalog.manage')      ? 1 : 0;   # provisioning-intent + apply (Configure/Decommission/Apply)

# Load each list only for users who need it: embedded JSON must not leak what the API would refuse.
# Catalogs need server and group names (their subscribers); Direct AXFR does not.
my ($servers, $groups, $tsigs, $ipgs) = ([], [], [], []);
my ($e1, $e2, $e3, $e4);
if ($CAN_SEC || $CAN_CAT) {
    ($servers, $e1) = secondary_servers_list(); $servers ||= [];
    ($groups,  $e2) = secondary_groups_all();   $groups  ||= [];
}
if ($CAN_SEC || $CAN_DIST) {     # as in Settings: either right may view keys and IP groups
    ($tsigs, $e3) = tsig_keys_all(); $tsigs ||= [];
    ($ipgs,  $e4) = ip_groups_all(); $ipgs  ||= [];
}
my $load_err = $e1 || $e2 || $e3 || $e4;

unless ($load_err) {
    for my $g (@$groups) {
        my ($d, $e) = secondary_group_get($g->{id}); $load_err ||= $e; last if $e; next unless $d;
        $g->{axfr_status} = $d->{axfr_status};
        $g->{node_count}  = scalar @{ $d->{nodes} || [] };
        $g->{tsig_keys}   = $d->{tsig_keys} || [];
        $g->{ip_groups}   = $d->{ip_groups} || [];
        $g->{prefixes}    = $d->{prefixes} || [];
    }
}

# Last change per server from audit_log; best-effort, a failure does not break the page.
unless ($load_err) {
    my ($lc) = secondary_nodes_last_change(); $lc ||= {};
    for my $s (@$servers) {
        my $c = $lc->{ $s->{id} } or next;
        $s->{last_by} = $c->{actor};
        $s->{last_at} = $c->{ts};
    }
}

# Without catalog.manage catalogs are hidden everywhere, including the Servers tab column. A failure is a real error.
if ($CAN_CAT && !$load_err) {
    my ($ncm, $ecm) = nodes_catalogs_map(); $load_err ||= $ecm;
    unless ($load_err) { $_->{catalog_ids} = ($ncm || {})->{ $_->{id} } || [] for @$servers; }
}

# Needed by both Direct AXFR and Catalog tabs; a failure does not break the Servers tab.
my @catalogs; my $all_zones = []; my $catalogs_err;
if ($CAN_DIST || $CAN_CAT) {
    my ($zc0, $ezc0) = distributable_zones();
    $catalogs_err = $ezc0;
    unless ($catalogs_err) {
        $all_zones = [ map { { domain_id => $_->{domain_id}+0, zone => $_->{zone}, type => $_->{type},
                               kind => $_->{kind}, kindx => $_->{kindx}, labels => ($_->{labels} || []) } } @{ $zc0 || [] } ];
    }
}

# Catalogs depend only on catalog.manage. Member zones come straight from PowerDNS, the source of truth.
if ($CAN_CAT && !$catalogs_err) {
    my ($cats, $ec) = catalogs_all();
    if ($ec) { $catalogs_err = $ec; }
    else {
        for my $c (@{ $cats || [] }) {
            last if $catalogs_err;
            my ($gids, $eg) = catalog_groups_get($c->{id}); if ($eg) { $catalogs_err = $eg; last; }
            my ($nids, $en) = catalog_nodes_get($c->{id});  if ($en) { $catalogs_err = $en; last; }
            my ($zs,   $ez) = catalog_zones($c->{id});      if ($ez) { $catalogs_err = $ez; last; }
            push @catalogs, {
                catalog_id  => $c->{id},
                name        => $c->{name},
                fqdn        => $c->{fqdn},
                provisioned => $c->{provisioned},
                last_error  => $c->{last_error},
                group_ids   => $gids,
                node_ids    => $nids,
                zone_ids    => [ map { $_->{domain_id} } @$zs ],
            };
        }
    }
    @catalogs = () if $catalogs_err;   # never show a partial list; the tab shows the error
}

# Direct AXFR has its own zone list, independent of catalogs, and its own right.
my $direct_zone_ids = [];
if ($CAN_DIST && !$catalogs_err) {
    my ($dm, $edm) = zone_direct_axfr_map();
    if ($edm) { $catalogs_err = $edm; @catalogs = (); }
    else { $direct_zone_ids = [ map { $_ + 0 } sort { $a <=> $b } keys %$dm ]; }
}

# Our PowerDNS addresses are one per-install setting, not per catalog; consumers fetch the catalog from them.
my $pdns_eps = [];
if ($CAN_CAT && !$catalogs_err) {
    my ($pe, $epe) = pdns_endpoints();
    if ($epe) { $catalogs_err = $epe; @catalogs = (); }
    else { $pdns_eps = [ map { { address => $_->{address}, port => $_->{port}+0 } } grep { $_->{enabled} } @$pe ]; }
}
# In an HA pair the secondaries pull from the service address, the same rule as their BIND configuration.
my $pdns_eps_pair = 0;
if (my $svc = ha_service_address()) {
    $pdns_eps = [ { address => $svc, port => (@$pdns_eps ? $pdns_eps->[0]{port} : 53) } ];
    $pdns_eps_pair = 1;
}

my $DATA = {
    caps    => { sec => $CAN_SEC, dist => $CAN_DIST, cat => $CAN_CAT },
    user    => ($USER ? $USER->{username} : undef),
    servers => $servers,
    groups  => $groups,
    catalogs     => \@catalogs,
    all_zones    => $all_zones,
    # No recipients here: the Servers inventory defines them, so this is just "served or not".
    direct_zone_ids => $direct_zone_ids,
    pdns_endpoints => $pdns_eps,
    pdns_endpoints_pair => $pdns_eps_pair,
    catalogs_err => $catalogs_err,
    options => {
        tsig_keys => [ map { { id => $_->{id}+0, name => $_->{name}, algorithm => $_->{algorithm} } } @$tsigs ],
        ip_groups => [ map { { id => $_->{id}+0, name => $_->{name} } } @$ipgs ],
    },
};

if ($load_err) {
    print qq{<div class="card banner-err"><p style="margin:0;">Failed to load secondary inventory: }
        . _esc($load_err) . qq{. The section is unavailable until this is resolved.</p></div>\n};
    return 1;
}
# Name the rights as labelled in Users & access, not by internal keys.
unless ($CAN_SEC || $CAN_DIST || $CAN_CAT) {
    print qq{<div class="card"><p class="text-dim" style="margin:0;">This section needs }
        . qq{<b>Manage servers</b>, <b>Manage Direct AXFR</b> or <b>Manage catalogs</b>.</p></div>\n};
    return 1;
}

print qq{<div id="prop-root"></div>\n};

print qq{<script type="application/json" id="prop-data">} . json_for_html($DATA) . qq{</script>\n};
1;
