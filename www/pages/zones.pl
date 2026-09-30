#!/usr/bin/perl

use strict;
use warnings;
use utf8;
use open ':std', ':encoding(UTF-8)';

use FindBin; use lib "$FindBin::RealBin/include";
use functions qw(pdns_list_domains request_user build_access_context access_for zone_labels_map
                 zone_kind has_capability sync_problem_zones zone_catalog_map
                 zone_direct_axfr_map zone_dynamic_map zone_signed_map dns_name_html dns_name_unicode);

# Zone list from PowerDNS; zones with no access are hidden.

my $USER = request_user();
my $CTX = build_access_context($USER);
my $CAN_MANAGE = has_capability($USER, 'zones.manage') ? 1 : 0;   # create/delete zones

sub _esc {
    my ($s) = @_;
    return '' unless defined $s;
    $s =~ s/&/&amp;/g; $s =~ s/</&lt;/g; $s =~ s/>/&gt;/g; $s =~ s/"/&quot;/g;
    return $s;
}

sub _type_class {
    my ($t) = @_;
    $t = lc($t || '');
    return 'slave'  if $t eq 'slave';
    return 'native' if $t eq 'native';
    return 'master';
}

# MASTER -> Primary, SLAVE -> Secondary, NATIVE -> Native.
sub _role_label {
    my ($t) = @_;
    $t = uc($t || '');
    return 'Secondary' if $t eq 'SLAVE';
    return 'Native'    if $t eq 'NATIVE';
    return 'Primary';
}

my $all  = pdns_list_domains();
my @ids  = map { $_->{id} } @$all;
my $lmap = zone_labels_map(@ids);          # one query for all zones
# Two independent lists: Direct AXFR and catalog. Errors are not swallowed: empty maps would claim
# "no zone is distributed anywhere"; show a banner instead.
my ($cmap, $cmap_err) = zone_catalog_map();
my ($dmap, $dmap_err) = zone_direct_axfr_map();
my ($dynmap) = zone_dynamic_map();   # zones accepting dynamic updates
my $signed = zone_signed_map();
# Zone features next to the name: short icons, filtered by Features.
my $ICON_DNSSEC = qq{<span class="zone-feat" data-tip="DNSSEC"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6z"/></svg></span>};
my $ICON_DYN    = qq{<span class="zone-feat" data-tip="Dynamic DHCP"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12a9 9 0 0 1-15.5 6.2M3 12a9 9 0 0 1 15.5-6.2"/><path d="M18.5 2v4h-4M5.5 22v-4h4"/></svg></span>};
$cmap ||= {}; $dmap ||= {};
$cmap_err ||= $dmap_err;
my @visible;
for my $d (@$all) {
    my $t = uc($d->{type} || '');
    next if $t eq 'PRODUCER' || $t eq 'CONSUMER';   # catalog zones are not listed here
    my $acc = access_for($CTX, $d->{id});
    next if $acc eq 'none';
    $d->{_access} = $acc;
    $d->{_labels} = $lmap->{ $d->{id} } || [];
    push @visible, $d;
}
my $domains = \@visible;
my $total   = scalar @$domains;
my ($prob_rows, $prob_err) = sync_problem_zones();
my %prob = $prob_err ? () : map { $_->{zone_name} => $_ } @$prob_rows;   # state DB error: no badges, the list still renders
my $prob_count = grep { $prob{ $_->{name} } } @$domains;
# The Sync filter chip appears only when some zone has a problem.
my $sync_chip = $prob_count
    ? qq{<span class="filter-wrap"><button class="filter" type="button" data-filter="sync" data-val="all">Sync: all \x{25be}</button></span>}
    : '';

# The head holds the title, the search with its filters and Add zone in one line, and stays on top while the
# zones scroll (with the table header under it).
print <<HTML;
<div class="page-head zones-head">
    <div class="zones-title">
        <h1>Zones</h1>
        <div class="sub">$total zone(s)</div>
    </div>
    <div class="toolbar">
        <div class="search">
            <svg class="ic" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/></svg>
            <input placeholder="Search zones\x{2026}" id="zone-search">
        </div>
        <span class="filter-wrap"><button class="filter" type="button" data-filter="kind"   data-val="all">Kind: all \x{25be}</button></span>
        <span class="filter-wrap"><button class="filter" type="button" data-filter="labels" data-val="all">Labels: all \x{25be}</button></span>
        <span class="filter-wrap"><button class="filter" type="button" data-filter="type"   data-val="all">Type: all \x{25be}</button></span>
        <span class="filter-wrap"><button class="filter" type="button" data-filter="feat"   data-val="all">Features: all \x{25be}</button></span>
        $sync_chip
        <button class="filter" type="button" id="zone-filter-clear" style="display:none;">\x{2715} Clear</button>
    </div>
    <div class="flex gap-3">
HTML

# Hidden without zones.manage; the server enforces it regardless.
if ($CAN_MANAGE) {
    print <<HTML;
        <button class="btn btn-primary" id="add-zone-btn" type="button">+ Add zone</button>
HTML
}

print <<HTML;
    </div>
</div>
HTML

if ($cmap_err) {
    print qq{<div class="card banner-err"><p style="margin:0;">Distribution column unavailable: }
        . _esc($cmap_err) . qq{. Assignments are not shown, they are not necessarily empty.</p></div>\n};
}

print <<HTML;

<div class="table-wrap zones-wrap">
    <table class="data-table zones-table">
        <colgroup>
            <col class="c-zone"><col class="c-labels"><col class="c-type">
            <col class="c-catalog"><col class="c-serial"><col class="c-rec"><col class="c-act">
        </colgroup>
        <thead>
            <tr>
                <th>Zone</th>
                <th>Labels</th>
                <th>Type</th>
                <th>Distribution</th>
                <th>Serial</th>
                <th class="right">Records</th>
                <th class="right">Actions</th>
            </tr>
        </thead>
        <tbody id="zone-tbody">
HTML

if (@$domains) {
    for my $d (@$domains) {
        my $name   = _esc($d->{name});
        my $type   = uc(_esc($d->{type} || ''));
        my $tclass = _type_class($d->{type});
        # Real SOA serial, not notified_serial (that one tracks the last NOTIFY).
        my $serial = _esc(defined $d->{soa_serial} && length $d->{soa_serial} ? $d->{soa_serial} : "\x{2014}");
        my $count  = _esc($d->{record_count} || 0);
        my $id     = _esc($d->{id});
        my @labs = @{ $d->{_labels} };
        my $labels_html = '';
        if (@labs) {
            my @show = @labs > 3 ? @labs[0..2] : @labs;
            $labels_html = join('', map {
                my $c = $_->{color} ? qq{ style="--c:} . _esc($_->{color}) . qq{"} : '';
                qq{<span class="lbl-tag"$c>} . _esc($_->{value}) . qq{</span>}
            } @show);
            $labels_html .= qq{<span class="lbl-more">+} . (scalar(@labs) - 3) . qq{</span>} if @labs > 3;
        } else {
            $labels_html = qq{<span class="text-mute">\x{2014}</span>};
        }
        # A zone can be both in Direct AXFR and in a catalog, so the column names both facts.
        # "Not distributed" is an answer, whereas a dash would read as "unknown".
        my $cat    = $cmap->{ $d->{id} + 0 };
        my $direct = $dmap->{ $d->{id} + 0 } ? 1 : 0;
        # Show the catalog name in the row; the full "name (fqdn)" goes to the tooltip.
        my @dlv_parts;
        push @dlv_parts, 'Direct AXFR'                     if $direct;
        push @dlv_parts, 'Catalog: ' . _esc($cat->{name} // $cat->{fqdn}) if $cat;
        my $dlv_label = join(' <span class="text-mute">+</span> ', @dlv_parts);
        my @dlv_why;
        push @dlv_why, 'Transferred directly to every server permitted to take zones' if $direct;
        push @dlv_why, 'Announced in catalog ' . _esc(functions::catalog_label($cat)) if $cat;
        my $dlv_title = join('; ', @dlv_why);
        # NATIVE zones cannot be distributed at all (DB-backend replication, no AXFR/NOTIFY; see
        # _zone_distributable), so they say "Not distributable" rather than "Not distributed".
        # The link opens the view where the zone is actually listed: its catalog, or the Direct AXFR tab.
        my $dlv_href = $cat ? "/propagation?catalog=$cat->{id}" : '/propagation?tab=direct';
        my $catalog_html = @dlv_parts
            ? qq{<a href="$dlv_href" class="badge cat-badge" data-tip="$dlv_title">$dlv_label</a>}
            : ($tclass eq 'native'
               ? qq{<span class="text-mute" data-tip="PowerDNS sends no NOTIFY for NATIVE zones and never lists them in a catalog, so the panel does not distribute them">Not distributable</span>}
               : qq{<span class="text-mute">Not distributed</span>});
        my $catdata = $cat ? _esc(lc $cat->{fqdn}) : '';
        # The filter finds a name both as punycode and as it is read.
        my $ndata = _esc(lc join ' ', $d->{name}, dns_name_unicode($d->{name}));
        my $tdata = lc($d->{type} || 'master');
        my $ldata = _esc(join(',', map { lc $_->{value} } @labs));
        my $kind  = zone_kind($d->{name});                         # forward|reverse4|reverse6
        my $kind_badge = ($kind eq 'reverse4') ? qq{ <span class="badge kind-rev">REVERSE</span>}
                       : ($kind eq 'reverse6') ? qq{ <span class="badge kind-rev">REVERSE&nbsp;v6</span>} : '';
        # A secondary without SOA has not been transferred yet; this state also blocks Make primary.
        my $xfer_pending = ($tclass eq 'slave' && !(defined $d->{soa_serial} && length $d->{soa_serial})) ? 1 : 0;
        my $pending_badge = $xfer_pending
            ? qq{ <span class="badge sync-badge sync-badge-warn" data-tip="Zone has not been transferred from its primary yet">AXFR&nbsp;pending</span>}
            : '';
        my @feat = (($signed->{ $d->{id} } ? 'dnssec' : ()), (($dynmap && $dynmap->{ $d->{id} }) ? 'dynamic' : ()));
        my $feat_icons = join '', map { $_ eq 'dnssec' ? $ICON_DNSSEC : $ICON_DYN } @feat;
        # Sync problem badge; the zone page has the Retry button.
        my $ps = $prob{ $d->{name} };
        my $sync_issue = $ps ? 1 : 0;
        my $sync_badge = '';
        if ($ps) {
            # pdns_state != active -> SYNC (error); NOTIFY failure while active -> NOTIFY (warning).
            my $pstate = $ps->{pdns_state} // '';
            my %sl = (activation_failed => 'Activation not confirmed', transfer_problem => 'Zone transfer problem',
                      still_served => 'Still served after delete', deactivation_failed => 'Deactivation not confirmed');
            my $serve_bad = ($pstate ne 'active') ? 1 : 0;
            my $t  = ($sl{$pstate} || 'NOTIFY to secondaries failed') . qq{ \x{2014} open zone to retry};
            $sync_badge = qq{ <span class="badge sync-badge } . ($serve_bad ? 'sync-badge-err' : 'sync-badge-warn')
                        . qq{" data-tip="$t">} . ($serve_bad ? 'SYNC' : 'NOTIFY') . qq{</span>};
        }
        # Secondary records are read-only, but the zone itself (upstream/TSIG, settings, deletion) is
        # manageable, so it says Manage. The server enforces access regardless.
        my $action = ($d->{_access} eq 'write' && ($tclass ne 'slave' || $CAN_MANAGE)) ? 'Manage' : 'View';
        # Role change is not offered in the row: it is rare and irreversible, so it lives in Zone settings.
        my $del = $CAN_MANAGE
            ? qq{<button type="button" class="zone-delete js-del-zone" aria-label="Delete zone"}
              . qq{ data-id="$id" data-name="$name" data-records="$count">}
              . qq{<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 6h18M8 6V4h8v2m-9 0v14a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1V6M10 11v6M14 11v6"/></svg></button>}
            : '';
        print <<ROW;
            <tr class="zone-row" data-name="$ndata" data-type="$tdata" data-labels="$ldata" data-kind="$kind" data-catalog="$catdata" data-feat="@{[ join(' ', @feat) ]}" data-sync="@{[ $sync_issue ? 'issue' : 'ok' ]}">
                <td class="zone-name"><a href="/records?zone=$id" class="zone-name-link">@{[ dns_name_html($d->{name}) ]}</a>$feat_icons$kind_badge$sync_badge</td>
                <td>$labels_html</td>
                <td><span class="badge $tclass" data-tip="@{[_esc($type)]}">@{[_role_label($d->{type})]}</span>$pending_badge</td>
                <td>$catalog_html</td>
                <td class="mono text-dim">$serial</td>
                <td class="right mono text-dim">$count</td>
                <td><div class="row-actions"><a href="/records?zone=$id" class="link">$action</a>$del</div></td>
            </tr>
ROW
    }
} else {
    print <<'EMPTY';
            <tr><td colspan="7" class="empty-row">No zones found (or PowerDNS DB not configured).</td></tr>
EMPTY
}

print <<HTML;
        </tbody>
    </table>
</div>
HTML

1;
