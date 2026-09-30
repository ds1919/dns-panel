#!/usr/bin/perl

use strict;
use warnings;
use utf8;
use open ':std', ':encoding(UTF-8)';
use CGI;
use JSON qw(encode_json);

use FindBin; use lib "$FindBin::RealBin/include";
use functions qw(dns_name_html dns_name_unicode pulse_rules_all has_capability json_for_html pdns_list_records pdns_get_domain request_user effective_zone_access
                 pdns_soa_fields pdns_apex_ns_list pdns_profile_map zone_labels_get zone_catalog_map
                 has_capability dns_record_types zone_kind get_zone_sync_state pdns_get_domain_metadata
                 catalogs_available zone_direct_axfr_map zone_recipients connectDB
                 pulse_sweep_zone_states zone_dynamic_map zone_signed_map);

# Manage Zone page (?zone=<domain_id>). SOA and apex NS live in the accordion, not the RRset table.
# Client logic: js/records.js.

sub _esc {
    my ($s) = @_;
    return '' unless defined $s;
    $s =~ s/&/&amp;/g; $s =~ s/</&lt;/g; $s =~ s/>/&gt;/g; $s =~ s/"/&quot;/g;
    return $s;
}
sub _url { my ($v) = @_; $v = '' unless defined $v; $v =~ s/([^A-Za-z0-9._~-])/sprintf('%%%02X', ord $1)/ge; return $v }

sub _pulse_ok_type { return $functions::PULSE_RR_OK{ uc($_[0] // '') } ? 1 : 0; }

sub _rec_params {
    my ($type, $r) = @_;
    my $p = (defined $r->{prio} && $r->{prio} ne '') ? $r->{prio} : '';
    my $c = defined $r->{content} ? $r->{content} : '';
    my $dot = " \x{00b7} ";
    $type = uc($type || '');
    if ($type eq 'MX')  { return "Priority: $p"; }
    if ($type eq 'SRV') { my @x = split /\s+/, $c; return "Priority: $p${dot}Weight: " . ($x[0] // '') . "${dot}Port: " . ($x[1] // ''); }
    if ($type eq 'CAA') { my @x = split /\s+/, $c, 3; return "Flags: " . ($x[0] // '') . "${dot}Tag: " . ($x[1] // ''); }
    return '';
}
sub _rec_value {
    my ($type, $r) = @_;
    my $c = defined $r->{content} ? $r->{content} : '';
    $type = uc($type || '');
    if ($type eq 'SRV') { my @x = split /\s+/, $c;    return $x[2] // ''; }
    if ($type eq 'CAA') { my @x = split /\s+/, $c, 3; return $x[2] // ''; }
    return $c;   # MX: content=mailserver; A/AAAA/CNAME/TXT/... : content
}
# updated_at is 'YYYY-MM-DD HH:MM:SS.ffffff' in UTC; shown to the minute, localized by JS (localizeTimes).
sub _last_change_cell {
    my ($rr) = @_;
    my ($by, $at) = ($rr->{updated_by}, $rr->{updated_at});
    my $info;
    if (defined $by && length $by) {
        my $raw  = (defined $at && length $at) ? $at : '';
        my $when = $raw ? substr($raw, 0, 16) : '';
        $info = functions::actor_icon_html($by)
              . qq{<div class="lc-at mono text-mute lc-time" data-utc="} . _esc($raw) . qq{">} . _esc($when) . qq{</div>};
    } else {
        $info = qq{<span class="text-mute">\x{2014}</span>};
    }
    my $hist = qq{<button type="button" class="rr-hist" data-tip="Change history">}
        . qq{<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">}
        . qq{<path d="M3 3v5h5"/><path d="M3.05 13A9 9 0 1 0 6 5.3L3 8"/><path d="M12 7v5l3 2"/></svg></button>};
    return qq{<div class="lc-cell">$info$hist</div>};
}
# Compact last-change without the history icon, for SOA/NS rows.
sub _lc_inline {
    my ($by, $at) = @_;
    return qq{<span class="text-mute">\x{2014}</span>} unless defined $by && length $by;
    my $raw = (defined $at && length $at) ? $at : '';
    return functions::actor_icon_html($by) . ' '
         . qq{<span class="lc-at mono text-mute lc-time" data-utc="} . _esc($raw) . qq{">} . _esc(substr($raw, 0, 16)) . qq{</span>};
}
sub _hist_btn {
    my ($cls) = @_;
    return qq{<button type="button" class="rr-hist $cls" data-tip="Change history">}
        . qq{<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">}
        . qq{<path d="M3 3v5h5"/><path d="M3.05 13A9 9 0 1 0 6 5.3L3 8"/><path d="M12 7v5l3 2"/></svg></button>};
}

my $q       = CGI->new;
my $zone_id = $q->param('zone');
my $USER    = request_user();
my $domain  = $zone_id ? pdns_get_domain($zone_id) : undef;
my $access  = $domain ? effective_zone_access($USER, $domain) : 'none';

if (!$domain || $access eq 'none') {
    print '<div class="page-head"><div><a href="/zones" class="link" style="font-size:13px;">&larr; Zones</a>'
        . '<h1 style="margin-top:6px;">Zone not found</h1></div></div>';
    print '<div class="card text-dim">Zone not found or no access.</div>';
    return 1;
}

my $rtype_early = uc($domain->{type} || 'MASTER');
# Metadata (labels, retry) is editable on SLAVE zones; records are not (they come via AXFR; the backend blocks it too).
my $can_manage_metadata = ($access eq 'write');
my $can_edit_records    = ($access eq 'write' && $rtype_early ne 'SLAVE');
my $can_write  = $can_edit_records;
my $can_manage = has_capability($USER, 'zones.manage') ? 1 : 0;
my $profile    = pdns_profile_map($zone_id)->{$zone_id};
my $rtype      = uc($domain->{type} || 'MASTER');
my $role       = $rtype eq 'SLAVE' ? 'Secondary' : ($rtype eq 'NATIVE' ? 'Native' : 'Primary');
my $labels     = zone_labels_get($zone_id);
my $soa        = pdns_soa_fields($zone_id);
my $zname      = $domain->{name};
my $kind       = zone_kind($zname);                 # forward | reverse4 | reverse6
my $is_reverse = ($kind =~ /^reverse/) ? 1 : 0;

# One row per pdns.records row. Pulse rules keyed by "name TYPE": a rule belongs to its RRset.
my %pulse;
my $can_pulse = has_capability($USER, 'pulse.manage') ? 1 : 0;
if ($can_pulse) {
    my ($rules) = pulse_rules_all();
    for my $r (@{ $rules || [] }) {
        next unless ($r->{domain_id} // 0) == $zone_id;
        $pulse{ lc($r->{rr_name}) . ' ' . uc($r->{rr_type}) } = $r;
    }
}

# Slow sweep (§7): only unavailable addresses are marked, with a dot next to the value.
# Not gated by pulse.manage: availability is an observation, visible to anyone who can see the zone.
my ($sweep_all) = pulse_sweep_zone_states($zone_id);
$sweep_all ||= {};
my %sweep = map { lc($_) => $sweep_all->{$_} }
            grep { ($sweep_all->{$_}{state} // '') eq 'unavailable' } keys %$sweep_all;

my @user;
for my $r (@{ pdns_list_records($zone_id) }) {
    my $t = uc($r->{type} || '');
    next if $t eq 'SOA';
    next if $t eq 'NS' && lc($r->{name}) eq lc($zname);   # apex NS goes to the accordion
    push @user, $r;
}
@user = sort { lc($a->{name}) cmp lc($b->{name}) || uc($a->{type}) cmp uc($b->{type}) } @user;

my $title = _esc($zname);
my $rclass = $rtype eq 'SLAVE' ? 'slave' : ($rtype eq 'NATIVE' ? 'native' : 'master');
my ($zcmap, $zcmap_err) = zone_catalog_map();
my $zcat = $zcmap ? $zcmap->{$zone_id} : undef;
my $cat_badge = $zcat
    ? qq{ <span class="text-dim">\x{00b7}</span> <a href="/propagation?catalog=$zcat->{audience_id}" class="badge cat-badge" data-tip="Distribution @{[_esc($zcat->{name})]}">} . _esc($zcat->{name}) . qq{</a>}
    : '';
my $meta_line = qq{<span class="badge $rclass">} . _esc($role)
    . qq{</span>} . (defined $profile && length $profile ? qq{ <span class="text-dim">\x{00b7} } . _esc($profile) . qq{</span>} : '') . $cat_badge;

my $labels_chips = join('', map {
    my $c = $_->{color} ? qq{ style="--c:} . _esc($_->{color}) . qq{"} : '';
    qq{<span class="lbl-tag"$c>} . _esc($_->{value}) . qq{</span>}
} @$labels);
my $labels_btn = $can_manage_metadata
    ? qq{<button type="button" class="btn btn-ghost btn-sm" id="zlabels-open" data-zone-id="@{[_esc($zone_id)]}">}
      . (@$labels ? 'Edit labels' : '+ Labels') . qq{</button>}
    : '';

# Dynamic updates are enabled in Zone settings; the header button appears only once enabled.
my ($zs_dyn_map) = zone_dynamic_map();
my $zs_dyn_flag = ($zs_dyn_map && $zs_dyn_map->{$zone_id}) ? 1 : 0;
my $head_actions = '';
if ($can_manage) {
    $head_actions .= qq{<button type="button" class="btn btn-ghost" id="zone-settings-btn"}
        . qq{ data-zone-id="@{[_esc($zone_id)]}" data-profile="@{[_esc(defined $profile ? $profile : '')]}"}
        . qq{ data-catalog="@{[ $zcat ? $zcat->{audience_id} : '' ]}"}
        . qq{ data-name="$title">Settings</button>};
    # js/dynamic.js. On a secondary the settings are prepared ahead and take effect after Make primary;
    # NATIVE zones do not accept dynamic updates.
    $head_actions .= qq{<button type="button" class="btn btn-ghost" id="zone-dynamic-btn" data-zone-id="@{[_esc($zone_id)]}"}
        . qq{ data-type="@{[_esc($rtype)]}" data-name="$title">Dynamic updates</button>} if $zs_dyn_flag && ($rtype eq 'MASTER' || $rtype eq 'SLAVE');
    # js/dnssec.js: signing is managed on primary zones only (a secondary serves what its primary signed).
    $head_actions .= qq{<button type="button" class="btn btn-ghost" id="zone-dnssec-btn" data-zone-id="@{[_esc($zone_id)]}" data-name="$title">DNSSEC</button>} if $rtype eq 'MASTER';
    $head_actions .= qq{<button type="button" class="btn btn-ghost" id="zone-delete-btn" data-id="@{[_esc($zone_id)]}" data-name="$title">Delete zone</button>};
}

# Distribution is two independent facts: Direct AXFR (a flag; recipients come from Propagation) and the
# catalog the zone is announced in, if any. The catalog list is always embedded (read-only users need the
# name). It follows desired_state='present', with provisioned sent separately to show "still being created".
my ($zs_cats) = catalogs_available();
$zs_cats ||= [];
my ($zs_direct_map) = zone_direct_axfr_map();
my $zs_direct = ($zs_direct_map && $zs_direct_map->{ $zone_id + 0 }) ? 1 : 0;
my ($zs_recip) = zone_recipients(connectDB(), $zone_id);
# Same right the API checks (_dist_ok -> distribution.manage) for both lists; managing catalogs
# themselves is catalog.manage on another page.
my $can_change_catalog  = ($can_manage && has_capability($USER, 'distribution.manage')) ? 1 : 0;
my $can_change_delivery = ($can_manage && has_capability($USER, 'distribution.manage')) ? 1 : 0;
# Secondary upstream is edited in Zone settings; read once and reused by the source panel below.
my (@sec_masters, $sec_tsig, $sec_renotify);
if ($rtype eq 'SLAVE') {
    my $m0 = pdns_get_domain_metadata($zone_id) || {};
    @sec_masters  = grep { length } split /\s*,\s*/, ($domain->{master} // '');
    $sec_tsig     = ($m0->{'AXFR-MASTER-TSIG'} && @{ $m0->{'AXFR-MASTER-TSIG'} }) ? $m0->{'AXFR-MASTER-TSIG'}[0] : '';
    $sec_renotify = ($m0->{'SLAVE-RENOTIFY'} && @{ $m0->{'SLAVE-RENOTIFY'} } && $m0->{'SLAVE-RENOTIFY'}[0]) ? 1 : 0;
}
# Import marker "zone was dynamic on the old server": Make primary then requires enabling updates.
# The form loads the settings themselves from GET /zones/:id/dynamic.
my $zs_dyn_on = ($rtype eq 'MASTER' && $zs_dyn_flag) ? 1 : 0;
$meta_line .= qq{ <span class="badge muted" data-tip="Accepts dynamic updates (RFC 2136)">Dynamic</span>} if $zs_dyn_on;
my $zs_signed = zone_signed_map()->{$zone_id};
$meta_line .= qq{ <span class="badge muted" data-tip="Signed with DNSSEC">DNSSEC</span>} if $zs_signed;
my $zs_dyn_imported = 0;
if ($rtype eq 'SLAVE') { my $m1 = pdns_get_domain_metadata($zone_id) || {}; $zs_dyn_imported = ($m1->{'X-DNSPANEL-IMPORT-DYNAMIC'} && @{ $m1->{'X-DNSPANEL-IMPORT-DYNAMIC'} }) ? 1 : 0; }
my %ZSDATA = ( can_change_catalog => $can_change_catalog, can_change_delivery => $can_change_delivery,
               catalogs => $zs_cats,
               # Two independent facts, edited by two routes.
               direct     => $zs_direct,
               catalog_id => ($zs_recip ? $zs_recip->{catalog_id} : undef),
               zone_type  => $rtype,
               dynamic    => { on => $zs_dyn_flag, imported => $zs_dyn_imported },
               # The upstream is a property of the zone itself, hence zones.manage.
               can_change_source => ($can_manage ? 1 : 0),
               # transferred: a SLAVE without SOA has not arrived yet; promoting it would yield an empty
               # authoritative primary. The core rejects it ('zone has no SOA yet'); the form says so upfront.
               role => { type => $rtype, transferred => ($soa ? 1 : 0), can_change => ($can_manage ? 1 : 0) },
               # SLAVE-RENOTIFY is derived from distribution policy, not an operator setting,
               # so it is shown in the source panel but not editable.
               ($rtype eq 'SLAVE' ? (secondary => { masters => \@sec_masters, tsig => $sec_tsig }) : ()) );

print <<HTML;
<div class="page-head zone-head">
    <div class="zone-head-main">
        <a href="/zones" class="btn btn-ghost btn-back">&larr; Zones</a>
        <h1 class="zone-title">@{[ dns_name_html($zname) ]}</h1>
        <span class="zone-meta">$meta_line</span>
    </div>
    <div class="flex gap-3">$head_actions</div>
</div>
<div class="zone-labels-row" id="zone-labels-row">$labels_chips $labels_btn</div>
HTML

print qq{<script type="application/json" id="zs-cat-data">} . json_for_html(\%ZSDATA) . qq{</script>\n};

my $ss = get_zone_sync_state($zname);
my $ss_ps = $ss ? $ss->{pdns_state} : '';
my $ss_notify_bad = ($ss && ($ss->{notify_state} // '') eq 'notify_failed' && $ss_ps eq 'active') ? 1 : 0;
if ($ss && ($ss_ps eq 'activation_failed' || $ss_ps eq 'transfer_problem' || $ss_notify_bad)) {
    my ($label, $sub, $cls);
    if ($ss_ps eq 'activation_failed') {
        $label = 'Activation not confirmed';
        $sub   = 'Saved to the database, but PowerDNS has not confirmed serving this zone.';
        $cls   = 'sync-banner-err';
    } elsif ($ss_ps eq 'transfer_problem') {
        $label = 'Zone transfer problem';
        $sub   = qq{AXFR could not be started or completed \x{2014} check upstream masters / TSIG.};
        $cls   = 'sync-banner-err';
    } else {
        $label = 'NOTIFY to secondaries failed';
        $sub   = qq{Zone is served, but notifying secondaries failed \x{2014} they will catch up on refresh.};
        $cls   = 'sync-banner-warn';
    }
    my $att = ($ss->{attempts} && $ss->{attempts} > 0)
        ? qq{ \x{00b7} $ss->{attempts} failed attempt} . ($ss->{attempts} == 1 ? '' : 's') : '';
    my $when = $ss->{last_attempt_at}
        ? qq{ \x{00b7} last <span class="lc-time" data-utc="} . _esc($ss->{last_attempt_at}) . qq{">} . _esc(substr($ss->{last_attempt_at}, 0, 16)) . qq{</span>} : '';
    my $detail = $ss->{last_detail} ? qq{<div class="sync-banner-detail mono">} . _esc($ss->{last_detail}) . qq{</div>} : '';
    my $btn = $can_manage_metadata
        ? qq{<button type="button" class="btn btn-sm sync-retry-btn" id="sync-retry-btn" data-zone-id="@{[_esc($zone_id)]}">Retry now</button>}
        : '';
    print <<HTML;
<div class="sync-banner $cls" id="sync-banner">
    <div class="sync-banner-body">
        <div class="sync-banner-head"><span class="sync-banner-dot"></span><b>$label</b>$att$when</div>
        <div class="sync-banner-sub text-dim">$sub</div>
        $detail
    </div>
    $btn
</div>
HTML
}

if ($rtype eq 'SLAVE') {
    my @masters  = @sec_masters;
    my $tsig     = (defined $sec_tsig && length $sec_tsig) ? $sec_tsig : undef;
    my $renotify = $sec_renotify ? 1 : 0;
    # domains.last_check is a Unix timestamp; the PDNS session runs in UTC, so FROM_UNIXTIME yields UTC.
    my ($last_check) = eval { functions::connectPDNS()->selectrow_array("SELECT FROM_UNIXTIME(last_check) FROM domains WHERE id=? AND last_check IS NOT NULL AND last_check>0", undef, $zone_id) };
    my $ss = get_zone_sync_state($zname);
    # From durable sync_state, else inferred from SOA presence.
    my ($st_label, $st_cls);
    my $ps = $ss ? $ss->{pdns_state} : '';
    if    ($ps eq 'active')           { ($st_label, $st_cls) = ('Active', 'master'); }
    elsif ($ps eq 'pending_transfer') { ($st_label, $st_cls) = ('Pending transfer', 'slave'); }
    elsif ($ps)                       { ($st_label, $st_cls) = ('Transfer problem', 'kind-rev'); }
    else { ($st_label, $st_cls) = $soa ? ('Active', 'master') : ('Pending transfer', 'slave'); }

    # Make primary lives only in Zone settings: one entry point for an irreversible operation.
    my $promote_html = '';
    # Edit upstream opens Zone settings. Refresh AXFR re-fetches now; same right as Retry now.
    my $refresh_btn = $can_manage_metadata
        ? qq{<button type="button" class="btn btn-ghost btn-sm" id="zone-refresh-btn">Refresh AXFR</button>}
        : '';
    my $src_btn = $can_manage
        ? qq{<button type="button" class="btn btn-ghost btn-sm" id="zone-source-btn">Edit upstream</button>}
        : '';
    my $head_btns = ($refresh_btn || $src_btn)
        ? qq{<span class="slave-panel-actions">$refresh_btn$src_btn</span>} : '';
    my $masters_html = @masters
        ? join('', map { qq{<span class="badge muted mono">} . _esc($_) . qq{</span> } } @masters)
        : qq{<span class="text-mute">\x{2014}</span>};
    my $serial_html = ($soa && defined $soa->{serial}) ? _esc($soa->{serial}) : qq{<span class="text-mute">\x{2014} not transferred</span>};
    my $lc_html = $last_check
        ? qq{<span class="lc-time" data-utc="@{[_esc($last_check)]}">@{[_esc($last_check)]}</span>}
        : qq{<span class="text-mute">never</span>};
    print <<HTML;
<div class="slave-panel">
    <div class="slave-panel-head">
        <span class="badge $st_cls">$st_label</span>
        <span class="text-dim">Secondary zone \x{2014} records arrive via AXFR from the primary and are read-only here.</span>
        $head_btns
    </div>
    <div class="slave-grid">
        <div><span class="slave-k">Upstream primaries</span><span class="slave-v">$masters_html</span></div>
        <div><span class="slave-k">TSIG key</span><span class="slave-v mono">@{[ defined $tsig ? _esc($tsig) : qq{<span class="text-mute">\x{2014}</span>} ]}</span></div>
        <div data-tip="Derived from the zone\x{2019}s distribution policy \x{2014} not an operator setting"><span class="slave-k">Renotify secondaries</span><span class="slave-v">@{[ $renotify ? 'Yes' : 'No' ]}</span></div>
        <div><span class="slave-k">Serial</span><span class="slave-v mono">$serial_html</span></div>
        <div><span class="slave-k">Last check</span><span class="slave-v">$lc_html</span></div>
    </div>
    $promote_html
</div>
HTML
}

if ($soa) {
    my $summary = _esc($soa->{primary_ns}) . qq{ <span class="text-mute">\x{00b7} TTL } . _esc($soa->{ttl})
        . qq{ \x{00b7} Serial } . _esc($soa->{serial}) . qq{</span>};
    my $ns_list = pdns_apex_ns_list($zone_id, $zname);
    my $ns_ttl  = @$ns_list ? $ns_list->[0]{ttl} : $soa->{ttl};
    my $soa_lc  = _lc_inline($soa->{updated_by}, $soa->{updated_at});
    my $zdata   = _esc($zone_id);
    # Serial is read-only: it is bumped automatically on save.
    my $soa_cell = sub {
        my ($f, $ed) = @_;
        my $v = _esc($soa->{$f});
        return $ed ? qq{<td class="mono soa-f" data-f="$f">$v</td>} : qq{<td class="mono">$v</td>};
    };
    my $soa_actions = $can_write ? qq{<a href="#" class="link soa-edit">Edit</a>} : qq{<span class="text-mute">\x{2014}</span>};

    my $ns_rows = '';
    if (@$ns_list) {
        for my $n (@$ns_list) {
            my $ev = _esc($n->{content});
            my $acts = $can_write
                ? qq{<a href="#" class="link ns-edit">Edit</a> <a href="#" class="link ns-del" style="margin-left:.5rem;color:var(--danger);">Delete</a>}
                : '';
            $ns_rows .= qq{<tr class="ns-row" data-id="@{[_esc($n->{id})]}" data-val="$ev" data-ttl="@{[_esc($n->{ttl})]}">}
                . qq{<td class="mono ns-v">$ev</td>}
                . qq{<td class="right mono text-dim ns-ttl">@{[_esc($n->{ttl})]}</td>}
                . qq{<td>@{[ _lc_inline($n->{updated_by}, $n->{updated_at}) ]}</td>}
                . qq{<td class="right">$acts</td></tr>\n};
        }
    } else {
        $ns_rows = qq{<tr><td colspan="4" class="empty-row">No NS records.</td></tr>};
    }
    my $ns_add = $can_write ? qq{
        <div class="ns-add-row">
            <input class="field-input ns-add-input" placeholder="ns1.example.com." autocomplete="off">
            <input class="field-input ns-add-ttl" value="@{[_esc($ns_ttl)]}" aria-label="TTL" style="width:5rem;">
            <button type="button" class="btn btn-ghost ns-add-btn">+ Add NS</button>
        </div>} : '';

    print <<HTML;
<details class="soa-acc" id="soa-acc" data-zone-id="$zdata" data-zone-name="$title" data-ns-ttl="@{[_esc($ns_ttl)]}">
    <summary><span class="soa-acc-title">SOA &amp; name servers</span><span class="soa-acc-sum">$summary</span>
        <span class="acc-hist-wrap">@{[ _hist_btn('acc-hist') ]}</span></summary>
    <div class="soa-acc-body">
        <div class="acc-sec">
            <div class="acc-sec-title">SOA</div>
            <div class="table-wrap"><table class="data-table soa-table" id="soa-table">
                <colgroup><col style="width:7%"><col style="width:15%"><col style="width:15%"><col style="width:12%"><col style="width:9%"><col style="width:8%"><col style="width:10%"><col style="width:8%"><col style="width:16%"></colgroup>
                <thead><tr><th>TTL</th><th>Primary NS</th><th>Hostmaster</th><th>Serial</th><th>Refresh</th><th>Retry</th><th>Expire</th><th>Minimum</th><th class="right">Actions</th></tr></thead>
                <tbody><tr id="soa-row" data-id="@{[_esc($soa->{id})]}">
                    @{[ $soa_cell->('ttl', $can_write) ]}
                    @{[ $soa_cell->('primary_ns', $can_write) ]}
                    @{[ $soa_cell->('hostmaster', $can_write) ]}
                    <td class="mono text-dim soa-serial">@{[_esc($soa->{serial})]}</td>
                    @{[ $soa_cell->('refresh', $can_write) ]}
                    @{[ $soa_cell->('retry', $can_write) ]}
                    @{[ $soa_cell->('expire', $can_write) ]}
                    @{[ $soa_cell->('minimum', $can_write) ]}
                    <td class="right soa-act">$soa_actions</td>
                </tr></tbody>
            </table></div>
        </div>
        <div class="acc-sec">
            <div class="acc-sec-title">Name servers</div>
            <div class="table-wrap"><table class="data-table ns-table" id="ns-table">
                <colgroup><col style="width:42%"><col style="width:10%"><col style="width:28%"><col style="width:20%"></colgroup>
                <thead><tr><th>Name server</th><th class="right">TTL</th><th>Last change</th><th class="right">Actions</th></tr></thead>
                <tbody>$ns_rows</tbody>
            </table></div>
            $ns_add
        </div>
    </div>
</details>
HTML
}

# Forward-add types, common first. No PTR (reverse only), SOA (own path) or SPF (obsolete, use TXT).
my %valid_type = map { $_ => 1 } @{ dns_record_types() };
my @fwd_types  = grep { $valid_type{$_} } qw(A AAAA CNAME MX TXT SRV CAA NS DNAME DS NAPTR SSHFP TLSA);
my $types_json = _esc(encode_json(\@fwd_types));
print qq{<hr class="sec-div">\n};
print <<HTML;
<div class="toolbar rr-toolbar">
    <div class="search">
        <svg class="ic" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/></svg>
        <input placeholder="Search name or value\x{2026}" id="rr-search">
    </div>
    <span class="filter-wrap"><button class="filter" type="button" data-filter="rtype" data-val="all">Type: all \x{25be}</button></span>
    <span class="filter-wrap"><button class="filter" type="button" data-filter="rstatus" data-val="all">Status: all \x{25be}</button></span>
    <span class="filter-wrap"><button class="filter" type="button" data-filter="rptr" data-val="all">PTR: all \x{25be}</button></span>
@{[ $can_pulse ? qq{<span class="filter-wrap"><button class="filter" type="button" data-filter="rpulse" data-val="all">Pulse: all \x{25be}</button></span>} : '' ]}
    <span class="filter-wrap"><button class="filter" type="button" data-filter="rping" data-val="all">Pinger: all \x{25be}</button></span>
    <button class="filter" type="button" id="rr-filter-clear" style="display:none;">\x{2715} Reset</button>
    <div class="rr-bulk" id="rr-bulk" style="display:none;"></div>
</div>
HTML
if ($can_write) {
    print qq{<div class="rr-add" id="rr-add" data-zone-id="@{[_esc($zone_id)]}" data-zone-name="$title" data-kind="@{[_esc($kind)]}" data-types="$types_json"></div>\n};
}

my $total = scalar @user;
print <<HTML;
<div class="table-wrap">
    <table class="data-table rr-table">
        <colgroup><col style="width:3%"><col style="width:13%"><col style="width:5%"><col style="width:17%"><col style="width:15%"><col style="width:5%"><col style="width:7%"><col style="width:6%"><col style="width:8%"><col style="width:10%"><col style="width:9%"></colgroup>
        <thead>
            <tr>
                <th class="th-check"><input type="checkbox" id="rr-check-all" aria-label="Select all (filtered)"></th>
                <th class="th-sort" data-sort="name">Name</th>
                <th class="th-sort" data-sort="type">Type</th>
                <th>Parameters</th>
                <th class="th-sort" data-sort="value">Value</th>
                <th class="th-sort right" data-sort="ttl">TTL</th>
                <th class="th-sort" data-sort="status">Status</th>
                <th class="th-sort" data-sort="ptr" data-tip="Reverse DNS (PTR) status for A/AAAA">PTR</th>
                <th class="th-sort" data-sort="pulse" data-tip="Switched by NS Pulse when checks say so">Pulse</th>
                <th class="th-sort" data-sort="updated">Last change</th>
                <th class="right">Actions</th>
            </tr>
        </thead>
        <tbody id="rr-tbody">
HTML

if (@user) {
    for my $r (@user) {
        my $name = _esc($r->{name});
        my $type = _esc($r->{type});
        my $ttl  = _esc(defined $r->{ttl} ? $r->{ttl} : '');
        my $content = defined $r->{content} ? $r->{content} : '';
        my $prio = (defined $r->{prio} && $r->{prio} ne '') ? $r->{prio} : '';
        my $params = _rec_params($r->{type}, $r);
        my $value  = _rec_value($r->{type}, $r);
        my $params_cell = length($params) ? _esc($params) : '';
        my $value_cell  = length($value)  ? _esc($value)  : '';
        # The dot marks the address, not the row: one RRset may hold several addresses.
        if (my $bad = $sweep{ lc $content }) {
            my $seen = $bad->{state_since} ? substr($bad->{state_since}, 0, 16) . ' UTC' : 'unknown time';
            $value_cell .= qq{ <button type="button" class="rr-dot" data-pinger-history}
                         . qq{ aria-label="Availability history"}
                         . qq{ data-tip="No ICMP reply since $seen"></button>};
        }
        my $disabled = $r->{disabled} ? 1 : 0;
        my $status = $disabled
            ? '<span class="badge slave">Disabled</span>' : '<span class="badge master">Active</span>';
        # Pulse-capable types come from the single list in functions.pm; the row carries the answer so
        # the history dialog does not keep its own copy.
        my $pulse_ok = _pulse_ok_type($r->{type}) ? 1 : 0;
        my $sweep_ok = (uc($r->{type}) eq 'A' || uc($r->{type}) eq 'AAAA') ? 1 : 0;
        # Filters read states from data-* attributes, never from badge text or markup.
        # Exactly three states: internal `unknown` is shown as not_checked.
        my $sweep_state = '';
        if ($sweep_ok) {
            my $st = ($sweep_all->{ $content } || $sweep_all->{ lc $content } || {})->{state} || '';
            $sweep_state = ($st eq 'available' || $st eq 'unavailable') ? $st : 'not_checked';
        }
        my $ndata = _esc(lc join ' ', $r->{name}, dns_name_unicode($r->{name}));
        my $vdata = _esc(lc "$params $value");
        # Non-apex NS is a child zone delegation (zone cut).
        my $is_deleg = (uc($r->{type}) eq 'NS' && lc($r->{name}) ne lc($zname)) ? 1 : 0;
        my $type_cell = $is_deleg
            ? qq{<span class="badge">$type</span> <span class="badge kind-rev" data-tip="Child zone delegation (zone cut)">Delegation</span>}
            : qq{<span class="badge">$type</span>};
        # A Pulse rule governs the whole RRset, so all rows of a name+type show the same status. Every
        # supported record shows "off" by default (a dash only where Pulse does not apply); the status
        # itself opens the settings.
        my ($pulse_cell, $pulse_sort, $pulse_state) = (qq{<span class="text-dim">\x{2014}</span>}, '', '');
        if ($can_pulse && _pulse_ok_type($r->{type})) {
            my $pr = $pulse{ lc($r->{name}) . ' ' . uc($r->{type}) };
            my $on  = $pr && $pr->{enabled};
            # Avoid "primary" (it means the zone role on this page); show the active branch number.
            my ($txt, $cls, $tip);
            # The filter uses the state, not the label: "rule 2" and "rule 5" are both "rule".
            if (!$on) {
                # No rule and a disabled rule both read "off"; only the badge style and tooltip differ.
                $txt = 'off';
                $cls = $pr ? 'badge slave' : 'badge muted';
                $tip = $pr ? 'Set up, but switched off'
                           : 'NS Pulse does not manage this record';
            } elsif (($pr->{state} // '') eq 'held') {
                ($txt, $cls) = ('held', 'badge err');
                $tip = 'The record was changed outside NS Pulse — it stopped rather than fight for the '
                     . 'record. Switch the rule off and on to take it over again';
            } elsif (($pr->{state} // '') eq 'switched') {
                $txt = $pr->{active_branch_no} ? "rule $pr->{active_branch_no}" : 'switched';
                $cls = 'badge';
                $tip = 'A rule matched, and it publishes this set instead of the default one';
            } else {
                ($txt, $cls) = ('default', 'badge master');
                $tip = 'No rule matches — the default set is published';
            }
            # A real link (middle-click opens it separately); js/pulse.js intercepts a plain click and
            # opens the settings in place.
            my $href = $pr ? "/pulse?rule=$pr->{id}"
                           : "/pulse?zone=$zone_id&name=" . _url(lc $r->{name}) . "&type=" . _url(uc $r->{type});
            my $open = join '|', $zone_id, lc($r->{name}), uc($r->{type});
            $pulse_cell = qq{<a href="$href" class="link" data-pulse-open="@{[ _esc($open) ]}"}
                        . qq{ data-tip="@{[ _esc($tip) ]}">}
                        . qq{<span class="$cls">} . _esc($txt) . qq{</span></a>};
            $pulse_sort  = $txt;
            $pulse_state = ($txt =~ /^rule /) ? 'rule' : $txt;
        }
        # While a rule is enabled Pulse owns the record; manual edits are disabled.
        my $pulse_on = $can_pulse && ($pulse{ lc($r->{name}) . ' ' . uc($r->{type}) } || {})->{enabled};
        my $actions = $can_write
            ? ($pulse_on
                ? qq{<span class="text-dim" data-tip="Managed by NS Pulse — switch it off to edit by hand">Edit</span>}
                  . qq{<span class="text-dim" style="margin-left:.6rem;">Delete</span>}
                : '<a href="#" class="link js-edit-rrset">Edit</a>'
                  . '<a href="#" class="link js-del-rrset" style="margin-left:.6rem;color:var(--danger);">Delete</a>')
            : '';
        print <<ROW;
            <tr class="rr-row@{[ $is_deleg ? ' rr-deleg' : '' ]}" data-id="@{[_esc($r->{id})]}" data-name="$name" data-type="$type" data-ttl="$ttl" data-content="@{[_esc($content)]}" data-prio="@{[_esc($prio)]}" data-disabled="$disabled" data-updated="@{[_esc(defined $r->{updated_at} ? $r->{updated_at} : '')]}" data-value="@{[_esc($value)]}" data-delegation="$is_deleg" data-ndata="$ndata" data-vdata="$vdata" data-pulse-ok="@{[ $can_pulse ? $pulse_ok : 0 ]}" data-sweep-ok="$sweep_ok" data-pulse-state="$pulse_state" data-sweep-state="$sweep_state">
                <td class="rr-checkcell"><input type="checkbox" class="rr-check"></td>
                <td class="zone-name">@{[ dns_name_html($r->{name}) ]}</td>
                <td>$type_cell</td>
                <td class="text-dim break-all rr-params">$params_cell</td>
                <td class="text-dim break-all rr-val">$value_cell</td>
                <td class="right mono text-dim rr-ttl">$ttl</td>
                <td class="rr-status">$status</td>
                <td class="rr-ptr" data-ptr="">@{[ (uc($r->{type}) eq 'A' || uc($r->{type}) eq 'AAAA') ? qq{<span class="ptr-badge ptr-pending">\x{2026}</span>} : qq{<span class="text-dim">\x{2014}</span>} ]}</td>
                <td class="rr-pulse" data-pulse="@{[ _esc($pulse_sort) ]}">$pulse_cell</td>
                <td>@{[ _last_change_cell($r) ]}</td>
                <td class="right rr-actions">$actions</td>
            </tr>
ROW
    }
} else {
    print qq{            <tr><td colspan="11" class="empty-row">No records yet.</td></tr>\n};
}

print <<HTML;
        </tbody>
    </table>
</div>
HTML

1;
