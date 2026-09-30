#!/usr/bin/perl

use strict;
use warnings;
use utf8;
use open ':std', ':encoding(UTF-8)';

use FindBin; use lib "$FindBin::RealBin/include";
use functions qw(dashboard_summary);

# Dashboard: read-only, server-rendered summary of data the panel already has; no telemetry.

sub _esc { my ($s) = @_; return '' unless defined $s; $s =~ s/&/&amp;/g; $s =~ s/</&lt;/g; $s =~ s/>/&gt;/g; $s =~ s/"/&quot;/g; return $s; }

my $S = dashboard_summary();
my $z = $S->{zones}; my $c = $S->{catalogs}; my $sec = $S->{secondaries};

my %COL = (ready => 'var(--ok,#3ba55d)', pending => 'var(--warn,#d9a441)', problem => 'var(--danger,#e05561)',
           synced => 'var(--ok,#3ba55d)', lagging => 'var(--warn,#d9a441)');
sub _dot { my ($col) = @_; return qq{<span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:$col;margin-right:6px;vertical-align:middle;"></span>}; }

# Same node_health as /health/ready.
my $op = $S->{operational} || {};
my %OPCOL = (ready => 'var(--ok,#3ba55d)', standby => 'var(--warn,#d9a441)', degraded => 'var(--danger,#e05561)');
my $opcol = $OPCOL{ $op->{status} // 'degraded' } || 'var(--danger,#e05561)';
my $role_lbl = ($op->{role} // '') eq 'active' ? 'Active' : ($op->{role} // '') eq 'standby' ? 'Standby (read-only)' : 'Unknown role';
my $status_lbl = ucfirst($op->{status} // 'unknown');
my $op_extra = '';
if (($op->{status} // '') eq 'degraded') {
    my @failed = grep { !$op->{checks}{$_} } qw(panel_db schema pdns_db pdns_control);
    $op_extra = qq{ \x{00b7} <span style="color:var(--danger,#e05561)">failed: } . _esc(join(', ', @failed)) . qq{</span>} if @failed;
}
my $op_html = _dot($opcol) . qq{<b>Node</b> \x{00b7} $role_lbl \x{00b7} $status_lbl$op_extra};

print <<HTML;
<div class="stats" style="margin-top:.25rem;">
    <a class="stat" href="/zones" style="text-decoration:none;"><div class="label">Zones</div><div class="value">$z->{total}</div></a>
    <div class="stat"><div class="label">Records</div><div class="value">$z->{records}</div></div>
    <a class="stat" href="/propagation" style="text-decoration:none;"><div class="label">Catalogs</div><div class="value">$c->{total}</div></a>
    <a class="stat" href="/propagation" style="text-decoration:none;"><div class="label">Secondary servers</div><div class="value">$sec->{total}</div></a>
</div>
<div class="card" style="margin:.5rem 0;padding:.5rem .8rem;font-size:13px;">$op_html</div>

<div class="dash-grid">
HTML

print qq{<div class="card"><div style="display:flex;justify-content:space-between;align-items:center;gap:1rem;margin-bottom:.6rem;">}
    . qq{<span><b>Catalogs</b><span class="text-dim" style="margin-left:.7rem;">}
    . _dot($COL{ready})   . qq{Ready $c->{ready} \x{00b7}&nbsp; }
    . _dot($COL{pending}) . qq{Pending $c->{pending} \x{00b7}&nbsp; }
    . _dot($COL{problem}) . qq{Problems $c->{problems}</span></span>}
    . qq{<a class="link" href="/propagation">Manage \x{2192}</a></div>};
if (@{ $S->{catalog_list} }) {
    print qq{<div class="table-wrap"><table class="data-table"><tbody>};
    for my $cat (@{ $S->{catalog_list} }) {
        my $col = $COL{ $cat->{state} } || 'var(--text-mute)';
        my $err = ($cat->{state} eq 'problem' && $cat->{last_error})
            ? qq{ <span class="text-mute" data-tip="} . _esc($cat->{last_error}) . qq{">\x{2014} } . _esc($cat->{last_error}) . qq{</span>} : '';
        print qq{<tr><td>} . _dot($col) . qq{<a class="link" href="/propagation?catalog=$cat->{audience_id}">} . _esc($cat->{name}) . qq{</a></td>}
            . qq{<td class="right"><span style="color:$col;text-transform:capitalize;">$cat->{state}</span>$err</td></tr>};
    }
    print qq{</tbody></table></div>};
} else {
    print qq{<p class="text-dim" style="margin:0;">No catalogs configured yet.</p>};
}
print qq{</div>};

my $sec_status = $sec->{total}
    ? qq{<span class="text-dim" style="margin-left:.7rem;">}
        . _dot($COL{synced})  . qq{Synced $sec->{synced} \x{00b7}&nbsp; }
        . _dot($COL{lagging}) . qq{Lagging $sec->{lagging} \x{00b7}&nbsp; }
        . _dot($COL{problem}) . qq{Unreachable/problem $sec->{problem}</span>}
    : qq{<span class="text-mute" style="margin-left:.7rem;font-weight:400;">no observations yet</span>};
print qq{<div class="card"><div style="display:flex;justify-content:space-between;align-items:center;gap:1rem;">}
    . qq{<span><b>Secondary servers</b>$sec_status</span>}
    . qq{<a class="link" href="/propagation">Servers \x{2192}</a></div></div>};

print qq{<div class="card"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:.6rem;">}
    . qq{<span style="font-weight:600">Zone sync problems</span><a class="link" href="/zones">Zones \x{2192}</a></div>};
if (@{ $S->{problem_zones} }) {
    print qq{<div class="table-wrap"><table class="data-table"><thead><tr><th>Zone</th><th>State</th><th class="right">Attempts</th></tr></thead><tbody>};
    for my $p (@{ $S->{problem_zones} }) {
        my $nm = _esc($p->{zone_name});
        my $link = $p->{domain_id} ? qq{<a class="link" href="/records?zone=$p->{domain_id}">$nm</a>} : $nm;
        print qq{<tr><td>} . _dot($COL{problem}) . qq{$link</td><td class="mono text-dim">} . _esc($p->{pdns_state} // '')
            . qq{</td><td class="right mono text-dim">} . _esc($p->{attempts} // 0) . qq{</td></tr>};
    }
    print qq{</tbody></table></div>};
} else {
    print qq{<p class="text-dim" style="margin:0;">} . _dot($COL{ready}) . qq{All zones in sync.</p>};
}
print qq{</div>};

# audit_recent omits automatic retries; say so, or the list looks out of step with the Audit log.
print qq{<div class="card"><div style="display:flex;justify-content:space-between;align-items:baseline;gap:1rem;margin-bottom:.6rem;">}
    . qq{<span style="font-weight:600">Recent activity</span>}
    . qq{<a class="link" href="/audit">Audit log \x{2192}</a></div>}
    . qq{<p class="text-mute" style="margin:-.35rem 0 .6rem;font-size:12px;">Automatic sync retries are not listed \x{2014} }
    . qq{their state is in Zone sync problems, the full record is in the audit log.</p>};
if (@{ $S->{recent_audit} }) {
    print qq{<div class="table-wrap"><table class="data-table"><thead><tr><th>When</th><th>Actor</th><th>Action</th><th>Target</th></tr></thead><tbody>};
    for my $a (@{ $S->{recent_audit} }) {
        my $res = ($a->{result} && $a->{result} ne 'ok') ? qq{ <span style="color:var(--danger)">} . _esc($a->{result}) . qq{</span>} : '';
        my $tgt = _esc($a->{target_label} // ($a->{target} // ($a->{target_type} // '')));
        print qq{<tr><td class="mono text-dim"><span data-utc="} . _esc($a->{ts} // '') . qq{">} . _esc($a->{ts} // '') . qq{</span></td><td>} . _esc($a->{actor} // '')
            . qq{</td><td>} . _esc($a->{action_label} // $a->{action} // '') . qq{$res</td><td class="text-dim">$tgt</td></tr>};
    }
    print qq{</tbody></table></div>};
} else {
    print qq{<p class="text-dim" style="margin:0;">No recent activity.</p>};
}
print qq{</div>};

print qq{</div>\n};   # /dash-grid

1;
