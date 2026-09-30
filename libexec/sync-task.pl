#!/usr/bin/perl
# sync-task — one pass of one background job, run by the dns-sync-worker daemon (src/dns-sync-worker).
# The daemon decides WHEN; the rules stay here, in functions.pm.
#
#   sync-task.pl schedule | retry-due | reconcile | probe-batch | catalogs
#
# Prints one JSON line: {"gate":"allow|skip|fail", "ok":1|0, "next_retry_in":N|null, "probe_queued":N,
# "catalog_every":N, "reconcile_every":N, "retry_failed_in":N, "progress":N, "summary":"..."}. The schedule
# fields let the daemon set its timer from the database alone. Problems go to stderr (the journal).
# Exit 0 = ok or skip, 1 = the pass had errors, 3 = HA state unknown (fail-closed), 2 = usage.
use strict;
use warnings;
use utf8;
use FindBin;
use lib "$FindBin::Bin/../www/include";
use JSON qw(encode_json);
use functions qw(due_retry_zones retry_zone_sync sync_next_due ha_write_verdict ha_gate_action setting
                 policy_refresh orphan_policy_sweep policy_lock policy_unlock
                 catalogs_all catalog_consumers_state catalog_subscription_recheck catalog_producer_serial
                 dynamic_materialize_all import_probe_run import_probe_queued);
binmode STDERR, ':encoding(UTF-8)';

my %TASK = (schedule => sub { {} }, 'retry-due' => \&retry_due, reconcile => \&reconcile,
            'probe-batch' => \&probe_batch, catalogs => \&catalogs);
my $name = $ARGV[0] // '';
my $task = $TASK{$name} or do { print STDERR "usage: sync-task.pl " . join(' | ', sort keys %TASK) . "\n"; exit 2 };
my @errors;
sub problem { push @errors, $_[0]; print STDERR "sync-task $name: $_[0]\n"; }

# HA write gate: nothing is written on STANDBY or during a freeze, and an unknown HA state is fail-closed.
# Checked before each item too, so a pass stops after the current operation once the role changes.
sub gate { my $v = ha_write_verdict(); return (ha_gate_action($v), $v); }
my ($gate, $verdict) = gate();
if ($gate eq 'fail') {
    print STDERR "sync-task $name: HA gate fail-closed (" . ($verdict->{code} // 'ha_unknown') . "): " . ($verdict->{message} // '') . "\n";
    print encode_json({ gate => 'fail', ok => 0, schedule_fields() }), "\n";
    exit 3;
}
my $out = ($gate eq 'allow' || $name eq 'schedule') ? $task->() : {};
my %busy = map { $_ => 1 } @{ delete $out->{busy_zones} || [] };

my ($next, $ne) = sync_next_due([ sort keys %busy ]);
problem("retry queue: $ne") if $ne;
my ($queued, $qe) = import_probe_queued();
problem("probe queue: $qe") if $qe;
print encode_json({ %$out, gate => $gate, ok => (@errors ? 0 : 1), next_retry_in => $next, probe_queued => $queued // 0,
                    schedule_fields() }), "\n";
exit(@errors ? 1 : 0);

# The intervals the daemon schedules by; they are the panel's settings, so they come from here.
sub schedule_fields {
    return (catalog_every   => setting('sync.catalog_check_seconds') + 0,
            reconcile_every => setting('sync.reconcile_seconds') + 0,
            retry_failed_in => setting('sync.backoff_initial_seconds') + 0);
}

# Zones whose retry is due: activate (verify + NOTIFY) or deactivate (rediscover + verify gone), picked by the
# queued operation; a task made stale by a concurrent create/delete is dropped via CAS as superseded.
sub retry_due {
    my ($due, $qerr) = due_retry_zones(setting('sync.retry_batch'));
    if ($qerr) { problem("cannot load the retry queue: $qerr"); return {}; }
    my %n = map { $_ => 0 } qw(recovered pending failing busy superseded error persist);
    my @busy;
    for my $item (@$due) {
        last if (gate())[0] ne 'allow';
        my ($zone, $op) = ($item->{zone_name}, $item->{operation} || 'activate');
        my $res = retry_zone_sync($zone, $op, $item->{state_version},
            { actor => 'dns-sync-worker', actor_role => 'system', source => 'system' });
        # Held by a manual Retry right now: its holder writes the next state and wakes us.
        if ($res->{busy})       { $n{busy}++; push @busy, $zone; next; }
        if ($res->{superseded}) { $n{superseded}++; next; }
        # Persistence first: a result whose state or audit did not reach the database is not a recovery.
        if ($res->{state_error} || $res->{audit_error}) {
            $n{persist}++; push @busy, $zone;   # its next_retry_at did not move; leave it to the next scheduled pass
            problem("$zone: state not saved (state_error=" . ($res->{state_error} ? 1 : 0) . " audit_error="
                    . ($res->{audit_error} ? 1 : 0) . ")" . ($res->{error} ? ", retry error: $res->{error}" : ''));
            next;
        }
        if ($res->{error}) { $n{error}++; problem("$zone ($op): $res->{error}"); next; }
        if (($res->{pdns_state} // '') eq 'pending_transfer') { $n{pending}++; next; }   # SLAVE still waits for its AXFR
        my $healthy = ($op eq 'deactivate')
            ? ($res->{pdns_state} eq 'removed')
            : ($res->{pdns_state} eq 'active' && ($res->{notify_state} // '') ne 'notify_failed');
        $n{ $healthy ? 'recovered' : 'failing' }++;
    }
    my $done = @$due - $n{busy} - $n{persist};
    return { progress => $done, busy_zones => \@busy,
             summary => ($n{recovered} || $n{failing} || $n{error} || $n{persist})
                 ? sprintf('retry: %d recovered, %d still failing, %d pending, %d error, %d not saved',
                           @n{qw(recovered failing pending error persist)}) : '' };
}

# Safety pass against drift: distribution policy of every served and catalog zone, orphaned policy, dynamic
# update policy. Edits apply all of this at once; this finishes what did not land (PowerDNS was down, the
# panel died mid-edit). Only distribution needs the reconcile lock; dynamic does not wait for it.
sub reconcile {
    my @notes;
    my ($got, $lerr) = policy_lock(0);
    if ($lerr) { problem("distribution lock: $lerr") }
    elsif (!$got) { push @notes, 'distribution: another reconcile is in progress' }
    else {
        problem("distribution: $_") for @{ policy_refresh() };
        if ((gate())[0] eq 'allow') {
            my ($cleaned, $oerr) = orphan_policy_sweep();
            problem("orphan policy: $_") for @{ $oerr || [] };
            push @notes, 'orphan policy cleared on ' . join(', ', @$cleaned) if @{ $cleaned || [] };
        }
        policy_unlock();
    }
    if ((gate())[0] eq 'allow') {
        my ($dyn, $derr) = dynamic_materialize_all();
        problem("dynamic updates: $derr") if $derr;
        problem("dynamic updates: $_->{name}: $_->{error}") for @{ ($dyn && $dyn->{failed}) || [] };
    }
    return { summary => join('; ', @notes) };
}

# One batch of queued probes of the old server; the daemon runs the next batch at once while this one made
# progress, so a long list does not wait a minute per batch. Sequential on purpose: a dead source or a
# wrong key is detected once and marks all its zones, instead of being hammered in parallel.
sub probe_batch {
    my ($r, $err) = import_probe_run();
    problem("import probe: $err") if $err;
    return {} unless $r;
    return { progress => $r->{probed} + 0,
             summary => $r->{probed} ? "probe: $r->{probed} zone(s), $r->{ok} ok, $r->{failed} failed" : '' };
}

# Subscription monitoring: has each catalog and its serial reached every secondary. The producer serial is
# read once per catalog. BIND tells us nothing on its own, so this is a real periodic observation.
sub catalogs {
    my ($cats, $cerr) = catalogs_all();
    if ($cerr) { problem("catalogs: $cerr"); return {}; }
    for my $c (grep { $_->{provisioned} } @{ $cats || [] }) {
        last if (gate())[0] ne 'allow';
        my ($cons, $ce) = catalog_consumers_state($c->{id});
        if ($ce) { problem("catalog $c->{name}: $ce"); next; }
        my ($pser) = catalog_producer_serial($c->{id});
        for my $cs (@$cons) {
            last if (gate())[0] ne 'allow';   # a switchover may start mid-pass
            my (undef, $re) = catalog_subscription_recheck($c->{id}, $cs->{node_id}, { producer_serial => $pser });
            problem("catalog $c->{name}, server $cs->{name}: $re") if $re;
        }
    }
    return {};
}
