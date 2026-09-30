#!/usr/bin/perl
# pulse-apply — switch one record's set as decided by pulse-server.
#
# Why a separate program rather than SQL inside Go: zone records change ONLY through pdns_apply_rrsets — the
# same path as for humans and MCP (transaction, zone role under lock, serial, audit, docs/25 §2). Pulse has no
# SQL of its own. The server decides — it has the live results, timings and events; this only executes, and
# under the lock re-checks what cannot be decided in advance: whether the rule is still enabled and the
# branch is still the right one.
#
# HA is asked HERE, by the same function the panel uses: there is no second HA model in the project, so Go
# does not get its own notion of "allowed to change DNS" — ha_write_verdict answers that.
#
#   pulse-apply.pl --rule N [--branch M] [--reason "..."]   — switch (without --branch: the primary set)
#   pulse-apply.pl --rule N --verify                        — only compare the zone with what we consider
#                                                             published; on mismatch — held
#
# Output is one JSON line on stdout; exit 0 = done or nothing to change, 1 = refused.
use strict;
use warnings;
use utf8;
use FindBin;
use lib "$FindBin::Bin/../www/include";
use functions qw(pulse_rule_apply pulse_rule_verify ha_write_verdict ha_gate_action);
use JSON::PP;

my %a;
while (@ARGV) {
    my $k = shift @ARGV;
    if    ($k eq '--rule')   { $a{rule}   = shift @ARGV }
    elsif ($k eq '--branch') { $a{branch} = shift @ARGV }
    elsif ($k eq '--reason') { $a{reason} = shift @ARGV }
    elsif ($k eq '--verify') { $a{verify} = 1 }
    else { out(0, "unknown argument '$k'") }
}
out(0, 'rule id required') unless ($a{rule} // '') =~ /^\d+$/;
out(0, 'branch id must be a number') if defined $a{branch} && $a{branch} ne '' && $a{branch} !~ /^\d+$/;

# Write permission comes first: on STANDBY or during a freeze a zone edit must not even start. "skip" is a
# normal refusal (not our node, an operation is running); "fail" is uncertainty and is a refusal too — never
# guess the role.
my $v = ha_write_verdict();
my $act = ha_gate_action($v);
out(0, ($v->{message} // 'HA gate'), ha => $act) unless $act eq 'allow';

if ($a{verify}) {
    my ($v, $ve) = pulse_rule_verify($a{rule});
    out(0, $ve) if $ve;
        # held is not a run failure: the program worked and reports what it found. The held field tells
        # them apart, not the exit code.
    out(1, undef, %$v, ($v->{held} ? (error => 'the record was changed outside NS Pulse') : ()));
}

my ($r, $e) = pulse_rule_apply($a{rule}, (defined $a{branch} && $a{branch} ne '' ? $a{branch} : undef),
                               $a{reason}, 'pulse');
out(0, $e) if $e;
out(1, undef, %$r);

sub out {
    my ($ok, $err, %rest) = @_;
    print JSON::PP->new->canonical->encode({ ok => ($ok ? JSON::PP::true : JSON::PP::false),
                                             ($err ? (error => $err) : ()), %rest }), "\n";
    exit($ok ? 0 : 1);
}
