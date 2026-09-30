#!/usr/bin/perl
# recover-access — break-glass access recovery for an EXISTING user, run on the node itself.
#
# Why outside the panel: only a signed-in user can reset a password or second factor through the UI. If the
# only administrator lost the authenticator (or the server lost the key the secret is encrypted with), nobody
# can get in, and bootstrap-admin refuses while an active admin exists. Access to the node is then all that
# is left — and it MUST be a way out, otherwise there is none.
#
# Both actions require an explicit flag: silently resetting the second factor on a password change would turn
# "forgot my password" into "lost my 2FA".
#
# Examples:
#   sudo -u www-data perl libexec/recover-access.pl --username admin --reset-totp
#   sudo -u www-data perl libexec/recover-access.pl --username admin --password 'NewPass123' --reset-totp
use strict;
use warnings;
use utf8;
use open ':std', ':encoding(UTF-8)';
use FindBin; use lib "$FindBin::RealBin/../www/include";
use Getopt::Long;
use functions qw(connectDB set_user_password auth_totp_reset audit_log ha_mode ha_write_verdict);

my %o;
GetOptions(\%o, 'username=s', 'password:s', 'reset-totp', 'help')
    or die "bad options (see --help)\n";
my $want_pw   = exists $o{password};
my $want_totp = $o{'reset-totp'} ? 1 : 0;
if ($o{help} || !$o{username} || !($want_pw || $want_totp)) {
    print <<'USAGE';
Usage: perl libexec/recover-access.pl --username U [--password [S]] [--reset-totp]
  --username U     (required) login of an existing user
  --password [S]   set the password; without a value a temporary one is generated and shown once.
                   must_change=1 is set either way: a password that went through a terminal
                   and shell history must not stay in use.
  --reset-totp     remove the authenticator and recovery codes: the user enrolls again
At least one action is required. All sessions of the user are closed.
USAGE
    exit($o{username} ? 0 : 1);
}

# This writes to the replicated dns_panel, so only on a node that may accept writes. MariaDB would refuse on
# STANDBY anyway, but saying so up front and plainly beats a driver error.
if (ha_mode() eq 'pair') {
    my $v = ha_write_verdict();
    unless ($v->{allow}) {
        print STDERR "this node cannot accept writes: $v->{message}\n";
        print STDERR "run this on the ACTIVE node of the pair.\n";
        exit 1;
    }
}

my $dbh = connectDB() or die "DB unavailable\n";
my ($uid, $active) = $dbh->selectrow_array("SELECT id, is_active FROM users WHERE username=?", undef, $o{username});
die "unknown user '$o{username}'\n" unless $uid;
print "user '$o{username}' (id $uid)" . ($active ? "\n" : " — DISABLED (is_active=0)\n");

my $temp;
if ($want_pw) {
    $temp = (defined $o{password} && length $o{password}) ? $o{password} : functions::_gen_temp_password();
    my ($ok, $err) = set_user_password($uid, $temp, 1);
    die "password reset failed: $err\n" if $err;
    print "  password: set (must be changed at next sign-in)\n";
}
if ($want_totp) {
    my ($ok, $err) = auth_totp_reset($uid);
    die "two-factor reset failed: $err\n" if $err;
    print "  two-factor: removed (enrollment happens at next sign-in)\n";
}

# The audit record is MANDATORY: recovering access from the node, bypassing the panel, is exactly the event
# that will need explaining later. Source 'system' because there is no human session here.
audit_log({
    source       => 'system',
    actor        => 'root@node',
    action       => 'user_access_recovered',
    target_type  => 'user',
    target       => $uid,
    target_label => $o{username},
    after        => { password => ($want_pw ? 1 : 0), totp_reset => $want_totp },
    detail       => 'libexec/recover-access.pl on ' . (functions::ha_node_id() || 'node'),
});

if (defined $temp && !(defined $o{password} && length $o{password})) {
    print "\n  TEMPORARY PASSWORD (shown once):\n      $temp\n";
}
print "\nAll sessions of this user are closed. Next sign-in: password"
    . ($want_pw ? " → forced change" : "")
    . ($want_totp ? " → authenticator enrollment" : "") . ".\n";
exit 0;
