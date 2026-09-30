#!/usr/bin/perl
# bootstrap-admin — create the FIRST administrator locally, not through the UI. Atomically creates the user
# (+ cert identity if --cert-cn is given), a temporary Argon2id password (must_change), the 'DNS Administrators'
# group with membership, all capabilities and zone_access all/write.
# Refused if an active users.manage admin already exists. --cert-cn is optional (a test machine may have no
# certificate): first login is then by username + temporary password → forced change → TOTP enrollment → recovery codes.
#
# Example:
#   perl deploy/bootstrap-admin.pl --username jdoe --display-name "Jane Doe" \
#        --email s@example.com [--cert-cn "Jane Doe"] [--password "..."]
use strict;
use warnings;
use utf8;
use open ':std', ':encoding(UTF-8)';
use FindBin; use lib "$FindBin::RealBin/../www/include";
use Getopt::Long;
use functions qw(bootstrap_admin);

my %o;
GetOptions(\%o, 'username=s', 'display-name=s', 'email=s', 'cert-cn=s', 'password=s', 'help')
    or die "bad options (see --help)\n";
if ($o{help} || !$o{username}) {
    print <<'USAGE';
Usage: perl deploy/bootstrap-admin.pl --username U [options]
  --username U        (required) admin login
  --display-name S    display name
  --email S           email
  --cert-cn CN        CN of the client certificate (mTLS), optional
  --password S        set the password (otherwise a temporary one is generated and shown once)
Creates the first administrator. Refused if an active admin already exists.
USAGE
    exit($o{username} ? 0 : 1);
}

my ($res, $err) = bootstrap_admin({
    username     => $o{username},
    display_name => $o{'display-name'},
    email        => $o{email},
    cert_cn      => $o{'cert-cn'},
    password     => $o{password},
});
if ($err) { print STDERR "bootstrap failed: $err\n"; exit 1; }

print "Administrator created.\n";
print "  user_id:  $res->{user_id}\n";
print "  username: $res->{username}\n";
print "  group:    DNS Administrators (id $res->{group_id}) — all capabilities + zone_access all/write\n";
print "  cert CN:  " . (defined $res->{cert_cn} ? $res->{cert_cn} : "(none — login by password first)") . "\n";
if (defined $res->{temp_password}) {
    print "\n  TEMPORARY PASSWORD (shown once — must be changed at first login):\n";
    print "      $res->{temp_password}\n";
}
print "\nNext: sign in with this password; you will be asked to change it. Two-factor can be set up in Account.\n";
exit 0;
