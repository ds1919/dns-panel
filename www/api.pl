#!/usr/bin/perl
use strict;
use warnings;
use utf8;
use CGI;

binmode(STDOUT, ":utf8");
binmode(STDERR, ":utf8");

use FindBin;
use lib "$FindBin::RealBin";
use lib "$FindBin::RealBin/include";
use JSON ();
use API::Router;
use API::Response;
use functions qw(resolve_current_user set_request_user csrf_ok ha_write_verdict authenticate_bearer request_bearer anonymous_user
                 set_request_via setting);

my $path = $ENV{'REQUEST_URI'} || '/';
$path =~ s{^/dns-api/}{};
$path =~ s/\?.*$//;
$path =~ s{^/+}{};       # root health/* paths arrive via the .htaccess alias
$path =~ s{^v1/}{};        # /dns-api/v1/ is the versioned name of the same API (external clients use it)

# Behind the proxy CGI sometimes does not hand over the body, so read it from STDIN ourselves.
my $method = $ENV{'REQUEST_METHOD'} || 'GET';
if ($method eq 'POST' || $method eq 'PUT' || $method eq 'PATCH' || $method eq 'DELETE') {
    my $len = $ENV{'CONTENT_LENGTH'} || 0;
    if ($len > 0 && $len < 1_000_000) {
        my $raw = '';
        read(STDIN, $raw, $len);
        $ENV{'POST_DATA'} = $raw if defined $raw && length($raw);
    }
}

my $cgi = CGI->new;
$ENV{'PATH_INFO'}      = '/' . $path;
$ENV{'REQUEST_METHOD'} = $cgi->request_method() || 'GET';

# Health endpoints skip session and CSRF (LB/anycast probes). /health/live must depend only on the CGI app, so no DB.
# The OpenAPI description is public too: a client reads it before it has a token.
my $is_health = ($path =~ m{^health(?:/live|/ready)?$} || $path eq 'openapi.json') ? 1 : 0;

# Resolve the user once here for the whole request. Not for health: liveness must not depend on MariaDB.
my $user = $is_health ? undef : resolve_current_user($cgi->cookie('session_token'));

# External clients: a Bearer token (API token or OIDC) acts as its user; without one, anonymous read of zones
# and records when it is switched on. No cookies are involved, so CSRF does not apply to them.
my $external = 0;
if (!$is_health && !$user) {
    if (defined(my $tok = request_bearer())) {
        my ($u, $via) = authenticate_bearer($tok);
        unless ($u) { API::Response->unauthorized($via); exit; }
        ($user, $external) = ($u, 1);
        set_request_via($via);
    } elsif ($method eq 'GET' && setting('external.anonymous_read')
             && $path =~ m{^zones(?:/\d+(?:/rrsets|/subdomains|/stats)?)?$}) {
        ($user, $external) = (anonymous_user(), 1);
        set_request_via('anonymous');
    }
}
set_request_user($user);

unless ($is_health) {
    unless ($user) {
        API::Response->unauthorized('Authentication required');
        exit;
    }
}

# CSRF double-submit for every mutating method: cookie csrf_token must equal X-CSRF-Token; body/query values are never used.
unless ($is_health || $external) {
    unless (csrf_ok($ENV{'REQUEST_METHOD'}, $cgi->cookie('csrf_token'), $ENV{'HTTP_X_CSRF_TOKEN'})) {
        API::Response->forbidden('CSRF token missing or invalid');
        exit;
    }
}

# HA write-gate (§6): in a pair, mutating requests pass only on an ACTIVE, writable, non-frozen node;
# standalone always passes. Runs after auth+CSRF and before Router. No blanket bypass for ha.emergency.
# Exempt, by exact route (not /ha/*): HA control commands, because they must run on STANDBY exactly when
# the gate would refuse; the manager applies its own, stricter safety gate. Pairing and pair creation are
# exempt too, since they happen before a pair exists. Auth, CSRF and the capability check still apply.
my $ha_control = (uc($ENV{'REQUEST_METHOD'} || '') eq 'POST' && (
        $path eq 'ha/switchover' || $path eq 'ha/emergency' || $path eq 'ha/reseed'
        || $path =~ m{^ha/pair/(create|join|approve|reject|reset|build)$}
        || $path =~ m{^ha/operations/[\w.\-]+/resume$})) ? 1 : 0;
if (!$is_health && !$ha_control && uc($ENV{'REQUEST_METHOD'} || '') =~ /^(POST|PUT|PATCH|DELETE)$/) {
    my $v = ha_write_verdict();
    unless ($v->{allow}) {
        my %SL = (409 => '409 Conflict', 503 => '503 Service Unavailable');
        API::Response->json(($SL{ $v->{status} } || '503 Service Unavailable'),
            { success => JSON::false, error => $v->{message}, code => $v->{code} });
        exit;
    }
}

my $router = API::Router->new($cgi, $user);
$router->handle_request();
