#!/usr/bin/perl
# DNS Panel MCP server, remote transport: Streamable HTTP at /mcp (POST of JSON-RPC, JSON replies; no
# server-initiated stream, so GET is 405). Runs inside panel.fcgi. Switched on in Settings → External access.
#
# The caller is proven by the request, never named by it: an API token acts as its owner, an OIDC access
# token as the user its username claim names, no token as anonymous (read-only tools) when anonymous read is
# on. The tools, permissions, HA gate and audit are the same as everywhere else (include/MCPServer.pm).
# Also serves /.well-known/oauth-protected-resource (RFC 9728) listing the enabled OIDC providers, so a
# client can find an identity provider by itself.
use strict;
use warnings;
use utf8;
use FindBin;
use lib "$FindBin::RealBin/include";
use JSON ();
use functions qw(setting authenticate_bearer request_bearer anonymous_user set_request_user set_request_via
                 oidc_issuers_enabled);
use MCPServer ();

my $JSON = JSON->new->utf8->canonical;
sub reply {
    my ($status, $body, @hdr) = @_;
    binmode(STDOUT, ':raw');
    print "Status: $status\n";
    print "$_\n" for @hdr;
    if (defined $body) { print "Content-Type: application/json\n\n", (ref $body ? $JSON->encode($body) : $body); }
    else               { print "\n"; }
    exit;
}

my $uri    = $ENV{REQUEST_URI} // '';
$uri =~ s/\?.*//;
my $method = uc($ENV{REQUEST_METHOD} // 'GET');
my $proto  = (($ENV{HTTPS} // '') eq 'on' || lc($ENV{HTTP_X_FORWARDED_PROTO} // '') eq 'https') ? 'https' : 'http';
my $base   = "$proto://" . ($ENV{HTTP_HOST} // 'localhost');

reply('404 Not Found', { error => 'remote MCP is off' }) unless setting('external.mcp_http');

my $issuers = oidc_issuers_enabled();
if ($uri eq '/.well-known/oauth-protected-resource') {
    reply('404 Not Found', { error => 'no OIDC provider' }) unless @$issuers;
    reply('200 OK', { resource => "$base/mcp", authorization_servers => $issuers, bearer_methods_supported => ['header'] });
}

reply('405 Method Not Allowed', { error => 'use POST' }, 'Allow: POST') unless $method eq 'POST';

# A browser page on another site must not drive this endpoint (DNS rebinding): an Origin, when sent, must be ours.
if (my $o = $ENV{HTTP_ORIGIN}) {
    (my $oh = $o) =~ s{^\w+://}{}; $oh =~ s{/.*}{};
    reply('403 Forbidden', { error => 'origin not allowed' }) unless lc $oh eq lc($ENV{HTTP_HOST} // '');
}

my @challenge = ('WWW-Authenticate: Bearer'
    . (@$issuers ? qq{ resource_metadata="$base/.well-known/oauth-protected-resource"} : ''));
my ($user, $via);
if (defined(my $tok = request_bearer())) {
    ($user, $via) = authenticate_bearer($tok);
    reply('401 Unauthorized', { error => $via }, @challenge) unless $user;
} elsif (setting('external.anonymous_read')) {
    ($user, $via) = (anonymous_user(), 'anonymous');
} else {
    reply('401 Unauthorized', { error => 'authentication required' }, @challenge);
}
set_request_user($user);
set_request_via($via);

my $len = $ENV{CONTENT_LENGTH} || 0;
reply('413 Payload Too Large', { error => 'body too large' }) if $len > 1_000_000;
my $raw = '';
read(STDIN, $raw, $len) if $len > 0;
my $in = eval { $JSON->decode($raw) };
reply('400 Bad Request', { jsonrpc => '2.0', id => undef, error => { code => -32700, message => 'Parse error' } })
    unless ref $in eq 'HASH' || ref $in eq 'ARRAY';

my $ctx = { transport => 'http', actor => $user };
my @replies;
for my $msg (ref $in eq 'ARRAY' ? @$in : ($in)) {
    next unless ref $msg eq 'HASH';
    my $r = eval { MCPServer::handle($msg, $ctx) };
    warn "[mcp-http] dispatch error: $@" if $@;
    push @replies, $r if $r;
}
# Only notifications or responses in the request: accepted, nothing to answer.
reply('202 Accepted', undef) unless @replies;
reply('200 OK', ref $in eq 'ARRAY' ? \@replies : $replies[0]);
