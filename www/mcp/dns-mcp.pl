#!/usr/bin/perl
# DNS Panel MCP server, local stdio transport: JSON-RPC 2.0, one JSON message per line; logs go to STDERR.
# Run by a local MCP client as `perl /opt/dns-panel/www/mcp/dns-mcp.pl`, as the panel's user (it reads
# etc/panel.toml). The tools live in include/MCPServer.pm; the remote transport is www/mcp/http.pl (/mcp).
# Here the agent names the person it acts for in `requester` on every call (docs/10-mcp.md).
use strict;
use warnings;
use utf8;
use FindBin qw($RealBin);
use lib "$RealBin/../include";
use MCPServer ();

binmode(STDIN,  ':encoding(UTF-8)');
binmode(STDOUT, ':encoding(UTF-8)');
binmode(STDERR, ':encoding(UTF-8)');
$| = 1;   # autoflush: required for the stdio transport

my $JSON = $MCPServer::JSON;
sub out { print $JSON->encode($_[0]) . "\n"; }

warn "[dns-mcp] started (readonly=" . MCPServer::readonly_mode() . ")\n";
while (defined(my $line = <STDIN>)) {
    $line =~ s/^\s+//; $line =~ s/\s+$//;
    next unless length $line;
    my $msg = eval { $JSON->decode($line) };
    if ($@ || ref($msg) ne 'HASH') {
        out({ jsonrpc => '2.0', id => undef, error => { code => -32700, message => 'Parse error' } });
        next;
    }
    my $reply = eval { MCPServer::handle($msg, { transport => 'stdio' }) };
    warn "[dns-mcp] dispatch error: $@\n" if $@;
    out($reply) if $reply;
}
warn "[dns-mcp] stdin closed, exiting\n";
