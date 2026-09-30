#!/usr/bin/perl
# panel.fcgi — the panel as one persistent FastCGI process (mod_fcgid) instead of a CGI process per request.
#
# A CGI request paid ~0.33 s just to compile functions.pm and the Router; here they are compiled once per
# process and each request runs the same scripts as before: api.pl for /dns-api/ and /health, index.pl for
# pages. They are run with `do`, so every request gets fresh file-scoped variables, exactly as under CGI.
#
# What would otherwise leak between requests is reset in functions::request_begin() (per-request caches,
# database handles). `exit` in a script ends the request, not the process. Output is collected in a buffer
# that each script gives its own UTF-8 layer, as it does under CGI, and goes to FastCGI as bytes (the FCGI
# stream takes no layers).
use strict;
use warnings;
use FindBin;
use lib "$FindBin::RealBin", "$FindBin::RealBin/include";

BEGIN { *CORE::GLOBAL::exit = sub { die "panel.fcgi: exit\n" }; }   # before anything that calls exit compiles

use FCGI;
use CGI ();
use functions ();
use API::Router ();
use API::Response ();

my %env;
my $req = FCGI::Request(\*STDIN, \*STDOUT, \*STDERR, \%env);
my $max = 1000;   # a fresh process now and then keeps any slow leak bounded

for (my $n = 0; $n < $max && $req->Accept() >= 0; $n++) {
    %ENV = %env;
    my $uri = $ENV{REQUEST_URI} // '/';
    my $script = ($uri =~ m{^/(?:dns-api/|health/(?:live|ready)(?:[?#]|$))}) ? 'api.pl'
               : ($uri =~ m{^/(?:mcp|\.well-known/oauth-protected-resource)(?:[?#]|$)}) ? 'mcp/http.pl'   # remote MCP
               : 'index.pl';
    $ENV{SCRIPT_NAME} = "/$script";
    $ENV{SCRIPT_FILENAME} = "$FindBin::RealBin/$script";

    my $out = '';
    {
        local *STDOUT;
        open(STDOUT, '>', \$out) or die "panel.fcgi: output buffer: $!\n";
        CGI::initialize_globals();
        functions::request_begin();
        # Scripts are recompiled on every request, so their named subs are redefined each time by design.
        local $SIG{__WARN__} = sub { warn @_ unless $_[0] =~ /^Subroutine \S+ redefined/ };
        my $ok = eval { do "$FindBin::RealBin/$script"; die $@ if $@; 1 };
        my $err = $ok ? '' : ($@ // 'unknown error');
        if ($err && $err ne "panel.fcgi: exit\n") {
            warn "panel.fcgi: $script $uri: $err";
            $out = "Status: 500 Internal Server Error\nContent-Type: text/plain; charset=utf-8\n\nInternal error\n"
                unless length $out;
        }
        alarm 0;   # whatever a request left pending must not fire in the next one
        close STDOUT;
    }
    print $out;
    $req->Finish();
}
