#!/usr/bin/perl
# Logout: close the current session (looked up by SHA-256 of the cookie token), record it, clear cookies, go to /login.
use strict;
use warnings;
use utf8;
use CGI;
use CGI::Cookie;

use FindBin; use lib "$FindBin::RealBin/include";
use functions qw(session_logout clear_session_cookie);

my $q = CGI->new;
my $token = $q->cookie('session_token');
session_logout($token) if $token;   # closes the session and records the sign-out

my $csrf_clear = CGI::Cookie->new(-name=>'csrf_token', -value=>'', -path=>'/', -expires=>'-1d');
print $q->redirect(
    -uri    => '/login',
    -cookie => [ clear_session_cookie(), $csrf_clear ],
);
