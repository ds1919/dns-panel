#!/usr/bin/perl

use strict;
use warnings;
use utf8;
use open ':std', ':encoding(UTF-8)';

use FindBin; use lib "$FindBin::RealBin/include";
use JSON qw(encode_json);
use CGI ();
use functions qw(json_for_html request_user has_capability audit_filter_options audit_search);

# Audit log (cap audit.read). The first page of rows ships with the page: an empty table would claim
# "no entries". Further pages and filter changes are loaded by js/audit.js.

my $USER = request_user();
my $CAN  = ($USER && has_capability($USER, 'audit.read')) ? 1 : 0;

# URL filters are applied server-side so a deep link never flashes an unfiltered result.
my $Q = CGI->new;
my %F;
for my $k (qw(actor action result target_type source target from to)) {
    my $v = $Q->param($k);
    $F{$k} = $v if defined $v && length $v;
}
my $LIMIT = 50;
my ($rows, $total) = $CAN ? audit_search(\%F, $LIMIT, 0) : ([], 0);

my %DATA = (
    can     => $CAN,
    options => ($CAN ? audit_filter_options() : {}),
    rows    => $rows,
    total   => $total + 0,
    limit   => $LIMIT,
);

print <<'HTML';
<div class="page-head"><div><h1>Audit log</h1></div></div>
<div id="audit-root"></div>
HTML

print qq{<script type="application/json" id="audit-data">} . json_for_html(\%DATA) . qq{</script>\n};

1;
