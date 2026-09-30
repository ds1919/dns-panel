package API::Response;

use strict;
use warnings;
use utf8;
use JSON qw(encode_json);

sub _send {
    my ($status_line, $payload) = @_;
    print "Status: $status_line\n";
    print "Content-Type: application/json; charset=utf-8\n\n";
    # encode_json already returns UTF-8 bytes; a :utf8 layer would encode them twice (mojibake), so print raw.
    binmode(STDOUT, ':raw');
    print encode_json($payload);
}

sub ok {
    my ($class, $data) = @_;
    _send('200 OK', { success => JSON::true, data => ($data // {}) });
}

sub created {
    my ($class, $data) = @_;
    _send('201 Created', { success => JSON::true, data => ($data // {}) });
}

sub bad_request {
    my ($class, $message) = @_;
    _send('400 Bad Request', { success => JSON::false, error => ($message || 'Bad request') });
}

sub unauthorized {
    my ($class, $message) = @_;
    _send('401 Unauthorized', { success => JSON::false, error => ($message || 'Unauthorized') });
}

sub forbidden {
    my ($class, $message) = @_;
    _send('403 Forbidden', { success => JSON::false, error => ($message || 'Forbidden') });
}

sub not_found {
    my ($class, $message) = @_;
    _send('404 Not Found', { success => JSON::false, error => ($message || 'Not found') });
}

sub conflict {
    my ($class, $message) = @_;
    _send('409 Conflict', { success => JSON::false, error => ($message || 'Conflict') });
}

sub server_error {
    my ($class, $message) = @_;
    _send('500 Internal Server Error', { success => JSON::false, error => ($message || 'Server error') });
}

sub service_unavailable {
    my ($class, $message) = @_;
    _send('503 Service Unavailable', { success => JSON::false, error => ($message || 'Service unavailable') });
}

# Arbitrary status and body (health endpoints need structured JSON with 200/503).
# undef becomes {}; an empty list stays a list, so the client never gets an object where it expects an array.
sub json {
    my ($class, $status_line, $payload) = @_;
    _send($status_line, defined $payload ? $payload : {});
}

1;
