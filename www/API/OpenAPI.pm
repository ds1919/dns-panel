package API::OpenAPI;
# OpenAPI 3.1 description of the external API contract: the routes a client outside the panel is expected to
# use. Served at GET /dns-api/v1/openapi.json without authentication. The panel UI uses more routes than
# this; they are not part of the contract. Keep in step with Router.pm when a listed route changes.
use strict;
use warnings;
use utf8;
use JSON ();

sub _ok {
    my ($desc, $data) = @_;
    return { description => $desc, content => { 'application/json' => { schema => {
        type => 'object', properties => { success => { type => 'boolean' }, data => ($data // { type => 'object' }) } } } } };
}
sub _body {
    my ($schema, $required) = @_;
    return { required => JSON::true, content => { 'application/json' => { schema => $schema } } };
}
my $ID   = { name => 'id', in => 'path', required => JSON::true, schema => { type => 'integer' }, description => 'Zone id (from GET /zones)' };
my $ERR  = { '$ref' => '#/components/responses/Error' };
my %STD  = (400 => $ERR, 401 => $ERR, 403 => $ERR, 404 => $ERR, 409 => $ERR);

sub spec {
    my $str = { type => 'string' };
    my $int = { type => 'integer' };
    my $rrset = { type => 'object', required => [qw(name type changetype)], properties => {
        name       => { type => 'string', description => '"@", a relative name ("www") or an FQDN inside the zone' },
        type       => { type => 'string', example => 'A' },
        ttl        => $int,
        changetype => { type => 'string', enum => [qw(REPLACE DELETE)] },
        records    => { type => 'array', items => { type => 'object', required => ['content'], properties => {
            content => $str, prio => $int, disabled => { type => 'boolean' } } } },
    } };
    return {
        openapi => '3.1.0',
        info => { title => 'DNS Panel API', version => '1',
                  description => 'Zones and records of a DNS Panel. Every call acts as a panel user and has exactly '
                               . 'that user\'s permissions; changes are in the audit log. On a STANDBY node of a pair, '
                               . 'writes return 409 (code standby_read_only): use the service address.' },
        servers => [ { url => '/dns-api/v1' } ],
        security => [ { bearer => [] } ],
        components => {
            securitySchemes => { bearer => { type => 'http', scheme => 'bearer',
                description => 'An API token (Settings → External access) or an access token of the configured OIDC provider.' } },
            responses => { Error => { description => 'Error', content => { 'application/json' => { schema => {
                type => 'object', properties => { success => { type => 'boolean', const => JSON::false },
                                                   error => $str, code => $str } } } } } },
        },
        paths => {
            '/zones' => {
                get => { summary => 'Zones visible to the caller', responses => { 200 => _ok('Zones',
                    { type => 'object', properties => { zones => { type => 'array', items => { type => 'object', properties => {
                        id => $int, name => $str, type => { type => 'string', enum => [qw(MASTER SLAVE)] },
                        access => { type => 'string', enum => [qw(read write)] }, soa_serial => $str, record_count => $int } } } } }), %STD } },
                post => { summary => 'Create a zone (zones.manage)',
                    requestBody => _body({ type => 'object', required => ['name'], properties => {
                        name => $str, role => { type => 'string', enum => [qw(primary secondary)], default => 'primary' },
                        profile => { type => 'string', description => 'Zone profile (SOA/NS preset)' },
                        masters => { type => 'array', items => $str, description => 'secondary: primary addresses' },
                        soa => { type => 'object' }, nameservers => { type => 'array', items => $str } } }),
                    responses => { 201 => _ok('Created'), %STD } },
            },
            '/zones/{id}' => {
                parameters => [ $ID ],
                get => { summary => 'Zone details', responses => { 200 => _ok('Zone'), %STD } },
                delete => { summary => 'Delete a zone (zones.manage)',
                    requestBody => _body({ type => 'object', required => ['confirm_name'], properties => {
                        confirm_name => { type => 'string', description => 'The zone name, as a confirmation' } } }),
                    responses => { 200 => _ok('Deleted'), %STD } },
            },
            '/zones/{id}/rrsets' => {
                parameters => [ $ID ],
                get => { summary => 'RRsets of a zone (name + type, with records)', responses => { 200 => _ok('RRsets',
                    { type => 'object', properties => { rrsets => { type => 'array', items => { type => 'object' } } } }), %STD } },
                patch => { summary => 'Change RRsets: all or nothing, one SOA bump, NOTIFY (write access to the zone)',
                    requestBody => _body({ type => 'object', required => ['rrsets'], properties => {
                        rrsets => { type => 'array', items => $rrset } } }),
                    responses => { 200 => _ok('Applied'), %STD } },
            },
            '/zones/{id}/soa' => {
                parameters => [ $ID ],
                patch => { summary => 'Change SOA fields', requestBody => _body({ type => 'object' }),
                    responses => { 200 => _ok('Updated'), %STD } },
            },
            '/zones/{id}/dnssec' => {
                parameters => [ $ID ],
                get => { summary => 'DNSSEC state and keys', responses => { 200 => _ok('DNSSEC'), %STD } },
                put => { summary => 'Sign or unsign the zone (zones.manage)',
                    requestBody => _body({ type => 'object', required => ['enabled'], properties => {
                        enabled => { type => 'boolean' }, algorithm => $str } }),
                    responses => { 200 => _ok('Done'), %STD } },
            },
            '/zones/{id}/audit' => {
                parameters => [ $ID ],
                get => { summary => 'Audit log of one zone', responses => { 200 => _ok('Entries'), %STD } },
            },
            '/audit' => {
                get => { summary => 'Audit log (audit.read)',
                    parameters => [ map { { name => $_, in => 'query', schema => $str } } qw(actor action result source target limit offset) ],
                    responses => { 200 => _ok('Entries'), %STD } },
            },
            '/health/ready' => {
                get => { summary => 'Node readiness (no authentication)', security => [],
                    responses => { 200 => { description => 'Ready' }, 503 => { description => 'Not ready (for example a STANDBY)' } } },
            },
        },
    };
}

1;
