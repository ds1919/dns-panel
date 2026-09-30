package MCPServer;
# DNS Panel MCP server (Model Context Protocol): the tools and the JSON-RPC dispatcher, shared by both
# transports — www/mcp/dns-mcp.pl (local stdio) and www/mcp/http.pl (remote, Streamable HTTP at /mcp).
# Reuses the panel data layer (include/functions.pm); record changes bump the SOA, which NOTIFYs the slaves.
# Who the caller is depends on the transport (see resolve_actor): over HTTP the server knows it from the
# token; over stdio the local agent names the person in `requester`. docs/10-mcp.md.
use strict;
use warnings;
use utf8;
use JSON qw(decode_json encode_json);


use functions qw(zone_delete_everywhere 
    pdns_list_domains pdns_get_domain pdns_get_domain_by_name
    pdns_count_records pdns_get_soa pdns_get_domain_metadata
    pdns_list_rrsets pdns_apply_rrsets zone_sync_verify set_zone_sync_state
    pdns_create_zone zone_activate_after_create pdns_delete_zone zone_profile_names dns_validate_zonename
    pdns_count_records_by_type pdns_list_subnames pdns_list_child_zones
    pdns_search_records dns_query dns_check_propagation
    get_user_by_username find_user_by_cert_cn setting
    build_access_context access_for effective_zone_access
    has_capability audit_log get_client_ip ha_write_verdict
);



use constant SERVER_NAME    => 'dns-panel-mcp';
use constant SERVER_VERSION => '0.1.0';
use constant PROTO_DEFAULT  => '2024-11-05';
use constant PROTO_KNOWN    => qw(2024-11-05 2025-03-26 2025-06-18);
# The caller of the current message, set by the transport through handle():
#   { transport => 'http', actor => $user }  the user the token proved (anonymous included); `requester` is ignored
#   { transport => 'stdio' }                  the local agent names the person in `requester`
our $CTX = { transport => 'stdio' };
# MCP policy lives in the settings table; read per message, the HTTP transport runs in a persistent process.
sub readonly_mode { return setting('mcp.readonly') ? 1 : 0; }

# Character JSON (no ->utf8): each transport does the byte encoding.
our $JSON = JSON->new->canonical;

# Replies are returned, not printed: the transport writes them.
sub send_msg { return $_[0]; }
sub send_result { send_msg({ jsonrpc => '2.0', id => $_[0], result => $_[1] }); }
sub send_error {
    my ($id, $code, $message, $data) = @_;
    send_msg({ jsonrpc => '2.0', id => $id,
               error => { code => $code, message => $message, ($data ? (data => $data) : ()) } });
}
sub tool_text {
    my ($text, $is_error) = @_;
    return { content => [ { type => 'text', text => $text } ],
             ($is_error ? (isError => JSON::true) : ()) };
}
sub tool_json { return tool_text($JSON->encode($_[0])); }

sub resolve_zone {
    my ($args) = @_;
    if (defined $args->{zone_id} && $args->{zone_id} =~ /^\d+$/) {
        return pdns_get_domain($args->{zone_id});
    }
    if (defined $args->{zone} && length $args->{zone}) {
        return pdns_get_domain_by_name($args->{zone});
    }
    return undef;
}

# Make a record name an FQDN within the zone ('@' or empty = the zone itself; relative names get the zone appended).
sub fqdn_for {
    my ($name, $zone) = @_;
    $name = '' unless defined $name;
    $name =~ s/\.$//;
    return $zone if $name eq '' || $name eq '@';
    my $ln = lc $name;
    my $lz = lc $zone;
    return $name if $ln eq $lz || $ln =~ /\.\Q$lz\E$/;
    return "$name.$zone";
}

# Requester: args.requester (name/CN), else mcp.default_user. Looked up as a cert principal (like panel login),
# then as a username; unresolved means unauthenticated.
# The requester model is provisional: it is not a proven identity until the agent passes a trusted Teams
# context (the agent supplies the name and MCP trusts it). See docs/10-mcp.md.
sub resolve_actor {
    my ($args) = @_;
    return $CTX->{actor} if $CTX->{transport} eq 'http';
    my $name = (defined $args->{requester} && length $args->{requester})
             ? $args->{requester} : setting('mcp.default_user');
    return undef unless defined $name && length $name;
    return find_user_by_cert_cn($name) || get_user_by_username($name);
}

# For MX/SRV, split a leading priority off the content (same as REST).
sub normalize_records {
    my ($type, $records) = @_;
    my @out;
    for my $r (@{ $records || [] }) {
        my $content = defined $r->{content} ? $r->{content} : '';
        $content =~ s/^\s+//; $content =~ s/\s+$//;
        my $prio = $r->{prio};
        if (($type eq 'MX' || $type eq 'SRV') && !defined $prio && $content =~ /^(\d+)\s+(.+)$/) {
            $prio = $1; $content = $2;
        }
        push @out, { content => $content, prio => $prio, disabled => ($r->{disabled} ? 1 : 0) };
    }
    return \@out;
}

sub deny_no_actor {
    my ($actor) = @_;
    return undef if $actor;
    return tool_text('Permission denied: not signed in.', 1) if $CTX->{transport} eq 'http';
    return tool_text('Permission denied: unknown requester — pass "requester" '
                   . '(the person\'s name/CN) and make sure they are registered.', 1);
}

sub deny_if_no_write {
    my ($actor, $zone) = @_;   # $zone = hashref{id,name}
    my $d = deny_no_actor($actor); return $d if $d;
    unless (effective_zone_access($actor, $zone) eq 'write') {
        return tool_text("Permission denied: '$actor->{username}' cannot modify zone "
                       . "'$zone->{name}'.", 1);
    }
    return undef;
}

# No read access answers like 404, so a zone's existence is not disclosed.
sub deny_if_no_read {
    my ($actor, $zone) = @_;
    my $d = deny_no_actor($actor); return $d if $d;
    return tool_text('Zone not found', 1) if effective_zone_access($actor, $zone) eq 'none';
    return undef;
}

# Log permission denials to audit (result=denied): an attempt without rights must leave a trace.
sub audit_denied {
    my ($actor, $action, $ttype, $target, $detail) = @_;
    audit_log({
        actor => (ref $actor ? ($actor->{username} // 'unknown') : ($actor // 'unknown')),
        source => 'mcp', action => $action,
        target_type => $ttype, target => $target,
        result => 'denied', detail => $detail, ip => get_client_ip(),
    });
}

my $STR  = { type => 'string' };
my $INT  = { type => 'integer' };
my $BOOL = { type => 'boolean' };

my @TOOLS = (
    {
        name => 'whoami',
        description => 'Answer "who am I and what may I do?" for a requester (person name/CN): effective zone access + admin capabilities. No legacy role/grants.',
        inputSchema => {
            type => 'object',
            properties => { requester => $STR },
            additionalProperties => JSON::false,
        },
        readonly => 1,
        handler => sub {
            my ($args) = @_;
            my $me = resolve_actor($args);
            return tool_json({ authenticated => JSON::false,
                               note => 'Unknown requester (not registered / requester not provided).' })
                unless $me;
            my @caps = grep { has_capability($me, $_) } @functions::CAPABILITIES;
            my $ctx = build_access_context($me);
            my $all = pdns_list_domains();
            my $writable = [ map { $_->{name} }
                             grep { access_for($ctx, $_->{id}) eq 'write' } @$all ];
            return tool_json({
                authenticated => JSON::true,
                username     => $me->{username},
                capabilities => \@caps,
                writable_zones => $writable,
            });
        },
    },
    {
        name => 'list_zones',
        description => 'List DNS zones the requester may see (with access read/write). No access → not listed.',
        inputSchema => { type => 'object', properties => { requester => $STR }, additionalProperties => JSON::false },
        readonly => 1,
        handler => sub {
            my ($args) = @_;
            my $me = resolve_actor($args);
            if (my $d = deny_no_actor($me)) { return $d; }
            my $ctx  = build_access_context($me);
            my $all  = pdns_list_domains();
            my @out;
            for my $z (@$all) {
                my $acc = access_for($ctx, $z->{id});
                next if $acc eq 'none';
                $z->{access} = $acc;
                push @out, $z;
            }
            return tool_json({ count => scalar(@out), zones => \@out });
        },
    },
    {
        name => 'get_zone',
        description => 'Get one zone by name (zone) or id (zone_id): details, SOA and panel metadata.',
        inputSchema => {
            type => 'object',
            properties => { requester => $STR, zone => $STR, zone_id => $INT },
            additionalProperties => JSON::false,
        },
        readonly => 1,
        handler => sub {
            my ($args) = @_;
            my $me = resolve_actor($args);
            my $z = resolve_zone($args) or return tool_text('Zone not found', 1);
            if (my $d = deny_if_no_read($me, $z)) { return $d; }
            $z->{access}   = effective_zone_access($me, $z);
            $z->{soa}      = pdns_get_soa($z->{id});
            $z->{metadata} = pdns_get_domain_metadata($z->{id});
            $z->{record_count} = pdns_count_records($z->{id});
            return tool_json({ zone => $z });
        },
    },
    {
        name => 'list_rrsets',
        description => 'List RRsets of a zone (unit = name+type), each with its records. Optional filters: type (A, MX, ...) and name ("@", relative "www", or FQDN). Use to read current values before changing.',
        inputSchema => {
            type => 'object',
            properties => { requester => $STR, zone => $STR, zone_id => $INT, type => $STR, name => $STR },
            additionalProperties => JSON::false,
        },
        readonly => 1,
        handler => sub {
            my ($args) = @_;
            my $me = resolve_actor($args);
            my $z = resolve_zone($args) or return tool_text('Zone not found', 1);
            if (my $d = deny_if_no_read($me, $z)) { return $d; }
            my $rr = pdns_list_rrsets($z->{id});
            if (defined $args->{type} && length $args->{type}) {
                my $t = uc $args->{type};
                $rr = [ grep { uc($_->{type}) eq $t } @$rr ];
            }
            if (defined $args->{name} && length $args->{name}) {
                my $fqdn = lc fqdn_for($args->{name}, $z->{name});
                $rr = [ grep { lc($_->{name}) eq $fqdn } @$rr ];
            }
            return tool_json({ zone => $z->{name}, access => effective_zone_access($me, $z),
                               count => scalar(@$rr), rrsets => $rr });
        },
    },
    {
        name => 'count_records',
        description => 'Count records in a zone: total and a breakdown by type (A, MX, TXT, ...), plus number of distinct hostnames. Optional type limits to that type.',
        inputSchema => {
            type => 'object',
            properties => { requester => $STR, zone => $STR, zone_id => $INT, type => $STR },
            additionalProperties => JSON::false,
        },
        readonly => 1,
        handler => sub {
            my ($args) = @_;
            my $me = resolve_actor($args);
            my $z = resolve_zone($args) or return tool_text('Zone not found', 1);
            if (my $d = deny_if_no_read($me, $z)) { return $d; }
            my $stats = pdns_count_records_by_type($z->{id});
            my $hosts = pdns_list_subnames($z->{id});
            my $out = {
                zone => $z->{name},
                total => $stats->{total},
                by_type => $stats->{by_type},
                host_count => scalar(@$hosts),
            };
            if (defined $args->{type} && length $args->{type}) {
                my $t = uc $args->{type};
                $out->{type} = $t;
                $out->{count} = $stats->{by_type}{$t} || 0;
            }
            return tool_json($out);
        },
    },
    {
        name => 'list_subdomains',
        description => 'List hostnames (subdomains) that have records under a zone (e.g. www, mail) with per-host record count and types, plus any delegated child zones. Optional type filter.',
        inputSchema => {
            type => 'object',
            properties => { requester => $STR, zone => $STR, zone_id => $INT, type => $STR },
            additionalProperties => JSON::false,
        },
        readonly => 1,
        handler => sub {
            my ($args) = @_;
            my $me = resolve_actor($args);
            my $z = resolve_zone($args) or return tool_text('Zone not found', 1);
            if (my $d = deny_if_no_read($me, $z)) { return $d; }
            my $hosts = pdns_list_subnames($z->{id}, $args->{type});
            my (@sub, @apex);
            for my $h (@$hosts) {
                if (lc($h->{name}) eq lc($z->{name})) { push @apex, $h } else { push @sub, $h }
            }
            # Only child zones the user can access (No access zones are not disclosed).
            my $children = pdns_list_child_zones($z->{name});
            my $ctx = build_access_context($me);
            unless ($ctx->{allow_all}) {
                $children = [ grep { access_for($ctx, $_->{id}) ne 'none' } @$children ];
            }
            return tool_json({
                zone => $z->{name},
                subdomain_count => scalar(@sub),
                subdomains => \@sub,
                apex => (@apex ? $apex[0] : undef),
                delegated_zones => $children,
            });
        },
    },
    {
        name => 'search_records',
        description => 'Search records across ALL zones by substring of name and/or content (reverse-lookup: "where is 10.20.20.5 used", "all CNAMEs to X"). field: name|content|any. Optional type and limit.',
        inputSchema => {
            type => 'object',
            properties => {
                requester => $STR, query => $STR,
                field => { type => 'string', enum => [ 'name', 'content', 'any' ] },
                type => $STR, limit => $INT,
            },
            required => [ 'query' ],
            additionalProperties => JSON::false,
        },
        readonly => 1,
        handler => sub {
            my ($args) = @_;
            my $me = resolve_actor($args);
            if (my $d = deny_no_actor($me)) { return $d; }
            return tool_text('query is required', 1) unless defined $args->{query} && length $args->{query};
            # Filter allowed zones in SQL, before LIMIT.
            my $ctx = build_access_context($me);
            my $domain_ids;
            unless ($ctx->{allow_all}) {
                my $all = pdns_list_domains();
                $domain_ids = [ grep { access_for($ctx, $_) ne 'none' } map { $_->{id} } @$all ];
                return tool_json({ query => $args->{query}, count => 0, records => [] }) unless @$domain_ids;
            }
            my $recs = pdns_search_records($args->{query},
                { field => $args->{field}, type => $args->{type}, limit => $args->{limit},
                  domain_ids => $domain_ids });
            return tool_json({ query => $args->{query}, count => scalar(@$recs), records => $recs });
        },
    },
    {
        name => 'dns_query',
        description => 'Live DNS query (like `dig TYPE NAME @server`). Use to verify what a specific server actually answers. server optional (default resolver).',
        inputSchema => {
            type => 'object',
            properties => { requester => $STR, name => $STR, type => $STR, server => $STR, port => $INT },
            required => [ 'name' ],
            additionalProperties => JSON::false,
        },
        readonly => 1,
        handler => sub {
            my ($args) = @_;
            my $r = dns_query($args->{name}, $args->{type}, $args->{server}, $args->{port});
            return tool_text($r->{error}, 1) if $r->{error};
            return tool_json($r);
        },
    },
    {
        name => 'check_propagation',
        description => 'Check whether a zone/record has propagated: query the SOA serial (or a specific record) on the master and all configured slaves, and report drift / who is stale. Servers come from config (dns_servers).',
        inputSchema => {
            type => 'object',
            properties => { requester => $STR, zone => $STR, zone_id => $INT, name => $STR, type => $STR },
            additionalProperties => JSON::false,
        },
        readonly => 1,
        handler => sub {
            my ($args) = @_;
            my $me = resolve_actor($args);
            my $z = resolve_zone($args) or return tool_text('zone (name) or zone_id required', 1);
            if (my $d = deny_if_no_read($me, $z)) { return $d; }
            my $r = dns_check_propagation($z->{name}, $args->{name}, $args->{type});
            return tool_text($r->{error}, 1) if $r->{error};
            return tool_json($r);
        },
    },
    {
        name => 'apply_rrsets',
        description => 'Apply a batch of RRset changes to a zone (same contract as REST PATCH /zones/:id/rrsets). Unit = name+type. Atomic: all-or-nothing + one SOA bump. Requires WRITE on the zone.',
        inputSchema => {
            type => 'object',
            properties => {
                requester => $STR, zone => $STR, zone_id => $INT,
                rrsets => {
                    type => 'array',
                    items => {
                        type => 'object',
                        properties => {
                            name => $STR, type => $STR, ttl => $INT,
                            changetype => { type => 'string', enum => [ 'REPLACE', 'DELETE' ] },
                            records => {
                                type => 'array',
                                items => { type => 'object', properties => {
                                    content => $STR, prio => $INT, disabled => $BOOL },
                                    additionalProperties => JSON::false },
                            },
                        },
                        required => [ 'name', 'type', 'changetype' ],
                        additionalProperties => JSON::false,
                    },
                },
            },
            required => [ 'rrsets' ],
            additionalProperties => JSON::false,
        },
        handler => sub {
            my ($args) = @_;
            my $me = resolve_actor($args);
            my $z  = resolve_zone($args) or return tool_text('Zone not found', 1);
            if (my $deny = deny_if_no_write($me, $z)) {
                audit_denied($me || $args->{requester}, 'apply_rrsets', 'zone', $z->{name},
                             $me ? 'no write access' : 'unknown requester');
                return $deny;
            }
            return tool_text('rrsets[] is required', 1)
                unless ref($args->{rrsets}) eq 'ARRAY' && @{ $args->{rrsets} };

            my @ops;
            for my $rr (@{ $args->{rrsets} }) {
                my $type = uc($rr->{type} // '');
                my $ct   = uc($rr->{changetype} // '');
                push @ops, {
                    name       => fqdn_for($rr->{name}, $z->{name}),
                    type       => $type,
                    ttl        => $rr->{ttl},
                    changetype => $rr->{changetype},
                    records    => ($ct eq 'DELETE' ? [] : normalize_records($type, $rr->{records})),
                };
            }
            # Single write path: actor -> updated_by; the SLAVE guard lives in pdns_apply_rrsets.
            my ($ok, $err, $serial) = pdns_apply_rrsets($z->{id}, \@ops, $me->{username});
            for my $op (@ops) {
                my $is_del = uc($op->{changetype} // '') eq 'DELETE';
                audit_log({
                    actor => $me->{username}, source => 'mcp',
                    action => ($is_del ? 'delete_rrset' : 'replace_rrset'),
                    target_type => 'rrset', target => "$op->{name} $op->{type}",
                    after => ($is_del ? undef : $op->{records}),
                    result => ($ok ? 'ok' : 'error'), detail => $err, ip => get_client_ip(),
                });
            }
            return tool_text($err, 1) unless $ok;
            # Confirmed apply like the API: purge -> verify(serial) -> [rediscover] -> notify; durable only on a real verify.
            my $sync = zone_sync_verify($z->{name}, $serial);
            my $sok = set_zone_sync_state($z->{name}, $sync->{pdns_state}, $sync->{notify_state}, $sync->{detail});
            return tool_json({ zone => $z->{name}, applied => scalar(@ops),
                               pdns_state => $sync->{pdns_state}, notify_state => $sync->{notify_state},
                               ($sok ? () : (state_error => JSON::true)) });
        },
    },
    {
        name => 'create_zone',
        description => 'Create a new PRIMARY (MASTER) zone with SOA + NS from the profile preset. Requires "profile". Pass requester for permission checks.',
        inputSchema => {
            type => 'object',
            properties => {
                requester => $STR,
                name => $STR,
                profile => $STR,
            },
            required => [ 'name', 'profile' ],
            additionalProperties => JSON::false,
        },
        handler => sub {
            my ($args) = @_;
            my $me = resolve_actor($args);
            if (my $d = deny_no_actor($me)) {
                audit_denied($args->{requester}, 'create_zone', 'zone', $args->{name}, 'unknown requester');
                return $d;
            }
            my ($name, $name_error) = dns_validate_zonename($args->{name});
            return tool_text($name_error, 1) if $name_error;
            return tool_text('profile is required', 1) unless defined $args->{profile} && length $args->{profile};
            my %valid = map { $_ => 1 } @{ zone_profile_names() };
            return tool_text("Unknown profile '$args->{profile}'. Known: " . join(', ', @{ zone_profile_names() }), 1)
                unless $valid{ $args->{profile} };
            # Creating the zone itself needs zones.manage (Write on content is not enough).
            unless (has_capability($me, 'zones.manage')) {
                audit_denied($me, 'create_zone', 'zone', $args->{name}, "lacks capability 'zones.manage'");
                return tool_text("Permission denied: '$me->{username}' lacks capability 'zones.manage'.", 1);
            }
            return tool_text('Zone already exists', 1) if pdns_get_domain_by_name($name);
            my $id = pdns_create_zone($name, {
                profile => $args->{profile}, role => 'primary',
            });
            # Same finishing step as the web UI: PowerDNS must see and serve the zone, slaves get NOTIFY,
            # and the panel records the outcome.
            my $sync = $id ? zone_activate_after_create($id) : { pdns_state => 'not_attempted' };
            audit_log({ actor => $me->{username}, source => 'mcp', action => 'create_zone',
                        target_type => 'zone', target => $name,
                        after => { profile => $args->{profile}, type => 'MASTER',
                                   pdns_state => $sync->{pdns_state}, notify_state => $sync->{notify_state} },
                        result => ($id ? 'ok' : 'error'), ip => get_client_ip() });
            return tool_text('Failed to create zone', 1) unless $id;
            return tool_json({ created => 1, zone_id => $id, name => $name,
                               profile => $args->{profile},
                               pdns_state => $sync->{pdns_state}, notify_state => $sync->{notify_state} });
        },
    },
    {
        name => 'delete_zone',
        description => 'Delete a whole zone (records + metadata + domain). DESTRUCTIVE — requires confirm=true. Pass requester for permission checks.',
        inputSchema => {
            type => 'object',
            properties => { requester => $STR, zone => $STR, zone_id => $INT, confirm => $BOOL },
            required => [ 'confirm' ],
            additionalProperties => JSON::false,
        },
        handler => sub {
            my ($args) = @_;
            my $me = resolve_actor($args);
            if (my $d = deny_no_actor($me)) {
                audit_denied($args->{requester}, 'delete_zone', 'zone', ($args->{zone} // $args->{zone_id}), 'unknown requester');
                return $d;
            }
            return tool_text('Refused: pass confirm=true to delete a zone', 1) unless $args->{confirm};
            my $z = resolve_zone($args) or return tool_text('Zone not found', 1);
            # Deleting the zone itself needs zones.manage (Write on content is not enough).
            unless (has_capability($me, 'zones.manage')) {
                audit_denied($me, 'delete_zone', 'zone', $z->{name}, "lacks capability 'zones.manage'");
                return tool_text("Permission denied: '$me->{username}' lacks capability 'zones.manage'.", 1);
            }
            # Same function as the web UI: besides the PowerDNS zone it clears labels, direct distribution and
            # sync state, so a new zone reusing the domain_id does not inherit them.
            my ($res, $derr) = zone_delete_everywhere($z->{id});
            audit_log({ actor => $me->{username}, source => 'mcp', action => 'delete_zone',
                        target_type => 'zone', target => $z->{name},
                        before => ($res ? $res->{snapshot} : undef),
                        result => (!$res ? 'error' : ($res->{cleanup_error} ? 'partial' : 'ok')),
                        detail => ($res && $res->{cleanup_error} ? "cleanup failed: $res->{cleanup_error}" : undef),
                        ip => get_client_ip() });
            return tool_text('Failed to delete zone: ' . ($derr // 'unknown'), 1) unless $res;
            return tool_json({ deleted => 1, zone_id => $z->{id}, name => $res->{name},
                               pdns_state => $res->{sync}{pdns_state},
                               ($res->{cleanup_error} ? (cleanup_error => $res->{cleanup_error}) : ()) });
        },
    },
);

my %TOOL_BY_NAME = map { $_->{name} => $_ } @TOOLS;

# Over HTTP the caller is known, so `requester` is not offered; anonymous and read-only mode see no write tools.
sub tools_list_payload {
    my $http = $CTX->{transport} eq 'http';
    my $ro   = readonly_mode() || ($http && $CTX->{actor} && $CTX->{actor}{anonymous});
    my @out;
    for my $t (grep { !$ro || $_->{readonly} } @TOOLS) {
        my $schema = $t->{inputSchema};
        if ($http) {
            my %p = %{ $schema->{properties} || {} }; delete $p{requester};
            $schema = { %$schema, properties => \%p };
        }
        push @out, { name => $t->{name}, description => $t->{description}, inputSchema => $schema };
    }
    return { tools => \@out };
}

# One JSON-RPC message -> reply hashref, or undef for a notification.
sub handle {
    my ($msg, $ctx) = @_;
    local $CTX = $ctx || { transport => 'stdio' };
    return handle_message($msg);
}
sub handle_message {
    my ($msg) = @_;
    my $id     = $msg->{id};
    my $method = $msg->{method} // '';
    my $params = $msg->{params} // {};
    my $is_notification = !exists $msg->{id};

    if ($method eq 'initialize') {
        my %known = map { $_ => 1 } PROTO_KNOWN;
        my $proto = $params->{protocolVersion} || PROTO_DEFAULT;
        $proto = (PROTO_KNOWN)[-1] if $CTX->{transport} eq 'http' && !$known{$proto};
        return send_result($id, {
            protocolVersion => $proto,
            capabilities    => { tools => {} },
            serverInfo      => { name => SERVER_NAME, version => SERVER_VERSION },
        });
    }
    if ($method eq 'notifications/initialized' || $method eq 'initialized') {
        return;   # notification: no response
    }
    if ($method eq 'ping') {
        return send_result($id, {});
    }
    if ($method eq 'tools/list') {
        return send_result($id, tools_list_payload());
    }
    if ($method eq 'tools/call') {
        my $name = $params->{name} // '';
        my $args = $params->{arguments} // {};
        my $tool = $TOOL_BY_NAME{$name}
            or return send_error($id, -32602, "Unknown tool: $name");
        if (readonly_mode() && !$tool->{readonly}) {
            return send_result($id, tool_text('Server is in read-only mode (mcp.readonly)', 1));
        }
        # HA write-gate (§6): mutating tools run only on an ACTIVE, writable, non-frozen node; standalone passes.
        # The panel DB being read-only does not protect the separate pdns DB, so MCP must pass the gate too.
        if (!$tool->{readonly}) {
            my $v = ha_write_verdict();
            return send_result($id, tool_text("$v->{code}: $v->{message}", 1)) unless $v->{allow};
        }
        my $result = eval { $tool->{handler}->($args) };
        if ($@) {
            warn "[dns-mcp] tool $name error: $@\n";
            return send_result($id, tool_text('Internal error', 1));
        }
        return send_result($id, $result);
    }

    return if $is_notification;
    return send_error($id, -32601, "Method not found: $method");
}


1;
