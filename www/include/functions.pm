package functions;

our $VERSION = '1.0';
our $LOADED = 1;

use strict;
use warnings;
use utf8;
use DBI;
use CGI;
use CGI::Cookie;
use JSON qw(decode_json encode_json);
use File::Basename qw(dirname);
use File::Spec;
use Socket qw(inet_pton inet_ntop AF_INET AF_INET6);
# POSIX and IO::Socket::UNIX are loaded lazily where used: a top-level `use` cost ~16 ms on every CGI
# request, while only zone creation (strftime) and the dns-agent/HA-manager sockets need them.
# SOCK_STREAM is therefore always written as Socket::SOCK_STREAM(): it used to come from IO::Socket's
# re-export, not from the Socket import list above.
use MIME::Base64 qw(decode_base64 encode_base64);
use Digest::SHA qw(sha256_hex);

require Exporter;
our @ISA = qw(Exporter);

our @EXPORT_OK = qw(
    secondary_group_prefixes_set
    external_settings external_settings_set api_token_list api_token_create api_token_update api_token_delete api_token_get
    authenticate_bearer request_bearer anonymous_user set_request_via oidc_user_for oidc_verify
    oidc_provider_list oidc_provider_create oidc_provider_update oidc_provider_delete oidc_provider_get oidc_issuers_enabled
    connectDB clear_session_cookie get_client_ip load_panel_config setting get_config_value cert_cn asset_version
    find_user_by_cert_cn authenticate_cert resolve_current_user set_request_user request_user session_open
    session_by_raw session_close session_logout login_password auth_step_password auth_step_totp_begin auth_step_totp_confirm
    auth_step_totp_verify auth_step_recovery_use auth_throttle_guard auth_throttle_fail auth_throttle_ok
    get_user_by_username connectPDNS pdns_list_domains zone_access_domains pdns_get_domain pdns_get_domain_by_name
    pdns_find_domain_by_name pdns_count_records pdns_list_records pdns_get_soa pdns_soa_fields pdns_update_soa
    pdns_apex_ns_list pdns_apex_ns_mutate pdns_record_mutate pdns_records_batch reverse_candidates_for_ip
    reverse_master_for_ip classify_ptr ptr_ui_status zone_ptr_statuses pdns_create_address_ptr is_ip_addr
    ptr_reverse_for_record pdns_create_record_ptr pdns_delete_records_ptr canonicalize_ip canonicalize_caa
    zone_sync_verify zone_activate_after_create pdns_create_zone pdns_delete_zone pdns_zone_defaults zone_profile_preset zone_profile_names
    zone_profiles_for_form zone_profiles_all zone_profile_get zone_profile_create zone_profile_update
    zone_profile_delete pdns_zone_snapshot dns_validate_zonename pdns_get_domain_metadata pdns_set_zone_metas
    bind_export_zones bind_export_sources zone_import_apply
    import_source_load import_sources_all import_source_get import_inventory import_zone_mark
    dns_agent_call zone_activate zone_verify zone_deactivate zone_sync_verify zone_secondary_request set_zone_sync_state
    get_zone_sync_state sync_problem_zones due_retry_zones sync_next_due sync_wake retry_zone_activation retry_zone_sync zone_secondary_refresh sync_operation_for
    dynamic_materialize_all zone_dynamic_map zone_dynamic_get zone_dynamic_save zone_dynamic_disable
    dyn_profiles_all dyn_profile_save dyn_profile_delete
    import_probe_queue import_probe_run import_probe_queued import_zone_diff import_zone_take import_zone_copy_ops
    sync_backoff_secs sync_write_plan pdns_count_records_by_type pdns_list_subnames pdns_list_child_zones
    pdns_search_records pdns_names_with_address ptr_suffix_for_partial_ip dns_query dns_check_propagation dns_validate dns_record_types pdns_list_rrsets
    pdns_apply_rrsets effective_zone_access build_access_context access_for pdns_profile_map zone_kind
    zone_role_or_die zone_role_norm reverse_zones_for_cidr reverse_plan_for_cidr
    pdns_create_zones_batch label_categories_all zone_labels_get zone_labels_map zone_labels_set
    zone_labels_delete_all label_category_create label_category_delete label_value_create label_value_delete
    has_capability capability_check effective_capabilities users_all user_get user_create user_update user_delete
    perm_groups_all perm_group_get perm_group_create perm_group_update perm_group_delete user_group_add
    user_group_remove capability_grant capability_revoke zone_access_set zone_access_delete auth_identity_add
    auth_identity_delete auth_totp_disable auth_totp_reset auth_totp_require user_sessions zone_access_effective user_access_set user_access_preview
    group_access_set session_ttl_default user_session_ttl user_session_ttl_raw set_user_session_ttl session_revoke
    account_overview account_password_change account_totp_begin account_totp_confirm account_totp_cancel
    account_totp_disable
    account_recovery_regenerate account_prefs_set account_themes theme_css_link ui_select_html actor_icon_html catalog_label
    pulse_testers_all pulse_tester_save pulse_tester_delete pulse_enroll_key pulse_enroll_key_new
    pulse_server_address_set
    pulse_groups_all pulse_group_save pulse_group_delete pulse_group_members_set
    pulse_checks_all pulse_check_save pulse_check_delete pulse_check_groups_set
    pulse_check_testers pulse_check_runs_on pulse_history pulse_rrset_history
    pulse_sweep_zone_states pulse_sweep_rrset_history pulse_sweep_policy pulse_policy_set pulse_policy_fields pulse_check_defaults
    pulse_sweep_mark_dirty pulse_sweep_after_write
    pulse_zones_writable pulse_rule_candidates pulse_rrset_draft pulse_server_hint pulse_canon_value pulse_canon_set
    pulse_rules_all pulse_rule_get pulse_rule_create pulse_rule_update pulse_rule_delete pulse_rule_clone_to
    pulse_rule_apply pulse_rule_verify pulse_notify pulse_server_alive
    pulse_rule_branches_set
    session_revoke_all password_hash password_verify set_user_password bootstrap_admin audit_log audit_action_label
    audit_target_label audit_type_label audit_history audit_search audit_filter_options dashboard_summary csrf_ok
    csrf_token_new node_health ha_mode ha_enabled ha_node_id ha_write_verdict ha_gate_action ha_manager_request
    ha_manager_status ha_service_url ha_service_address upstream_tsig_resolve upstream_tsig_rollback upstream_tsig_keys import_update_from zone_dnssec_get zone_dnssec_set zone_dnssec_key_add zone_dnssec_key_set zone_dnssec_key_delete zone_signed_by_name import_zone_dnssec import_zone_dnssec_keys import_zone_dnssec_unsigned zone_signed_map ha_sign_in_block ha_sign_in_hint node_addresses node_ifaces ha_pair_address ha_pair_address_set ha_configured
    ha_trusted dns_name_unicode dns_name_ascii dns_name_html cidr_normalize cidr_contains strict_bool tsig_secret_check node_caps_check axfr_readiness tsig_keys_all
    tsig_key_meta tsig_key_create tsig_keys_forget_unused tsig_key_forget_unused_by_name tsig_key_secret ip_groups_all ip_group_get
    ip_group_create ip_group_update ip_group_delete ip_group_member_add ip_group_member_delete pdns_endpoints
    secondary_groups_all secondary_group_get secondary_group_create secondary_group_update
    secondary_group_delete secondary_group_member_add secondary_group_member_remove secondary_group_ip_group_add
    secondary_group_ip_group_remove secondary_group_tsig_key_add secondary_group_tsig_key_remove
    secondary_group_tsig_set_primary secondary_node_tsig_key_add secondary_node_tsig_key_remove
    secondary_node_tsig_set_primary secondary_nodes_tsig_map secondary_node_tsig_key_create_and_add
    secondary_group_tsig_key_create_and_add secondary_node_set_default_group secondary_nodes_all secondary_node_get
    secondary_node_create secondary_node_update secondary_node_delete secondary_server_save secondary_server_get
    secondary_servers_list secondary_server_delete secondary_nodes_last_change secondary_node_endpoint_add
    secondary_node_endpoint_update secondary_node_endpoint_delete secondary_node_endpoint_get label_predicate_eval
    label_predicate_validate zone_eligible_for_distribution zone_distribution_cleanup zone_delete_everywhere
    catalogs_all catalog_get catalog_create catalog_update catalog_delete distributable_zones
    catalog_groups_get catalog_groups_set catalog_nodes_get catalog_node_remove nodes_catalogs_map node_catalogs_set
    catalog_zones zone_catalog_of zone_catalog_map catalogs_available
    catalog_provision catalog_provision_delete catalog_axfr_materialize
    catalog_subscription_config catalog_subscription_recheck catalog_producer_serial catalog_consumers_state
    zone_direct_axfr_map zone_direct_axfr_set zones_direct_axfr_set direct_axfr_zones
    zone_recipients zone_catalog_set zone_policy_materialize apply_zones served_zones
    policy_refresh policy_lock policy_unlock zone_policy_clear orphan_policy_sweep
    catalog_primary_endpoints catalog_primary_endpoints_set node_addresses_state
    zone_promote_to_primary zone_demote_to_secondary zone_secondary_source_set json_for_html
);

binmode(STDOUT, ":utf8");
binmode(STDERR, ":utf8");

# managed_kind is a leftover of the removed zone-selection assignment path. The guard against editing a
# system rule via the generic rule API stays: if such a rule ever appears from outside, it must not be
# changed blindly.
our $MANAGED_RULE_MSG = 'managed rule cannot be edited through the generic rule API';   # -> 409 in _inv_fail
# Threshold for AUTOMATIC removal of zones from a catalog. Kept in one place so the worker and the API agree;
# otherwise a bad edit of a broad rule could silently remove any number of zones.
our $MASS_DELETE_GUARD = 5;

# Config comes from etc/panel.toml only (no ENV).
#   _cfg(section,key)          -> required: dies if missing.
#   _cfg(section,key,$default) -> optional.
# Apache request data (SSL_CLIENT_*, REMOTE_ADDR, HTTPS...) is not config and is read from %ENV.
sub _cfg {
    my ($section, $key, @def) = @_;
    my $v = get_config_value($section, $key);
    return $v if defined $v && $v ne '';
    return $def[0] if @def;
    die "etc/panel.toml: missing required key '$section.$key'\n";
}

# Per-file asset version for cache busting: mtime + size. .htaccess serves assets as
# `immutable, max-age=1 year`, so a shared time()/max-mtime version would either defeat the cache or
# invalidate every file on any edit. mtime is fractional (Time::HiRes): with whole seconds, two same-size
# edits within one second (e.g. a one-char sed) would keep the same version and the browser would hold the
# stale file for a year.
our $_WWW_ROOT;
sub _www_root {
    return $_WWW_ROOT if defined $_WWW_ROOT;
    # Relative to this module, not cwd or the entry script: pages are loaded from index.pl, so FindBin
    # would point elsewhere.
    my $inc = File::Spec->rel2abs(dirname(__FILE__));
    $_WWW_ROOT = File::Spec->canonpath(File::Spec->catdir($inc, File::Spec->updir));
    return $_WWW_ROOT;
}
# $rel is the path as used in markup ('/css/main.css'). Missing/unreadable file -> '0': the link still
# works without a version, which beats a 500 over a missing image.
sub asset_version {
    my ($rel) = @_;
    return '0' unless defined $rel && length $rel;
    (my $r = $rel) =~ s{^/+}{};
    return '0' if $r =~ m{(?:^|/)\.\.(?:/|$)};
    require Time::HiRes;
    my @st = Time::HiRes::stat(File::Spec->catfile(_www_root(), split m{/}, $r));
    return '0' unless @st;
    my $mtime = sprintf('%.6f', $st[9]);
    $mtime =~ tr/.//d;                     # a dot is legal in a query string, but the number reads easier without it
    return $mtime . '-' . $st[7];
}

our $dbh_cache;
our $pdns_cache;

# ============================================================================
# DATABASE
# ============================================================================

sub connectDB {
    my $dbname = shift || _cfg('panel_db', 'name');

    if ($dbh_cache && !$dbh_cache->state) {
        eval { $dbh_cache->do("SET time_zone = '+00:00'") };
        return $dbh_cache;
    }

    my $host = _cfg('panel_db', 'host', '127.0.0.1');
    my $user = _cfg('panel_db', 'user');
    my $pass = _secret_file('panel_db', 'password_file');
    my $dsn  = "DBI:mysql:database=$dbname;host=$host;mysql_ssl=0";
    my $dbh = eval {
        DBI->connect($dsn, $user, $pass, {
            RaiseError        => 0,
            PrintError        => 0,
            AutoCommit        => 1,
            mysql_enable_utf8 => 1,
        });
    };
    return undef unless $dbh;

    eval { $dbh->do("SET time_zone = '+00:00'") };
    $dbh_cache = $dbh;
    return $dbh;
}


# ============================================================================
# SESSIONS / USERS
# ============================================================================

sub get_user_by_id {
    my ($user_id) = @_;
    return undef unless $user_id;

    my $dbh = connectDB() or return undef;
    my $sth = $dbh->prepare(
        "SELECT id, username, email, created_at, timezone, date_format, theme
           FROM users
          WHERE id = ?
          LIMIT 1"
    ) or return undef;
    $sth->execute($user_id) or return undef;
    my $row = $sth->fetchrow_hashref;
    $sth->finish;
    return $row;
}

# ============================================================================
# COOKIES
# ============================================================================

sub clear_session_cookie {
    return CGI::Cookie->new(
        -name    => 'session_token',
        -value   => '',
        -path    => '/',
        -expires => '-1d',
    );
}

# ============================================================================
# AUTHENTICATION (mTLS client certificate -> user -> session)
# ============================================================================

sub cert_cn {
    return undef unless ($ENV{SSL_CLIENT_VERIFY} || '') eq 'SUCCESS';
    my $cn = $ENV{SSL_CLIENT_S_DN_CN};
    return (defined $cn && length $cn) ? $cn : undef;
}

# User by certificate CN (auth_identities type=cert); hashref or undef.
sub find_user_by_cert_cn {
    my ($cn) = @_;
    return undef unless defined $cn && length $cn;
    my $dbh = connectDB() or return undef;
    my $sth = $dbh->prepare(
        # provider='' strictly: otherwise an oauth provider with the same principal could match a cert CN.
        "SELECT u.id, u.username, u.email, u.display_name
           FROM users u
           JOIN auth_identities ai ON ai.user_id = u.id
          WHERE ai.type = 'cert' AND ai.provider = '' AND ai.principal = ? AND ai.is_active = 1 AND u.is_active = 1
          LIMIT 1"
    ) or return undef;
    $sth->execute($cn) or return undef;
    my $row = $sth->fetchrow_hashref;
    $sth->finish;
    return $row;
}

sub authenticate_cert {
    my $cn = cert_cn();                    # trusts Apache (SSLVerifyClient require)
    return undef unless defined $cn;
    return find_user_by_cert_cn($cn);
}

# Current user for panel/API: only a FULL hashed session (stage='full'). Pending login sessions are
# accepted only by auth endpoints (login.pl). The raw bearer is never stored in the DB.
sub resolve_current_user {
    my ($token) = @_;
    my $s = session_by_raw($token);
    return undef unless $s && $s->{stage} eq 'full';
    return get_user_by_id($s->{user_id});
}

# Resolved once per request (index.pl/api.pl); pages and the router read it from here.
our $_request_user;
# Start of a request in a persistent process (www/panel.fcgi): nothing from the previous request may survive.
# The caches below live for one request. Database handles are closed, not reused: a request that died inside
# a transaction or holding a GET_LOCK would hand both to the next one. A local reconnect costs milliseconds.
sub request_begin {
    $_request_user = undef;
    $functions::_request_via = undef;
    $functions::ha_view_cache = $functions::ha_trusted_cache = $functions::settings_cache = $functions::config_cache = undef;
    for my $h ($dbh_cache, $pdns_cache) {
        next unless $h;
        eval { $h->rollback unless $h->{AutoCommit}; $h->disconnect };
    }
    $dbh_cache = $pdns_cache = undef;
    return;
}
sub set_request_user { $_request_user = $_[0]; return $_[0]; }
sub request_user     { return $_request_user; }

# ============================================================================
# PERMISSIONS: zone access (build_access_context / access_for / effective_zone_access) + capabilities
# ============================================================================

sub get_user_by_username {
    my ($username) = @_;
    return undef unless defined $username && length $username;
    my $dbh = connectDB() or return undef;
    return $dbh->selectrow_hashref(
        "SELECT id, username, email, display_name, is_active
           FROM users WHERE username = ? AND is_active = 1 LIMIT 1",
        undef, $username);
}

# ============================================================================
# UTILITIES
# ============================================================================


# Real client IP: Cloudflare -> first X-Forwarded-For -> REMOTE_ADDR.
sub get_client_ip {
    my $ip;
    $ip = $ENV{'HTTP_CF_CONNECTING_IP'} if $ENV{'HTTP_CF_CONNECTING_IP'} && $ENV{'HTTP_CF_CONNECTING_IP'} =~ /\S/;
    if (!$ip && $ENV{'HTTP_X_FORWARDED_FOR'}) {
        ($ip) = split(/,/, $ENV{'HTTP_X_FORWARDED_FOR'});
        $ip =~ s/\s+//g if $ip;
    }
    $ip = $ENV{'REMOTE_ADDR'} if (!$ip || $ip !~ /\S/) && $ENV{'REMOTE_ADDR'};
    return $ip;
}

# ============================================================================
# POWERDNS (gmysql backend: domains, records)
# ============================================================================

# Separate connection to the PowerDNS DB (shadow master): the panel writes records here, then the SOA
# serial bump makes PowerDNS NOTIFY the secondaries.
sub connectPDNS {
    if ($pdns_cache && !$pdns_cache->state) {
        eval { $pdns_cache->do("SET time_zone = '+00:00'") };
        return $pdns_cache;
    }
    my $host = _cfg('pdns_db', 'host', '127.0.0.1');
    my $name = _cfg('pdns_db', 'name');
    my $user = _cfg('pdns_db', 'user');
    my $pass = _secret_file('pdns_db', 'password_file');
    my $dsn  = "DBI:mysql:database=$name;host=$host;mysql_ssl=0";
    my $dbh = eval {
        DBI->connect($dsn, $user, $pass, {
            RaiseError        => 0,
            PrintError        => 0,
            AutoCommit        => 1,
            mysql_enable_utf8 => 1,
        });
    };
    return undef unless $dbh;
    # Session in UTC (as in connectDB) so records.updated_at (NOW(6)) and audit_log.ts share one scale;
    # local time is rendered in the browser.
    eval { $dbh->do("SET time_zone = '+00:00'") };
    $pdns_cache = $dbh;
    return $dbh;
}

sub pdns_list_domains {
    my $dbh = connectPDNS() or return [];
    # soa_serial is the real serial from the SOA record, not notified_serial (the last NOTIFY sent,
    # see docs/03-database.md).
    my $sth = $dbh->prepare(
        "SELECT d.id, d.name, d.type, d.master, d.notified_serial, d.account,
                (SELECT COUNT(*) FROM records r WHERE r.domain_id = d.id AND r.type IS NOT NULL AND r.type <> '' AND r.type NOT IN ('RRSIG','NSEC','NSEC3','NSEC3PARAM','DNSKEY','CDS','CDNSKEY','TYPE65534')) AS record_count,
                (SELECT SUBSTRING_INDEX(SUBSTRING_INDEX(s.content, ' ', 3), ' ', -1)
                   FROM records s WHERE s.domain_id = d.id AND s.type = 'SOA' LIMIT 1) AS soa_serial
           FROM domains d
          ORDER BY d.name ASC"
    ) or return [];
    $sth->execute or return [];
    return $sth->fetchall_arrayref({}) || [];
}
# ids of catalog producer zones (by catalogs.pdns_domain_id, NOT by name) -> { domain_id => 1 } | undef on
# DB error. Write-side validation must treat undef as "DB unavailable" (fail-closed); the display path
# (zone_access_domains) treats it as {} - fail-open is safe for an exclusion-only display filter.
sub _catalog_domain_ids {
    my ($dbh) = @_;
    $dbh ||= connectDB() or return undef;
    my $rows = $dbh->selectcol_arrayref("SELECT pdns_domain_id FROM catalogs WHERE pdns_domain_id IS NOT NULL");
    return undef if $dbh->err;
    return { map { $_ + 0 => 1 } @{ $rows || [] } };
}
# Zones that user access can be assigned to: all PowerDNS zones minus catalog producer zones. Single
# source for settings.pl, zone_access_effective, user_access_preview and per-zone rule validation.
sub zone_access_domains {
    my $doms = pdns_list_domains() || [];
    my $cat = _catalog_domain_ids() || {};   # display: fail-open (undef -> no filtering)
    return [ grep { !$cat->{ $_->{id} + 0 } } @$doms ];
}

sub pdns_get_domain {
    my ($domain_id) = @_;
    return undef unless $domain_id;
    my $dbh = connectPDNS() or return undef;
    my $sth = $dbh->prepare(
        "SELECT d.id, d.name, d.type, d.master, d.notified_serial, d.account,
                (SELECT SUBSTRING_INDEX(SUBSTRING_INDEX(s.content, ' ', 3), ' ', -1)
                   FROM records s WHERE s.domain_id = d.id AND s.type = 'SOA' LIMIT 1) AS soa_serial
           FROM domains d WHERE d.id = ? LIMIT 1")
        or return undef;
    $sth->execute($domain_id) or return undef;
    my $row = $sth->fetchrow_hashref;
    $sth->finish;
    return $row;
}

sub pdns_count_records {
    my ($domain_id) = @_;
    my $dbh = connectPDNS() or return 0;
    my $sth = $dbh->prepare("SELECT COUNT(*) FROM records WHERE domain_id = ? AND type IS NOT NULL AND type <> '' AND type NOT IN ('RRSIG','NSEC','NSEC3','NSEC3PARAM','DNSKEY','CDS','CDNSKEY','TYPE65534')") or return 0;
    $sth->execute($domain_id) or return 0;
    my ($n) = $sth->fetchrow_array;
    $sth->finish;
    return $n || 0;
}

# Zone records (all records if domain_id is not given).
# DNSSEC signature data (what a signed zone carries or what PowerDNS makes itself) is not a record anyone
# edits: it is left out of listings and counts. The keys are in the zone's DNSSEC window.
sub pdns_list_records {
    my ($domain_id) = @_;
    my $dbh = connectPDNS() or return [];
    my ($sql, @bind);
    if ($domain_id) {
        $sql = "SELECT id, domain_id, name, type, content, ttl, prio, disabled, updated_by, updated_at
                  FROM records WHERE domain_id = ? AND type IS NOT NULL AND type <> ''
                       AND type NOT IN ('RRSIG','NSEC','NSEC3','NSEC3PARAM','DNSKEY','CDS','CDNSKEY','TYPE65534') ORDER BY name ASC, type ASC";
        @bind = ($domain_id);
    } else {
        $sql = "SELECT id, domain_id, name, type, content, ttl, prio, disabled, updated_by, updated_at
                  FROM records ORDER BY name ASC, type ASC LIMIT 500";
    }
    my $sth = $dbh->prepare($sql) or return [];
    $sth->execute(@bind) or return [];
    return $sth->fetchall_arrayref({}) || [];
}

sub pdns_get_soa {
    my ($domain_id) = @_;
    my $dbh = connectPDNS() or return undef;
    my $sth = $dbh->prepare("SELECT id, name, content, ttl, updated_by, updated_at FROM records WHERE domain_id = ? AND type = 'SOA' LIMIT 1")
        or return undef;
    $sth->execute($domain_id) or return undef;
    my $row = $sth->fetchrow_hashref;
    $sth->finish;
    return $row;
}

# SOA as parsed fields; undef if there is no SOA.
sub pdns_soa_fields {
    my ($domain_id) = @_;
    my $soa = pdns_get_soa($domain_id) or return undef;
    my @p = split /\s+/, ($soa->{content} // '');
    return undef unless @p >= 7;
    return {
        id => $soa->{id},
        primary_ns => $p[0], hostmaster => $p[1], serial => $p[2] + 0,
        refresh => $p[3] + 0, retry => $p[4] + 0, expire => $p[5] + 0, minimum => $p[6] + 0,
        ttl => (defined $soa->{ttl} ? $soa->{ttl} + 0 : 0),
        updated_by => $soa->{updated_by}, updated_at => $soa->{updated_at},
    };
}

# SOA update is a dedicated path (SOA is blocked in generic _canonicalize_ops); transaction + FOR UPDATE.
# $f: {primary_ns,hostmaster,serial?,refresh,retry,expire,minimum,ttl}; empty/auto serial -> increment.
# Returns (1,\%after) | (undef,err). Purge/notify are done by the API layer.
sub pdns_update_soa {
    my ($domain_id, $f, $actor) = @_;
    return (undef, 'domain_id required') unless $domain_id;
    if (my $we = pdns_zone_write_error($domain_id)) { return (undef, $we); }
    $f ||= {};
    for my $k (qw(refresh retry expire minimum ttl)) {
        return (undef, "$k must be a number")
            if defined $f->{$k} && $f->{$k} ne '' && $f->{$k} !~ /^\d+$/;
    }
    return (undef, 'primary_ns is required')
        if exists $f->{primary_ns} && (!defined $f->{primary_ns} || $f->{primary_ns} eq '');
    return (undef, 'serial must be a number')
        if defined $f->{serial} && $f->{serial} ne '' && $f->{serial} !~ /^\d+$/;

    my $dbh = connectPDNS() or return (undef, 'DB unavailable');
    my $after;
    my $ok = eval {
        $dbh->begin_work;
        if (my $we = _lock_zones_writable($dbh, $domain_id)) { die "$we\n"; }
        my $soa = _lock_soa($dbh, $domain_id) or die "no SOA in zone\n";   # {id, content}
        my @p = split /\s+/, ($soa->{content} // '');
        die "bad SOA content\n" unless @p >= 7;
        my %n = (primary_ns => $p[0], hostmaster => $p[1], serial => $p[2],
                 refresh => $p[3], retry => $p[4], expire => $p[5], minimum => $p[6]);
        for my $k (qw(primary_ns hostmaster refresh retry expire minimum)) {
            $n{$k} = $f->{$k} if defined $f->{$k} && $f->{$k} ne '';
        }
        $n{serial} = (defined $f->{serial} && $f->{serial} =~ /^\d+$/)
                   ? $f->{serial} + 0 : ($p[2] || 0) + 1;    # explicit serial or bump
        my $content = join(' ', @n{qw(primary_ns hostmaster serial refresh retry expire minimum)});
        if (defined $f->{ttl} && $f->{ttl} =~ /^\d+$/) {
            $dbh->do("UPDATE records SET content=?, ttl=?, updated_by=?, updated_at=NOW(6) WHERE id=?",
                     undef, $content, $f->{ttl}, $actor, $soa->{id}) or die "update failed";
        } else {
            $dbh->do("UPDATE records SET content=?, updated_by=?, updated_at=NOW(6) WHERE id=?",
                     undef, $content, $actor, $soa->{id}) or die "update failed";
        }
        $dbh->commit or die "commit failed\n";
        $after = { %n };
        1;
    };
    if (!$ok) { my $e = $@ || 'error'; chomp $e; eval { $dbh->rollback }; return (undef, $e); }
    return (1, $after);
}

# Apex NS records for per-row CRUD (each NS is its own records row with its own updated_by/updated_at).
sub pdns_apex_ns_list {
    my ($domain_id, $zone_name) = @_;
    return [] unless $domain_id && defined $zone_name && length $zone_name;
    my $dbh = connectPDNS() or return [];
    return $dbh->selectall_arrayref(
        "SELECT id, content, ttl, updated_by, updated_at FROM records
          WHERE domain_id = ? AND type = 'NS' AND name = ? ORDER BY content",
        { Slice => {} }, $domain_id, $zone_name) || [];
}

# Per-row apex NS edit (add|update|delete) on pdns.records as they are, without rebuilding the RRset.
# TTL belongs to the whole RRset (changes all NS at once). Transaction, SOA lock, one serial bump.
# $op: { action, content?, ttl?, record_id?, actor }.
# Returns (1, \%info) | (undef, err); %info: { action, before, after, ttl } for audit.
sub pdns_apex_ns_mutate {
    my ($domain_id, $zone_name, $op) = @_;
    return (undef, 'domain_id required') unless $domain_id;
    if (my $we = pdns_zone_write_error($domain_id)) { return (undef, $we); }
    my $act = $op->{action} || '';
    my $dbh = connectPDNS() or return (undef, 'DB unavailable');
    my $info;
    my $ok = eval {
        $dbh->begin_work;
        if (my $we = _lock_zones_writable($dbh, $domain_id)) { die "$we\n"; }
        my $soa = _lock_soa($dbh, $domain_id) or die "no SOA in zone\n";
        my $rows = $dbh->selectall_arrayref(
            "SELECT id, content, ttl FROM records WHERE domain_id=? AND type='NS' AND name=? FOR UPDATE",
            { Slice => {} }, $domain_id, $zone_name) || [];
        my $cur_ttl = @$rows ? $rows->[0]{ttl} : 3600;
        my $want_ttl = (defined $op->{ttl} && $op->{ttl} =~ /^\d+$/) ? $op->{ttl} + 0 : undef;

        if ($act eq 'add') {
            die "content required\n" unless defined $op->{content} && length $op->{content};
            die "name server already exists\n" if grep { lc($_->{content}) eq lc($op->{content}) } @$rows;
            my $ttl = defined($want_ttl) ? $want_ttl : $cur_ttl;
            if (@$rows && defined($want_ttl) && $want_ttl != $cur_ttl) {
                $dbh->do("UPDATE records SET ttl=?, updated_by=?, updated_at=NOW(6) WHERE domain_id=? AND type='NS' AND name=?",
                         undef, $ttl, $op->{actor}, $domain_id, $zone_name) or die "ttl update failed\n";
            }
            $dbh->do("INSERT INTO records (domain_id,name,type,content,ttl,disabled,updated_by,updated_at)
                      VALUES (?,?,'NS',?,?,0,?,NOW(6))",
                     undef, $domain_id, $zone_name, $op->{content}, $ttl, $op->{actor}) or die "insert failed\n";
            $info = { action => 'add', before => undef, after => $op->{content}, ttl => $ttl };
        } elsif ($act eq 'update') {
            my ($row) = grep { $_->{id} == $op->{record_id} } @$rows;
            die "name server not found\n" unless $row;
            my $new = (defined $op->{content} && length $op->{content}) ? $op->{content} : $row->{content};
            die "name server already exists\n"
                if lc($new) ne lc($row->{content}) && grep { lc($_->{content}) eq lc($new) } @$rows;
            if (defined($want_ttl) && $want_ttl != $cur_ttl) {   # TTL applies to the whole RRset
                $dbh->do("UPDATE records SET ttl=?, updated_by=?, updated_at=NOW(6) WHERE domain_id=? AND type='NS' AND name=?",
                         undef, $want_ttl, $op->{actor}, $domain_id, $zone_name) or die "ttl update failed\n";
            }
            $dbh->do("UPDATE records SET content=?, updated_by=?, updated_at=NOW(6) WHERE id=?",
                     undef, $new, $op->{actor}, $row->{id}) or die "update failed\n";
            $info = { action => 'update', before => $row->{content}, after => $new,
                      ttl => (defined($want_ttl) ? $want_ttl : $cur_ttl) };
        } elsif ($act eq 'delete') {
            my ($row) = grep { $_->{id} == $op->{record_id} } @$rows;
            die "name server not found\n" unless $row;
            # Same guard as the other paths: "@$rows <= 1" also counted disabled records.
            if (my $g = _apex_ns_guard($dbh, $domain_id, [ $row->{id} ])) { die "$g\n"; }
            $dbh->do("DELETE FROM records WHERE id=?", undef, $row->{id}) or die "delete failed\n";
            $info = { action => 'delete', before => $row->{content}, after => undef, ttl => $cur_ttl };
        } else {
            die "unknown action\n";
        }
        $info->{serial} = _bump_soa_row($dbh, $soa) or die "soa bump failed\n";
        $dbh->commit or die "commit failed\n"; 1;
    };
    if (!$ok) { my $e = $@ || 'error'; chomp $e; eval { $dbh->rollback }; return (undef, $e); }
    return (1, $info);
}

# Per-row edit of a regular record (add|update|delete): one record = one UI row, each with its own
# updated_by/updated_at. RRset integrity is enforced here:
#   - CNAME does not coexist with other types on a name (checked on the final state);
#   - one TTL per (name,type): a TTL change applies to the whole RRset;
#   - duplicate values within (name,type) are rejected;
#   - one SOA bump; SOA itself is edited via its own path.
# $op: { action, name, type, content?, ttl?, prio?, disabled?, record_id?, actor }.
# Returns (1, \%info) | (undef, err); %info: {action,name,type,before,after,ttl,before_dis,after_dis}.
# ZONE INTEGRITY: at least one WORKING apex NS must remain. One rule, one place - otherwise another path
# bypasses it.
# The guard reads the rows itself, by id: when callers passed rows in, the NS delete path selected only
# (id, content, ttl), the guard saw no type/name/disabled and silently allowed deleting the last NS.
# Only live NS count (disabled=0): a disabled NS serves nobody, so removing it takes nothing away.
sub _apex_ns_zone_name {
    my ($dbh, $domain_id) = @_;
    my ($n) = $dbh->selectrow_array("SELECT name FROM domains WHERE id=?", undef, $domain_id);
    return $n;
}
sub _apex_ns_live {
    my ($dbh, $domain_id, $zone_name) = @_;
    my ($n) = $dbh->selectrow_array(
        "SELECT COUNT(*) FROM records WHERE domain_id=? AND type='NS' AND name=? AND disabled=0",
        undef, $domain_id, $zone_name);
    return $n // 0;
}
# $ids: records the operation removes or disables. Returns undef | 'reason'.
sub _apex_ns_guard {
    my ($dbh, $domain_id, $ids) = @_;
    my @ids = grep { defined && /^\d+$/ } @{ $ids || [] };
    return undef unless @ids;
    my $zone_name = _apex_ns_zone_name($dbh, $domain_id) // return undef;
    my $ph = join(',', ('?') x @ids);
    my ($losing) = $dbh->selectrow_array(
        "SELECT COUNT(*) FROM records
          WHERE domain_id=? AND id IN ($ph) AND type='NS' AND name=? AND disabled=0",
        undef, $domain_id, @ids, $zone_name);
    return undef unless $losing;
    return 'cannot delete the last name server'
        if _apex_ns_live($dbh, $domain_id, $zone_name) - $losing < 1;
    return undef;
}
# Same question for the RRset path: it replaces the whole set, so the FINAL set is what counts.
# Previously this path (API and MCP) skipped the rule and could remove all NS at once.
sub _apex_ns_guard_rrsets {
    my ($dbh, $domain_id, $canon) = @_;
    my $zone_name = _apex_ns_zone_name($dbh, $domain_id) // return undef;
    my $apex = lc($zone_name); $apex =~ s/\.$//;
    my $touches = 0; my $after = 0;
    for my $op (@{ $canon || [] }) {
        next unless uc($op->{type} // '') eq 'NS';
        my $n = lc($op->{name} // ''); $n =~ s/\.$//;
        next unless $n eq $apex;
        $touches = 1;
        next if uc($op->{changetype} // 'REPLACE') eq 'DELETE';
        $after += scalar grep { !$_->{disabled} } @{ $op->{records} || [] };
    }
    return undef unless $touches;
    return 'cannot delete the last name server' if $after < 1;
    return undef;
}
sub pdns_record_mutate {
    my ($domain_id, $op) = @_;
    return (undef, 'domain_id required') unless $domain_id;
    if (my $we = pdns_zone_write_error($domain_id)) { return (undef, $we); }
    my $act = $op->{action} || '';
    my $dbh = connectPDNS() or return (undef, 'DB unavailable');
    my $info;
    my $ok = eval {
        $dbh->begin_work;
        if (my $we = _lock_zones_writable($dbh, $domain_id)) { die "$we\n"; }
        my $soa = _lock_soa($dbh, $domain_id) or die "no SOA in zone\n";

        if ($act eq 'add') {
            my $type = uc($op->{type} // '');
            die "name and type are required\n" unless defined $op->{name} && length $op->{name} && $type;
            # Same normalizer as the batch path, so the name is stored identically.
            my ($name, $nerr) = dns_record_name_norm($op->{name});
            die "$nerr\n" if $nerr;
            die "SOA is managed separately\n" if $type eq 'SOA';
            if ($type eq 'CAA') { my $c = canonicalize_caa($op->{content}); $op->{content} = $c if defined $c; }
            my $at = $dbh->selectall_arrayref(
                "SELECT type, content, ttl FROM records WHERE domain_id=? AND name=? FOR UPDATE",
                { Slice => {} }, $domain_id, $name) || [];
            die "CNAME cannot coexist with other records at $name\n" if $type eq 'CNAME' && @$at;
            die "cannot add $type: a CNAME exists at $name\n" if $type ne 'CNAME' && grep { uc($_->{type}) eq 'CNAME' } @$at;
            my @same = grep { uc($_->{type}) eq $type } @$at;
            die "value already exists\n" if grep { lc($_->{content}) eq lc($op->{content}) } @same;
            my $ex_ttl = @same ? $same[0]{ttl} : undef;
            my $want   = (defined $op->{ttl} && $op->{ttl} =~ /^\d+$/) ? $op->{ttl} + 0 : undef;
            my $ttl    = defined($want) ? $want : (defined($ex_ttl) ? $ex_ttl : 3600);
            if (defined($ex_ttl) && defined($want) && $want != $ex_ttl) {        # TTL applies to the whole RRset
                $dbh->do("UPDATE records SET ttl=?, updated_by=?, updated_at=NOW(6) WHERE domain_id=? AND name=? AND type=?",
                         undef, $ttl, $op->{actor}, $domain_id, $name, $type) or die "ttl update failed\n";
            }
            my $prio = (defined $op->{prio} && $op->{prio} =~ /^\d+$/) ? $op->{prio} + 0 : undef;
            if (my $e = dns_validate($type, $name, $ttl, $op->{content}, $prio)) { die "$e\n"; }
            $dbh->do("INSERT INTO records (domain_id,name,type,content,ttl,prio,disabled,updated_by,updated_at)
                      VALUES (?,?,?,?,?,?,?,?,NOW(6))",
                     undef, $domain_id, $name, $type, $op->{content}, $ttl, $prio, ($op->{disabled} ? 1 : 0), $op->{actor})
                or die "insert failed\n";
            $info = { action => 'add', name => $name, type => $type, before => undef, after => $op->{content},
                      ttl => $ttl, after_dis => ($op->{disabled} ? 1 : 0) };
        } elsif ($act eq 'update') {
            my $row = $dbh->selectrow_hashref(
                "SELECT id,name,type,content,ttl,prio,disabled FROM records WHERE id=? AND domain_id=? FOR UPDATE",
                undef, $op->{record_id}, $domain_id);
            die "record not found\n" unless $row;
            die "SOA is managed separately\n" if uc($row->{type}) eq 'SOA';
            my $newc = (defined $op->{content} && length $op->{content}) ? $op->{content} : $row->{content};
            if (uc($row->{type}) eq 'CAA') { my $c = canonicalize_caa($newc); $newc = $c if defined $c; }
            if (lc($newc) ne lc($row->{content})) {
                my ($dup) = $dbh->selectrow_array(
                    "SELECT COUNT(*) FROM records WHERE domain_id=? AND name=? AND type=? AND LOWER(content)=LOWER(?) AND id<>?",
                    undef, $domain_id, $row->{name}, $row->{type}, $newc, $row->{id});
                die "value already exists\n" if $dup;
            }
            my $want = (defined $op->{ttl} && $op->{ttl} =~ /^\d+$/) ? $op->{ttl} + 0 : undef;
            if (defined($want) && $want != $row->{ttl}) {                        # TTL applies to the whole RRset
                $dbh->do("UPDATE records SET ttl=?, updated_by=?, updated_at=NOW(6) WHERE domain_id=? AND name=? AND type=?",
                         undef, $want, $op->{actor}, $domain_id, $row->{name}, $row->{type}) or die "ttl update failed\n";
            }
            my $prio = (defined $op->{prio} && $op->{prio} =~ /^\d+$/) ? $op->{prio} + 0 : $row->{prio};
            my $dis  = (defined $op->{disabled}) ? ($op->{disabled} ? 1 : 0) : ($row->{disabled} ? 1 : 0);
            my $eff_ttl = defined($want) ? $want : $row->{ttl};
            if (my $e = dns_validate(uc($row->{type}), $row->{name}, $eff_ttl, $newc, $prio)) { die "$e\n"; }
            # Disabling an apex NS takes it out of service just like deleting it.
            if ($dis && !$row->{disabled}) { if (my $g = _apex_ns_guard($dbh, $domain_id, [ $row->{id} ])) { die "$g\n"; } }
            $dbh->do("UPDATE records SET content=?, prio=?, disabled=?, updated_by=?, updated_at=NOW(6) WHERE id=?",
                     undef, $newc, $prio, $dis, $op->{actor}, $row->{id}) or die "update failed\n";
            $info = { action => 'update', name => $row->{name}, type => $row->{type},
                      before => $row->{content}, after => $newc, ttl => (defined($want) ? $want : $row->{ttl}),
                      before_dis => ($row->{disabled} ? 1 : 0), after_dis => $dis };
        } elsif ($act eq 'delete') {
            my $row = $dbh->selectrow_hashref(
                "SELECT id,name,type,content,ttl FROM records WHERE id=? AND domain_id=?",
                undef, $op->{record_id}, $domain_id);
            die "record not found\n" unless $row;
            die "SOA is managed separately\n" if uc($row->{type}) eq 'SOA';
            if (my $g = _apex_ns_guard($dbh, $domain_id, [ $row->{id} ])) { die "$g\n"; }
            $dbh->do("DELETE FROM records WHERE id=?", undef, $row->{id}) or die "delete failed\n";
            $info = { action => 'delete', name => $row->{name}, type => $row->{type},
                      before => $row->{content}, after => undef, ttl => $row->{ttl} };
        } else {
            die "unknown action\n";
        }
        $info->{serial} = _bump_soa_row($dbh, $soa) or die "soa bump failed\n";
        $dbh->commit or die "commit failed\n"; 1;
    };
    if (!$ok) { my $e = $@ || 'error'; chomp $e; eval { $dbh->rollback }; return (undef, $e); }
    return (1, $info);
}

# Batch enable|disable|delete of zone records: ONE transaction, one SOA bump; SOA is never touched.
# Returns (\%res, undef) | (undef, err); %res: { action, records => [{id,name,type,content,before_dis}] }
# for per-record audit.
sub pdns_records_batch {
    my ($domain_id, $ids, $action, $actor) = @_;
    return (undef, 'domain_id required') unless $domain_id;
    if (my $we = pdns_zone_write_error($domain_id)) { return (undef, $we); }
    return (undef, 'no records selected') unless ref($ids) eq 'ARRAY' && @$ids;
    my %valid = (enable => 1, disable => 1, delete => 1);
    return (undef, "invalid action '$action'") unless $valid{ $action || '' };
    my @nids = grep { defined && /^\d+$/ } @$ids;
    return (undef, 'no valid record ids') unless @nids;

    my $dbh = connectPDNS() or return (undef, 'DB unavailable');
    my $res;
    my $ok = eval {
        $dbh->begin_work;
        if (my $we = _lock_zones_writable($dbh, $domain_id)) { die "$we\n"; }
        my $soa = _lock_soa($dbh, $domain_id) or die "no SOA in zone\n";
        my $ph = join(',', ('?') x @nids);
        my $rows = $dbh->selectall_arrayref(
            "SELECT id, name, type, content, disabled FROM records WHERE domain_id=? AND id IN ($ph) FOR UPDATE",
            { Slice => {} }, $domain_id, @nids) || [];
        my @touch = grep { uc($_->{type}) ne 'SOA' } @$rows;   # SOA only via its dedicated path
        die "nothing to change\n" unless @touch;

        # Zone integrity is enforced here too: otherwise a bulk operation silently deleted the last apex NS
        # that the NS path protects.
        if ($action eq 'delete' || $action eq 'disable') {
            if (my $g = _apex_ns_guard($dbh, $domain_id, [ map { $_->{id} } @touch ])) { die "$g\n"; }
        }

        for my $r (@touch) {
            if ($action eq 'delete') {
                $dbh->do("DELETE FROM records WHERE id=?", undef, $r->{id}) or die "delete failed\n";
            } else {
                my $dis = ($action eq 'disable') ? 1 : 0;
                $dbh->do("UPDATE records SET disabled=?, updated_by=?, updated_at=NOW(6) WHERE id=?",
                         undef, $dis, $actor, $r->{id}) or die "update failed\n";
            }
        }
        my $serial = _bump_soa_row($dbh, $soa) or die "soa bump failed\n";
        $res = { action => $action, serial => $serial, records => [ map { {
            id => $_->{id}, name => $_->{name}, type => $_->{type},
            content => $_->{content}, before_dis => ($_->{disabled} ? 1 : 0),
        } } @touch ] };
        $dbh->commit or die "commit failed\n"; 1;
    };
    if (!$ok) { my $e = $@ || 'error'; chomp $e; eval { $dbh->rollback }; return (undef, $e); }
    return ($res, undef);
}

# ---------------------------------------------------------------------------
# R3: atomic A + PTR
# ---------------------------------------------------------------------------

# PURE: is the string a valid IPv4/IPv6 address? (SLAVE masters etc.)
sub is_ip_addr {
    my ($s) = @_;
    return 0 unless defined $s && length $s;
    return (eval { inet_pton(AF_INET, $s) } || eval { inet_pton(AF_INET6, $s) }) ? 1 : 0;
}

# PURE: canonical A/AAAA address via inet_pton->inet_ntop (so 2001:db8::5 and 2001:0db8:0:0:0:0:0:5 are
# one address); returns the input unchanged if not A/AAAA or invalid.
sub canonicalize_ip {
    my ($type, $ip) = @_;
    return $ip unless defined $ip;
    $type = uc($type || '');
    if ($type eq 'AAAA') { my $p = eval { inet_pton(AF_INET6, $ip) }; return $p ? inet_ntop(AF_INET6, $p) : $ip; }
    if ($type eq 'A')    { my $p = eval { inet_pton(AF_INET,  $ip) }; return $p ? inet_ntop(AF_INET,  $p) : $ip; }
    return $ip;
}

# PURE: CAA canonicalization. PowerDNS/gmysql requires the value in double quotes: flags tag "value"
# (otherwise SERVFAIL for the WHOLE zone on serving - a real bug on itos-app.corp). Accepts quoted or bare
# value; returns the canonical form, or undef if unparsable or flags outside 0..255. Inner quotes -> \".
sub canonicalize_caa {
    my ($content) = @_;
    return undef unless defined $content;
    return undef unless $content =~ /^\s*(\d{1,3})\s+([A-Za-z0-9]+)\s+(.*\S)\s*$/;
    my ($flags, $tag, $val) = ($1, lc($2), $3);
    return undef if $flags > 255;
    if ($val =~ /^"(.*)"$/s) { $val = $1; }         # strip existing outer quotes
    $val =~ s/\\"/"/g;                               # unescape, then escape again: idempotent
    $val =~ s/"/\\"/g;
    return sprintf('%d %s "%s"', $flags, $tag, $val);
}

# PURE: owner (PTR name) + reverse zone candidates (longest-first) for IPv4/IPv6; () if invalid.
# IPv4 -> in-addr.arpa (/24,/16,/8). IPv6 -> ip6.arpa on every nibble boundary /124../4, not just /64,/48,/32.
sub reverse_candidates_for_ip {
    my ($ip) = @_;
    return () unless defined $ip && length $ip;
    if ($ip =~ /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/) {
        my @o = ($1, $2, $3, $4);
        return () if grep { $_ > 255 } @o;
        my $owner = "$o[3].$o[2].$o[1].$o[0].in-addr.arpa";
        return ($owner, ["$o[2].$o[1].$o[0].in-addr.arpa", "$o[1].$o[0].in-addr.arpa", "$o[0].in-addr.arpa"]);
    }
    if ($ip =~ /:/) {
        my $packed = eval { inet_pton(AF_INET6, $ip) };
        return () unless $packed;
        my @nib = split //, unpack('H*', $packed);          # 32 hex nibbles
        my $owner = join('.', reverse @nib) . '.ip6.arpa';
        my @cands;                                           # k network nibbles, longest-first (k=31..1)
        for (my $k = 31; $k >= 1; $k--) { push @cands, join('.', reverse @nib[0 .. $k - 1]) . '.ip6.arpa'; }
        return ($owner, \@cands);
    }
    return ();
}

# Most specific LOCAL reverse zone for an IP (longest match), one IN query.
# Returns ($rev, $error): $rev = { domain_id, zone_name, type, owner } | undef. $error is set ONLY on a DB
# error (fail-closed: "read failed" != "no local zone"). type may be SLAVE/NATIVE: writability
# (MASTER/NATIVE + access) is the caller's decision.
sub reverse_master_for_ip {
    my ($ip) = @_;
    my ($owner, $cands) = reverse_candidates_for_ip($ip);
    return (undef, undef) unless $owner && @$cands;
    my $dbh = connectPDNS() or return (undef, 'DB unavailable');
    my $ph = join(',', ('?') x @$cands);
    my $rows = $dbh->selectall_arrayref("SELECT id, name, type FROM domains WHERE name IN ($ph)",
                                        { Slice => {} }, @$cands);
    return (undef, 'domains lookup failed') unless defined $rows;   # error != "no zone"
    my %by = map { $_->{name} => $_ } @$rows;
    for my $z (@$cands) {                                    # cands are already longest-first
        my $r = $by{$z} or next;
        return ({ domain_id => $r->{id}, zone_name => $r->{name}, type => uc($r->{type} || ''), owner => $owner }, undef);
    }
    return (undef, undef);                                   # no local zone
}

# PURE: classify existing PTRs (\@ {content,disabled}) against target:
# 'free' | 'exists_active' (all active == target) | 'multiple' (target present alongside others)
# | 'conflict' (active ones exist, target not among them) | 'disabled' (all records disabled).
# 'multiple' is separate from 'conflict' so a just-created correct PTR is not shown as "points elsewhere";
# neither allows automatic PTR creation or deletes anything.
sub classify_ptr {
    my ($rows, $target) = @_;
    return 'free' unless $rows && @$rows;
    my $norm = sub { my $s = lc($_[0] // ''); $s =~ s/\.$//; return $s; };
    my $t = $norm->($target);
    my @active = map { $norm->($_->{content}) } grep { !$_->{disabled} } @$rows;
    return 'disabled' unless @active;                       # only disabled
    return 'exists_active' unless grep { $_ ne $t } @active;
    return (grep { $_ eq $t } @active) ? 'multiple' : 'conflict';
}


# PURE: classify_ptr -> R4 UI status.
#   exists_active → ok | free → missing | multiple → multiple | conflict → different
#   | disabled → disabled | else → error.
sub ptr_ui_status {
    my ($c) = @_;
    return 'ok'        if $c eq 'exists_active';
    return 'missing'   if $c eq 'free';
    return 'multiple'  if $c eq 'multiple';
    return 'different' if $c eq 'conflict';
    return 'disabled'  if $c eq 'disabled';
    return 'error';
}

# Batch PTR statuses for ALL A/AAAA of a forward zone (R4), exactly 3 PDNS queries:
#   1) the zone's A/AAAA; 2) candidate reverse zones in one SELECT; 3) PTRs of matched (domain_id, owner).
# Access comes from the already built $ctx (build_access_context, once per HTTP request) via access_for,
# with no extra panel DB queries. Reverse zone without access (or not local) -> 'external' (zone/PTR names
# are not disclosed). FAIL-CLOSED on EVERY SELECT: undef (error) != [] (empty); an error yields 'error',
# never a false 'external'/'missing'. Returns { rows => [ { id,name,type,content,status,ptr? } ], error? }.
sub zone_ptr_statuses {
    my ($ctx, $fwd_id) = @_;
    my $dbh = connectPDNS() or return { error => 'DB unavailable', rows => [] };
    my $recs = $dbh->selectall_arrayref(
        "SELECT id, name, type, content FROM records
          WHERE domain_id=? AND type IN ('A','AAAA')",
        { Slice => {} }, $fwd_id);
    return { error => 'query failed', rows => [] } unless defined $recs;
    return { rows => [] } unless @$recs;

    # 1) canonical IP + owner + candidates; collect distinct reverse zone names.
    my %zone_want;
    for my $r (@$recs) {
        my $ip = canonicalize_ip($r->{type}, $r->{content});
        my ($owner, $cands) = reverse_candidates_for_ip($ip);
        $r->{_owner} = $owner;
        $r->{_cands} = $cands || [];
        if ($cands) { $zone_want{$_} = 1 for @$cands; }
    }

    # 2) existing candidate zones in one query; undef -> fail-closed (every status 'error').
    my %zinfo; my $zone_err = 0;                            # name => { id, name, type }
    my @names = keys %zone_want;
    if (@names) {
        my $ph = join(',', ('?') x @names);
        my $zr = $dbh->selectall_arrayref(
            "SELECT d.id, d.name, d.type FROM domains d WHERE d.name IN ($ph)", { Slice => {} }, @names);
        if (defined $zr) { $zinfo{ $_->{name} } = $_ for @$zr; }
        else             { $zone_err = 1; }
    }
    # longest match: _cands are already longest-first.
    for my $r (@$recs) {
        for my $zn (@{ $r->{_cands} }) { if (my $z = $zinfo{$zn}) { $r->{_zone} = $z; last; } }
    }

    # access to matched reverse zones from the prebuilt context, no DB queries.
    my %rev_access;
    for my $r (@$recs) {
        next unless $r->{_zone};
        my $zid = $r->{_zone}{id};
        $rev_access{$zid} //= access_for($ctx, $zid);
    }

    # 3) PTRs for (domain_id, owner) of accessible zones in one query; undef -> fail-closed ('error').
    my (@pairs, %pair_seen); my %ptr_by; my $ptr_err = 0;   # "zid\0owner" => [ {content,disabled} ]
    for my $r (@$recs) {
        next unless $r->{_zone} && $r->{_owner};
        my $zid = $r->{_zone}{id};
        next if ($rev_access{$zid} || 'none') eq 'none';
        my $key = "$zid\0$r->{_owner}";
        next if $pair_seen{$key}++;
        push @pairs, [ $zid, $r->{_owner} ];
    }
    if (@pairs) {
        my $ph   = join(',', ('(?,?)') x @pairs);
        my @bind = map { @$_ } @pairs;
        my $pr = $dbh->selectall_arrayref(
            "SELECT domain_id, name, content, disabled FROM records
              WHERE type='PTR' AND (domain_id,name) IN ($ph)", { Slice => {} }, @bind);
        if (defined $pr) { for my $row (@$pr) { push @{ $ptr_by{"$row->{domain_id}\0$row->{name}"} }, $row; } }
        else             { $ptr_err = 1; }
    }

    # 4) per-row status (SELECT errors -> 'error', never a false normal status).
    my @out;
    for my $r (@$recs) {
        my ($status, $ptr);
        if    (!$r->{_owner}) { $status = 'error'; }        # IP did not parse (should not happen for a valid A)
        elsif ($zone_err)     { $status = 'error'; }        # zone list could not be read
        elsif (!$r->{_zone})  { $status = 'external'; }     # no local reverse zone
        elsif (($rev_access{ $r->{_zone}{id} } || 'none') eq 'none') { $status = 'external'; }
        elsif ($ptr_err)      { $status = 'error'; }        # PTRs could not be read
        else {
            my $rows = $ptr_by{ "$r->{_zone}{id}\0$r->{_owner}" } || [];
            $status = ptr_ui_status(classify_ptr($rows, $r->{name}));
            $ptr = [ map { $_->{content} } grep { !$_->{disabled} } @$rows ] if @$rows;
        }
        # reverse_zone_id + owner only when the reverse zone is local and accessible (deep link / "+");
        # not disclosed for external/error (R3 policy: none = external). writable (MASTER/NATIVE + write access)
        # drives "Missing +" and the PTR delete checkbox; read-only users get links only, never a false 403.
        my $linkable = ($status ne 'external' && $status ne 'error' && $r->{_zone}) ? 1 : 0;
        my $writable = ($linkable
                        && ($rev_access{ $r->{_zone}{id} } || '') eq 'write'
                        && (uc($r->{_zone}{type} || '') eq 'MASTER' || uc($r->{_zone}{type} || '') eq 'NATIVE')) ? 1 : 0;
        push @out, { id => $r->{id}, name => $r->{name}, type => $r->{type},
                     content => $r->{content}, status => $status,
                     (defined $ptr ? (ptr => $ptr) : ()),
                     ($linkable ? (reverse_zone_id => $r->{_zone}{id}, owner => $r->{_owner},
                                   writable => ($writable ? JSON::true : JSON::false)) : ()) };
    }
    return { rows => \@out };
}

# Atomically (one transaction, two zones) create an address record (A/AAAA) and its PTR. The PTR decision
# is made INSIDE the transaction UNDER LOCK (SELECT ... FOR UPDATE), so preflight->insert cannot race.
# $p: { fwd_id, fwd_name, a_type(A|AAAA), ip, ttl, prio?, rev_id?, owner?, target?, ptr_mode, actor }.
# Type/mode/zone validation lives in the core. Returns (\%out, undef) | (undef, err).
# %out: { blocked=>1, reason=>'conflict', status, existing=>[...] } (nothing created) OR
#       { a=>'created', ptr=>'created'|'replaced'|'exists'|'skipped', status, replaced=>[], eff_ttl }.
sub pdns_create_address_ptr {
    my ($p) = @_;
    my $type = uc($p->{a_type} || '');
    return (undef, 'type must be A or AAAA') unless $type eq 'A' || $type eq 'AAAA';
    my $mode = $p->{ptr_mode} || 'auto';
    return (undef, "invalid ptr_mode '$mode'") unless $mode =~ /^(auto|a_only|replace)$/;
    return (undef, 'fwd_id required') unless $p->{fwd_id};
    return (undef, 'forward and reverse zones must differ') if $p->{rev_id} && $p->{rev_id} == $p->{fwd_id};
    if (my $we = pdns_zone_write_error($p->{fwd_id})) { return (undef, $we); }
    if ($p->{rev_id} && (my $wr = pdns_zone_write_error($p->{rev_id}))) { return (undef, "reverse $wr"); }
    my $ttl  = (defined $p->{ttl} && $p->{ttl} =~ /^\d+$/) ? $p->{ttl} + 0 : 3600;
    my $ip   = canonicalize_ip($type, $p->{ip});           # 2001:db8::5 == 2001:0db8:0:0:0:0:0:5
    my $has_rev = ($p->{rev_id} && defined $p->{owner} && defined $p->{target}) ? 1 : 0;
    my $use_rev = ($has_rev && $mode ne 'a_only') ? 1 : 0;
    my $prio = (defined $p->{prio} && $p->{prio} =~ /^\d+$/) ? $p->{prio} + 0 : undef;
    my $dbh = connectPDNS() or return (undef, 'DB unavailable');
    my $out;
    my $ok = eval {
        $dbh->begin_work;
        # 1) lock zone SOAs FOR UPDATE in domain_id order (deterministic, no deadlocks); fwd != rev (checked above).
        my @ids = ($p->{fwd_id}); push @ids, $p->{rev_id} if $use_rev;
        if (my $we = _lock_zones_writable($dbh, @ids)) { die "$we\n"; }
        my %soa;
        for my $did (sort { $a <=> $b } @ids) { $soa{$did} = _lock_soa($dbh, $did) or die "no SOA in zone $did\n"; }

        # 2) PTR decision UNDER the reverse zone lock (state re-checked).
        my $ptr_action = 'none'; my $status = 'n/a';
        if ($use_rev) {
            my $rows = $dbh->selectall_arrayref(
                "SELECT content, disabled FROM records WHERE domain_id=? AND type='PTR' AND name=? FOR UPDATE",
                { Slice => {} }, $p->{rev_id}, $p->{owner}) || [];
            $status = classify_ptr($rows, $p->{target});
            if    ($status eq 'free')         { $ptr_action = 'create'; }
            elsif ($status eq 'exists_active'){ $ptr_action = 'none'; }
            else {   # conflict | multiple | disabled: manual only, nothing is removed automatically
                if ($mode eq 'replace') { $ptr_action = 'replace'; }
                else {   # auto -> block, create NOTHING
                    $dbh->rollback;
                    # Report the REAL reason: "the right one exists, but not alone" reads differently from
                    # "points elsewhere".
                    $out = { blocked => 1, reason => $status, status => $status,
                             existing => [ map { $_->{content} } @$rows ] };
                    return 1;
                }
            }
        }

        # 3) A: CNAME integrity + duplicate + single RRset TTL (as in pdns_record_mutate).
        my $at = $dbh->selectall_arrayref("SELECT type,content,ttl FROM records WHERE domain_id=? AND name=? FOR UPDATE",
                                          { Slice => {} }, $p->{fwd_id}, $p->{fwd_name}) || [];
        die "cannot add $type: a CNAME exists at $p->{fwd_name}\n" if grep { uc($_->{type}) eq 'CNAME' } @$at;
        die "value already exists\n" if grep { uc($_->{type}) eq $type && lc(canonicalize_ip($type, $_->{content})) eq lc($ip) } @$at;
        my @sameA  = grep { uc($_->{type}) eq $type } @$at;
        my $ex_ttl = @sameA ? $sameA[0]{ttl} : undef;
        my $want   = (defined $p->{ttl} && $p->{ttl} =~ /^\d+$/) ? $p->{ttl} + 0 : undef;
        my $eff_ttl = defined($want) ? $want : (defined($ex_ttl) ? $ex_ttl : 3600);
        if (my $e = dns_validate($type, $p->{fwd_name}, $eff_ttl, $ip, $prio)) { die "$e\n"; }
        # single TTL: if the RRset has rows and another TTL is requested, update them all and insert with it
        if (@sameA && defined($want) && $want != $ex_ttl) {
            $dbh->do("UPDATE records SET ttl=?, updated_by=?, updated_at=NOW(6) WHERE domain_id=? AND name=? AND type=?",
                     undef, $eff_ttl, $p->{actor}, $p->{fwd_id}, $p->{fwd_name}, $type) or die "ttl update failed\n";
        }
        $dbh->do("INSERT INTO records (domain_id,name,type,content,ttl,prio,disabled,updated_by,updated_at)
                  VALUES (?,?,?,?,?,?,0,?,NOW(6))",
                 undef, $p->{fwd_id}, $p->{fwd_name}, $type, $ip, $eff_ttl, $prio, $p->{actor}) or die "insert A failed\n";

        # 4) PTR.
        my @replaced;
        if ($ptr_action eq 'replace') {
            @replaced = @{ $dbh->selectcol_arrayref("SELECT content FROM records WHERE domain_id=? AND type='PTR' AND name=?",
                                                    undef, $p->{rev_id}, $p->{owner}) || [] };
            $dbh->do("DELETE FROM records WHERE domain_id=? AND type='PTR' AND name=?", undef, $p->{rev_id}, $p->{owner})
                or die "delete old PTR failed\n";
        }
        if ($ptr_action eq 'create' || $ptr_action eq 'replace') {
            $dbh->do("INSERT INTO records (domain_id,name,type,content,ttl,prio,disabled,updated_by,updated_at)
                      VALUES (?,?,'PTR',?,?,NULL,0,?,NOW(6))",
                     undef, $p->{rev_id}, $p->{owner}, $p->{target}, $eff_ttl, $p->{actor}) or die "insert PTR failed\n";
        }

        # 5) Bump: fwd always, rev only if a PTR was written. New serials are returned for exact verify.
        my $fwd_serial = _bump_soa_row($dbh, $soa{ $p->{fwd_id} }) or die "soa bump failed (fwd)\n";
        my $rev_serial;
        if ($ptr_action ne 'none') { $rev_serial = _bump_soa_row($dbh, $soa{ $p->{rev_id} }) or die "soa bump failed (rev)\n"; }
        $dbh->commit or die "commit failed\n";
        my $ptr = ($ptr_action eq 'none')
                ? ($use_rev ? 'exists' : 'skipped')
                : ($ptr_action eq 'replace' ? 'replaced' : 'created');
        $out = { address => 'created', ptr => $ptr, status => $status, replaced => \@replaced,
                 eff_ttl => $eff_ttl, ip => $ip, fwd_serial => $fwd_serial, rev_serial => $rev_serial };
        1;
    };
    if (!$ok) { my $e = $@ || 'error'; chomp $e; eval { $dbh->rollback }; return (undef, $e); }
    return ($out, undef);
}

# Preflight (no writes): target reverse zone for an existing forward A/AAAA record. Does NOT check
# permissions (the Router does, via access_for). IP/target come from the record.
# { ok=>1, rev_id, rev_name, rev_type, owner, target, type, ip, fwd_ttl }
# | { blocked=>1, reason=>'not_managed' } (no local reverse zone)
# | { error=>'...' } (no record / not A|AAAA / DB).
sub ptr_reverse_for_record {
    my ($fwd_id, $record_id) = @_;
    my $dbh = connectPDNS() or return { error => 'DB unavailable' };
    my $rec = $dbh->selectrow_hashref(
        "SELECT id, name, type, content, ttl FROM records WHERE id=? AND domain_id=?",
        undef, $record_id, $fwd_id);
    return { error => 'record not found' } unless $rec;
    my $type = uc($rec->{type} || '');
    return { error => 'PTR is available for A/AAAA records only' } unless $type eq 'A' || $type eq 'AAAA';
    my $ip  = canonicalize_ip($type, $rec->{content});
    my ($rev, $rev_err) = reverse_master_for_ip($ip);
    return { error => $rev_err } if $rev_err;                # DB error != "no zone" (fail-closed)
    return { blocked => 1, reason => 'not_managed' } unless $rev;
    my $target = $rec->{name}; $target .= '.' unless $target =~ /\.$/;
    return { ok => 1, rev_id => $rev->{domain_id}, rev_name => $rev->{zone_name},
             rev_type => $rev->{type}, owner => $rev->{owner},
             target => $target, type => $type, ip => $ip, fwd_ttl => $rec->{ttl} };
}

# Create a PTR for an EXISTING forward A/AAAA record (R4: Missing -> "+"). IP/type/target come FROM the
# record (record_id); the frontend does not send target. PTRs are re-checked under the reverse zone lock
# (the table status is not trusted): free->create | exists_active->'exists' (ok) |
# conflict|disabled -> blocked (auto) OR replace (mode=replace: delete old + create).
# TTL: existing PTR RRset's, else the forward record's, else 3600.
# Writability (MASTER/NATIVE) is checked here; PERMISSIONS in the Router. $mode: auto|replace.
# Returns (\%out, undef) | (undef, err). %out:
#   { blocked=>1, reason=>('conflict'|'disabled'|'not_managed'|'not_writable'), status, existing?, rev_id?, rev_name?, owner? }
#   OR { ptr=>'created'|'replaced'|'exists', status=>'ok', rev_id, rev_name, owner, target, ttl, replaced, serial? }.
sub pdns_create_record_ptr {
    my ($fwd_id, $record_id, $mode, $actor) = @_;
    $mode ||= 'auto';
    return (undef, "invalid mode '$mode'") unless $mode =~ /^(auto|replace)$/;
    my $dbh = connectPDNS() or return (undef, 'DB unavailable');

    my $rec = $dbh->selectrow_hashref(
        "SELECT id, name, type, content, ttl FROM records WHERE id=? AND domain_id=?",
        undef, $record_id, $fwd_id);
    return (undef, 'record not found') unless $rec;
    my $type = uc($rec->{type} || '');
    return (undef, 'PTR is available for A/AAAA records only') unless $type eq 'A' || $type eq 'AAAA';

    my $ip     = canonicalize_ip($type, $rec->{content});
    my $target = $rec->{name}; $target .= '.' unless $target =~ /\.$/;    # PTR target is an FQDN with a dot (as in R3)

    my ($rev, $rev_err) = reverse_master_for_ip($ip);
    return (undef, "reverse lookup failed: $rev_err") if $rev_err;   # fail-closed on DB error
    return ({ blocked => 1, reason => 'not_managed', status => 'external' }, undef) unless $rev;
    my $rev_id = $rev->{domain_id};
    return (undef, 'forward and reverse zones must differ') if $rev_id == $fwd_id;
    if (my $we = pdns_zone_write_error($rev_id)) {
        return ({ blocked => 1, reason => 'not_writable', status => 'external', detail => $we,
                  rev_id => $rev_id, rev_name => $rev->{zone_name}, owner => $rev->{owner} }, undef);
    }
    my $owner = $rev->{owner};
    my ($exp_ip, $exp_target) = ($ip, $target);             # snapshot BEFORE the transaction (anti-race check)

    my $out;
    my $ok = eval {
        $dbh->begin_work;
        # Lock SOA of BOTH zones in domain_id order (no deadlocks; forward too, to serialize with Edit/Delete).
        if (my $we = _lock_zones_writable($dbh, $fwd_id, $rev_id)) { die "$we\n"; }
        my %soa;
        for my $did (sort { $a <=> $b } ($fwd_id, $rev_id)) { $soa{$did} = _lock_soa($dbh, $did) or die "no SOA in zone $did\n"; }
        my $soa = $soa{$rev_id};
        # Anti-race: re-read the forward record UNDER LOCK. If it changed between preflight and lock,
        # owner/target/rev_id are stale (a PTR for the old IP could be created) -> roll back.
        my $cur = $dbh->selectrow_hashref(
            "SELECT id,name,type,content,ttl FROM records WHERE id=? AND domain_id=? FOR UPDATE",
            undef, $record_id, $fwd_id);
        die "record changed, reload\n" unless $cur && uc($cur->{type} || '') eq $type;
        my $cur_ip = canonicalize_ip($type, $cur->{content});
        my $cur_target = $cur->{name}; $cur_target .= '.' unless $cur_target =~ /\.$/;
        die "record changed, reload\n" if $cur_ip ne $exp_ip || lc($cur_target) ne lc($exp_target);
        # Re-check UNDER LOCK: the PTR may have been created/changed/disabled since the table was rendered.
        my $rows = $dbh->selectall_arrayref(                    # fail-closed: undef (error) != [] (free)
            "SELECT content, ttl, disabled FROM records WHERE domain_id=? AND type='PTR' AND name=? FOR UPDATE",
            { Slice => {} }, $rev_id, $owner);
        die "PTR lookup failed\n" unless defined $rows;        # SELECT error -> rollback, not a bogus 'free'
        my $status = classify_ptr($rows, $target);
        my $action;
        if    ($status eq 'free')          { $action = 'create'; }
        elsif ($status eq 'exists_active') { $action = 'none'; }    # already points at target -> OK, nothing to do
        else {                                          # conflict | multiple | disabled: manual only
            if ($mode eq 'replace') { $action = 'replace'; }
            else {
                $dbh->rollback;
                $out = { blocked => 1, reason => $status, status => $status,
                         existing => [ map { $_->{content} } @$rows ],
                         rev_id => $rev_id, rev_name => $rev->{zone_name}, owner => $owner };
                return 1;
            }
        }

        # TTL: existing PTR RRset's; else the forward record's UNDER LOCK ($cur, not the pre-tx $rec - a
        # concurrent Edit may have changed the RRset TTL with the same IP/name); else 3600.
        my $ttl = (@$rows && defined $rows->[0]{ttl}) ? $rows->[0]{ttl}
                : (defined $cur->{ttl} ? $cur->{ttl} : 3600);

        my @replaced;
        if ($action eq 'replace') {
            my $rc = $dbh->selectcol_arrayref(                  # fail-closed before deleting old PTRs
                "SELECT content FROM records WHERE domain_id=? AND type='PTR' AND name=?",
                undef, $rev_id, $owner);
            die "PTR lookup failed\n" unless defined $rc;
            @replaced = @$rc;
            $dbh->do("DELETE FROM records WHERE domain_id=? AND type='PTR' AND name=?", undef, $rev_id, $owner)
                or die "delete old PTR failed\n";
        }
        if ($action eq 'create' || $action eq 'replace') {
            if (my $e = dns_validate('PTR', $owner, $ttl, $target, undef)) { die "$e\n"; }
            $dbh->do("INSERT INTO records (domain_id,name,type,content,ttl,prio,disabled,updated_by,updated_at)
                      VALUES (?,?,'PTR',?,?,NULL,0,?,NOW(6))",
                     undef, $rev_id, $owner, $target, $ttl, $actor) or die "insert PTR failed\n";
        }
        my $serial;
        $serial = _bump_soa_row($dbh, $soa) or die "soa bump failed\n" if $action ne 'none';
        $dbh->commit or die "commit failed\n";
        $out = { ptr => ($action eq 'none' ? 'exists' : ($action eq 'replace' ? 'replaced' : 'created')),
                 status => 'ok', rev_id => $rev_id, rev_name => $rev->{zone_name}, owner => $owner,
                 target => $target, ttl => $ttl, replaced => \@replaced, serial => $serial };
        1;
    };
    if (!$ok) { my $e = $@ || 'ptr create failed'; chomp $e; eval { $dbh->rollback }; return (undef, $e); }
    return ($out, undef);
}

# Bulk delete of forward records (one forward zone) + selected matching PTRs (in their reverse zones):
# ONE transaction over ALL affected zones (SOA locks in domain_id order -> no deadlocks; one bump per
# zone). Same path for single and bulk. $items: [ { record_id, ptr => { rev_id, owner, target, exp_ip }? } ].
#   With ptr: delete PTRs in rev_id whose content == target (the record's FQDN) - ONLY matching ones;
#   other hosts' PTRs on the same owner are untouched. Reverse permissions/writability: the Router.
# CONCURRENCY: owner/target/exp_ip are computed by the Router BEFORE the transaction; under lock the core
#   verifies the forward record is unchanged (canonical IP == exp_ip AND name == target). If it changed
#   (e.g. a concurrent Edit changed the IP) the PTR is left alone - otherwise the old IP's PTR would go.
# Returns (\%out, undef) | (undef, err). %out:
#   { deleted=>[{id,name,type,content,ttl}], ptr_deleted=>[{rev_id,owner,content}],
#     ptr_stale=>[record_id,...], fwd_serial, rev_serials=>{ rev_id => serial } }.
sub pdns_delete_records_ptr {
    my ($fwd_id, $items, $actor) = @_;
    return (undef, 'fwd_id required') unless $fwd_id;
    if (my $we = pdns_zone_write_error($fwd_id)) { return (undef, $we); }
    return (undef, 'no records') unless ref($items) eq 'ARRAY' && @$items;

    my %zones = ($fwd_id => 1);                                  # every zone goes under lock
    for my $it (@$items) {
        next unless $it->{ptr} && $it->{ptr}{rev_id};
        return (undef, 'forward and reverse zones must differ') if $it->{ptr}{rev_id} == $fwd_id;
        $zones{ $it->{ptr}{rev_id} } = 1;
    }
    # Reverse zone writability is checked HERE too (like other write functions), not only in the Router.
    for my $zid (keys %zones) {
        next if $zid == $fwd_id;
        if (my $we = pdns_zone_write_error($zid)) { return (undef, "reverse zone: $we"); }
    }
    my $dbh = connectPDNS() or return (undef, 'DB unavailable');
    my $out;
    my $ok = eval {
        $dbh->begin_work;
        if (my $we = _lock_zones_writable($dbh, keys %zones)) { die "$we\n"; }
        my %soa;
        for my $did (sort { $a <=> $b } keys %zones) { $soa{$did} = _lock_soa($dbh, $did) or die "no SOA in zone $did\n"; }

        my (@deleted, @ptr_deleted, @ptr_stale, %bumped_rev);
        for my $it (@$items) {
            my $row = $dbh->selectrow_hashref(
                "SELECT id,name,type,content,ttl FROM records WHERE id=? AND domain_id=?",
                undef, $it->{record_id}, $fwd_id);
            next unless $row;                                    # already gone / foreign id: skip
            next if uc($row->{type}) eq 'SOA';                   # SOA only via its dedicated path
            $dbh->do("DELETE FROM records WHERE id=?", undef, $row->{id}) or die "delete failed\n";
            push @deleted, { id => $row->{id}, name => $row->{name}, type => $row->{type},
                             content => $row->{content}, ttl => $row->{ttl} };
            next unless $it->{ptr} && $it->{ptr}{rev_id};
            my ($rev_id, $owner, $target, $exp_ip) = @{ $it->{ptr} }{qw(rev_id owner target exp_ip)};
            # Concurrency guard: the record must not have changed between preflight and lock.
            my $cur_target = $row->{name}; $cur_target .= '.' unless $cur_target =~ /\.$/;
            my $cur_ip = canonicalize_ip(uc($row->{type}), $row->{content});
            if (!defined($exp_ip) || $cur_ip ne $exp_ip || lc($cur_target) ne lc($target // '')) {
                push @ptr_stale, $row->{id};                     # changed -> leave its PTR alone
                next;
            }
            my $norm = lc($target); $norm =~ s/\.$//;            # target FQDN vs content — dot/case-insensitive
            my $prs = $dbh->selectall_arrayref(                   # fail-closed: undef (error) != [] (empty)
                "SELECT id, content FROM records WHERE domain_id=? AND type='PTR' AND name=? FOR UPDATE",
                { Slice => {} }, $rev_id, $owner);
            die "PTR lookup failed\n" unless defined $prs;       # SELECT error -> roll back the whole transaction
            for my $pr (@$prs) {
                my $c = lc($pr->{content} // ''); $c =~ s/\.$//;
                next unless $c eq $norm;                         # only PTRs pointing at this host
                $dbh->do("DELETE FROM records WHERE id=?", undef, $pr->{id}) or die "ptr delete failed\n";
                push @ptr_deleted, { rev_id => $rev_id, owner => $owner, content => $pr->{content} };
                $bumped_rev{$rev_id} = 1;
            }
        }
        die "nothing to delete\n" unless @deleted;
        my $fwd_serial = _bump_soa_row($dbh, $soa{$fwd_id}) or die "soa bump failed (fwd)\n";
        my %rev_serials;
        for my $rid (keys %bumped_rev) { $rev_serials{$rid} = _bump_soa_row($dbh, $soa{$rid}) or die "soa bump failed (rev $rid)\n"; }
        $dbh->commit or die "commit failed\n";
        $out = { deleted => \@deleted, ptr_deleted => \@ptr_deleted, ptr_stale => \@ptr_stale,
                 fwd_serial => $fwd_serial, rev_serials => \%rev_serials };
        1;
    };
    if (!$ok) { my $e = $@ || 'error'; chomp $e; eval { $dbh->rollback }; return (undef, $e); }
    return ($out, undef);
}

# ---------------------------------------------------------------------------
# ZONE AGGREGATES (counts, subdomains/hosts, delegated zones)
# ---------------------------------------------------------------------------

# Record count per type + total: { by_type => {A=>n,...}, total => N }.
sub pdns_count_records_by_type {
    my ($domain_id) = @_;
    return { by_type => {}, total => 0 } unless $domain_id;
    my $dbh = connectPDNS() or return { by_type => {}, total => 0 };
    my $rows = $dbh->selectall_arrayref(
        "SELECT type, COUNT(*) AS c FROM records WHERE domain_id = ? GROUP BY type ORDER BY type",
        { Slice => {} }, $domain_id) || [];
    my (%by, $total);
    for (@$rows) { $by{ $_->{type} } = $_->{c} + 0; $total += $_->{c}; }
    return { by_type => \%by, total => ($total || 0) };
}

# Zone hosts/subdomains: distinct names with record count and types; $type is an optional filter.
# Returns [{name, count, types}].
sub pdns_list_subnames {
    my ($domain_id, $type) = @_;
    return [] unless $domain_id;
    my $dbh = connectPDNS() or return [];
    my ($sql, @bind);
    my $base = "SELECT name, COUNT(*) AS count, GROUP_CONCAT(DISTINCT type ORDER BY type SEPARATOR ',') AS types
                  FROM records WHERE domain_id = ?";
    if (defined $type && length $type) {
        $sql = "$base AND type = ? GROUP BY name ORDER BY name";
        @bind = ($domain_id, uc $type);
    } else {
        $sql = "$base GROUP BY name ORDER BY name";
        @bind = ($domain_id);
    }
    my $rows = $dbh->selectall_arrayref($sql, { Slice => {} }, @bind) || [];
    $_->{count} += 0 for @$rows;
    return $rows;
}

# Record search across zones by name and/or content substring, optional type filter.
# $opt: { field => 'name'|'content'|'any'(default), type => 'A', limit => 200 }.
# PURE. Partial IPv4 -> reverse-name SUFFIX: '10.99' -> '.99.10.in-addr.arpa' (undef if not partial IPv4).
# Needed because a PTR name holds the address reversed, so the substring "10.99" never occurs in it;
# full addresses already match via an exact name (extra_name). The leading dot keeps octets whole:
# '10.9' must not match '...19.10.in-addr.arpa'. IPv6 is deliberately unsupported: with :: shortening,
# a partial input would need guessing. Full IPv6 works via the exact name.
sub ptr_suffix_for_partial_ip {
    my ($q) = @_;
    return undef unless defined $q && length $q;
    (my $t = $q) =~ s/\.\z//;                  # '10.99.' is the normal state while typing
    return undef unless $t =~ /^\d{1,3}(?:\.\d{1,3}){0,2}$/;   # 4 octets never get here: they use the exact name
    my @o = split /\./, $t;
    return undef if grep { $_ > 255 } @o;
    return '.' . join('.', reverse @o) . '.in-addr.arpa';
}
# Owner names of A/AAAA holding EXACTLY this address, for one level of references (CNAME/MX/SRV to a
# name with this address). Exact match: a substring would find 203.0.113.10 for 203.0.113.1. Same scope
# as the search (accessible zones), otherwise a reference would reveal a name in an invisible zone.
sub pdns_names_with_address {
    my ($ip, $domain_ids) = @_;
    return [] unless defined $ip && length $ip;
    my $dbh = connectPDNS() or return [];
    # INET6_ATON canonicalizes BOTH sides: _apply_one_rrset stores content as given, so the DB may hold
    # `2001:0db8:0:0:0:0:0:5`, which a text compare would not match to `2001:db8::5`. NULL for non-addresses.
    # Disabled records are excluded: they do not answer, so a CNAME to that name does not resolve to this
    # address in reality. (The disabled A/AAAA itself still shows in search results, marked.)
    my ($where, @bind) = ("r.type IN ('A','AAAA') AND r.disabled = 0
                           AND INET6_ATON(r.content) = INET6_ATON(?)", $ip);
    if (ref($domain_ids) eq 'ARRAY') {
        return [] unless @$domain_ids;
        $where .= ' AND r.domain_id IN (' . join(',', ('?') x @$domain_ids) . ')';
        push @bind, @$domain_ids;
    }
    my $rows = $dbh->selectall_arrayref(
        "SELECT DISTINCT r.name FROM records r WHERE $where LIMIT 200", { Slice => {} }, @bind) || [];
    return [ map { $_->{name} } @$rows ];
}

sub pdns_search_records {
    my ($query, $opt) = @_;
    return [] unless defined $query && length $query;
    $opt ||= {};
    my $field = $opt->{field} || 'any';
    my $limit = ($opt->{limit} && $opt->{limit} =~ /^\d+$/) ? $opt->{limit} : 200;
    my $dbh = connectPDNS() or return [];

    # LOCATE, not LIKE '%q%': `_` and `%` are LIKE wildcards but occur literally in DNS (`_sip._tcp`).
    # LIKE '%...%' cannot use an index either, so nothing is lost.
    my ($where, @bind);
    if ($field eq 'name')    { $where = "LOCATE(?, r.name) > 0";    @bind = ($query); }
    elsif ($field eq 'content') { $where = "LOCATE(?, r.content) > 0"; @bind = ($query); }
    elsif ($opt->{ip}) {
        # The query is an address: A/AAAA content is compared EXACTLY via INET6_ATON (a substring would find
        # 203.0.113.10 for 203.0.113.1; text compare misses non-canonical forms). Other types keep substring
        # matching: an address legitimately appears in TXT/SPF.
        $where = "(LOCATE(?, r.name) > 0
                   OR (r.type IN ('A','AAAA') AND INET6_ATON(r.content) = INET6_ATON(?))
                   OR (r.type NOT IN ('A','AAAA') AND LOCATE(?, r.content) > 0))";
        @bind  = ($query, $query, $query);
    }
    else { $where = "(LOCATE(?, r.name) > 0 OR LOCATE(?, r.content) > 0)"; @bind = ($query, $query); }

    # extra_name: an EXACT name in addition to the substring, for IP search - a PTR name holds the reverse
    # form (7.100.51.198.in-addr.arpa). Only with field=any: an explicit field=content must not match names.
    if ($field eq 'any' && defined $opt->{extra_name} && length $opt->{extra_name}) {
        $where = "($where OR r.name = ?)";
        push @bind, $opt->{extra_name};
    }
    # Partial IPv4: PTRs by reverse-name suffix. PTR only, otherwise "10.99" would also return the reverse
    # zone's own SOA/NS. RIGHT(), not LIKE '%...', so `_`/`%` can never act as wildcards.
    if ($field eq 'any' && defined $opt->{ptr_suffix} && length $opt->{ptr_suffix}) {
        $where = "($where OR (r.type = 'PTR' AND RIGHT(r.name, CHAR_LENGTH(?)) = ?))";
        push @bind, $opt->{ptr_suffix}, $opt->{ptr_suffix};
    }
    # ONE level of references: records whose LAST content token is one of these names (with or without
    # the trailing dot) - covers `CNAME host.`, `MX host.` (priority is in prio) and `SRV 0 5 5060 host.`.
    # Deeper resolution is graph traversal with loop protection - a different task.
    if ($field eq 'any' && ref($opt->{ref_names}) eq 'ARRAY' && @{ $opt->{ref_names} }) {
        my @v;
        for my $n (@{ $opt->{ref_names} }) {
            next unless defined $n && length $n;
            (my $bare = $n) =~ s/\.\z//;
            push @v, $bare, "$bare.";
        }
        if (@v) {
            $where = "($where OR SUBSTRING_INDEX(r.content, ' ', -1) IN (" . join(',', ('?') x @v) . "))";
            push @bind, @v;
        }
    }
    if (defined $opt->{type} && length $opt->{type}) {
        $where .= " AND r.type = ?"; push @bind, uc $opt->{type};
    }
    # Accessible-zone restriction in SQL (before LIMIT), so accessible matches are not lost.
    if (ref($opt->{domain_ids}) eq 'ARRAY') {
        return [] unless @{ $opt->{domain_ids} };
        my $ph = join(',', ('?') x @{ $opt->{domain_ids} });
        $where .= " AND r.domain_id IN ($ph)";
        push @bind, @{ $opt->{domain_ids} };
    }
    my $sql = "SELECT r.id, r.domain_id, d.name AS zone, r.name, r.type, r.content, r.ttl, r.prio, r.disabled
                 FROM records r JOIN domains d ON d.id = r.domain_id
                WHERE $where
                ORDER BY d.name, r.name, r.type
                LIMIT $limit";
    return $dbh->selectall_arrayref($sql, { Slice => {} }, @bind) || [];
}

# Delegated child zones (separate domains rows *.<zone>).
sub pdns_list_child_zones {
    my ($zone_name) = @_;
    return [] unless defined $zone_name && length $zone_name;
    my $dbh = connectPDNS() or return [];
    my $like = '%.' . $zone_name;
    return $dbh->selectall_arrayref(
        "SELECT id, name, type FROM domains WHERE name LIKE ? ORDER BY name",
        { Slice => {} }, $like) || [];
}

# ---------------------------------------------------------------------------
# WRITES to PowerDNS (direct SQL, transactions + SOA bump). A move to the PowerDNS HTTP API
# would change only these functions, not the callers (panel, MCP).
# ---------------------------------------------------------------------------

sub pdns_get_domain_by_name {
    my ($name) = @_;
    return undef unless defined $name && length $name;
    my $dbh = connectPDNS() or return undef;
    my $row = $dbh->selectrow_hashref(
        "SELECT id, name, type, master, notified_serial, account FROM domains WHERE name = ? LIMIT 1",
        undef, $name);
    return $row;
}

# STRICT zone lookup by name: tells "no such zone" from "read error" for fail-closed paths such as
# retry (a transient PDNS DB failure must not look like "no zone" -> orphaned forever).
# Returns ($dom, $error): ($dom,undef) found; (undef,undef) definitely absent; (undef,$error) DB error.
sub pdns_find_domain_by_name {
    my ($name) = @_;
    return (undef, undef) unless defined $name && length $name;
    my $dbh = connectPDNS() or return (undef, 'DB unavailable');
    my $rows = $dbh->selectall_arrayref(
        "SELECT id, name, type, master, notified_serial, account FROM domains WHERE name = ? LIMIT 1",
        { Slice => {} }, $name);
    return (undef, 'domains lookup failed') unless defined $rows;   # error != "no row"
    return (undef, undef) unless @$rows;
    return ($rows->[0], undef);
}

# Zone type (uc) by domain_id; '' if not found.
sub pdns_zone_type {
    my ($domain_id) = @_;
    return '' unless $domain_id;
    my $dbh = connectPDNS() or return '';
    my ($t) = $dbh->selectrow_array("SELECT type FROM domains WHERE id = ? LIMIT 1", undef, $domain_id);
    return uc($t || '');
}

# Central guard: manual writes only into MASTER/NATIVE. Returns undef (ok) or an error string.
# Called by ALL core write functions -> identical for API/UI/MCP.
sub pdns_zone_write_error {
    my ($domain_id) = @_;
    return _zone_type_write_error(pdns_zone_type($domain_id));
}
# One error text for both the early check and the check under lock.
sub _zone_type_write_error {
    my ($t) = @_;
    $t = defined $t ? uc $t : '';
    return "zone not found" unless length $t;
    return undef if $t eq 'MASTER' || $t eq 'NATIVE';      # only these are edited manually
    return "zone is SLAVE (read-only; data arrives via AXFR)" if $t eq 'SLAVE';
    return "zone type $t is not writable";                 # PRODUCER/CONSUMER (catalog) etc.
}

# The SAME check, but INSIDE the transaction with the domains row locked. The early
# pdns_zone_write_error only gives a clear error up front: between it and the write the zone may become
# Secondary (Make secondary changes domains.type and wipes records), and the edit would land in a zone
# the next AXFR overwrites while audit records success.
# SELECT ... FOR UPDATE holds the row until commit, so role change and zone delete wait for us.
# Lock order is the same on ALL write paths: domains rows by ascending id, then SOA rows - otherwise two
# operations on the same zone pair can deadlock. This serializes PANEL operations only; an AXFR already
# running inside PowerDNS is not covered (docs/24-dns-engine.md).
sub _lock_zones_writable {
    my ($dbh, @ids) = @_;
    my %seen;
    my @ord = grep { !$seen{$_}++ } map { $_ + 0 } grep { defined $_ && $_ =~ /^\d+$/ } @ids;
    return 'domain_id required' unless @ord;
    for my $id (sort { $a <=> $b } @ord) {
        my ($t) = $dbh->selectrow_array("SELECT type FROM domains WHERE id = ? FOR UPDATE", undef, $id);
        # A failing query (including a lock wait timeout) is NOT "no zone": otherwise any DB error
        # would surface as "zone not found".
        if ($dbh->err) { return _db_err_kind($dbh->err) || 'DB error'; }
        if (my $e = _zone_type_write_error($t)) { return $e; }
    }
    return undef;
}

# WHO CHANGED as an icon, not a name: long usernames widen the narrow column; the name is the tooltip.
# Shared component: same look in the server-rendered records table and the browser-built servers
# table (DNSPanel.actorIcon in app.js).
sub actor_icon_html {
    my ($name) = @_;
    return qq{<span class="text-mute">\x{2014}</span>} unless defined $name && length $name;
    my $t = $name; $t =~ s/&/&amp;/g; $t =~ s/</&lt;/g; $t =~ s/>/&gt;/g; $t =~ s/"/&quot;/g;
    return qq{<span class="lc-who" data-tip="$t" aria-label="$t">}
         . qq{<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">}
         . qq{<path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg></span>};
}

# On-screen catalog name: the human name ("TEST Catalog"), FQDN ("test.catalog") in parentheses.
# One rule for all screens: pickers show "Name (fqdn)", tight table rows show the name with the FQDN
# in the tooltip. Markup twin: DNSPanel.catalogLabel in app.js.
sub catalog_label {
    my ($c) = @_;
    return '' unless ref $c eq 'HASH';
    my ($n, $f) = ($c->{name}, $c->{fqdn});
    return $f // '' unless defined $n && length $n;
    return $n unless defined $f && length $f;
    return "$n ($f)";
}

# Dropdown as a SITE COMPONENT, not a native <select>: an open native menu cannot be styled. The browser
# builds it with DNSPanel.selectHtml; this is the markup twin for server-rendered pages. Markup must match
# class for class: the same app.js attaches the behavior (open, choose, hidden field).
# $opts: [ { value, label }, ... ].
sub ui_select_html {
    my ($name, $opts, $value) = @_;
    $opts ||= [];
    my $esc = sub { my $t = shift; $t = '' unless defined $t;
                    $t =~ s/&/&amp;/g; $t =~ s/</&lt;/g; $t =~ s/>/&gt;/g; $t =~ s/"/&quot;/g; return $t };
    my $cur;
    for my $o (@$opts) { if (defined $value && "$o->{value}" eq "$value") { $cur = $o; last } }
    $cur ||= $opts->[0] || { value => '', label => '' };
    my $menu = join '', map {
        sprintf('<div class="ui-select-opt%s" data-val="%s">%s</div>',
                ("$_->{value}" eq "$cur->{value}" ? ' sel' : ''), $esc->($_->{value}), $esc->($_->{label}))
    } @$opts;
    return sprintf('<div class="ui-select" data-name="%s"><input type="hidden" name="%s" value="%s">'
                 . '<div class="ui-select-trigger"><span class="ui-select-label">%s</span><span class="chev"></span></div>'
                 . '<div class="ui-select-menu">%s</div></div>',
                   $esc->($name), $esc->($name), $esc->($cur->{value}), $esc->($cur->{label}), $menu);
}

# ---------------------------------------------------------------------------
# MIGRATING ZONES FROM THE OLD MASTER
# ---------------------------------------------------------------------------
# DNS cannot list a server's zones (AXFR needs a known name, and old servers rarely have an RFC 9432
# catalog), so the list comes as a file. Instead of parsing arbitrary named.conf with includes, BIND
# flattens its own config:
#     named-checkconf -p > bind-export.conf
# Input is exactly that output (includes expanded, one normalized form). Only what the decision needs is
# taken: name, role, dynamic flag and who may update, masters of slave zones, and one name in two views.
# Only the keys named in allow-update are taken (with their secrets); files and policies are not read.
# Values of a `directive { a; b; }` block (addresses, ACL names, key names) taken verbatim; [] if absent.
sub _bind_block_items {
    my ($body, $name) = @_;
    my ($inner) = $body =~ /\b\Q$name\E\s*\{(.*?)\}/is;
    return [] unless defined $inner;
    my @out;
    for my $tok (split /;/, $inner) {
        $tok =~ s/^\s+|\s+$//g;
        $tok =~ s/^"(.*)"$/$1/;
        next unless length $tok;
        push @out, $tok;
    }
    return \@out;
}
# allow-update items resolved through named ACLs: {cidrs[], keys[], other[], key_defs{name: {algorithm, secret}}}. `other` is what the panel
# cannot carry over (any, localhost, negations, unknown ACLs) - shown to the human, never guessed.
sub _bind_update_from {
    my ($items, $acl, $kdef) = @_;
    my (%seen, %out) = ();
    $out{$_} = [] for qw(cidrs keys other);
    my $walk; $walk = sub {
        my ($list, $depth) = @_;
        for my $it (@$list) {
            my $t = $it =~ s/^"(.*)"$/$1/r;
            next if lc($t) eq 'none' || $seen{$t}++;
            if    ($t =~ /^key\s+"?([A-Za-z0-9._-]+)"?$/i) { push @{ $out{keys} }, $1 }
            elsif (my $c = cidr_normalize($t))             { push @{ $out{cidrs} }, $c }
            elsif ($acl->{$t} && $depth < 8)               { $walk->($acl->{$t}, $depth + 1) }
            else                                            { push @{ $out{other} }, $t }
        }
    };
    $walk->($items, 0);
    $out{key_defs} = { map { $_ => $kdef->{$_} } grep { $kdef->{$_} } @{ $out{keys} } };
    return \%out;
}

# What the panel reads from `named-checkconf -p`: everything describing the zone and its links - what a
# human needs to decide on the migration screen. Key secrets are read only for keys named in allow-update
# (see _bind_update_from); otherwise only the key NAME referenced by the zone is kept. Unknown directives go
# to `review` and the zone is flagged - "not understood but migrated anyway" is the worst outcome.
our %BIND_ZONE_KNOWN = map { $_ => 1 } qw(
    type file masters primaries also-notify notify allow-update update-policy allow-query allow-transfer
    forwarders forward in-view journal auto-dnssec inline-signing dnssec-policy key-directory serial-update-method
    max-journal-size notify-source transfer-source zone-statistics check-names check-mx masterfile-format
);
# What the panel can migrate via AXFR. Other types (hint, forward, stub...) are listed without a checkbox:
# offering an action that will not happen is worse than showing the type.
our %BIND_ZONE_IMPORTABLE = (master => 1, primary => 1, slave => 1, secondary => 1);
sub bind_export_zones {
    my ($text) = @_;
    return (undef, 'nothing to read') unless defined $text && $text =~ /\S/;
    return (undef, 'file is too large') if length($text) > 8 * 1024 * 1024;

    my (@out, %at);
    # Named ACLs, so allow-update can be resolved to addresses and key names (`named-checkconf -p` prints
    # them at the top level, closed by `};` at the start of a line).
    my %acl;
    while ($text =~ /^acl\s+"([^"]+)"\s*\{(.*?)^\};/gms) { $acl{$1} = [ grep { length } map { s/^\s+|\s+$//gr } split /;/, $2 ]; }
    # Keys defined in the export (algorithm and secret): the operator uploaded the whole config, and a migrated
    # zone needs the very key its DHCP server signs with. Only keys named in allow-update are kept.
    my %kdef;
    while ($text =~ /^key\s+"([^"]+)"\s*\{([^}]*)\}/gms) {
        my ($kn, $kb) = ($1, $2);
        my ($alg) = $kb =~ /\balgorithm\s+"?([A-Za-z0-9-]+)"?\s*;/i;
        my ($sec) = $kb =~ /\bsecret\s+"([^"]+)"\s*;/i;
        $kdef{$kn} = { algorithm => lc($alg // 'hmac-md5'), (defined $sec ? (secret => ($sec =~ s/\s+//gr)) : ()) };   # BIND allows spaces inside
    }
    # A scanner, not a regex: zone bodies contain their own braces (also-notify, masters, update-policy).
    # A zone may also sit inside a view - then one name appears twice, which is split-horizon, not a file
    # error, and the human must be told.
    while ($text =~ /\bzone\s+"([^"]+)"\s*(?:in\s+)?\{/gis) {
        my ($name, $start) = ($1, pos($text));
        my ($depth, $i) = (1, $start);
        while ($i < length($text) && $depth) {
            my $c = substr($text, $i, 1);
            $depth++ if $c eq '{';
            $depth-- if $c eq '}';
            $i++;
        }
        my $body = substr($text, $start, $i - $start - 1);
        pos($text) = $i;

        # `in-view "internal";` is NOT a second zone but a reference to the same zone from another view (a live
        # server had 585 such blocks for 307 real zones).
        next if $body =~ /\bin-view\s+"?[A-Za-z0-9._-]+"?\s*;/i;

        my ($type) = $body =~ /\btype\s+(\w+)\s*;/i;
        $type = lc($type // '');
        # BIND prints both old and new keywords: master/primary and slave/secondary are synonyms.
        my $role = ($type eq 'master' || $type eq 'primary')     ? 'master'
                 : ($type eq 'slave'  || $type eq 'secondary')   ? 'slave'
                 : $type;
        my ($zname, $zerr) = dns_validate_zonename($name);
        next if $zerr;                               # "." and anything else that cannot be a panel zone

        # Dynamic zone (RFC 2136 updates; who sends them is not visible in the config). It can be migrated,
        # but the migration cannot be declared complete until the new server accepts UPDATE.
        my $au = _bind_block_items($body, 'allow-update');
        my $has_policy = ($body =~ /\bupdate-policy\s*\{/i) ? 1 : 0;
        my @au_real = grep { lc($_) ne 'none' } @$au;
        my $dynamic = ($has_policy || @au_real) ? 1 : 0;
        my $update_from = @au_real ? _bind_update_from(\@au_real, \%acl, \%kdef) : undef;

        my $masters = ($role eq 'slave')
                    ? [ grep { _is_ipv4($_) || _is_ipv6($_) } @{ _bind_block_items($body, 'masters') },
                                                              @{ _bind_block_items($body, 'primaries') } ]
                    : [];
        my ($file)   = $body =~ /\bfile\s+"([^"]*)"/i;
        my ($notify) = $body =~ /\bnotify\s+(\S+?)\s*;/i;
        my $keys = [];   # TSIG key names referenced by the zone
        push @$keys, $1 while $body =~ /\bkey\s+"?([A-Za-z0-9._-]+)"?\s*;/gi;

        # Unsupported or unknown directives, looking ONLY at the zone's own directives: addresses inside
        # also-notify are not directives, so nested blocks are cut out first.
        my $flat = $body;
        1 while $flat =~ s/\{[^{}]*\}/ /s;
        my (%seen, @unknown);
        while ($flat =~ /^[ \t]*([a-z][a-z0-9-]*)\b/gim) {
            my $d = lc $1;
            next if $seen{$d}++;
            push @unknown, $d unless $BIND_ZONE_KNOWN{$d};
        }
        my @review;
        push @review, 'zone type the panel cannot migrate: ' . $type unless $BIND_ZONE_IMPORTABLE{$type};
        # An empty `forwarders { };` means nothing (36 of 37 on a live server); only a non-empty list needs review.
        push @review, 'forwarders' if @{ _bind_block_items($body, 'forwarders') };
        push @review, 'update-policy' if $has_policy;
        # A signed zone is mirrored as it is; Make primary carries its keys over (_dnssec_promote_plan).
        my $dnssec = ($body =~ /\b(?:auto-dnssec|inline-signing|dnssec-policy)\b/i) ? 1 : 0;
        push @review, 'unknown: ' . join(', ', @unknown) if @unknown;

        # Mark the zone ALREADY in the list, not the last one added: other zones usually sit between two views.
        # One name with SEVERAL real definitions (different views/files) is two different zones; the panel has
        # one zone per name and cannot pick the "real" one for the human.
        if (defined $at{$zname}) {
            $out[ $at{$zname} ]{split_horizon} = 1;
            $out[ $at{$zname} ]{importable} = 0;
            push @{ $out[ $at{$zname} ]{review} }, 'the same name is defined more than once'
                unless grep { /defined more than once/ } @{ $out[ $at{$zname} ]{review} };
            next;
        }
        $at{$zname} = scalar @out;
        push @out, {
            name => $zname, role => $role, type => $type, dynamic => $dynamic, dnssec => $dnssec,
            importable => ($BIND_ZONE_IMPORTABLE{$type} ? 1 : 0),
            masters => $masters, split_horizon => 0,
            file => $file, notify => $notify,
            allow_update  => $au,
            ($update_from ? (update_from => $update_from) : ()),
            update_policy => $has_policy,
            allow_query   => _bind_block_items($body, 'allow-query'),
            allow_transfer=> _bind_block_items($body, 'allow-transfer'),
            also_notify   => _bind_block_items($body, 'also-notify'),
            forwarders    => _bind_block_items($body, 'forwarders'),
            keys          => $keys,
            review        => \@review,
        };
    }
    return (undef, 'no zones found — is this the output of `named-checkconf -p`?') unless @out;
    return (\@out, undef);
}

# The transfer source is usually in the export itself (`listen-on` of the old server). Only a HINT:
# there may be several addresses or a VIP, or AXFR may go elsewhere - so a single candidate is suggested,
# and the human decides.
sub bind_export_sources {
    my ($text) = @_;
    return [] unless defined $text && length $text;
    my @out;
    my %seen;
    while ($text =~ /\blisten-on(?:-v6)?\s*(?:port\s+\d+\s*)?\{(.*?)\}/gis) {
        for my $tok (split /;/, $1) {
            $tok =~ s/^\s+|\s+$//g;
            $tok =~ s{/\d+$}{};                    # the listener's netmask is irrelevant
            next unless length $tok;
            next if $tok =~ /^(any|none|localhost|localnets)$/i;
            next unless _is_ipv4($tok) || _is_ipv6($tok);
            next if $tok =~ /^127\./ || lc($tok) eq '::1';   # its own loopback is never a source
            push @out, $tok unless $seen{$tok}++;
        }
    }
    return \@out;
}

# ---- Stored zone list of an old server (docs/26) ----
# The file is parsed ONCE into the DB; the migration screen works with the list. Migrating hundreds of
# zones takes weeks, and the human must see what was taken, what was skipped and what only just appeared.
# Re-loading an export of the SAME master does not create a second operation: rows are updated by name,
# new ones added, vanished ones fall behind by last_seen_at. Existing panel zones are NEVER touched.
# ($source, undef) | (undef, err). $source = { id, master, zone_count, loaded_at, added, updated, gone }.
# BIND key files (K<zone>.+<alg>+<tag>.key and .private, from key-directory) -> {zone => [key]}. Only pairs
# count: the private half is what PowerDNS needs, the public half gives the flags. keyset-/dsset- files,
# .signed and .jnl are not keys and are skipped. key: {tag, flags, algorithm, dnskey, privatekey, publish,
# activate, inactive, delete} with BIND timestamps (YYYYMMDDHHMMSS) or undef.
sub bind_dnssec_keys {
    my ($files) = @_;
    my (%half, %out);
    for my $f (@{ ref $files eq 'ARRAY' ? $files : [] }) {
        next unless ref $f eq 'HASH' && defined $f->{name} && defined $f->{content};
        my ($base, $ext) = ($f->{name} =~ m{(?:^|/)(K[^/]+\+\d{3}\+\d{5})\.(key|private)$}) or next;
        $half{$base}{$ext} = $f->{content};
    }
    for my $base (sort keys %half) {
        my $h = $half{$base};
        next unless defined $h->{key} && defined $h->{private};
        my ($zone, $alg, $tag) = $base =~ /^K(.+?)\.?\+(\d{3})\+(\d{5})$/ or next;
        my ($dk) = grep { !/^\s*;/ && /\bDNSKEY\b/ } split /\n/, $h->{key};
        my ($rdata) = ($dk // '') =~ /\bDNSKEY\s+(.+?)\s*$/ or next;
        my %t = map { lc($_) => undef } qw(Publish Activate Inactive Delete);
        for my $l (split /\n/, $h->{private}) { $t{ lc $1 } = $2 if $l =~ /^(Publish|Activate|Inactive|Delete):\s*(\d{14})/; }
        my ($flags) = $rdata =~ /^(\d+)/;
        push @{ $out{ lc $zone } }, { tag => $tag + 0, algorithm => $alg + 0, flags => $flags + 0,
                                      dnskey => ($rdata =~ s/\s+/ /gr), privatekey => $h->{private},
                                      map { $_ => $t{$_} } qw(publish activate inactive delete) };
    }
    return \%out;
}
# DNSSEC of one signed zone in the import list: which keys it signs with on the source (its live DNSKEY set),
# the key files loaded for it, and the "import unsigned" choice. Kept in the zone's config_json.
sub _import_zone_row {
    my ($iz_id) = @_;
    return (undef, 'invalid id') unless $iz_id && "$iz_id" =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $r, my $e) = _db_row($dbh, "SELECT z.id, z.zone_name, z.config_json, s.master FROM import_zones z
                                      JOIN import_sources s ON s.id = z.source_id WHERE z.id=?", $iz_id);
    return (undef, $e) if $e;
    return (undef, 'not found') unless $r;
    $r->{cfg} = eval { JSON->new->decode($r->{config_json} // '{}') } || {};
    return (undef, 'the zone is not signed on the source server') unless $r->{cfg}{dnssec};
    return ($r, undef);
}
sub _import_zone_cfg_save {
    my ($r) = @_;
    my $dbh = connectDB() or return 'DB unavailable';
    (my $x, my $e) = _do($dbh, "UPDATE import_zones SET config_json=? WHERE id=?", JSON->new->canonical->encode($r->{cfg}), $r->{id});
    return $e;
}
# ({zone, source, keys[{tag, role, algorithm, files[], have}], unsigned, error?}, undef) | (undef, err).
sub import_zone_dnssec {
    my ($iz_id) = @_;
    (my $r, my $e) = _import_zone_row($iz_id); return (undef, $e) if $e;
    my %have = map { _dnskey_norm($_->{dnskey}) => 1 } @{ ref $r->{cfg}{dnssec_keys} eq 'ARRAY' ? $r->{cfg}{dnssec_keys} : [] };
    my $q = dns_query($r->{zone_name}, 'DNSKEY', $r->{master});
    my @keys;
    for my $a (@{ $q->{answers} || [] }) {
        my ($f, undef, $alg) = split ' ', ($a->{data} // '');
        next unless defined $alg && $alg =~ /^\d+$/ && $f =~ /^\d+$/;
        my $tag = _dnskey_tag($a->{data}); my $b = sprintf 'K%s.+%03d+%05d', $r->{zone_name}, $alg, $tag;
        push @keys, { tag => $tag, role => ($f == 257 ? 'KSK' : 'ZSK'), algorithm => $alg + 0,
                      files => [ "$b.key", "$b.private" ], have => ($have{ _dnskey_norm($a->{data}) } ? 1 : 0) };
    }
    # Already promoted: the panel signs it now, nothing is left to choose.
    my $pz = pdns_get_domain_by_name($r->{zone_name});
    my $done = ($pz && uc($pz->{type} // '') eq 'MASTER') ? (zone_signed_by_name($r->{zone_name}) ? 'signed' : 'unsigned') : undef;
    return ({ zone => $r->{zone_name}, source => $r->{master}, keys => \@keys, unsigned => ($r->{cfg}{dnssec_unsigned} ? 1 : 0), ($done ? (done => $done) : ()),
              (@keys ? () : (error => 'the source server did not return its DNSKEY set' . ($q->{error} ? ": $q->{error}" : ''))) }, undef);
}
sub import_zone_dnssec_keys {
    my ($iz_id, $files) = @_;
    (my $r, my $e) = _import_zone_row($iz_id); return (undef, $e) if $e;
    my $k = bind_dnssec_keys($files)->{ lc $r->{zone_name} } || [];
    return (undef, "no key pair (.key + .private) of $r->{zone_name} among these files") unless @$k;
    my %by = map { $_->{tag} => $_ } @{ ref $r->{cfg}{dnssec_keys} eq 'ARRAY' ? $r->{cfg}{dnssec_keys} : [] }, @$k;
    $r->{cfg}{dnssec_keys} = [ map { $by{$_} } sort { $a <=> $b } keys %by ];
    delete $r->{cfg}{dnssec_unsigned};
    my $se = _import_zone_cfg_save($r); return (undef, $se) if $se;
    return import_zone_dnssec($iz_id);
}
sub import_zone_dnssec_unsigned {
    my ($iz_id, $on) = @_;
    (my $r, my $e) = _import_zone_row($iz_id); return (undef, $e) if $e;
    if ($on) { $r->{cfg}{dnssec_unsigned} = 1 } else { delete $r->{cfg}{dnssec_unsigned} }
    my $se = _import_zone_cfg_save($r); return (undef, $se) if $se;
    return import_zone_dnssec($iz_id);
}
sub import_source_load {
    my ($master, $text) = @_;
    return (undef, 'source address required') unless defined $master && is_ip_addr($master);
    (my $zones, my $ze) = bind_export_zones($text);
    return (undef, $ze) if $ze;

    my $dbh = connectDB() or return (undef, 'DB unavailable');
    my $fhash = sha256_hex(defined $text ? $text : '');
    (my $bo, my $be) = _txn_begin($dbh); return (undef, $be) if $be;
    my ($sid, $added, $updated);
    my $err = eval {
        (my $row, my $e) = _db_row($dbh, "SELECT id FROM import_sources WHERE master=?", $master); die "$e\n" if $e;
        if ($row) {
            $sid = $row->{id};
            $dbh->do("UPDATE import_sources SET zone_count=?, file_hash=?, loaded_at=UTC_TIMESTAMP() WHERE id=?",
                     undef, scalar @$zones, $fhash, $sid) or die "db\n";
        } else {
            $dbh->do("INSERT INTO import_sources (master, zone_count, file_hash) VALUES (?,?,?)",
                     undef, $master, scalar @$zones, $fhash) or die "db\n";
            $sid = $dbh->last_insert_id(undef, undef, undef, undef);
        }
        # Changes since the last load are computed by COMPARISON, not affected-row counts: depending on MySQL
        # client flags "found" and "changed" rows give the same number, which reported "added 306" for nothing.
        (my $prev, my $pe) = _db_all($dbh, "SELECT zone_name, config_hash, config_json FROM import_zones WHERE source_id=?",
                                     { Slice => {} }, $sid); die "$pe\n" if $pe;
        my %was = map { lc $_->{zone_name} => $_->{config_hash} } @$prev;
        # The DNSSEC choices made on a zone (its key files, "import unsigned") survive a reload of the export.
        my %was_dnssec;
        for my $p (@$prev) {
            next unless ($p->{config_json} // '') =~ /"dnssec_(?:keys|unsigned)"/;
            my $c = eval { JSON->new->decode($p->{config_json}) } || {};
            $was_dnssec{ lc $p->{zone_name} } = { map { defined $c->{$_} ? ($_ => $c->{$_}) : () } qw(dnssec_keys dnssec_unsigned) };
        }
        # Clear last-load flags: "new" and "changed" refer to THIS load only.
        $dbh->do("UPDATE import_zones SET new_in_last_load=0, changed_in_last_load=0 WHERE source_id=?",
                 undef, $sid) or die "db\n";
        $added = 0; $updated = 0;
        for my $z (@$zones) {
            # type is part of the zone config: master turned slave is a change, so it is in the json and the hash.
            my %cfg = map { $_ => $z->{$_} } qw(type file notify masters also_notify allow_query allow_transfer
                                                allow_update update_policy forwarders keys review split_horizon
                                                dnssec);
            $cfg{update_from} = $z->{update_from} if $z->{update_from};   # only dynamic zones: others keep their hash
            my $chash = sha256_hex(JSON->new->canonical->encode(\%cfg));
            # They are stored with the zone but are not part of its config hash: they are not a change on the old server.
            %cfg = (%cfg, %{ $was_dnssec{ lc $z->{name} } || {} }) if $z->{dnssec};
            my $json  = JSON->new->canonical->encode(\%cfg);
            my $smaster = join(',', @{ $z->{masters} || [] });
            my $review  = (@{ $z->{review} || [] } || $z->{split_horizon}) ? 1 : 0;
            # The row is NOT overwritten wholesale: status, panel_zone_id and human decisions are ours; only what the
            # file actually says comes from the file.
            my $is_new = !exists $was{ lc $z->{name} } ? 1 : 0;
            my $is_chg = (!$is_new && ($was{ lc $z->{name} } // '') ne $chash) ? 1 : 0;
            my $aff = $dbh->do("INSERT INTO import_zones
                        (source_id, zone_name, source_type, source_master, dynamic, needs_review,
                         config_hash, config_json, last_seen_at, new_in_last_load, changed_in_last_load)
                      VALUES (?,?,?,?,?,?,?,?,UTC_TIMESTAMP(),?,?)
                      ON DUPLICATE KEY UPDATE
                        source_type=VALUES(source_type), source_master=VALUES(source_master),
                        dynamic=VALUES(dynamic), needs_review=VALUES(needs_review),
                        config_hash=VALUES(config_hash), config_json=VALUES(config_json),
                        last_seen_at=UTC_TIMESTAMP(),
                        new_in_last_load=VALUES(new_in_last_load),
                        changed_in_last_load=VALUES(changed_in_last_load)",
                     undef, $sid, $z->{name}, ($z->{type} // ''), $smaster, ($z->{dynamic} ? 1 : 0),
                     $review, $chash, $json, $is_new, $is_chg);
            die "db\n" unless defined $aff;
            $added++   if $is_new;
            $updated++ if $is_chg;
        }
        1;
    } ? undef : ($@ || 'load failed');
    if (defined $err) { chomp $err; eval { $dbh->rollback }; return (undef, ($err eq 'db' ? _db_err_kind($dbh->err) : $err)); }
    unless ($dbh->commit) { my $k = _db_err_kind($dbh->err); eval { $dbh->rollback }; return (undef, $k); }

    (my $src, my $se) = import_source_get($sid);
    return (undef, $se) if $se;
    $src->{added} = $added + 0; $src->{updated} = $updated + 0;
    return ($src, undef);
}
sub import_sources_all {
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $rows, my $e) = _db_all($dbh,
        "SELECT s.id, s.master, s.zone_count, s.loaded_at,
                (SELECT COUNT(*) FROM import_zones z WHERE z.source_id=s.id AND z.status='imported') AS imported
           FROM import_sources s ORDER BY s.master", { Slice => {} });
    return (undef, $e) if $e;
    for (@$rows) { $_->{id} += 0; $_->{zone_count} += 0; $_->{imported} += 0 }
    return ($rows, undef);
}
sub import_source_get {
    my ($id) = @_;
    return (undef, 'id required') unless $id && "$id" =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $r, my $e) = _db_row($dbh, "SELECT id, master, zone_count, file_hash, loaded_at, probe_tsig FROM import_sources WHERE id=?", $id);
    return (undef, $e) if $e;
    return (undef, 'not found') unless $r;
    $r->{id} += 0; $r->{zone_count} += 0;
    return ($r, undef);
}

# Source zone list with what the panel knows about them NOW. "Already in the panel" has two meanings
# that must be told apart (migrated by us vs. lived here on its own):
#   imported            - created by THIS operation (panel_zone_id is ours and the zone exists);
#   imported_gone       - created by this operation, but the zone was since deleted;
#   exists              - a zone with this name exists, but not from us;
#   reviewed            - the human looked and decided to leave it;
#   pending             - nothing done yet;
#   failed              - an attempt failed (reason in note).
# (\%{source, zones, counts}, undef) | (undef, err).
sub import_inventory {
    my ($sid) = @_;
    (my $src, my $se) = import_source_get($sid); return (undef, $se) if $se;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $rows, my $e) = _db_all($dbh,
        "SELECT id, zone_name, source_type, source_master, dynamic, needs_review, source_serial,
                source_record_count, probed_at, probe_state, probe_error, panel_zone_id, status, note, imported_at,
                config_hash, config_json, last_seen_at, new_in_last_load, changed_in_last_load
           FROM import_zones WHERE source_id=? ORDER BY zone_name", { Slice => {} }, $sid);
    return (undef, $e) if $e;

    my %have;
    for my $d (@{ pdns_list_domains() || [] }) { $have{ lc $d->{name} } = $d }
    my ($pmap) = pdns_profile_map(map { $_->{id} } values %have);

    my (@out, %n);
    for my $r (@$rows) {
        my $d = $have{ lc $r->{zone_name} };
        my $cfg = eval { JSON->new->decode($r->{config_json} // '{}') } || {};
        _import_cfg_public($cfg);
        my $state = $r->{status};
        if ($r->{status} eq 'imported') { $state = $d ? 'imported' : 'imported_gone' }
        elsif ($d && $r->{status} eq 'pending') { $state = 'exists' }
        # Zone gone from the fresh export: not deleted here (a migrated zone lives on), but no longer shown as
        # still present on the old server.
        my $gone = (($r->{last_seen_at} // '') lt ($src->{loaded_at} // '')) ? 1 : 0;
        my @masters = grep { length } split /\s*,\s*/, ($r->{source_master} // '');
        # Only AXFR-migratable zones are selectable: hint/forward/stub and multiply-defined names stay visible
        # but cannot be selected.
        my $importable = ($BIND_ZONE_IMPORTABLE{ $r->{source_type} // '' } && !$cfg->{split_horizon}) ? 1 : 0;
        push @out, {
            id => $r->{id} + 0, name => $r->{zone_name},
            kind => zone_kind($r->{zone_name}),   # forward | reverse4 | reverse6, as in Zones
            type => $r->{source_type}, role => ($r->{source_type} =~ /^(slave|secondary)$/ ? 'slave' : 'master'),
            importable => $importable,
            masters => \@masters, dynamic => $r->{dynamic} + 0, needs_review => $r->{needs_review} + 0,
            source_serial => $r->{source_serial}, source_records => $r->{source_record_count},
            probe_state => $r->{probe_state}, probe_error => $r->{probe_error}, probed_at => $r->{probed_at},
            state => $state, status => $r->{status}, note => $r->{note}, gone => $gone,
            is_new => $r->{new_in_last_load} + 0, changed => $r->{changed_in_last_load} + 0,
            dnssec => ($cfg->{dnssec} ? 1 : 0),
            imported_at => $r->{imported_at}, last_seen_at => $r->{last_seen_at},
            config => $cfg,
            panel => ($d ? { id => $d->{id} + 0, type => lc($d->{type} // ''), serial => $d->{soa_serial},
                             records => ($d->{record_count} // 0) + 0, master => $d->{master},
                             profile => ($pmap ? $pmap->{ $d->{id} } : undef),
                             ours => ($r->{panel_zone_id} && $r->{panel_zone_id} == $d->{id}) ? 1 : 0 } : undef),
        };
        $n{ $state }++;
        $n{gone}++ if $gone;
        $n{is_new}++  if $r->{new_in_last_load};
        $n{changed}++ if $r->{changed_in_last_load};
        $n{dnssec}++  if $cfg->{dnssec};
        $n{dynamic}++ if $r->{dynamic};
        $n{review}++  if $r->{needs_review};
    }
    $n{total} = scalar @out;
    return ({ source => $src, zones => \@out, counts => \%n }, undef);
}

# Human decision on a row: "reviewed, leave it" and back. Changes nothing in DNS.
sub import_zone_mark {
    my ($id, $status, $note) = @_;
    return (undef, 'id required') unless $id && "$id" =~ /^\d+$/;
    return (undef, 'unknown status') unless ($status // '') =~ /^(pending|reviewed)$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $nt, my $ne) = _check_len($note, 'note', 255, 0); return (undef, $ne) if $ne;
    (my $ok, my $e) = _do($dbh, "UPDATE import_zones SET status=?, note=? WHERE id=? AND status IN ('pending','reviewed')",
                          $status, $nt, $id);
    return (undef, $e) if $e;
    return (1, undef);
}

# ---- Probing the old server: Source serial / Source records / Diff (docs/26) ----
# Asks the import SOURCE server (import_sources.master), for slave zones too: what it serves is compared.
# Probe = AXFR via dns-agent (axfr_at), giving the SOA serial and record count. Hundreds of AXFRs would
# hold one HTTP request for minutes, so "Probe" only queues zones (probe_state=queued) and the worker
# processes a batch per pass (settings.import.probe_batch). Results live in import_zones.
# Diff is per zone, on demand: live AXFR from the source vs. our zone in PowerDNS, per RRset. Display only,
# never merges. Both sides are normalized alike: names (including in CNAME/NS/PTR/MX/SRV data) lowercase
# without the dot, whitespace collapsed (except TXT), MX/SRV priority in the data. DNSSEC records
# (RRSIG/NSEC/DNSKEY...) are skipped: we cannot have them, and they would drown real differences.
my %RR_NAME_FIELDS = (CNAME => [0], NS => [0], PTR => [0], DNAME => [0], MX => [1], SRV => [3], SOA => [0, 1]);
my %RR_SKIP = map { $_ => 1 } qw(RRSIG NSEC NSEC3 NSEC3PARAM DNSKEY CDS CDNSKEY TYPE65534);
sub _rr_name { (my $n = lc($_[0] // '')) =~ s/\.$//; return $n eq '' ? '.' : $n }
sub _rr_rdata {
    my ($type, $rd) = @_;
    $rd = _trim($rd) // '';
    return $rd if $type eq 'TXT' || $type eq 'SPF';
    my @f = split ' ', $rd;
    for my $i (@{ $RR_NAME_FIELDS{$type} || [] }) { $f[$i] = _rr_name($f[$i]) if defined $f[$i] && $f[$i] ne '.'; }
    return join(' ', @f);
}
sub _rrset_add {
    my ($sets, $name, $type, $ttl, $rd) = @_;
    my $k = "$name $type";
    my $s = $sets->{$k} ||= { name => $name, type => $type, ttl => $ttl, rdata => {} };
    $s->{ttl} = $ttl if $ttl < $s->{ttl};
    $s->{rdata}{ _rr_rdata($type, $rd) } = 1;
}
# AXFR lines (dig) -> ({ "name TYPE" => {name,type,ttl,rdata{}} }, serial, record count).
sub _axfr_rrsets {
    my ($lines) = @_;
    my (%sets, $serial);
    my @l = @{ $lines || [] };
    # AXFR starts and ends with SOA; do not count the second one.
    pop @l if @l > 1 && ($l[-1] =~ /^\S+\s+\d+\s+IN\s+SOA\s/i);
    for my $line (@l) {
        my ($n, $ttl, $cls, $type, $rd) = split /\s+/, $line, 5;
        next unless defined $type;
        $type = uc $type;
        $serial //= (split ' ', $rd // '')[2] if $type eq 'SOA';
        next if $RR_SKIP{$type};
        _rrset_add(\%sets, _rr_name($n), $type, $ttl + 0, $rd);
    }
    return (\%sets, $serial, scalar @l);
}
sub _pdns_rrsets {
    my ($domain_id) = @_;
    my $pdns = connectPDNS() or return (undef, 'DB unavailable');
    (my $rows, my $e) = _db_all($pdns, "SELECT name, type, content, ttl, prio FROM records
                                          WHERE domain_id=? AND disabled=0 AND type IS NOT NULL AND type<>''", { Slice => {} }, $domain_id);
    return (undef, $e) if $e;
    my (%sets, $serial);
    for my $r (@$rows) {
        my $type = uc $r->{type};
        next if $RR_SKIP{$type};
        my $c = $r->{content} // '';
        $c = "$r->{prio} $c" if ($type eq 'MX' || $type eq 'SRV') && defined $r->{prio} && $c !~ /^\d+\s/;
        $serial = (split ' ', $c)[2] if $type eq 'SOA';
        _rrset_add(\%sets, _rr_name($r->{name}), $type, ($r->{ttl} // 0) + 0, $c);
    }
    return (\%sets, undef, $serial);
}
# Key for signing the probe: the same existing key chosen for the migration, otherwise
# Import takes the zone while Probe says "no transfer". The secret comes from PowerDNS, as for the
# migration AXFR. Empty name -> unsigned. ({name, algorithm, secret}|undef, undef) | (undef, err).
sub _probe_key {
    my ($name) = @_;
    $name = _trim($name);
    return (undef, undef) unless defined $name && length $name;
    my $pdns = connectPDNS() or return (undef, 'DB unavailable');
    (my $k, my $e) = _db_row($pdns, "SELECT name, algorithm, secret FROM tsigkeys WHERE name=?", $name);
    return (undef, $e) if $e;
    return (undef, "TSIG key '$name' is not in PowerDNS") unless $k;
    return ($k, undef);
}
# Queue source zones for probing ($names: only these; otherwise all migratable ones still at the source).
# $tsig: key name for signing, remembered on the source for the worker. ({queued}, undef) | (undef, err).
sub import_probe_queue {
    my ($sid, $names, $tsig) = @_;
    (my $src, my $se) = import_source_get($sid); return (undef, $se) if $se;
    (my $key, my $ke) = _probe_key($tsig); return (undef, $ke) if $ke;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (undef, my $te) = _do($dbh, "UPDATE import_sources SET probe_tsig=? WHERE id=?", ($key ? $key->{name} : undef), $sid);
    return (undef, $te) if $te;
    my @types = sort keys %BIND_ZONE_IMPORTABLE;
    my $sql = "UPDATE import_zones SET probe_state='queued', probe_error=NULL
                WHERE source_id=? AND source_type IN (" . join(',', ('?') x @types) . ") AND last_seen_at >= ?";
    my @b = ($sid, @types, $src->{loaded_at});
    if (ref $names eq 'ARRAY' && @$names) { $sql .= " AND zone_name IN (" . join(',', ('?') x @$names) . ")"; push @b, @$names; }
    my $n = $dbh->do($sql, undef, @b);
    return (undef, _db_err_kind($dbh->err)) unless defined $n;
    sync_wake();
    return ({ queued => ($n eq '0E0' ? 0 : $n + 0) }, undef);
}
# How many zones wait for a probe. ($n, undef) | (undef, err).
sub import_probe_queued {
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $r, my $e) = _db_row($dbh, "SELECT COUNT(*) AS n FROM import_zones WHERE probe_state='queued'");
    return (undef, $e) if $e;
    return ($r->{n} + 0, undef);
}
# Worker pass: up to $limit queued zones, at most import.probe_budget_seconds, so an unreachable source
# does not delay other worker tasks; the rest waits for the next pass (also when the agent fails).
# No response at all (timeout, no route) is about the server: all its queued zones get that reason at
# once instead of a timeout each. Same for a rejected key (one key per source). Other rcode failures
# (REFUSED...) are per zone. ({probed, ok, failed}, undef) | (undef|{...}, err).
sub import_probe_run {
    my ($limit) = @_;
    $limit //= setting('import.probe_batch');
    $limit = 50 unless $limit && "$limit" =~ /^\d+$/ && $limit > 0;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $rows, my $e) = _db_all($dbh, "SELECT z.id, z.source_id, z.zone_name, s.master, s.probe_tsig FROM import_zones z
                                           JOIN import_sources s ON s.id = z.source_id
                                         WHERE z.probe_state='queued' ORDER BY z.id LIMIT $limit", { Slice => {} });
    return (undef, $e) if $e;
    my %n = (probed => 0, ok => 0, failed => 0);
    my (%down, %key, $we);
    my $until = time + setting('import.probe_budget_seconds');
    for my $r (@$rows) {
        last if time >= $until;
        next if $down{ $r->{source_id} };
        # Key gone from PowerDNS: about the source, like "no response" - the reason goes to all its queued zones.
        (my $k, my $ke) = exists $key{ $r->{source_id} } ? ($key{ $r->{source_id} }) : _probe_key($r->{probe_tsig});
        return (\%n, $ke) if $ke && $ke =~ /^DB /;
        $key{ $r->{source_id} } = $k;
        my $ax = $ke ? { ok => 0, error => $ke }
                     : dns_agent_call('axfr_at', zone => $r->{zone_name}, server => $r->{master}, ($k ? (key => $k) : ()));
        return (\%n, 'dns-agent is unreachable: ' . _agent_why($ax)) if $ax->{_unreachable};
        if ($ax->{ok}) {
            (undef, my $serial, my $count) = _axfr_rrsets($ax->{records});
            (undef, $we) = _do($dbh, "UPDATE import_zones SET probe_state='ok', probe_error=NULL, source_serial=?, source_record_count=?,
                                       probed_at=UTC_TIMESTAMP() WHERE id=?", $serial, $count, $r->{id});
            return (\%n, "cannot save the probe of $r->{zone_name}: $we") if $we;
            $n{ok}++; $n{probed}++;
        } elsif ($ax->{status} && !$ax->{tsig_rejected}) {
            (undef, $we) = _do($dbh, "UPDATE import_zones SET probe_state='failed', probe_error=?, probed_at=UTC_TIMESTAMP() WHERE id=?",
                               substr(_agent_why($ax), 0, 255), $r->{id});
            return (\%n, "cannot save the probe of $r->{zone_name}: $we") if $we;
            $n{failed}++; $n{probed}++;
        } else {
            $down{ $r->{source_id} } = 1;
            my $cnt = $dbh->do("UPDATE import_zones SET probe_state='failed', probe_error=?, probed_at=UTC_TIMESTAMP()
                               WHERE source_id=? AND probe_state='queued'", undef,
                             substr(($ke || $ax->{status} ? '' : "$r->{master} did not answer: ") . _agent_why($ax), 0, 255), $r->{source_id});
            return (\%n, "cannot save the probe of source $r->{master}: " . _db_err_kind($dbh->err)) unless defined $cnt;
            $cnt = 0 if $cnt eq '0E0';
            $n{failed} += $cnt; $n{probed} += $cnt;
        }
    }
    return (\%n, undef);
}
# Diff of a listed zone against our zone of the same name; also updates the row's Source serial/records.
# ({zone, source, source_serial, our_serial, source_records, rows[{name,type,status,old,panel}], counts}, undef) | (undef, err).
sub import_zone_diff {
    my ($iz_id, $tsig) = @_;
    return (undef, 'invalid id') unless $iz_id && "$iz_id" =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $r, my $e) = _db_row($dbh, "SELECT z.id, z.zone_name, s.master FROM import_zones z JOIN import_sources s ON s.id = z.source_id
                                     WHERE z.id=?", $iz_id);
    return (undef, $e) if $e;
    return (undef, 'not found') unless $r;
    my $d = pdns_get_domain_by_name($r->{zone_name}) or return (undef, 'the zone is not in the panel — there is nothing to compare with');
    (my $key, my $ke) = _probe_key($tsig); return (undef, $ke) if $ke;
    my $ax = dns_agent_call('axfr_at', zone => $r->{zone_name}, server => $r->{master}, ($key ? (key => $key) : ()));
    return (undef, 'the source server did not give the zone: ' . _agent_why($ax)) unless $ax->{ok};
    (my $src, my $sserial, my $count) = _axfr_rrsets($ax->{records});
    # Incidental row update: if it fails, the diff is still shown.
    _do($dbh, "UPDATE import_zones SET probe_state='ok', probe_error=NULL, source_serial=?, source_record_count=?,
                      probed_at=UTC_TIMESTAMP() WHERE id=?", $sserial, $count, $r->{id});
    (my $our, my $oe, my $oserial) = _pdns_rrsets($d->{id}); return (undef, $oe) if $oe;
    # One row per name+type: old server left, panel right, status. Equal rows are rows too (hidden by default
    # on screen): "same" is an answer like "different". SOA is compared whole (MNAME, RNAME, timers, TTL)
    # except serial, shown in the header - otherwise every zone edited after the export would differ.
    my $side = sub { my ($s) = @_; return $s ? { ttl => $s->{ttl}, values => [ sort keys %{ $s->{rdata} } ] } : undef };
    my $cmp = sub { my ($s) = @_; return join("\n", sort map { my @f = split ' '; $f[2] = '-' if $s->{type} eq 'SOA' && @f > 2; join(' ', @f) } keys %{ $s->{rdata} }) };
    my (@rows, %n);
    my %keys = map { $_ => 1 } keys %$src, keys %$our;
    for my $k (keys %keys) {
        my ($s, $o) = ($src->{$k}, $our->{$k});
        my $st = !$o ? 'old_only' : !$s ? 'panel_only'
               : $cmp->($s) ne $cmp->($o) ? 'differs' : $s->{ttl} != $o->{ttl} ? 'ttl' : 'same';
        $n{$st}++;
        my $x = $s || $o;
        push @rows, { name => $x->{name}, type => $x->{type}, status => $st, old => $side->($s), panel => $side->($o) };
    }
    # Zone order: apex first (SOA, NS), then names compared right to left so subtrees stay together;
    # numeric labels compare as numbers (15 before 100 in a reverse zone).
    my $zn = _rr_name($r->{zone_name});
    my %tord = (SOA => 0, NS => 1);
    my $ncmp = sub {
        my @a = reverse split /\./, $_[0]; my @b = reverse split /\./, $_[1];
        for my $i (0 .. ($#a < $#b ? $#a : $#b)) {
            my $c = ($a[$i] =~ /^\d+$/ && $b[$i] =~ /^\d+$/) ? $a[$i] <=> $b[$i] : $a[$i] cmp $b[$i];
            return $c if $c;
        }
        return @a <=> @b;
    };
    @rows = sort { ($a->{name} ne $zn) <=> ($b->{name} ne $zn) || $ncmp->($a->{name}, $b->{name})
                   || ($tord{ $a->{type} } // 9) <=> ($tord{ $b->{type} } // 9) || $a->{type} cmp $b->{type} } @rows;
    return ({ zone => $r->{zone_name}, source => $r->{master}, source_serial => $sserial, our_serial => $oserial,
              source_records => $count, rows => \@rows, counts => { map { $_ => ($n{$_} // 0) } qw(same differs ttl old_only panel_only) } }, undef);
}

# What the panel remembers about a migration: see the comment at zone_import_apply.
our $IMPORT_META  = 'X-DNSPANEL-IMPORT';
our $DYNAMIC_META = 'X-DNSPANEL-IMPORT-DYNAMIC';
# The zone was signed on the old server (auto-dnssec/inline-signing): Make primary needs its private keys
# (or the "import unsigned" choice), otherwise it is refused.
our $DNSSEC_META  = 'X-DNSPANEL-IMPORT-DNSSEC';

# The panel remembers exactly three facts about a migration, all its own, not pieces of foreign config:
#   X-DNSPANEL-IMPORT          - export server address: the zone came via migration and is STILL a mirror.
#                                Absent for zones that were secondary on the old server too: nothing to
#                                finish there, we just slave a foreign zone ourselves.
#   X-DNSPANEL-IMPORT-DYNAMIC  - the old server accepted RFC 2136 updates for the zone. Visible ONLY when
#                                parsing the file; promoting without accepting updates would silently cut
#                                off DHCP, so Make primary requires Dynamic updates and clears the marker -
#                                from then on the zone's own flag is the source of truth.
#   X-DNSPANEL-IMPORT-DNSSEC   - the zone was signed: Make primary carries its keys over.
# All three are cleared by Make primary.
# EVERYTHING the migration needs comes from the stored list by source_id: export address, zone type, its
# own masters, flags. The browser sends names only - it need not know these facts and could forge them.
sub zone_import_apply {
    my ($names, $opts) = @_;
    $opts ||= {};
    return (undef, 'no zones selected') unless ref $names eq 'ARRAY' && @$names;
    return (undef, 'too many zones in one request — split it') if @$names > 200;
    my $pdns = connectPDNS() or return (undef, 'DB unavailable');
    # The new key is the only thing besides zones this creates, so it is made after all shared checks:
    # earlier, a typo in the profile left an unreferenced key in the panel and in PowerDNS.
    my $new = _import_tsig_asked($opts);
    return (undef, 'choose either an existing TSIG key or a new one, not both')
        if $new && defined _trim($opts->{tsig}) && length _trim($opts->{tsig});
    # The source address comes from the stored source row, not the browser: otherwise a request could
    # create a zone "from a convenient server" and the migration marker would point elsewhere.
    my $sid = $opts->{source_id};
    return (undef, 'source_id is required') unless $sid && "$sid" =~ /^\d+$/;
    (my $src, my $se) = import_source_get($sid); return (undef, $se) if $se;
    my $export = $src->{master};
    # Export address and key are validated ONCE, by the same function as a zone source change.
    (my $mref, my $tsig, my $fe) = _secondary_source_fields($pdns, { masters => [ $export ],
                                                                     tsig => ($new ? '' : $opts->{tsig}) });
    return (undef, $fe) if $fe;
    # What the zone was on the old server (dynamic, signed, migratable) the panel knows ITSELF from the
    # stored list; a browser-supplied flag could be forgotten, and the marker would then be missing.
    my (%dyn, %known);
    {
        my $dbh = connectDB() or return (undef, 'DB unavailable');
        (my $rows, my $le) = _db_all($dbh,
            "SELECT zone_name, source_type, source_master, dynamic, config_json, last_seen_at
               FROM import_zones WHERE source_id=?", { Slice => {} }, $sid);
        return (undef, $le) if $le;
        $known{ lc $_->{zone_name} } = _import_zone_facts($src, $_) for @$rows;
    }

    # Everything shared is checked and read; only now create the key. Earlier, a DB failure at this point
    # left an orphan key in the panel and PowerDNS that was never cleaned up.
    my $made;
    if ($new) { (my $m, my $ne) = _tsig_key_new($new); return (undef, $ne) if $ne; $made = $m; $tsig = $made->{name}; }

    my (@ok, @failed, @skipped);
    for my $raw (@$names) {
        my ($name, $nerr) = dns_validate_zonename($raw);
        if ($nerr) { push @failed, { name => $raw, error => $nerr }; next }
        # A zone not in this list (or not migratable) is not created: taking a name past the list means
        # creating a zone blindly.
        my $k = $known{ lc $name };
        unless ($k) { push @failed, { name => $name, error => 'not in the loaded configuration of this source' }; next }
        unless ($k->{importable}) {
            _import_zone_result($sid, $name, undef, 'zone type cannot be migrated');
            push @failed, { name => $name, error => 'this zone type cannot be migrated' }; next;
        }
        if ($k->{gone}) {
            push @failed, { name => $name, error => 'the last load of this source no longer has this zone' }; next;
        }
        $dyn{$name} = 1 if $k->{dynamic};

        (my $zmref, my $zt, my $note, my $me) = _import_upstream($pdns, $k, $mref, $tsig);
        if ($me) { _import_zone_result($sid, $name, undef, $me); push @failed, { name => $name, error => $me }; next }

        if (pdns_get_domain_by_name($name)) { push @skipped, $name; next }
        # A migrated zone gets no profile: a profile presets SOA/NS of OUR primaries, while a secondary gets
        # everything via AXFR (and one profile per batch would be wrong - one export mixes brands). Origin and
        # dynamic/signed flags are written IN THE SAME transaction as the zone: there is no later chance to learn
        # them, and a zone without the marker would silently drop out of migration completion. The migration
        # marker means an UNFINISHED state ("still mirroring the export server"); a zone that was secondary on
        # the old server too has nothing to finish.
        my $id = pdns_create_zone($name, { role => 'secondary',
                                           masters => $zmref, tsig => $zt,
                                           renotify => ($opts->{renotify} ? 1 : 0),
                                           metas => [ [ $IMPORT_META, ($k->{slave} ? undef : $export) ],
                                                      [ $DYNAMIC_META, ($dyn{$name} ? '1' : undef) ],
                                                      [ $DNSSEC_META,  ($k->{dnssec} ? '1' : undef) ] ] });
        unless ($id) {
            _import_zone_result($sid, $name, undef, 'create failed');
            push @failed, { name => $name, error => 'create failed' }; next;
        }
        # The list is the migration's memory: it shows tomorrow that WE created this zone. If it cannot be
        # written, the zone is removed - otherwise it would look "native", and for a zone the old server itself
        # slaved there is no marker to recover the origin from. PowerDNS does not know the zone yet (rediscover
        # runs after the loop), so removing it is a clean rollback.
        if (my $ie = _import_zone_result($sid, $name, $id, $note)) {
            my $ue = _zone_insert_undo($id);
            push @failed, { name => $name, ($ue ? (id => $id + 0) : ()),
                            error => "the import list was not updated ($ie), so the zone was not kept"
                                   . ($ue ? " — and removing it failed ($ue); delete it by hand" : '') };
            next;
        }
        if (my $dn = _import_dynamic_seed($id, $k->{update_from})) {
            $note = join '; ', grep { defined } $note, $dn;
            _import_zone_result($sid, $name, $id, $note);
        }
        # masters and tsig are the ACTUAL ones the zone was created with; history is written from them, so a
        # zone taken from foreign masters must not show the export key it does not have.
        push @ok, { name => $name, id => $id + 0,
                    masters => $zmref, tsig => $zt, ($k->{slave} ? (kept_secondary => 1) : ()),
                    ($note ? (note => $note) : ()), ($dyn{$name} ? (dynamic => 1) : ()) };
    }
    # PowerDNS learns new zones by ONE rediscover for the batch, then an AXFR retrieve per zone. Nothing waits:
    # the worker watches arrival. If the agent fails (rediscover or a retrieve hits its unavailability), the
    # remaining zones get transfer_problem immediately - otherwise fifty zones would wait fifty timeouts in one
    # HTTP request; the worker finishes them. Import ends here with Secondary zones; they are promoted later
    # (Zone settings -> Make primary) once the AXFR has arrived.
    if (@ok) {
        my $rd = dns_agent_call('rediscover');
        my $down = ($rd->{ok} && !$rd->{_unreachable}) ? undef : 'PowerDNS did not re-read its zones: ' . _agent_why($rd);
        for my $z (@ok) {
            my $sync = zone_activate_after_create($z->{id}, $down ? { problem => $down } : { rediscovered => 1 });
            $down = $sync->{detail} if $sync->{unreachable};
            $z->{pdns_state} = $sync->{pdns_state} // 'unknown';
        }
    }

    # A key created here is ALWAYS checked, not only when no zone was created: a batch of foreign secondary
    # zones uses their own masters, the form key is not set on them, and it would stay an orphan. The cleanup
    # itself decides from real references (group/node bindings, zone metadata) and never removes a key in use.
    # The outcome is reported as FACT: if PowerDNS is down the key remains, and saying "it is gone" would hide
    # exactly the orphan the cleanup is for.
    my ($removed, $twarn);
    if ($made) {
        (my $gone, my $ge) = tsig_keys_forget_unused($made->{id});
        if (@{ $gone || [] }) { $removed = 1 }
        elsif ($ge) { $twarn = "the new TSIG key '$made->{name}' is not used by any zone, and removing it failed: $ge" }
    }
    return ({ source => $export, created => \@ok, failed => \@failed, skipped => \@skipped,
              ($made    ? (tsig_created => $made) : ()),
              ($removed ? (tsig_removed => 1)     : ()),
              ($twarn   ? (tsig_warning => $twarn) : ()) }, undef);
}
# Remove a just-created zone PowerDNS does NOT know yet (no rediscover): its rows in one transaction.
# Not zone_delete_everywhere - that makes PowerDNS stop serving the zone, which it never served.
# undef - removed, otherwise the reason.
sub _zone_insert_undo {
    my ($id) = @_;
    my $pdns = connectPDNS() or return 'DB unavailable';
    my $ok = eval {
        $pdns->begin_work;
        for my $t (qw(domainmetadata records)) { $pdns->do("DELETE FROM $t WHERE domain_id=?", undef, $id) or die "$t\n" }
        $pdns->do("DELETE FROM domains WHERE id=?", undef, $id) or die "domains\n";
        $pdns->commit or die "commit\n"; 1;
    };
    return undef if $ok;
    my $e = $@ || 'error'; chomp $e; eval { $pdns->rollback }; return "delete $e failed";
}
# Copy from Compare: selected source RRsets -> into the panel zone, whole (name+type); the zone keeps its
# role. The browser sends only keys (name, type); content comes from a live AXFR of the source, not from
# what the screen showed. Apex SOA and NS are not copied - they are the zone's own structure. The caller
# writes via pdns_apply_rrsets (same path as record edits: one transaction, one serial bump, CNAME/apex checks).
# ({zone_id, zone, ops[]}, undef) | (undef, err).
sub import_zone_copy_ops {
    my ($iz_id, $keys, $tsig) = @_;
    return (undef, 'invalid id') unless $iz_id && "$iz_id" =~ /^\d+$/;
    return (undef, 'choose the record sets to copy') unless ref $keys eq 'ARRAY' && @$keys;
    return (undef, 'too many record sets in one request — split it') if @$keys > 2000;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $r, my $e) = _db_row($dbh, "SELECT z.zone_name, s.master FROM import_zones z JOIN import_sources s ON s.id = z.source_id
                                     WHERE z.id=?", $iz_id);
    return (undef, $e) if $e;
    return (undef, 'not found') unless $r;
    my $d = pdns_get_domain_by_name($r->{zone_name}) or return (undef, 'the zone is not in the panel — import it as usual');
    return (undef, 'the current zone is a secondary — its records come by AXFR and cannot be edited here')
        if uc($d->{type} // '') eq 'SLAVE';
    (my $key, my $ke) = _probe_key($tsig); return (undef, $ke) if $ke;
    my $ax = dns_agent_call('axfr_at', zone => $r->{zone_name}, server => $r->{master}, ($key ? (key => $key) : ()));
    return (undef, 'the source server did not give the zone: ' . _agent_why($ax)) unless $ax->{ok};
    # Raw AXFR lines keyed "name TYPE" (same key as Compare), data as is: trailing dots and TXT quotes, the
    # form PowerDNS stores. MX/SRV priority as a separate field, as in the panel.
    my %set;
    my $zn = _rr_name($r->{zone_name});
    for my $line (@{ $ax->{records} || [] }) {
        my ($n, $ttl, $cls, $type, $rd) = split /\s+/, $line, 5;
        next unless defined $rd;
        $type = uc $type;
        next if $type eq 'SOA' || $RR_SKIP{$type};
        my $k = _rr_name($n) . " $type";
        my $s = $set{$k} ||= { name => $n, type => $type, ttl => $ttl + 0, records => [], seen => {} };
        $s->{ttl} = $ttl + 0 if $ttl < $s->{ttl};
        $rd = _trim($rd) // '';
        next if $s->{seen}{$rd}++;
        my $prio;
        ($prio, $rd) = ($1, $2) if ($type eq 'MX' || $type eq 'SRV') && $rd =~ /^(\d+)\s+(.+)$/;
        push @{ $s->{records} }, { content => $rd, prio => $prio, disabled => 0 };
    }
    my (@ops, %dup);
    for my $k (@$keys) {
        my $type = uc($k->{type} // ''); my $nk = _rr_name($k->{name});
        return (undef, 'SOA is not copied — it belongs to the zone itself') if $type eq 'SOA';
        return (undef, 'NS of the zone apex is not copied — it belongs to the zone itself') if $type eq 'NS' && $nk eq $zn;
        next if $dup{"$nk $type"}++;
        my $s = $set{"$nk $type"} or return (undef, "$nk $type is no longer on the source server");
        push @ops, { name => $s->{name}, type => $type, ttl => $s->{ttl}, changetype => 'REPLACE', records => $s->{records} };
    }
    return ({ zone_id => $d->{id} + 0, zone => $r->{zone_name}, ops => \@ops }, undef);
}
# "Use old server version": the zone ALREADY exists in the panel and the human chose the old server's
# version. Same result as a regular migration: a Secondary from where Import would take it, with the same
# markers, promoted later in Zone settings. Our records are replaced by what arrives via AXFR:
#   Primary   - Make secondary (records wiped, catalog removed - as the button does);
#   Secondary - only the source changes, AXFR is requested immediately.
# $opts: { tsig => key name for the export server }.
# ({zone, id, masters, tsig, note?, catalog_removed, tsig_released, warnings}, undef) | (undef, err).
sub import_zone_take {
    my ($iz_id, $opts) = @_;
    $opts ||= {};
    return (undef, 'invalid id') unless $iz_id && "$iz_id" =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $r, my $e) = _db_row($dbh, "SELECT id, source_id, zone_name, source_type, source_master, dynamic, config_json,
                                           last_seen_at, panel_zone_id, status FROM import_zones WHERE id=?", $iz_id);
    return (undef, $e) if $e;
    return (undef, 'not found') unless $r;
    (my $src, my $se) = import_source_get($r->{source_id}); return (undef, $se) if $se;
    my $k = _import_zone_facts($src, $r);
    return (undef, 'this zone type cannot be migrated') unless $k->{importable};
    return (undef, 'the last load of this source no longer has this zone') if $k->{gone};
    my $d = pdns_get_domain_by_name($r->{zone_name}) or return (undef, 'the zone is not in the panel — import it as usual');
    return (undef, 'this zone was already imported from this server')
        if $r->{status} eq 'imported' && $r->{panel_zone_id} && $r->{panel_zone_id} == $d->{id};
    my $pdns = connectPDNS() or return (undef, 'DB unavailable');
    (my $mref, my $tsig, my $fe) = _secondary_source_fields($pdns, { masters => [ $src->{master} ], tsig => $opts->{tsig} });
    return (undef, $fe) if $fe;
    (my $masters, my $zt, my $note, my $ue) = _import_upstream($pdns, $k, $mref, $tsig);
    return (undef, $ue) if $ue;

    my $type = uc($d->{type} // '');
    my ($res, $err);
    if ($type eq 'SLAVE') {
        ($res, $err) = zone_secondary_source_set($d->{id}, { masters => $masters, tsig => $zt });
        return (undef, $err) if $err;
        my $rf = zone_secondary_refresh($r->{zone_name});
        push @{ $res->{warnings} }, $rf->{error} unless $rf->{requested};
    } else {
        ($res, $err) = zone_demote_to_secondary($d->{id}, { masters => $masters, tsig => $zt });
        return (undef, $err) if $err;
    }
    # Role already changed; only markers remain. On failure: a warning, not an error - nothing to roll back.
    push @{ $res->{warnings} }, 'the import markers were not set on the zone'
        unless pdns_set_zone_metas($d->{id}, [ [ $IMPORT_META, ($k->{slave} ? undef : $src->{master}) ],
                                               [ $DYNAMIC_META, ($k->{dynamic} ? '1' : undef) ],
                                               [ $DNSSEC_META,  ($k->{dnssec} ? '1' : undef) ] ]);
    if (my $dn = _import_dynamic_seed($d->{id}, $k->{update_from})) { $note = join '; ', grep { defined } $note, $dn; }
    if (my $ie = _import_zone_result($r->{source_id}, $r->{zone_name}, $d->{id}, $note)) {
        push @{ $res->{warnings} }, "the import list was not updated: $ie";
    }
    return ({ zone => $r->{zone_name}, id => $d->{id} + 0, was => $type, masters => $masters, tsig => $zt,
              ($note ? (note => $note) : ()), catalog_removed => ($res->{catalog_removed} ? 1 : 0),
              tsig_released => $res->{tsig_released}, warnings => $res->{warnings} || [] }, undef);
}
# What the panel knows about a zone from the stored list - same for a new migration and a replacement.
sub _import_zone_facts {
    my ($src, $r) = @_;
    my $cfg = eval { JSON->new->decode($r->{config_json} // '{}') } || {};
    my $type = lc($r->{source_type} // '');
    return {
        type    => $type,
        slave   => ($type =~ /^(slave|secondary)$/) ? 1 : 0,
        masters => [ grep { length } split /\s*,\s*/, ($r->{source_master} // '') ],
        keys    => [ grep { length } @{ (ref $cfg->{keys} eq 'ARRAY' ? $cfg->{keys} : []) } ],
        dynamic => ($r->{dynamic} ? 1 : 0),
        dnssec  => ($cfg->{dnssec} ? 1 : 0),
        update_from => (ref $cfg->{update_from} eq 'HASH' ? $cfg->{update_from} : undef),
        importable => ($BIND_ZONE_IMPORTABLE{$type} && !$cfg->{split_horizon}) ? 1 : 0,
        # A zone missing from this source's latest load no longer exists on the old server: mirroring it
        # means subscribing to an AXFR that will never come.
        gone => (($r->{last_seen_at} // '') lt ($src->{loaded_at} // '')) ? 1 : 0,
    };
}
# WHERE the zone will be pulled from depends on what it was on the old server:
#   its master/primary - from IT ($mref/$tsig: export address and form key), it owns the zone;
#   its slave/secondary - from the SAME masters it used: it was just a mirror like us. Using the export
#   server here keeps the zone fresh only until it is switched off, then it silently freezes (44 of 50
#   zones on the live pair).
# (\@masters, $tsig, $note, undef) | (undef, undef, undef, err).
sub _import_upstream {
    my ($pdns, $k, $mref, $tsig) = @_;
    my (@src_masters, $zone_tsig, $note);
    if ($k->{slave}) {
        @src_masters = @{ $k->{masters} };
        return (undef, undef, undef, 'the source server does not say where it pulls this secondary from') unless @src_masters;
        # The form key is for the EXPORT SERVER and does not fit a foreign master. The key this zone used for
        # its master is taken if PowerDNS has one of that name; otherwise it must be said: without it, AXFR from a
        # master that requires one will fail.
        $zone_tsig = '';
        my @keys = @{ $k->{keys} };
        if (@keys == 1 && (_db_exists($pdns, "SELECT 1 FROM tsigkeys WHERE name=?", $keys[0]))[0]) { $zone_tsig = $keys[0] }
        elsif (@keys) { $note = 'TSIG key required: ' . join(', ', @keys) . ' — add it in zone settings' }
    } else {
        @src_masters = @$mref;
        $zone_tsig   = $tsig;
    }
    (my $zmref, my $zt, my $me) = _secondary_source_fields($pdns, { masters => \@src_masters, tsig => $zone_tsig });
    return (undef, undef, undef, $me) if $me;
    return ($zmref, $zt, $note, undef);
}
# Who may update the zone, taken from the old server's allow-update, so the settings are on the zone from the
# start (a secondary only keeps them; Make primary turns them on). A Dynamic DHCP profile holding one of the
# old keys is followed; otherwise the zone gets the addresses and the key - taken from the export when it
# defines it, else a panel key of the same name; a key found nowhere is named in the note. A zone that already has
# settings keeps them. Returns a note or undef.
sub _import_dynamic_seed {
    my ($domain_id, $u) = @_;
    return undef unless ref $u eq 'HASH';
    my $dbh = connectDB() or return 'dynamic updates: DB unavailable';
    (my $has, my $he) = _db_exists($dbh, "SELECT 1 FROM zone_dynamic WHERE domain_id=?", $domain_id);
    return "dynamic updates: $he" if $he;
    return undef if $has;
    my @keys = @{ $u->{keys} || [] };
    my $in = join ',', ('?') x @keys;
    my ($pid, $s, $made, @missing, @n);
    if (@keys) {
        (my $p, my $pe) = _db_row($dbh, "SELECT pk.profile_id FROM dyn_profile_keys pk JOIN tsig_keys k ON k.id = pk.tsig_key_id
                                          WHERE k.name IN ($in) ORDER BY pk.profile_id LIMIT 1", @keys);
        return "dynamic updates: $pe" if $pe;
        $pid = $p->{profile_id} if $p;
    }
    if ($pid) {
        (my $c, my $ce) = _dyn_cidrs_of($dbh, 'dyn_profile_sources', 'profile_id', $pid); return "dynamic updates: $ce" if $ce;
        (my $k, my $ke) = _dyn_key_of($dbh, 'dyn_profile_keys', 'profile_id', $pid);      return "dynamic updates: $ke" if $ke;
        $s = { mode => _dyn_mode_of(scalar @$c, $k ? 1 : 0), cidrs => $c, key_id => ($k ? $k->{id} : undef) };
    } else {
        # The key from the export itself: an identical panel key is reused, a missing one is created (once -
        # the next zone finds it). A panel key of that name with another secret is not touched.
        my ($k, @clash);
        my $defs = $u->{key_defs} || {};
        for my $kn (@keys) {
            my $def = $defs->{$kn};
            next unless $def && defined $def->{secret};
            (my $r, my $re) = _dyn_key_ensure({ name => $kn, algorithm => $def->{algorithm}, secret => ($def->{secret} =~ s{\s+}{}gr) }, { domain_id => $domain_id });
            if ($re) { push @n, "key $kn from the export was not added: $re"; push @clash, $kn; next }
            if ($r->{rotate}) { push @n, "the panel already has a TSIG key named $kn with another secret — the zone was not given it"; push @clash, $kn; next }
            $k = { id => $r->{id}, name => $kn, created => $r->{created} }; last;
        }
        if (!$k && @keys) {
            ($k, my $ke) = _db_row($dbh, "SELECT id, name FROM tsig_keys WHERE name IN ($in) ORDER BY name LIMIT 1", @keys);
            return "dynamic updates: $ke" if $ke;
        }
        $made = $k if $k && $k->{created};
        my %clash = map { $_ => 1 } @clash;
        @missing = grep { (!$k || $_ ne $k->{name}) && !$clash{$_} } @keys;        my @c = @{ $u->{cidrs} || [] };
        $s = { mode => _dyn_mode_of(scalar @c, $k ? 1 : 0), cidrs => \@c, key_id => ($k ? $k->{id} : undef) };
    }
    my $ok = eval { $dbh->begin_work; _dyn_zone_rows($dbh, $domain_id, $s, 1, $pid); $dbh->commit or die "commit failed\n"; 1 };
    unless ($ok) {
        my $err = $@ || 'error'; chomp $err; eval { $dbh->rollback };
        tsig_keys_forget_unused($made->{id}) if $made;
        return "dynamic updates were not set: $err";
    }
    push @n, 'TSIG key required for dynamic updates: ' . join(', ', @missing) . ' — add it in the zone\'s Dynamic updates' if @missing;
    push @n, 'not carried over from allow-update: ' . join(', ', @{ $u->{other} }) if @{ $u->{other} || [] };
    return @n ? join('; ', @n) : undef;
}
# Key secrets from the export stay on the server: what goes to the browser has name and algorithm only.
sub _import_cfg_public {
    my ($cfg) = @_;
    my $d = ref $cfg->{update_from} eq 'HASH' ? $cfg->{update_from}{key_defs} : undef;
    delete $_->{secret} for values %{ $d || {} };
    delete $_->{privatekey} for @{ ref $cfg->{dnssec_keys} eq 'ARRAY' ? $cfg->{dnssec_keys} : [] };
    return $cfg;
}
# Who could update this zone on the old server (allow-update resolved), for the zone's Dynamic updates form.
# (hash|undef, undef) | (undef, err).
sub import_update_from {
    my ($domain_id) = @_;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $r, my $e) = _db_row($dbh, "SELECT config_json FROM import_zones WHERE panel_zone_id=? ORDER BY imported_at DESC LIMIT 1", $domain_id);
    return (undef, $e) if $e;
    my $cfg = $r ? (eval { JSON->new->decode($r->{config_json} // '{}') } || {}) : {};
    _import_cfg_public($cfg);
    return (ref $cfg->{update_from} eq 'HASH' ? $cfg->{update_from} : undef, undef);
}
# Record in the stored list how the zone creation attempt ended: without it, tomorrow "already taken"
# cannot be told from "not reached yet". Returns undef when written, else the error - never lost silently.
sub _import_zone_result {
    my ($sid, $name, $zone_id, $note) = @_;
    return 'no source' unless $sid && "$sid" =~ /^\d+$/;
    my $dbh = connectDB() or return 'DB unavailable';
    my (undef, $e) = $zone_id
        # The note stays on success too: "set the key manually" is exactly what gets forgotten.
        ? _do($dbh, "UPDATE import_zones SET status='imported', panel_zone_id=?, note=?,
                            imported_at=UTC_TIMESTAMP() WHERE source_id=? AND zone_name=?",
              $zone_id, $note, $sid, $name)
        : _do($dbh, "UPDATE import_zones SET status='failed', note=? WHERE source_id=? AND zone_name=?",
              $note, $sid, $name);
    return $e;
}

# Was a new key requested? The "new key" mode arrives as the object itself, and empty fields in it do NOT
# mean "unsigned": the human chose signing, and a silent unsigned AXFR is exactly what they did not want.
sub _import_tsig_asked { my ($opts) = @_; return (ref $opts->{tsig_new} eq 'HASH') ? $opts->{tsig_new} : undef }
# New migration key, in both places as everywhere: the panel row (holds the secret; the key is removed from
# there when the last reference goes) and the key in PowerDNS (otherwise AXFR silently fails). If PowerDNS
# cannot take it, the panel row is removed too: a key only the panel knows is useless.
sub _tsig_key_new {
    my ($n) = @_;
    my $nm  = _trim($n->{name});
    my $sec = _trim($n->{secret});
    return (undef, 'TSIG key name is required') unless defined $nm && length $nm;
    return (undef, 'TSIG secret is required')   unless defined $sec && length $sec;
    # A key with this name already exists in PowerDNS, possibly made by hand. The panel never touches those:
    # _pdns_ensure_tsigkeys would overwrite the secret and silently break someone's AXFR.
    my $pdns = connectPDNS() or return (undef, 'DB unavailable');
    (my $ex, my $xe) = _db_exists($pdns, "SELECT 1 FROM tsigkeys WHERE name=?", $nm); return (undef, $xe) if $xe;
    return (undef, "TSIG key '$nm' already exists in PowerDNS — use the existing key instead") if $ex;
    (my $id, my $e) = tsig_key_create($nm, $n->{algorithm}, $sec);
    return (undef, $e) if $e;
    my ($meta) = tsig_key_meta($id);
    (my $ok, my $pe) = _pdns_ensure_tsigkeys(_cfg('pdns_api', 'server', 'localhost'),
        [ { name => $meta->{name}, algorithm => $meta->{algorithm}, secret => $sec } ]);
    if ($pe) {
        my $dbh = connectDB(); _do($dbh, "DELETE FROM tsig_keys WHERE id=?", $id) if $dbh;
        return (undef, "TSIG key was not created in PowerDNS: $pe");
    }
    return ({ id => $id + 0, name => $meta->{name}, algorithm => $meta->{algorithm} }, undef);
}

# Zone name normalization + validation (PURE, no DB): ($normalized, undef) | (undef, error).
# Lowercase, no trailing dot, RFC 1035 labels. Deliberately STRICTER than DNS: zone names are kept in
# preferred name syntax. Record names are not affected: _dmarc, _sip._tcp and DKIM selectors are allowed
# and checked separately (dns_validate).
sub dns_validate_zonename {
    my ($name) = @_;
    return (undef, 'zone name is required') unless defined $name && length $name;
    $name =~ s/^\s+//; $name =~ s/\s+$//;
    return (undef, 'use ASCII letters and digits; international names must use Punycode (xn--)')
        if $name =~ /[^\x00-\x7f]/;
    $name = lc $name;
    $name =~ s/\.$//;                          # no trailing dot (DB names have none)
    return (undef, 'zone name is required') unless length $name;
    return (undef, 'zone name too long (max 253)') if length($name) > 253;
    return (undef, 'zone name must not contain spaces') if $name =~ /\s/;
    my @labels = split /\./, $name, -1;
    for my $l (@labels) {
        return (undef, "invalid empty label in '$name'") unless length $l;
        return (undef, "label too long (max 63): '$l'") if length($l) > 63;
        return (undef, "invalid label '$l' (allowed: a-z 0-9 -, not at ends)")
            unless $l =~ /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/;
    }
    return ($name, undef);
}

# Profile preset from the DB (zone_profiles + nameservers). A profile is ONE set of NS/SOA/catalog: if they
# differ, it is another profile ("FXTM Internal" vs "FXTM External"), not a variant.
# ($preset, undef) | (undef, error). preset = {primary_ns, hostmaster, nameservers=>[...],
#   ttl, refresh, retry, expire, minimum, default_catalog_id}.
sub zone_profile_preset {
    my ($code) = @_;
    return (undef, 'profile is required') unless defined $code && length $code;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $row, my $e) = _db_row($dbh,
        "SELECT id, primary_ns, hostmaster, default_catalog_id,
                soa_ttl, soa_refresh, soa_retry, soa_expire, soa_minimum
           FROM zone_profiles WHERE code=?", $code);
    return (undef, $e) if $e;
    return (undef, "unknown profile '$code'") unless $row;
    (my $nss, $e) = _db_all($dbh, "SELECT nameserver FROM zone_profile_nameservers WHERE profile_id=? ORDER BY ord, id", { Slice => {} }, $row->{id});
    return (undef, $e) if $e;
    return ({
        primary_ns  => $row->{primary_ns}, hostmaster => $row->{hostmaster},
        nameservers => [ map { $_->{nameserver} } @$nss ],
        ttl => $row->{soa_ttl}+0, refresh => $row->{soa_refresh}+0, retry => $row->{soa_retry}+0,
        expire => $row->{soa_expire}+0, minimum => $row->{soa_minimum}+0,
        default_catalog_id => (defined $row->{default_catalog_id} ? $row->{default_catalog_id}+0 : undef),
    }, undef);
}

# SOA/NS defaults for a new PRIMARY zone (PURE; same for preview and create). A profile is a convenience:
# if chosen it supplies defaults the form overrides; if not, Primary NS, hostmaster and NS must come from
# the form and timers are standard. $opts: {profile, role, soa=>{overrides}, nameservers=>[...]}.
# Returns (hashref, undef) or (undef, error).
our %SOA_STANDARD = (ttl => 3600, refresh => 7200, retry => 3600, expire => 1209600, minimum => 3600);
sub pdns_zone_defaults {
    my ($name, $opts) = @_;
    $opts ||= {};
    my $preset = { %SOA_STANDARD, nameservers => [] };
    if (defined $opts->{profile} && length $opts->{profile}) {
        ($preset, my $perr) = zone_profile_preset($opts->{profile});
        return (undef, $perr) if $perr;
    }

    # SOA timers/TTL come from the profile variant (preset), not from config.
    my $ov  = (ref($opts->{soa}) eq 'HASH') ? $opts->{soa} : {};
    my ($primary_ns, $pe) = _zp_fqdn($ov->{primary_ns} || $preset->{primary_ns}, 'primary NS');
    return (undef, "$pe — fill it in or choose a profile") if $pe;
    my ($hostmaster, $he) = _zp_fqdn($ov->{hostmaster} || $preset->{hostmaster}, 'hostmaster');
    return (undef, "$he — fill it in or choose a profile") if $he;
    my $ttl        = (defined $ov->{ttl}     && $ov->{ttl}     =~ /^\d+$/) ? $ov->{ttl}     : $preset->{ttl};
    my $refresh    = (defined $ov->{refresh} && $ov->{refresh} =~ /^\d+$/) ? $ov->{refresh} : $preset->{refresh};
    my $retry      = (defined $ov->{retry}   && $ov->{retry}   =~ /^\d+$/) ? $ov->{retry}   : $preset->{retry};
    my $expire     = (defined $ov->{expire}  && $ov->{expire}  =~ /^\d+$/) ? $ov->{expire}  : $preset->{expire};
    my $minimum    = (defined $ov->{minimum} && $ov->{minimum} =~ /^\d+$/) ? $ov->{minimum} : $preset->{minimum};
    my $serial     = (defined $ov->{serial}  && $ov->{serial}  =~ /^\d+$/) ? $ov->{serial}
                   : do { require POSIX; POSIX::strftime('%Y%m%d', localtime()) . '01' };   # YYYYMMDD01
    my @form_ns = grep { defined && /\S/ } @{ ref($opts->{nameservers}) eq 'ARRAY' ? $opts->{nameservers} : [] };
    my $nameservers = [];
    for my $ns (@form_ns ? @form_ns : @{ $preset->{nameservers} || [] }) {
        (my $n, my $ne) = _zp_fqdn($ns, 'name server'); return (undef, $ne) if $ne;
        push @$nameservers, $n;
    }
    return (undef, 'at least one name server is required — fill it in or choose a profile') unless @$nameservers;

    my $soa_content = join(' ', $primary_ns, $hostmaster, $serial, $refresh, $retry, $expire, $minimum);
    return ({
        type        => 'MASTER',
        role        => 'primary',
        profile     => $opts->{profile},
        primary_ns  => $primary_ns,
        hostmaster  => $hostmaster,
        ttl         => $ttl + 0,
        serial      => $serial,
        refresh     => $refresh + 0, retry => $retry + 0, expire => $expire + 0, minimum => $minimum + 0,
        nameservers => $nameservers,
        soa_content => $soa_content,
    }, undef);
}

# Inserts the zone rows inside an ALREADY OPEN transaction ($dbh); dies on error; returns domain_id.
# $d: primary defaults (from pdns_zone_defaults); not needed for secondary.
sub _zone_insert {
    my ($dbh, $name, $opts, $d) = @_;
    my $role  = zone_role_or_die($opts->{role});    # core contract: unknown role -> die (never a silent MASTER)
    my $profile = $opts->{profile};
    my $domain_id;
    if ($role eq 'secondary') {
        my @masters = grep { defined && length } @{ $opts->{masters} || [] };
        die "secondary requires masters\n" unless @masters;
        $dbh->do("INSERT INTO domains (name, type, master) VALUES (?, 'SLAVE', ?)",
                 undef, $name, join(',', @masters)) or die "insert SLAVE domain failed\n";
        $domain_id = $dbh->last_insert_id(undef, undef, undef, undef);
        if ($opts->{tsig}) {
            $dbh->do("INSERT INTO domainmetadata (domain_id, kind, content) VALUES (?, 'AXFR-MASTER-TSIG', ?)",
                     undef, $domain_id, $opts->{tsig}) or die "insert AXFR-MASTER-TSIG failed\n";
        }
        if ($opts->{renotify}) {
            $dbh->do("INSERT INTO domainmetadata (domain_id, kind, content) VALUES (?, 'SLAVE-RENOTIFY', '1')",
                     undef, $domain_id) or die "insert SLAVE-RENOTIFY failed\n";
        }
    } else {
        # primary -> MASTER with SOA+NS from the preset. The panel never creates NATIVE: that relies on
        # replicating the DB between PowerDNS servers, while we distribute via primary -> AXFR/catalog ->
        # secondary. Existing NATIVE zones are still shown.
        $dbh->do("INSERT INTO domains (name, type) VALUES (?, 'MASTER')", undef, $name)
            or die "insert domain failed\n";
        $domain_id = $dbh->last_insert_id(undef, undef, undef, undef);
        $dbh->do("INSERT INTO records (domain_id, name, type, content, ttl) VALUES (?, ?, 'SOA', ?, ?)",
                 undef, $domain_id, $name, $d->{soa_content}, $d->{ttl}) or die "insert SOA failed\n";
        for my $ns (@{ $d->{nameservers} }) {
            $dbh->do("INSERT INTO records (domain_id, name, type, content, ttl) VALUES (?, ?, 'NS', ?, ?)",
                     undef, $domain_id, $name, $ns, $d->{ttl}) or die "insert NS failed\n";
        }
    }
    if (defined $profile && length $profile) {
        $dbh->do("INSERT INTO domainmetadata (domain_id, kind, content) VALUES (?, 'X-DNSPANEL-PROFILE', ?)",
                 undef, $domain_id, $profile) or die "insert X-DNSPANEL-PROFILE failed\n";
    }
    # metas: panel metadata the zone is meaningless without (migration markers), in the SAME transaction -
    # a zone without them is worse than none: PowerDNS has it, but the migration does not know it.
    for my $m (@{ $opts->{metas} || [] }) {
        next unless defined $m->[1];
        $dbh->do("INSERT INTO domainmetadata (domain_id, kind, content) VALUES (?, ?, ?)", undef, $domain_id, @$m)
            or die "insert $m->[0] failed\n";
    }
    return $domain_id;
}

# Create a zone. role='primary' (MASTER: SOA + multi-row NS from the profile preset) or
# role='secondary' (SLAVE: masters, TSIG, renotify; SOA/NS arrive via AXFR).
# $opts: { profile, role, soa=>{overrides}, nameservers=>[...], masters=>[...], tsig=>'keyname', renotify=>bool }.
# Returns domain_id or undef (the caller checks existence -> 409).
sub pdns_create_zone {
    my ($name, $opts) = @_;
    my $name_error;
    ($name, $name_error) = dns_validate_zonename($name);
    return undef if $name_error;
    $opts ||= {};
    return undef if pdns_get_domain_by_name($name);   # already exists
    my $role = eval { zone_role_or_die($opts->{role}) };
    return undef unless defined $role;                 # unknown role -> refuse (never a silent MASTER)
    my $d;
    if ($role ne 'secondary') {                        # primary needs the SOA/NS preset
        my $err;
        ($d, $err) = pdns_zone_defaults($name, $opts);
        return undef if $err || !$d;
    }
    my $dbh = connectPDNS() or return undef;
    my $domain_id;
    my $ok = eval {
        $dbh->begin_work;
        $domain_id = _zone_insert($dbh, $name, $opts, $d);
        $dbh->commit or die "commit failed\n"; 1;
    };
    if (!$ok) { eval { $dbh->rollback }; return undef; }
    return $domain_id;
}

# Atomically create SEVERAL zones in one transaction (/23 -> /24 etc.), all or nothing.
# $specs: [ { name, opts=>{profile,role,...}, delegate_parent=>parent_zone_name? } ].
# With delegate_parent, NS records for the child (zone cut) are added to the parent, whose SOA is bumped
# once. Returns (\@ids, undef, \@parents) | (undef, err); \@parents = [ {name, serial}, ... ] with the
# parent serial after the bump, for delegation verify.
sub pdns_create_zones_batch {
    my ($specs) = @_;
    return (undef, 'no zones') unless ref($specs) eq 'ARRAY' && @$specs;
    for my $s (@$specs) {
        return (undef, "zone '$s->{name}' already exists") if pdns_get_domain_by_name($s->{name});
        my $role = eval { zone_role_or_die($s->{opts}{role}) };
        return (undef, "invalid role for '$s->{name}'") unless defined $role;
        if ($role ne 'secondary') {                    # primary needs the SOA/NS preset
            my ($d, $err) = pdns_zone_defaults($s->{name}, $s->{opts});
            return (undef, $err) if $err;
            $s->{_d} = $d;
        }
    }
    my $dbh = connectPDNS() or return (undef, 'DB unavailable');
    my @ids; my %bump; my @parents;   # parent domain_id => parent name (one SOA bump); @parents = {name,serial}
    my $ok = eval {
        $dbh->begin_work;
        # Parent zones are locked FIRST, all at once, as on every write path: domains rows by ascending id before
        # any write. Delegation edits ANOTHER zone, which may have become Secondary meanwhile - NS would then land
        # in a zone the panel no longer controls. Also makes lock order independent of list order.
        my %pid;                                        # parent name -> domain_id
        for my $s (@$specs) {
            next unless $s->{delegate_parent};
            next if exists $pid{ $s->{delegate_parent} };
            my ($id) = $dbh->selectrow_array("SELECT id FROM domains WHERE name = ? LIMIT 1",
                                             undef, $s->{delegate_parent});
            die "parent zone '$s->{delegate_parent}' not found\n" unless $id;
            $pid{ $s->{delegate_parent} } = $id;
        }
        if (%pid) {
            if (my $we = _lock_zones_writable($dbh, values %pid)) { die "parent zone: $we\n"; }
        }
        for my $s (@$specs) {
            push @ids, _zone_insert($dbh, $s->{name}, $s->{opts}, $s->{_d});
            next unless $s->{delegate_parent};
            # zone cut: child NS delegation in the parent (already locked and checked)
            my $pid = $pid{ $s->{delegate_parent} };
            my $ttl = $s->{_d}{ttl} || 3600;
            for my $ns (@{ $s->{_d}{nameservers} }) {
                $dbh->do("INSERT INTO records (domain_id, name, type, content, ttl) VALUES (?, ?, 'NS', ?, ?)",
                         undef, $pid, $s->{name}, $ns, $ttl) or die "insert delegation NS failed\n";
            }
            $bump{$pid} = $s->{delegate_parent};
        }
        for my $pid (sort { $a <=> $b } keys %bump) {
            my $soa = _lock_soa($dbh, $pid) or die "no SOA in parent $bump{$pid}\n";
            my $serial = _bump_soa_row($dbh, $soa) or die "parent SOA bump failed\n";
            push @parents, { name => $bump{$pid}, serial => $serial };   # parent verify runs with this serial
        }
        $dbh->commit or die "commit failed\n"; 1;
    };
    if (!$ok) { my $e = $@ || 'error'; chomp $e; eval { $dbh->rollback }; return (undef, $e); }
    return (\@ids, undef, \@parents);
}

# Reverse zone creation plan from a CIDR: existing/covered/missing. (\%plan, undef)|(undef,err).
sub reverse_plan_for_cidr {
    my ($cidr) = @_;
    my ($names, $err) = reverse_zones_for_cidr($cidr);
    return (undef, $err) if $err;
    my $dbh = connectPDNS();
    my %have;                                          # existing reverse domains
    if ($dbh) {
        my $suffix = ($names->[0] =~ /ip6\.arpa$/) ? '%.ip6.arpa' : '%.in-addr.arpa';
        my $rows = $dbh->selectcol_arrayref(
            "SELECT name FROM domains WHERE name LIKE ? OR name IN ('in-addr.arpa','ip6.arpa')", undef, $suffix) || [];
        $have{ lc $_ } = 1 for @$rows;
    }
    my ($create, $exists, $covered) = (0, 0, 0);
    my @zones;
    for my $n (@$names) {
        my $st = 'missing'; my $by;
        if ($have{ lc $n }) { $st = 'exists'; $exists++; }
        else {
            # covered by a wider parent reverse zone? (drop left labels)
            my @lab = split /\./, $n;
            for (my $i = 1; $i < @lab - 2; $i++) {     # never 'in-addr.arpa'/'ip6.arpa' itself
                my $parent = join('.', @lab[$i .. $#lab]);
                if ($have{ lc $parent }) { $st = 'covered'; $by = $parent; last; }
            }
            $st eq 'covered' ? $covered++ : $create++;
        }
        push @zones, { name => $n, status => $st, ($by ? (covered_by => $by) : ()) };
    }
    return ({ cidr => $cidr, zones => \@zones, create => $create, exists => $exists, covered => $covered }, undef);
}

# Compact zone snapshot for audit "before" (what is destroyed): name, type, RRset/record counts,
# delegated child zones.
sub pdns_zone_snapshot {
    my ($domain_id) = @_;
    my $z = pdns_get_domain($domain_id) or return undef;
    my $meta   = pdns_get_domain_metadata($domain_id);
    my $counts = pdns_count_records_by_type($domain_id);
    my $rrsets = pdns_list_rrsets($domain_id);
    my $kids   = pdns_list_child_zones($z->{name});
    return {
        name        => $z->{name},
        type        => $z->{type},
        profile     => ($meta->{'X-DNSPANEL-PROFILE'} ? $meta->{'X-DNSPANEL-PROFILE'}[0] : undef),
        master      => $z->{master},
        soa_serial  => $z->{soa_serial},
        record_total => $counts->{total},
        rrset_count => scalar(@$rrsets),
        by_type     => $counts->{by_type},
        child_zones => [ map { $_->{name} } @$kids ],
    };
}

# Delete a whole zone. The gmysql schema has NO FK cascades (verified live), so ALL zone-owned tables are
# cleaned explicitly: records, domainmetadata, comments, cryptokeys, then domains. tsigkeys are not
# per-domain and are left alone.
sub pdns_delete_zone {
    my ($domain_id) = @_;
    return undef unless $domain_id;
    my $dbh = connectPDNS() or return undef;
    my $ok = eval {
        $dbh->begin_work;
        # Lock the zone row FIRST, as all write paths do (_lock_zones_writable): domains before records,
        # otherwise zone delete and record edits deadlock. An edit started earlier also finishes first.
        $dbh->selectrow_array("SELECT id FROM domains WHERE id = ? FOR UPDATE", undef, $domain_id);
        # EVERY delete is checked: previously a failed records delete still removed the zone row and reported
        # success, leaving orphan records in PowerDNS.
        $dbh->do("DELETE FROM records WHERE domain_id = ?",        undef, $domain_id) or die "delete records failed\n";
        $dbh->do("DELETE FROM domainmetadata WHERE domain_id = ?", undef, $domain_id) or die "delete metadata failed\n";
        # comments/cryptokeys exist in the standard gmysql schema; do not fail on a non-standard one.
        eval { $dbh->do("DELETE FROM comments WHERE domain_id = ?",   undef, $domain_id) };
        eval { $dbh->do("DELETE FROM cryptokeys WHERE domain_id = ?", undef, $domain_id) };
        $dbh->do("DELETE FROM domains WHERE id = ?", undef, $domain_id) or die "delete domain failed\n";

        $dbh->commit or die "commit failed\n";
        1;
    };
    if (!$ok) { eval { $dbh->rollback }; return undef; }
    # For Pulse a zone delete is the same event as a record delete: addresses drop to zero, links close,
    # targets stop being observed, history stays. No own cleanup on purpose - it would take history with
    # it, and the same event would mean different things depending on how the address disappeared.
    pulse_sweep_after_write($domain_id);
    return 1;
}

# Zone metadata (kind -> [values]) from domainmetadata.
sub pdns_get_domain_metadata {
    my ($domain_id) = @_;
    return {} unless $domain_id;
    my $dbh = connectPDNS() or return {};
    my $rows = $dbh->selectall_arrayref(
        "SELECT kind, content FROM domainmetadata WHERE domain_id = ? ORDER BY id",
        { Slice => {} }, $domain_id) || [];
    my %meta;
    push @{ $meta{ $_->{kind} } }, $_->{content} for @$rows;
    return \%meta;
}

# Upsert of zone metadata (single-value kinds, e.g. X-DNSPANEL-PROFILE) in ONE transaction: per kind,
# delete all rows and insert one; content undef/'' -> delete only. A half-saved section is a state the UI
# does not have. Does NOT touch PowerDNS sync (panel metadata does not affect DNS).
# $pairs = [ [kind, content|undef], ... ]. 1 | undef.
sub pdns_set_zone_metas {
    my ($domain_id, $pairs) = @_;
    return undef unless $domain_id && ref($pairs) eq 'ARRAY';
    return 1 unless @$pairs;
    my $dbh = connectPDNS() or return undef;
    # RaiseError is off (see connectDB/connectPDNS), so EVERY do is checked: eval alone would only catch
    # exceptions that never come, and a failed write would report "saved".
    my $ok = eval {
        $dbh->begin_work or die "begin failed\n";
        for my $p (@$pairs) {
            my ($kind, $content) = @$p;
            die "kind required\n" unless defined $kind && length $kind;
            $dbh->do("DELETE FROM domainmetadata WHERE domain_id = ? AND kind = ?", undef, $domain_id, $kind)
                or die "delete $kind failed\n";
            if (defined $content && length $content) {
                $dbh->do("INSERT INTO domainmetadata (domain_id, kind, content) VALUES (?, ?, ?)",
                         undef, $domain_id, $kind, $content) or die "insert $kind failed\n";
            }
        }
        $dbh->commit or die "commit failed\n";
        1;
    };
    if (!$ok) { eval { $dbh->rollback }; return undef; }
    return 1;
}

# ============================================================================
# dns-agent (privileged helper) + PowerDNS sync. The panel runs as www-data without access to the
# PowerDNS control socket, so it sends fixed commands to the agent over a unix socket.
# See src/dns-agent, docs/INSTALL/reference/05-dns-agent.md.
# ============================================================================

# One agent call; $args: extra fields (zone, expect_serial). Returns the agent response hashref,
# or { ok=>0, error=>... } on unavailability/timeout (the panel does not die).
sub dns_agent_call {
    my ($cmd, %args) = @_;
    my $socket  = get_config_value('agent', 'socket');
    my $timeout = get_config_value('agent', 'timeout') || 5;
    return { ok => 0, error => 'agent.socket not configured' } unless $socket;
    my %req = (cmd => $cmd, %args);
    my $resp = eval {
        local $SIG{ALRM} = sub { die "timeout\n" };
        alarm($timeout + 1);
        require IO::Socket::UNIX;
        my $s = IO::Socket::UNIX->new(Type => Socket::SOCK_STREAM(), Peer => $socket)
            or die "connect $socket: $!\n";
        print $s encode_json(\%req), "\n";
        my $line = <$s>;
        close($s);
        alarm(0);
        die "empty response\n" unless defined $line;
        decode_json($line);
    };
    alarm(0);
    return { ok => 0, error => ($@ || 'agent error'), _unreachable => 1 } unless ref($resp) eq 'HASH';
    return $resp;
}

# PURE: RFC 1982 serial arithmetic: true if $a is "not older" than $b (equal OR newer) in the 32-bit ring.
# So a concurrent bump (serial moved ahead) is not a false activation_failed: PowerDNS serving a
# NEWER zone is success.
sub serial_ge {
    my ($a, $b) = @_;
    return 0 unless defined $a && defined $b && $a =~ /^\d+$/ && $b =~ /^\d+$/;
    my $diff = ($a - $b) % 4294967296;      # (a - b) mod 2^32, always in [0, 2^32)
    return $diff < 2147483648 ? 1 : 0;      # [0, 2^31) => a equal-or-newer than b
}

# Verify only (NO rediscover): the zone is really served with the expected serial. { pdns_state, detail }.
# For batch creation rediscover runs ONCE and verify per zone.
sub zone_verify {
    my ($zone, $expect_serial) = @_;
    my $vr = dns_agent_call('verify', zone => $zone, (defined $expect_serial ? (expect_serial => $expect_serial) : ()));
    # check_ok: the check itself ran (agent/dig answered), separate from served. An agent error/timeout
    # (check_ok=0) != "zone not served" (check_ok=1, served=0).
    my $check_ok  = $vr->{ok} ? 1 : 0;
    my $served    = $vr->{served} ? 1 : 0;
    my $serial    = $vr->{serial};
    # "equal or newer" by serial arithmetic, not strict ==; the agent's $vr->{matches} is ignored.
    my $serial_ok = (!defined $expect_serial) || (defined $serial && serial_ge($serial, $expect_serial));
    my $state = ($check_ok && $served && $serial_ok) ? 'active' : 'activation_failed';
    return { pdns_state => $state, check_ok => $check_ok, served => $served, serial => $serial,
             detail => "check_ok=$check_ok served=$served serial=" . ($serial // '?')
                     . (defined $expect_serial ? " expect>=$expect_serial" : ''),
             error => (!$check_ok ? ($vr->{error} // 'verify did not complete') : undef) };
}

# Activate a PRIMARY zone after direct SQL: rediscover (PowerDNS learns the zone) -> verify.
sub zone_activate {
    my ($zone, $expect_serial) = @_;
    my $rd = dns_agent_call('rediscover');
    return { pdns_state => 'activation_failed', detail => "agent unreachable: $rd->{error}" }
        if $rd->{_unreachable};
    return { pdns_state => 'activation_failed', detail => "rediscover failed: " . ($rd->{output} // $rd->{error} // '') }
        unless $rd->{ok};
    return zone_verify($zone, $expect_serial);
}

# Deactivate after delete: rediscover -> verify the zone is NO LONGER served.
sub zone_deactivate {
    my ($zone) = @_;
    my $rd = dns_agent_call('rediscover');
    return { pdns_state => 'deactivation_failed', detail => "agent unreachable: $rd->{error}" }
        if $rd->{_unreachable};
    # Rediscover does not drop the packet cache: a recently answered SOA would still read as "served".
    dns_agent_call('purge', zone => $zone);
    my $vr = dns_agent_call('verify', zone => $zone);
    # Tell "verify did not run" (agent/timeout) from a confirmed "still served".
    return { pdns_state => 'deactivation_failed', detail => "verify failed: " . ($vr->{error} // 'agent error') }
        unless $vr->{ok};
    return { pdns_state => 'still_served', detail => "serial=" . ($vr->{serial} // '?') } if $vr->{served};
    return { pdns_state => 'removed' };
}

# Secondary: ASK PowerDNS to pull the zone from the primary. Nothing waits: PowerDNS queues the AXFR and
# the sync worker watches completion - an HTTP request waiting for the transfer would hang as long as the
# foreign server takes. rediscover makes PowerDNS know the zone and its current primaries; a batch does
# it once itself and passes rediscovered => 1.
# { pdns_state => pending_transfer | transfer_problem, notify_state => 'not_applicable', detail }.
sub zone_secondary_request {
    my ($zone, %o) = @_;
    # unreachable: the agent did not answer at all, so a batch need not call it for the next zone.
    my $fail = sub { return { pdns_state => 'transfer_problem', notify_state => 'not_applicable', detail => $_[0],
                               ($_[1]->{_unreachable} ? (unreachable => 1) : ()) } };
    unless ($o{rediscovered}) {
        my $rd = dns_agent_call('rediscover');
        return $fail->('PowerDNS did not re-read its zones: ' . _agent_why($rd), $rd) unless $rd->{ok} && !$rd->{_unreachable};
    }
    my $rt = dns_agent_call('retrieve', zone => $zone);
    return $fail->('AXFR was not requested: ' . _agent_why($rt), $rt) unless $rt->{ok} && !$rt->{_unreachable};
    return { pdns_state => 'pending_transfer', notify_state => 'not_applicable', detail => 'AXFR requested, awaiting transfer' };
}
sub _agent_why { my ($r) = @_; (my $w = $r->{error} // $r->{output} // 'agent error') =~ s/\s+\z//; return $w }

# Has the secondary arrived from the CURRENT primary? "Served" is not enough: after an upstream edit the
# zone keeps serving the old primary's data, and a dig check would say "Active" with the new one down.
# PowerDNS sets domains.last_check only after a successful check with the primary (AXFR or SOA with the
# same serial); a source change and Make secondary reset it. No timeouts. 1 | 0 | undef (DB unavailable).
sub _slave_fresh {
    my ($zone) = @_;
    my $pdns = connectPDNS() or return undef;
    my ($lc) = $pdns->selectrow_array("SELECT last_check FROM domains WHERE name=?", undef, $zone);
    return undef if $pdns->err;
    return ($lc && $lc > 0) ? 1 : 0;
}

# SLAVE: active = served AND checked against the current primary; otherwise AXFR is requested again and
# waiting continues. This is the worker path (one zone per poll); zone creation has its own, without it.
sub _slave_sync_verify {
    my ($zone) = @_;
    dns_agent_call('purge', zone => $zone);
    my $v = zone_verify($zone, undef);
    return { pdns_state => 'transfer_problem', notify_state => 'not_applicable',
             detail => 'check did not complete: ' . ($v->{error} // 'agent error') } unless $v->{check_ok};
    my $fresh = _slave_fresh($zone);
    return { pdns_state => 'transfer_problem', notify_state => 'not_applicable',
             detail => 'PowerDNS database unavailable' } unless defined $fresh;
    return { pdns_state => 'active', notify_state => 'not_applicable', detail => $v->{detail} } if $v->{served} && $fresh;
    my $r = zone_secondary_request($zone);
    $r->{detail} .= " ($v->{detail}" . ($fresh ? '' : ', not yet confirmed by the current primary') . ')';
    return $r;
}

# FINISHING ZONE CREATION - the shared step for EVERYONE who creates zones (site, MCP). A DB row is not
# enough: PowerDNS must see and serve the zone, secondaries must get NOTIFY, and the panel must record
# the outcome. Previously MCP-created zones were never verified, announced or given a state row.
# Name, type and serial are read HERE by domain_id, so the caller has nothing to pass or mix up.
# Secondary only REQUESTS AXFR (zone_secondary_request): a new empty zone has nothing to verify, the
# worker watches arrival. $o: { rediscovered => 1 } - the batch already ran one rediscover for all;
# { problem => reason } - the agent already failed: state is written at once, without another call.
# Returns the zone_sync_verify / zone_secondary_request hash (+ state_error if the state was not written).
sub zone_activate_after_create {
    my ($domain_id, $o) = @_;
    return { pdns_state => 'not_attempted' } unless $domain_id;
    my $dbh = connectPDNS() or return { pdns_state => 'not_attempted' };
    my ($name, $type) = $dbh->selectrow_array("SELECT name, type FROM domains WHERE id=?", undef, $domain_id);
    return { pdns_state => 'not_attempted' } unless defined $name;
    $type = uc($type // '');
    # SLAVE: the serial belongs to the master; nothing of ours to wait for.
    my $serial;
    if ($type ne 'SLAVE') {
        my ($soa) = $dbh->selectrow_array(
            "SELECT content FROM records WHERE domain_id=? AND type='SOA' AND name=? LIMIT 1",
            undef, $domain_id, $name);
        $serial = (split ' ', $soa)[2] if defined $soa;
    }
    my $sync = ($type ne 'SLAVE') ? zone_sync_verify($name, $serial, $type)
             : ($o && $o->{problem}) ? { pdns_state => 'transfer_problem', notify_state => 'not_applicable', detail => $o->{problem} }
             : zone_secondary_request($name, rediscovered => $o && $o->{rediscovered});
    my $sok  = set_zone_sync_state($name, $sync->{pdns_state}, $sync->{notify_state}, $sync->{detail});
    $sync->{state_error} = 1 unless $sok;
    return $sync;
}

# Single sync path WITH CONFIRMATION: purge -> verify(serial) -> if not served / serial mismatch:
# rediscover -> purge -> verify again -> notify. Only 'active' means PowerDNS really serves the zone.
# NOTIFY is TYPE-AWARE: MASTER -> secondaries; NATIVE -> DB replication, no NOTIFY (not_applicable).
# SLAVE has its own path (_slave_sync_verify): active | pending_transfer (AXFR requested) | transfer_problem.
# $zone_type is optional (otherwise looked up by name; unknown -> treated as MASTER, which is safe).
sub zone_sync_verify {
    my ($zone, $expect_serial, $zone_type) = @_;
    if (!defined $zone_type) {                          # the type decides both verify and notify
        my $d = pdns_get_domain_by_name($zone);
        $zone_type = $d ? uc($d->{type} || '') : '';
    } else { $zone_type = uc($zone_type); }
    return _slave_sync_verify($zone) if $zone_type eq 'SLAVE';

    # Records are written by SQL, so a signed zone needs its NSEC chain (ordername/auth) rebuilt after every
    # write, or PowerDNS answers with a broken chain. A failure is a failed activation: the worker retries it.
    if (my $rf = _dnssec_rectify($zone)) {
        return { pdns_state => 'activation_failed', notify_state => 'not_attempted', detail => $rf };
    }
    # Every write ends here, so this is where Pulse learns the zone changed (its slow sweep follows the
    # addresses the zone publishes).
    if (my $zd = pdns_get_domain_by_name($zone)) { pulse_sweep_after_write($zd->{id}); }
    dns_agent_call('purge', zone => $zone);
    my $es = $expect_serial;
    my $v = zone_verify($zone, $es);
    my $rediscover_ok = 1;
    if ($v->{pdns_state} ne 'active') {          # PowerDNS does not see the zone or the serial is stale -> rediscover
        my $rd = dns_agent_call('rediscover');
        $rediscover_ok = ($rd->{ok} && !$rd->{_unreachable}) ? 1 : 0;   # a rediscover FAILURE is recorded, not masked
        dns_agent_call('purge', zone => $zone);
        $v = zone_verify($zone, $es);
    }

    # NOTIFY is TYPE-AWARE and only after a confirmed active: MASTER -> secondaries;
    # NATIVE -> not_applicable (DB replication). Not active: not_attempted.
    my $notify_state;
    if ($v->{pdns_state} ne 'active') {
        $notify_state = 'not_attempted';
    } elsif ($zone_type eq 'NATIVE') {
        $notify_state = 'not_applicable';
    } else {                                     # MASTER (or unknown - treated as MASTER, safe)
        my $nt = dns_agent_call('notify', zone => $zone);
        $notify_state = $nt->{ok} ? 'notified' : 'notify_failed';
    }
    return {
        pdns_state   => $v->{pdns_state},               # active | activation_failed | (slave -> pending_transfer above)
        notify_state => $notify_state,                  # notified | notify_failed | not_attempted | not_applicable
        detail       => $v->{detail},
    };
}

# ---- DNSSEC ----
# PowerDNS signs a primary zone live from its keys (cryptokeys); the panel manages only the keys, through the
# PowerDNS API. Every key change bumps the serial, so secondaries transfer the new DNSKEY set, and goes through
# zone_sync_verify (rectify, verify, NOTIFY).
our %DNSSEC_ALGOS = map { $_ => 1 } qw(ECDSAP256SHA256 ECDSAP384SHA384 ED25519 ED448 RSASHA256 RSASHA512);
our $DNSSEC_DEFAULT_ALGO = 'ECDSAP256SHA256';
sub _cryptokeys_path { return '/api/v1/servers/' . _cfg('pdns_api', 'server', 'localhost') . "/zones/$_[0]./cryptokeys" }
# Signed zones for display: {domain_id => 1}. A secondary that mirrors a signed zone (PRESIGNED) counts too.
sub zone_signed_map {
    my $pdns = connectPDNS() or return {};
    return { map { $_->[0] => 1 } @{ $pdns->selectall_arrayref("SELECT domain_id FROM cryptokeys UNION SELECT domain_id FROM domainmetadata WHERE kind='PRESIGNED' AND content='1'") || [] } };
}
# Zone is signed = it has keys. By name, for the write path. 0 | 1.
sub zone_signed_by_name {
    my ($zone) = @_;
    my $pdns = connectPDNS() or return 0;
    (my $x) = _db_exists($pdns, "SELECT 1 FROM cryptokeys k JOIN domains d ON d.id = k.domain_id WHERE d.name=? LIMIT 1", $zone);
    return $x ? 1 : 0;
}
# undef | error text.
sub _dnssec_rectify {
    my ($zone) = @_;
    return undef unless zone_signed_by_name($zone);
    my $srv = _cfg('pdns_api', 'server', 'localhost');
    (my $r, my $c, my $e) = _pdns_api('PUT', "/api/v1/servers/$srv/zones/$zone./rectify");
    return "rectify failed: $e" if $e;
    return "rectify failed: HTTP $c" unless $c == 200;
    return undef;
}
# One form for comparing DNSKEYs: "flags protocol algorithm base64" with the key in one piece.
sub _dnskey_norm { my ($f, $p, $a, @b64) = split ' ', ($_[0] // ''); return join ' ', grep { defined } $f, $p, $a, join('', @b64); }
# RFC 4034 appendix B, from "flags protocol algorithm base64".
sub _dnskey_tag {
    my ($dnskey) = @_;
    my ($f, $p, $a, @b64) = split ' ', ($dnskey // '');
    return undef unless defined $a && @b64;
    my $rd = pack('nCC', $f, $p, $a) . decode_base64(join '', @b64);
    my $ac = 0; my $i = 0;
    $ac += ($i++ & 1) ? $_ : ($_ << 8) for unpack 'C*', $rd;
    $ac += ($ac >> 16) & 0xFFFF;
    return $ac & 0xFFFF;
}
sub _dnssec_zone {
    my ($domain_id) = @_;
    my $d = pdns_get_domain($domain_id) or return (undef, 'zone not found');
    return (undef, 'only a primary zone can be signed') unless uc($d->{type} // '') eq 'MASTER';
    return ($d, undef);
}
# ({signed, keys[{id, tag, keytype, algorithm, bits, active, published, dnskey, ds[]}]}, undef) | (undef, err).
sub zone_dnssec_get {
    my ($domain_id) = @_;
    my $d = pdns_get_domain($domain_id) or return (undef, 'zone not found');
    (my $r, my $c, my $e) = _pdns_api('GET', _cryptokeys_path($d->{name}));
    return (undef, "PowerDNS API: $e") if $e;
    return (undef, "PowerDNS API → HTTP $c") unless $c == 200;
    my @keys = sort { $a->{id} <=> $b->{id} } map { {
        id => $_->{id} + 0, tag => _dnskey_tag($_->{dnskey}), keytype => lc($_->{keytype} // ''),
        algorithm => $_->{algorithm}, bits => $_->{bits}, active => ($_->{active} ? 1 : 0),
        published => ((!defined $_->{published} || $_->{published}) ? 1 : 0),
        dnskey => $_->{dnskey}, ds => $_->{ds} || [],
    } } @{ ref $r eq 'ARRAY' ? $r : [] };
    # The role comes from the DNSKEY flags (PowerDNS's own keytype names every key csk while no ksk/zsk pair
    # exists): 257 is a KSK when an active 256 key signs the records, else a CSK; 256 is a ZSK.
    my $zsk = grep { ($_->{dnskey} // '') =~ /^256 / && $_->{active} } @keys;
    $_->{keytype} = ($_->{dnskey} // '') =~ /^256 / ? 'zsk' : $zsk ? 'ksk' : 'csk' for @keys;
    return ({ signed => (@keys ? 1 : 0), keys => \@keys }, undef);
}
# After a key change: new serial, then the common verify path. Returns the sync result.
sub _dnssec_after {
    my ($d) = @_;
    my $dbh = connectPDNS() or return { pdns_state => 'activation_failed', detail => 'DB unavailable' };
    my $serial = eval {
        $dbh->begin_work;
        my $soa = _lock_soa($dbh, $d->{id}) or die "no SOA in zone\n";
        my $s = _bump_soa_row($dbh, $soa) or die "soa bump failed\n";
        $dbh->commit or die "commit failed\n"; $s;
    };
    unless ($serial) { my $err = $@ || 'error'; chomp $err; eval { $dbh->rollback }; return { pdns_state => 'activation_failed', detail => $err }; }
    my $sync = zone_sync_verify($d->{name}, $serial, 'MASTER');
    set_zone_sync_state($d->{name}, $sync->{pdns_state}, $sync->{notify_state}, $sync->{detail});
    return $sync;
}
# Generate ({keytype, algorithm, bits}) or import ({keytype, privatekey}: BIND/ISC private key text) a key.
# ({key_id, sync}, undef) | (undef, err).
sub zone_dnssec_key_add {
    my ($domain_id, $in) = @_;
    $in ||= {};
    (my $d, my $de) = _dnssec_zone($domain_id); return (undef, $de) if $de;
    my $kt = lc($in->{keytype} // 'csk');
    return (undef, "key type must be csk, ksk or zsk") unless $kt =~ /^(csk|ksk|zsk)$/;
    my %b = (keytype => $kt, active => (($in->{active} // 1) ? JSON::true : JSON::false), published => JSON::true);
    my $pk = _trim($in->{privatekey});
    if (defined $pk && length $pk) {
        return (undef, 'this is not a BIND private key file (Private-key-format: …)') unless $pk =~ /^Private-key-format:/m;
        $b{privatekey} = $pk;
    } else {
        my $alg = $in->{algorithm} || $DNSSEC_DEFAULT_ALGO;
        return (undef, "unknown DNSSEC algorithm '$alg'") unless $DNSSEC_ALGOS{$alg};
        $b{algorithm} = $alg;
        $b{bits} = ($in->{bits} && $in->{bits} =~ /^\d+$/) ? $in->{bits} + 0 : 2048 if $alg =~ /^RSA/;
    }
    (my $r, my $c, my $e) = _pdns_api('POST', _cryptokeys_path($d->{name}), \%b);
    return (undef, "PowerDNS API: $e") if $e;
    return (undef, 'PowerDNS refused the key: ' . (ref $r eq 'HASH' ? ($r->{error} // "HTTP $c") : "HTTP $c")) unless $c == 201;
    return ({ key_id => (ref $r eq 'HASH' ? $r->{id} + 0 : undef), sync => _dnssec_after($d) }, undef);
}
# ({sync}, undef) | (undef, err). $in: {active?, published?}.
sub zone_dnssec_key_set {
    my ($domain_id, $kid, $in) = @_;
    return (undef, 'invalid key id') unless $kid && "$kid" =~ /^\d+$/;
    (my $d, my $de) = _dnssec_zone($domain_id); return (undef, $de) if $de;
    return (undef, 'nothing to change') unless exists $in->{active} || exists $in->{published};
    # PowerDNS wants both flags in every PUT: the one not being changed keeps its current value.
    (my $cur, my $ce) = zone_dnssec_get($domain_id); return (undef, $ce) if $ce;
    my ($k) = grep { $_->{id} == $kid } @{ $cur->{keys} }; return (undef, 'key not found') unless $k;
    my %b = map { $_ => ((exists $in->{$_} ? $in->{$_} : $k->{$_}) ? JSON::true : JSON::false) } qw(active published);
    (my $r, my $c, my $e) = _pdns_api('PUT', _cryptokeys_path($d->{name}) . "/$kid", \%b);
    return (undef, "PowerDNS API: $e") if $e;
    return (undef, 'PowerDNS refused: ' . (ref $r eq 'HASH' ? ($r->{error} // "HTTP $c") : "HTTP $c")) unless $c == 204 || $c == 200;
    return ({ sync => _dnssec_after($d) }, undef);
}
sub zone_dnssec_key_delete {
    my ($domain_id, $kid) = @_;
    return (undef, 'invalid key id') unless $kid && "$kid" =~ /^\d+$/;
    (my $d, my $de) = _dnssec_zone($domain_id); return (undef, $de) if $de;
    (my $r, my $c, my $e) = _pdns_api('DELETE', _cryptokeys_path($d->{name}) . "/$kid");
    return (undef, "PowerDNS API: $e") if $e;
    return (undef, 'PowerDNS refused: ' . (ref $r eq 'HASH' ? ($r->{error} // "HTTP $c") : "HTTP $c")) unless $c == 204 || $c == 200;
    return ({ sync => _dnssec_after($d) }, undef);
}
# Make primary of a zone signed on the old server: every DNSKEY that arrived by AXFR must have its private key
# from the import (keyset/dsset files do not count). Active = the BIND Activate time has passed and Inactive
# has not. ({keys[], nsec3param}, undef) | (undef, err).
sub _dnssec_promote_plan {
    my ($pdns, $domain_id, $zname) = @_;
    (my $rows, my $e) = _db_all($pdns, "SELECT type, content FROM records WHERE domain_id=? AND name=? AND type IN ('DNSKEY','NSEC3PARAM')",
                                { Slice => {} }, $domain_id, $zname);
    return (undef, $e) if $e;
    my @live = map { _dnskey_norm($_->{content}) } grep { $_->{type} eq 'DNSKEY' } @$rows;
    my ($n3) = map { $_->{content} } grep { $_->{type} eq 'NSEC3PARAM' } @$rows;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $iz, my $ie) = _db_row($dbh, "SELECT config_json FROM import_zones WHERE zone_name=? AND config_json LIKE ?
                                       ORDER BY last_seen_at DESC LIMIT 1", $zname, '%"dnssec_%');
    return (undef, $ie) if $ie;
    my $cfg = $iz ? (eval { JSON->new->decode($iz->{config_json}) } || {}) : {};
    # "Import unsigned", chosen in Import: the zone becomes an unsigned primary.
    return ({ keys => [], unsigned => 1 }, undef) if $cfg->{dnssec_unsigned};
    return (undef, 'the zone is signed on the source server, but no DNSKEY arrived by AXFR') unless @live;
    # Matched by the whole DNSKEY (flags, algorithm, public key), not the 16-bit tag: a tag can collide, and a
    # wrong file pair can carry the right name.
    my %have = map { _dnskey_norm($_->{dnskey}) => $_ } @{ ref $cfg->{dnssec_keys} eq 'ARRAY' ? $cfg->{dnssec_keys} : [] };
    my @missing = map { _dnskey_tag($_) } grep { !$have{$_} } @live;
    return (undef, 'DNSSEC private key missing: ' . join(', ', @missing) . ' — load its key files in Import') if @missing;
    require POSIX; my $now = POSIX::strftime('%Y%m%d%H%M%S', gmtime);
    my @keys = map { my $k = $have{$_};
                     +{ %$k, active => ((defined $k->{activate} && $k->{activate} le $now)
                                       && !(defined $k->{inactive} && $k->{inactive} le $now)) ? 1 : 0 } } @live;
    return ({ keys => \@keys, nsec3param => $n3, dnskeys => \@live }, undef);
}
# After the role change: PowerDNS signs from the keys now. The presigned records and flag go (with BIND's TYPE65534
# signing-state records), NSEC3 keeps the
# old server's parameters, the marker goes, and a new serial pushes fresh signatures to the secondaries.
# Returns warnings (the role already changed: nothing is rolled back).
sub _dnssec_promote_finish {
    my ($pdns, $d, $zname, $plan) = @_;
    my @w;
    my $srv = _cfg('pdns_api', 'server', 'localhost');
    (my $r, my $c, my $e) = _pdns_api('PUT', "/api/v1/servers/$srv/zones/$zname.",
                                      { presigned => JSON::false, ($plan->{nsec3param} ? (nsec3param => $plan->{nsec3param}) : ()) });
    push @w, 'DNSSEC: ' . ($e // "PowerDNS API → HTTP $c") . ' while switching to live signing' if $e || !($c == 204 || $c == 200);
    (my $ok, my $de) = _do($pdns, "DELETE FROM records WHERE domain_id=? AND type IN ('RRSIG','NSEC','NSEC3','NSEC3PARAM','DNSKEY','CDS','CDNSKEY','TYPE65534')", $d->{id});
    push @w, "DNSSEC: old signatures were not removed: $de" if $de;
    # The API answers presigned=false but leaves the PRESIGNED metadata, and rectify then refuses the zone.
    (my $ok2, my $pe) = _do($pdns, "DELETE FROM domainmetadata WHERE domain_id=? AND kind='PRESIGNED'", $d->{id});
    push @w, "DNSSEC: the presigned flag was not removed: $pe" if $pe;
    dns_agent_call('purge', zone => $zname);
    push @w, 'the DNSSEC import marker is still on the zone' unless pdns_set_zone_metas($d->{id}, [ [ $DNSSEC_META, undef ] ]);
    # PowerDNS holds the private keys now; the import list keeps only their public halves.
    {
        my $dbh = connectDB();
        (my $rows) = $dbh ? _db_all($dbh, "SELECT id, config_json FROM import_zones WHERE zone_name=? AND config_json LIKE ?",
                                    { Slice => {} }, $zname, '%"privatekey"%') : ();
        for my $iz (@{ $rows || [] }) {
            my $cfg = eval { JSON->new->decode($iz->{config_json}) } or next;
            delete $_->{privatekey} for @{ ref $cfg->{dnssec_keys} eq 'ARRAY' ? $cfg->{dnssec_keys} : [] };
            (my $x, my $ue) = _do($dbh, "UPDATE import_zones SET config_json=? WHERE id=?", JSON->new->canonical->encode($cfg), $iz->{id});
            push @w, "DNSSEC: the imported private keys were not cleared from the import list: $ue" if $ue;
        }
    }
    my $sync = _dnssec_after({ id => $d->{id}, name => $zname });
    push @w, "DNSSEC: $sync->{detail}" if ($sync->{pdns_state} // '') ne 'active';
    return @w;
}
# Sign with one new CSK, or stop signing: every key is removed. ({sync, keys}, undef) | (undef, err).
sub zone_dnssec_set {
    my ($domain_id, $on, $algorithm) = @_;
    (my $d, my $de) = _dnssec_zone($domain_id); return (undef, $de) if $de;
    (my $cur, my $ce) = zone_dnssec_get($domain_id); return (undef, $ce) if $ce;
    if ($on) {
        return ({ unchanged => 1 }, undef) if $cur->{signed};
        return zone_dnssec_key_add($domain_id, { keytype => 'csk', algorithm => $algorithm });
    }
    return ({ unchanged => 1 }, undef) unless $cur->{signed};
    for my $k (@{ $cur->{keys} }) {
        (my $r, my $c, my $e) = _pdns_api('DELETE', _cryptokeys_path($d->{name}) . "/$k->{id}");
        return (undef, "PowerDNS API: $e") if $e;
        return (undef, "PowerDNS refused to remove key $k->{tag}: HTTP $c") unless $c == 204 || $c == 200;
    }
    return ({ sync => _dnssec_after($d), removed => scalar @{ $cur->{keys} } }, undef);
}

# PURE: operation implied by pdns_state. removed/still_served/deactivation_failed belong to
# DEACTIVATION (zone deleted, must not be served); everything else is activation.
sub sync_operation_for {
    my ($pdns_state) = @_;
    return 'deactivate' if $pdns_state =~ /^(removed|still_served|deactivation_failed)$/;
    return 'activate';
}

# PURE: is this a failure for the given operation?
sub _sync_is_failed {
    my ($op, $pdns_state, $notify_state) = @_;
    return ($op eq 'deactivate')
        ? ($pdns_state eq 'still_served' || $pdns_state eq 'deactivation_failed')
        : ($pdns_state eq 'activation_failed' || $pdns_state eq 'transfer_problem'
           || ($notify_state // '') eq 'notify_failed');
}

# Recovery loop parameters: DB settings (dns_panel.settings), defaults in %SETTING_DEFAULTS.
sub _sync_poll_secs        { return setting('sync.poll_seconds') + 0; }
sub _sync_transfer_timeout { return setting('sync.transfer_timeout_seconds') + 0; }
sub _sync_backoff_initial  { return setting('sync.backoff_initial_seconds') + 0; }
sub _sync_backoff_max      { return setting('sync.backoff_max_seconds') + 0; }

# PURE state transition model (SHARED by the plain write and CAS): all attempts/backoff/pending_since/
# operation logic in one place. Branches:
#   recheck (pending_transfer): attempts=0, next=+poll, pending_since kept;
#   failed  (_sync_is_failed):  attempts=cur+1, next=+backoff(new), pending_since kept ONLY for
#                               transfer_problem (otherwise the next poll would time out pending again);
#   clear   (otherwise):        attempts=0, next=NULL, pending_since=NULL.
sub sync_write_plan {
    my ($pdns_state, $notify_state, $cur_attempts, $init, $max, $poll) = @_;
    my $op = sync_operation_for($pdns_state);
    if ($pdns_state eq 'pending_transfer') {
        return { operation => $op, class => 'recheck', new_attempts => 0, next_secs => $poll, keep_pending => 1 };
    }
    if (_sync_is_failed($op, $pdns_state, $notify_state)) {
        my $na = (($cur_attempts && $cur_attempts > 0) ? $cur_attempts : 0) + 1;
        return { operation => $op, class => 'failed', new_attempts => $na,
                 next_secs => sync_backoff_secs($na, $init, $max),
                 keep_pending => ($pdns_state eq 'transfer_problem' ? 1 : 0) };
    }
    return { operation => $op, class => 'clear', new_attempts => 0, next_secs => undef, keep_pending => 0 };
}

# Durable zone sync state vs PowerDNS (in dns_panel): an honest trace when SQL succeeded but PowerDNS
# activation/deactivation/NOTIFY did not; an operator ("Retry now") or the worker can retry.
# $notify_state: notified | notify_failed | not_attempted | not_applicable (undef -> NULL).
# operation is derived from pdns_state. Failure depends on the operation:
#   activate:   activation_failed | notify_failed;   deactivate: still_served | deactivation_failed.
# Failure -> attempts+1 + backoff (60s*2^(attempts-1), cap 1h). Success -> attempts=0, next_retry_at=NULL.
sub set_zone_sync_state {
    my ($zone, $pdns_state, $notify_state, $detail) = @_;
    my $dbh = connectDB() or return 0;
    my ($cur_attempts) = $dbh->selectrow_array("SELECT attempts FROM zone_sync_state WHERE zone_name=?", undef, $zone);
    my $p = sync_write_plan($pdns_state, $notify_state, $cur_attempts,
                            _sync_backoff_initial(), _sync_backoff_max(), _sync_poll_secs());
    # next_retry/pending_since are SQL expressions (plan values are integers from validated config).
    my $next_ins = defined($p->{next_secs}) ? "NOW() + INTERVAL $p->{next_secs} SECOND" : 'NULL';
    my $pend_ins = $p->{keep_pending} ? 'NOW()' : 'NULL';
    my $pend_dup = $p->{keep_pending} ? 'COALESCE(pending_since, NOW())' : 'NULL';
    my $rv = $dbh->do("INSERT INTO zone_sync_state
              (zone_name, pdns_state, operation, notify_state, last_detail, attempts, state_version, last_attempt_at, next_retry_at, pending_since, updated_at)
              VALUES (?,?,?,?,?,?,1,NOW(), $next_ins, $pend_ins, NOW())
              ON DUPLICATE KEY UPDATE pdns_state=VALUES(pdns_state), operation=VALUES(operation), notify_state=VALUES(notify_state),
                last_detail=VALUES(last_detail), attempts=VALUES(attempts), state_version=state_version+1,
                last_attempt_at=NOW(), next_retry_at=$next_ins, pending_since=$pend_dup, updated_at=NOW()",
             undef, $zone, $pdns_state, $p->{operation}, $notify_state, $detail, $p->{new_attempts});
    sync_wake() if defined $rv && defined $p->{next_secs};   # a retry is now scheduled
    return defined($rv) ? 1 : 0;                            # 0 = durable state NOT written (never report false success)
}

# PURE: backoff seconds for the Nth consecutive failure (init*2^(N-1), capped at max).
sub sync_backoff_secs {
    my ($attempts, $init, $max) = @_;
    my $n = ($attempts && $attempts > 0) ? $attempts : 1;
    $n = 30 if $n > 30;                          # guard against 2**n overflow
    my $s = $init * (2 ** ($n - 1));
    return $s > $max ? $max : $s;
}
# CAS write of a retry result: applied ONLY if state_version is unchanged since the worker took the task
# under lock (otherwise a concurrent zone create/delete already wrote a newer state - do not clobber it).
# $cur_attempts: current attempts (from the row re-read under lock) for backoff.
# Returns 'applied' | 'superseded' (version changed) | 'error' (DB failure).
sub set_zone_sync_state_cas {
    my ($zone, $pdns_state, $notify_state, $detail, $expected_version, $cur_attempts) = @_;
    return 'error' unless defined $expected_version;
    my $dbh = connectDB() or return 'error';
    # SAME transition model as the plain write.
    my $p = sync_write_plan($pdns_state, $notify_state, $cur_attempts,
                            _sync_backoff_initial(), _sync_backoff_max(), _sync_poll_secs());
    my $next_expr    = defined($p->{next_secs}) ? "NOW() + INTERVAL $p->{next_secs} SECOND" : 'NULL';
    my $pending_expr = $p->{keep_pending} ? 'COALESCE(pending_since, NOW())' : 'NULL';
    my $rv = $dbh->do(
        "UPDATE zone_sync_state
            SET pdns_state=?, operation=?, notify_state=?, last_detail=?,
                attempts=?, next_retry_at=$next_expr, pending_since=$pending_expr,
                state_version=state_version+1, last_attempt_at=NOW(), updated_at=NOW()
          WHERE zone_name=? AND state_version=?",
        undef, $pdns_state, $p->{operation}, $notify_state, $detail, $p->{new_attempts}, $zone, $expected_version);
    return 'error' unless defined $rv;                     # DB error
    sync_wake() if $rv > 0 && defined $p->{next_secs};      # manual Retry rescheduled the zone
    return ($rv > 0) ? 'applied' : 'superseded';           # 0 rows = the version already changed
}

sub get_zone_sync_state {
    my ($zone) = @_;
    my $dbh = connectDB() or return undef;
    return $dbh->selectrow_hashref(
        "SELECT zone_name, pdns_state, operation, notify_state, last_detail, attempts, state_version, last_attempt_at, next_retry_at, pending_since, updated_at
           FROM zone_sync_state WHERE zone_name = ?",
        undef, $zone);
}

# WHERE "zone is in trouble": activation/deactivation/transfer failure (UI, filter, banner).
my $SYNC_FAIL_WHERE = "pdns_state IN ('activation_failed','still_served','deactivation_failed','transfer_problem') OR notify_state='notify_failed'";
# WHERE "zone needs a recheck": problems + pending_transfer (polling a SLAVE until AXFR completes).
my $SYNC_DUE_WHERE  = "pdns_state IN ('activation_failed','still_served','deactivation_failed','transfer_problem','pending_transfer') OR notify_state='notify_failed'";

# Problem zones (activate OR deactivate failure) for the Dashboard/filter and the worker.
# Returns ($rows, $error): a DB error is NOT masked as "no problems" (fail-closed).
sub sync_problem_zones {
    my $dbh = connectDB() or return ([], 'DB unavailable');
    my $rows = $dbh->selectall_arrayref(
        "SELECT zone_name, pdns_state, operation, notify_state, last_detail, attempts, last_attempt_at, next_retry_at, updated_at
           FROM zone_sync_state
          WHERE $SYNC_FAIL_WHERE
          ORDER BY updated_at DESC", { Slice => {} });
    return ([], 'sync_state query failed') unless defined $rows;
    return ($rows, undef);
}

# Zones DUE for retry (failure + next_retry_at reached), for the background worker.
# Returns (\@items, $error), item = { zone_name, operation } (the worker picks the path by operation).
# On a DB error the worker must exit non-zero rather than treat it as "queue empty".
sub due_retry_zones {
    my ($limit) = @_;
    $limit = 50 unless defined $limit && $limit =~ /^\d+$/ && $limit > 0;
    my $dbh = connectDB() or return ([], 'DB unavailable');
    my $rows = $dbh->selectall_arrayref(
        "SELECT zone_name, operation, state_version FROM zone_sync_state
          WHERE ($SYNC_DUE_WHERE)
            AND (next_retry_at IS NULL OR next_retry_at <= NOW())
          ORDER BY (next_retry_at IS NULL) DESC, next_retry_at ASC
          LIMIT $limit", { Slice => {} });
    return ([], 'due_retry query failed') unless defined $rows;
    return ($rows, undef);
}

# Seconds until the next retry falls due (0 = due now; undef = nothing scheduled), for the sync daemon's
# timer. $exclude: zones to leave out - ones another process holds under its lock right now; that process
# writes their next state itself and wakes the daemon. ($secs, undef) | (undef, err).
sub sync_next_due {
    my ($exclude) = @_;
    my @ex = @{ $exclude || [] };
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    my $not = @ex ? ' AND zone_name NOT IN (' . join(',', ('?') x @ex) . ')' : '';
    (my $r, my $e) = _db_row($dbh,
        "SELECT GREATEST(0, TIMESTAMPDIFF(SECOND, NOW(), MIN(COALESCE(next_retry_at, NOW())))) AS s, COUNT(*) AS n
           FROM zone_sync_state WHERE ($SYNC_DUE_WHERE)$not", @ex);
    return (undef, $e) if $e;
    return (($r && $r->{n}) ? $r->{s} + 0 : undef, undef);
}

# Wake the sync daemon: something now waits in the database (a retry, a probe queue). Only a hint - the
# state is durable, and a lost wake is caught by the daemon's next scheduled pass. Never blocks, never fails
# the caller. The daemon's own tasks set DNS_SYNC_NO_WAKE: a wake from inside its pass is redundant.
our $SYNC_WAKE_SOCKET = '/run/dns-panel/sync/wake.sock';
sub sync_wake {
    return if $ENV{DNS_SYNC_NO_WAKE} || !-S $SYNC_WAKE_SOCKET;
    eval {
        require IO::Socket::UNIX;
        my $s = IO::Socket::UNIX->new(Type => Socket::SOCK_DGRAM(), Peer => $SYNC_WAKE_SOCKET) or return;
        $s->blocking(0); $s->send('wake'); close $s;
    };
    return;
}

# Retry zone sync: operation-aware, with CAS protection against a stale task.
# $operation: 'activate' | 'deactivate'. $expected_version: the state version the worker took the task
# with (undef for a manual Retry). $meta: { actor, actor_role, source, ip } for audit.
# Under GET_LOCK the state is re-read: if the worker's task is stale (version/operation changed by a
# concurrent create/delete) -> { superseded=>1 }, NOTHING written. The final write is a CAS on the version
# taken under lock (a change during rediscover/verify -> 'superseded', someone else's state is kept).
#   activate:   find the zone in pdns (absent -> 'orphaned', off retry), take the current serial,
#               zone_sync_verify; success = active AND not notify_failed.
#   deactivate: zone_deactivate (rediscover -> verify NOT served); success = 'removed';
#               still_served/deactivation_failed -> failure (backoff). 'orphaned' does not apply.
# Returns { pdns_state, notify_state?, detail, serial? } | { busy=>1 } | { superseded=>1 } | { error=>... };
# state_error/audit_error when the state/audit write failed. result='ok' only on real success.
sub retry_zone_sync {
    my ($zone, $operation, $expected_version, $meta) = @_;
    $operation = 'activate' unless defined $operation && $operation eq 'deactivate';
    $meta ||= {};
    # source: audit_log ENUM ('panel','api','mcp','ha-agent','system'); default 'system' (background worker).
    my %am = ( actor => ($meta->{actor} || 'system'), actor_role => ($meta->{actor_role} || 'system'),
               source => ($meta->{source} || 'system'), ip => $meta->{ip} );
    my $audit_ok = 1;
    my $audit = sub {
        my ($result, $detail, $after) = @_;
        my $r = audit_log({ %am, action => 'retry_sync', target_type => 'zone', target => $zone,
                            after => { operation => $operation, %{ $after || {} } }, result => $result, detail => $detail });
        $audit_ok = 0 unless $r;                             # audit INSERT failed - do not stay silent
    };
    my $dbh = connectDB() or return { error => 'DB unavailable' };
    my ($got) = $dbh->selectrow_array("SELECT GET_LOCK(?, 0)", undef, "zsync:$zone");
    return { error => 'lock acquisition error' } unless defined $got;   # NULL = GET_LOCK error (NOT busy)
    return { busy => 1 } unless $got;                        # 0 = already running in another retry/worker

    # Re-read the state UNDER LOCK: CAS base + "task not stale" check.
    # selectall_arrayref: undef = DB error (fail-closed), [] = no row (not an error).
    my $curr = $dbh->selectall_arrayref(
        "SELECT operation, state_version, attempts FROM zone_sync_state WHERE zone_name=?", { Slice => {} }, $zone);
    unless (defined $curr) {
        $dbh->do("DO RELEASE_LOCK(?)", undef, "zsync:$zone");
        return { error => 'sync state lookup failed' };     # read error != superseded
    }
    my $cur = $curr->[0];                                    # undef if there is no row
    if (defined $expected_version                            # worker: task taken with a version
        && (!$cur || $cur->{state_version} != $expected_version || ($cur->{operation} // '') ne $operation)) {
        $dbh->do("DO RELEASE_LOCK(?)", undef, "zsync:$zone");
        return { superseded => 1 };                         # state changed between queue and lock
    }
    my $base_version  = $cur ? $cur->{state_version} : undef;
    my $base_attempts = $cur ? $cur->{attempts} : 0;
    # Final write: CAS on the version under lock (if the row exists), else a plain upsert.
    my $write = sub {
        my ($ps, $ns, $det) = @_;
        return set_zone_sync_state_cas($zone, $ps, $ns, $det, $base_version, $base_attempts) if defined $base_version;
        return set_zone_sync_state($zone, $ps, $ns, $det) ? 'applied' : 'error';
    };

    my $writeres = 'applied';
    my $res;
    eval {
        if ($operation eq 'deactivate') {                    # the zone must NO LONGER be served
            my $v = zone_deactivate($zone);                  # rediscover -> verify NOT served
            $writeres = $write->($v->{pdns_state}, 'not_applicable', $v->{detail});
            $audit->(($v->{pdns_state} eq 'removed' ? 'ok' : 'failed'), $v->{detail}, { pdns_state => $v->{pdns_state} })
                if $writeres eq 'applied';
            $res = { pdns_state => $v->{pdns_state}, detail => $v->{detail} };
            return 1;
        }
        # activate
        my ($dom, $lookup_err) = pdns_find_domain_by_name($zone);
        die "PowerDNS lookup failed: $lookup_err\n" if $lookup_err;   # DB error -> exception (backoff), NOT orphaned
        if (!$dom) {                                         # zone DEFINITELY absent in PDNS -> off retry (orphaned)
            $writeres = $write->('orphaned', 'not_applicable', 'zone not found in PowerDNS');
            $audit->('failed', 'zone not found in PowerDNS', { pdns_state => 'orphaned' }) if $writeres eq 'applied';
            $res = { pdns_state => 'orphaned', detail => 'zone not found in PowerDNS' };
            return 1;
        }
        # SLAVE: the serial belongs to the master and SOA may be absent before the first AXFR -> not read.
        # MASTER/NATIVE: current SOA serial from the DB for verify against the expected serial.
        my $dtype = uc($dom->{type} || '');
        my $serial;
        if ($dtype ne 'SLAVE') {
            my $sf = pdns_soa_fields($dom->{id}) or die "cannot read SOA from PowerDNS\n";
            $serial = $sf->{serial};
        }
        my $v = zone_sync_verify($zone, $serial, $dtype);    # type-aware verify/NOTIFY
        # SLAVE: pending_transfer longer than the timeout without AXFR -> escalate to transfer_problem.
        if ($dtype eq 'SLAVE' && $v->{pdns_state} eq 'pending_transfer') {
            my ($aged) = $dbh->selectrow_array(
                "SELECT (pending_since IS NOT NULL AND pending_since <= NOW() - INTERVAL ? SECOND) FROM zone_sync_state WHERE zone_name=?",
                undef, _sync_transfer_timeout(), $zone);
            if ($aged) {
                $v = { pdns_state => 'transfer_problem', notify_state => 'not_applicable',
                       detail => "AXFR not completed within transfer timeout ($v->{detail})" };
            }
        }
        $writeres = $write->($v->{pdns_state}, $v->{notify_state}, $v->{detail});
        if ($writeres eq 'applied') {
            # result by the shared predicate (transfer_problem/activation_failed/notify_failed -> failed).
            my $healthy = !_sync_is_failed('activate', $v->{pdns_state}, $v->{notify_state});
            $audit->($healthy ? 'ok' : 'failed', $v->{detail},
                     { pdns_state => $v->{pdns_state}, notify_state => $v->{notify_state}, serial => $serial });
        }
        $res = { pdns_state => $v->{pdns_state}, notify_state => $v->{notify_state},
                 detail => $v->{detail}, serial => $serial };
        1;
    } or do {                                                # exception -> backoff + audit (in terms of the operation)
        my $e = $@ || 'retry failed'; chomp $e;
        my $fail_state = ($operation eq 'deactivate') ? 'deactivation_failed' : 'activation_failed';
        $writeres = $write->($fail_state, 'not_attempted', $e);
        $audit->('failed', $e, { pdns_state => $fail_state }) if $writeres eq 'applied';
        $res = { error => $e };
    };
    $dbh->do("DO RELEASE_LOCK(?)", undef, "zsync:$zone");
    return { superseded => 1 } if $writeres eq 'superseded'; # version changed during the agent calls
    $res->{state_error} = 1 if $writeres eq 'error';         # durable state was not written
    $res->{audit_error} = 1 unless $audit_ok;               # audit was not written
    return $res;
}
# Manual Retry activates the zone (no version: the operator initiated it just now).
sub retry_zone_activation { my ($zone, $meta) = @_; return retry_zone_sync($zone, 'activate', undef, $meta); }

# Refresh AXFR: ASK PowerDNS to pull a secondary zone again, on human request (button and Edit upstream).
# One retrieve, no waiting. It also bypasses PowerDNS's own backoff: after a few master refusals it
# excludes the zone from checks ("Excluding zone from secondary-checks until ..."), and without an explicit
# request the zone would wait even after allow-transfer was fixed on the old server.
# This call does NOT guess transfer completion: a check right after retrieve on an already served zone
# would see old records and say "done" even with the new primary down. Arrival is domains.last_check
# (_slave_fresh), shown as Last check in the Secondary block and watched by the worker.
# State is touched only if the zone is NOT yet checked against the current primary: the request then
# restarts the wait (the old pending_since belongs to the previous attempt and would time out at once).
# { requested => 1, pdns_state } | { error } (+ requested => 1 if AXFR was requested but state not written).
sub zone_secondary_refresh {
    my ($zone) = @_;
    my ($dom, $le) = pdns_find_domain_by_name($zone);
    return { error => "PowerDNS lookup failed: $le" } if $le;
    return { error => 'zone not found in PowerDNS' } unless $dom;
    return { error => 'zone is not a secondary' } unless uc($dom->{type} // '') eq 'SLAVE';
    my $rt = dns_agent_call('retrieve', zone => $zone);
    return { error => 'AXFR was not requested: ' . _agent_why($rt) } unless $rt->{ok} && !$rt->{_unreachable};
    my $ss = get_zone_sync_state($zone);
    my $settled = _slave_fresh($zone) && (!$ss || ($ss->{pdns_state} // '') eq 'active');
    return { requested => 1, pdns_state => 'active' } if $settled;
    my $dbh = connectDB() or return { requested => 1, error => 'DB unavailable' };
    $dbh->do("UPDATE zone_sync_state SET pending_since=NULL WHERE zone_name=?", undef, $zone)
        or return { requested => 1, error => 'sync state update failed' };
    set_zone_sync_state($zone, 'pending_transfer', 'not_applicable', 'AXFR requested, awaiting transfer')
        or return { requested => 1, error => 'sync state update failed' };
    return { requested => 1, pdns_state => 'pending_transfer' };
}

# ============================================================================
# LIVE DNS (dig): record propagation to secondaries
# ============================================================================

# Live DNS query to a server (like `dig TYPE NAME @server`) via external dig, list-form exec (no shell)
# and strict argument validation. Returns { server, qname, qtype, status, answers => [ {name,ttl,type,data}, ... ], error? }.
sub dns_query {
    my ($name, $type, $server, $port) = @_;
    $type = uc($type || 'A');
    return { error => 'invalid name' }
        unless defined $name && length $name && $name =~ /\A[A-Za-z0-9._\-]+\z/ && $name !~ /^-/;
    return { error => 'invalid type' } unless $type =~ /\A[A-Z0-9]+\z/;

    my @args = ('+noall', '+comments', '+answer', '+time=3', '+tries=1', $type, $name);
    if (defined $server && length $server) {
        return { error => 'invalid server' }
            unless $server =~ /\A[A-Za-z0-9._:\-]+\z/ && $server !~ /^-/;
        push @args, '@' . $server;
    }
    if (defined $port && $port =~ /\A\d+\z/) { push @args, '-p', $port; }

    my $out = { server => ($server // 'default'), qname => $name, qtype => $type,
                status => undef, answers => [] };
    my $pid = open(my $fh, '-|');
    if (!defined $pid) { return { %$out, error => 'fork failed' }; }
    if ($pid == 0) {                       # child
        # Under FastCGI STDERR is tied to the FCGI stream and cannot be reopened; exit would end the request.
        untie *STDERR if tied *STDERR;
        open(STDERR, '>', '/dev/null');
        { exec('dig', @args) }
        require POSIX; POSIX::_exit(127);
    }
    while (my $line = <$fh>) {
        if ($line =~ /->>HEADER<<-.*status:\s*(\w+)/) { $out->{status} = $1; }
        next if $line =~ /^\s*;/;           # comments/header
        next unless $line =~ /\S/;
        my @f = split /\s+/, $line, 5;      # name ttl class type data
        next unless @f >= 5;
        push @{ $out->{answers} }, { name => $f[0], ttl => ($f[1] + 0), type => $f[3], data => $f[4] =~ s/\s+$//r };
    }
    close $fh;
    return $out;
}

# Zone propagation check: compare the SOA serial (or a specific record) on the master and all
# secondaries; $name/$type optional. Returns { zone, in_sync, servers => [ {role,host,serial|answers,status,reachable} ] }.
sub dns_check_propagation {
    my ($zone, $name, $type) = @_;
    return { error => 'zone required' } unless defined $zone && length $zone;

    # Targets come from the inventory, not the config file: servers are managed in the panel, and a second
    # list in config would eventually check propagation on the wrong nodes.
    my @targets = ({ role => 'master', host => '127.0.0.1' });   # the local shadow master is the source
    if (my $dbh = connectDB()) {
        my $rows = eval {
            $dbh->selectall_arrayref(
                "SELECT n.name, e.address FROM secondary_nodes n
                    JOIN secondary_node_endpoints e ON e.secondary_node_id = n.id
                  WHERE n.enabled=1 AND e.enabled=1 AND e.purpose='dns_listen'
                  ORDER BY n.name, e.address", { Slice => {} });
        };
        push @targets, { role => 'secondary', host => $_->{address}, name => $_->{name} } for @{ $rows || [] };
    }
    return { error => 'no DNS servers in inventory' } unless @targets;

    my (@servers, %serials);
    for my $t (@targets) {
        my %row = (role => $t->{role}, host => $t->{host});
        if (defined $name && length $name) {
            my $q = dns_query($name, ($type || 'A'), $t->{host});
            $row{status}    = $q->{status};
            $row{reachable} = $q->{status} ? JSON::true : JSON::false;
            $row{answers}   = [ map { $_->{data} } @{ $q->{answers} } ];
        } else {
            (my $serial, my $status) = _soa_serial_at($zone, $t->{host});
            $row{status}    = $status;
            $row{reachable} = $status ? JSON::true : JSON::false;
            if (defined $serial) { $row{serial} = $serial; $serials{$serial} = 1; }
        }
        push @servers, \%row;
    }

    my $in_sync;
    if (defined $name && length $name) {
        # in sync if all reachable servers returned the same answer set
        my %seen; my $reach = 0;
        for my $s (@servers) {
            next unless $s->{reachable} == JSON::true;
            $reach++;
            $seen{ join(',', sort @{ $s->{answers} || [] }) } = 1;
        }
        $in_sync = ($reach > 0 && keys(%seen) == 1) ? JSON::true : JSON::false;
    } else {
        $in_sync = (keys(%serials) == 1) ? JSON::true : JSON::false;
    }
    return { zone => $zone, in_sync => $in_sync, servers => \@servers };
}

# ============================================================================
# DNS VALIDATION (shared by UI/API/MCP)
# ============================================================================

my %VALID_TYPES = map { $_ => 1 } qw(A AAAA CNAME MX TXT NS PTR SRV CAA TLSA SSHFP SPF NAPTR DNAME DS);
sub dns_record_types { return [ sort keys %VALID_TYPES ]; }

sub _is_ipv4 { my $x = shift; return defined($x) && defined(eval { inet_pton(AF_INET,  $x) }); }
sub _is_ipv6 { my $x = shift; return defined($x) && defined(eval { inet_pton(AF_INET6, $x) }); }
sub _is_hostname {
    my $h = shift;
    return 0 unless defined $h && length $h && length($h) <= 253;
    $h =~ s/\.$//;
    return 0 unless length $h;
    return 0 unless $h =~ /^(?:[A-Za-z0-9_](?:[A-Za-z0-9_\-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?$/;
    # An address is not a name: "192.168.1.2" passes the regex but cannot be an MX/NS/CNAME target.
    # Ask "is it an address?", not "does it end in digits": `mail.2026` and `host.123` are names found in
    # internal zones. IPv6 never gets here: names contain no colons.
    return 0 if _is_ipv4($h);
    return 1;
}

# Record name -> the form the core searches, deletes and inserts by. Previously only the comparison key
# (_nk) dropped the trailing dot while records got the raw name: "www.example." and "www.example" became
# two records, and DELETE by the dotted name found nothing. The CORE strips the dot, not the form or the
# router (relative names and "@" are their job, and MCP has neither).
# It does NOT repair broken names (a..example stays an error), does not touch content (each type has its
# own rules) and does not turn the root "." into an empty string. ($name, undef) | (undef, error).
sub dns_record_name_norm {
    my ($name) = @_;
    return (undef, 'name is required') unless defined $name && length $name;
    return (undef, 'name must not contain spaces') if $name =~ /\s/;
    return (undef, 'use ASCII letters and digits; international names must use Punycode (xn--)')
        if $name =~ /[^\x00-\x7f]/;
    return ('.', undef) if $name eq '.';                  # the root stays the root
    $name =~ s/\.$//;                                     # exactly one trailing dot
    return (undef, 'name is required') unless length $name;
    return (undef, 'name too long (max 253)') if length($name) > 253;
    my @labels = split /\./, $name, -1;
    for my $i (0 .. $#labels) {
        my $l = $labels[$i];
        return (undef, "invalid empty label in '$name'") unless length $l;
        return (undef, "label too long (max 63): '$l'") if length($l) > 63;
        next if $l eq '*' && $i == 0;                      # wildcard only as the first label
        # Underscore is allowed on purpose: _dmarc, _sip._tcp and other service names are legal.
        # Slash too: classless reverse delegations look like 0/25.2.0.192.in-addr.arpa.
        return (undef, "invalid label '$l' in '$name'")
            unless $l =~ m{^[A-Za-z0-9_]([A-Za-z0-9_/-]*[A-Za-z0-9_])?$};
    }
    return ($name, undef);
}

# Validate one record. Returns an error string or undef (ok). PURE.
sub dns_validate {
    my ($type, $name, $ttl, $content, $prio) = @_;
    $type = uc($type // '');
    return "unsupported type: $type" unless $VALID_TYPES{$type};
    return "name is required" unless defined $name && length $name;
    return "invalid name" unless $name =~ /^(?:\*\.)?[A-Za-z0-9._\-\@]+$/;
    if (defined $ttl && length $ttl) {
        return "TTL must be a non-negative integer" unless $ttl =~ /^\d+$/ && $ttl <= 2147483647;
    }
    return "content is required" unless defined $content && length $content;

    if    ($type eq 'A')    { return "invalid IPv4 address" unless _is_ipv4($content); }
    elsif ($type eq 'AAAA') { return "invalid IPv6 address" unless _is_ipv6($content); }
    elsif ($type =~ /^(?:CNAME|NS|PTR|DNAME)$/) {
        return "invalid target hostname" unless _is_hostname($content);
    }
    elsif ($type eq 'MX') {
        return "MX priority (integer) is required" unless defined $prio && $prio =~ /^\d+$/;
        return "MX priority must be 0..65535" if $prio > 65535;          # 16-bit field
        # "." as MX is Null MX (RFC 7505, "this domain accepts no mail") and must have priority 0.
        return "Null MX (target '.') must have priority 0" if $content eq '.' && $prio != 0;
        return "invalid MX target" unless $content eq '.' || _is_hostname($content);
    }
    elsif ($type eq 'SRV') {
        return "SRV priority (integer) is required" unless defined $prio && $prio =~ /^\d+$/;
        return "SRV priority must be 0..65535" if $prio > 65535;
        my ($w, $port, $target) = $content =~ /^(\d+)\s+(\d+)\s+(\S+)$/;
        return "invalid SRV content (expect: weight port target)" unless defined $target;
        return "SRV weight and port must be 0..65535" if $w > 65535 || $port > 65535;
        # The SRV target is a NAME, not an address; "." means "no service" (RFC 2782).
        return "invalid SRV target" unless $target eq '.' || _is_hostname($target);
    }
    elsif ($type eq 'CAA') {
        return "invalid CAA content (expect: flags[0-255] tag value, e.g. 0 issue letsencrypt.org)"
            unless defined canonicalize_caa($content);
    }
    # TXT/SPF/TLSA/SSHFP/NAPTR/DS: free-form content (non-empty check already done)
    return undef;
}

# ============================================================================
# RRSET (unit of DNS editing: name + type). Direct SQL, transaction, SOA bump.
# ============================================================================

# All zone RRsets: [ { name, type, ttl, records => [ {content,prio,disabled,id} ] } ].
sub pdns_list_rrsets {
    my ($domain_id) = @_;
    my $recs = pdns_list_records($domain_id);
    my (%g, @order);
    for my $r (@$recs) {
        my $k = lc($r->{name}) . "\0" . uc($r->{type});
        if (!$g{$k}) {
            $g{$k} = { name => $r->{name}, type => uc($r->{type}), ttl => $r->{ttl}, records => [],
                       updated_by => undef, updated_at => undef };
            push @order, $k;
        }
        push @{ $g{$k}{records} },
            { content => $r->{content}, prio => $r->{prio}, disabled => ($r->{disabled} ? 1 : 0), id => $r->{id} };
        # RRset last change: the latest updated_at among its rows (REPLACE sets them all alike)
        if (defined $r->{updated_at} &&
            (!defined $g{$k}{updated_at} || $r->{updated_at} gt $g{$k}{updated_at})) {
            $g{$k}{updated_at} = $r->{updated_at};
            $g{$k}{updated_by} = $r->{updated_by};
        }
    }
    return [ map { $g{$_} } @order ];
}


# Batch canonicalization (PURE, no DB): normalize name/type/changetype, duplicates, empty REPLACE,
# record validation. Returns (\@canon, undef) or (undef, error).
# canon element: { name, type, changetype, ttl, records, _nk (lc name without dot) }.
sub _canonicalize_ops {
    my ($ops) = @_;
    return (undef, 'no rrsets') unless ref($ops) eq 'ARRAY' && @$ops;
    my (@canon, %seen);
    for my $o (@$ops) {
        my $type = uc($o->{type} // '');
        return (undef, 'name and type are required') unless defined $o->{name} && length $o->{name} && $type;
        # The name is normalized IDENTICALLY for REPLACE and DELETE: both must find the same rows.
        my ($name, $nerr) = dns_record_name_norm($o->{name});
        return (undef, $nerr) if $nerr;
        return (undef, 'SOA is managed separately') if $type eq 'SOA';
        my $ct = uc($o->{changetype} // '');
        return (undef, "changetype must be REPLACE or DELETE (got '" . ($o->{changetype} // '') . "')")
            unless $ct eq 'REPLACE' || $ct eq 'DELETE';
        my $records = $o->{records} || [];
        my $ttl = (defined $o->{ttl} && $o->{ttl} =~ /^\d+$/) ? $o->{ttl} : 3600;
        if ($ct eq 'REPLACE') {
            return (undef, 'REPLACE with empty records[] is not allowed — use changetype DELETE')
                unless @$records;
            for my $r (@$records) {
                # CAA: canonicalize to 'flags tag "value"' BEFORE validation/storage (otherwise zone SERVFAIL).
                if ($type eq 'CAA') { my $c = canonicalize_caa($r->{content}); $r->{content} = $c if defined $c; }
                my $e = dns_validate($type, $name, $ttl, $r->{content}, $r->{prio});
                return (undef, $e) if $e;
            }
            # A SET rule, not a record rule: "no mail" and "mail is here" are mutually exclusive (RFC 7505).
            if ($type eq 'MX' && @$records > 1
                && grep { ($_->{content} // '') eq '.' } @$records) {
                return (undef, "Null MX (target '.') must be the only MX record of $name");
            }
        }
        my $nk = lc $name;                                # name key: the same name, case-insensitive
        return (undef, "duplicate rrset in batch: $name $type") if $seen{"$nk/$type"}++;
        push @canon, {
            name => $name, type => $type, changetype => $ct, ttl => $ttl,
            records => ($ct eq 'DELETE' ? [] : $records), _nk => $nk,
        };
    }
    return (\@canon, undef);
}

# FINAL-state name check (PURE): CNAME does not coexist with other types - by the result, not by
# operation order. $existing = { name_key => { TYPE => 1 } } (current DB state).
sub _final_state_ok {
    my ($canon, $existing) = @_;
    my %final;
    for my $o (@$canon) {
        $final{ $o->{_nk} } = { %{ $existing->{ $o->{_nk} } || {} } } unless $final{ $o->{_nk} };
    }
    for my $o (@$canon) {
        if ($o->{changetype} eq 'DELETE') { delete $final{ $o->{_nk} }{ $o->{type} }; }
        else                              { $final{ $o->{_nk} }{ $o->{type} } = 1; }
    }
    for my $nk (sort keys %final) {
        my @types = keys %{ $final{$nk} };
        return "CNAME cannot coexist with other records at $nk"
            if (grep { $_ eq 'CNAME' } @types) && @types > 1;
    }
    return undef;
}

# Current record types of the affected names: { name_key => { TYPE => 1 } }.
sub _existing_types {
    my ($dbh, $domain_id, $name_keys) = @_;
    return {} unless @$name_keys;
    my $ph = join(',', ('?') x @$name_keys);
    my $rows = $dbh->selectall_arrayref(
        "SELECT name, type FROM records WHERE domain_id = ? AND LOWER(TRIM(TRAILING '.' FROM name)) IN ($ph)",
        { Slice => {} }, $domain_id, @$name_keys) || [];
    my %m;
    for (@$rows) { my $nk = lc($_->{name}); $nk =~ s/\.$//; $m{$nk}{ uc $_->{type} } = 1; }
    return \%m;
}

# Apply a SET of RRset changes ATOMICALLY: canonicalize -> final state -> one transaction -> one SOA
# bump. All or nothing. Returns (1, undef, $new_serial) or (undef, error).
sub pdns_apply_rrsets {
    my ($domain_id, $ops, $actor, $by) = @_;
    return (undef, 'domain_id required') unless $domain_id;
    if (my $we = pdns_zone_write_error($domain_id)) { return (undef, $we); }   # SLAVE/nonexistent: the single guard (MCP included)
    # A record has one owner. While a Pulse rule is enabled the RRset belongs to it: a manual edit would be
    # overwritten on the next recompute (and look like the panel lying) or get stuck and put the rule on
    # hold. The guard sits HERE, in the only write path, so it covers MCP and API too (docs/24, docs/25 §6).
    unless (($by // '') eq 'pulse') {
        if (my $pe = _pulse_rrset_locked($domain_id, $ops)) { return (undef, $pe) }
    }

    # Canonicalization is pure, before the DB.
    my ($canon, $err) = _canonicalize_ops($ops);
    return (undef, $err) if $err;

    my $dbh = connectPDNS() or return (undef, 'DB unavailable');
    my %names = map { $_->{_nk} => 1 } @$canon;

    my $serial;
    my $ok = eval {
        $dbh->begin_work;
        # 0) Zone role under the domains row lock: while the batch waited, the zone may have become
        #    Secondary, and the edit would land in a zone the next AXFR overwrites.
        if (my $we = _lock_zones_writable($dbh, $domain_id)) { die "$we\n"; }
        # 1) Serialize ALL zone changes: lock the SOA row FIRST (before reads/checks), otherwise two
        #    concurrent batches could both pass final-state and insert a conflict.
        my $soa = _lock_soa($dbh, $domain_id) or die "no SOA in zone\n";
        # 2) Current state of the affected names, already under lock.
        my $existing = _existing_types($dbh, $domain_id, [ keys %names ]);
        # 3) Final-state check (CNAME by the result).
        if (my $e = _final_state_ok($canon, $existing)) { die "$e\n"; }
        # The zone must keep a working apex NS here too: this path replaces whole sets, and without the check
        # one call could remove all NS at once via API or MCP.
        if (my $e = _apex_ns_guard_rrsets($dbh, $domain_id, $canon)) { die "$e\n"; }
        # 4) Apply and bump the already locked SOA.
        _apply_one_rrset($dbh, $domain_id, $_, $actor) for @$canon;
        $serial = _bump_soa_row($dbh, $soa) or die "soa bump failed\n";
        $dbh->commit or die "commit failed\n";
        1;
    };
    if (!$ok) { my $e = $@ || 'error'; chomp $e; eval { $dbh->rollback }; return (undef, $e); }
    # The slow sweep target list follows the zone itself: an address appearing or going away is exactly the
    # event it looks for. A failure here does not undo the zone write: the sweep observes, it is not part of
    # the write.
    pulse_sweep_after_write($domain_id);
    return (1, undef, $serial);
}

# Lock the zone's SOA row (SELECT ... FOR UPDATE). Returns {id,content} or undef.
sub _lock_soa {
    my ($dbh, $domain_id) = @_;
    return $dbh->selectrow_hashref(
        "SELECT id, content FROM records WHERE domain_id = ? AND type = 'SOA' LIMIT 1 FOR UPDATE",
        undef, $domain_id);
}

# Increment the serial in an already read/locked SOA row. Returns the new serial or undef.
sub _bump_soa_row {
    my ($dbh, $soa) = @_;
    my @p = split /\s+/, ($soa->{content} // '');
    return undef unless @p >= 7;
    $p[2] = ($p[2] || 0) + 1;
    $dbh->do("UPDATE records SET content = ? WHERE id = ?", undef, join(' ', @p), $soa->{id}) or return undef;
    return $p[2];
}

# Apply one RRset in an open transaction (no bump). Order-independent: just replace (name,type);
# CNAME coexistence was checked BEFORE, on the final state.
sub _apply_one_rrset {
    my ($dbh, $domain_id, $op, $actor) = @_;
    my $name = $op->{name};
    my $type = uc($op->{type});
    my $ttl  = (defined $op->{ttl} && $op->{ttl} =~ /^\d+$/) ? $op->{ttl} : 3600;
    my $records = (uc($op->{changetype} // 'REPLACE') eq 'DELETE') ? [] : ($op->{records} || []);

    $dbh->do("DELETE FROM records WHERE domain_id=? AND name=? AND type=?",
             undef, $domain_id, $name, $type) or die "delete failed\n";
    # updated_by/updated_at: who and when edited this RRset (all rows alike; for a new record also
    # "created"). NOW(6) is DB time, the same for the whole transaction.
    my $ins = $dbh->prepare(
        "INSERT INTO records (domain_id,name,type,content,ttl,prio,disabled,updated_by,updated_at)
         VALUES (?,?,?,?,?,?,?,?,NOW(6))")
        or die "prepare failed\n";
    for my $r (@$records) {
        $ins->execute($domain_id, $name, $type, $r->{content}, $ttl,
                      (defined $r->{prio} && $r->{prio} =~ /^\d+$/ ? $r->{prio} : undef),
                      ($r->{disabled} ? 1 : 0), $actor) or die "insert failed\n";
    }
}


# ============================================================================
# PERMISSIONS (docs/20-permissions.md): effective zone access + capabilities
# ============================================================================

sub _access_rank { my $a = shift // 'none'; return $a eq 'write' ? 2 : $a eq 'read' ? 1 : 0; }

# Resolution WITHIN one subject (one group OR the user's personal rules).
# By specificity zone(2) > all(1); ties on one level -> max access.
# rules: [ { scope=>'all'|'zone', zone_id=>, access=>, label=>? } ]
# -> { access, scope, label, spec } of the most specific applicable rule, OR undef if none applies.
sub _spec_of { my $s = shift; return $s eq 'zone' ? 2 : 1; }
sub _resolve_within {
    my ($rules, $zone_id) = @_;
    my @m = grep {
           $_->{scope} eq 'all'
        || ($_->{scope} eq 'zone' && defined $zone_id && defined $_->{zone_id} && $_->{zone_id} == $zone_id)
    } @$rules;
    return undef unless @m;
    my $top = 0; for (@m) { my $s = _spec_of($_->{scope}); $top = $s if $s > $top; }
    my @at = grep { _spec_of($_->{scope}) == $top } @m;
    my $b = $at[0]; for (@at) { $b = $_ if _access_rank($_->{access}) > _access_rank($b->{access}); }
    return { access => $b->{access}, scope => $b->{scope}, label => $b->{label}, spec => $top };
}

# ADDITIVE model (the ONLY core, for both enforcement and preview):
#   1) each GROUP computes ITS OWN access to the zone (zone > all WITHIN the group);
#   2) groups combine by MAXIMUM access (Manage > View > No access) - groups only ADD to each other,
#      a specific rule of one group does NOT narrow a broad rule of another;
#   3) the personal rule is compared with the group result BY SPECIFICITY: the more specific level wins,
#      ties go to personal. So a group zone rule still beats a personal all, and a personal zone
#      override beats groups.
# Returns { access, source, scope, group, group_source }: group/group_source - the additive group maximum
# + the name of that group ("Access from groups" column); source='Direct' if personal won.
# rules: [ { source=>'group'|'user', gid=>?, scope, zone_id, access, label=>? } ]
sub _resolve_additive {
    my ($rules, $zone_id) = @_;
    my (@personal, %by_gid, %gname);
    for (@$rules) {
        if (($_->{source} // '') eq 'user') { push @personal, $_; }
        else { my $g = defined $_->{gid} ? $_->{gid} : ($_->{label} // 'g'); push @{ $by_gid{$g} }, $_; $gname{$g} = $_->{label}; }
    }
    # Group maximum: max access; among groups with it, the highest specificity (for comparison with personal).
    my ($gacc, $gspec, $gsrc);
    for my $g (keys %by_gid) {
        my $r = _resolve_within($by_gid{$g}, $zone_id) or next;
        if (!defined $gacc
            || _access_rank($r->{access}) > _access_rank($gacc)
            || (_access_rank($r->{access}) == _access_rank($gacc) && $r->{spec} > ($gspec // 0))) {
            $gacc = $r->{access}; $gspec = $r->{spec}; $gsrc = $gname{$g};
        }
    }
    my $group = defined $gacc ? $gacc : 'none';
    # Personal vs group result by specificity (personal wins ties).
    my $p = _resolve_within(\@personal, $zone_id);
    if (defined $p && (!defined $gacc || $p->{spec} >= ($gspec // 0))) {
        return { access => $p->{access}, source => ($p->{label} // 'Direct'), scope => $p->{scope},
                 group => $group, group_source => $gsrc };
    }
    return { access => $group, source => $gsrc, scope => undef, group => $group, group_source => $gsrc };
}
sub _effective_access { my ($r, $z) = @_; return _resolve_additive($r, $z)->{access}; }

# User's access to EACH zone for the Zone access table, per zone via _resolve_additive: group (MAX over
# groups), group_source (that group's name), personal (personal zone override or undef, for the
# dropdown), effective (groups + personal override). Plus default (all): the same fields.
# -> ({ default=>{...}, zones=>[{zone_id,name,scope,group,group_source,personal,effective}] }, undef) | (undef,err).
sub zone_access_effective {
    my ($uid) = @_;
    return (undef, 'user id required') unless $uid && $uid =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    my ($ex) = $dbh->selectrow_array("SELECT 1 FROM users WHERE id=?", undef, $uid);
    return (undef, 'unknown user') unless $ex;
    my @all;
    my $gr = $dbh->selectall_arrayref(
        "SELECT za.scope, za.zone_id, za.access, za.subject_id AS gid, g.name AS gname
           FROM zone_access za JOIN user_groups ug ON ug.group_id = za.subject_id
           JOIN groups g ON g.id = za.subject_id
          WHERE za.subject_type='group' AND ug.user_id = ?", { Slice => {} }, $uid) || [];
    push @all, { %$_, source => 'group', label => $_->{gname} } for @$gr;   # label = group name -> "Access from groups"
    my $ur = $dbh->selectall_arrayref(
        "SELECT scope, zone_id, access FROM zone_access WHERE subject_type='user' AND subject_id = ?", { Slice => {} }, $uid) || [];
    push @all, { %$_, source => 'user' } for @$ur;

    my %pzone; for (grep { ($_->{source} // '') eq 'user' && $_->{scope} eq 'zone' } @all) { $pzone{ $_->{zone_id} } = $_->{access}; }
    my ($pa) = grep { ($_->{source} // '') eq 'user' && $_->{scope} eq 'all' } @all;   # personal all-override

    my $domains = zone_access_domains() || [];
    my @zones;
    for my $d (@$domains) {
        my $r = _resolve_additive(\@all, $d->{id} + 0);
        push @zones, {
            zone_id      => $d->{id} + 0,
            name         => $d->{name},
            group        => $r->{group},
            group_source => $r->{group_source},   # name of the maximum group (or undef)
            personal     => (exists $pzone{ $d->{id} } ? $pzone{ $d->{id} } : undef),
            effective    => $r->{access},
        };
    }
    my $dr = _resolve_additive(\@all, undef);
    return ({
        default => {
            group        => $dr->{group},
            group_source => $dr->{group_source},
            personal     => ($pa ? $pa->{access} : undef),
            effective    => $dr->{access},
        },
        zones => \@zones,
    }, undef);
}

# Canonical PREVIEW of a user's draft access WITHOUT saving: the same additive core computes the
# effective access for the given group_ids + personal capabilities + zone_rules.
# -> ({ capabilities=>{ effective=>[...], sources=>{cap=>{direct,groups=>[{id,name}]}} },
#      zones=>{ default=>{...}, zones=>[...] } }, undef) | (undef, err).
# NB: same engine as enforcement/user_get - NO second resolver in JS. Validation is lenient (read-only).
sub user_access_preview {
    my ($uid, $body) = @_; $body ||= {};
    return (undef, 'user id required') unless $uid && $uid =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    my ($ex) = $dbh->selectrow_array("SELECT 1 FROM users WHERE id=?", undef, $uid);
    return (undef, 'unknown user') unless $ex;
    my $groups = ref $body->{group_ids}   eq 'ARRAY' ? $body->{group_ids}   : [];
    my $caps   = ref $body->{capabilities} eq 'ARRAY' ? $body->{capabilities} : [];
    my $denied = ref $body->{denied_capabilities} eq 'ARRAY' ? $body->{denied_capabilities} : [];
    my $rules  = ref $body->{zone_rules}  eq 'ARRAY' ? $body->{zone_rules}  : [];
    my %seen_g; my @gids;
    for my $g (@$groups) { next unless defined $g && "$g" =~ /^\d+$/; next if $seen_g{$g + 0}++; push @gids, $g + 0; }

    # Names + capabilities + zone_access of the selected draft groups.
    my (%gname, %gcaps, @grules);
    if (@gids) {
        my $ph = join(',', ('?') x @gids);
        my $gn = $dbh->selectall_arrayref("SELECT id, name FROM groups WHERE id IN ($ph)", { Slice => {} }, @gids) || [];
        $gname{ $_->{id} } = $_->{name} for @$gn;
        my $cg = $dbh->selectall_arrayref(
            "SELECT subject_id AS gid, capability FROM capability_grants WHERE subject_type='group' AND subject_id IN ($ph)", { Slice => {} }, @gids) || [];
        for (@$cg) { push @{ $gcaps{ $_->{capability} } }, $_->{gid} + 0; }
        my $gz = $dbh->selectall_arrayref(
            "SELECT subject_id AS gid, scope, zone_id, access FROM zone_access WHERE subject_type='group' AND subject_id IN ($ph)", { Slice => {} }, @gids) || [];
        push @grules, { %$_, source => 'group', label => $gname{ $_->{gid} } } for @$gz;
    }

    # Panel permissions: combined sources (only valid, known capabilities).
    my %seenc; my @directU = grep { $functions::IS_CAP{$_} && !$seenc{$_}++ } @$caps;
    my %src; my %eff;
    my %deny = map { $_ => 1 } grep { $functions::IS_CAP{$_} } @$denied;
    for my $c (@directU) { $src{$c}{direct} = 1; $eff{$c} = 1; }
    for my $c (sort keys %gcaps) {
        next unless $functions::IS_CAP{$c};
        push @{ $src{$c}{groups} }, { id => $_, name => ($gname{$_} // '') } for sort { $a <=> $b } @{ $gcaps{$c} };
        $eff{$c} = 1;
    }
    # A personal deny overrides both group and personal grants - the same rule as in has_capability.
    for my $c (keys %deny) { $src{$c}{denied} = 1; delete $eff{$c}; }

    # Zone access: the same additive rules; personal = the draft zone_rules.
    my @all = @grules;
    my %pzone; my $pall;
    for my $r (@$rules) {
        my $sc = $r->{scope} // ''; next unless $sc =~ /^(all|zone)$/;
        my $ac = $r->{access} // ''; next unless $ac =~ /^(none|read|write)$/;
        my $row = { source => 'user', scope => $sc, access => $ac,
                    zone_id => ($sc eq 'zone' ? ($r->{zone_id} + 0) : undef) };
        push @all, $row;
        $pzone{ $row->{zone_id} } = $ac if $sc eq 'zone';
        $pall = $ac if $sc eq 'all';
    }

    my $domains = zone_access_domains() || [];
    my @zones;
    for my $d (@$domains) {
        my $r = _resolve_additive(\@all, $d->{id} + 0);
        push @zones, {
            zone_id => $d->{id} + 0, name => $d->{name},
            group => $r->{group}, group_source => $r->{group_source},
            personal => (exists $pzone{ $d->{id} } ? $pzone{ $d->{id} } : undef),
            effective => $r->{access},
        };
    }
    my $dr = _resolve_additive(\@all, undef, undef);
    return ({
        capabilities => {
            effective => [ sort keys %eff ],
            direct    => [ @directU ],
            sources   => \%src,
        },
        zones => {
            default => { group => $dr->{group}, group_source => $dr->{group_source},
                         personal => (defined $pall ? $pall : undef), effective => $dr->{access} },
            zones   => \@zones,
        },
    }, undef);
}

# JSON safe to embed inside <script type="application/json">. The HTML parser closes <script> at the
# first "</script" whatever JSON says: a server description "</script><script>...</script>" escaped the
# data block and became executable. "<" is escaped as \u003c (same string for JSON, not a tag for HTML);
# U+2028/2029 too, as JavaScript line terminators they break parsing inside a literal.
sub json_for_html {
    my ($data) = @_;
    # CHARACTERS, not bytes: pages print to STDOUT with :utf8, so encode_json's UTF-8 bytes were encoded
    # twice (mojibake for any non-ASCII), and the \x{2028}/\x{2029} replacements below never matched.
    my $j = JSON->new->encode($data);
    $j =~ s{<}{\\u003c}g;
    $j =~ s{\x{2028}}{\\u2028}g;
    $j =~ s{\x{2029}}{\\u2029}g;
    return $j;
}
# Access context: group and personal rules are loaded ONCE per request (not per zone).
# Returns { allow_all => 0, rules => [...], producer_ids => {id=>1} }. allow_all is always 0 (an admin sees
# everything via an all=write rule, not a flag). producer_ids: catalog producer zones, always 'none'
# (managed as catalogs in Propagation, not as regular zones).
# NOT FULLY READ means NO ACCESS: a failed read used to become an empty list, so if group rules loaded
# and personal ones did not, a personal DENY vanished and the user got write access. The context is
# marked broken and access_for answers 'none' to everything.
sub build_access_context {
    my ($user) = @_;
    return { allow_all => 0, rules => [], producer_ids => {} } unless $user;
    my $dbh = connectDB();
    return { allow_all => 0, rules => [], producer_ids => {}, broken => 'DB unavailable' } unless $dbh;
    if ($user->{anonymous}) {   # read on every zone (catalog producers stay hidden)
        my $prod = _catalog_domain_ids($dbh) or return { allow_all => 0, rules => [], producer_ids => {}, broken => 'catalog zones unreadable' };
        return { allow_all => 0, rules => [ { scope => 'all', access => 'read', source => 'user' } ], producer_ids => $prod };
    }
    my @rules;
    my $gr = $dbh->selectall_arrayref(
        "SELECT za.scope, za.zone_id, za.access, za.subject_id AS gid
           FROM zone_access za JOIN user_groups ug ON ug.group_id = za.subject_id
          WHERE za.subject_type='group' AND ug.user_id = ?", { Slice => {} }, $user->{id});
    return { allow_all => 0, rules => [], producer_ids => {}, broken => ($dbh->errstr || 'group rules unreadable') }
        unless defined $gr;
    push @rules, { %$_, source => 'group' } for @$gr;
    my $ur = $dbh->selectall_arrayref(
        "SELECT scope, zone_id, access FROM zone_access
          WHERE subject_type='user' AND subject_id = ?", { Slice => {} }, $user->{id});
    return { allow_all => 0, rules => [], producer_ids => {}, broken => ($dbh->errstr || 'user rules unreadable') }
        unless defined $ur;
    push @rules, { %$_, source => 'user' } for @$ur;
    my $prod = _catalog_domain_ids($dbh);
    return { allow_all => 0, rules => [], producer_ids => {}, broken => ($dbh->errstr || 'catalog zones unreadable') }
        unless defined $prod;
    return { allow_all => 0, rules => \@rules, producer_ids => $prod };
}

# Zone access from a prebuilt context ('none'|'read'|'write').
sub access_for {
    my ($ctx, $zone_id) = @_;
    return 'none' if $ctx && $ctx->{broken};   # not fully read -> no permissions (see build_access_context)
    return 'none' if $ctx && $ctx->{producer_ids} && $ctx->{producer_ids}{ $zone_id + 0 };   # catalog producer zones are hidden
    return 'write' if $ctx && $ctx->{allow_all};
    return _effective_access(($ctx ? $ctx->{rules} : []), $zone_id);
}


# SINGLE source of truth for valid roles: values, default (only when ABSENT), normalization and the error
# text. undef -> default; an EXPLICIT unknown value -> error (a typo must not silently become
# MASTER/internal). _norm -> ($val,undef)|(undef,$err) for core (undef,error) contracts; _or_die -> die
# (transactional paths); Router/MCP use the same _norm.
sub zone_role_norm {
    my ($r) = @_;
    $r = 'primary' unless defined $r;
    return ($r =~ /^(primary|secondary)$/) ? ($r, undef)
         : (undef, "invalid zone role '$r' (expected primary|secondary)");
}
sub zone_role_or_die { my ($v, $e) = zone_role_norm($_[0]); die "$e\n" if $e; return $v; }

# Zone kind by name (PURE): reverse4 (in-addr.arpa) / reverse6 (ip6.arpa) / forward.
sub zone_kind {
    my ($name) = @_;
    $name = lc($name // '');
    return 'reverse6' if $name =~ /\.ip6\.arpa\.?$/ || $name eq 'ip6.arpa';
    return 'reverse4' if $name =~ /\.in-addr\.arpa\.?$/ || $name eq 'in-addr.arpa';
    return 'forward';
}

# CIDR -> reverse zone names (PURE). IPv4: /8,/16,/24 (octet-aligned); /9-23 expand into several
# /8|/16|/24 zones. IPv6: prefix a multiple of 4, 4..64 -> one ip6.arpa zone.
# Returns (\@names, undef) | (undef, error).
sub reverse_zones_for_cidr {
    my ($cidr) = @_;
    return (undef, 'network is required') unless defined $cidr && length $cidr;
    $cidr =~ s/^\s+//; $cidr =~ s/\s+$//;
    my ($addr, $pfx) = split m{/}, $cidr, 2;
    return (undef, 'expected NETWORK/PREFIX (e.g. 10.20.30.0/24)') unless defined $pfx && $pfx =~ /^\d+$/;
    $pfx += 0;

    if (defined $addr && $addr =~ /:/) {                       # IPv6
        return (undef, 'IPv6 prefix must be a multiple of 4 (e.g. /32, /48, /64)') if $pfx % 4;
        return (undef, 'IPv6 prefix must be between 4 and 64') if $pfx < 4 || $pfx > 64;
        my $packed = eval { inet_pton(AF_INET6, $addr) };
        return (undef, 'invalid IPv6 address') unless $packed;
        my $hex = unpack('H*', $packed);                       # 32 nibbles
        # canonical: bits past the prefix must be zero (no silent "fixing")
        return (undef, 'network address expected (host bits must be zero)')
            if substr($hex, $pfx / 4) =~ /[^0]/;
        my @nib = split //, substr($hex, 0, $pfx / 4);
        return ([ join('.', reverse @nib) . '.ip6.arpa' ], undef);
    }

    # IPv4
    my @o = split /\./, ($addr // '');
    return (undef, 'invalid IPv4 address')
        if @o != 4 || grep { $_ !~ /^\d+$/ || $_ > 255 } @o;
    return (undef, 'IPv4 prefix must be between 8 and 24') if $pfx < 8 || $pfx > 24;
    my $ipnum = ($o[0] << 24) | ($o[1] << 16) | ($o[2] << 8) | $o[3];
    my $mask  = $pfx == 0 ? 0 : (0xFFFFFFFF << (32 - $pfx)) & 0xFFFFFFFF;
    my $base  = $ipnum & $mask;
    # canonical network address: 10.10.174.99/24 is not silently fixed; show the expected one
    if ($base != $ipnum) {
        my $canon = join('.', ($base >> 24) & 255, ($base >> 16) & 255, ($base >> 8) & 255, $base & 255);
        return (undef, "network address expected: $canon/$pfx");
    }
    my $level  = $pfx <= 8 ? 8 : ($pfx <= 16 ? 16 : 24);        # octet level of the zone
    my $octets = $level / 8;
    my $count  = 1 << ($level - $pfx);                         # how many zones of level $level
    return (undef, "too many zones ($count) — narrow the range") if $count > 256;
    my $step   = 1 << (32 - $level);
    my @names;
    for (my $i = 0; $i < $count; $i++) {
        my $a = $base + $i * $step;
        my @b = (($a >> 24) & 255, ($a >> 16) & 255, ($a >> 8) & 255, $a & 255);
        push @names, join('.', reverse @b[0 .. $octets - 1]) . '.in-addr.arpa';
    }
    return (\@names, undef);
}

# Business group (X-DNSPANEL-PROFILE) for a list of zones in one query: { domain_id => group }.
sub pdns_profile_map {
    my (@ids) = @_;
    return {} unless @ids;
    my $dbh = connectPDNS() or return {};
    my $ph = join(',', ('?') x @ids);
    my $rows = $dbh->selectall_arrayref(
        "SELECT domain_id, content FROM domainmetadata
          WHERE kind='X-DNSPANEL-PROFILE' AND domain_id IN ($ph)",
        { Slice => {} }, @ids) || [];
    my %m; $m{ $_->{domain_id} } = $_->{content} for @$rows;
    return \%m;
}

# ============================================================================
# LABELS: flexible zone classification, stored in dns_panel (PowerDNS does not know them).
# Categories (single|multiple) -> values -> zone assignments (M:N zone_labels).
# Does NOT affect DNS: the SOA/NS preset is separate (Profile/zone_profiles).
# ============================================================================

# All categories with values: [{id,name,slug,cardinality,sort_order,values=>[{id,name,color,sort_order}]}].
sub label_categories_all {
    my $dbh = connectDB() or return [];
    my $cats = $dbh->selectall_arrayref(
        "SELECT id, name, slug, cardinality, sort_order FROM label_categories WHERE enabled=1
          ORDER BY sort_order, name", { Slice => {} }) || [];
    return [] unless @$cats;
    my $vals = $dbh->selectall_arrayref(
        "SELECT id, category_id, name, color, sort_order FROM label_values WHERE enabled=1
          ORDER BY sort_order, name", { Slice => {} }) || [];
    my %byc; push @{ $byc{ $_->{category_id} } }, { %$_, id => $_->{id}+0 } for @$vals;
    for my $c (@$cats) { $c->{id} += 0; $c->{values} = $byc{ $c->{id} } || []; }
    return $cats;
}

# Zone labels: [{category, slug, cardinality, value, value_id, color}].
sub zone_labels_get {
    my ($domain_id) = @_;
    return [] unless $domain_id;
    my $dbh = connectDB() or return [];
    my $rows = $dbh->selectall_arrayref(
        "SELECT c.name AS category, c.slug, c.cardinality, v.name AS value, v.id AS value_id, v.color
           FROM zone_labels zl JOIN label_values v ON v.id = zl.label_value_id
           JOIN label_categories c ON c.id = v.category_id
          WHERE zl.domain_id = ? ORDER BY c.sort_order, v.sort_order", { Slice => {} }, $domain_id) || [];
    $_->{value_id} += 0 for @$rows;
    return $rows;
}

# Bulk for the table: { domain_id => [labels] }.
sub zone_labels_map {
    my (@ids) = @_;
    return {} unless @ids;
    my $dbh = connectDB() or return {};
    my $ph = join(',', ('?') x @ids);
    my $rows = $dbh->selectall_arrayref(
        "SELECT zl.domain_id, c.name AS category, c.slug, v.name AS value, v.id AS value_id, v.color
           FROM zone_labels zl JOIN label_values v ON v.id = zl.label_value_id
           JOIN label_categories c ON c.id = v.category_id
          WHERE zl.domain_id IN ($ph) ORDER BY c.sort_order, v.sort_order", { Slice => {} }, @ids) || [];
    my %m; push @{ $m{ $_->{domain_id} } }, $_ for @$rows;
    return \%m;
}

# Replace zone labels with a set of value_ids (validation + single cardinality). (1,undef)|(undef,err).
sub zone_labels_set {
    my ($domain_id, $value_ids, $actor) = @_;
    return (undef, 'domain_id required') unless $domain_id;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    my @want = grep { defined && /^\d+$/ } @{ $value_ids || [] };
    my @ids;
    if (@want) {
        my $ph = join(',', ('?') x @want);
        my $rows = $dbh->selectall_arrayref(
            "SELECT v.id, v.category_id, c.cardinality FROM label_values v
               JOIN label_categories c ON c.id = v.category_id
              WHERE v.enabled = 1 AND v.id IN ($ph)", { Slice => {} }, @want) || [];
        my %valid = map { $_->{id} => $_ } @$rows;
        my (%single_seen, @final);
        for my $id (@want) {
            my $r = $valid{$id} or next;                      # unknown/disabled: dropped
            next if $r->{cardinality} eq 'single' && $single_seen{ $r->{category_id} }++;
            push @final, $id;
        }
        @ids = @final;
    }
    my $ok = eval {
        $dbh->begin_work;
        $dbh->do("DELETE FROM zone_labels WHERE domain_id = ?", undef, $domain_id);
        if (@ids) {
            my $sth = $dbh->prepare("INSERT INTO zone_labels (domain_id, label_value_id, created_by) VALUES (?,?,?)");
            $sth->execute($domain_id, $_, $actor) for @ids;
        }
        $dbh->commit or die "commit failed\n"; 1;
    };
    if (!$ok) { my $e = $@ || 'error'; chomp $e; eval { $dbh->rollback }; return (undef, $e); }
    return (1, undef);
}

sub zone_labels_delete_all {
    my ($domain_id) = @_;
    return unless $domain_id;
    my $dbh = connectDB() or return;
    $dbh->do("DELETE FROM zone_labels WHERE domain_id = ?", undef, $domain_id);
}

# --- Label taxonomy management (Settings -> Labels); requires capability labels.manage. ---

sub _slugify {
    my ($s) = @_;
    $s = lc($s // '');
    $s =~ s/[^a-z0-9]+/-/g; $s =~ s/^-+//; $s =~ s/-+$//;
    return $s;
}

# Create a category; cardinality: single|multiple. Returns (id, undef) | (undef, err).
sub label_category_create {
    my ($name, $cardinality) = @_;
    $name =~ s/^\s+//, $name =~ s/\s+$// if defined $name;
    return (undef, 'name required') unless defined $name && length $name;
    $cardinality = ($cardinality && $cardinality eq 'single') ? 'single' : 'multiple';
    my $slug = _slugify($name);
    return (undef, 'invalid name (need a-z0-9)') unless length $slug;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    return (undef, "category '$name' already exists")
        if $dbh->selectrow_array("SELECT id FROM label_categories WHERE slug=?", undef, $slug);
    my ($ord) = $dbh->selectrow_array("SELECT COALESCE(MAX(sort_order),0)+1 FROM label_categories");
    $dbh->do("INSERT INTO label_categories (name, slug, cardinality, sort_order) VALUES (?,?,?,?)",
             undef, $name, $slug, $cardinality, $ord) or return (undef, 'insert failed');
    return ($dbh->last_insert_id(undef,undef,undef,undef), undef);
}

# Delete a category (FK cascade removes its values and zone_labels assignments).
sub label_category_delete {
    my ($id) = @_;
    return (undef, 'id required') unless $id;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    $dbh->do("DELETE FROM label_categories WHERE id=?", undef, $id) or return (undef, 'delete failed');
    return (1, undef);
}

# Create a value in a category (optional #hex color). (id, undef) | (undef, err).
sub label_value_create {
    my ($category_id, $name, $color) = @_;
    $name =~ s/^\s+//, $name =~ s/\s+$// if defined $name;
    return (undef, 'category_id required') unless $category_id && $category_id =~ /^\d+$/;
    return (undef, 'name required') unless defined $name && length $name;
    if (defined $color && length $color) {
        return (undef, 'invalid color (use #rrggbb)') unless $color =~ /^#[0-9a-fA-F]{6}$/;
    } else { $color = undef; }
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    return (undef, 'unknown category')
        unless $dbh->selectrow_array("SELECT id FROM label_categories WHERE id=?", undef, $category_id);
    return (undef, "value '$name' already exists in category")
        if $dbh->selectrow_array("SELECT id FROM label_values WHERE category_id=? AND name=?", undef, $category_id, $name);
    my ($ord) = $dbh->selectrow_array("SELECT COALESCE(MAX(sort_order),0)+1 FROM label_values WHERE category_id=?", undef, $category_id);
    $dbh->do("INSERT INTO label_values (category_id, name, color, sort_order) VALUES (?,?,?,?)",
             undef, $category_id, $name, $color, $ord) or return (undef, 'insert failed');
    return ($dbh->last_insert_id(undef,undef,undef,undef), undef);
}

# Delete a value (FK cascade removes zone_labels assignments).
sub label_value_delete {
    my ($id) = @_;
    return (undef, 'id required') unless $id;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    $dbh->do("DELETE FROM label_values WHERE id=?", undef, $id) or return (undef, 'delete failed');
    return (1, undef);
}

# Single zone access check (for non-list places). $zone = hashref{id} or id.
sub effective_zone_access {
    my ($user, $zone) = @_;
    return 'none' unless $user;
    my $zid   = ref($zone) eq 'HASH' ? $zone->{id} : $zone;
    return access_for(build_access_context($user), $zid);
}

# Effective capability: ALLOWED (personally or via a group) AND NOT personally denied - like zone access.
# Previously grants only added up, so "Manage HA" could not be taken from one member of the admin group.
# Denies are personal only: a group "deny" is just the absence of a grant. One query for the whole
# panel: two different answers to "has the right?" would be a hole.
sub _cap_effective_sql {
    return "SELECT 1 WHERE EXISTS (
                SELECT 1 FROM capability_grants cg
                  LEFT JOIN user_groups ug ON ug.group_id = cg.subject_id
                 WHERE cg.capability = ? AND cg.effect = 'allow'
                   AND ( (cg.subject_type='user'  AND cg.subject_id = ?)
                      OR (cg.subject_type='group' AND ug.user_id   = ?) ) )
              AND NOT EXISTS (
                SELECT 1 FROM capability_grants d
                 WHERE d.capability = ? AND d.effect = 'deny'
                   AND d.subject_type = 'user' AND d.subject_id = ? )";
}

# Does the user have a panel capability (users.manage, ha.switchover, ...)?
sub has_capability {
    my ($user, $cap) = @_;
    return 0 unless $user && $cap;
    my $dbh = connectDB() or return 0;
    my ($r) = $dbh->selectrow_array(_cap_effective_sql(), undef, $cap, $user->{id}, $user->{id}, $cap, $user->{id});
    return $r ? 1 : 0;
}

# Strict capability check: (1|0, undef) | (undef,'DB unavailable'). Unlike has_capability (0 on any error,
# fail-closed for gates) it tells "no right" from "could not check", so the Router returns 503, not 403,
# when the DB is down.
sub capability_check {
    my ($user, $cap) = @_;
    return (0, undef) unless $user && $cap;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    my $r = $dbh->selectrow_arrayref(_cap_effective_sql(), undef, $cap, $user->{id}, $user->{id}, $cap, $user->{id});
    return (undef, _db_err_kind($dbh->err)) if $dbh->err;
    return ($r ? 1 : 0, undef);
}

# ============================================================================
# USERS & ACCESS: CRUD for users/permission groups + effective permissions (docs/20-permissions.md).
# Zone access resolution itself lives in build_access_context/access_for.
# ============================================================================
our @CAPABILITIES = qw(users.manage secondary.manage catalog.manage distribution.manage
                       ha.manage ha.emergency audit.read zones.manage labels.manage
                       pulse.manage);
our %IS_CAP = map { $_ => 1 } @CAPABILITIES;

# Effective capabilities of a user (direct + group, minus personal denies), sorted. \@caps.
sub effective_capabilities {
    my ($user_id) = @_;
    return [] unless $user_id && $user_id =~ /^\d+$/;
    my $dbh = connectDB() or return [];
    return $dbh->selectcol_arrayref(
        "SELECT DISTINCT cg.capability FROM capability_grants cg
           LEFT JOIN user_groups ug ON ug.group_id = cg.subject_id
          WHERE cg.effect = 'allow'
            AND ( (cg.subject_type='user'  AND cg.subject_id = ?)
               OR (cg.subject_type='group' AND ug.user_id   = ?) )
            AND NOT EXISTS (SELECT 1 FROM capability_grants d
                             WHERE d.capability = cg.capability AND d.effect = 'deny'
                               AND d.subject_type='user' AND d.subject_id = ?)
          ORDER BY cg.capability", undef, $user_id, $user_id, $user_id) || [];
}

sub _admin_count_sql {
    return "SELECT COUNT(DISTINCT u.id) FROM users u
              LEFT JOIN user_groups ug ON ug.user_id = u.id
              JOIN capability_grants cg ON cg.capability='users.manage' AND cg.effect='allow'
                AND ( (cg.subject_type='user'  AND cg.subject_id = u.id)
                   OR (cg.subject_type='group' AND cg.subject_id = ug.group_id) )
             WHERE u.is_active = 1
               AND NOT EXISTS (SELECT 1 FROM capability_grants d
                                WHERE d.capability='users.manage' AND d.effect='deny'
                                  AND d.subject_type='user' AND d.subject_id = u.id)";
}
sub _txn_keep_admin {
# Mutation in a transaction guaranteeing at least one active admin with users.manage remains (else
# rollback). $code: a sub making changes on $dbh (die 'db' on error). ($ok, undef) | (undef, err).
    my ($dbh, $code) = @_;
    # SERIALIZED by an advisory lock, otherwise two concurrent transactions could strip the last two admins
    # (each sees before>=1). GET_LOCK is not transactional -> RELEASE_LOCK on ALL branches.
    my ($got) = $dbh->selectrow_array("SELECT GET_LOCK('dns-panel:last-admin', 5)");
    return (undef, 'busy: another admin change is in progress') unless $got;   # 0 = timeout, NULL = error
    my $rel = sub { eval { $dbh->do("SELECT RELEASE_LOCK('dns-panel:last-admin')") }; };
    (my $bo, my $be) = _txn_begin($dbh);
    if ($be) { $rel->(); return (undef, $be); }
    # rollback + release + error (single exit for any problem).
    my $fail = sub { my ($err) = @_; eval { $dbh->rollback }; $rel->(); return (undef, $err); };
    my ($before) = $dbh->selectrow_array(_admin_count_sql());  return $fail->(_db_err_kind($dbh->err)) if $dbh->err;
    my $done = eval { $code->(); 1 };
    if (!$done) { my $e = $@ || 'failed'; $e =~ s/\n//g; return $fail->($e eq 'db' ? _db_err_kind($dbh->err) : $e); }
    my ($after) = $dbh->selectrow_array(_admin_count_sql());   return $fail->(_db_err_kind($dbh->err)) if $dbh->err;
    # Refuse ONLY if there was >=1 admin and now 0 (otherwise everything would be blocked before bootstrap).
    return $fail->('refused: would remove the last active administrator (users.manage)') if ($before // 0) >= 1 && !($after // 0);
    my $ok = $dbh->commit;
    if (!$ok || $dbh->err) { my $err = _db_err_kind($dbh->err) || 'commit failed'; eval { $dbh->rollback }; $rel->(); return (undef, $err); }
    $rel->();
    return (1, undef);
}

# ---- Users ----
sub users_all {
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $rows, my $e) = _db_all($dbh,
        "SELECT u.id, u.username, u.display_name, u.email, u.is_active,
                (SELECT COUNT(*) FROM user_groups g WHERE g.user_id=u.id) AS group_count,
                (SELECT COUNT(*) FROM password_credentials p WHERE p.user_id=u.id) AS has_password,
                (SELECT COUNT(*) FROM totp_credentials t WHERE t.user_id=u.id AND t.confirmed_at IS NOT NULL) AS has_totp,
                (SELECT COUNT(*) FROM auth_identities a WHERE a.user_id=u.id AND a.type='cert') AS cert_count,
                (SELECT MAX(created_at) FROM sessions s WHERE s.user_id=u.id AND s.stage='full') AS last_login,
                ((EXISTS(SELECT 1 FROM capability_grants cg WHERE cg.subject_type='user' AND cg.subject_id=u.id AND cg.capability='users.manage' AND cg.effect='allow')
                  OR EXISTS(SELECT 1 FROM user_groups ug2 JOIN capability_grants cg2 ON cg2.subject_type='group' AND cg2.subject_id=ug2.group_id AND cg2.capability='users.manage' AND cg2.effect='allow' WHERE ug2.user_id=u.id))
                 AND NOT EXISTS(SELECT 1 FROM capability_grants d WHERE d.subject_type='user' AND d.subject_id=u.id AND d.capability='users.manage' AND d.effect='deny')) AS is_admin
           FROM users u ORDER BY u.username", { Slice => {} });
    return (undef, $e) if $e;
    for (@$rows) { $_->{id} += 0; $_->{is_active} += 0; $_->{group_count} += 0;
                   $_->{has_password} += 0; $_->{has_totp} += 0; $_->{cert_count} += 0; $_->{is_admin} += 0; }
    return ($rows, undef);
}
sub user_get {
    my ($id) = @_;
    return (undef, 'not found') unless $id && $id =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $u, my $e) = _db_row($dbh, "SELECT id, username, display_name, email, is_active FROM users WHERE id=?", $id); return (undef, $e) if $e;
    return (undef, 'not found') unless $u;
    $u->{id} += 0; $u->{is_active} += 0;
    (my $ids, $e) = _db_all($dbh, "SELECT id, type, provider, principal, is_active, last_used_at FROM auth_identities WHERE user_id=? ORDER BY type", { Slice => {} }, $id); return (undef, $e) if $e;
    $_->{id} += 0 for @$ids; $u->{identities} = $ids;   # the secret is never returned
    # Groups + their capabilities and zone_access (for the permission "source" and effective access in the UI).
    (my $grp, $e) = _db_all($dbh, "SELECT g.id, g.name FROM user_groups ug JOIN groups g ON g.id=ug.group_id WHERE ug.user_id=? ORDER BY g.name", { Slice => {} }, $id); return (undef, $e) if $e;
    for my $g (@$grp) {
        $g->{id} += 0;
        (my $gc) = _db_all($dbh, "SELECT capability FROM capability_grants WHERE subject_type='group' AND subject_id=? ORDER BY capability", { Slice => {} }, $g->{id});
        $g->{capabilities} = [ map { $_->{capability} } @{ $gc || [] } ];
        (my $gz) = _db_all($dbh, "SELECT id, scope, zone_id, access FROM zone_access WHERE subject_type='group' AND subject_id=? ORDER BY scope", { Slice => {} }, $g->{id});
        for (@{ $gz || [] }) { $_->{id} += 0; $_->{zone_id} = defined $_->{zone_id} ? $_->{zone_id}+0 : undef; }
        $g->{zone_access} = $gz || [];
    }
    $u->{groups} = $grp;
    (my $dc, $e) = _db_all($dbh, "SELECT capability, effect FROM capability_grants WHERE subject_type='user' AND subject_id=? ORDER BY capability", { Slice => {} }, $id); return (undef, $e) if $e;
    $u->{direct_capabilities}    = [ map { $_->{capability} } grep { $_->{effect} eq 'allow' } @$dc ];
    # Personal denies as a separate list: the screen must show the right was taken from this person,
    # not just "no right".
    $u->{denied_capabilities}    = [ map { $_->{capability} } grep { $_->{effect} eq 'deny'  } @$dc ];
    $u->{effective_capabilities} = effective_capabilities($id);
    # Source of each capability: direct and/or via which groups (UI "via <group> / Direct").
    my %src;
    $src{$_}{direct} = 1 for @{ $u->{direct_capabilities} };
    for my $g (@$grp) { push @{ $src{$_}{groups} }, { id => $g->{id}, name => $g->{name} } for @{ $g->{capabilities} }; }
    $u->{capability_sources} = \%src;
    (my $za, $e) = _db_all($dbh, "SELECT id, scope, zone_id, access FROM zone_access WHERE subject_type='user' AND subject_id=? ORDER BY scope", { Slice => {} }, $id); return (undef, $e) if $e;
    for (@$za) { $_->{id} += 0; $_->{zone_id} = defined $_->{zone_id} ? $_->{zone_id}+0 : undef; }
    $u->{zone_overrides} = $za;
    # auth status for the Authentication tab.
    my ($tconf) = $dbh->selectrow_array("SELECT confirmed_at FROM totp_credentials WHERE user_id=?", undef, $id);
    my ($treq) = $dbh->selectrow_array("SELECT totp_required FROM users WHERE id=?", undef, $id);
    $u->{totp} = { enrolled => ($tconf ? 1 : 0), required => (($treq // 0) + 0) };
    my ($pset, $pmust) = $dbh->selectrow_array("SELECT 1, must_change FROM password_credentials WHERE user_id=?", undef, $id);
    $u->{password} = { set => ($pset ? 1 : 0), must_change => (($pmust // 0) + 0) };
    ($u->{last_login}) = $dbh->selectrow_array("SELECT MAX(created_at) FROM sessions WHERE user_id=? AND stage='full'", undef, $id);
    return ($u, undef);
}

# An admin manages SOMEONE ELSE's second factor. Exactly two actions, differing only in whether we expect
# the person to enroll the app again:
#   auth_totp_reset   - "lost the phone / reinstalled the app": the old app is unlinked but the second
#                       factor stays required; the next login asks to enroll a new one
#                       (users.totp_required=1).
#   auth_totp_disable - "no second factor needed": unlinked and no longer asked; the person can enable it
#                       again in Account (or an admin via Require).
# Both delete the secret and recovery codes and revoke sessions. (1,undef)|(undef,err).
sub _auth_totp_clear {
    my ($uid, $required) = @_;
    return (undef, 'user id required') unless $uid && $uid =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    my ($ex) = $dbh->selectrow_array("SELECT 1 FROM users WHERE id=?", undef, $uid);
    return (undef, 'unknown user') unless $ex;
    (my $bo, my $be) = _txn_begin($dbh); return (undef, $be) if $be;
    my $fail = sub { my ($e) = @_; eval { $dbh->rollback }; return (undef, $e); };
    my $done = eval {
        $dbh->do("DELETE FROM totp_credentials WHERE user_id=?", undef, $uid); die "db\n" if $dbh->err;
        $dbh->do("DELETE FROM recovery_codes  WHERE user_id=?", undef, $uid); die "db\n" if $dbh->err;
        $dbh->do("UPDATE users SET totp_required=? WHERE id=?", undef, ($required ? 1 : 0), $uid); die "db\n" if $dbh->err;
        $dbh->do("UPDATE sessions SET is_active=0 WHERE user_id=? AND is_active=1", undef, $uid); die "db\n" if $dbh->err;
        1;
    };
    if (!$done) { return $fail->(_db_err_kind($dbh->err) || 'DB error'); }
    my $ok = $dbh->commit;
    if (!$ok || $dbh->err) { return $fail->(_db_err_kind($dbh->err) || 'commit failed'); }
    return (1, undef);
}
sub auth_totp_reset   { my ($uid) = @_; return _auth_totp_clear($uid, 1); }
sub auth_totp_disable { my ($uid) = @_; return _auth_totp_clear($uid, 0); }

# Require a second factor without unlinking anything: the person has no app yet and will be asked to
# enroll at the next login. Sessions are left alone - they reach that step on the next login anyway.
# (1,undef)|(undef,err).
sub auth_totp_require {
    my ($uid, $on) = @_;
    return (undef, 'user id required') unless $uid && $uid =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    my ($ex) = $dbh->selectrow_array("SELECT 1 FROM users WHERE id=?", undef, $uid);
    return (undef, 'unknown user') unless $ex;
    (my $ok, my $e) = _do($dbh, "UPDATE users SET totp_required=? WHERE id=?", ($on ? 1 : 0), $uid);
    return (undef, $e) if $e;
    return (1, undef);
}

# Active (unexpired) sessions of a user, for the Sessions tab. (\@rows, undef)|(undef,err).
sub user_sessions {
    my ($uid, $current_id) = @_;
    return (undef, 'user id required') unless $uid && $uid =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $rows, my $e) = _db_all($dbh,
        "SELECT id, auth_type, stage, remember, ip, user_agent,
                UNIX_TIMESTAMP(created_at) AS created_at, UNIX_TIMESTAMP(expires_at) AS expires_at
           FROM sessions WHERE user_id=? AND is_active=1 AND expires_at > UTC_TIMESTAMP()
          ORDER BY created_at DESC", { Slice => {} }, $uid);
    return (undef, $e) if $e;
    for (@$rows) { $_->{id} += 0; $_->{remember} += 0; $_->{is_current} = ($current_id && $_->{id} == $current_id) ? 1 : 0; }
    return ($rows, undef);
}

# ============================ ACCOUNT (self-service) ============================
# A person manages ONLY themselves here: password, authenticator app, sessions, display settings.
# users.manage is irrelevant - otherwise only an admin could change their own password.
# Unlike the admin reset (which SETS a password for someone locked out), this CHANGES it and so asks for
# the current one. The session making the change stays alive; other sessions are closed (the password
# may have leaked).

# Everything the Account page needs. (\%info, undef) | (undef, err).
sub account_overview {
    my ($uid, $cur_sid) = @_;
    return (undef, 'user id required') unless $uid && "$uid" =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $u, my $ue) = _db_row($dbh,
        "SELECT username, email, display_name, timezone, date_format, theme, totp_required FROM users WHERE id=?", $uid);
    return (undef, $ue) if $ue;
    return (undef, 'unknown user') unless $u;
    (my $t, my $te) = _db_row($dbh,
        "SELECT UNIX_TIMESTAMP(confirmed_at) AS confirmed_at,
                (pending_secret_encrypted IS NOT NULL) AS pending
           FROM totp_credentials WHERE user_id=?", $uid);
    return (undef, $te) if $te;
    (my $rc, my $rce) = _db_row($dbh,
        "SELECT COUNT(*) AS left_codes FROM recovery_codes WHERE user_id=? AND used_at IS NULL", $uid);
    return (undef, $rce) if $rce;
    # GROUPS, not users.role: there are no roles in this model - rights come from group membership and
    # personal grants.
    (my $grp, my $ge) = _db_all($dbh,
        "SELECT g.name FROM user_groups ug JOIN groups g ON g.id=ug.group_id WHERE ug.user_id=? ORDER BY g.name",
        { Slice => {} }, $uid);
    return (undef, $ge) if $ge;
    (my $sess, my $se) = user_sessions($uid, $cur_sid);
    return (undef, $se) if $se;
    return ({
        username     => $u->{username},
        email        => $u->{email},
        display_name => $u->{display_name},
        groups       => [ map { $_->{name} } @{ $grp || [] } ],
        timezone     => $u->{timezone},
        date_format  => $u->{date_format},
        theme        => $u->{theme},
        totp         => { enrolled => ($t && $t->{confirmed_at} ? 1 : 0),
                          confirmed_at => ($t ? $t->{confirmed_at} : undef),
                          replacing => ($t && $t->{pending} ? 1 : 0),
                          required  => (($u->{totp_required} // 0) + 0) },
        recovery_codes_left => ($rc ? $rc->{left_codes} + 0 : 0),
        sessions     => $sess,
    }, undef);
}

# Change OWN password. The current one is required - otherwise an unattended screen equals a password
# change. $keep_sid: the session making the change stays, all others are closed. (1, undef) | (undef, err).
sub account_password_change {
    my ($uid, $current, $new, $keep_sid) = @_;
    return (undef, 'user id required') unless $uid && "$uid" =~ /^\d+$/;
    return (undef, 'current password is required') unless defined $current && length $current;
    return (undef, 'new password too short (min 8)') unless defined $new && length $new >= 8;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    my ($hash_cur) = $dbh->selectrow_array("SELECT password_hash FROM password_credentials WHERE user_id=?", undef, $uid);
    return (undef, 'no password is set for this account') unless $hash_cur;
    return (undef, 'current password is wrong') unless password_verify($hash_cur, $current);
    return (undef, 'new password must differ from the current one') if password_verify($hash_cur, $new);
    my $hash = eval { password_hash($new) }; return (undef, 'hashing failed') unless $hash;   # expensive - outside the txn
    (my $bo, my $be) = _txn_begin($dbh); return (undef, $be) if $be;
    my $fail = sub { my ($e) = @_; eval { $dbh->rollback }; return (undef, $e); };
    my $done = eval {
        $dbh->do("UPDATE password_credentials SET password_hash=?, must_change=0 WHERE user_id=?", undef, $hash, $uid);
        die "db\n" if $dbh->err;
        my @a = ($uid); my $sql = "UPDATE sessions SET is_active=0 WHERE user_id=? AND is_active=1";
        if ($keep_sid && "$keep_sid" =~ /^\d+$/) { $sql .= " AND id<>?"; push @a, $keep_sid; }
        $dbh->do($sql, undef, @a); die "db\n" if $dbh->err;
        1;
    };
    return $fail->(_db_err_kind($dbh->err) || 'DB error') unless $done;
    unless ($dbh->commit) { my $k = _db_err_kind($dbh->err); eval { $dbh->rollback }; return (undef, $k); }
    return (1, undef);
}

# Start replacing the authenticator app. The old one keeps working until the new one is confirmed with a
# code: an abandoned replacement must not lock the person out. (\%{otpauth,qr_png_base64,secret}, undef).
sub account_totp_begin {
    my ($uid, $issuer_label) = @_;
    return (undef, 'user id required') unless $uid && "$uid" =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    require Auth::GoogleAuth;
    my $secret = Auth::GoogleAuth->new->generate_secret32;
    my $enc = eval { _totp_encrypt($secret) }; return (undef, 'master key unavailable: ' . ($@ || '?')) unless defined $enc;
    my ($conf) = $dbh->selectrow_array("SELECT confirmed_at FROM totp_credentials WHERE user_id=?", undef, $uid);
    if ($conf) {
        (my $ok, my $e) = _do($dbh, "UPDATE totp_credentials SET pending_secret_encrypted=?, pending_created_at=UTC_TIMESTAMP()
                                      WHERE user_id=?", $enc, $uid);
        return (undef, $e) if $e;
    } else {
        # No second factor yet (or enrollment unfinished): nothing to replace, write directly.
        (my $ok, my $e) = _do($dbh,
            "INSERT INTO totp_credentials (user_id, secret_encrypted, key_version, confirmed_at, last_used_step)
             VALUES (?,?,1,NULL,NULL)
             ON DUPLICATE KEY UPDATE secret_encrypted=VALUES(secret_encrypted), key_version=1, last_used_step=NULL",
            $uid, $enc);
        return (undef, $e) if $e;
    }
    my ($uname) = $dbh->selectrow_array("SELECT username FROM users WHERE id=?", undef, $uid);
    my $otpauth = _otpauth_uri($secret, ($uname // 'user'), ($issuer_label || 'DNS Panel'));
    my $png = eval { _qr_png_base64($otpauth) };
    return ({ otpauth => $otpauth, qr_png_base64 => $png, secret => $secret }, undef);
}

# Confirm the new app with its first code. Only now is the old secret replaced, and new recovery codes
# are issued at once (the old ones belonged to the previous app). (\@codes, undef) | (undef, err).
sub account_totp_confirm {
    my ($uid, $code) = @_;
    return (undef, 'user id required') unless $uid && "$uid" =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $row, my $re) = _db_row($dbh,
        "SELECT secret_encrypted, pending_secret_encrypted, confirmed_at FROM totp_credentials WHERE user_id=?", $uid);
    return (undef, $re) if $re;
    return (undef, 'nothing to confirm') unless $row;
    my $replacing = defined $row->{pending_secret_encrypted} ? 1 : 0;
    my $enc = $replacing ? $row->{pending_secret_encrypted} : $row->{secret_encrypted};
    return (undef, 'nothing to confirm') if !$replacing && $row->{confirmed_at};
    my $secret = _totp_decrypt($enc); return (undef, 'totp secret unreadable') unless defined $secret;
    my $step = _totp_check($secret, $code, undef); return (undef, 'invalid code') unless defined $step;

    my ($plain, $hash) = _recovery_gen();
    (my $bo, my $be) = _txn_begin($dbh); return (undef, $be) if $be;
    my $fail = sub { my ($e) = @_; eval { $dbh->rollback }; return (undef, $e); };
    my $done = eval {
        # Confirm EXACTLY the secret that was read: a concurrent replacement that wrote another -> rows==0.
        my $rc = $replacing
            ? $dbh->do("UPDATE totp_credentials SET secret_encrypted=pending_secret_encrypted,
                          pending_secret_encrypted=NULL, pending_created_at=NULL,
                          confirmed_at=UTC_TIMESTAMP(), last_used_step=?
                        WHERE user_id=? AND pending_secret_encrypted=?", undef, $step, $uid, $enc)
            : $dbh->do("UPDATE totp_credentials SET confirmed_at=UTC_TIMESTAMP(), last_used_step=?
                        WHERE user_id=? AND confirmed_at IS NULL AND secret_encrypted=?", undef, $step, $uid, $enc);
        die "db\n" if $dbh->err;
        die "gone\n" unless $rc && $rc == 1;
        $dbh->do("DELETE FROM recovery_codes WHERE user_id=?", undef, $uid); die "db\n" if $dbh->err;
        for my $h (@$hash) {
            $dbh->do("INSERT INTO recovery_codes (user_id, code_hash) VALUES (?,?)", undef, $uid, $h);
            die "db\n" if $dbh->err;
        }
        1;
    };
    unless ($done) { my $e = $@ || 'failed'; chomp $e;
        return $fail->($e eq 'db' ? (_db_err_kind($dbh->err) || 'DB error') : 'invalid code'); }
    unless ($dbh->commit) { my $k = _db_err_kind($dbh->err); eval { $dbh->rollback }; return (undef, $k); }
    return ($plain, undef);
}

# Disable OWN second factor. Asks for an app code, as for new recovery codes: an open screen does not
# prove the app is at hand, and disabling the factor matters no less. Recovery codes go too (they
# belonged to this app). Sessions are left alone: nothing leaked.
# (1, undef) | (undef, 'two-factor is not enabled'|'invalid code'|err).
sub account_totp_disable {
    my ($uid, $code) = @_;
    return (undef, 'user id required') unless $uid && "$uid" =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    my ($req) = $dbh->selectrow_array("SELECT totp_required FROM users WHERE id=?", undef, $uid);
    return (undef, 'two-factor is required for this account by an administrator') if $req;
    my ($enc, $last) = $dbh->selectrow_array(
        "SELECT secret_encrypted, last_used_step FROM totp_credentials WHERE user_id=? AND confirmed_at IS NOT NULL", undef, $uid);
    return (undef, 'two-factor is not enabled') unless defined $enc;
    my $secret = _totp_decrypt($enc); return (undef, 'totp secret unreadable') unless defined $secret;
    return (undef, 'invalid code') unless defined _totp_check($secret, $code, $last);
    (my $bo, my $be) = _txn_begin($dbh); return (undef, $be) if $be;
    my $fail = sub { my ($e) = @_; eval { $dbh->rollback }; return (undef, $e); };
    my $done = eval {
        $dbh->do("DELETE FROM totp_credentials WHERE user_id=?", undef, $uid); die "db\n" if $dbh->err;
        $dbh->do("DELETE FROM recovery_codes  WHERE user_id=?", undef, $uid); die "db\n" if $dbh->err;
        1;
    };
    return $fail->(_db_err_kind($dbh->err) || 'DB error') unless $done;
    unless ($dbh->commit) { my $k = _db_err_kind($dbh->err); eval { $dbh->rollback }; return (undef, $k); }
    return (1, undef);
}

# Abandon an unfinished replacement. (1, undef).
sub account_totp_cancel {
    my ($uid) = @_;
    return (undef, 'user id required') unless $uid && "$uid" =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $ok, my $e) = _do($dbh, "UPDATE totp_credentials SET pending_secret_encrypted=NULL, pending_created_at=NULL
                                  WHERE user_id=? AND confirmed_at IS NOT NULL", $uid);
    return (undef, $e) if $e;
    return (1, undef);
}

# Issue new recovery codes. Asks for an app code: access to the screen does not prove the app is at
# hand. (\@codes, undef) | (undef, err).
sub account_recovery_regenerate {
    my ($uid, $code) = @_;
    return (undef, 'user id required') unless $uid && "$uid" =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    my ($enc, $last) = $dbh->selectrow_array(
        "SELECT secret_encrypted, last_used_step FROM totp_credentials WHERE user_id=? AND confirmed_at IS NOT NULL", undef, $uid);
    return (undef, 'two-factor authentication is not set up') unless defined $enc;
    my $secret = _totp_decrypt($enc); return (undef, 'totp secret unreadable') unless defined $secret;
    my $step = _totp_check($secret, $code, $last); return (undef, 'invalid code') unless defined $step;
    my ($plain, $hash) = _recovery_gen();
    (my $bo, my $be) = _txn_begin($dbh); return (undef, $be) if $be;
    my $fail = sub { my ($e) = @_; eval { $dbh->rollback }; return (undef, $e); };
    my $done = eval {
        # Same anti-replay as at login: the code's step is consumed.
        my $rc = $dbh->do("UPDATE totp_credentials SET last_used_step=? WHERE user_id=? AND (last_used_step IS NULL OR last_used_step < ?)",
                          undef, $step, $uid, $step);
        die "db\n" if $dbh->err;
        die "gone\n" unless $rc && $rc == 1;
        $dbh->do("DELETE FROM recovery_codes WHERE user_id=?", undef, $uid); die "db\n" if $dbh->err;
        for my $h (@$hash) {
            $dbh->do("INSERT INTO recovery_codes (user_id, code_hash) VALUES (?,?)", undef, $uid, $h);
            die "db\n" if $dbh->err;
        }
        1;
    };
    unless ($done) { my $e = $@ || 'failed'; chomp $e;
        return $fail->($e eq 'db' ? (_db_err_kind($dbh->err) || 'DB error') : 'invalid code'); }
    unless ($dbh->commit) { my $k = _db_err_kind($dbh->err); eval { $dbh->rollback }; return (undef, $k); }
    return ($plain, undef);
}

# Themes: code -> label. Empty = "same as the browser": css/themes/auto.css follows the system scheme by
# media query, with no script and no flash of the wrong theme. Dark is main.css itself and needs no file;
# every other theme must have one.
our @THEMES = (
    [ ''                  => 'Same as this browser' ],
    [ 'dark'              => 'Dark'                 ],
    [ 'light'             => 'Light'                ],
    [ 'nord' => 'Nord' ],
    [ 'dracula'           => 'Dracula'              ],
    [ 'gruvbox-dark'      => 'Gruvbox Dark'         ],
    [ 'tokyo-night'       => 'Tokyo Night'          ],
    [ 'solarized-dark'    => 'Solarized Dark'       ],
    [ 'solarized-light'   => 'Solarized Light'      ],
    [ 'catppuccin-latte'  => 'Catppuccin Latte'     ],
    [ 'coffee'            => 'Coffee'               ],
    [ 'gruvbox-light'     => 'Gruvbox Light'        ],
    [ 'matrix'            => 'Matrix'               ],
    [ 'blueprint'         => 'Blueprint'            ],
    [ 'steampunk'         => 'Steampunk'            ],
    [ 'synthwave'         => 'Synthwave'            ],
    [ 'sakura'            => 'Sakura'               ],
    [ 'cubism'            => 'Cubism'               ],
    [ 'amber'             => 'Amber terminal'       ],
);
sub account_themes { return [ map { { value => $_->[0], label => $_->[1] } } @THEMES ] }
# <link> to the theme file for <head>, shared by the whole site and the login page. The SERVER adds it,
# not a script after load, otherwise the page flashes the wrong theme. Dark is main.css ('' returned);
# none or unknown -> auto.css, which enables the light palette by media query when the browser is light.
sub theme_css_link {
    my ($theme) = @_;
    my %known = map { $_->[0] => 1 } @THEMES;
    $theme = 'auto' unless defined $theme && length $theme && $known{$theme};
    return '' if $theme eq 'dark';
    my $v = asset_version("/css/themes/$theme.css");
    return qq{    <link rel="stylesheet" href="/css/themes/$theme.css?v=$v">\n};
}
# Personal display settings: time zone and theme. Times are always stored in UTC; the zone applies only
# to display and does not affect background schedules. NULL/'' zone = browser's; theme = default.
our %DATE_FORMATS = map { $_ => 1 } qw(dmy iso mdy);
sub account_prefs_set {
    my ($uid, $tz, $theme, $df) = @_;
    return (undef, 'user id required') unless $uid && "$uid" =~ /^\d+$/;
    my %ok_theme = map { $_->[0] => 1 } @THEMES;
    $tz    = _trim($tz);    $tz    = undef unless defined $tz    && length $tz;
    $theme = _trim($theme); $theme = undef unless defined $theme && length $theme;
    return (undef, 'unknown theme') if defined $theme && !$ok_theme{$theme};
    $df = _trim($df); $df = undef unless defined $df && length $df;
    return (undef, 'unknown date format') if defined $df && !$DATE_FORMATS{$df};
    if (defined $tz) {
        # IANA zone name syntax, and the system must know the zone - otherwise the screen would silently show
        # UTC while the person thinks their choice was saved.
        return (undef, 'invalid time zone') unless $tz =~ m{^[A-Za-z][A-Za-z0-9_+/-]{0,63}$};
        return (undef, "unknown time zone '$tz'") unless -e "/usr/share/zoneinfo/$tz";
    }
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $ok, my $e) = _do($dbh, "UPDATE users SET timezone=?, date_format=?, theme=? WHERE id=?", $tz, $df, $theme, $uid);
    return (undef, $e) if $e;
    return ({ timezone => $tz, date_format => $df, theme => $theme }, undef);
}

# ============================ SESSION POLICY ============================
sub session_ttl_default { my $v = setting('auth.session_ttl'); return ("$v" =~ /^\d+$/ && $v > 0) ? $v + 0 : 86400; }
sub user_session_ttl {
    my ($uid) = @_;
    my $dbh = connectDB() or return session_ttl_default();
    my ($t) = $dbh->selectrow_array("SELECT session_ttl FROM users WHERE id=?", undef, $uid);
    return ($t && $t > 0) ? $t + 0 : session_ttl_default();
}
# Personal TTL: positive int (seconds) or undef = system default. Active full sessions are SHORTENED to
# the new policy (expires_at = LEAST(expires_at, created_at + new_ttl)), never extended. (1,undef)|(undef,err).
sub set_user_session_ttl {
    my ($uid, $ttl) = @_;
    return (undef, 'user id required') unless $uid && $uid =~ /^\d+$/;
    if (defined $ttl && "$ttl" ne '') {
        return (undef, 'session_ttl must be a positive integer') unless "$ttl" =~ /^\d+$/ && $ttl > 0;
        return (undef, 'session_ttl too small (min 300s)') if $ttl < 300;
        return (undef, 'session_ttl too large')            if $ttl > 315360000;   # 10 years
        $ttl += 0;
    } else { $ttl = undef; }
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    my ($ex) = $dbh->selectrow_array("SELECT 1 FROM users WHERE id=?", undef, $uid); return (undef, 'unknown user') unless $ex;
    my $eff = (defined $ttl && $ttl > 0) ? $ttl : session_ttl_default();
    (my $bo, my $be) = _txn_begin($dbh); return (undef, $be) if $be;
    my $fail = sub { my ($e) = @_; eval { $dbh->rollback }; return (undef, $e); };
    my $done = eval {
        $dbh->do("UPDATE users SET session_ttl=? WHERE id=?", undef, $ttl, $uid); die "db\n" if $dbh->err;
        $dbh->do("UPDATE sessions SET expires_at = LEAST(expires_at, DATE_ADD(created_at, INTERVAL ? SECOND)) WHERE user_id=? AND stage='full' AND is_active=1", undef, $eff, $uid); die "db\n" if $dbh->err;
        1;
    };
    if (!$done) { return $fail->(_db_err_kind($dbh->err) || 'DB error'); }
    my $ok = $dbh->commit;
    if (!$ok || $dbh->err) { return $fail->(_db_err_kind($dbh->err) || 'commit failed'); }
    return (1, undef);
}
# Raw personal TTL: seconds or undef (no override, inherits the default). Lets the UI tell default from override.
sub user_session_ttl_raw {
    my ($uid) = @_;
    my $dbh = connectDB() or return undef;
    my ($t) = $dbh->selectrow_array("SELECT session_ttl FROM users WHERE id=?", undef, $uid);
    return defined $t ? $t + 0 : undef;
}
# Revoke one session of a user (scoped by user_id). (1|0, undef)|(undef,err).
sub session_revoke {
    my ($uid, $sid) = @_;
    return (undef, 'ids required') unless $uid && $uid =~ /^\d+$/ && $sid && "$sid" =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    my $rc = $dbh->do("UPDATE sessions SET is_active=0 WHERE id=? AND user_id=? AND is_active=1", undef, $sid, $uid);
    return (undef, _db_err_kind($dbh->err)) if $dbh->err;
    return (($rc && $rc > 0) ? 1 : 0, undef);
}
# Revoke ALL active sessions of a user (optionally except $except). (count, undef)|(undef,err).
sub session_revoke_all {
    my ($uid, $except) = @_;
    return (undef, 'user id required') unless $uid && $uid =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    my @a = ($uid); my $sql = "UPDATE sessions SET is_active=0 WHERE user_id=? AND is_active=1";
    if ($except && "$except" =~ /^\d+$/) { $sql .= " AND id<>?"; push @a, $except; }
    my $rc = $dbh->do($sql, undef, @a); return (undef, _db_err_kind($dbh->err)) if $dbh->err;
    return (($rc // 0) + 0, undef);
}

# Atomically REPLACE a user's whole personal access in one request (Access tab: one draft -> one Save).
# $b: { group_ids, capabilities=>[...] (direct grants), denied_capabilities, zone_rules=>[{scope,zone_id?,access}...] }.
# One transaction under the last-admin guard. scope=zone zones are checked in PowerDNS (fail-closed).
# (1,undef)|(undef,err).
sub user_access_set {
    my ($uid, $b) = @_; $b ||= {};
    return (undef, 'user id required') unless $uid && $uid =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    my ($ex) = $dbh->selectrow_array("SELECT 1 FROM users WHERE id=?", undef, $uid);
    return (undef, 'unknown user') unless $ex;
    # Full replace contract: ALL fields are required (empty array is fine, missing -> 400), so a partial
    # body cannot accidentally wipe half the access.
    my $groups = $b->{group_ids};
    my $caps   = $b->{capabilities};
    my $denied = $b->{denied_capabilities};
    my $rules  = $b->{zone_rules};
    return (undef, 'group_ids required (array)')    unless ref $groups eq 'ARRAY';
    return (undef, 'capabilities required (array)') unless ref $caps   eq 'ARRAY';
    # denied_capabilities is part of the same full replace: a forgotten field would silently drop all denies.
    return (undef, 'denied_capabilities required (array)') unless ref $denied eq 'ARRAY';
    return (undef, 'zone_rules required (array)')   unless ref $rules  eq 'ARRAY';
    for my $c (@$caps)   { return (undef, "unknown capability: $c") unless $IS_CAP{$c}; }
    for my $c (@$denied) { return (undef, "unknown capability: $c") unless $IS_CAP{$c}; }
    { my %a = map { $_ => 1 } @$caps;
      for my $c (@$denied) {
          return (undef, "capability cannot be granted and denied at once: $c") if $a{$c};
      } }
    my %seen_g; my @gids;
    for my $g (@$groups) { return (undef, 'group_ids must be integers') unless defined $g && "$g" =~ /^\d+$/;
                           next if $seen_g{$g + 0}++; push @gids, $g + 0; }
    if (@gids) {
        my $ph = join(',', ('?') x @gids); my %have;
        my $got = $dbh->selectall_arrayref("SELECT id FROM groups WHERE id IN ($ph)", undef, @gids) || [];
        $have{ $_->[0] } = 1 for @$got;
        for my $g (@gids) { return (undef, 'unknown group') unless $have{$g}; }
    }
    my (@zids, $seen_all, %seen_zone);
    for my $r (@$rules) {
        my $sc = $r->{scope}  // ''; return (undef, 'scope must be all|zone')  unless $sc =~ /^(all|zone)$/;
        my $ac = $r->{access} // ''; return (undef, 'access must be none|read|write') unless $ac =~ /^(none|read|write)$/;
        if ($sc eq 'all')   { return (undef, 'duplicate rule: all') if $seen_all++; }
        if ($sc eq 'zone')  { return (undef, 'zone_id required') unless defined $r->{zone_id} && "$r->{zone_id}" =~ /^\d+$/;
                              my $z = $r->{zone_id} + 0; return (undef, "duplicate rule: zone $z") if $seen_zone{$z}++; push @zids, $z; }
    }
    if (@zids) {   # fail-closed: PDNS unavailable -> nothing saved
        my $pdns = connectPDNS() or return (undef, 'DB unavailable');
        my $ph = join(',', ('?') x @zids); my %have;
        my $got = $pdns->selectall_arrayref("SELECT id FROM domains WHERE id IN ($ph)", undef, @zids) || [];
        $have{ $_->[0] } = 1 for @$got;
        my $cat = _catalog_domain_ids($dbh) or return (undef, 'DB unavailable');   # catalog producer zones are not assignable (fail-closed)
        for my $z (@zids) { return (undef, 'unknown zone') unless $have{$z};
                            return (undef, 'zone not eligible: catalog producer zone') if $cat->{$z}; }
    }
    my %seen;  my @capsU = grep { !$seen{$_}++ }  @$caps;
    my %seend; my @denyU = grep { !$seend{$_}++ } @$denied;
    my ($ok, $err) = _txn_keep_admin($dbh, sub {
        # membership: full replacement of the group set
        $dbh->do("DELETE FROM user_groups WHERE user_id=?", undef, $uid); die "db\n" if $dbh->err;
        for my $g (@gids) { $dbh->do("INSERT INTO user_groups (user_id, group_id) VALUES (?,?)", undef, $uid, $g); die "db\n" if $dbh->err; }
        $dbh->do("DELETE FROM capability_grants WHERE subject_type='user' AND subject_id=?", undef, $uid); die "db\n" if $dbh->err;
        for my $c (@capsU) { $dbh->do("INSERT INTO capability_grants (subject_type,subject_id,capability,effect) VALUES ('user',?,?,'allow')", undef, $uid, $c); die "db\n" if $dbh->err; }
        for my $c (@denyU) { $dbh->do("INSERT INTO capability_grants (subject_type,subject_id,capability,effect) VALUES ('user',?,?,'deny')",  undef, $uid, $c); die "db\n" if $dbh->err; }
        $dbh->do("DELETE FROM zone_access WHERE subject_type='user' AND subject_id=?", undef, $uid); die "db\n" if $dbh->err;
        for my $r (@$rules) {
            $dbh->do("INSERT INTO zone_access (subject_type,subject_id,scope,zone_id,access) VALUES ('user',?,?,?,?)",
                undef, $uid, $r->{scope}, ($r->{scope} eq 'zone' ? $r->{zone_id} + 0 : undef), $r->{access}); die "db\n" if $dbh->err;
        }
    });
    return (undef, $err) if $err;
    return (1, undef);
}

# Atomically replace a GROUP's access (capabilities + zone_rules) in one request - the group UI draft/Save.
# -> (1,undef)|(undef,err). Under the last-admin guard (removing users.manage from a group can orphan admins).
sub group_access_set {
    my ($gid, $b) = @_; $b ||= {};
    return (undef, 'group id required') unless $gid && $gid =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    my ($ex) = $dbh->selectrow_array("SELECT 1 FROM groups WHERE id=?", undef, $gid);
    return (undef, 'unknown group') unless $ex;
    my $caps  = $b->{capabilities};
    my $rules = $b->{zone_rules};
    return (undef, 'capabilities required (array)') unless ref $caps  eq 'ARRAY';
    return (undef, 'zone_rules required (array)')   unless ref $rules eq 'ARRAY';
    for my $c (@$caps) { return (undef, "unknown capability: $c") unless $IS_CAP{$c}; }
    my (@zids, $seen_all, %seen_zone);
    for my $r (@$rules) {
        my $sc = $r->{scope}  // ''; return (undef, 'scope must be all|zone')  unless $sc =~ /^(all|zone)$/;
        my $ac = $r->{access} // ''; return (undef, 'access must be none|read|write') unless $ac =~ /^(none|read|write)$/;
        if ($sc eq 'all')   { return (undef, 'duplicate rule: all') if $seen_all++; }
        if ($sc eq 'zone')  { return (undef, 'zone_id required') unless defined $r->{zone_id} && "$r->{zone_id}" =~ /^\d+$/;
                              my $z = $r->{zone_id} + 0; return (undef, "duplicate rule: zone $z") if $seen_zone{$z}++; push @zids, $z; }
    }
    if (@zids) {   # fail-closed: PDNS/panel DB unavailable -> nothing saved
        my $pdns = connectPDNS() or return (undef, 'DB unavailable');
        my $ph = join(',', ('?') x @zids); my %have;
        my $got = $pdns->selectall_arrayref("SELECT id FROM domains WHERE id IN ($ph)", undef, @zids) || [];
        $have{ $_->[0] } = 1 for @$got;
        my $cat = _catalog_domain_ids($dbh) or return (undef, 'DB unavailable');   # catalog producer zones are not assignable (for groups either)
        for my $z (@zids) { return (undef, 'unknown zone') unless $have{$z};
                            return (undef, 'zone not eligible: catalog producer zone') if $cat->{$z}; }
    }
    my %seen; my @capsU = grep { !$seen{$_}++ } @$caps;
    my ($ok, $err) = _txn_keep_admin($dbh, sub {
        $dbh->do("DELETE FROM capability_grants WHERE subject_type='group' AND subject_id=?", undef, $gid); die "db\n" if $dbh->err;
        for my $c (@capsU) { $dbh->do("INSERT INTO capability_grants (subject_type,subject_id,capability) VALUES ('group',?,?)", undef, $gid, $c); die "db\n" if $dbh->err; }
        $dbh->do("DELETE FROM zone_access WHERE subject_type='group' AND subject_id=?", undef, $gid); die "db\n" if $dbh->err;
        for my $r (@$rules) {
            $dbh->do("INSERT INTO zone_access (subject_type,subject_id,scope,zone_id,access) VALUES ('group',?,?,?,?)",
                undef, $gid, $r->{scope}, ($r->{scope} eq 'zone' ? $r->{zone_id} + 0 : undef), $r->{access}); die "db\n" if $dbh->err;
        }
    });
    return (undef, $err) if $err;
    return (1, undef);
}
sub user_create {
    my ($f) = @_; $f ||= {};
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $un, my $e) = _check_len($f->{username}, 'username', 64, 1); return (undef, $e) if $e;
    return (undef, 'username invalid (letters, digits, . _ -)') unless $un =~ /^[A-Za-z0-9._-]+$/;
    (my $dn, $e) = _check_len($f->{display_name}, 'display_name', 128, 0); return (undef, $e) if $e;
    (my $em, $e) = _check_len($f->{email}, 'email', 255, 0); return (undef, $e) if $e;
    my $active = 1; if (defined $f->{is_active}) { (my $b, my $be) = strict_bool($f->{is_active}); return (undef, "is_active: $be") if $be; $active = $b; }
    (my $dup, $e) = _db_exists($dbh, "SELECT 1 FROM users WHERE username=?", $un); return (undef, $e) if $e;
    return (undef, "user '$un' already exists") if $dup;
    # username and e-mail must not name another user (they identify OIDC sign-ins, like certificate CNs).
    for my $n ($un, $em) { if (my $c = identity_name_conflict($n, 0)) { return (undef, $c); } }
    (my $ok, my $de) = _do($dbh, "INSERT INTO users (username, display_name, email, is_active) VALUES (?,?,?,?)",
        $un, ((defined $dn && $dn ne '') ? $dn : undef), ((defined $em && $em ne '') ? $em : undef), $active); return (undef, $de) if $de;
    return ($dbh->last_insert_id(undef,undef,undef,undef) + 0, undef);
}
sub user_update {
    my ($id, $f) = @_; $f ||= {};
    return (undef, 'id required') unless $id && $id =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $cur, my $e) = _db_row($dbh, "SELECT id FROM users WHERE id=?", $id); return (undef, $e) if $e;
    return (undef, 'not found') unless $cur;
    my (@set, @val);
    if (exists $f->{username}) { (my $un, $e) = _check_len($f->{username}, 'username', 64, 1); return (undef, $e) if $e;
        return (undef, 'username invalid') unless $un =~ /^[A-Za-z0-9._-]+$/;
        (my $dup, $e) = _db_exists($dbh, "SELECT 1 FROM users WHERE username=? AND id<>?", $un, $id); return (undef, $e) if $e;
        return (undef, "user '$un' already exists") if $dup;
        if (my $c = identity_name_conflict($un, $id)) { return (undef, $c); }
        push @set, 'username=?'; push @val, $un; }
    if (exists $f->{display_name}) { (my $dn, $e) = _check_len($f->{display_name}, 'display_name', 128, 0); return (undef, $e) if $e; push @set, 'display_name=?'; push @val, ((defined $dn && $dn ne '') ? $dn : undef); }
    if (exists $f->{email}) { (my $em, $e) = _check_len($f->{email}, 'email', 255, 0); return (undef, $e) if $e;
        if (my $c = identity_name_conflict($em, $id)) { return (undef, $c); }
        push @set, 'email=?'; push @val, ((defined $em && $em ne '') ? $em : undef); }
    my $deactivating = 0;
    if (exists $f->{is_active}) { (my $b, my $be) = strict_bool($f->{is_active}); return (undef, "is_active: $be") if $be; push @set, 'is_active=?'; push @val, $b; $deactivating = !$b; }
    return (1, undef) unless @set;
    my $upd = sub {
        $dbh->do("UPDATE users SET " . join(',', @set) . " WHERE id=?", undef, @val, $id); die "db\n" if $dbh->err;
        # Deactivation MUST revoke all sessions, otherwise old cookies revive when the user is re-enabled.
        if ($deactivating) { $dbh->do("UPDATE sessions SET is_active=0 WHERE user_id=? AND is_active=1", undef, $id); die "db\n" if $dbh->err; }
    };
    if ($deactivating) { return _txn_keep_admin($dbh, $upd); }   # deactivating the last admin -> rollback
    $upd->(); return $dbh->err ? (undef, _db_err_kind($dbh->err)) : (1, undef);
}
sub user_delete {
    my ($id) = @_;
    return (undef, 'id required') unless $id && $id =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $ex, my $e) = _db_exists($dbh, "SELECT 1 FROM users WHERE id=?", $id); return (undef, $e) if $e;
    return (undef, 'not found') unless $ex;
    # auth_identities/user_groups/sessions are FK CASCADE; capability_grants/zone_access(user) have no FK.
    return _txn_keep_admin($dbh, sub {
        $dbh->do("DELETE FROM capability_grants WHERE subject_type='user' AND subject_id=?", undef, $id); die "db\n" if $dbh->err;
        $dbh->do("DELETE FROM zone_access WHERE subject_type='user' AND subject_id=?", undef, $id); die "db\n" if $dbh->err;
        $dbh->do("DELETE FROM users WHERE id=?", undef, $id); die "db\n" if $dbh->err;
    });
}

# ---- Permission groups (table groups; NOT secondary_groups) ----
sub perm_groups_all {
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $rows, my $e) = _db_all($dbh,
        "SELECT g.id, g.name, g.description,
                (SELECT COUNT(*) FROM user_groups ug WHERE ug.group_id=g.id) AS member_count,
                (SELECT COUNT(*) FROM capability_grants c WHERE c.subject_type='group' AND c.subject_id=g.id) AS cap_count
           FROM groups g ORDER BY g.name", { Slice => {} });
    return (undef, $e) if $e;
    for (@$rows) { $_->{id} += 0; $_->{member_count} += 0; $_->{cap_count} += 0; }
    return ($rows, undef);
}
sub perm_group_get {
    my ($id) = @_;
    return (undef, 'not found') unless $id && $id =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $g, my $e) = _db_row($dbh, "SELECT id, name, description FROM groups WHERE id=?", $id); return (undef, $e) if $e;
    return (undef, 'not found') unless $g;
    $g->{id} += 0;
    (my $mem, $e) = _db_all($dbh, "SELECT u.id, u.username, u.display_name FROM user_groups ug JOIN users u ON u.id=ug.user_id WHERE ug.group_id=? ORDER BY u.username", { Slice => {} }, $id); return (undef, $e) if $e;
    $_->{id} += 0 for @$mem; $g->{members} = $mem;
    (my $c, $e) = _db_all($dbh, "SELECT capability FROM capability_grants WHERE subject_type='group' AND subject_id=? ORDER BY capability", { Slice => {} }, $id); return (undef, $e) if $e;
    $g->{capabilities} = [ map { $_->{capability} } @$c ];
    (my $za, $e) = _db_all($dbh, "SELECT id, scope, zone_id, access FROM zone_access WHERE subject_type='group' AND subject_id=? ORDER BY scope", { Slice => {} }, $id); return (undef, $e) if $e;
    for (@$za) { $_->{id} += 0; $_->{zone_id} = defined $_->{zone_id} ? $_->{zone_id}+0 : undef; }
    $g->{zone_access} = $za;
    return ($g, undef);
}
sub perm_group_create {
    my ($f) = @_; $f ||= {};
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $n, my $e) = _check_len($f->{name}, 'name', 64, 1); return (undef, $e) if $e;
    (my $d, $e) = _check_len($f->{description}, 'description', 255, 0); return (undef, $e) if $e;
    (my $dup, $e) = _db_exists($dbh, "SELECT 1 FROM groups WHERE name=?", $n); return (undef, $e) if $e;
    return (undef, "group '$n' already exists") if $dup;
    (my $ok, my $de) = _do($dbh, "INSERT INTO groups (name, description) VALUES (?,?)", $n, ((defined $d && $d ne '') ? $d : undef)); return (undef, $de) if $de;
    return ($dbh->last_insert_id(undef,undef,undef,undef) + 0, undef);
}
sub perm_group_update {
    my ($id, $f) = @_; $f ||= {};
    return (undef, 'id required') unless $id && $id =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $ex, my $e) = _db_exists($dbh, "SELECT 1 FROM groups WHERE id=?", $id); return (undef, $e) if $e;
    return (undef, 'not found') unless $ex;
    my (@set, @val);
    if (exists $f->{name}) { (my $n, $e) = _check_len($f->{name}, 'name', 64, 1); return (undef, $e) if $e;
        (my $dup, $e) = _db_exists($dbh, "SELECT 1 FROM groups WHERE name=? AND id<>?", $n, $id); return (undef, $e) if $e;
        return (undef, "group '$n' already exists") if $dup; push @set, 'name=?'; push @val, $n; }
    if (exists $f->{description}) { (my $d, $e) = _check_len($f->{description}, 'description', 255, 0); return (undef, $e) if $e; push @set, 'description=?'; push @val, ((defined $d && $d ne '') ? $d : undef); }
    return (1, undef) unless @set;
    (my $ok, my $de) = _do($dbh, "UPDATE groups SET " . join(',', @set) . " WHERE id=?", @val, $id); return (undef, $de) if $de;
    return (1, undef);
}
sub perm_group_delete {
    my ($id) = @_;
    return (undef, 'id required') unless $id && $id =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $ex, my $e) = _db_exists($dbh, "SELECT 1 FROM groups WHERE id=?", $id); return (undef, $e) if $e;
    return (undef, 'not found') unless $ex;
    # user_groups is FK CASCADE; capability_grants/zone_access(group) are cleaned explicitly. Guard: no orphaned admin.
    return _txn_keep_admin($dbh, sub {
        $dbh->do("DELETE FROM capability_grants WHERE subject_type='group' AND subject_id=?", undef, $id); die "db\n" if $dbh->err;
        $dbh->do("DELETE FROM zone_access WHERE subject_type='group' AND subject_id=?", undef, $id); die "db\n" if $dbh->err;
        $dbh->do("DELETE FROM groups WHERE id=?", undef, $id); die "db\n" if $dbh->err;
    });
}

# ---- Membership / capability grants / zone access (subject = user|group) ----
sub _valid_subject { my ($st, $sid) = @_; return 0 unless ($st eq 'user' || $st eq 'group') && $sid && "$sid" =~ /^\d+$/;
    my $dbh = connectDB() or return 0; my $t = $st eq 'user' ? 'users' : 'groups';
    my ($ex) = $dbh->selectrow_array("SELECT 1 FROM $t WHERE id=?", undef, $sid); return $ex ? 1 : 0; }
sub user_group_add {
    my ($uid, $gid) = @_;
    return (undef, 'ids required') unless $uid && $uid =~ /^\d+$/ && $gid && $gid =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $ux, my $ue) = _db_exists($dbh, "SELECT 1 FROM users WHERE id=?", $uid);  return (undef, $ue) if $ue; return (undef, 'unknown user')  unless $ux;
    (my $gx, my $ge) = _db_exists($dbh, "SELECT 1 FROM groups WHERE id=?", $gid); return (undef, $ge) if $ge; return (undef, 'unknown group') unless $gx;
    (my $ok, my $de) = _do($dbh, "INSERT IGNORE INTO user_groups (user_id, group_id) VALUES (?,?)", $uid, $gid); return (undef, $de) if $de;
    return (1, undef);
}
sub user_group_remove {
    my ($uid, $gid) = @_;
    return (undef, 'ids required') unless $uid && $uid =~ /^\d+$/ && $gid && $gid =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    return _txn_keep_admin($dbh, sub { $dbh->do("DELETE FROM user_groups WHERE user_id=? AND group_id=?", undef, $uid, $gid); die "db\n" if $dbh->err; });
}
# $effect: 'allow' (default) or 'deny'. A deny is ONLY personal: for a group "no right" and "denied" are
# the same thing. A personal deny of users.manage can orphan the panel - same guard as a revoke.
sub capability_grant {
    my ($st, $sid, $cap, $effect) = @_;
    $effect = (defined $effect && $effect eq 'deny') ? 'deny' : 'allow';
    return (undef, 'invalid subject') unless _valid_subject($st, $sid);
    return (undef, 'unknown capability') unless $cap && $IS_CAP{$cap};
    return (undef, 'a group cannot be denied a capability — remove the grant instead')
        if $effect eq 'deny' && $st ne 'user';
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    my $write = sub {
        $dbh->do("INSERT INTO capability_grants (subject_type, subject_id, capability, effect) VALUES (?,?,?,?)
                  ON DUPLICATE KEY UPDATE effect=VALUES(effect)", undef, $st, $sid, $cap, $effect);
        die "db\n" if $dbh->err;
    };
    if ($cap eq 'users.manage' && $effect eq 'deny') { return _txn_keep_admin($dbh, $write); }
    my $done = eval { $write->(); 1 };
    return (undef, _db_err_kind($dbh->err) || 'DB error') unless $done;
    return (1, undef);
}
sub capability_revoke {
    my ($st, $sid, $cap) = @_;
    return (undef, 'invalid subject') unless ($st eq 'user' || $st eq 'group') && $sid && "$sid" =~ /^\d+$/;
    return (undef, 'unknown capability') unless $cap && $IS_CAP{$cap};
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    # revoking users.manage can orphan an admin -> guard; otherwise a plain delete.
    if ($cap eq 'users.manage') {
        return _txn_keep_admin($dbh, sub { $dbh->do("DELETE FROM capability_grants WHERE subject_type=? AND subject_id=? AND capability=?", undef, $st, $sid, $cap); die "db\n" if $dbh->err; });
    }
    (my $ok, my $de) = _do($dbh, "DELETE FROM capability_grants WHERE subject_type=? AND subject_id=? AND capability=?", $st, $sid, $cap); return (undef, $de) if $de;
    return (1, undef);
}
# zone_access: $r = {scope(all|zone), zone_id?, access(none|read|write)}. Replaces the rule with the same
# (scope+key). (id,undef)|(undef,err).
sub zone_access_set {
    my ($st, $sid, $r) = @_; $r ||= {};
    return (undef, 'invalid subject') unless _valid_subject($st, $sid);
    my $scope = $r->{scope} // ''; return (undef, 'scope must be all|zone') unless $scope =~ /^(all|zone)$/;
    my $access = $r->{access} // ''; return (undef, 'access must be none|read|write') unless $access =~ /^(none|read|write)$/;
    my $zid;
    if ($scope eq 'zone')  {
        $zid = $r->{zone_id}; return (undef, 'zone_id required') unless defined $zid && "$zid" =~ /^\d+$/; $zid += 0;
        # The zone must exist in PowerDNS (otherwise a meaningless zone#N rule). FAIL-CLOSED: with the PDNS DB
        # down the zone is NOT assumed to exist.
        my $pdns = connectPDNS() or return (undef, 'DB unavailable');
        my ($ex) = $pdns->selectrow_array("SELECT 1 FROM domains WHERE id=?", undef, $zid);
        return (undef, 'unknown zone') unless $ex;
        my $cat = _catalog_domain_ids() or return (undef, 'DB unavailable');   # fail-closed: the producer zone list could not be read
        return (undef, 'zone not eligible: catalog producer zone') if $cat->{$zid};
    }
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $bo, my $be) = _txn_begin($dbh); return (undef, $be) if $be;
    my $newid;
    my $done = eval {
        # drop the previous rule of the same specificity (otherwise a duplicate)
        if    ($scope eq 'all')   { $dbh->do("DELETE FROM zone_access WHERE subject_type=? AND subject_id=? AND scope='all'", undef, $st, $sid); }
        else                      { $dbh->do("DELETE FROM zone_access WHERE subject_type=? AND subject_id=? AND scope='zone' AND zone_id=?", undef, $st, $sid, $zid); }
        die "db\n" if $dbh->err;
        $dbh->do("INSERT INTO zone_access (subject_type, subject_id, scope, zone_id, access) VALUES (?,?,?,?,?)", undef, $st, $sid, $scope, $zid, $access); die "db\n" if $dbh->err;
        $newid = $dbh->last_insert_id(undef, undef, undef, undef);
        1;
    };
    if (!$done) { my $e = $@ || 'failed'; $e =~ s/\n//g; eval { $dbh->rollback }; return (undef, ($e eq 'db' ? _db_err_kind($dbh->err) : $e)); }
    my $ok = $dbh->commit;
    if (!$ok || $dbh->err) { eval { $dbh->rollback }; return (undef, _db_err_kind($dbh->err) || 'commit failed'); }
    return (($newid // 0) + 0, undef);
}
sub zone_access_delete {
    my ($id) = @_;
    return (undef, 'id required') unless $id && $id =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $ex, my $e) = _db_exists($dbh, "SELECT 1 FROM zone_access WHERE id=?", $id); return (undef, $e) if $e;
    return (undef, 'not found') unless $ex;
    (my $ok, my $de) = _do($dbh, "DELETE FROM zone_access WHERE id=?", $id); return (undef, $de) if $de;
    return (1, undef);
}

# ---- External identity (cert/oauth) ----
# cert -> provider='' (forced); oauth -> provider required. principal required. Duplicate
# (type,provider,principal) -> error. (id,undef)|(undef,err).
sub auth_identity_add {
    my ($user_id, $type, $provider, $principal, $data) = @_;
    return (undef, 'user id required') unless $user_id && $user_id =~ /^\d+$/;
    return (undef, 'type must be cert|oauth') unless defined $type && ($type eq 'cert' || $type eq 'oauth');
    (my $pr, my $pe) = _check_len($principal, 'principal', 255, 1); return (undef, $pe) if $pe;
    my $prov;
    if ($type eq 'cert') { $prov = ''; }                                        # cert: provider is always empty
    else { $prov = _trim($provider) // ''; return (undef, 'oauth requires provider') unless length $prov; return (undef, 'provider too long') if length $prov > 32; }
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $ux, my $ue) = _db_exists($dbh, "SELECT 1 FROM users WHERE id=?", $user_id); return (undef, $ue) if $ue; return (undef, 'unknown user') unless $ux;
    # One CN belongs to one user (UNIQUE key), and it must not be another user's username or e-mail either:
    # OIDC sign-in matches all three (identity_name_conflict).
    if (my $c = identity_name_conflict($pr, $user_id)) { return (undef, $c); }
    my $djson = (defined $data && ref $data) ? encode_json($data) : undef;
    (my $ok, my $de) = _do($dbh, "INSERT INTO auth_identities (user_id, type, provider, principal, data) VALUES (?,?,?,?,?)", $user_id, $type, $prov, $pr, $djson); return (undef, $de) if $de;
    return ($dbh->last_insert_id(undef, undef, undef, undef) + 0, undef);
}
sub auth_identity_delete {
    my ($id) = @_;
    return (undef, 'id required') unless $id && $id =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $ex, my $e) = _db_exists($dbh, "SELECT 1 FROM auth_identities WHERE id=?", $id); return (undef, $e) if $e;
    return (undef, 'not found') unless $ex;
    (my $ok, my $de) = _do($dbh, "DELETE FROM auth_identities WHERE id=?", $id); return (undef, $de) if $de;
    return (1, undef);
}

# ---- Passwords (Argon2id) ----
# Lazy require: functions.pm loads without Crypt::Argon2 (paths without passwords); the error only comes on call.
sub password_hash {
    my ($plain) = @_;
    require Crypt::Argon2; require Crypt::URandom;
    my $salt = Crypt::URandom::urandom(16);
    return Crypt::Argon2::argon2id_pass($plain, $salt, 3, '19M', 1, 32);   # OWASP profile: t=3, m=19MiB, p=1
}
sub password_verify {
    my ($encoded, $plain) = @_;
    return 0 unless defined $encoded && length $encoded && defined $plain;
    require Crypt::Argon2;
    my $ok = eval { Crypt::Argon2::argon2id_verify($encoded, $plain) };
    return $ok ? 1 : 0;
}
# Set/change a password (upsert password_credentials); must_change=1 forces a change at login.
# ATOMICALLY revokes ALL active sessions of the user (resetting a compromised account leaves no attacker
# in the panel; a password change invalidates old full/pending sessions). (1,undef)|(undef,err).
sub set_user_password {
    my ($user_id, $plain, $must_change) = @_;
    return (undef, 'user id required') unless $user_id && $user_id =~ /^\d+$/;
    return (undef, 'password too short (min 8)') unless defined $plain && length $plain >= 8;
    my $hash = eval { password_hash($plain) }; return (undef, 'hashing failed: ' . ($@ || '?')) unless $hash;   # expensive - outside the txn
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $bo, my $be) = _txn_begin($dbh); return (undef, $be) if $be;
    my $fail = sub { my ($e) = @_; eval { $dbh->rollback }; return (undef, $e); };
    my $done = eval {
        $dbh->do("INSERT INTO password_credentials (user_id, password_hash, must_change) VALUES (?,?,?)
                  ON DUPLICATE KEY UPDATE password_hash=VALUES(password_hash), must_change=VALUES(must_change)",
                 undef, $user_id, $hash, ($must_change ? 1 : 0)); die "db\n" if $dbh->err;
        $dbh->do("UPDATE sessions SET is_active=0 WHERE user_id=? AND is_active=1", undef, $user_id); die "db\n" if $dbh->err;
        1;
    };
    if (!$done) { return $fail->(_db_err_kind($dbh->err) || 'DB error'); }
    my $ok = $dbh->commit;
    if (!$ok || $dbh->err) { return $fail->(_db_err_kind($dbh->err) || 'commit failed'); }
    return (1, undef);
}
sub _gen_temp_password {
    require Crypt::URandom; require MIME::Base64;
    (my $b = MIME::Base64::encode_base64url(Crypt::URandom::urandom(18))) =~ s/[^A-Za-z0-9]//g;
    return substr($b, 0, 20);
}

# ---- Bootstrap of the first administrator (deploy/bootstrap-admin.pl) ----
# Atomic: user (+ cert identity if a CN is given) + temp password (must_change) + group 'DNS Administrators'
# + membership + ALL capabilities + zone_access all/write. Refused if an active users.manage admin exists.
# cert_cn is optional. ({user_id,group_id,username,cert_cn,temp_password}, undef) | (undef, err).
sub bootstrap_admin {
    my ($opts) = @_; $opts ||= {};
    my $un = _trim($opts->{username}) // '';
    return (undef, 'username required') unless length $un;
    return (undef, 'username invalid (letters, digits, . _ -)') unless $un =~ /^[A-Za-z0-9._-]{1,64}$/;
    my $dn = _trim($opts->{display_name}); my $em = _trim($opts->{email});
    my $cert_cn = (defined $opts->{cert_cn} && length(_trim($opts->{cert_cn}) // '')) ? _trim($opts->{cert_cn}) : undef;
    my $given_pw  = (defined $opts->{password} && length $opts->{password}) ? $opts->{password} : undef;
    return (undef, 'password too short (min 8)') if defined $given_pw && length $given_pw < 8;
    my $pw = $given_pw // _gen_temp_password();
    my $hash = eval { password_hash($pw) }; return (undef, 'password hashing failed (Crypt::Argon2 installed?): ' . ($@ || '?')) unless $hash;

    my $dbh = connectDB() or return (undef, 'DB unavailable');
    my ($got) = $dbh->selectrow_array("SELECT GET_LOCK('dns-panel:last-admin', 5)");
    return (undef, 'busy: admin change in progress') unless $got;
    my $rel = sub { eval { $dbh->do("SELECT RELEASE_LOCK('dns-panel:last-admin')") }; };
    my ($admins) = $dbh->selectrow_array(_admin_count_sql());
    if ($dbh->err) { $rel->(); return (undef, _db_err_kind($dbh->err)); }
    if (($admins // 0) >= 1) { $rel->(); return (undef, 'bootstrap refused: an active administrator (users.manage) already exists'); }

    (my $bo, my $be) = _txn_begin($dbh); if ($be) { $rel->(); return (undef, $be); }
    my ($uid, $gid);
    my $done = eval {
        my ($dup) = $dbh->selectrow_array("SELECT 1 FROM users WHERE username=?", undef, $un); die "user '$un' already exists\n" if $dup;
        $dbh->do("INSERT INTO users (username, display_name, email, is_active) VALUES (?,?,?,1)", undef, $un, (length($dn // '') ? $dn : undef), (length($em // '') ? $em : undef)); die "db\n" if $dbh->err;
        $uid = $dbh->last_insert_id(undef, undef, undef, undef);
        if ($cert_cn) { $dbh->do("INSERT INTO auth_identities (user_id, type, provider, principal) VALUES (?, 'cert','', ?)", undef, $uid, $cert_cn); die "db\n" if $dbh->err; }
        $dbh->do("INSERT INTO password_credentials (user_id, password_hash, must_change) VALUES (?,?,1)", undef, $uid, $hash); die "db\n" if $dbh->err;
        # The group is NOT reused: if 'DNS Administrators' exists -> refuse (otherwise its members would suddenly
        # become admins). Created anew, with only the new user as a member.
        my ($gexists) = $dbh->selectrow_array("SELECT 1 FROM groups WHERE name='DNS Administrators'");
        die "reserved group 'DNS Administrators' already exists — remove it or grant admin manually\n" if $gexists;
        $dbh->do("INSERT INTO groups (name, description) VALUES ('DNS Administrators','Full administrative access (bootstrap)')"); die "db\n" if $dbh->err;
        $gid = $dbh->last_insert_id(undef, undef, undef, undef);
        $dbh->do("INSERT INTO user_groups (user_id, group_id) VALUES (?,?)", undef, $uid, $gid); die "db\n" if $dbh->err;
        for my $cap (@CAPABILITIES) { $dbh->do("INSERT INTO capability_grants (subject_type, subject_id, capability) VALUES ('group',?,?)", undef, $gid, $cap); die "db\n" if $dbh->err; }
        $dbh->do("INSERT INTO zone_access (subject_type, subject_id, scope, access) VALUES ('group',?, 'all','write')", undef, $gid); die "db\n" if $dbh->err;
        1;
    };
    if (!$done) { my $e = $@ || 'failed'; $e =~ s/\n//g; eval { $dbh->rollback }; $rel->(); return (undef, ($e eq 'db' ? _db_err_kind($dbh->err) : $e)); }
    my $ok = $dbh->commit;
    if (!$ok || $dbh->err) { my $err = _db_err_kind($dbh->err) || 'commit failed'; eval { $dbh->rollback }; $rel->(); return (undef, $err); }
    $rel->();
    return ({ user_id => $uid + 0, group_id => $gid + 0, username => $un, cert_cn => $cert_cn, temp_password => ($given_pw ? undef : $pw) }, undef);
}

# ============================================================================
# AUDIT LOG (who/when/before/after) - docs/15-audit-log.md
# ============================================================================
# detail is a STRING column (VARCHAR 255) and TEXT FOR HUMANS: the log only displays it (js/audit.js).
# Callers often pass a hashref, which silently became "HASH(0x55f3...)"; it is expanded here, at the
# single write point. "key: value", not JSON: JSON cut to the column length would stop being parseable
# and read worse. Structured data belongs in before/after, which are JSON anyway.
sub _audit_detail {
    my ($d) = @_;
    return undef unless defined $d;
    my $s;
    if (ref $d eq 'HASH') {
        $s = join ', ', map { "$_: " . _audit_detail_val($d->{$_}) } sort keys %$d;
    } elsif (ref $d eq 'ARRAY') {
        $s = _audit_detail_val($d);
    } else {
        $s = "$d";
    }
    return $s if length($s) <= 255;
    return substr($s, 0, 252) . '...';
}
sub _audit_detail_val {
    my ($v) = @_;
    return '—' unless defined $v;
    return join(', ', map { _audit_detail_val($_) } @$v) if ref $v eq 'ARRAY';
    return join(', ', map { "$_=" . _audit_detail_val($v->{$_}) } sort keys %$v) if ref $v eq 'HASH';
    return "$v";
}
sub audit_log {
    my ($e) = @_;
    my $dbh = connectDB() or return 0;   # no DB -> no-op
    my $sth = $dbh->prepare(
        "INSERT INTO audit_log
            (actor, actor_role, source, via, action, target_type, target, target_label, before_val, after_val, result, detail, ip, request_id)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)") or return 0;
    return $sth->execute(
        $e->{actor}, $e->{actor_role}, ($e->{source} || 'panel'), ($e->{via} // $functions::_request_via), $e->{action},
        $e->{target_type}, $e->{target}, $e->{target_label},
        (defined $e->{before} ? encode_json($e->{before}) : undef),
        (defined $e->{after}  ? encode_json($e->{after})  : undef),
        ($e->{result} || 'ok'), _audit_detail($e->{detail}), $e->{ip}, $e->{request_id});
}

# Single dictionary: technical action -> human-readable English label (Audit UI + Dashboard).
# Unknown actions are humanized (prefix/suffix stripped, underscores -> spaces, capitalized).
our %AUDIT_ACTION_LABELS = (
    login => 'Signed in', logout => 'Signed out',
    api_token_create => 'Created API token', api_token_update => 'Updated API token', api_token_delete => 'Deleted API token',
    external_settings_update => 'Updated external access',
    oidc_provider_create => 'Added OIDC provider', oidc_provider_update => 'Updated OIDC provider', oidc_provider_delete => 'Deleted OIDC provider',
    user_create => 'Created user', user_update => 'Updated user', user_delete => 'Deleted user',
    user_access_set => 'Updated access', user_password_reset => 'Reset password',
    totp_reset => 'Reset two-factor', totp_off => 'Turned off two-factor',
    totp_required => 'Required two-factor', totp_not_required => 'Stopped requiring two-factor',
    account_totp_off => 'Turned off own two-factor',
    user_access_recovered => 'Recovered access from the node',
    user_group_add => 'Added to group', user_group_remove => 'Removed from group',
    capability_grant => 'Granted permission', capability_revoke => 'Revoked permission',
    auth_identity_add => 'Added certificate', auth_identity_delete => 'Removed certificate',
    session_revoke => 'Revoked session', session_revoke_all => 'Revoked all sessions', session_policy_set => 'Updated session policy',
    perm_group_create => 'Created group', perm_group_update => 'Updated group', perm_group_delete => 'Deleted group',
    group_access_set => 'Updated group access',
    zone_access_set => 'Set zone access', zone_access_delete => 'Removed zone access',
    create_zone => 'Created zone', delete_zone => 'Deleted zone', create_reverse_zones => 'Created reverse zones',
    add_record => 'Added DNS record', update => 'Updated DNS record', delete_record => 'Deleted DNS record',
    update_soa => 'Updated SOA', update_zone_settings => 'Updated zone settings', update_zone_labels => 'Updated zone labels',
    zone_overrides_set => 'Updated zone overrides', inventory_access_denied => 'Access denied',
    label_category_create => 'Created label category', label_category_delete => 'Deleted label category',
    label_value_create => 'Created label', label_value_delete => 'Deleted label',
    zone_profile_create => 'Created zone profile', zone_profile_update => 'Updated zone profile', zone_profile_delete => 'Deleted zone profile',
    tsig_key_create => 'Created TSIG key', tsig_key_update => 'Changed TSIG key secret', tsig_key_delete => 'Deleted unused TSIG key', tsig_key_reveal => 'Revealed TSIG key',
    catalog_create => 'Created catalog', catalog_update => 'Updated catalog', catalog_delete => 'Deleted catalog',
    catalog_provision => 'Created the catalog zone in PowerDNS',
    catalog_groups_set => 'Changed catalog subscribers', catalog_node_remove => 'Removed server from catalog',
    distribution_delete => 'Deleted distribution',
    catalog_apply => 'Applied catalog', catalog_members_apply => 'Applied catalog members', catalog_set => 'Configured catalog',
    catalog_source_set => 'Set catalog source (removed)',   # RETIRED-OK: the action is gone, but old audit rows must stay readable
    pdns_endpoints_set => 'Set PowerDNS addresses (removed)',   # RETIRED-OK: the action is gone, but old audit rows must stay readable
    catalog_unconfigure => 'Unconfigured catalog',
    retry_sync => 'Retried sync', refresh_axfr => 'Requested AXFR', node_catalogs_set => 'Set server catalogs',
    zone_promote_to_primary => q{Promoted to primary}, zone_demote_to_secondary => q{Turned into a secondary}, zone_import_take => q{Replaced by the import version},
    zone_source_set => q{Updated secondary source},
    zone_dynamic_set => q{Changed dynamic updates},
    dyn_profile_create => q{Created dynamic DHCP profile}, dyn_profile_update => q{Changed dynamic DHCP profile},
    dyn_profile_delete => q{Deleted dynamic DHCP profile},
    # HA: the panel audit records human DECISIONS, not mechanics. Opening pairing, approving a peer,
    # creating a pair - someone is accountable for these; secrets, GTID and reseed live in the HA operation
    # history and would drown the decisions here.
    ha_pair_open => 'Opened pairing', ha_pair_join => 'Requested pairing',
    ha_pair_approve => 'Approved pairing', ha_pair_reject => 'Rejected pairing',
    ha_pair_reset => 'Reset pairing', ha_pair_build => 'Created HA pair',
    ha_switchover_create => 'Planned switchover', ha_emergency_promote => 'Emergency promote',
    ha_reseed => 'Reseed node', ha_operation_resume => 'Resumed HA operation',
    ha_config_apply => 'Updated HA configuration',
    # NS Pulse. A rule writes DNS, so enabling/disabling it is a decision, not a view setting.
    pulse_tester_approve => 'Approved Pulse agent', pulse_tester_update => 'Updated Pulse tester',
    pulse_tester_delete => 'Removed Pulse tester', pulse_enroll_key_new => 'Replaced Pulse enrollment key',
    pulse_server_address_set => 'Set Pulse server address',
    pulse_group_create => 'Created Pulse tester group', pulse_group_update => 'Updated Pulse tester group',
    pulse_group_delete => 'Deleted Pulse tester group', pulse_group_members_set => 'Changed Pulse group members',
    pulse_check_create => 'Created Pulse check', pulse_check_update => 'Updated Pulse check',
    pulse_check_delete => 'Deleted Pulse check', pulse_check_groups_set => 'Changed who runs a Pulse check',
    pulse_rule_create => 'Created Pulse rule', pulse_rule_update => 'Updated Pulse rule',
    pulse_rule_delete => 'Deleted Pulse rule', pulse_rule_branches_set => 'Changed Pulse rule logic',
    pulse_rule_clone => 'Cloned Pulse setup to other records', pulse_switch => 'NS Pulse switched a record',
    pulse_held => 'NS Pulse stopped: the record was changed outside it',
    pulse_rule_enabled => 'Enabled Pulse rule', pulse_rule_disabled => 'Disabled Pulse rule',
);
sub audit_action_label {
    my ($action) = @_;
    return '' unless defined $action && length $action;
    return $AUDIT_ACTION_LABELS{$action} if $AUDIT_ACTION_LABELS{$action};
    (my $h = $action) =~ s/_/ /g; $h = ucfirst $h;   # fallback: humanize (e.g. secondary_group_create → «Secondary group create»)
    return $h;
}

# SINGLE resolver of a human-readable object name by (target_type, numeric id). Audit writes a snapshot at
# event time (survives deletion); the read-time fallback fills old rows for objects that still exist.
# Types whose target is already readable (record/zone = FQDN/name) are not here -> undef.
our %AUDIT_LABEL_SQL = (
    user              => "SELECT COALESCE(NULLIF(display_name,''), username) FROM users WHERE id=?",
    group             => "SELECT name FROM groups WHERE id=?",
    permission_group  => "SELECT name FROM groups WHERE id=?",
    catalog           => "SELECT name FROM catalogs WHERE id=?",
    secondary_group   => "SELECT name FROM secondary_groups WHERE id=?",
    secondary_node    => "SELECT name FROM secondary_nodes WHERE id=?",
    zone_profile      => "SELECT name FROM zone_profiles WHERE id=?",
    tsig_key          => "SELECT name FROM tsig_keys WHERE id=?",
    ip_group          => "SELECT name FROM ip_groups WHERE id=?",
    auth_identity     => "SELECT principal FROM auth_identities WHERE id=?",
    label_category    => "SELECT name FROM label_categories WHERE id=?",
    label_value       => "SELECT name FROM label_values WHERE id=?",
    pulse_tester      => "SELECT name FROM pulse_testers WHERE id=?",
    pulse_group       => "SELECT name FROM pulse_groups WHERE id=?",
    pulse_check       => "SELECT name FROM pulse_checks WHERE id=?",
    # A rule has no name: its "name" is the record it manages.
    pulse_rule        => "SELECT CONCAT(rr_name, ' ', rr_type) FROM pulse_rules WHERE id=?",
);
sub audit_target_label {
    my ($type, $id) = @_;
    return undef unless defined $id && "$id" =~ /^\d+$/;
    # a zone target holds domain_id -> name from the PowerDNS DB (separate connection). A non-numeric target (FQDN) is already readable.
    if (($type // '') eq 'zone') {
        my $pdns = connectPDNS() or return undef;
        my ($n) = $pdns->selectrow_array("SELECT name FROM domains WHERE id=?", undef, $id);
        return $n;
    }
    my $sql = $AUDIT_LABEL_SQL{ $type // '' } or return undef;
    my $dbh = connectDB() or return undef;
    my ($name) = $dbh->selectrow_array($sql, undef, $id);
    return $name;
}
# target_type -> human-readable English label (the "All types" filter). Unknown -> humanized.
our %AUDIT_TYPE_LABELS = (
    user => 'User', group => 'Permission group', permission_group => 'Permission group',
    zone => 'Zone', rrset => 'DNS record', zone_access => 'Zone access rule', capability => 'Permission',
    catalog => 'Catalog', secondary_group => 'Secondary server group', secondary_node => 'Secondary server',
    zone_profile => 'Zone profile', tsig_key => 'TSIG key', ip_group => 'IP group',
    # primary_set stays only for HISTORY: the object is gone from the model, but old audit rows reference
    # it and must stay readable (they carry a target_label snapshot).
    primary_set => 'Address set (removed)', pdns_endpoints => 'PowerDNS addresses',
    auth_identity => 'Authentication identity',
    label_category => 'Label category', label_value => 'Label',
    pulse_tester => 'Pulse tester', pulse_group => 'Pulse tester group',
    pulse_check => 'Pulse check', pulse_rule => 'Pulse rule', pulse_server => 'NS Pulse server',
);
sub audit_type_label {
    my ($type) = @_;
    return '' unless defined $type && length $type;
    return $AUDIT_TYPE_LABELS{$type} if $AUDIT_TYPE_LABELS{$type};
    (my $h = $type) =~ s/_/ /g; return ucfirst $h;
}

# ============================================================================
# HEALTH / CSRF (prod-hardening Phase 1a)
# ============================================================================

# CSRF double-submit: safe methods (GET/HEAD/OPTIONS) pass; mutating ones only if the cookie token is
# NON-EMPTY and EQUAL to the header token. Body/query values are never used. 1 = allowed, 0 = reject (403).
sub csrf_ok {
    my ($method, $cookie_tok, $header_tok) = @_;
    $method = uc($method // '');
    return 1 if $method eq 'GET' || $method eq 'HEAD' || $method eq 'OPTIONS';
    return 0 unless defined $cookie_tok && length $cookie_tok;
    return 0 unless defined $header_tok && length $header_tok;
    return ($cookie_tok eq $header_tok) ? 1 : 0;
}
# New CSRF token (64 hex = 32 bytes of urandom), stored in a non-HttpOnly cookie (double-submit).
sub csrf_token_new {
    require Crypt::URandom;
    return unpack('H*', Crypt::URandom::urandom(32));
}

# Is the dns-agent control socket reachable (PowerDNS control plane: rediscover/notify)? A plain connect
# test, no command. 1|0.
sub agent_reachable {
    my $sock = _cfg('agent', 'socket', '');
    return 0 unless $sock && -S $sock;
    my $ok = eval {
        require IO::Socket::UNIX;
        my $c = IO::Socket::UNIX->new(Peer => $sock, Timeout => 2);   # default Type = SOCK_STREAM
        if ($c) { close $c; return 1; }
        return 0;
    };
    return $ok ? 1 : 0;
}

our @HEALTH_CORE_TABLES = qw(users sessions capability_grants zone_access groups user_groups audit_log catalogs);

# ---- HA: thin client for the dns-ha-manager control socket -----------------------------------------------
# The panel has NO HA logic: it reads state and creates INTENTS; the manager decides and executes.
# Otherwise there would be a second place deciding node roles - exactly what we moved away from.
# Short deadline: /health/ready and the write gate call this on every request and must not hang on a
# dead daemon. An unavailable manager is NOT "all good": callers must treat it fail-closed.
sub ha_manager_socket { return '/run/dns-panel/ha/manager.sock'; }

# How long to wait for the manager. Observation answers instantly; pair creation takes as long as the DB
# reseed. A flat 5 s timeout would show "failed" exactly while things succeed: the manager keeps
# rebuilding the node and the human sees an error. The client must not give up before the executor.
our %HA_TIMEOUTS = (
    pair_build     => 900,   # secrets, grants, DB reseed, revision
    pair_join      => 60,    # talks to the peer over the network
    pair_approve   => 120,   # approval -> key installed on both sides
    pair_reset     => 60,
    pair_inventory => 60,    # polls both sides
    pair_devices   => 30,    # asks both sides, changes nothing
);
sub ha_manager_timeout { my ($cmd) = @_; return $HA_TIMEOUTS{$cmd || ''} || 5; }

sub ha_manager_request {
    my ($cmd, %args) = @_;
    return (undef, 'ha_manager_unavailable') unless ha_mode() eq 'pair';
    my $req = encode_json({ cmd => $cmd, %args });
    my ($resp, $err);
    eval {
        local $SIG{ALRM} = sub { die "__ha_to__\n" };
        alarm ha_manager_timeout($cmd);
        require IO::Socket::UNIX;
        my $sock = IO::Socket::UNIX->new(Peer => ha_manager_socket(), Type => Socket::SOCK_STREAM())
            or die "connect: $!\n";
        print $sock $req, "\n" or die "write: $!\n";
        my $line = <$sock>;
        close $sock;
        die "empty\n" unless defined $line && length $line;
        $resp = decode_json($line);
        alarm 0;
        1;
    } or do {
        alarm 0;   # a pending alarm outlives the local handler and would kill a persistent process later
        # The EXACT reason is kept. Missing socket, connection refused, timeout, EOF without a reply and broken
        # JSON used to collapse into "ha_manager_unavailable", leaving nothing to debug. The outward code stays
        # the same (the browser needs no socket details); the reason goes to error_log and as a second value
        # for the panel audit.
        my $why = $@ || 'unknown';
        chomp $why;
        my $timed_out = $why =~ /__ha_to__/;
        $err = $timed_out ? 'ha_manager_timeout' : 'ha_manager_unavailable';
        my $detail = $timed_out
            ? sprintf('timeout after %ss', ha_manager_timeout($cmd))
            : $why;
        warn sprintf("ha_manager_request(%s) failed: %s (socket %s)\n", $cmd, $detail, ha_manager_socket());
        return (undef, $err, $detail);
    };
    return (undef, $err) if $err;
    # The third value is the manager's EXPLANATION: without it the human saw a bare "failed" and the one
    # useful line (what did not match) was lost between the socket and the browser.
    if (ref $resp eq 'HASH' && exists $resp->{ok} && !$resp->{ok}) {
        return (undef, ($resp->{error} || 'ha_manager_error'), $resp->{message});
    }
    return ($resp, undef, undef);
}

# Node state as the manager sees it: role, readiness, pair health, scheduler decision.
sub ha_manager_status { my ($r, $e) = ha_manager_request('status'); return ($r, $e); }

# ---- HA: the only local fact is "HA is installed" ----
# panel.toml answers one question: is HA installed on this node. Who we are, who the peer is and which
# address serves the pair is known to dns-ha-manager only; node_id/nodes in the panel config used to be a
# second source that survived role switches and confidently answered wrong.
# The flag is local on purpose: it is needed BEFORE and WITHOUT the manager. Asking the daemon would make
# an unavailable daemon mean "maybe HA" and block writes on a node that has no HA at all.
# It means "HA INSTALLED", not "pair created": pairing two standalone nodes happens precisely while there
# is no pair yet. Whether a pair exists is the manager's answer (ha_configured()); trust is ha_trusted().
sub ha_enabled {
    my $c = load_panel_config();
    return (ref $c->{ha} eq 'HASH' && $c->{ha}{enabled}) ? 1 : 0;
}
sub ha_mode { return ha_enabled() ? 'pair' : 'standalone'; }

# Identity and service address come from the manager, cached per request: node_health, the write gate
# and the HA page ask in a row, and the socket call has a timeout.
our $ha_view_cache;
sub _ha_view {
    return $ha_view_cache if $ha_view_cache;
    return {} unless ha_enabled();
    my ($st) = ha_manager_status();
    my %v;
    if (ref $st eq 'HASH') {
        $v{node_id} = $st->{node_id};
        my $pair = ref $st->{pair} eq 'HASH' ? $st->{pair} : {};
        my $self = ref $pair->{self} eq 'HASH' ? $pair->{self} : {};
        my $peer = ref $pair->{peer} eq 'HASH' ? $pair->{peer} : {};
        $v{node_id} ||= $self->{node_id};
        $v{peer_node_id} = $peer->{node_id};
        # THREE values, not two: undef means "the manager could not tell". Turning it into 0 would declare HA
        # off for a pair that may be working.
        $v{ha_configured} = defined $pair->{ha_configured} ? ($pair->{ha_configured} ? 1 : 0) : undef;
        # The service address is the one the node ACTUALLY holds under the current pair configuration.
        my $addr = $self->{publication_address} || $peer->{publication_address};
        if (defined $addr && length $addr) { $addr =~ s{/\d+$}{}; $v{service_url} = "http://$addr/"; }
    }
    $ha_view_cache = \%v;
    return $ha_view_cache;
}
# Is HA on for this node, i.e. is there an ACTIVE pair configuration? The manager answers; the panel keeps
# no second opinion. Returns 1 | 0 | undef. undef means "unknown" and must not be treated as 0: each caller
# decides what caution means for it (write refusal, degraded, "state unknown" on screen) - fail-closed is
# deliberately not hardwired here because it differs per consumer.
# This is NOT "are the nodes paired" (see ha_trusted()): between paired and HA-on lives a real working
# state (Paired - HA not configured) that nodes reach after HA teardown; answering both with one flag
# showed such nodes the initial pairing screen.
sub ha_configured {
    return 0 unless ha_enabled();
    my $v = _ha_view();
    return $v->{ha_configured};
}

# Are the nodes paired, i.e. do they trust each other? The ONLY source of truth is pair_status
# (pairing.Service): trust lives on its own and survives HA teardown. An unavailable manager means "not
# paired" - the opposite of ha_configured, on purpose: there caution means "refuse writes", here it means
# "do not hide the pairing screen". Either way unknown leads to the lesser harm.
our $ha_trusted_cache;
sub ha_trusted {
    return 0 unless ha_enabled();
    return $$ha_trusted_cache if $ha_trusted_cache;
    my ($r) = ha_manager_request('pair_status');
    my $res = (ref $r eq 'HASH' && ref $r->{result} eq 'HASH') ? $r->{result} : $r;
    my $v = (ref $res eq 'HASH' && defined $res->{state} && $res->{state} eq 'trusted') ? 1 : 0;
    $ha_trusted_cache = \$v;
    return $v;
}

sub ha_node_id     { my $v = _ha_view(); return (defined $v->{node_id} && length $v->{node_id}) ? $v->{node_id} : undef; }
sub ha_service_url { my $v = _ha_view(); return (defined $v->{service_url} && length $v->{service_url}) ? $v->{service_url} : undef; }
# Own addresses of both pair nodes (no mask) while HA is confirmed on: what NOTIFY actually leaves from.
sub ha_node_addresses {
    return () unless ha_configured();
    my ($st) = ha_manager_status();
    my $pair = (ref $st eq 'HASH' && ref $st->{pair} eq 'HASH') ? $st->{pair} : {};
    my %seen;
    return grep { defined && length && !$seen{$_}++ }
           map { my $c = (ref $_ eq 'HASH') ? ($_->{ip_cidr} // '') : ''; $c =~ s{/\d+$}{}; $c } ($pair->{self}, $pair->{peer});
}
# The pair's service address (no mask) while HA is confirmed on; undef otherwise.
sub ha_service_address {
    return undef unless ha_configured();
    my $u = ha_service_url() // return undef;
    return $u =~ m{^http://([^/]+)/$} ? $1 : undef;
}

# Node addresses WITH interface state, for choosing published addresses. State is shown but NOT filtered:
# a VIP comes up later, a tunnel may be down for a while, and hiding such an address makes it unselectable.
# The interface name matters to the human: a tunnel and a bridge are indistinguishable by address alone.
sub node_addresses_state {
    # "Working" is LOWER_UP (carrier present), NOT state or the UP flag:
    #   lo     - state UNKNOWN, yet anycast lives on it;
    #   wg0    - state UNKNOWN for every working tunnel;
    #   lxcbr0 - UP flag set, but NO-CARRIER and state DOWN (bridge without a cable).
    # LOWER_UP tells these three apart correctly; state and UP do not.
    my (%up, %st);
    for my $l (split /\n/, (`ip -o link show 2>/dev/null` || '')) {
        next unless $l =~ /^\d+:\s+([^:@\s]+):\s+<([^>]*)>/;
        my ($ifc, $flags) = ($1, $2);   # NAME AND FLAGS FIRST: the next =~ resets $1
        $up{$ifc} = ($flags =~ /\bLOWER_UP\b/) ? 1 : 0;
        $st{$ifc} = ($l =~ /\bstate\s+(\S+)/) ? $1 : '';
    }
    my @out;
    for my $line (split /\n/, (`ip -o -4 addr show 2>/dev/null` || '')) {
        next unless $line =~ /^\d+:\s+(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+)/;
        my ($ifc, $ip) = ($1, $2);
        next if $ip =~ /^127\./;
        # lo is NOT excluded: anycast lives as a /32 on it (same reason as in _pdns_listen_parse).
        push @out, { address => $ip, iface => $ifc, up => ($up{$ifc} ? 1 : 0), state => ($st{$ifc} // '') }
            unless grep { $_->{address} eq $ip } @out;
    }
    return @out;
}
# This node's addresses (IPv4, no loopback), for the initial setup form: asking the human what the machine
# knows about itself is an extra step and a chance for a typo.
sub node_addresses {
    my @out;
    my $raw = `ip -o -4 addr show 2>/dev/null` || '';
    for my $line (split /\n/, $raw) {
        next unless $line =~ /\binet\s+(\d+\.\d+\.\d+\.\d+)/;
        my $ip = $1;
        next if $ip =~ /^127\./;
        push @out, $ip unless grep { $_ eq $ip } @out;
    }
    return @out;
}

# Address the SECOND node uses to pair with this one; chosen from the node's addresses and stored.
# Previously the screen showed the FIRST non-loopback address from `ip -o -4 addr show` - a guess that was
# the LXC bridge on the stand. The manager listens on :7901 everywhere, so technically nothing depends on
# it, but the human types it on the second node, so it must not be guessed.
# Returns the chosen address if it is STILL on the node; otherwise undef (it may have moved with an interface).
sub ha_pair_address {
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $r, my $e) = _db_row($dbh, "SELECT `value` FROM settings WHERE `key`='ha_pair_address'"); return (undef, $e) if $e;
    my $ip = ($r && defined $r->{value}) ? $r->{value} : '';
    return (undef, undef) unless length $ip;
    return (undef, undef) unless grep { $_ eq $ip } node_addresses();
    return ($ip, undef);
}
sub ha_pair_address_set {
    my ($ip) = @_;
    $ip = _trim($ip) // '';
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    if (!length $ip) {   # "not chosen" is a legitimate state: no hint is required
        (my $ok, my $de) = _do($dbh, "DELETE FROM settings WHERE `key`='ha_pair_address'"); return (undef, $de) if $de;
        return (1, undef);
    }
    # Only an address that EXISTS on the node: free input would be the same guess, just manual.
    return (undef, 'address not found on this node') unless grep { $_ eq $ip } node_addresses();
    (my $ok, my $de) = _do($dbh,
        "INSERT INTO settings (`key`,`value`) VALUES ('ha_pair_address',?) ON DUPLICATE KEY UPDATE `value`=VALUES(`value`)",
        $ip); return (undef, $de) if $de;
    return (1, undef);
}
# Network interfaces of this node, for choosing the service address interface: free input would mean
# guessing a name and finding the error at the next role switch, when the address does not come up.
# loopback is included: in anycast mode the address lives on it.
sub node_ifaces {
    my @out;
    my $raw = `ip -o link show 2>/dev/null` || '';
    for my $line (split /\n/, $raw) {
        next unless $line =~ /^\d+:\s+([^:@]+)[:@]/;
        my $if = $1;
        next if $if =~ /^(docker|veth|br-|virbr)/;   # foreign bridges and veth pairs are irrelevant for the service address
        push @out, $if unless grep { $_ eq $if } @out;
    }
    return @out;
}

# Why sign-in is impossible on THIS node and where to go instead; undef -> the node accepts sign-in.
# Pure: the manager status is an argument, so behaviour is testable without a live pair. Sign-in on STANDBY
# is physically impossible (a session is a MariaDB row and the DB is read-only), and reporting "wrong
# password" there would be a lie (see login.pl).
sub ha_sign_in_block {
    my ($st, $err, $service_url) = @_;
    return { code => 'ha_manager_unavailable', role => 'unknown', service_url => $service_url,
             message => 'HA state is unknown on this node — sign-in may not be possible here'
                      . (defined $err && length $err ? " ($err)" : '') } unless ref $st eq 'HASH';
    my $role = $st->{role} // 'unknown';
    return undef if $role eq 'active';
    my $pair   = ref $st->{pair} eq 'HASH' ? $st->{pair} : {};
    my $peer   = ref $pair->{peer} eq 'HASH' ? $pair->{peer} : {};
    # ACTIVE is named by node hostname/address, not UUID: the human needs to know where to go (the service
    # address or the ACTIVE directly).
    my $is_act = (($peer->{role} // '') eq 'active' && defined $peer->{node_id});
    my $active = $is_act ? ($peer->{hostname} || $peer->{node_id}) : undef;
    (my $active_addr = ($is_act ? $peer->{ip_cidr} : undef) // '') =~ s{/\d+$}{};
    return { code => ($role eq 'unknown' ? 'ha_role_unknown' : 'standby_read_only'),
             role => $role, active_node => $active, (length $active_addr ? (active_addr => $active_addr) : ()),
             service_url => $service_url,
             message => $role eq 'unknown'
                      ? 'This node does not know its HA role — sign-in is not available here'
                      : 'This node is standby: its database is read-only and cannot create a session' };
}

# Same, but asking the live manager. undef -> sign-in is possible.
sub ha_sign_in_hint {
    return undef if ha_mode() ne 'pair';
    my ($st, $err) = ha_manager_status();
    # HA PROVABLY off: the node serves itself and sign-in is ordinary; there is no pair service address to
    # point to. Pairing is irrelevant here: trust does not govern sign-in. With an unknown state
    # (ha_configured=null) no ordinary sign-in is promised: the manager's own account is shown instead of
    # sending the human to log in on a node that may be STANDBY.
    my $hc = (ref $st eq 'HASH' && ref $st->{pair} eq 'HASH') ? $st->{pair}{ha_configured} : undef;
    return undef if defined $hc && !$hc;
    return ha_sign_in_block($st, $err, ha_service_url());
}

# Actual state of the CURRENT node (no fencing/promotion - only "as it is now"), for /health/ready, the
# Dashboard operational status and the load balancer. -> {live, checks{panel_db,schema,pdns_db,pdns_control,
# writable}, role('active'|'standby'|'unknown'), ready(0|1), status('ready'|'standby'|'degraded'), reason}.
sub node_health {
    my %h = (live => 1, checks => {}, role => 'unknown');
    my $mode = ha_mode();
    my $dbh = connectDB();
    $h{checks}{panel_db} = ($dbh && !$dbh->err) ? 1 : 0;
    my $ro;
    if ($h{checks}{panel_db}) {
        my $ph = join(',', ('?') x @HEALTH_CORE_TABLES);
        my ($cnt) = $dbh->selectrow_array(
            "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME IN ($ph)",
            undef, @HEALTH_CORE_TABLES);
        $h{checks}{schema} = (defined $cnt && $cnt == scalar @HEALTH_CORE_TABLES) ? 1 : 0;
        ($ro) = $dbh->selectrow_array("SELECT \@\@global.read_only");
        if (defined $ro) { $h{role} = $ro ? 'standby' : 'active'; $h{checks}{writable} = $ro ? 0 : 1; }
        else { $h{checks}{writable} = 0; }   # role unknown -> conservatively not writable
    } else { $h{checks}{schema} = 0; $h{checks}{writable} = 0; }
    my $pdns = connectPDNS();
    $h{checks}{pdns_db} = ($pdns && !$pdns->err && ($pdns->selectrow_array("SELECT 1"))[0]) ? 1 : 0;
    $h{checks}{pdns_control} = agent_reachable();

    # pair: role and pair health come from the manager; the panel has no role model of its own.
    # HA installed does not mean a pair exists: a node without a pair is plain standalone, and demanding ACTIVE
    # and a raised service address would declare a healthy standalone node sick.
    $h{mode} = $mode;
    my ($mgr_st, $mgr_err);
    my $ha_on = 0;
    if ($mode eq 'pair') {
        ($mgr_st, $mgr_err) = ha_manager_status();
        my ($st, $err) = ($mgr_st, $mgr_err);
        # HA-on is asked, not pairing: after teardown a node is paired but has no roles, and judging it by pair
        # rules would declare a healthy node sick. UNKNOWN (manager unavailable or ha_configured=null from it)
        # counts as "HA on": the other mistake would mark a possibly STANDBY node ready for traffic. The report
        # still carries undef, not 1 - the state is not invented even when the decision is cautious.
        my $hc = (ref $st eq 'HASH' && ref $st->{pair} eq 'HASH') ? $st->{pair}{ha_configured} : undef;
        $ha_on = defined $hc ? ($hc ? 1 : 0) : 1;
        $h{ha_configured} = $hc;
        if (defined $hc && !$hc) {
            $h{mode} = 'standalone';
            $h{node_id} = $st->{node_id} if ref $st eq 'HASH';
        }
    }
    if ($mode eq 'pair' && $ha_on) {
        my ($st, $err) = ($mgr_st, $mgr_err);
        $h{checks}{ha_manager} = $st ? 1 : 0;
        if ($st) {
            $h{node_id}      = $st->{node_id};
            $h{role}         = $st->{role} // 'unknown';
            $h{ha_healthy}   = $st->{ha_healthy} ? 1 : 0;
            $h{peer}         = { map { $_ => $st->{$_} } grep { exists $st->{$_} } qw(peer_node_id) };
            $h{_pair_reason} = $st->{reason};
            # the manager's service_ready is the traffic decision; the panel does not override it.
            $h{checks}{ha_service_ready} = $st->{service_ready} ? 1 : 0;
            $h{ha_operation} = ref $st->{execution} eq 'HASH' ? ($st->{execution}{operation} // '') : '';
        } else {
            $h{role} = 'unknown';
            $h{checks}{ha_service_ready} = 0;
            $h{_pair_reason} = "HA manager is unavailable ($err)";
        }
    }

    ($h{status}, $h{ready}, $h{reason}) =
        _node_verdict($h{checks}, $h{role}, (($mode eq 'pair' && $ha_on) ? ['ha_manager', 'ha_service_ready'] : undef));
    # In pair mode, if BASE core checks pass but not ready, show the specific HA reason (init/mismatch/...).
    if ($mode eq 'pair' && $ha_on && !$h{ready}) {
        my $base_ok = $h{checks}{panel_db} && $h{checks}{schema} && $h{checks}{pdns_db} && $h{checks}{pdns_control};
        $h{reason} = $h{_pair_reason} if $base_ok && defined $h{_pair_reason};
    }
    # An HA operation in progress: a node mid-switch is not ready for traffic even if physically writable,
    # otherwise an external balancer would switch to it before the transition completes.
    if ($mode eq 'pair' && $h{ha_operation}) {
        $h{status} = 'switching';
        $h{reason} = "HA operation in progress ($h{ha_operation})";
        $h{ready}  = 0;
    }
    # Service activation gate (pair): not ready for traffic until PowerDNS is primary AND publication is
    # confirmed. ACTIVE becomes writable right after promote but publishes later; this closes promote..announce.
    # Facts come FROM THE MANAGER, not the agent directly: which address is the service address lives in the
    # replicated config the manager knows. Asking the agent gave a second source of truth (the manager saw
    # publication, the panel did not, and /health/ready kept a healthy ACTIVE "activating" forever).
    # The gate applies only with HA ON: without it there is no role to confirm and no address to publish.
    if ($mode eq 'pair' && $ha_on) {
        my $self = (ref $mgr_st eq 'HASH' && ref $mgr_st->{pair} eq 'HASH') ? $mgr_st->{pair}{self} : undef;
        my $agent_ok = 0;
        if (ref $mgr_st eq 'HASH' && ref $mgr_st->{service_checks} eq 'ARRAY') {
            ($agent_ok) = map { ($_->{state} // '') eq 'ok' ? 1 : 0 }
                          grep { ($_->{name} // '') eq 'agent' } @{ $mgr_st->{service_checks} };
        }
        $h{checks}{ha_agent}  = $agent_ok ? 1 : 0;
        $h{notifier_on}       = (ref $self eq 'HASH' && $self->{notifier_on})     ? 1 : 0;
        $h{route_announced}   = (ref $self eq 'HASH' && $self->{route_announced}) ? 1 : 0;
        $h{service_activated} = ($h{notifier_on} && $h{route_announced}) ? 1 : 0;
        if ($h{role} eq 'active' && $h{ready}) {
            if (!$h{checks}{ha_agent}) {
                $h{status} = 'degraded';
                $h{reason} = 'PowerDNS/HA role not confirmed by the HA agent';
                $h{ready}  = 0;
            } elsif (!$h{service_activated}) {
                $h{status} = 'activating';
                $h{reason} = 'Service activation (NOTIFY/publication) not complete';
                $h{ready}  = 0;
            }
        }
    }
    delete $h{_pair_reason};
    delete $h{reason} unless defined $h{reason};
    # What is installed: the release and the last applied migration ('base' = the schema of the release).
    $h{version} = panel_version();
    if (my $dbh = connectDB()) {
        local $dbh->{PrintError} = 0;
        my ($m) = $dbh->selectrow_array("SELECT MAX(version) FROM schema_migrations");
        $h{schema} = $m // 'base' unless $dbh->err;
    }
    return \%h;
}
# The release of this tree (VERSION at its root, installed as /opt/dns-panel/VERSION).
sub panel_version {
    require File::Spec;
    (my $root = File::Spec->rel2abs(__FILE__)) =~ s{/www/include/functions\.pm$}{};
    open(my $fh, '<', "$root/VERSION") or return 'unknown';
    my $v = <$fh> // ''; $v =~ s/\s+//g;
    return length $v ? $v : 'unknown';
}
# Write gate: may the CURRENT node accept a MUTATING request (contract §6)? Cheap, runs on every mutation:
# standalone -> always allow; pair -> role and running operation from the manager, physics (read_only)
# confirmed locally. STANDBY -> 409, operation running -> 409, unknown state -> 503 (fail-closed).
# -> { allow=>1 } | { allow=>0, status=>409|503, code=>..., message=>... }.
sub _wg_block { my ($status, $code, $msg) = @_; return { allow => 0, status => $status, code => $code, message => $msg }; }
sub ha_write_verdict {
    return { allow => 1 } if ha_mode() ne 'pair';                               # no HA installed at all

    # Role and readiness come from the manager, the only one governing them. The old panel role model read a
    # replicated table that became unavailable exactly when it was needed most.
    my ($st, $err) = ha_manager_status();
    return _wg_block(503, 'ha_manager_unavailable', "HA manager is unavailable ($err)") unless $st;

    # HA installed but NOT ON: the node serves itself and writes freely - there is no role, generation or
    # STANDBY here. HA-on is checked, NOT pairing: after teardown nodes stay paired with both DBs writable,
    # and asking about trust would forbid writes on both.
    # UNKNOWN is a refusal - the main reason the field is three-valued. The manager is alive but could not
    # read `dns_ha` and honestly says "don't know"; taking that as "HA off" would open writes on a node that
    # may be STANDBY right now and diverge the databases - exactly what the whole design exists to prevent.
    my $pv = ref $st->{pair} eq 'HASH' ? $st->{pair} : {};
    return _wg_block(503, 'ha_state_unknown',
        'HA manager cannot tell whether HA is configured (its dns_ha is unreadable)')
        unless defined $pv->{ha_configured};
    return { allow => 1 } unless $pv->{ha_configured};

    my $role = $st->{role} // 'unknown';
    return _wg_block(503, 'ha_role_unknown', 'HA role is not determined') if $role eq 'unknown';
    return _wg_block(409, 'standby_read_only', 'node is standby (read-only) — perform changes on the ACTIVE node')
        if $role ne 'active';

    # An operation in progress freezes writes: a node mid-switch must not accept edits.
    my $op = ref $st->{execution} eq 'HASH' ? ($st->{execution}{operation} // '') : '';
    return _wg_block(409, 'writes_frozen', "writes temporarily frozen (operation $op)") if length $op;

    # Physics is confirmed locally: the right to be ACTIVE and the actual read_only must agree - an
    # independent split-brain detector that does not depend on what the manager thinks.
    my $dbh = connectDB() or return _wg_block(503, 'ha_db_unavailable', 'HA state DB unavailable');
    my ($ro) = $dbh->selectrow_array("SELECT \@\@global.read_only");
    return _wg_block(503, 'ha_read_only_unknown', 'MariaDB read_only undetermined') unless defined $ro;
    return _wg_block(503, 'ha_role_mismatch', 'HA role/read_only mismatch (possible split-brain)') if $ro;
    return { allow => 1 };
}

# Background worker action from the HA verdict: 'allow' (work) | 'skip' (normally change nothing:
# standby/freeze) | 'fail' (fail-closed on unknown/degraded HA state - no guessing). Pure, testable.
sub ha_gate_action {
    my ($v) = @_;
    return 'allow' if $v && $v->{allow};
    my $code = ($v && $v->{code}) || '';
    return 'skip' if $code eq 'standby_read_only' || $code eq 'writes_frozen';
    return 'fail';
}


# =============== Planned switchover facade (REST/CLI); emergency is separate. ===============

# Pure verdict (fail-closed). ready ONLY when all core checks pass AND the role is explicitly active+writable.
#   failed core check         → degraded / 503
#   role=standby              → standby  / 503
#   role=active && writable   → ready    / 200
#   anything else (unknown, read_only undetermined) -> degraded / 503
# → ($status, $ready, $reason).
sub _node_verdict {
    my ($checks, $role, $extra_core) = @_; $role //= '';
    my @core = (qw(panel_db schema pdns_db pdns_control), @{ $extra_core || [] });   # extra_core: e.g. ha_schema in pair mode
    my @failed = grep { !$checks->{$_} } @core;
    return ('degraded', 0, 'failed checks: ' . join(', ', @failed)) if @failed;
    return ('standby',  0, 'node is standby (MariaDB read_only) — not write-ready') if $role eq 'standby';
    return ('ready',    1, undef) if $role eq 'active' && $checks->{writable};
    return ('degraded', 0, 'MariaDB role/read_only could not be determined');
}

# Audit history of one target (e.g. target_type='rrset', target="<fqdn> <TYPE>").
# Index idx_target(target_type,target). Returns \@rows (newest first) with ts/actor/action/...
sub audit_history {
    my ($target_type, $target, $limit) = @_;
    return [] unless defined $target_type && defined $target;
    $limit = 50 unless defined $limit && $limit =~ /^\d+$/ && $limit > 0;
    my $dbh = connectDB() or return [];
    my $rows = $dbh->selectall_arrayref(
        "SELECT ts, actor, actor_role, source, action, result, detail, ip, before_val, after_val, target_label
           FROM audit_log
          WHERE target_type = ? AND target = ?
          ORDER BY id DESC LIMIT $limit",
        { Slice => {} }, $target_type, $target) || [];
    return $rows;
}
# Audit search with filters (Audit log page): exact match on actor/action/result/target_type/source,
# LIKE on target. Paginated. ($rows, $total). limit <= 500.
# The reverse-zone name an address (or its leading octets) is recorded under: '10.99.0.9' -> '9.0.99.10.in-addr.arpa',
# '10.99' -> '99.10.in-addr.arpa', a full IPv6 address -> its nibble name. Anything else -> ().
sub _audit_reverse_name {
    my ($q) = @_;
    return join('.', reverse split /\./, $1) . '.in-addr.arpa' if $q =~ /^(\d{1,3}(?:\.\d{1,3}){0,3})\.?$/;
    if ($q =~ /:/) {
        require Socket;
        my $bin = Socket::inet_pton(Socket::AF_INET6(), $q) // return ();
        return join('.', reverse split //, unpack('H32', $bin)) . '.ip6.arpa';
    }
    return ();
}
sub audit_search {
    my ($f, $limit, $offset) = @_;
    $f ||= {};
    $limit  = 50 unless defined $limit  && $limit  =~ /^\d+$/ && $limit > 0 && $limit <= 500;
    $offset = 0  unless defined $offset && $offset =~ /^\d+$/;
    my $dbh = connectDB() or return ([], 0);
    my (@w, @a);
    for my $col (qw(actor action result target_type source)) {
        next unless defined $f->{$col} && length $f->{$col};
        push @w, "$col = ?"; push @a, $f->{$col};
    }
    # One search box over everything a row says: who, the action (code and its label), target and its
    # displayed name, old and new values, detail, client address, how it signed in. An address also finds
    # its reverse name, so 10.99.0.9 matches both the A record and 9.0.99.10.in-addr.arpa.
    # Time range. A UTC moment 'YYYY-MM-DDTHH:MM:SS' (the UI sends the person's day bounds so, 'to' exclusive),
    # or a UTC day 'YYYY-MM-DD' with both ends inclusive.
    for my $k (qw(from to)) {
        my $d = $f->{$k} // '';
        if ($d =~ /^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})$/) { push @w, 'ts ' . ($k eq 'from' ? '>=' : '<') . ' ?'; push @a, "$1 $2"; }
        elsif ($d =~ /^\d{4}-\d{2}-\d{2}$/) { push @w, $k eq 'from' ? 'ts >= ?' : 'ts < DATE_ADD(?, INTERVAL 1 DAY)'; push @a, $d; }
    }
    my $q = _trim($f->{target});
    if (defined $q && length $q) {
        my @terms = ($q, _audit_reverse_name($q));
        my @or;
        for my $t (@terms) {
            (my $l = $t) =~ s/([\\%_])/\\$1/g;
            push @or, '(' . join(' OR ', map { "$_ LIKE ?" } qw(actor action target target_label before_val after_val detail ip via)) . ')';
            push @a, ("%$l%") x 9;
        }
        my @codes = grep { index(lc $AUDIT_ACTION_LABELS{$_}, lc $q) >= 0 } keys %AUDIT_ACTION_LABELS;
        if (@codes) { push @or, 'action IN (' . join(',', ('?') x @codes) . ')'; push @a, @codes; }
        push @w, '(' . join(' OR ', @or) . ')';
    }
    my $where = @w ? ('WHERE ' . join(' AND ', @w)) : '';
    my ($total) = $dbh->selectrow_array("SELECT COUNT(*) FROM audit_log $where", undef, @a);
    my $rows = $dbh->selectall_arrayref(
        "SELECT id, ts, actor, actor_role, source, via, action, result, target_type, target, target_label, detail, ip, before_val, after_val
           FROM audit_log $where ORDER BY id DESC LIMIT $limit OFFSET $offset", { Slice => {} }, @a) || [];
    for my $r (@$rows) {
        $r->{action_label} = audit_action_label($r->{action});   # human-readable label (single dictionary)
        # read-time fallback: old rows without a snapshot -> name of a still existing object (deleted -> id stays).
        $r->{target_label} = audit_target_label($r->{target_type}, $r->{target})
            if (!defined $r->{target_label} || $r->{target_label} eq '');
    }
    # Enrich zone targets with domain_id for a clickable link: target holds EITHER an id OR a name (old/system
    # rows). Names resolve to ids in one pdns query; a deleted zone -> target_id undef (frontend shows text).
    my %n2id;
    my @names = map { (my $n = lc $_->{target}) =~ s/\.$//; $n }
                grep { ($_->{target_type} // '') eq 'zone' && defined $_->{target} && $_->{target} !~ /^\d+$/ } @$rows;
    if (@names) {
        my %uniq = map { $_ => 1 } @names;
        my $pdns = connectPDNS();
        if ($pdns) {
            my @u = keys %uniq; my $ph = join(',', ('?') x @u);
            my $dr = $pdns->selectall_arrayref("SELECT id, name FROM domains WHERE name IN ($ph)", { Slice => {} }, @u) || [];
            $n2id{ $_->{name} } = $_->{id} + 0 for @$dr;
        }
    }
    for my $r (@$rows) {
        next unless ($r->{target_type} // '') eq 'zone' && defined $r->{target};
        if ($r->{target} =~ /^\d+$/) { $r->{target_id} = $r->{target} + 0; }
        else { (my $n = lc $r->{target}) =~ s/\.$//; $r->{target_id} = $n2id{$n}; }   # undef if the zone was deleted
    }
    return ($rows, ($total // 0) + 0);
}
# Distinct values for the Audit log filter dropdowns. \%{actions,results,target_types,sources,actors}.
sub audit_filter_options {
    my $dbh = connectDB() or return {};
    my $col = sub { $dbh->selectcol_arrayref("SELECT DISTINCT $_[0] FROM audit_log WHERE $_[0] IS NOT NULL AND $_[0] <> '' ORDER BY $_[0] LIMIT 200") || []; };
    # actions/target_types as {value (technical), label (readable)}: the dropdown shows labels, filters by value.
    my $actions = [ map { { value => $_, label => audit_action_label($_) } } @{ $col->('action') } ];
    my $types   = [ map { { value => $_, label => audit_type_label($_) } }   @{ $col->('target_type') } ];
    return { actions => $actions, results => $col->('result'), target_types => $types, sources => $col->('source'), actors => $col->('actor') };
}
# Recent activity for the Dashboard. The background worker's AUTOMATIC retries are excluded: one problem
# secondary zone writes a row every few minutes and filled all 12 lines on the live stand. Nothing is lost:
# state and attempts are shown in "Zone sync problems", the full log on the Audit log page. The filter
# is narrow: a human "Retry now" comes with source='api' and stays visible.
our $AUDIT_RECENT_SKIP = "(source = 'system' AND action = 'retry_sync')";
sub audit_recent {
    my ($limit) = @_;
    $limit = 15 unless defined $limit && $limit =~ /^\d+$/ && $limit > 0;
    my $dbh = connectDB() or return [];
    my $rows = $dbh->selectall_arrayref(
        "SELECT ts, actor, action, result, target_type, target, target_label FROM audit_log
          WHERE NOT $AUDIT_RECENT_SKIP
          ORDER BY id DESC LIMIT $limit",
        { Slice => {} }) || [];
    for my $r (@$rows) {
        $r->{action_label} = audit_action_label($r->{action});
        $r->{target_label} = audit_target_label($r->{target_type}, $r->{target})
            if (!defined $r->{target_label} || $r->{target_label} eq '');
    }
    return $rows;
}
# Catalog state for the Dashboard. Exactly two questions: does the producer zone exist, and did policy
# application fail.
sub _dashboard_catalog_state {
    my ($c) = @_;
    return 'problem' if $c->{last_error};
    return 'ready'   if $c->{provisioned};
    return 'pending';
}
# Subscription observed_state -> Dashboard bucket. unknown = NO observation yet -> problem (not lagging,
# which is a confirmed lagging serial). Worst state per node by rank.
our %DASH_SEC_BUCKET = (subscribed => 'synced', lagging => 'lagging', unsubscribed => 'problem', error => 'problem', unknown => 'problem');
our %DASH_SEC_RANK   = (synced => 0, lagging => 1, problem => 2);

# Dashboard summary: an aggregate of EXISTING data. \%summary.
#   zones {total,records,masters,slaves}; catalogs {total,ready,pending,problems} + catalog_list[];
#   secondaries {synced,lagging,problem,total} (per NODE worst state from catalog_subscriptions);
#   problem_zones[] (sync_problem_zones); recent_audit[].
sub dashboard_summary {
    my %s;
    my $doms = pdns_list_domains() || [];
    $s{zones} = { total => 0, records => 0, masters => 0, slaves => 0 };
    for my $d (@$doms) {
        my $t = uc($d->{type} || '');
        next if $t eq 'PRODUCER' || $t eq 'CONSUMER';   # catalog service zones are not counted as regular ones
        $s{zones}{total}++;
        $s{zones}{records} += ($d->{record_count} || 0);
        $s{zones}{masters}++ if $t eq 'MASTER';
        $s{zones}{slaves}++  if $t eq 'SLAVE';
    }
    (my $cats) = catalogs_all(); $cats ||= [];
    $s{catalogs} = { total => 0, ready => 0, pending => 0, problems => 0 };
    my @clist;
    for my $c (@$cats) {
        $s{catalogs}{total}++;
        my $state = _dashboard_catalog_state($c);
        $s{catalogs}{ $state eq 'problem' ? 'problems' : $state }++;
        push @clist, { catalog_id => $c->{id}, name => $c->{name}, fqdn => $c->{fqdn},
                       state => $state, last_error => $c->{last_error} };
    }
    $s{catalog_list} = \@clist;
    # Secondary nodes: the worst bucket across all the node's subscriptions (a node may be in several catalogs).
    my $dbh = connectDB();
    my %worst;
    if ($dbh) {
        my $subs = $dbh->selectall_arrayref("SELECT secondary_node_id nid, observed_state st FROM catalog_subscriptions", { Slice => {} }) || [];
        for my $r (@$subs) {
            my $b  = $DASH_SEC_BUCKET{ $r->{st} } // 'problem';
            my $rk = $DASH_SEC_RANK{$b};
            $worst{ $r->{nid} } = $b if !exists $worst{ $r->{nid} } || $rk > $DASH_SEC_RANK{ $worst{ $r->{nid} } };
        }
    }
    $s{secondaries} = { synced => 0, lagging => 0, problem => 0, total => scalar keys %worst };
    $s{secondaries}{$_}++ for values %worst;
    (my $pz) = sync_problem_zones(); $pz ||= [];
    my %name2id = map { lc($_->{name}) => $_->{id} + 0 } @$doms;   # for clickable zone links
    $_->{domain_id} = $name2id{ lc($_->{zone_name}) } for @$pz;
    $s{problem_zones} = $pz;
    $s{recent_audit} = audit_recent(12);
    $s{operational} = node_health();   # single operational status (same as /health/ready)
    return \%s;
}

# ============================================================================
# CONFIG: etc/panel.toml (bootstrap) + the settings table (operational settings)
# ============================================================================
# Split by owner, not convenience:
#   panel.toml  - what is needed BEFORE the DB can be reached (MariaDB access, PowerDNS API, encryption
#                 key, privileged agent socket) and properties of THIS node. Edited by hand, rarely.
#   settings    - what the admin manages in the panel (sync timeouts, MCP policy, session TTL). Shared by
#                 the pair, replicated with the rest of the DB.
#   secrets/    - the secrets themselves, as FILES. A password in config ends up in backups and clipboards;
#                 a TOTP encryption key next to the encrypted secrets in the DB defeats the encryption.
# HA is ONE FLAG here (`ha.enabled`). Who we are, who the peer is and the pair's service address are known
# to dns-ha-manager only; a second source once made the panel believe it was ACTIVE when it was not.

our $config_cache;

# Minimal TOML parser: sections, key = value, strings/numbers/booleans/string arrays. Enough because the
# format is our own and deliberately flat; no CPAN module needed.
sub _toml_value {
    my ($raw) = @_;
    $raw =~ s/\s+#.*$//;                       # trailing comment
    $raw =~ s/^\s+|\s+$//g;
    return [ map { my $v = $_; $v =~ s/^\s*"|"\s*$//g; $v } grep { length } split /\s*,\s*/, $1 ]
        if $raw =~ /^\[(.*)\]$/;
    return 1 if $raw eq 'true';
    return 0 if $raw eq 'false';
    if ($raw =~ /^"(.*)"$/) { return $1; }
    return $raw + 0 if $raw =~ /^-?\d+$/;
    return $raw;
}

sub load_panel_config {
    return $config_cache if $config_cache;
    # Product root is one level above www/: the same tree in the repo and in the install (/opt/dns-panel).
    my $path = File::Spec->catfile(dirname(__FILE__), '..', '..', 'etc', 'panel.toml');
    die "etc/panel.toml not found ($path). Copy etc/panel.example.toml.\n" unless -f $path;
    open(my $fh, '<:encoding(UTF-8)', $path) or die "etc/panel.toml: cannot read: $!\n";
    my (%cfg, $section);
    my $ln = 0;
    while (my $line = <$fh>) {
        $ln++;
        $line =~ s/^\s+|\s+$//g;
        next if $line eq '' || $line =~ /^#/;
        if ($line =~ /^\[(.+)\]$/) { $section = $1; next; }
        my ($k, $v) = $line =~ /^([A-Za-z0-9_]+)\s*=\s*(.+)$/;
        die "etc/panel.toml:$ln: expected 'key = value'\n" unless defined $k;
        die "etc/panel.toml:$ln: key outside of a section\n" unless defined $section;
        $cfg{$section}{$k} = _toml_value($v);
    }
    close $fh;
    validate_panel_config(\%cfg);
    $config_cache = \%cfg;
    return $config_cache;
}

# Fail loud: the panel never invents values. A missing required section fails on first config access,
# not as "somehow cannot connect to the DB".
sub validate_panel_config {
    my ($c) = @_;
    my @err;
    for my $sec (qw(panel_db pdns_db)) {
        my $d = $c->{$sec};
        if (ref $d ne 'HASH') { push @err, "section [$sec] is required"; next; }
        push @err, "$sec.$_ is required" for grep { !defined $d->{$_} || $d->{$_} eq '' } qw(name user);
        push @err, "$sec.password_file is required (the password lives in a file, not in the config)"
            unless defined $d->{password_file} && length $d->{password_file};
    }
    push @err, "section [auth] is required: auth.master_key_file"
        unless ref $c->{auth} eq 'HASH' && defined $c->{auth}{master_key_file} && length $c->{auth}{master_key_file};
    push @err, "section [agent] is required: agent.socket"
        unless ref $c->{agent} eq 'HASH' && defined $c->{agent}{socket} && length $c->{agent}{socket};
    if (defined $c->{ha} && ref $c->{ha} ne 'HASH') { push @err, "section [ha] must be a table"; }
    die "etc/panel.toml is invalid:\n  - " . join("\n  - ", @err) . "\n" if @err;
    return 1;
}

# Operational settings live in the DB. Defaults live in code: a fresh install must work with no settings
# rows, and the admin changes only what they actually want to change.
our %SETTING_DEFAULTS = (
    'sync.poll_seconds'              => 30,       # how soon a zone waiting for its first AXFR is checked again
    'import.probe_batch'             => 50,       # zones per probe pass of the sync worker (docs/26)
    'sync.transfer_timeout_seconds'  => 3600,
    'sync.backoff_initial_seconds'   => 60,
    'sync.backoff_max_seconds'       => 3600,
    'sync.catalog_check_seconds'     => 60,       # how often the sync daemon asks secondaries for the catalog serial
    'sync.reconcile_seconds'         => 600,      # safety pass over distribution/dynamic policy against drift
    'sync.retry_batch'               => 100,      # zones one retry pass takes; the daemon runs the next pass at once if more are due
    'import.probe_budget_seconds'     => 60,       # one probe batch stops after this, so a slow old server does not hold other passes
    'dist_verify.timeout'            => 3,
    'auth.session_ttl'               => 86400,
    'auth.totp_issuer'               => 'DNS Panel',   # name shown in the authenticator app
    'mcp.readonly'                   => 0,
    'mcp.default_user'               => '',
    # External access (Settings → External access): remote MCP endpoint, anonymous read.
    'external.mcp_http'              => 0,
    'external.anonymous_read'        => 0,
);
our $settings_cache;

sub setting {
    my ($key, $default) = @_;
    die "unknown setting '$key'\n" unless exists $SETTING_DEFAULTS{$key};
    unless ($settings_cache) {
        $settings_cache = {};
        if (my $dbh = connectDB()) {
            my $rows = eval { $dbh->selectall_arrayref("SELECT `key`, `value` FROM settings", { Slice => {} }) };
            $settings_cache->{ $_->{key} } = $_->{value} for @{ $rows || [] };
        }
    }
    my $v = $settings_cache->{$key};
    return $v if defined $v && $v ne '';
    return defined $default ? $default : $SETTING_DEFAULTS{$key};
}


# Value from panel.toml. Secrets are returned as the file CONTENT: config holds only the path.
sub get_config_value {
    my ($section, $key) = @_;
    my $c = load_panel_config();
    return undef unless ref $c->{$section} eq 'HASH';
    return $c->{$section}{$key};
}

# Read a secret from the file referenced by config. An unreadable file is an error, not an empty password:
# silently connecting without a password is worse than not connecting.
sub _secret_file {
    my ($section, $key) = @_;
    my $path = get_config_value($section, $key);
    die "etc/panel.toml: $section.$key is not set\n" unless defined $path && length $path;
    open(my $fh, '<', $path) or die "$section.$key: cannot read $path: $!\n";
    local $/; my $v = <$fh>; close $fh;
    $v =~ s/\s+$//;
    return $v;
}

# Zone profile codes, sorted.
sub zone_profile_names {
    my $dbh = connectDB() or return [];
    my $rows = $dbh->selectcol_arrayref("SELECT code FROM zone_profiles WHERE enabled=1 ORDER BY name");
    return $rows || [];
}
# Profiles for the Add zone / Zone settings form: {code(value), name(label)} objects, enabled only.
sub zone_profiles_for_form {
    my $dbh = connectDB() or return [];
    my $rows = $dbh->selectall_arrayref("SELECT code, name FROM zone_profiles WHERE enabled=1 ORDER BY name", { Slice => {} });
    return $rows || [];
}

# ================= Zone profiles CRUD (Settings -> Zone profiles) =================
# code is immutable (written to X-DNSPANEL-PROFILE); >=1 nameserver; strict FQDN and positive SOA timer
# validation. default_catalog_id -> catalogs.id (logical catalog).
sub _zp_fqdn {   # NS/hostmaster: FQDN-like, trailing dot normalized. ($norm, undef) | (undef, err).
    my ($v, $label) = @_;
    $v = defined $v ? "$v" : ''; $v =~ s/^\s+|\s+$//g;
    return (undef, "$label required") unless length $v;
    # Hostmaster is naturally written as an email: postmaster@example.com -> postmaster.example.com. (in SOA
    # "@" is the first dot; dots before "@" are escaped: first.last@... -> first\.last....).
    if ($label eq 'hostmaster' && $v =~ /^([^@\s]+)@([^@\s]+)$/) {
        my ($local, $domain) = ($1, $2);   # before s///: the substitution resets $1/$2
        $local =~ s/\./\\./g;
        $v = "$local.$domain";
    }
    return (undef, "$label too long") if length $v > 255;
    return (undef, "$label invalid (need a name like ns1.example.com" . ($label eq 'hostmaster' ? ' or an e-mail address' : '') . ")")
        unless $v =~ /^[A-Za-z0-9._\\-]+$/ && $v =~ /\./ && ($label eq 'hostmaster' || $v !~ /\\/);
    $v .= '.' unless $v =~ /\.$/;
    return ($v, undef);
}
sub _zp_posint { my ($v, $l) = @_; return (undef, "$l must be a positive integer") unless defined $v && "$v" =~ /^\d+$/ && $v + 0 > 0; return ($v + 0, undef); }
# Preset body validation. $v = {primary_ns,hostmaster,nameservers[],soa_*,default_catalog_id?}.
sub _zp_validate_preset {
    my ($dbh, $v) = @_;
    return (undef, 'preset missing') unless ref($v) eq 'HASH';
    my %o;
    (my $pn, my $e) = _zp_fqdn($v->{primary_ns}, 'primary_ns'); return (undef, $e) if $e; $o{primary_ns} = $pn;
    (my $hm, $e)    = _zp_fqdn($v->{hostmaster}, 'hostmaster'); return (undef, $e) if $e; $o{hostmaster} = $hm;
    return (undef, 'nameservers required (>=1)') unless ref($v->{nameservers}) eq 'ARRAY' && @{ $v->{nameservers} };
    my @ns; for my $n (@{ $v->{nameservers} }) { (my $nn, my $ne) = _zp_fqdn($n, 'nameserver'); return (undef, $ne) if $ne; push @ns, $nn; }
    $o{nameservers} = \@ns;
    for my $k (qw(soa_ttl soa_refresh soa_retry soa_expire soa_minimum)) { (my $iv, my $ie) = _zp_posint($v->{$k}, $k); return (undef, $ie) if $ie; $o{$k} = $iv; }
    my $aud = $v->{default_catalog_id};
    if (defined $aud && "$aud" ne '') {
        return (undef, 'invalid default_catalog_id') unless "$aud" =~ /^\d+$/;
        (my $ex, $e) = _db_exists($dbh, "SELECT 1 FROM catalogs WHERE id=?", $aud); return (undef, $e) if $e;
        return (undef, 'unknown catalog') unless $ex;
        $o{default_catalog_id} = $aud + 0;
    } else { $o{default_catalog_id} = undef; }
    return (\%o, undef);
}
# Write a profile preset (+ nameservers) FROM SCRATCH, in the caller's transaction. undef=ok | errstr.
sub _zp_write_preset {
    my ($dbh, $pid, $o) = @_;
    $dbh->do("UPDATE zone_profiles SET default_catalog_id=?, primary_ns=?, hostmaster=?,
                     soa_ttl=?, soa_refresh=?, soa_retry=?, soa_expire=?, soa_minimum=? WHERE id=?",
             undef, $o->{default_catalog_id}, $o->{primary_ns}, $o->{hostmaster},
             $o->{soa_ttl}, $o->{soa_refresh}, $o->{soa_retry}, $o->{soa_expire}, $o->{soa_minimum}, $pid);
    return $dbh->errstr if $dbh->err;
    $dbh->do("DELETE FROM zone_profile_nameservers WHERE profile_id=?", undef, $pid); return $dbh->errstr if $dbh->err;
    my $ord = 0;
    for my $ns (@{ $o->{nameservers} }) {
        $dbh->do("INSERT INTO zone_profile_nameservers (profile_id, nameserver, ord) VALUES (?,?,?)", undef, $pid, $ns, $ord++);
        return $dbh->errstr if $dbh->err;
    }
    return undef;
}
# Zones using each profile (by code), cross-DB via X-DNSPANEL-PROFILE in pdns.domainmetadata.
sub _zone_profile_usage_map {
# (\%{code=>count}, undef)|(undef,err).
    my $pdns = connectPDNS() or return (undef, 'DB unavailable');
    (my $rows, my $e) = _db_all($pdns, "SELECT content, COUNT(*) c FROM domainmetadata WHERE kind='X-DNSPANEL-PROFILE' GROUP BY content", { Slice => {} });
    return (undef, $e) if $e;
    my %m; $m{ $_->{content} } = $_->{c} + 0 for @$rows;
    return (\%m, undef);
}
sub zone_profiles_all {
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $rows, my $e) = _db_all($dbh, "SELECT id, code, name, enabled FROM zone_profiles ORDER BY name", { Slice => {} });
    return (undef, $e) if $e;
    (my $use, my $ue) = _zone_profile_usage_map(); return (undef, $ue) if $ue;   # used_by N zones: for Settings + the delete guard
    for (@$rows) { $_->{id} += 0; $_->{enabled} += 0; $_->{used_by} = ($use->{ $_->{code} } || 0) + 0; }
    return ($rows, undef);
}
sub zone_profile_get {
    my ($id) = @_;
    return (undef, 'not found') unless $id && $id =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $p, my $e) = _db_row($dbh,
        "SELECT id, code, name, enabled, default_catalog_id, primary_ns, hostmaster,
                soa_ttl, soa_refresh, soa_retry, soa_expire, soa_minimum FROM zone_profiles WHERE id=?", $id);
    return (undef, $e) if $e;
    return (undef, 'not found') unless $p;
    (my $ns, $e) = _db_all($dbh, "SELECT nameserver FROM zone_profile_nameservers WHERE profile_id=? ORDER BY ord, id", { Slice => {} }, $id); return (undef, $e) if $e;
    $p->{id} += 0; $p->{enabled} += 0;
    $p->{default_catalog_id} = defined $p->{default_catalog_id} ? $p->{default_catalog_id} + 0 : undef;
    $p->{$_} += 0 for qw(soa_ttl soa_refresh soa_retry soa_expire soa_minimum);
    $p->{nameservers} = [ map { $_->{nameserver} } @$ns ];
    return ($p, undef);
}
sub zone_profile_create {
    my ($f) = @_; $f ||= {};
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $name, my $ne) = _check_len($f->{name}, 'name', 64, 1); return (undef, $ne) if $ne;
    # code: internal immutable key (written to the zone's X-DNSPANEL-PROFILE so renaming a profile keeps the
    # link). Not typed by the human: derived from the name, with -2, -3... on collision.
    my $code = _trim($f->{code}) // '';
    if ($code eq '') {
        (my $base = lc $name) =~ s/[^a-z0-9._-]+/-/g;
        $base =~ s/^-+|-+$//g;
        $base = 'profile' if $base eq '';
        $base = substr($base, 0, 60);
        $code = $base;
        for (my $i = 2; ; $i++) {
            (my $taken, my $te) = _db_exists($dbh, "SELECT 1 FROM zone_profiles WHERE code=?", $code); return (undef, $te) if $te;
            last unless $taken;
            $code = "$base-$i";
        }
    }
    return (undef, 'code invalid (1-64 chars A-Z a-z 0-9 . _ -)') unless $code =~ /^[A-Za-z0-9._-]{1,64}$/;
    my $enabled = 1; if (defined $f->{enabled}) { (my $b, my $be) = strict_bool($f->{enabled}); return (undef, "enabled: $be") if $be; $enabled = $b; }
    (my $preset, my $pe) = _zp_validate_preset($dbh, $f->{preset}); return (undef, $pe) if $pe;
    (my $dup, my $de) = _db_exists($dbh, "SELECT 1 FROM zone_profiles WHERE code=? OR name=?", $code, $name); return (undef, $de) if $de;
    return (undef, "profile '$code'/'$name' already exists") if $dup;
    (my $bo, my $be2) = _txn_begin($dbh); return (undef, $be2) if $be2;
    my $done = eval {
        $dbh->do("INSERT INTO zone_profiles (code, name, enabled) VALUES (?,?,?)", undef, $code, $name, $enabled); die "db\n" if $dbh->err;
        my $pid = $dbh->last_insert_id(undef, undef, undef, undef);
        my $we = _zp_write_preset($dbh, $pid, $preset); die "$we\n" if $we;
        $pid;
    };
    if (!$done) { my $err = $@ || 'create failed'; $err =~ s/\n//g; eval { $dbh->rollback }; return (undef, ($err eq 'db' ? _db_err_kind($dbh->err) : $err)); }
    $dbh->commit or die "commit failed\n";
    return ($done + 0, undef);
}
sub zone_profile_update {
    my ($id, $f) = @_; $f ||= {};
    return (undef, 'id required') unless $id && $id =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $cur, my $e) = _db_row($dbh, "SELECT id, code FROM zone_profiles WHERE id=?", $id); return (undef, $e) if $e;
    return (undef, 'not found') unless $cur;
    return (undef, 'code is immutable') if exists $f->{code} && defined $f->{code} && (_trim($f->{code}) // '') ne $cur->{code};
    my (@set, @val);
    if (exists $f->{name}) {
        (my $n, my $ne) = _check_len($f->{name}, 'name', 64, 1); return (undef, $ne) if $ne;
        (my $dup, my $de) = _db_exists($dbh, "SELECT 1 FROM zone_profiles WHERE name=? AND id<>?", $n, $id); return (undef, $de) if $de;
        return (undef, "name '$n' already exists") if $dup;
        push @set, 'name=?'; push @val, $n;
    }
    if (exists $f->{enabled}) { (my $b, my $be) = strict_bool($f->{enabled}); return (undef, "enabled: $be") if $be; push @set, 'enabled=?'; push @val, $b; }
    my $preset;
    if (exists $f->{preset}) { (my $o, my $ve) = _zp_validate_preset($dbh, $f->{preset}); return (undef, $ve) if $ve; $preset = $o; }
    return (1, undef) unless @set || $preset;
    (my $bo, my $be2) = _txn_begin($dbh); return (undef, $be2) if $be2;
    my $done = eval {
        if (@set)  { $dbh->do("UPDATE zone_profiles SET " . join(',', @set) . " WHERE id=?", undef, @val, $id); die "db\n" if $dbh->err; }
        if ($preset) { my $we = _zp_write_preset($dbh, $id, $preset); die "$we\n" if $we; }
        1;
    };
    if (!$done) { my $err = $@ || 'update failed'; $err =~ s/\n//g; eval { $dbh->rollback }; return (undef, ($err eq 'db' ? _db_err_kind($dbh->err) : $err)); }
    $dbh->commit or die "commit failed\n";
    return (1, undef);
}
sub zone_profile_delete {
    my ($id) = @_;
    return (undef, 'id required') unless $id && $id =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $p, my $e) = _db_row($dbh, "SELECT code FROM zone_profiles WHERE id=?", $id); return (undef, $e) if $e;
    return (undef, 'not found') unless $p;
    # Delete is refused while zones use the profile (a dangling X-DNSPANEL-PROFILE); disable is always allowed.
    (my $use, my $ue) = _zone_profile_usage_map(); return (undef, $ue) if $ue;
    my $n = $use->{ $p->{code} } || 0;
    return (undef, "profile in use by $n zone(s) — disable it instead") if $n;
    (my $ok, my $de) = _do($dbh, "DELETE FROM zone_profiles WHERE id=?", $id); return (undef, $de) if $de;   # nameservers CASCADE
    return (1, undef);
}

# ============================================================================
# SECONDARY DISTRIBUTION - inventory foundation (docs/21 §9, §14). CRUD + strict validation, NO apply in PowerDNS.
# Return contracts (strict -> the Router maps to 200/400/404/409/500/503):
#   *_all  → (\@rows, undef) | (undef, 'DB unavailable')
#   *_get  → ($data, undef)  | (undef, 'not found') | (undef, 'DB unavailable')
#   create → ($id, undef) | (undef, $err) ; update/delete → (1, undef) | (undef, $err)
# Error kinds: validation string->400; 'not found'/'unknown ...'->404; 'conflict'/'in use'/
#   'invalid reference'/'constraint violation'/'already ...'->409; 'DB error'->500; 'DB unavailable'->503.
# A DB error is NEVER reported as not-found/empty/400: reads go through _db_*, writes through _do
# (MySQL errno classified: 1062->conflict, 1451->in use, 1452->invalid reference, CHECK->constraint).
# Child entities are changed/deleted STRICTLY by the (parent,child) pair: a foreign child -> not found.
# Permissions (docs/20 + 21 §12) are checked by the Router (field-level for axfr_auth_mode).
# ============================================================================

# --- DB helpers: reads tell success/no-row/DB-error apart; writes classify errno ---
# DBI error class: lost/refused CONNECTION -> 'DB unavailable' (503, real outage);
# SQL/schema/programming error (missing table, syntax, ...) -> 'DB error' (500).
sub _db_err_kind {
    my ($code) = @_;
    $code = ($code // 0) + 0;
    return 'DB unavailable' if $code==2002 || $code==2003 || $code==2006 || $code==2013
                            || $code==2055 || $code==1053 || $code==1077 || $code==1152;
    # 1205 (lock wait timeout), 1213 (deadlock) and 1020 ("record has changed since last read") are not
    # breakage but "busy right now": the same operation can be retried and will succeed. 1020 came from a
    # live trace: the DB returns it to whoever read a row while another changed it, then wrote.
    return 'busy — another change is in progress, try again' if $code==1205 || $code==1213 || $code==1020;
    return 'DB error';
}
sub _db_exists {
    my ($dbh, $sql, @b) = @_;
    my $r = $dbh->selectrow_arrayref($sql, undef, @b);
    return (undef, _db_err_kind($dbh->err)) if $dbh->err;
    return ($r ? 1 : 0, undef);
}
sub _db_row {
    my ($dbh, $sql, @b) = @_;
    my $r = $dbh->selectrow_hashref($sql, undef, @b);
    return (undef, _db_err_kind($dbh->err)) if $dbh->err;
    return ($r, undef);
}
sub _db_all {
    my ($dbh, $sql, $attr, @b) = @_;
    my $r = $dbh->selectall_arrayref($sql, $attr, @b);
    return (undef, _db_err_kind($dbh->err)) if $dbh->err;
    return ($r // [], undef);
}
sub _db_count {
    my ($dbh, $sql, @b) = @_;
    my ($n) = $dbh->selectrow_array($sql, undef, @b);
    return (undef, _db_err_kind($dbh->err)) if $dbh->err;
    return (($n // 0)+0, undef);
}
# Write: (1,undef) | (undef, typed-error). MySQL errno is classified (precheck<->do races, internal
# failures) - otherwise everything would fall into 400.
sub _do {
    my ($dbh, $sql, @b) = @_;
    my $r = $dbh->do($sql, undef, @b);
    return (1, undef) if defined $r;
    my $code = $dbh->err || 0;
    return (undef, 'conflict')             if $code == 1062;             # duplicate key
    return (undef, 'in use')               if $code == 1451;             # FK: parent has children (RESTRICT)
    return (undef, 'invalid reference')    if $code == 1452;             # FK: child references missing parent
    return (undef, 'constraint violation') if $code == 3819 || $code == 4025;  # CHECK
    return (undef, _db_err_kind($code));   # conn loss (2006/2013/...) -> 'DB unavailable'/503; SQL/schema -> 'DB error'/500
}
# Begin a transaction with a typed error (RaiseError=0): (1,undef)|(undef,'DB unavailable'|'DB error').
sub _txn_begin {
    my ($dbh) = @_;
    return (1, undef) if $dbh->begin_work;
    return (undef, _db_err_kind($dbh->err));
}

# --- Pure validators (no DB) ---
sub _mask_packed {
    my ($packed, $len) = @_;
    my @b = unpack('C*', $packed);
    my $full = int($len / 8);
    my $rem  = $len % 8;
    my @out;
    for my $i (0 .. $#b) {
        if    ($i <  $full)         { push @out, $b[$i]; }
        elsif ($i == $full && $rem) { push @out, $b[$i] & ((0xFF << (8 - $rem)) & 0xFF); }
        else                        { push @out, 0; }
    }
    return pack('C*', @out);
}
# IDN: a name as people read it. PowerDNS keeps punycode (xn--...); a label that does not decode stays as it is.
sub dns_name_unicode {
    my ($name) = @_;
    return $name unless defined $name && $name =~ /xn--/i;
    require URI::_punycode;
    return join '.', map {
        my $l = $_;
        if ($l =~ /^xn--(.+)$/i) {
            my $u = eval { URI::_punycode::decode_punycode($1) };
            $l = $u if defined $u && length $u;
        }
        $l;
    } split /\./, $name, -1;
}
# The other way, for what people type: every non-ASCII label becomes xn--... (a part of a word cannot be found
# this way — punycode of a fragment is not a fragment of the punycode).
sub dns_name_ascii {
    my ($name) = @_;
    return $name unless defined $name && $name =~ /[^\x00-\x7f]/;
    require URI::_punycode;
    # CGI hands parameters over as UTF-8 bytes.
    unless (utf8::is_utf8($name)) {
        require Encode;
        my $c = eval { Encode::decode('UTF-8', $name, Encode::FB_CROAK()) };
        $name = $c if defined $c;
    }
    return join '.', map {
        my $l = lc $_;
        if ($l =~ /[^\x00-\x7f]/) {
            my $a = eval { URI::_punycode::encode_punycode($l) };
            $l = "xn--$a" if defined $a;
        }
        $l;
    } split /\./, $name, -1;
}
# The name for a table cell: Unicode, with the punycode in the tooltip — look-alike letters must stay checkable.
sub dns_name_html {
    my ($name) = @_;
    my $esc = sub { my $t = shift // ''; $t =~ s/&/&amp;/g; $t =~ s/</&lt;/g; $t =~ s/>/&gt;/g; $t =~ s/"/&quot;/g; $t };
    my $u = dns_name_unicode($name);
    return $esc->($name) if !defined $u || $u eq ($name // '');
    return '<span data-tip="' . $esc->($name) . '">' . $esc->($u) . '</span>';
}
sub cidr_normalize {
    my ($s) = @_;
    return undef unless defined $s && length $s;
    $s =~ s/^\s+//; $s =~ s/\s+$//;
    my ($ip, $len) = split m{/}, $s, 2;
    my ($fam, $max, $packed);
    if    ($packed = eval { inet_pton(AF_INET,  $ip) }) { $fam = AF_INET;  $max = 32;  }
    elsif ($packed = eval { inet_pton(AF_INET6, $ip) }) { $fam = AF_INET6; $max = 128; }
    else { return undef; }
    if (defined $len && length $len) {
        return undef unless $len =~ /^\d+$/ && $len >= 0 && $len <= $max;
        $len += 0;
        return inet_ntop($fam, _mask_packed($packed, $len)) . "/$len";
    }
    return inet_ntop($fam, $packed);
}
sub _norm_ip {
    my ($s) = @_;
    return undef unless defined $s && length $s;
    $s =~ s/^\s+//; $s =~ s/\s+$//;
    for my $fam (AF_INET, AF_INET6) { my $p = eval { inet_pton($fam, $s) }; return inet_ntop($fam, $p) if $p; }
    return undef;
}
sub cidr_contains {
    my ($cidr, $addr) = @_;
    return 0 unless defined $cidr && defined $addr;
    my ($net, $len) = split m{/}, $cidr, 2;
    my ($fam, $max, $pa);
    if    ($pa = eval { inet_pton(AF_INET,  $addr) }) { $fam = AF_INET;  $max = 32;  }
    elsif ($pa = eval { inet_pton(AF_INET6, $addr) }) { $fam = AF_INET6; $max = 128; }
    else { return 0; }
    my $pn = eval { inet_pton($fam, $net) };
    return 0 unless defined $pn;
    $len = $max unless defined $len && length $len;
    return 0 unless $len =~ /^\d+$/ && $len >= 0 && $len <= $max;
    return (_mask_packed($pa, $len) eq _mask_packed($pn, $len)) ? 1 : 0;
}
sub strict_bool {
    my ($v) = @_;
    return (undef, 'missing boolean') unless defined $v;
    my $r = ref $v;
    if ($r) {
        return ($v ? 1 : 0, undef) if $r =~ /Boolean/;
        return (undef, 'not a boolean');
    }
    return ($v + 0, undef) if $v =~ /^[01]$/;
    return (undef, 'not a boolean');
}
my %TSIG_ALGOS = map { $_ => 1 } qw(hmac-md5 hmac-sha1 hmac-sha224 hmac-sha256 hmac-sha384 hmac-sha512);
use constant TSIG_SECRET_MAX => 512;
our %EP_PURPOSE = map { $_ => 1 } qw(dns_listen notify_target axfr_source management health_check anycast_service);
sub tsig_secret_check {
    my ($secret) = @_;
    return (undef, 'secret required') unless defined $secret && length $secret;
    return (undef, 'secret too long') if length $secret > TSIG_SECRET_MAX;
    return (undef, 'secret must be valid base64')
        unless $secret =~ m{^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$}
            && length($secret) % 4 == 0;
    my $raw = decode_base64($secret);
    return (undef, 'secret must be valid base64') unless defined $raw && length $raw;
    return (encode_base64($raw, ''), undef);
}
sub node_caps_check {
    my ($supports_catalog, $supports_coo) = @_;
    return (undef, 'supports_coo requires supports_catalog') if $supports_coo && !$supports_catalog;
    return (1, undef);
}
sub axfr_readiness {
    my ($f) = @_;
    my $mode = $f->{mode} // '';
    my @issues;
    my $need_ip   = ($mode eq 'ip_only');
    my $need_tsig = ($mode eq 'tsig_only');
    my $policy_ready = 1;
    if ($need_tsig && !($f->{tsig_count} || 0)) { push @issues, "$mode requires at least one TSIG key"; $policy_ready = 0; }
    # ip_only needs no separate network list: the ACL is built from the recipients' own addresses
    # (axfr_source), see _catalog_effective_axfr. Previously a CIDR in a bound IP group was required - an
    # entity the UI cannot create - so on a clean install EVERY IP-ACL group was "Incomplete".
    my @nodes = @{ $f->{nodes} || [] };
    my $consumer_ready = $policy_ready;
    if (!@nodes) { push @issues, 'no enabled secondary nodes'; $consumer_ready = 0; }
    if ($need_ip) {
        for my $n (@nodes) {
            next if $n->{has_axfr_source};
            push @issues, "node '$n->{name}' has no axfr_source endpoint"; $consumer_ready = 0;
        }
    }
    return { policy_ready => $policy_ready, consumer_ready => $consumer_ready, issues => \@issues };
}

sub _trim { my $s = shift; return undef unless defined $s; $s =~ s/^\s+//; $s =~ s/\s+$//; return $s; }
sub _norm_port { my ($p) = @_; $p = 53 unless defined $p && length $p; return ($p =~ /^\d+$/ && $p >= 1 && $p <= 65535) ? $p+0 : undef; }
sub _check_len {
    my ($val, $field, $max, $required) = @_;
    my $v = _trim($val);
    return (undef, "$field required") if $required && !(defined $v && length $v);
    return (undef, "$field too long")  if defined $v && length $v > $max;
    return ($v, undef);
}

# ---- TSIG keys. The secret is NEVER returned by list/get. ----
sub tsig_keys_all {
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    my ($rows, $e) = _db_all($dbh,
        "SELECT id, name, algorithm, created_at, updated_at FROM tsig_keys ORDER BY name", { Slice => {} });
    return (undef, $e) if $e;
    $_->{id} += 0 for @$rows;
    return ($rows, undef);
}
# Internal read of key metadata (no secret) for the audit "before".
sub tsig_key_meta {
    my ($id) = @_;
    return (undef, 'not found') unless $id && $id =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    my ($r, $e) = _db_row($dbh, "SELECT id, name, algorithm FROM tsig_keys WHERE id=?", $id); return (undef, $e) if $e;
    return (undef, 'not found') unless $r;
    $r->{id} += 0;
    return ($r, undef);
}
sub tsig_key_create {
    my ($name, $algorithm, $secret) = @_;
    (my $n, my $e) = _check_len($name, 'name', 255, 1); return (undef, $e) if $e;
    $algorithm = lc(_trim($algorithm) // 'hmac-sha256');
    return (undef, 'invalid algorithm') unless $TSIG_ALGOS{$algorithm};
    (my $sec, $e) = tsig_secret_check($secret); return (undef, $e) if $e;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $ex, $e) = _db_exists($dbh, "SELECT 1 FROM tsig_keys WHERE name=?", $n); return (undef, $e) if $e;
    return (undef, "TSIG key '$n' already exists") if $ex;
    (my $ok, my $de) = _do($dbh, "INSERT INTO tsig_keys (name, algorithm, secret) VALUES (?,?,?)", $n, $algorithm, $sec);
    return (undef, $de) if $de;
    return ($dbh->last_insert_id(undef,undef,undef,undef), undef);
}
# Who holds a key. References on both sides - our bindings and the key name in PowerDNS metadata:
#   group / server          - secondary_*_tsig_keys: who we give zones to;
#   dynamic updates         - dyn_profile_keys / zone_dynamic_keys: whose RFC 2136 updates we accept;
#   TSIG-ALLOW-AXFR         - the same name in PowerDNS: who may pull the zone from us;
#   AXFR-MASTER-TSIG        - what WE sign with when pulling from a foreign master;
#   TSIG-ALLOW-DNSUPDATE    - whose updates the zone accepts.
# Fail-closed: if we could not look, assume a reference exists. A spare key harms nobody; deleting a
# working one silently breaks AXFR. ($key, \@refs, undef) | (undef, undef, err).
sub _tsig_key_refs {
    my ($id) = @_;
    return (undef, undef, 'id required') unless $id && $id =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, undef, 'DB unavailable');
    (my $k, my $e) = _db_row($dbh, "SELECT id, name FROM tsig_keys WHERE id=?", $id); return (undef, undef, $e) if $e;
    return (undef, undef, 'not found') unless $k;
    my @refs;
    (my $ug, $e) = _db_count($dbh, "SELECT COUNT(*) FROM secondary_group_tsig_keys WHERE tsig_key_id=?", $id); return (undef, undef, $e) if $e;
    push @refs, "$ug group(s)" if $ug;
    (my $un, $e) = _db_count($dbh, "SELECT COUNT(*) FROM secondary_node_tsig_keys WHERE tsig_key_id=?", $id); return (undef, undef, $e) if $e;
    push @refs, "$un server(s)" if $un;
    (my $ud, $e) = _db_count($dbh, "SELECT (SELECT COUNT(*) FROM dyn_profile_keys WHERE tsig_key_id=?)
                                          + (SELECT COUNT(*) FROM zone_dynamic_keys WHERE tsig_key_id=?)", $id, $id);
    return (undef, undef, $e) if $e;
    push @refs, 'dynamic updates' if $ud;
    my $pdns = connectPDNS() or return (undef, undef, 'DB unavailable');
    (my $nz, $e) = _db_count($pdns,
        "SELECT COUNT(*) FROM domainmetadata WHERE kind IN ('TSIG-ALLOW-AXFR','AXFR-MASTER-TSIG','TSIG-ALLOW-DNSUPDATE')
            AND LOWER(TRIM(TRAILING '.' FROM content)) = ?", lc($k->{name}));
    return (undef, undef, $e) if $e;
    push @refs, "$nz zone(s)" if $nz;
    return ($k, \@refs, undef);
}
# Delete both copies, PowerDNS first (where the key works); if that fails our copy stays, otherwise the
# signature would live on while the panel forgot its secret.
sub _tsig_key_drop {
    my ($k) = @_;
    (my $pk, my $pe) = _pdns_delete_tsigkey($k->{name}); return (undef, $pe) if $pe;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $ok, my $de) = _do($dbh, "DELETE FROM tsig_keys WHERE id=?", $k->{id}); return (undef, $de) if $de;
    return (1, undef);
}
sub _pdns_delete_tsigkey {
    my ($name) = @_;
    my $srv = _cfg('pdns_api', 'server', 'localhost');
    (my $tl, my $tc, my $tge) = _pdns_api('GET', "/api/v1/servers/$srv/tsigkeys"); return (undef, $tge) if $tge;
    return (undef, "PowerDNS tsigkeys GET → HTTP $tc") unless $tc == 200;
    return (undef, 'PowerDNS tsigkeys GET returned a non-list response') unless ref $tl eq 'ARRAY';
    (my $want = lc($name)) =~ s/\.$//;
    for my $k (@$tl) {
        next unless ref $k eq 'HASH';
        (my $n = lc($k->{name} // '')) =~ s/\.$//;
        next unless $n eq $want;
        (my $r, my $dc, my $de) = _pdns_api('DELETE', "/api/v1/servers/$srv/tsigkeys/" . ($k->{id} // $k->{name}));
        return (undef, $de) if $de;
        return (undef, "PowerDNS tsigkey delete '$name' → HTTP $dc") unless $dc == 204 || $dc == 200;
    }
    return (1, undef);   # not in PowerDNS - nothing to delete
}
# Same by NAME: removed upstream zone metadata only knows the name. Keys created on the server by hand
# are not in our table - nothing to look for, and that is not an error.
sub tsig_key_forget_unused_by_name {
    my ($name) = @_;
    my $n = _trim($name);
    return ([], undef) unless defined $n && length $n;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    my ($r, $e) = _db_row($dbh, "SELECT id FROM tsig_keys WHERE name=?", $n); return (undef, $e) if $e;
    return ([], undef) unless $r;
    return tsig_keys_forget_unused($r->{id});
}
# Cleanup after a binding is removed. It walks ALL keys, not just the removed one: there is no key screen
# and no other occasion to come here, so a cleanup that failed last time (PowerDNS down) must happen with
# the next removal. Keys not in our table (created on the server by hand) are never touched.
# (\@removed, $err): removed keys are always returned; an error means "some keys remain".
sub tsig_keys_forget_unused {
    my (@only) = grep { defined && /^\d+$/ } @_;   # no list -> all keys; the list is for the check
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    my $where = @only ? ' WHERE id IN (' . join(',', ('?') x @only) . ')' : '';
    my ($rows, $e) = _db_all($dbh, "SELECT id FROM tsig_keys$where ORDER BY id", { Slice => {} }, @only);
    return (undef, $e) if $e;
    my (@gone, $err);
    for my $r (@$rows) {
        (my $k, my $refs, my $re) = _tsig_key_refs($r->{id});
        if ($re) { $err ||= $re unless $re eq 'not found'; next; }
        next if @$refs;
        (my $ok, my $de) = _tsig_key_drop($k);
        if ($de) { $err ||= $de; next; }
        push @gone, { id => $k->{id} + 0, name => $k->{name} };
    }
    return (\@gone, $err);
}

# ---- IP groups + members ----
sub ip_groups_all {
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    my ($rows, $e) = _db_all($dbh,
        "SELECT g.id, g.name, g.description, COUNT(m.id) AS member_count
           FROM ip_groups g LEFT JOIN ip_group_members m ON m.ip_group_id=g.id
          GROUP BY g.id ORDER BY g.name", { Slice => {} });
    return (undef, $e) if $e;
    for (@$rows) { $_->{id} += 0; $_->{member_count} += 0; }
    return ($rows, undef);
}
sub ip_group_get {
    my ($id) = @_;
    return (undef, 'not found') unless $id && $id =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $g, my $e) = _db_row($dbh, "SELECT id, name, description FROM ip_groups WHERE id=?", $id); return (undef, $e) if $e;
    return (undef, 'not found') unless $g;
    $g->{id} += 0;
    (my $mem, $e) = _db_all($dbh, "SELECT id, cidr FROM ip_group_members WHERE ip_group_id=? ORDER BY cidr", { Slice => {} }, $id); return (undef, $e) if $e;
    $_->{id} += 0 for @$mem;
    $g->{members} = $mem;
    return ($g, undef);
}
sub ip_group_create {
    my ($name, $desc) = @_;
    (my $n, my $e) = _check_len($name, 'name', 64, 1); return (undef, $e) if $e;
    (my $d, $e)    = _check_len($desc, 'description', 255, 0); return (undef, $e) if $e;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $ex, $e) = _db_exists($dbh, "SELECT 1 FROM ip_groups WHERE name=?", $n); return (undef, $e) if $e;
    return (undef, "IP group '$n' already exists") if $ex;
    (my $ok, my $de) = _do($dbh, "INSERT INTO ip_groups (name, description) VALUES (?,?)", $n, $d); return (undef, $de) if $de;
    return ($dbh->last_insert_id(undef,undef,undef,undef), undef);
}
sub ip_group_update {
    my ($id, $f) = @_;
    return (undef, 'id required') unless $id && $id =~ /^\d+$/;
    $f ||= {};
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $ex, my $e) = _db_exists($dbh, "SELECT 1 FROM ip_groups WHERE id=?", $id); return (undef, $e) if $e;
    return (undef, 'not found') unless $ex;
    my (@set, @val);
    if (exists $f->{name}) {
        (my $n, $e) = _check_len($f->{name}, 'name', 64, 1); return (undef, $e) if $e;
        (my $dup, $e) = _db_exists($dbh, "SELECT 1 FROM ip_groups WHERE name=? AND id<>?", $n, $id); return (undef, $e) if $e;
        return (undef, "IP group '$n' already exists") if $dup;
        push @set, 'name=?'; push @val, $n;
    }
    if (exists $f->{description}) {
        (my $d, $e) = _check_len($f->{description}, 'description', 255, 0); return (undef, $e) if $e;
        push @set, 'description=?'; push @val, $d;
    }
    return (1, undef) unless @set;
    (my $ok, my $de) = _do($dbh, "UPDATE ip_groups SET ".join(',',@set)." WHERE id=?", @val, $id); return (undef, $de) if $de;
    return (1, undef);
}
sub ip_group_delete {
    my ($id) = @_;
    return (undef, 'id required') unless $id && $id =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $ex, my $e) = _db_exists($dbh, "SELECT 1 FROM ip_groups WHERE id=?", $id); return (undef, $e) if $e;
    return (undef, 'not found') unless $ex;
    (my $ug, $e) = _db_count($dbh, "SELECT COUNT(*) FROM secondary_group_ip_groups WHERE ip_group_id=?", $id); return (undef, $e) if $e;
    return (undef, "IP group in use by $ug group(s)") if $ug;
    (my $ok, my $de) = _do($dbh, "DELETE FROM ip_groups WHERE id=?", $id); return (undef, $de) if $de;
    return (1, undef);
}
sub ip_group_member_add {
    my ($group_id, $cidr) = @_;
    return (undef, 'ip_group_id required') unless $group_id && $group_id =~ /^\d+$/;
    my $c = cidr_normalize($cidr);
    return (undef, 'invalid IP/CIDR') unless defined $c;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $ex, my $e) = _db_exists($dbh, "SELECT 1 FROM ip_groups WHERE id=?", $group_id); return (undef, $e) if $e;
    return (undef, 'not found') unless $ex;
    (my $dup, $e) = _db_exists($dbh, "SELECT 1 FROM ip_group_members WHERE ip_group_id=? AND cidr=?", $group_id, $c); return (undef, $e) if $e;
    return (undef, "'$c' already in group") if $dup;
    (my $ok, my $de) = _do($dbh, "INSERT INTO ip_group_members (ip_group_id, cidr) VALUES (?,?)", $group_id, $c); return (undef, $de) if $de;
    return ($dbh->last_insert_id(undef,undef,undef,undef), undef, $c);   # 3rd element = canonical (for audit)
}
# Delete STRICTLY by the (group,member) pair: a foreign member -> not found.
sub ip_group_member_delete {
    my ($group_id, $member_id) = @_;
    return (undef, 'ids required') unless $group_id && $group_id =~ /^\d+$/ && $member_id && $member_id =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $ex, my $e) = _db_exists($dbh, "SELECT 1 FROM ip_group_members WHERE id=? AND ip_group_id=?", $member_id, $group_id); return (undef, $e) if $e;
    return (undef, 'not found') unless $ex;
    (my $ok, my $de) = _do($dbh, "DELETE FROM ip_group_members WHERE id=? AND ip_group_id=?", $member_id, $group_id); return (undef, $de) if $de;
    return (1, undef);
}

# ---- Addresses of our PowerDNS: ONE global list per installation ----
# There used to be a "named address set" object (primary_sets, RETIRED-OK) chosen per catalog and per
# server, with the panel creating sets itself ("catalog-35"): three entities instead of one fact. There
# are exactly two facts:
#   the panel has ONE producer -> one address set consumers pull the catalog from (this list);
#   whether we give a group the zones themselves -> secondary_groups.zone_axfr (all subscribers get the catalog).
# A list, not one field: an HA pair has two addresses.
# Our PowerDNS addresses are DERIVED, not asked. A hand-typed list in Settings lied by construction: twenty
# addresses of one host became twenty "sources" in every secondary's config. PowerDNS itself is asked:
# its local-address/local-port are where AXFR can be reached. Only 127.0.0.0/8 and ::1 are dropped; lo
# addresses are kept (anycast is a /32 on loopback). With a wildcard (0.0.0.0 / ::) the node's own
# addresses are used, minus the loopback network. The last good answer is cached in settings: PowerDNS may
# be down exactly when the operator opens the secondary config, and empty is worse than "as it was".
# (\@[{address, port}], undef) | (undef, err).
sub pdns_listen_endpoints {
    my $srv = _cfg('pdns_api', 'server', 'localhost');
    (my $cfg, my $code, my $err) = _pdns_api('GET', "/api/v1/servers/$srv/config");
    if ($err || $code != 200 || ref $cfg ne 'ARRAY') {
        # PowerDNS did not answer - state unknown. Return the last known list: an empty secondary config
        # while the server is down is worse than "as it was".
        (my $seen, my $se) = _setting_json('pdns_endpoints_seen');
        return ($seen, undef) if !$se && ref $seen eq 'ARRAY' && @$seen;
        return ([], undef);
    }
    my %v = map { ($_->{name} // '') => ($_->{value} // '') } @$cfg;
    return (_pdns_listen_parse(\%v, [ node_addresses() ]), undef);
}
# Parse the PowerDNS answer into addresses. PURE: config and node addresses are arguments, so parsing is
# tested, not "on the live server as it happens to be".
#   no local-address             -> PowerDNS listens on EVERYTHING (its default) -> node addresses minus 127.0.0.0/8;
#   0.0.0.0 or ::                -> the same;
#   addresses listed             -> those, minus loopback. lo addresses are NOT excluded: an anycast /32
#                                  lives there and stays because PowerDNS named it;
#   ONLY loopback left           -> EMPTY. True: nobody can reach such a PowerDNS from outside. Node
#                                  addresses must not be substituted - it does not listen on them.
sub _pdns_listen_parse {
    my ($v, $host) = @_;
    $v ||= {}; $host ||= [];
    my $port = (defined $v->{'local-port'} && $v->{'local-port'} =~ /^(\d+)$/) ? $1 + 0 : 53;
    my $raw  = $v->{'local-address'};
    my @addr;
    for my $a (split /\s*,\s*/, (defined $raw ? $raw : '')) {
        $a =~ s/^\s+|\s+$//g;
        next unless length $a;
        $a =~ s/:\d+$// if $a =~ /^\d+\.\d+\.\d+\.\d+:\d+$/;   # PowerDNS allows address:port
        push @addr, $a;
    }
    my $wildcard = (!defined $raw || !@addr || grep { $_ eq '0.0.0.0' || $_ eq '::' } @addr) ? 1 : 0;
    @addr = $wildcard ? @$host : @addr;
    @addr = grep { !/^127\./ && $_ ne '::1' && $_ ne '0.0.0.0' && $_ ne '::' } @addr;
    my (%seen, @uniq);
    for my $a (@addr) { push @uniq, $a unless $seen{$a}++; }
    return [ map { { address => $_, port => $port } } @uniq ];
}
# A settings value as JSON (\@|\%|undef, err).
sub _setting_json {
    my ($key) = @_;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $r, my $e) = _db_row($dbh, "SELECT `value` FROM settings WHERE `key`=?", $key); return (undef, $e) if $e;
    return (undef, undef) unless $r && defined $r->{value} && length $r->{value};
    my $d = eval { decode_json($r->{value}) };
    return (undef, undef) if $@ || !defined $d;
    return ($d, undef);
}
sub pdns_endpoints {
    (my $eps, my $e) = pdns_listen_endpoints(); return (undef, $e) if $e;
    # the "last known" cache is updated only on a successful read
    if (@{ $eps || [] }) {
        my $dbh = connectDB();
        $dbh->do("INSERT INTO settings (`key`,`value`) VALUES ('pdns_endpoints_seen',?)
                  ON DUPLICATE KEY UPDATE `value`=VALUES(`value`)", undef, encode_json($eps)) if $dbh;
    }
    my $i = 0;
    return ([ map { { id => ++$i, address => $_->{address}, port => $_->{port} + 0, priority => 0, enabled => 1 } } @$eps ], undef);
}
# Addresses of OUR PowerDNS that the secondaries of this Distribution get ("where to pull from").
# The operator's choice beats derivation: with local-address=0.0.0.0 (recommended at install, otherwise a
# later HA address is not served) PowerDNS reports ALL node addresses, and only the operator knows which
# one the recipient can reach (a tunnel address for a server behind a tunnel, a local one on the LAN).
# Until a choice is made, derivation from local-address applies.
sub catalog_primary_endpoints {
    my ($dbh, $cid) = @_;
    return (undef, 'invalid catalog') unless $cid && "$cid" =~ /^\d+$/;
    (my $rows, my $e) = _db_all($dbh,
        "SELECT address, port FROM catalog_primary_endpoints
          WHERE catalog_id=? AND secondary_group_id IS NULL ORDER BY address, port",
        { Slice => {} }, $cid);
    return (undef, $e) if $e;
    return ([ map { { address => $_->{address}, port => $_->{port} + 0 } } @$rows ], undef);
}
# Replace the Distribution's address set wholesale; an empty list = back to deriving from local-address.
# An address need NOT be on the node now: VIP and anycast come up later, a tunnel may be down.
sub catalog_primary_endpoints_set {
    my ($cid, $list) = @_;
    return (undef, 'invalid catalog') unless $cid && "$cid" =~ /^\d+$/;
    return (undef, 'list must be an array') unless ref $list eq 'ARRAY';
    my @want;
    for my $x (@$list) {
        my $a = ref $x eq 'HASH' ? $x->{address} : $x;
        my $p = ref $x eq 'HASH' ? $x->{port} : undef;
        $a = defined $a ? "$a" : ''; $a =~ s/^\s+|\s+$//g;
        return (undef, "invalid address '$a'") unless is_ip_addr($a);
        $p = 53 unless defined $p && "$p" ne '';
        return (undef, "invalid port '$p'") unless "$p" =~ /^\d+$/ && $p >= 1 && $p <= 65535;
        push @want, { address => $a, port => $p + 0 };
    }
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $ax, my $ae) = _db_exists($dbh, "SELECT 1 FROM catalogs WHERE id=?", $cid); return (undef, $ae) if $ae;
    return (undef, 'not found') unless $ax;
    return _txn_wrap($dbh, sub {
        (my $d, my $de) = _do($dbh, "DELETE FROM catalog_primary_endpoints WHERE catalog_id=? AND secondary_group_id IS NULL", $cid);
        return (undef, $de) if $de;
        for my $w (@want) {
            (my $i, my $ie) = _do($dbh, "INSERT INTO catalog_primary_endpoints (catalog_id, secondary_group_id, address, port) VALUES (?,NULL,?,?)",
                                  $cid, $w->{address}, $w->{port});
            return (undef, $ie) if $ie;
        }
        return (\@want, undef);
    });
}
sub _pdns_endpoints {
    my ($dbh, $cid) = @_;
    (my $eps, my $e) = pdns_listen_endpoints(); return (undef, $e) if $e;
    if (defined $cid) {
        (my $chosen, my $ce) = catalog_primary_endpoints($dbh, $cid); return (undef, $ce) if $ce;
        return ($chosen, undef) if @$chosen;
        # In an HA pair secondaries pull from the pair, not from this node: its own address becomes the
        # STANDBY's after a switchover.
        if (my $svc = ha_service_address()) {
            return ([ { address => $svc, port => (@$eps ? $eps->[0]{port} + 0 : 53) } ], undef);
        }
    }
    return ([ map { { address => $_->{address}, port => $_->{port} + 0 } } @$eps ], undef);
}
# Endpoint field validation (shared by primary_set/node endpoints). $create: whether address is required.
sub _ep_fields {
    my ($f, $create, $allow_purpose, $allow_priority) = @_;
    my %out;
    if (exists $f->{address} || $create) {
        my $a = _norm_ip($f->{address}); return (undef, 'invalid address') unless defined $a;
        $out{address} = $a;
    }
    if (exists $f->{port} || $create) {
        my $p = _norm_port($f->{port}); return (undef, 'invalid port') unless defined $p;
        $out{port} = $p;
    }
    if ($allow_purpose && (exists $f->{purpose} || $create)) {
        my $pu = _trim($f->{purpose}) // '';
        return (undef, 'invalid purpose') unless $EP_PURPOSE{$pu};
        $out{purpose} = $pu;
    }
    if ($allow_priority && exists $f->{priority}) {
        return (undef, 'invalid priority') unless defined $f->{priority} && $f->{priority} =~ /^-?\d+$/;
        $out{priority} = $f->{priority}+0;
    }
    if (exists $f->{enabled}) {
        (my $b, my $e) = strict_bool($f->{enabled}); return (undef, "enabled: $e") if $e;
        $out{enabled} = $b;
    }
    return (\%out, undef);
}
# ---- Secondary groups + bindings ----
my %AXFR_MODES = map { $_ => 1 } qw(ip_only tsig_only);
sub secondary_group_axfr_status {
    my ($dbh, $gid, $mode) = @_;
    # Active keys, not all bound ones: AXFR can only be signed with the one _node_effective_auth picks
    # (is_primary=1). COUNT(*) showed "Ready" on a group with no active key that could not serve a single zone.
    (my $ntsig, my $e) = _db_count($dbh, "SELECT COUNT(*) FROM secondary_group_tsig_keys WHERE secondary_group_id=? AND is_primary=1", $gid); return (undef, $e) if $e;
    (my $nodes, $e) = _db_all($dbh,
        "SELECT n.id, n.name FROM secondary_group_members gm
           JOIN secondary_nodes n ON n.id=gm.secondary_node_id
          WHERE gm.secondary_group_id=? AND n.enabled=1 ORDER BY n.name", { Slice => {} }, $gid); return (undef, $e) if $e;
    # axfr_source of all group nodes in ONE query (was N+1 per server).
    my %has_src;
    if (@$nodes) {
        my $ph = join(',', ('?') x @$nodes);
        (my $srows, $e) = _db_all($dbh,
            "SELECT DISTINCT secondary_node_id FROM secondary_node_endpoints
              WHERE purpose='axfr_source' AND enabled=1 AND secondary_node_id IN ($ph)",
            { Slice => {} }, map { $_->{id} } @$nodes); return (undef, $e) if $e;
        $has_src{ $_->{secondary_node_id} + 0 } = 1 for @$srows;
    }
    my @nodefacts = map { { name => $_->{name}, has_axfr_source => ($has_src{ $_->{id} + 0 } ? 1 : 0) } } @$nodes;
    my $r = axfr_readiness({ mode => $mode, tsig_count => $ntsig, nodes => \@nodefacts });
    return ({ mode => $mode, tsig_count => $ntsig,
              policy_ready => $r->{policy_ready}, consumer_ready => $r->{consumer_ready},
              issues => $r->{issues}, nodes => \@nodefacts }, undef);
}
# The networks of a group, replaced as a whole: IPs or CIDRs, IPv4/IPv6; a bare address becomes /32 or /128.
# -> ([canonical list], undef) | (undef, error)
sub secondary_group_prefixes_set {
    my ($gid, $list) = @_;
    return (undef, 'id required') unless $gid && $gid =~ /^\d+$/;
    return (undef, 'prefixes must be a list') unless ref $list eq 'ARRAY';
    my (%seen, @want);
    for my $p (@$list) {
        next unless defined $p && $p =~ /\S/;
        my $c = cidr_normalize($p) // return (undef, "not an IP address or network: '$p'");
        $c .= ($c =~ /:/ ? '/128' : '/32') unless $c =~ m{/};
        push @want, $c unless $seen{$c}++;
    }
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $ex, my $e) = _db_exists($dbh, "SELECT 1 FROM secondary_groups WHERE id=?", $gid); return (undef, $e) if $e;
    return (undef, 'not found') unless $ex;
    (my $bo, my $be) = _txn_begin($dbh); return (undef, $be) if $be;
    my $ok = eval {
        $dbh->do("DELETE FROM secondary_group_prefixes WHERE secondary_group_id=?", undef, $gid); die "db\n" if $dbh->err;
        for my $c (@want) { $dbh->do("INSERT INTO secondary_group_prefixes (secondary_group_id, cidr) VALUES (?,?)", undef, $gid, $c); die "db\n" if $dbh->err; }
        $dbh->commit; 1;
    };
    unless ($ok) { my $code = $dbh->err; eval { $dbh->rollback }; return (undef, _db_err_kind($code)); }
    return ([ sort @want ], undef);
}
# Networks that may transfer a zone besides its servers: the prefixes of IP ACL groups that receive it — with
# direct AXFR every group with AXFR allowed, with a catalog the catalog's groups with AXFR allowed. A TSIG
# group adds none: PowerDNS ORs ALLOW-AXFR-FROM with TSIG-ALLOW-AXFR, so a network would allow unsigned
# transfers. -> ([cidr...], undef) | (undef, error)
sub _zone_group_prefixes {
    my ($dbh, $direct, $cat_id) = @_;
    my @q;
    push @q, [ "SELECT p.cidr FROM secondary_group_prefixes p JOIN secondary_groups g ON g.id=p.secondary_group_id
                 WHERE g.zone_axfr=1 AND g.axfr_auth_mode='ip_only'" ] if $direct;
    push @q, [ "SELECT p.cidr FROM secondary_group_prefixes p JOIN secondary_groups g ON g.id=p.secondary_group_id
                  JOIN catalog_groups cg ON cg.secondary_group_id=g.id
                 WHERE cg.catalog_id=? AND g.zone_axfr=1 AND g.axfr_auth_mode='ip_only'", $cat_id ] if $cat_id;
    my %c;
    for my $x (@q) {
        my ($sql, @b) = @$x;
        (my $rows, my $e) = _db_all($dbh, $sql, {}, @b); return (undef, $e) if $e;
        $c{ $_->[0] } = 1 for @$rows;
    }
    return ([ sort keys %c ], undef);
}
sub secondary_groups_all {
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    my ($rows, $e) = _db_all($dbh,
        "SELECT g.id, g.name, g.description, g.axfr_auth_mode, g.send_notify, g.zone_axfr,
                (SELECT COUNT(*) FROM secondary_group_members m WHERE m.secondary_group_id=g.id) AS node_count,
                (SELECT COUNT(*) FROM secondary_group_ip_groups i WHERE i.secondary_group_id=g.id) AS ip_group_count,
                (SELECT COUNT(*) FROM secondary_group_tsig_keys t WHERE t.secondary_group_id=g.id) AS tsig_count
           FROM secondary_groups g ORDER BY g.name", { Slice => {} });
    return (undef, $e) if $e;
    for (@$rows) { $_->{id}+=0; $_->{node_count}+=0; $_->{ip_group_count}+=0; $_->{tsig_count}+=0; $_->{send_notify}+=0; $_->{zone_axfr}+=0; }
    return ($rows, undef);
}
sub secondary_group_get {
    my ($id) = @_;
    return (undef, 'not found') unless $id && $id =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $g, my $e) = _db_row($dbh, "SELECT id, name, description, axfr_auth_mode, send_notify, zone_axfr FROM secondary_groups WHERE id=?", $id); return (undef, $e) if $e;
    return (undef, 'not found') unless $g;
    $g->{id} += 0; $g->{send_notify} += 0; $g->{zone_axfr} += 0;
    (my $nodes, $e) = _db_all($dbh, "SELECT n.id, n.name FROM secondary_group_members m JOIN secondary_nodes n ON n.id=m.secondary_node_id WHERE m.secondary_group_id=? ORDER BY n.name", { Slice => {} }, $id); return (undef, $e) if $e;
    (my $ipg, $e)   = _db_all($dbh, "SELECT g.id, g.name FROM secondary_group_ip_groups b JOIN ip_groups g ON g.id=b.ip_group_id WHERE b.secondary_group_id=? ORDER BY g.name", { Slice => {} }, $id); return (undef, $e) if $e;
    (my $tsig, $e)  = _db_all($dbh, "SELECT k.id, k.name, k.algorithm, b.is_primary FROM secondary_group_tsig_keys b JOIN tsig_keys k ON k.id=b.tsig_key_id WHERE b.secondary_group_id=? ORDER BY k.id", { Slice => {} }, $id); return (undef, $e) if $e;
    $_->{id}+=0 for (@$nodes, @$ipg, @$tsig);
    $g->{nodes} = $nodes; $g->{ip_groups} = $ipg; $g->{tsig_keys} = $tsig;
    (my $pfx, $e) = _db_all($dbh, "SELECT cidr FROM secondary_group_prefixes WHERE secondary_group_id=? ORDER BY cidr", {}, $id); return (undef, $e) if $e;
    $g->{prefixes} = [ map { $_->[0] } @$pfx ];
    (my $status, $e) = secondary_group_axfr_status($dbh, $id, $g->{axfr_auth_mode}); return (undef, $e) if $e;
    $g->{axfr_status} = $status;
    return ($g, undef);
}
# zone_axfr: DO WE GIVE THIS GROUP THE ZONES THEMSELVES? Every subscriber gets the catalog (just a list
# of names), member zones only the groups we serve. Where a zone_axfr=0 group pulls from is its own
# routing and BIND config, not the panel's business. Default 1 = the previous behaviour.
sub secondary_group_create {
    my ($name, $desc, $mode, $send_notify, $zone_axfr) = @_;
    (my $n, my $e) = _check_len($name, 'name', 64, 1); return (undef, $e) if $e;
    (my $d, $e)    = _check_len($desc, 'description', 255, 0); return (undef, $e) if $e;
    $mode = _trim($mode) || 'tsig_only';
    return (undef, 'invalid axfr_auth_mode') unless $AXFR_MODES{$mode};
    my $sn = 1;   # the group gets NOTIFY by default (previous behaviour)
    if (defined $send_notify) { (my $b, my $be) = strict_bool($send_notify); return (undef, "send_notify: $be") if $be; $sn = $b; }
    my $za = 1;
    if (defined $zone_axfr) { (my $b, my $be) = strict_bool($zone_axfr); return (undef, "zone_axfr: $be") if $be; $za = $b; }
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $ex, $e) = _db_exists($dbh, "SELECT 1 FROM secondary_groups WHERE name=?", $n); return (undef, $e) if $e;
    return (undef, "secondary group '$n' already exists") if $ex;
    (my $ok, my $de) = _do($dbh, "INSERT INTO secondary_groups (name, description, axfr_auth_mode, send_notify, zone_axfr) VALUES (?,?,?,?,?)", $n, $d, $mode, $sn, $za); return (undef, $de) if $de;
    return ($dbh->last_insert_id(undef,undef,undef,undef), undef);
}
sub secondary_group_update {
    my ($id, $f) = @_;
    return (undef, 'id required') unless $id && $id =~ /^\d+$/;
    $f ||= {};
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $ex, my $e) = _db_exists($dbh, "SELECT 1 FROM secondary_groups WHERE id=?", $id); return (undef, $e) if $e;
    return (undef, 'not found') unless $ex;
    my (@set, @val);
    if (exists $f->{name}) {
        (my $n, $e) = _check_len($f->{name}, 'name', 64, 1); return (undef, $e) if $e;
        (my $dup, $e) = _db_exists($dbh, "SELECT 1 FROM secondary_groups WHERE name=? AND id<>?", $n, $id); return (undef, $e) if $e;
        return (undef, "secondary group '$n' already exists") if $dup;
        push @set, 'name=?'; push @val, $n;
    }
    if (exists $f->{description}) {
        (my $d, $e) = _check_len($f->{description}, 'description', 255, 0); return (undef, $e) if $e;
        push @set, 'description=?'; push @val, $d;
    }
    if (exists $f->{axfr_auth_mode}) {
        my $m = _trim($f->{axfr_auth_mode}) // '';
        return (undef, 'invalid axfr_auth_mode') unless $AXFR_MODES{$m};
        push @set, 'axfr_auth_mode=?'; push @val, $m;
    }
    if (exists $f->{send_notify}) {
        (my $b, my $be) = strict_bool($f->{send_notify}); return (undef, "send_notify: $be") if $be;
        push @set, 'send_notify=?'; push @val, $b;
    }
    if (exists $f->{zone_axfr}) {
        (my $b, my $be) = strict_bool($f->{zone_axfr}); return (undef, "zone_axfr: $be") if $be;
        push @set, 'zone_axfr=?'; push @val, $b;
    }
    return (1, undef) unless @set;
    (my $ok, my $de) = _do($dbh, "UPDATE secondary_groups SET ".join(',',@set)." WHERE id=?", @val, $id); return (undef, $de) if $de;
    return (1, undef);
}
sub secondary_group_delete {
    my ($id) = @_;
    return (undef, 'id required') unless $id && $id =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $ex, my $e) = _db_exists($dbh, "SELECT 1 FROM secondary_groups WHERE id=?", $id); return (undef, $e) if $e;
    return (undef, 'not found') unless $ex;
    # AXFR/TSIG policy bindings belong to distribution.manage and must not be cascaded away by a group delete
    # (secondary.manage). FK RESTRICT on the group side is the hard guarantee; this gives a clean message.
    (my $nb, $e) = _db_count($dbh,
        "SELECT (SELECT COUNT(*) FROM secondary_group_ip_groups WHERE secondary_group_id=?)
              + (SELECT COUNT(*) FROM secondary_group_tsig_keys WHERE secondary_group_id=?)", $id, $id);
    return (undef, $e) if $e;
    return (undef, "secondary group in use by $nb AXFR/TSIG policy binding(s) — remove them first (distribution.manage)") if $nb;
    # default group invariant: nodes that had this group as default get another of their groups (or none) BEFORE the delete
    (my $dnodes, my $dne) = _db_all($dbh, "SELECT id FROM secondary_nodes WHERE default_group_id=?", { Slice => {} }, $id); return (undef, $dne) if $dne;
    for my $nrow (@$dnodes) {
        (my $nextg) = _db_row($dbh, "SELECT secondary_group_id FROM secondary_group_members WHERE secondary_node_id=? AND secondary_group_id<>? ORDER BY secondary_group_id LIMIT 1", $nrow->{id}, $id);
        (my $u, my $ue) = _do($dbh, "UPDATE secondary_nodes SET default_group_id=? WHERE id=?", ($nextg ? $nextg->{secondary_group_id} : undef), $nrow->{id}); return (undef, $ue) if $ue;
    }
    (my $ok, my $de) = _do($dbh, "DELETE FROM secondary_groups WHERE id=?", $id); return (undef, $de) if $de;
    return (1, undef);
}
# AUTOMATIC ACL INVARIANT: each node's /32 is present in the ip_groups of the groups it belongs to and
# disappears when no node of the group uses it. It used to live ONLY in secondary_server_save, so the same
# logical action via different APIs gave different results. Kept in the core, not in one screen.
# (1, undef) | (undef, err).
sub _acl_sync_node {
    my ($dbh, $nid) = @_;
    return (1, undef) unless $nid && "$nid" =~ /^\d+$/;
    # node addresses (axfr_source) -> candidate /32s
    (my $eps, my $ee) = _db_all($dbh, "SELECT address FROM secondary_node_endpoints WHERE secondary_node_id=? AND purpose='axfr_source'", { Slice => {} }, $nid);
    return (undef, $ee) if $ee;
    my @ips = map { $_->{address} } @$eps;
    # ip_groups of the groups the node is in NOW -> the /32 must be there
    (my $grows, my $ge) = _db_all($dbh, "SELECT secondary_group_id AS gid FROM secondary_group_members WHERE secondary_node_id=?", { Slice => {} }, $nid);
    return (undef, $ge) if $ge;
    (my $need, my $ne) = _groups_ipgroups($dbh, map { $_->{gid} } @$grows);
    return (undef, $ne) if $ne;
    for my $igid (sort { $a <=> $b } keys %$need) {
        for my $ip (@ips) {
            my $cidr = _server_acl_cidr($ip); next if $cidr eq '';
            (my $have, my $he) = _db_exists($dbh, "SELECT 1 FROM ip_group_members WHERE ip_group_id=? AND cidr=?", $igid, $cidr); return (undef, $he) if $he;
            next if $have;
            (my $ok, my $ie) = _do($dbh, "INSERT INTO ip_group_members (ip_group_id, cidr) VALUES (?,?)", $igid, $cidr); return (undef, $ie) if $ie;
        }
    }
    # and clean up /32s where the node no longer belongs (leaving others' and operator CIDRs alone)
    (my $allg, my $ae) = _db_all($dbh, "SELECT id FROM secondary_groups", { Slice => {} }); return (undef, $ae) if $ae;
    (my $all_ig, my $aie) = _groups_ipgroups($dbh, map { $_->{id} } @$allg); return (undef, $aie) if $aie;
    my %stale = map { $_ => 1 } grep { !$need->{$_} } keys %$all_ig;
    my $ce = _acl_cleanup($dbh, \%stale, \@ips);
    return (undef, $ce) if $ce;
    return (1, undef);
}
sub secondary_group_member_add {
    my ($gid, $nid) = @_;
    return (undef, 'ids required') unless $gid && $gid =~ /^\d+$/ && $nid && $nid =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $g, my $e) = _db_exists($dbh, "SELECT 1 FROM secondary_groups WHERE id=?", $gid); return (undef, $e) if $e;
    return (undef, 'unknown secondary group') unless $g;
    (my $n, $e) = _db_exists($dbh, "SELECT 1 FROM secondary_nodes WHERE id=?", $nid); return (undef, $e) if $e;
    return (undef, 'unknown secondary node') unless $n;
    (my $dup, $e) = _db_exists($dbh, "SELECT 1 FROM secondary_group_members WHERE secondary_group_id=? AND secondary_node_id=?", $gid, $nid); return (undef, $e) if $e;
    return (1, undef) if $dup;
    (my $ok, my $de) = _do($dbh, "INSERT INTO secondary_group_members (secondary_group_id, secondary_node_id) VALUES (?,?)", $gid, $nid); return (undef, $de) if $de;
    (my $as, my $ase) = _acl_sync_node($dbh, $nid); return (undef, $ase) if $ase;   # ACL invariant, in the core
    return (1, undef);
}
sub secondary_group_member_remove {
    my ($gid, $nid) = @_;
    return (undef, 'ids required') unless $gid && $gid =~ /^\d+$/ && $nid && $nid =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $ok, my $de) = _do($dbh, "DELETE FROM secondary_group_members WHERE secondary_group_id=? AND secondary_node_id=?", $gid, $nid); return (undef, $de) if $de;
    # default group invariant: if the removed group was the default -> reassign to the first remaining one (or clear)
    (my $cur) = _db_row($dbh, "SELECT default_group_id FROM secondary_nodes WHERE id=?", $nid);
    if ($cur && $cur->{default_group_id} && $cur->{default_group_id}+0 == $gid+0) {
        (my $nextg) = _db_row($dbh, "SELECT secondary_group_id FROM secondary_group_members WHERE secondary_node_id=? ORDER BY secondary_group_id LIMIT 1", $nid);
        (my $u, my $ue) = _do($dbh, "UPDATE secondary_nodes SET default_group_id=? WHERE id=?", ($nextg ? $nextg->{secondary_group_id} : undef), $nid); return (undef, $ue) if $ue;
    }
    (my $as, my $ase) = _acl_sync_node($dbh, $nid); return (undef, $ase) if $ase;   # the /32 leaves the ACL of the group it left
    return (1, undef);
}
sub secondary_group_ip_group_add {
    my ($gid, $ipg) = @_;
    return (undef, 'ids required') unless $gid && $gid =~ /^\d+$/ && $ipg && $ipg =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $g, my $e) = _db_exists($dbh, "SELECT 1 FROM secondary_groups WHERE id=?", $gid); return (undef, $e) if $e;
    return (undef, 'unknown secondary group') unless $g;
    (my $i, $e) = _db_exists($dbh, "SELECT 1 FROM ip_groups WHERE id=?", $ipg); return (undef, $e) if $e;
    return (undef, 'unknown IP group') unless $i;
    (my $dup, $e) = _db_exists($dbh, "SELECT 1 FROM secondary_group_ip_groups WHERE secondary_group_id=? AND ip_group_id=?", $gid, $ipg); return (undef, $e) if $e;
    return (1, undef) if $dup;
    (my $ok, my $de) = _do($dbh, "INSERT INTO secondary_group_ip_groups (secondary_group_id, ip_group_id) VALUES (?,?)", $gid, $ipg); return (undef, $de) if $de;
    # a new ip_group -> the /32s of all group nodes must appear in it (ACL invariant, in the core).
    { (my $ns, my $nse) = _db_all($dbh, "SELECT secondary_node_id AS nid FROM secondary_group_members WHERE secondary_group_id=?", { Slice => {} }, $gid);
      return (undef, $nse) if $nse;
      for my $n (@$ns) { (my $a, my $ae) = _acl_sync_node($dbh, $n->{nid}); return (undef, $ae) if $ae; } }
    return (1, undef);
}
sub secondary_group_ip_group_remove {
    my ($gid, $ipg) = @_;
    return (undef, 'ids required') unless $gid && $gid =~ /^\d+$/ && $ipg && $ipg =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $ok, my $de) = _do($dbh, "DELETE FROM secondary_group_ip_groups WHERE secondary_group_id=? AND ip_group_id=?", $gid, $ipg); return (undef, $de) if $de;
    # ip_group unbound -> the nodes' /32s are removed from it if no longer needed (ACL invariant, in the core).
    { (my $ns, my $nse) = _db_all($dbh, "SELECT secondary_node_id AS nid FROM secondary_group_members WHERE secondary_group_id=?", { Slice => {} }, $gid);
      return (undef, $nse) if $nse;
      for my $n (@$ns) { (my $a, my $ae) = _acl_sync_node($dbh, $n->{nid}); return (undef, $ae) if $ae; } }
    return (1, undef);
}
# Transaction OPENED only if none is active. For functions called both from the Router and INSIDE another
# transaction (create_and_add): it opens none of its own there and leaves commit/rollback to the outer one.
sub _txn_wrap {
    my ($dbh, $body) = @_;
    my $own = $dbh->{AutoCommit} ? 1 : 0;
    if ($own) { (my $bo, my $be) = _txn_begin($dbh); return (undef, $be) if $be; }
    my ($r, $e) = $body->();
    return ($r, $e) unless $own;                       # the outer transaction decides the outcome
    if ($e) { eval { $dbh->rollback }; return (undef, $e); }
    unless ($dbh->commit) { my $k = _db_err_kind($dbh->err); eval { $dbh->rollback }; return (undef, $k); }
    return ($r, undef);
}
# Bind a TSIG key to an owner (group or server) UNDER THE OWNER LOCK. UNIQUE does not replace the lock:
# UNIQUE forbids TWO active keys, but without a shared lock we get ZERO - add sees the old active one and
# inserts its own inactive while a concurrent remove drops the old one without seeing the new. So add
# takes the same rows in the same order (by tsig_key_id) as remove and set_primary.
# Table/column names are internal constants ($TSIG_OWNER_*), not user input.
sub _tsig_key_bind {
    my ($dbh, $t, $oid, $kid) = @_;
    (my $ox, my $oe) = _db_exists($dbh, $t->{owner_sql}, $oid); return (undef, $oe) if $oe;
    return (undef, $t->{owner_err}) unless $ox;
    (my $kx, my $ke) = _db_exists($dbh, "SELECT 1 FROM tsig_keys WHERE id=?", $kid); return (undef, $ke) if $ke;
    return (undef, 'unknown TSIG key') unless $kx;
    (my $rows, my $re) = _db_all($dbh,
        "SELECT tsig_key_id, is_primary FROM $t->{table} WHERE $t->{col}=? ORDER BY tsig_key_id FOR UPDATE",
        { Slice => {} }, $oid); return (undef, $re) if $re;
    return (1, undef) if grep { $_->{tsig_key_id} == $kid } @$rows;        # already bound - idempotent
    my $prim = (grep { $_->{is_primary} } @$rows) ? 0 : 1;                  # the owner's first key is the active one
    (my $ok, my $de) = _do($dbh,
        "INSERT INTO $t->{table} ($t->{col}, tsig_key_id, is_primary) VALUES (?,?,?)", $oid, $kid, $prim);
    return (undef, $de) if $de;
    return (1, undef);
}
our $TSIG_OWNER_GROUP = { table => 'secondary_group_tsig_keys', col => 'secondary_group_id',
                          owner_sql => "SELECT 1 FROM secondary_groups WHERE id=?", owner_err => 'unknown secondary group' };
our $TSIG_OWNER_NODE  = { table => 'secondary_node_tsig_keys',  col => 'secondary_node_id',
                          owner_sql => "SELECT 1 FROM secondary_nodes WHERE id=?",  owner_err => 'unknown server' };
sub secondary_group_tsig_key_add {
    my ($gid, $kid) = @_;
    return (undef, 'ids required') unless $gid && $gid =~ /^\d+$/ && $kid && $kid =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    return _txn_wrap($dbh, sub { _tsig_key_bind($dbh, $TSIG_OWNER_GROUP, $gid, $kid) });
}
# Remove a key and promote the next in ONE transaction, checking every step. Previously DELETE and the
# promoting UPDATE were separate and the second was unchecked: a failure between them left keys with none
# active - _node_effective_auth (strictly is_primary=1) found no key while readiness saw "keys exist".
sub secondary_group_tsig_key_remove {
    my ($gid, $kid) = @_;
    return (undef, 'ids required') unless $gid && $gid =~ /^\d+$/ && $kid && $kid =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    { (my $bo, my $be) = _txn_begin($dbh); return (undef, $be) if $be; }
    my $err = eval {
        # The group's keys are read INSIDE the transaction, FOR UPDATE, in fixed id order. Outside it raced: a
        # concurrent call could move activity onto the key between "is it active" and DELETE, and we deleted the
        # active key promoting nobody. One ordered SELECT also avoids two concurrent removals deadlocking.
        (my $rows, my $re) = _db_all($dbh,
            "SELECT tsig_key_id, is_primary FROM secondary_group_tsig_keys
              WHERE secondary_group_id=? ORDER BY tsig_key_id FOR UPDATE", { Slice => {} }, $gid); die "$re\n" if $re;
        my ($wasprim) = grep { $_->{tsig_key_id} == $kid && $_->{is_primary} } @$rows;
        (my $ok, my $de) = _do($dbh, "DELETE FROM secondary_group_tsig_keys WHERE secondary_group_id=? AND tsig_key_id=?", $gid, $kid); die "$de\n" if $de;
        if ($wasprim) {   # removed the active one -> promote the first remaining (with keys there is always an active one)
            my ($next) = grep { $_->{tsig_key_id} != $kid } @$rows;
            if ($next) { (my $u, my $ue) = _do($dbh, "UPDATE secondary_group_tsig_keys SET is_primary=1 WHERE secondary_group_id=? AND tsig_key_id=?", $gid, $next->{tsig_key_id}); die "$ue\n" if $ue; }
        }
        1;
    } ? undef : ($@ || 'error');
    if (defined $err) { chomp $err; eval { $dbh->rollback }; return (undef, $err); }
    unless ($dbh->commit) { my $ck = _db_err_kind($dbh->err); eval { $dbh->rollback }; return (undef, $ck); }
    return (1, undef);
}
# Make a key active for the group (radio): 0 for all, 1 for the chosen one. Requires an existing binding.
sub secondary_group_tsig_set_primary {
    my ($gid, $kid) = @_;
    return (undef, 'ids required') unless $gid && $gid =~ /^\d+$/ && $kid && $kid =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    { (my $bo, my $be) = _txn_begin($dbh); return (undef, $be) if $be; }
    my $err = eval {
        # The binding is checked INSIDE the transaction under the same FOR UPDATE as removal. Outside it raced the
        # other way: the key could be removed between check and write, the first UPDATE cleared all, the second
        # matched nothing - success reported with no active key. Same id lock order as remove, so no deadlock.
        (my $rows, my $re) = _db_all($dbh,
            "SELECT tsig_key_id FROM secondary_group_tsig_keys
              WHERE secondary_group_id=? ORDER BY tsig_key_id FOR UPDATE", { Slice => {} }, $gid); die "$re\n" if $re;
        die "key not bound to group\n" unless grep { $_->{tsig_key_id} == $kid } @$rows;
        (my $o1, my $e1) = _do($dbh, "UPDATE secondary_group_tsig_keys SET is_primary=0 WHERE secondary_group_id=?", $gid); die "$e1\n" if $e1;
        (my $o2, my $e2) = _do($dbh, "UPDATE secondary_group_tsig_keys SET is_primary=1 WHERE secondary_group_id=? AND tsig_key_id=?", $gid, $kid); die "$e2\n" if $e2;
        1;
    } ? undef : ($@ || 'error');
    if (defined $err) { chomp $err; eval { $dbh->rollback }; return (undef, $err); }
    unless ($dbh->commit) { my $k = _db_err_kind($dbh->err); eval { $dbh->rollback }; return (undef, $k); }
    return (1, undef);
}

# ---- Personal node TSIG keys (mirror of the group ones; take precedence in _node_effective_auth) ----
sub secondary_node_tsig_key_add {
    my ($nid, $kid) = @_;
    return (undef, 'ids required') unless $nid && $nid =~ /^\d+$/ && $kid && $kid =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    return _txn_wrap($dbh, sub { _tsig_key_bind($dbh, $TSIG_OWNER_NODE, $nid, $kid) });
}
# Create a TSIG key AND bind it to the node in ONE transaction (a binding failure rolls back the create,
# no orphan). (kid, err). connectDB is a singleton and subfunctions do not commit, so begin_work covers their _do.
sub secondary_node_tsig_key_create_and_add {
    my ($nid, $name, $algo, $secret) = @_;
    return (undef, 'id required') unless $nid && $nid =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $nx, my $e) = _db_exists($dbh, "SELECT 1 FROM secondary_nodes WHERE id=?", $nid); return (undef, $e) if $e;
    return (undef, 'unknown server') unless $nx;
    { (my $bo, my $be) = _txn_begin($dbh); return (undef, $be) if $be; }
    my $kid;
    my $err = eval {
        (my $k, my $ke) = tsig_key_create($name, $algo, $secret); die "$ke\n" if $ke;
        (my $ok, my $ae) = secondary_node_tsig_key_add($nid, $k);  die "$ae\n" if $ae;
        $kid = $k; 1;
    } ? undef : ($@ || 'error');
    if (defined $err) { chomp $err; eval { $dbh->rollback }; return (undef, $err); }
    unless ($dbh->commit) { my $ck = _db_err_kind($dbh->err); eval { $dbh->rollback }; return (undef, $ck); }
    return ($kid, undef);
}
# Same for a GROUP, one transaction.
sub secondary_group_tsig_key_create_and_add {
    my ($gid, $name, $algo, $secret) = @_;
    return (undef, 'id required') unless $gid && $gid =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $gx, my $e) = _db_exists($dbh, "SELECT 1 FROM secondary_groups WHERE id=?", $gid); return (undef, $e) if $e;
    return (undef, 'unknown secondary group') unless $gx;
    { (my $bo, my $be) = _txn_begin($dbh); return (undef, $be) if $be; }
    my $kid;
    my $err = eval {
        (my $k, my $ke) = tsig_key_create($name, $algo, $secret); die "$ke\n" if $ke;
        (my $ok, my $ae) = secondary_group_tsig_key_add($gid, $k); die "$ae\n" if $ae;
        $kid = $k; 1;
    } ? undef : ($@ || 'error');
    if (defined $err) { chomp $err; eval { $dbh->rollback }; return (undef, $err); }
    unless ($dbh->commit) { my $ck = _db_err_kind($dbh->err); eval { $dbh->rollback }; return (undef, $ck); }
    return ($kid, undef);
}
# Remove a key and promote the next in ONE transaction, checking every step. Previously DELETE and the
# promoting UPDATE were separate and the second was unchecked: a failure between them left keys with none
# active - _node_effective_auth (strictly is_primary=1) found no key while readiness saw "keys exist".
# A PERSONAL key costs more than a group one: an active personal key unconditionally puts the server into
# tsig_only (_node_effective_auth). Losing it silently drops the server to its group's mode - a change of
# AXFR authorization, not just a badge.
sub secondary_node_tsig_key_remove {
    my ($nid, $kid) = @_;
    return (undef, 'ids required') unless $nid && $nid =~ /^\d+$/ && $kid && $kid =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    { (my $bo, my $be) = _txn_begin($dbh); return (undef, $be) if $be; }
    my $err = eval {
        # The server's keys are read INSIDE the transaction, FOR UPDATE, in fixed id order. Outside it raced: a
        # concurrent call could move activity onto the key between "is it active" and DELETE, and we deleted the
        # active key promoting nobody. One ordered SELECT also avoids two concurrent removals deadlocking.
        (my $rows, my $re) = _db_all($dbh,
            "SELECT tsig_key_id, is_primary FROM secondary_node_tsig_keys
              WHERE secondary_node_id=? ORDER BY tsig_key_id FOR UPDATE", { Slice => {} }, $nid); die "$re\n" if $re;
        my ($wasprim) = grep { $_->{tsig_key_id} == $kid && $_->{is_primary} } @$rows;
        (my $ok, my $de) = _do($dbh, "DELETE FROM secondary_node_tsig_keys WHERE secondary_node_id=? AND tsig_key_id=?", $nid, $kid); die "$de\n" if $de;
        if ($wasprim) {   # removed the active one -> promote the first remaining (with keys there is always an active one)
            my ($next) = grep { $_->{tsig_key_id} != $kid } @$rows;
            if ($next) { (my $u, my $ue) = _do($dbh, "UPDATE secondary_node_tsig_keys SET is_primary=1 WHERE secondary_node_id=? AND tsig_key_id=?", $nid, $next->{tsig_key_id}); die "$ue\n" if $ue; }
        }
        1;
    } ? undef : ($@ || 'error');
    if (defined $err) { chomp $err; eval { $dbh->rollback }; return (undef, $err); }
    unless ($dbh->commit) { my $ck = _db_err_kind($dbh->err); eval { $dbh->rollback }; return (undef, $ck); }
    return (1, undef);
}
sub secondary_node_tsig_set_primary {
    my ($nid, $kid) = @_;
    return (undef, 'ids required') unless $nid && $nid =~ /^\d+$/ && $kid && $kid =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    { (my $bo, my $be) = _txn_begin($dbh); return (undef, $be) if $be; }
    my $err = eval {
        # The binding is checked INSIDE the transaction under the same FOR UPDATE as removal. Outside it raced the
        # other way: the key could be removed between check and write, the first UPDATE cleared all, the second
        # matched nothing - success reported with no active key. Same id lock order as remove, so no deadlock.
        (my $rows, my $re) = _db_all($dbh,
            "SELECT tsig_key_id FROM secondary_node_tsig_keys
              WHERE secondary_node_id=? ORDER BY tsig_key_id FOR UPDATE", { Slice => {} }, $nid); die "$re\n" if $re;
        die "key not bound to server\n" unless grep { $_->{tsig_key_id} == $kid } @$rows;
        (my $o1, my $e1) = _do($dbh, "UPDATE secondary_node_tsig_keys SET is_primary=0 WHERE secondary_node_id=?", $nid); die "$e1\n" if $e1;
        (my $o2, my $e2) = _do($dbh, "UPDATE secondary_node_tsig_keys SET is_primary=1 WHERE secondary_node_id=? AND tsig_key_id=?", $nid, $kid); die "$e2\n" if $e2;
        1;
    } ? undef : ($@ || 'error');
    if (defined $err) { chomp $err; eval { $dbh->rollback }; return (undef, $err); }
    unless ($dbh->commit) { my $k = _db_err_kind($dbh->err); eval { $dbh->rollback }; return (undef, $k); }
    return (1, undef);
}
# Batch: node_id => [{id,name,algorithm,is_primary}] of personal keys (Servers tab).
sub secondary_nodes_tsig_map {
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $rows, my $e) = _db_all($dbh,
        "SELECT b.secondary_node_id, k.id, k.name, k.algorithm, b.is_primary
           FROM secondary_node_tsig_keys b JOIN tsig_keys k ON k.id=b.tsig_key_id ORDER BY k.id", { Slice => {} }); return (undef, $e) if $e;
    my %m; push @{ $m{ $_->{secondary_node_id}+0 } }, { id => $_->{id}+0, name => $_->{name}, algorithm => $_->{algorithm}, is_primary => $_->{is_primary}+0 } for @$rows;
    return (\%m, undef);
}
# Effective AXFR authorization of a SERVER (a node property, independent of catalogs). Fixed priority:
#   1) the node's active personal TSIG; 2) the default group's active TSIG; 3) otherwise IP ACL (default
#   group coverage). Other node groups are tags and do NOT take part. { source, mode, tsig_key_id?, group_id?, authorized }.
sub _node_effective_auth {
    my ($dbh, $node_id) = @_;
    my $NONE = sub { return { source=>'none', mode=>'none', authorized=>0, issues=>($_[0] || []) } };
    (my $pk, my $pe) = _db_row($dbh, "SELECT tsig_key_id FROM secondary_node_tsig_keys WHERE secondary_node_id=? AND is_primary=1 ORDER BY tsig_key_id LIMIT 1", $node_id); return ($NONE->(), $pe) if $pe;
    return ({ source=>'personal', mode=>'tsig_only', tsig_key_id=>$pk->{tsig_key_id}+0, authorized=>1, issues=>[] }, undef) if $pk;
    (my $nr, my $ne) = _db_row($dbh, "SELECT default_group_id FROM secondary_nodes WHERE id=?", $node_id); return ($NONE->(), $ne) if $ne;
    my $dg = ($nr && $nr->{default_group_id}) ? $nr->{default_group_id}+0 : undef;
    # Neither a personal key nor an authorization group: groups are optional, and a server stands on its own
    # address (ALLOW-AXFR-FROM its /32). Only a server with no address at all is unauthorized.
    unless (defined $dg) {
        (my $has, my $he) = _db_exists($dbh, "SELECT 1 FROM secondary_node_endpoints WHERE secondary_node_id=? AND purpose='axfr_source' AND enabled=1", $node_id);
        return ($NONE->(), $he) if $he;
        return ($NONE->(['the server has no address to allow AXFR from']), undef) unless $has;
        return ({ source=>'ip', mode=>'ip_only', authorized=>1, issues=>[] }, undef);
    }
    # The source group's MODE decides: tsig_only -> the group key (if any); ip_only -> IP ACL (a stored key is NOT used).
    (my $gr, my $gre) = _db_row($dbh, "SELECT axfr_auth_mode, name FROM secondary_groups WHERE id=?", $dg); return ($NONE->(), $gre) if $gre;
    my $gmode = $gr ? $gr->{axfr_auth_mode} : '';
    my $gname = ($gr && defined $gr->{name}) ? $gr->{name} : "#$dg";
    (my $auth, my $ae, my $issues) = _group_node_auth($dbh, $dg, $node_id, ''); return ($NONE->(), $ae) if $ae;
    my @iss = @{ $issues || [] };
    if ($gmode eq 'tsig_only') {
        (my $gk) = _db_row($dbh, "SELECT tsig_key_id FROM secondary_group_tsig_keys WHERE secondary_group_id=? AND is_primary=1 ORDER BY tsig_key_id LIMIT 1", $dg);
        # the group may have keys but none marked active - then AXFR cannot be signed, and that must be named.
        push @iss, "group '$gname' has no active TSIG key" unless $gk;
        return ({ source=>'group', group_id=>$dg, mode=>'tsig_only', tsig_key_id=>($gk ? $gk->{tsig_key_id}+0 : undef), authorized=>($auth?1:0), issues=>\@iss }, undef);
    }
    return ({ source=>'ip', group_id=>$dg, mode=>'ip_only', authorized=>($auth?1:0), issues=>\@iss }, undef);   # ip_only: IP ACL
}
# Set the node's default group (its key = the authorization). $gid must be one of the node's groups (or 0/undef to clear).
# Choosing a group means using its key -> the active PERSONAL key is deactivated (it would override the group).
sub secondary_node_set_default_group {
    my ($nid, $gid) = @_;
    return (undef, 'id required') unless $nid && $nid =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $nx, my $e) = _db_exists($dbh, "SELECT 1 FROM secondary_nodes WHERE id=?", $nid); return (undef, $e) if $e;
    return (undef, 'unknown server') unless $nx;
    my $g = (defined $gid && "$gid" =~ /^\d+$/ && $gid > 0) ? $gid+0 : undef;
    if (defined $g) {
        (my $mem, my $me) = _db_exists($dbh, "SELECT 1 FROM secondary_group_members WHERE secondary_group_id=? AND secondary_node_id=?", $g, $nid); return (undef, $me) if $me;
        return (undef, 'server is not a member of that group') unless $mem;
    }
    { (my $bo, my $be) = _txn_begin($dbh); return (undef, $be) if $be; }
    (my $o1, my $e1) = _do($dbh, "UPDATE secondary_nodes SET default_group_id=? WHERE id=?", $g, $nid);
    if ($e1) { eval { $dbh->rollback }; return (undef, $e1); }
    (my $o2, my $e2) = _do($dbh, "UPDATE secondary_node_tsig_keys SET is_primary=0 WHERE secondary_node_id=?", $nid);
    if ($e2) { eval { $dbh->rollback }; return (undef, $e2); }
    unless ($dbh->commit) { my $k = _db_err_kind($dbh->err); eval { $dbh->rollback }; return (undef, $k); }
    return (1, undef);
}

# ---- Secondary nodes + endpoints ----
my %NODE_IMPL   = map { $_ => 1 } qw(bind powerdns);
my %NODE_PROV   = map { $_ => 1 } qw(manual agent);
my %NODE_NOTIFY = map { $_ => 1 } qw(inherit on off);      # per-server NOTIFY override; see _node_effective_notify
my %NODE_AXFR   = map { $_ => 1 } qw(inherit allow deny);   # per-server AXFR override; see _node_effective_axfr

sub secondary_nodes_all {
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    my ($rows, $e) = _db_all($dbh,
        "SELECT n.id, n.name, n.location, n.enabled, n.implementation, n.provisioning_mode,
                n.supports_catalog, n.supports_coo, n.notify_policy, n.axfr_policy,
                (SELECT COUNT(*) FROM secondary_group_members m WHERE m.secondary_node_id=n.id) AS group_count,
                (SELECT COUNT(*) FROM secondary_node_endpoints ep WHERE ep.secondary_node_id=n.id) AS endpoint_count
           FROM secondary_nodes n
          ORDER BY n.name", { Slice => {} });
    return (undef, $e) if $e;
    for (@$rows) { $_->{id}+=0; $_->{enabled}+=0; $_->{supports_catalog}+=0; $_->{supports_coo}+=0;
                   $_->{group_count}+=0; $_->{endpoint_count}+=0; }
    return ($rows, undef);
}
sub secondary_node_get {
    my ($id) = @_;
    return (undef, 'not found') unless $id && $id =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $n, my $e) = _db_row($dbh,
        "SELECT id, name, location, enabled, implementation, provisioning_mode, supports_catalog, supports_coo, notify_policy, axfr_policy, default_group_id
           FROM secondary_nodes WHERE id=?", $id); return (undef, $e) if $e;
    return (undef, 'not found') unless $n;
    $n->{id}+=0; $n->{enabled}+=0; $n->{supports_catalog}+=0; $n->{supports_coo}+=0;
    (my $eps, $e) = _db_all($dbh, "SELECT id, purpose, address, port, enabled FROM secondary_node_endpoints WHERE secondary_node_id=? ORDER BY purpose, address", { Slice => {} }, $id); return (undef, $e) if $e;
    for (@$eps) { $_->{id}+=0; $_->{port}+=0; $_->{enabled}+=0; }
    (my $groups, $e) = _db_all($dbh, "SELECT g.id, g.name FROM secondary_group_members m JOIN secondary_groups g ON g.id=m.secondary_group_id WHERE m.secondary_node_id=? ORDER BY g.name", { Slice => {} }, $id); return (undef, $e) if $e;
    $_->{id}+=0 for @$groups;
    $n->{endpoints} = $eps; $n->{groups} = $groups;
    return ($n, undef);
}
sub _node_validate {
    my ($dbh, $f, $for_update, $cur) = @_;
    my %out;
    if (!$for_update || exists $f->{name}) {
        (my $n, my $e) = _check_len($f->{name}, 'name', 64, 1); return (undef, $e) if $e;
        $out{name} = $n;
    }
    if (exists $f->{location}) {
        (my $l, my $e) = _check_len($f->{location}, 'location', 64, 0); return (undef, $e) if $e;
        $out{location} = $l;
    }
    if (exists $f->{enabled}) { (my $b, my $e) = strict_bool($f->{enabled}); return (undef, "enabled: $e") if $e; $out{enabled} = $b; }
    if (!$for_update || exists $f->{implementation}) {
        my $v = _trim($f->{implementation}) || 'bind';
        return (undef, 'invalid implementation') unless $NODE_IMPL{$v};
        $out{implementation} = $v;
    }
    if (!$for_update || exists $f->{provisioning_mode}) {
        my $v = _trim($f->{provisioning_mode}) || 'manual';
        return (undef, 'invalid provisioning_mode') unless $NODE_PROV{$v};
        $out{provisioning_mode} = $v;
    }
    if (!$for_update || exists $f->{axfr_policy}) {
        my $v = _trim($f->{axfr_policy});
        $v = ($for_update && $cur) ? ($cur->{axfr_policy} // 'inherit') : 'inherit' unless defined $v && length $v;
        return (undef, 'invalid axfr_policy') unless $NODE_AXFR{$v};
        $out{axfr_policy} = $v;
    }
    if (!$for_update || exists $f->{notify_policy}) {
        my $v = _trim($f->{notify_policy});
        $v = ($for_update && $cur) ? ($cur->{notify_policy} // 'inherit') : 'inherit' unless defined $v && length $v;
        return (undef, 'invalid notify_policy') unless $NODE_NOTIFY{$v};
        $out{notify_policy} = $v;
    }
    if (exists $f->{supports_catalog}) { (my $b, my $e) = strict_bool($f->{supports_catalog}); return (undef, "supports_catalog: $e") if $e; $out{supports_catalog} = $b; }
    if (exists $f->{supports_coo})     { (my $b, my $e) = strict_bool($f->{supports_coo});     return (undef, "supports_coo: $e") if $e;     $out{supports_coo} = $b; }
    my $eff_cat = exists $out{supports_catalog} ? $out{supports_catalog} : ($for_update ? $cur->{supports_catalog} : 0);
    my $eff_coo = exists $out{supports_coo}     ? $out{supports_coo}     : ($for_update ? $cur->{supports_coo}     : 0);
    (my $ok, my $ce) = node_caps_check($eff_cat, $eff_coo); return (undef, $ce) if $ce;
    return (\%out, undef);
}
sub secondary_node_create {
    my ($f) = @_;
    $f ||= {};
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    my ($v, $err) = _node_validate($dbh, $f, 0, undef);
    return (undef, $err) if $err;
    (my $ex, my $e) = _db_exists($dbh, "SELECT 1 FROM secondary_nodes WHERE name=?", $v->{name}); return (undef, $e) if $e;
    return (undef, "secondary node '$v->{name}' already exists") if $ex;
    my @cols = sort keys %$v;
    my @vals = map { $v->{$_} } @cols;
    my $ph = join(',', ('?') x @cols);
    (my $ok, my $de) = _do($dbh, "INSERT INTO secondary_nodes (".join(',',@cols).") VALUES ($ph)", @vals); return (undef, $de) if $de;
    return ($dbh->last_insert_id(undef,undef,undef,undef), undef);
}
sub secondary_node_update {
    my ($id, $f) = @_;
    return (undef, 'id required') unless $id && $id =~ /^\d+$/;
    $f ||= {};
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $cur, my $e) = _db_row($dbh, "SELECT * FROM secondary_nodes WHERE id=?", $id); return (undef, $e) if $e;
    return (undef, 'not found') unless $cur;
    my ($v, $err) = _node_validate($dbh, $f, 1, $cur);
    return (undef, $err) if $err;
    if (exists $v->{name}) {
        (my $dup, $e) = _db_exists($dbh, "SELECT 1 FROM secondary_nodes WHERE name=? AND id<>?", $v->{name}, $id); return (undef, $e) if $e;
        return (undef, "secondary node '$v->{name}' already exists") if $dup;
    }
    my (@set, @val);
    for my $k (sort keys %$v) { push @set, "$k=?"; push @val, $v->{$k}; }
    return (1, undef) unless @set;
    (my $ok, my $de) = _do($dbh, "UPDATE secondary_nodes SET ".join(',',@set)." WHERE id=?", @val, $id); return (undef, $de) if $de;
    return (1, undef);
}
sub secondary_node_delete {
    my ($id) = @_;
    return (undef, 'id required') unless $id && $id =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $ex, my $e) = _db_exists($dbh, "SELECT 1 FROM secondary_nodes WHERE id=?", $id); return (undef, $e) if $e;
    return (undef, 'not found') unless $ex;
    (my $ok, my $de) = _do($dbh, "DELETE FROM secondary_nodes WHERE id=?", $id); return (undef, $de) if $de;
    return (1, undef);
}

# ---- "Secondary server": a THIN wrapper over EXISTING operations (no new tables/fields/planner). ----
# The simple UI sees only name/IP/description/groups/enabled; underneath are regular node + endpoints +
# memberships + ACL. IP comes from the axfr_source endpoint, description = node.location.
sub secondary_server_get {
    my ($nid) = @_;
    (my $n, my $e) = secondary_node_get($nid); return (undef, $e) if $e;
    my ($ip) = map { $_->{address} } grep { ($_->{purpose} // '') eq 'axfr_source' } @{ $n->{endpoints} || [] };
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    # Personal node TSIG keys + backend-authoritative effective_auth (JS does NOT recompute it).
    (my $tks, my $te) = _db_all($dbh, "SELECT k.id, k.name, k.algorithm, b.is_primary
        FROM secondary_node_tsig_keys b JOIN tsig_keys k ON k.id=b.tsig_key_id WHERE b.secondary_node_id=? ORDER BY k.id", { Slice => {} }, $nid); return (undef, $te) if $te;
    (my $ea, my $eae) = _node_effective_auth($dbh, $nid); return (undef, $eae) if $eae;
    return ({ id => $n->{id} + 0, name => $n->{name}, ip => $ip, description => $n->{location},
              enabled => $n->{enabled} + 0,
              notify_policy => ($n->{notify_policy} // 'inherit'),
              axfr_policy   => ($n->{axfr_policy}   // 'inherit'),
              default_group_id => (defined $n->{default_group_id} ? $n->{default_group_id} + 0 : undef),
              groups => [ map { { id => $_->{id} + 0, name => $_->{name} } } @{ $n->{groups} || [] } ],
              tsig_keys => [ map { { id => $_->{id}+0, name => $_->{name}, algorithm => $_->{algorithm}, is_primary => $_->{is_primary}+0 } } @$tks ],
              effective_auth => $ea }, undef);
}
# Server list in ONE set of queries, not "list then re-read each row": previously N servers cost
# 1 + N x (node + addresses + groups + keys + auth) queries; now related data is fetched in shared
# selects and assembled in memory.
sub secondary_servers_list {
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $rows, my $e) = _db_all($dbh,
        "SELECT id, name, location, enabled, notify_policy, axfr_policy, default_group_id
           FROM secondary_nodes ORDER BY name", { Slice => {} });
    return (undef, $e) if $e;
    return ([], undef) unless @$rows;
    my @ids = map { $_->{id} + 0 } @$rows;
    my $ph  = join(',', ('?') x @ids);

    (my $eps, my $ee) = _db_all($dbh,
        "SELECT secondary_node_id AS nid, address FROM secondary_node_endpoints
          WHERE purpose='axfr_source' AND secondary_node_id IN ($ph) ORDER BY id", { Slice => {} }, @ids);
    return (undef, $ee) if $ee;
    my %ip; $ip{ $_->{nid} + 0 } //= $_->{address} for @$eps;

    (my $grs, my $ge) = _db_all($dbh,
        "SELECT m.secondary_node_id AS nid, g.id, g.name FROM secondary_group_members m
           JOIN secondary_groups g ON g.id = m.secondary_group_id
          WHERE m.secondary_node_id IN ($ph) ORDER BY g.name", { Slice => {} }, @ids);
    return (undef, $ge) if $ge;
    my %grp; push @{ $grp{ $_->{nid} + 0 } }, { id => $_->{id} + 0, name => $_->{name} } for @$grs;

    (my $tks, my $te) = _db_all($dbh,
        "SELECT b.secondary_node_id AS nid, k.id, k.name, k.algorithm, b.is_primary
           FROM secondary_node_tsig_keys b JOIN tsig_keys k ON k.id = b.tsig_key_id
          WHERE b.secondary_node_id IN ($ph) ORDER BY k.id", { Slice => {} }, @ids);
    return (undef, $te) if $te;
    my %tk; push @{ $tk{ $_->{nid} + 0 } },
        { id => $_->{id} + 0, name => $_->{name}, algorithm => $_->{algorithm}, is_primary => $_->{is_primary} + 0 } for @$tks;

    my @out;
    for my $r (@$rows) {
        my $nid = $r->{id} + 0;
        # Effective authorization is computed, not selected: it has its own logic (personal key, source group,
        # IP ACL), and duplicating it here would create a second answer to the same question.
        (my $ea, my $eae) = _node_effective_auth($dbh, $nid); return (undef, $eae) if $eae;
        push @out, { id => $nid, name => $r->{name}, ip => $ip{$nid}, description => $r->{location},
                     enabled => $r->{enabled} + 0,
                     notify_policy => ($r->{notify_policy} // 'inherit'),
                     axfr_policy   => ($r->{axfr_policy}   // 'inherit'),
                     default_group_id => (defined $r->{default_group_id} ? $r->{default_group_id} + 0 : undef),
                     groups    => ($grp{$nid} || []),
                     tsig_keys => ($tk{$nid}  || []),
                     effective_auth => $ea };
    }
    return (\@out, undef);
}
# Last change of each secondary node (who/when) from audit_log in ONE query (no N+1).
# target_type='secondary_node', target=id (see _inv_audit in the Router). ({id=>{actor,ts}},undef)|(undef,err).
sub secondary_nodes_last_change {
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    my $rows = $dbh->selectall_arrayref(
        "SELECT a.target AS id, a.actor, a.ts
           FROM audit_log a
           JOIN (SELECT target, MAX(id) AS mid FROM audit_log
                  WHERE target_type='secondary_node' GROUP BY target) m ON a.id = m.mid",
        { Slice => {} });
    return (undef, 'DB unavailable') unless defined $rows;
    my %by; $by{ $_->{id} } = { actor => $_->{actor}, ts => $_->{ts} } for @$rows;
    return (\%by, undef);
}
# TSIG key secret (base64, stored plaintext). The owner deliberately allowed reveal for configuring
# secondaries; the caller (Router) must be capability-gated + audited. ({..secret},undef)|(undef,err).
sub tsig_key_secret {
    my ($id) = @_;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    my $rows = $dbh->selectall_arrayref("SELECT id, name, algorithm, secret FROM tsig_keys WHERE id=?", { Slice => {} }, $id);
    return (undef, 'DB unavailable') unless defined $rows;
    return (undef, 'not found') unless @$rows;
    my $r = $rows->[0];
    return ({ id => $r->{id} + 0, name => $r->{name}, algorithm => $r->{algorithm}, secret => $r->{secret} }, undef);
}
# Canonical /32|/128 for an IP (for ip_group ACL rows); '' if the IP is empty/invalid.
sub _server_acl_cidr { my ($ip) = @_; return '' unless defined $ip && length $ip; return cidr_normalize(($ip =~ /:/) ? "$ip/128" : "$ip/32") // ''; }
# Is this IP the axfr_source of any member node of any group bound to the ip_group? (Protects another node's /32.)
sub _acl_ip_in_use {
    my ($dbh, $ip_group_id, $ip) = @_;
    return _db_exists($dbh,
        "SELECT 1 FROM secondary_group_ip_groups b
           JOIN secondary_group_members m ON m.secondary_group_id = b.secondary_group_id
           JOIN secondary_node_endpoints e ON e.secondary_node_id = m.secondary_node_id AND e.purpose = 'axfr_source' AND e.address = ?
          WHERE b.ip_group_id = ? LIMIT 1", $ip, $ip_group_id);
}
# ip_groups bound to any of the groups (to compute the affected ACL). -> (\%ipgroup_id=>1, undef) | (undef, err).
sub _groups_ipgroups {
    my ($dbh, @gids) = @_; my %ig;
    for my $g (@gids) {
        (my $rows, my $e) = _db_all($dbh, "SELECT ip_group_id FROM secondary_group_ip_groups WHERE secondary_group_id=?", { Slice => {} }, $g); return (undef, $e) if $e;
        $ig{$_->{ip_group_id}} = 1 for @$rows;
    }
    return (\%ig, undef);
}
# Remove candidate /32s from affected ACLs if no other node of the group uses the IP (others'/operator CIDRs untouched).
sub _acl_cleanup {
    my ($dbh, $affected_ig, $ips) = @_;   # \%ipgroup_id=>1 ; \@candidate_ips
    for my $igid (keys %$affected_ig) {
        for my $ip (@$ips) {
            my $cidr = _server_acl_cidr($ip); next unless $cidr ne '';
            (my $present, my $pe) = _db_exists($dbh, "SELECT 1 FROM ip_group_members WHERE ip_group_id=? AND cidr=?", $igid, $cidr); return $pe if $pe; next unless $present;
            (my $inuse, my $ue) = _acl_ip_in_use($dbh, $igid, $ip); return $ue if $ue; next if $inuse;
            (my $del, my $de) = _do($dbh, "DELETE FROM ip_group_members WHERE ip_group_id=? AND cidr=?", $igid, $cidr); return $de if $de;
        }
    }
    return undef;
}
# Save: node (location=description, bind, manual, catalog) -> axfr_source+dns_listen endpoints = IP ->
# group_ids membership -> IP/32 in group ACLs, + CLEANUP of stale /32s (IP change / group removed) once
# unused. ALSO-NOTIFY is not touched (per catalog). (\%server, undef)|(undef,err).
sub secondary_server_save {
    my ($f) = @_; $f ||= {};
    my $ip = _trim($f->{ip});
    return (undef, 'ip required') unless defined $ip && length $ip;
    return (undef, 'invalid ip address') unless is_ip_addr($ip);
    my @gids = grep { defined && /^\d+$/ } @{ $f->{group_ids} || [] };
    my %node_fields = ( name => $f->{name}, location => $f->{description},
                        enabled => (exists $f->{enabled} ? ($f->{enabled} ? 1 : 0) : 1),
                        implementation => 'bind', provisioning_mode => 'manual', supports_catalog => 1 );
    $node_fields{notify_policy} = $f->{notify_policy} if exists $f->{notify_policy};
    $node_fields{axfr_policy}   = $f->{axfr_policy}   if exists $f->{axfr_policy};
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    my $nid = $f->{id};
    my $existing = (defined $nid && "$nid" =~ /^\d+$/);
    my ($old_ip, @old_groups);
    if ($existing) {   # snapshot of the previous state BEFORE the transaction (for ACL cleanup)
        (my $old, my $oe) = secondary_server_get($nid); return (undef, $oe) if $oe;
        $old_ip = $old->{ip}; @old_groups = map { $_->{id} } @{ $old->{groups} || [] };
    }
    # ALL writes (node, endpoints, memberships, default group, ACL add + cleanup) in ONE transaction.
    # connectDB is a singleton; subfunctions write via the same $dbh without committing, so begin_work covers them.
    # An error at ANY step -> die -> full rollback (no half servers). The final read is after commit.
    { (my $bo, my $be) = _txn_begin($dbh); return (undef, $be) if $be; }
    my $err = eval {
        if ($existing) { (my $u, my $ue) = secondary_node_update($nid, \%node_fields); die "$ue\n" if $ue; }
        else           { (my $id, my $ce) = secondary_node_create(\%node_fields); die "$ce\n" if $ce; $nid = $id; }
        (my $nd, my $ge) = secondary_node_get($nid); die "$ge\n" if $ge;
        my %ep; for my $ee (@{ $nd->{endpoints} || [] }) { $ep{$ee->{purpose}} ||= $ee; }
        for my $purpose (qw(axfr_source dns_listen)) {   # both point at the server IP
            if (!$ep{$purpose}) { (my $a, my $ae) = secondary_node_endpoint_add($nid, $purpose, $ip, 53, 1); die "$ae\n" if $ae; }
            elsif (($ep{$purpose}{address} // '') ne $ip) { (my $u, my $ue) = secondary_node_endpoint_update($nid, $ep{$purpose}{id}, { address => $ip }); die "$ue\n" if $ue; }
        }
        my %want = map { $_ + 0 => 1 } @gids;
        my %have = map { $_->{id} + 0 => 1 } @{ $nd->{groups} || [] };
        for my $g (keys %want) { next if $have{$g}; (my $a, my $ae) = secondary_group_member_add($g, $nid); die "$ae\n" if $ae; }
        for my $g (keys %have) { next if $want{$g}; (my $r, my $re) = secondary_group_member_remove($g, $nid); die "$re\n" if $re; }
        # default group (its key = authorization): if the current one is not in the set -> the FIRST given (or clear)
        { (my $cur) = _db_row($dbh, "SELECT default_group_id FROM secondary_nodes WHERE id=?", $nid);
          my $dg = ($cur && $cur->{default_group_id}) ? $cur->{default_group_id}+0 : undef;
          unless (defined $dg && $want{$dg}) { $dg = @gids ? $gids[0]+0 : undef; }
          (my $ud, my $ude) = _do($dbh, "UPDATE secondary_nodes SET default_group_id=? WHERE id=?", $dg, $nid); die "$ude\n" if $ude; }
        my $cidr = _server_acl_cidr($ip);   # IP/32 in the ACL of current groups (idempotent; 'already' is not an error)
        for my $g (keys %want) { (my $gd, my $gde) = secondary_group_get($g); die "$gde\n" if $gde; next unless $gd;
            for my $ig (@{ $gd->{ip_groups} || [] }) { (my $m, my $ae) = ip_group_member_add($ig->{id}, $cidr); die "$ae\n" if $ae && $ae !~ /already/; } }
        # clean up stale /32s: {old IP, new IP} across all affected ip_groups (old + new groups)
        my %allg = (%want, map { $_ + 0 => 1 } @old_groups);
        (my $affected, my $afe) = _groups_ipgroups($dbh, keys %allg); die "$afe\n" if $afe;
        my %ips = map { $_ => 1 } grep { defined && length } ($old_ip, $ip);
        my $ac = _acl_cleanup($dbh, $affected, [ keys %ips ]); die "$ac\n" if $ac;
        1;
    } ? undef : ($@ || 'error');
    if (defined $err) { chomp $err; eval { $dbh->rollback }; return (undef, $err); }
    unless ($dbh->commit) { my $ck = _db_err_kind($dbh->err); eval { $dbh->rollback }; return (undef, $ck); }
    return secondary_server_get($nid);   # the canonical object, AFTER commit
}
# Server delete: remember its IP + groups, delete the node (cascades endpoints/membership), then drop its /32 from those groups' ACLs.
sub secondary_server_delete {
    my ($id) = @_;
    return (undef, 'id required') unless $id && $id =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $srv, my $e) = secondary_server_get($id); return (undef, $e) if $e;   # snapshot BEFORE the txn (for ACL cleanup)
    (my $affected, my $afe) = _groups_ipgroups($dbh, map { $_->{id} } @{ $srv->{groups} || [] }); return (undef, $afe) if $afe;
    # node delete (cascades endpoints/membership/tsig/catalog_nodes) + ACL cleanup, ATOMICALLY (one transaction).
    { (my $bo, my $be) = _txn_begin($dbh); return (undef, $be) if $be; }
    my $err = eval {
        (my $d, my $de) = secondary_node_delete($id); die "$de\n" if $de;
        my $ce = _acl_cleanup($dbh, $affected, [ grep { defined && length } ($srv->{ip}) ]); die "$ce\n" if $ce;   # the /32 is no longer needed
        1;
    } ? undef : ($@ || 'error');
    if (defined $err) { chomp $err; eval { $dbh->rollback }; return (undef, $err); }
    unless ($dbh->commit) { my $ck = _db_err_kind($dbh->err); eval { $dbh->rollback }; return (undef, $ck); }
    return (1, undef);
}
sub secondary_node_endpoint_add {
    my ($node_id, $purpose, $address, $port, $enabled) = @_;
    return (undef, 'secondary_node_id required') unless $node_id && $node_id =~ /^\d+$/;
    my ($v, $ve) = _ep_fields({ purpose=>$purpose, address=>$address, port=>$port, (defined $enabled ? (enabled=>$enabled) : ()) }, 1, 1, 0);
    return (undef, $ve) if $ve;
    my $en = exists $v->{enabled} ? $v->{enabled} : 1;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $ex, my $e) = _db_exists($dbh, "SELECT 1 FROM secondary_nodes WHERE id=?", $node_id); return (undef, $e) if $e;
    return (undef, 'not found') unless $ex;
    (my $dup, $e) = _db_exists($dbh, "SELECT 1 FROM secondary_node_endpoints WHERE secondary_node_id=? AND purpose=? AND address=? AND port=?", $node_id, $v->{purpose}, $v->{address}, $v->{port}); return (undef, $e) if $e;
    return (undef, "endpoint $v->{purpose} $v->{address}:$v->{port} already exists") if $dup;
    (my $ok, my $de) = _do($dbh, "INSERT INTO secondary_node_endpoints (secondary_node_id, purpose, address, port, enabled) VALUES (?,?,?,?,?)",
             $node_id, $v->{purpose}, $v->{address}, $v->{port}, $en); return (undef, $de) if $de;
    # The node address feeds the automatic ACL: the /32 must appear/disappear whichever API changed it
    # (previously only secondary_server_save did, and the old /32 stayed in the ACL via this path).
    (my $as, my $ase) = _acl_sync_node($dbh, $node_id); return (undef, $ase) if $ase;
    return ($dbh->last_insert_id(undef,undef,undef,undef), undef, $v->{address});
}
sub secondary_node_endpoint_get {
    my ($node_id, $ep_id) = @_;
    return (undef, 'not found') unless $node_id && $node_id =~ /^\d+$/ && $ep_id && $ep_id =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $r, my $e) = _db_row($dbh, "SELECT id, secondary_node_id, purpose, address, port, enabled FROM secondary_node_endpoints WHERE id=? AND secondary_node_id=?", $ep_id, $node_id); return (undef, $e) if $e;
    return (undef, 'not found') unless $r;
    $r->{$_} += 0 for qw(id secondary_node_id port enabled);
    return ($r, undef);
}
sub secondary_node_endpoint_update {
    my ($node_id, $ep_id, $f) = @_;
    return (undef, 'ids required') unless $node_id && $node_id =~ /^\d+$/ && $ep_id && $ep_id =~ /^\d+$/;
    $f ||= {};
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $cur, my $e) = _db_row($dbh, "SELECT * FROM secondary_node_endpoints WHERE id=? AND secondary_node_id=?", $ep_id, $node_id); return (undef, $e) if $e;
    return (undef, 'not found') unless $cur;
    my ($v, $ve) = _ep_fields($f, 0, 1, 0); return (undef, $ve) if $ve;
    return (1, undef) unless %$v;
    my $pu   = exists $v->{purpose} ? $v->{purpose} : $cur->{purpose};
    my $addr = exists $v->{address} ? $v->{address} : $cur->{address};
    my $port = exists $v->{port}    ? $v->{port}    : $cur->{port};
    if (exists $v->{purpose} || exists $v->{address} || exists $v->{port}) {
        (my $dup, $e) = _db_exists($dbh, "SELECT 1 FROM secondary_node_endpoints WHERE secondary_node_id=? AND purpose=? AND address=? AND port=? AND id<>?", $node_id, $pu, $addr, $port, $ep_id); return (undef, $e) if $e;
        return (undef, "endpoint $pu $addr:$port already exists") if $dup;
    }
    my (@set, @val); for my $k (sort keys %$v) { push @set, "$k=?"; push @val, $v->{$k}; }
    (my $ok, my $de) = _do($dbh, "UPDATE secondary_node_endpoints SET ".join(',',@set)." WHERE id=? AND secondary_node_id=?", @val, $ep_id, $node_id); return (undef, $de) if $de;
    # The node address feeds the automatic ACL: the /32 must appear/disappear whichever API changed it
    # (previously only secondary_server_save did, and the old /32 stayed in the ACL via this path).
    (my $as, my $ase) = _acl_sync_node($dbh, $node_id); return (undef, $ase) if $ase;
    return (1, undef);
}
sub secondary_node_endpoint_delete {
    my ($node_id, $ep_id) = @_;
    return (undef, 'ids required') unless $node_id && $node_id =~ /^\d+$/ && $ep_id && $ep_id =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $ex, my $e) = _db_exists($dbh, "SELECT 1 FROM secondary_node_endpoints WHERE id=? AND secondary_node_id=?", $ep_id, $node_id); return (undef, $e) if $e;
    return (undef, 'not found') unless $ex;
    (my $ok, my $de) = _do($dbh, "DELETE FROM secondary_node_endpoints WHERE id=? AND secondary_node_id=?", $ep_id, $node_id); return (undef, $de) if $de;
    # The node address feeds the automatic ACL: the /32 must appear/disappear whichever API changed it
    # (previously only secondary_server_save did, and the old /32 stayed in the ACL via this path).
    (my $as, my $ase) = _acl_sync_node($dbh, $node_id); return (undef, $ase) if $ase;
    return (1, undef);
}

# ============================================================================
# ZONE DISTRIBUTION: catalogs and direct distribution, a layer above the inventory.
# Same return contracts as the inventory (_db_*/_do; 'not found'/'in use'/'conflict'/'DB error'/'DB unavailable').
# ============================================================================


# --- Pure: evaluate the label DSL against zone labels. $labels = { slug => [values] } ---
# Nodes: {and:[..]} {or:[..]} {not:node} {has:'slug'} {eq:{slug,value}}. Empty predicate -> 0.
sub label_predicate_eval {
    my ($p, $labels) = @_;
    return 0 unless ref($p) eq 'HASH';
    $labels ||= {};
    if (exists $p->{and}) { return 0 unless ref($p->{and}) eq 'ARRAY'; for (@{$p->{and}}) { return 0 unless label_predicate_eval($_, $labels); } return 1; }
    if (exists $p->{or})  { return 0 unless ref($p->{or})  eq 'ARRAY'; for (@{$p->{or}})  { return 1 if     label_predicate_eval($_, $labels); } return 0; }
    if (exists $p->{not}) { return label_predicate_eval($p->{not}, $labels) ? 0 : 1; }
    if (exists $p->{has}) { my $s = $p->{has}; return ($s && $labels->{$s} && @{$labels->{$s}}) ? 1 : 0; }
    if (exists $p->{eq})  { my $s = $p->{eq}{slug}; my $v = $p->{eq}{value};
        return 0 unless $s && defined $v && $labels->{$s};
        return (grep { $_ eq $v } @{$labels->{$s}}) ? 1 : 0; }
    return 0;
}

# --- Pure: strict structural predicate validation. (1,undef)|(undef,err).
# Only string scalar values (no refs/extra keys), length limits, depth <= 8, <= 64 nodes. ---
sub label_predicate_validate {
    my ($p, $depth, $count) = @_;
    $depth ||= 0;
    $count ||= \(my $c = 0);
    return (undef, 'predicate too deep')  if $depth > 8;
    $$count++;
    return (undef, 'predicate too large') if $$count > 64;
    return (undef, 'invalid predicate node') unless ref($p) eq 'HASH';
    my @k = keys %$p;
    return (undef, 'predicate node needs exactly one operator') unless @k == 1;
    my $op = $k[0];
    if ($op eq 'and' || $op eq 'or') {
        return (undef, "$op needs a non-empty array") unless ref($p->{$op}) eq 'ARRAY' && @{$p->{$op}};
        return (undef, "$op has too many args")       if @{$p->{$op}} > 32;
        for my $ch (@{$p->{$op}}) { my ($ok, $e) = label_predicate_validate($ch, $depth + 1, $count); return (undef, $e) if $e; }
        return (1, undef);
    }
    if ($op eq 'not') { return label_predicate_validate($p->{not}, $depth + 1, $count); }
    if ($op eq 'has') {
        my $s = $p->{has};
        return (defined $s && !ref($s) && length "$s" && length "$s" <= 64) ? (1, undef) : (undef, 'has needs a slug string (<=64)');
    }
    if ($op eq 'eq') {
        my $eq = $p->{eq};
        return (undef, 'eq needs an object') unless ref($eq) eq 'HASH';
        return (undef, 'eq allows only {slug,value}') unless join(',', sort keys %$eq) eq 'slug,value';
        my ($s, $v) = ($eq->{slug}, $eq->{value});
        return (undef, 'eq.slug must be a string (<=64)')  unless defined $s && !ref($s) && length "$s" && length "$s" <= 64;
        return (undef, 'eq.value must be a string (<=128)') unless defined $v && !ref($v) && length "$v" <= 128;
        return (1, undef);
    }
    return (undef, "unknown operator '$op'");
}


# PURE: can a zone take part in distribution AT ALL (by any delivery)? $z = { type, is_catalog }.
#   MASTER - yes: via a catalog or direct.
#   SLAVE  - yes, direct only: the producer lists members with d.type in ('MASTER','PRODUCER'), so a
#            secondary zone never gets into a catalog, but it must still be passed down (docs/16-delivery.md).
#   NATIVE - NOT yet. PowerDNS does serve AXFR for NATIVE (verified) but sends no NOTIFY and excludes it
#            from producer catalogs (verified live: pdnsutil catalog list-members is empty until set-kind
#            primary), so delivery would be SOA-refresh only. A product decision, to enable deliberately.
#   PRODUCER/CONSUMER - the catalog itself, not a member.
sub zone_eligible_for_distribution {
    my ($z) = @_;
    return 0 unless $z && $z->{type};
    my $t = uc $z->{type};
    return 0 unless $t eq 'MASTER' || $t eq 'SLAVE';
    return 0 if $z->{is_catalog};
    return 1;
}

# DELETE A WHOLE ZONE - one path for all callers. Besides the PowerDNS zone there are per-zone panel rows
# without an FK to pdns.domains (labels, direct distribution) and sync state; forgetting them hands a new
# zone with the same domain_id someone else's labels and distribution. Previously only the site route did
# this, MCP stopped after the zone itself.
# (\%{deleted, name, snapshot, sync, cleanup_error}, undef) | (undef, err).
sub zone_delete_everywhere {
    my ($domain_id) = @_;
    return (undef, 'invalid domain_id') unless $domain_id && "$domain_id" =~ /^\d+$/;
    my $zone = pdns_get_domain($domain_id) or return (undef, 'zone not found');
    my $snapshot = pdns_zone_snapshot($domain_id);   # what exactly is destroyed, for audit
    my ($ok) = pdns_delete_zone($domain_id);
    return (undef, 'failed to delete zone') unless $ok;

    zone_labels_delete_all($domain_id);                                  # labels live in dns_panel
    (my $cl_ok, my $cl_err) = zone_distribution_cleanup($domain_id);     # direct distribution too
    my $sync = zone_deactivate($zone->{name});                           # make sure it is no longer served
    my $sok  = set_zone_sync_state($zone->{name}, $sync->{pdns_state}, $sync->{notify_state}, $sync->{detail});
    return ({ deleted => 1, name => $zone->{name}, snapshot => $snapshot,
              sync => $sync, state_error => ($sok ? 0 : 1),
              cleanup_error => $cl_err }, undef);
}
# Per-zone rows without an FK to pdns.domains: a forgotten row outlives the zone, and the next zone with
# the same domain_id silently gets distribution nobody gave it. (1,undef) | (undef,'DB unavailable'|'DB error').
sub zone_distribution_cleanup {
    my ($domain_id) = @_;
    return (undef, 'invalid domain_id') unless $domain_id && $domain_id =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $o, my $e) = _do($dbh, "DELETE FROM zone_direct_axfr WHERE domain_id=?", $domain_id);
    return (undef, $e) if $e;
    ($o, $e) = _do($dbh, "DELETE FROM zone_dynamic WHERE domain_id=?", $domain_id);   # and update acceptance
    return (undef, $e) if $e;
    return (1, undef);
}

# Zone exists in pdns.domains and is distributable (see zone_eligible_for_distribution).
# (1,undef) | (undef,'unknown zone'|'zone not eligible…'|'DB unavailable'|'DB error').
sub _zone_distributable {
    my ($domain_id) = @_;
    return (undef, 'invalid domain_id') unless $domain_id && $domain_id =~ /^\d+$/;
    my $pdns = connectPDNS() or return (undef, 'DB unavailable');
    my $r = $pdns->selectrow_hashref("SELECT id, type FROM domains WHERE id=?", undef, $domain_id);
    return (undef, _db_err_kind($pdns->err)) if $pdns->err;
    return (undef, 'unknown zone') unless $r;
    # is_catalog=0: catalog-transport zones are excluded by type already.
    return (undef, 'zone not eligible for distribution (primary/MASTER or secondary/SLAVE; NATIVE and catalog zones are not distributable)')
        unless zone_eligible_for_distribution({ type => $r->{type}, is_catalog => 0 });
    return (1, undef);
}

# Zone name by domain_id (PowerDNS DB). Previews must name zones, not count them: "6 zones" tells the
# operator nothing. (name|undef).
sub _pdns_zone_name {
    my ($did) = @_;
    my $pdns = connectPDNS() or return undef;
    my ($n) = $pdns->selectrow_array("SELECT name FROM domains WHERE id=?", undef, $did);
    return $n;
}

# ================= CATALOG =================
# A catalog is a standalone object: name, producer zone FQDN, subscribers (server groups and individual
# servers) and zones. Its zones live in pdns.domains.catalog, in PowerDNS itself; there is deliberately
# no separate assignment in the panel - two copies of one fact diverge, giving two answers to "is the
# zone in the catalog".
# Panel marker on a zone: lets the recovery pass tell OUR policy from a hand-made one. Set first on apply
# and removed last on cleanup - while any field is unreconciled the zone must stay marked, or it drops
# out of the pass with leftovers.
our $DIST_POLICY_MARK = 'X-DNSPANEL-POLICY';
# TSIG keys already reconciled with PowerDNS in this batch - no per-zone check needed. Set only by bulk
# operations, around their loop.
our $KEYS_READY = 0;

# All distributable zones with list filter fields: scope, kind, labels. Pickers and tables show the same
# list, so it is built in one place.
sub distributable_zones {
    my $pdns = connectPDNS() or return (undef, 'DB unavailable');
    my $dbh  = connectDB()   or return (undef, 'DB unavailable');
    (my $doms, my $e) = _db_all($pdns, "SELECT id, name, type FROM domains ORDER BY name", { Slice => {} }); return (undef, $e) if $e;
    (my $lrows, $e) = _db_all($dbh,
        "SELECT zl.domain_id, c.slug, c.name AS category, v.name AS value, v.color FROM zone_labels zl
           JOIN label_values v ON v.id=zl.label_value_id JOIN label_categories c ON c.id=v.category_id
          ORDER BY c.sort_order, v.sort_order", { Slice => {} }); return (undef, $e) if $e;
    my %ld; push @{ $ld{$_->{domain_id}+0} }, { slug => $_->{slug}, category => $_->{category}, value => $_->{value}, color => $_->{color} } for @$lrows;
    my @out;
    for my $d (@$doms) {
        next unless zone_eligible_for_distribution({ type => $d->{type}, is_catalog => 0 });
        my $did = $d->{id}+0;
        # kind is coarse, for the filter (forward|reverse). kindx is exact: zone tables show a REVERSE /
        # REVERSE v6 badge, which 'reverse' cannot tell apart.
        my $kindx = zone_kind($d->{name});
        my $kind = ($kindx =~ /^reverse/) ? 'reverse' : 'forward';
        push @out, { domain_id => $did, zone => $d->{name}, type => uc($d->{type} // ''),
                     kind => $kind, kindx => $kindx, labels => ($ld{$did} || []) };
    }
    return (\@out, undef);
}
sub catalogs_all {
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $rows, my $e) = _db_all($dbh,
        "SELECT id, name, fqdn, pdns_domain_id, last_error FROM catalogs ORDER BY name", { Slice => {} });
    return (undef, $e) if $e;
    return ([ map { { id => $_->{id} + 0, name => $_->{name}, fqdn => $_->{fqdn},
                      provisioned => (defined $_->{pdns_domain_id} ? 1 : 0),
                      last_error => $_->{last_error} } } @$rows ], undef);
}
sub catalog_get {
    my ($cid) = @_;
    return (undef, 'not found') unless $cid && "$cid" =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $r, my $e) = _db_row($dbh,
        "SELECT id, name, fqdn, pdns_domain_id, last_error FROM catalogs WHERE id=?", $cid);
    return (undef, $e) if $e;
    return (undef, 'not found') unless $r;
    return ({ id => $r->{id} + 0, name => $r->{name}, fqdn => $r->{fqdn},
              provisioned => (defined $r->{pdns_domain_id} ? 1 : 0),
              last_error => $r->{last_error} }, undef);
}
# Creating a catalog is ONE action: a panel row plus a producer zone in PowerDNS. (\%catalog, undef) | (undef, err).
sub catalog_create {
    my ($opts) = @_;
    $opts ||= {};
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $name, my $ne) = _check_len($opts->{name}, 'name', 190, 1); return (undef, $ne) if $ne;
    my $fqdn = _norm_fqdn($opts->{fqdn} // '');
    return (undef, 'catalog FQDN is required and must be a valid DNS name') if $fqdn eq '';
    (my $ins, my $ie) = _do($dbh, "INSERT INTO catalogs (name, fqdn) VALUES (?,?)", $name, $fqdn);
    return (undef, $ie) if $ie;
    my $cid = $dbh->last_insert_id(undef, undef, undef, undef);
    (my $pr, my $pe) = catalog_provision($cid);
    return (undef, $pe) if $pe;   # the row stays: a retry finishes the job, nothing to clean by hand
    return catalog_get($cid);
}
sub catalog_update {
    my ($cid, $opts) = @_;
    return (undef, 'not found') unless $cid && "$cid" =~ /^\d+$/;
    $opts ||= {};
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $cur, my $ce) = catalog_get($cid); return (undef, $ce) if $ce;
    if (exists $opts->{name}) {
        (my $name, my $ne) = _check_len($opts->{name}, 'name', 190, 1); return (undef, $ne) if $ne;
        (my $o, my $e) = _do($dbh, "UPDATE catalogs SET name=? WHERE id=?", $name, $cid); return (undef, $e) if $e;
    }
    if (exists $opts->{fqdn}) {
        my $fqdn = _norm_fqdn($opts->{fqdn} // '');
        return (undef, 'catalog FQDN is required and must be a valid DNS name') if $fqdn eq '';
        # PowerDNS cannot rename a producer zone, and pretending otherwise is wrong: the zone would live on under
        # the old name and subscribers would keep pulling it.
        return (undef, 'a provisioned catalog cannot be renamed — delete it and create a new one')
            if $cur->{provisioned} && $fqdn ne _norm_fqdn($cur->{fqdn});
        (my $o, my $e) = _do($dbh, "UPDATE catalogs SET fqdn=? WHERE id=?", $fqdn, $cid); return (undef, $e) if $e;
    }
    return catalog_get($cid);
}
# Catalog delete. Zones leave it FIRST: removing the producer zone while keeping members leaves
# subscribers a list that no longer exists and rights to zones nobody serves them.
sub catalog_delete {
    my ($cid) = @_;
    return (undef, 'not found') unless $cid && "$cid" =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $cur, my $ce) = catalog_get($cid); return (undef, $ce) if $ce;
    (my $zs, my $ze) = catalog_zones($cid); return (undef, $ze) if $ze;
    for my $z (@$zs) {
        (my $r, my $e) = zone_catalog_set($z->{domain_id}, undef, 'catalog deleted');
        return (undef, "zone $z->{name}: $e") if $e;
    }
    if ($cur->{provisioned}) { (my $d, my $de) = catalog_provision_delete($cid); return (undef, $de) if $de; }
    (my $o, my $e) = _do($dbh, "DELETE FROM catalogs WHERE id=?", $cid); return (undef, $e) if $e;
    return (1, undef);
}
# Catalog subscribers are server groups; full replacement in one action.
sub catalog_groups_set {
    my ($cid, $group_ids) = @_;
    return (undef, 'not found') unless $cid && "$cid" =~ /^\d+$/;
    $group_ids = [] unless ref($group_ids) eq 'ARRAY';
    my (%seen, @clean);
    for my $g (@$group_ids) {
        return (undef, 'invalid group id') unless defined $g && "$g" =~ /^\d+$/ && $g > 0;
        next if $seen{$g + 0}++; push @clean, $g + 0;
    }
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $cx, my $cxe) = _db_exists($dbh, "SELECT 1 FROM catalogs WHERE id=?", $cid); return (undef, $cxe) if $cxe;
    return (undef, 'not found') unless $cx;
    if (@clean) {
        my $ph = join(',', ('?') x @clean);
        (my $n, my $ne) = _db_count($dbh, "SELECT COUNT(*) FROM secondary_groups WHERE id IN ($ph)", @clean);
        return (undef, $ne) if $ne;
        return (undef, 'unknown group') unless $n == scalar(@clean);
    }
    { (my $bo, my $be) = _txn_begin($dbh); return (undef, $be) if $be; }
    (my $od, my $de) = _do($dbh, "DELETE FROM catalog_groups WHERE catalog_id=?", $cid);
    if ($de) { eval { $dbh->rollback }; return (undef, $de); }
    for my $g (@clean) {
        (my $oi, my $ie) = _do($dbh, "INSERT INTO catalog_groups (catalog_id, secondary_group_id) VALUES (?,?)", $cid, $g);
        if ($ie) { eval { $dbh->rollback }; return (undef, $ie); }
    }
    unless ($dbh->commit) { my $k = _db_err_kind($dbh->err); eval { $dbh->rollback }; return (undef, $k); }
    return (\@clean, undef);
}
sub catalog_groups_get {
    my ($cid) = @_;
    return (undef, 'not found') unless $cid && "$cid" =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $rows, my $e) = _db_all($dbh,
        "SELECT secondary_group_id FROM catalog_groups WHERE catalog_id=?", { Slice => {} }, $cid);
    return (undef, $e) if $e;
    return ([ map { $_->{secondary_group_id} + 0 } @$rows ], undef);
}
# Catalog zones straight from PowerDNS - one source, nothing to diverge. PowerDNS stores domains.catalog
# as an FQDN WITHOUT the trailing dot (observed), but historically with it too -> both forms are matched.
# A miss here means a member zone without rights and NOTAUTH on its AXFR.
sub catalog_zones {
    my ($cid) = @_;
    return (undef, 'not found') unless $cid && "$cid" =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $c, my $ce) = _db_row($dbh, "SELECT fqdn FROM catalogs WHERE id=?", $cid); return (undef, $ce) if $ce;
    return (undef, 'not found') unless $c;
    my $fqdn = _norm_fqdn($c->{fqdn}); return ([], undef) if $fqdn eq '';
    my $pdns = connectPDNS() or return (undef, 'DB unavailable');
    (my $rows, my $e) = _db_all($pdns,
        "SELECT id, name, type FROM domains WHERE catalog IN (?, ?) ORDER BY name", { Slice => {} }, $fqdn, "$fqdn.");
    return (undef, $e) if $e;
    return ([ map { { domain_id => $_->{id} + 0, name => $_->{name}, type => uc($_->{type} // '') } } @$rows ], undef);
}
# Which catalog holds the zone: id or undef. Asks PowerDNS, not the panel.
sub zone_catalog_of {
    my ($dbh, $domain_id) = @_;
    return (undef, undef) unless $domain_id && "$domain_id" =~ /^\d+$/;
    my $pdns = connectPDNS() or return (undef, 'DB unavailable');
    (my $z, my $ze) = _db_row($pdns, "SELECT catalog FROM domains WHERE id=?", $domain_id);
    return (undef, $ze) if $ze;
    my $fq = ($z && defined $z->{catalog}) ? _norm_fqdn($z->{catalog}) : '';
    return (undef, undef) if $fq eq '';
    (my $c, my $ce) = _db_row($dbh, "SELECT id FROM catalogs WHERE fqdn=?", $fq);
    return (undef, $ce) if $ce;
    return ($c ? $c->{id} + 0 : undef, undef);
}
# Zone -> catalog map in one query: the zone list needs it for every row.
sub zone_catalog_map {
    my $dbh  = connectDB()   or return (undef, 'DB unavailable');
    my $pdns = connectPDNS() or return (undef, 'DB unavailable');
    (my $cats, my $ce) = _db_all($dbh, "SELECT id, name, fqdn FROM catalogs", { Slice => {} });
    return (undef, $ce) if $ce;
    my %by_fqdn = map { _norm_fqdn($_->{fqdn}) => { id => $_->{id} + 0, name => $_->{name}, fqdn => $_->{fqdn} } } @$cats;
    (my $rows, my $e) = _db_all($pdns,
        "SELECT id, catalog FROM domains WHERE catalog IS NOT NULL AND catalog <> ''", { Slice => {} });
    return (undef, $e) if $e;
    my %m;
    for my $r (@$rows) {
        my $c = $by_fqdn{ _norm_fqdn($r->{catalog}) } or next;
        $m{ $r->{id} + 0 } = $c;
    }
    return (\%m, undef);
}
# ---- Two independent lists: direct distribution and catalog ----------------------------------------------
# A zone may be in direct distribution, a catalog, both or neither. Its PowerDNS rights are computed ONCE
# as the union of recipients and written in one operation; two separate writes would let the last one
# overwrite the first, leaving a zone on both lists with only one set of rights.
sub zone_direct_axfr_map {
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $rows, my $e) = _db_all($dbh, "SELECT domain_id FROM zone_direct_axfr", { Slice => {} });
    return (undef, $e) if $e;
    return ({ map { $_->{domain_id} + 0 => 1 } @$rows }, undef);
}
sub zone_direct_axfr_set {
    my ($domain_id, $on, $reason) = @_;
    return (undef, 'invalid domain_id') unless $domain_id && "$domain_id" =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $rr, my $rre) = _check_len($reason, 'reason', 255, 0); return (undef, $rre) if $rre;
    if ($on) {
        (my $zok, my $ze) = _zone_distributable($domain_id); return (undef, $ze) if $ze;
        (my $r, my $e) = _do($dbh, "INSERT INTO zone_direct_axfr (domain_id, reason) VALUES (?,?)
                                    ON DUPLICATE KEY UPDATE reason=VALUES(reason)", $domain_id, $rr);
        return (undef, $e) if $e;
    } else {
        (my $r, my $e) = _do($dbh, "DELETE FROM zone_direct_axfr WHERE domain_id=?", $domain_id);
        return (undef, $e) if $e;
    }
    # A DB row is not yet distribution: rights are reconciled at once, otherwise the operator sees "Allow"
    # while AXFR is refused until the next worker pass.
    (my $m, my $me) = zone_policy_materialize($domain_id); return (undef, $me) if $me;
    return (1, undef);
}
# BULK enable/disable of direct distribution. Panel rows are written in one transaction (half an applied
# list would be a state the operator never chose); application goes through the shared path.
# Partial failure: rows are the INTENT and are saved even if the PowerDNS write failed. "Nothing changed"
# would be a lie - the intent changed and the background pass will finish it. So both are returned: what
# the panel saved and what was actually applied.
# (\%{saved,applied,failed}, undef) | (undef, err).
sub zones_direct_axfr_set {
    my ($ids, $on, $reason) = @_;
    my @clean;
    { my %seen;
      for my $x (@{ $ids || [] }) {
          return (undef, 'invalid domain_id') unless defined $x && "$x" =~ /^\d+$/;
          next if $seen{$x + 0}++; push @clean, $x + 0;
      } }
    return ({ saved => [], applied => [], failed => [] }, undef) unless @clean;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $rr, my $rre) = _check_len($reason, 'reason', 255, 0); return (undef, $rre) if $rre;

    if ($on) { for my $id (@clean) { (my $ok, my $e) = _zone_distributable($id); return (undef, "zone #$id: $e") if $e; } }

    { (my $bo, my $be) = _txn_begin($dbh); return (undef, $be) if $be; }
    my $ph = join(',', ('?') x @clean);
    if ($on) {
        for my $id (@clean) {
            (my $o, my $e) = _do($dbh, "INSERT INTO zone_direct_axfr (domain_id, reason) VALUES (?,?)
                                        ON DUPLICATE KEY UPDATE reason=VALUES(reason)", $id, $rr);
            if ($e) { eval { $dbh->rollback }; return (undef, $e); }
        }
    } else {
        (my $o, my $e) = _do($dbh, "DELETE FROM zone_direct_axfr WHERE domain_id IN ($ph)", @clean);
        if ($e) { eval { $dbh->rollback }; return (undef, $e); }
    }
    unless ($dbh->commit) { my $k = _db_err_kind($dbh->err); eval { $dbh->rollback }; return (undef, $k); }

    (my $st, my $ae) = apply_zones(\@clean);
    # A failure of the SHARED step (e.g. key reconciliation) applied nothing, but the intent is saved.
    # Catalog membership did NOT change, so it is read, not set to undef: undef made the screen drop the zone
    # from catalog lists although no catalog was touched. An unknown field must not be invented.
    if ($ae) {
        (my $cmap) = zone_catalog_map();
        return ({ saved  => \@clean,
                  zones  => [ map { { domain_id => $_, direct => ($on ? 1 : 0),
                                      catalog_id => (($cmap && $cmap->{$_}) ? $cmap->{$_}{id} : undef) } } @clean ],
                  failed => [ map { { domain_id => $_, error => $ae } } @clean ] }, undef);
    }
    # zones: the state of EACH zone after application, including those that failed - the screen must show
    # both the intent and what became of it.
    return ({ saved  => \@clean,
              zones  => [ map { { domain_id => $_->{domain_id}, direct => $_->{direct}, catalog_id => $_->{catalog_id} } } @$st ],
              failed => [ map { { domain_id => $_->{domain_id}, error => $_->{error} } } grep { $_->{error} } @$st ] }, undef);
}
# ============================================================================
# DYNAMIC UPDATES (RFC 2136) - docs/05-dns-model.md
# ============================================================================
# Who may update a zone is a property of the ZONE itself: DHCP server addresses and/or a TSIG key. The mode
# is not chosen but follows from what is set: addresses -> IP, key -> TSIG, both -> IP + TSIG (PowerDNS ANDs
# the checks: the address must be in ALLOW-DNSUPDATE-FROM, and with TSIG-ALLOW-DNSUPDATE the update must
# also be signed; for key-only any address: 0.0.0.0/0, ::/0). One key per setting - that is how DHCP servers work.
# Shared settings of many zones are kept in a Dynamic DHCP profile that zones may follow: a profile edit is
# copied into all following zones. An edit in the zone (or an unlinked zone) keeps its own values. Values
# always live on the zone, so unlinking loses nothing.
# The key is a shared panel key (tsig_keys + a PowerDNS copy) and its PowerDNS name is one per install. So
# the same name with another secret ROTATES the key everywhere it is used; if it also signs AXFR
# (Propagation, a foreign master), it is not changed here. The secret is visible in the form on purpose.
# pdns.conf is never touched: it enables update acceptance once with an EMPTY global list.
# NOTIFY-DNSUPDATE is always set: without it PowerDNS does not notify secondaries after an update. The flag
# and values are intent: the worker reconciles them to PowerDNS after failures both ways (enabled=0 - remove).
our @DYN_KINDS = ('ALLOW-DNSUPDATE-FROM', 'TSIG-ALLOW-DNSUPDATE', 'NOTIFY-DNSUPDATE');
my %DYN_ALGOS = map { $_ => 1 } qw(hmac-md5 hmac-sha1 hmac-sha224 hmac-sha256 hmac-sha384 hmac-sha512);

sub _dyn_mode_of { my ($ncidr, $haskey) = @_; return $ncidr && $haskey ? 'ip_tsig' : $ncidr ? 'ip' : $haskey ? 'tsig' : undef }
# Read and check submitted settings: { cidrs[], key{name,algorithm,secret} | empty }.
# ({mode, cidrs[], key{}|undef}, undef) | (undef, err).
sub _dyn_settings_check {
    my ($in) = @_;
    my (@cidrs, %seen);
    for my $raw (@{ ref $in->{cidrs} eq 'ARRAY' ? $in->{cidrs} : [] }) {
        next unless defined $raw && length _trim($raw);
        my $c = cidr_normalize(_trim($raw)) or return (undef, "'$raw' is not an IP address or a network");
        push @cidrs, $c unless $seen{$c}++;
    }
    my $key;
    my $k = ref $in->{key} eq 'HASH' ? $in->{key} : {};
    my ($kn, $ks) = (_trim($k->{name}), _trim($k->{secret}));
    if ((defined $kn && length $kn) || (defined $ks && length $ks)) {
        (my $n, my $ne) = _check_len($kn, 'TSIG key name', 255, 1); return (undef, $ne) if $ne;
        my $alg = lc(_trim($k->{algorithm}) // 'hmac-sha256');
        return (undef, "unknown TSIG algorithm '$alg'") unless $DYN_ALGOS{$alg};
        (my $sec, my $se) = tsig_secret_check($ks); return (undef, "TSIG key: $se") if $se;
        $key = { name => $n, algorithm => $alg, secret => $sec };
    }
    my $mode = _dyn_mode_of(scalar @cidrs, $key ? 1 : 0)
        or return (undef, 'set the DHCP server addresses, a TSIG key, or both');
    return ({ mode => $mode, cidrs => \@cidrs, key => $key }, undef);
}
# The panel key for this name/algorithm/secret: an identical one -> it; none -> new (a key created in
# PowerDNS by hand is never overwritten); another secret -> rotation, but ONLY if it is used solely by those
# the edit concerns anyway ($scope: {profile_id} - the profile and its following zones; {domain_id} - one
# zone). The PowerDNS key name is install-wide, so rotating would hit an unlinked zone, another profile or
# AXFR - then refuse: another name is needed. The rotation is NOT written here but by the caller in the same
# transaction as the settings (_dyn_key_rotate_row), otherwise a failed save would leave the secret rotated.
# PowerDNS gets it after commit (_dyn_key_rotate_push); if that fails, the worker finishes it.
# ({id, created?, rotate{name,algorithm,secret}?}, undef) | (undef, err).
sub _dyn_key_ensure {
    my ($k, $scope) = @_;
    $scope ||= {};
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $row, my $e) = _db_row($dbh, "SELECT id, name, algorithm, secret FROM tsig_keys WHERE name=?", $k->{name}); return (undef, $e) if $e;
    unless ($row) {
        (my $made, my $me) = _tsig_key_new($k); return (undef, $me) if $me;
        return ({ id => $made->{id}, created => 1 }, undef);
    }
    return ({ id => $row->{id} + 0 }, undef) if lc($row->{algorithm}) eq $k->{algorithm} && $row->{secret} eq $k->{secret};
    (my $ax, my $ae) = _db_count($dbh, "SELECT (SELECT COUNT(*) FROM secondary_group_tsig_keys WHERE tsig_key_id=?)
                                              + (SELECT COUNT(*) FROM secondary_node_tsig_keys WHERE tsig_key_id=?)", $row->{id}, $row->{id});
    return (undef, $ae) if $ae;
    my $pdns = connectPDNS() or return (undef, 'DB unavailable');
    (my $am, my $ame) = _db_count($pdns, "SELECT COUNT(*) FROM domainmetadata WHERE kind IN ('TSIG-ALLOW-AXFR','AXFR-MASTER-TSIG')
                                             AND LOWER(TRIM(TRAILING '.' FROM content)) = ?", lc $row->{name});
    return (undef, $ame) if $ame;
    return (undef, "the TSIG key '$row->{name}' also signs zone transfers — change its secret there, or use another name")
        if $ax || $am;
    # Who else holds the key among dynamic update settings, besides those the edit concerns.
    my ($pw, $zw, @b) = ('', '');
    if ($scope->{profile_id}) {
        $pw = ' AND profile_id <> ?';
        $zw = ' AND domain_id NOT IN (SELECT domain_id FROM zone_dynamic WHERE profile_id = ?)';
        @b = ($scope->{profile_id}, $scope->{profile_id});
    } elsif ($scope->{domain_id}) {
        $zw = ' AND domain_id <> ?';
        @b = ($scope->{domain_id});
    }
    (my $op, my $ope) = _db_count($dbh, "SELECT COUNT(*) FROM dyn_profile_keys WHERE tsig_key_id=?$pw", $row->{id}, ($pw ? $b[0] : ()));
    return (undef, $ope) if $ope;
    (my $oz, my $oze) = _db_count($dbh, "SELECT COUNT(*) FROM zone_dynamic_keys WHERE tsig_key_id=?$zw", $row->{id}, ($zw ? $b[-1] : ()));
    return (undef, $oze) if $oze;
    my @who = (($op ? "$op other profile(s)" : ()), ($oz ? "$oz other zone(s)" : ()));
    return (undef, "the TSIG key '$row->{name}' is also used by " . join(' and ', @who)
                 . " — changing its secret would change it there too; use another key name") if @who;
    return ({ id => $row->{id} + 0, rotate => { name => $row->{name}, algorithm => $k->{algorithm}, secret => $k->{secret} } }, undef);
}
# Secret rotation inside the save transaction (dies on error).
sub _dyn_key_rotate_row {
    my ($dbh, $kinfo) = @_;
    return unless $kinfo && $kinfo->{rotate};
    $dbh->do("UPDATE tsig_keys SET algorithm=?, secret=? WHERE id=?", undef, $kinfo->{rotate}{algorithm}, $kinfo->{rotate}{secret}, $kinfo->{id})
        or die _db_err_kind($dbh->err) . "\n";
}
# After commit, into PowerDNS. On failure a warning (the worker finishes it). Returns the warning text or undef.
sub _dyn_key_rotate_push {
    my ($kinfo) = @_;
    return undef unless $kinfo && $kinfo->{rotate};
    $kinfo->{rotated} = 1;
    (my $ok, my $pe) = _pdns_ensure_tsigkeys(_cfg('pdns_api', 'server', 'localhost'), [ $kinfo->{rotate} ]);
    delete $kinfo->{rotate};   # the secret never goes into the API response
    return $pe ? "the new key secret is saved, but PowerDNS was not updated yet ($pe) — the panel keeps retrying" : undef;
}
sub _dyn_key_of {   # settings key (zone or profile) with its secret - shown in the form
    my ($dbh, $table, $col, $id) = @_;
    (my $r, my $e) = _db_row($dbh, "SELECT k.id, k.name, k.algorithm, k.secret FROM $table x JOIN tsig_keys k ON k.id = x.tsig_key_id
                                     WHERE x.$col=? ORDER BY k.name LIMIT 1", $id);
    return (undef, $e) if $e;
    $r->{id} += 0 if $r;
    return ($r, undef);
}
sub _dyn_cidrs_of {
    my ($dbh, $table, $col, $id) = @_;
    (my $r, my $e) = _db_all($dbh, "SELECT cidr FROM $table WHERE $col=? ORDER BY cidr", { Slice => {} }, $id);
    return (undef, $e) if $e;
    return ([ map { $_->{cidr} } @$r ], undef);
}
# Zone settings. ({enabled, mode, profile_id, profile, cidrs[], key{}|undef} | undef if never set, undef) | (undef, err).
sub zone_dynamic_get {
    my ($domain_id) = @_;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $z, my $e) = _db_row($dbh, "SELECT z.enabled, z.profile_id, p.name AS profile
                                      FROM zone_dynamic z LEFT JOIN dyn_profiles p ON p.id = z.profile_id
                                     WHERE z.domain_id=?", $domain_id);
    return (undef, $e) if $e;
    return (undef, undef) unless $z;
    (my $c, $e) = _dyn_cidrs_of($dbh, 'zone_dynamic_sources', 'domain_id', $domain_id); return (undef, $e) if $e;
    (my $k, $e) = _dyn_key_of($dbh, 'zone_dynamic_keys', 'domain_id', $domain_id); return (undef, $e) if $e;
    return ({ enabled => $z->{enabled} ? 1 : 0, mode => _dyn_mode_of(scalar @$c, $k ? 1 : 0),
              profile_id => (defined $z->{profile_id} ? $z->{profile_id} + 0 : undef), profile => $z->{profile},
              cidrs => $c, key => $k }, undef);
}
# Write zone values in an open transaction ($s = {mode, cidrs[], key_id|undef}). Dies on error.
sub _dyn_zone_rows {
    my ($dbh, $domain_id, $s, $enabled, $profile_id) = @_;
    $dbh->do("INSERT INTO zone_dynamic (domain_id, enabled, mode, profile_id) VALUES (?,?,?,?)
              ON DUPLICATE KEY UPDATE enabled=VALUES(enabled), mode=VALUES(mode), profile_id=VALUES(profile_id)",
             undef, $domain_id, $enabled, $s->{mode}, $profile_id) or die _db_err_kind($dbh->err) . "\n";
    for my $t (qw(zone_dynamic_sources zone_dynamic_keys)) {
        $dbh->do("DELETE FROM $t WHERE domain_id=?", undef, $domain_id) or die _db_err_kind($dbh->err) . "\n";
    }
    $dbh->do("INSERT INTO zone_dynamic_sources (domain_id, cidr) VALUES (?,?)", undef, $domain_id, $_)
        or die _db_err_kind($dbh->err) . "\n" for @{ $s->{cidrs} };
    if ($s->{key_id}) {
        $dbh->do("INSERT INTO zone_dynamic_keys (domain_id, tsig_key_id) VALUES (?,?)", undef, $domain_id, $s->{key_id})
            or die _db_err_kind($dbh->err) . "\n";
    }
}
# What must be on the zone for these settings.
sub _dyn_want {
    my ($z) = @_;
    return { 'ALLOW-DNSUPDATE-FROM' => (@{ $z->{cidrs} } ? [ sort @{ $z->{cidrs} } ] : [ '0.0.0.0/0', '::/0' ]),
             'TSIG-ALLOW-DNSUPDATE' => ($z->{key} ? [ $z->{key}{name} ] : []),
             'NOTIFY-DNSUPDATE'     => ['1'] };
}
# Bring one zone to $want, or remove everything of ours ($want undef). Via the PowerDNS API (which also
# flushes its cache), writing only what differs, so a routine worker pass writes nothing.
# $gone collects key names removed from the zone: a key nobody references any more goes away.
# (undef) | (err, unreachable) - the latter: the API did not answer at all, no point trying the next zone.
sub _dyn_zone_apply {
    my ($domain_id, $name, $want, $gone) = @_;
    my $pdns = connectPDNS() or return ('DB unavailable');
    (my $rows, my $e) = _db_all($pdns, "SELECT kind, content FROM domainmetadata WHERE domain_id=? AND kind IN (?,?,?)",
                                { Slice => {} }, $domain_id, @DYN_KINDS);
    return ($e) if $e;
    my %cur; push @{ $cur{ $_->{kind} } }, $_->{content} for @$rows;
    my $srv = _cfg('pdns_api', 'server', 'localhost');
    for my $kind (@DYN_KINDS) {
        my @w = sort @{ ($want ? $want->{$kind} : undef) || [] };
        my @h = sort @{ $cur{$kind} || [] };
        next if join("\n", @w) eq join("\n", @h);
        (my $r, my $c, my $ae) = _pdns_api('PUT', "/api/v1/servers/$srv/zones/$name./metadata/$kind", { metadata => \@w });
        return ("$kind: $ae", ($c == 0 ? 1 : 0)) if $ae;
        return ("$kind → HTTP $c") unless $c == 200 || $c == 201 || $c == 204;
        if ($kind eq 'TSIG-ALLOW-DNSUPDATE' && $gone) { my %w = map { $_ => 1 } @w; $gone->{$_} = 1 for grep { !$w{$_} } @h; }
    }
    return ();
}
# Reconcile the listed zones in PowerDNS: an enabled primary with settings gets its values, otherwise ours
# are removed. API unreachable -> other zones are left for the worker. Keys removed from zones go away if
# unreferenced; a failed cleanup is also a failed pass (the worker turns red).
# (\%{zones, failed[]}, undef) | (undef, err).
sub _dyn_apply_zones {
    my (@ids) = @_;
    my $pdns = connectPDNS() or return (undef, 'DB unavailable');
    my (@failed, %gone, $down);
    my $n = 0;
    for my $id (@ids) {
        if ($down) { push @failed, { domain_id => $id + 0, error => "not attempted: $down" }; next }
        (my $d, my $de) = _db_row($pdns, "SELECT id, name, type FROM domains WHERE id=?", $id);
        if ($de) { push @failed, { domain_id => $id + 0, error => $de }; next }
        unless ($d) { my $dbh = connectDB(); _do($dbh, "DELETE FROM zone_dynamic WHERE domain_id=?", $id) if $dbh; next }
        (my $z, my $ze) = zone_dynamic_get($id);
        if ($ze) { push @failed, { domain_id => $id + 0, name => $d->{name}, error => $ze }; next }
        my $on = ($z && $z->{enabled} && $z->{mode} && uc($d->{type} // '') eq 'MASTER') ? 1 : 0;
        (my $ae, my $unreach) = _dyn_zone_apply($d->{id}, $d->{name}, ($on ? _dyn_want($z) : undef), \%gone);
        if ($ae) { push @failed, { domain_id => $d->{id} + 0, name => $d->{name}, error => $ae }; $down = $ae if $unreach; next }
        $n++;
    }
    for my $kn (sort keys %gone) {
        (undef, my $ke) = tsig_key_forget_unused_by_name($kn);
        push @failed, { name => "TSIG key $kn", error => "no longer used, but removing it failed: $ke" } if $ke;
    }
    return ({ zones => $n, failed => \@failed }, undef);
}
# All zones with settings, on every worker pass (drift after failures). Keys used by zones and profiles go
# first: a rotation that did not reach PowerDNS would otherwise stay a mismatch - new key in the panel, old
# in PowerDNS, and DHCP with the new one refused.
sub dynamic_materialize_all {
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $keys, my $ke) = _db_all($dbh, "SELECT DISTINCT k.name, k.algorithm, k.secret FROM tsig_keys k
                                          WHERE k.id IN (SELECT tsig_key_id FROM zone_dynamic_keys)
                                             OR k.id IN (SELECT tsig_key_id FROM dyn_profile_keys)", { Slice => {} });
    return (undef, $ke) if $ke;
    my @kfail;
    if (@$keys) {
        (my $ok, my $pe) = _pdns_ensure_tsigkeys(_cfg('pdns_api', 'server', 'localhost'), $keys);
        push @kfail, { name => 'TSIG keys', error => "not synced to PowerDNS: $pe" } if $pe;
    }
    (my $ids, my $e) = _db_all($dbh, "SELECT domain_id FROM zone_dynamic ORDER BY domain_id", { Slice => {} });
    return (undef, $e) if $e;
    (my $m, my $me) = _dyn_apply_zones(map { $_->{domain_id} } @$ids);
    return (undef, $me) if $me;
    unshift @{ $m->{failed} }, @kfail;
    return ($m, undef);
}
sub _dyn_warnings {
    my ($m, $me) = @_;
    return $me ? [ "PowerDNS was not updated yet ($me) — the panel keeps retrying" ]
               : [ map { ($_->{name} // "zone #$_->{domain_id}") . ": $_->{error}" } @{ $m->{failed} || [] } ];
}
sub zone_dynamic_map {
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $rows, my $e) = _db_all($dbh, "SELECT domain_id FROM zone_dynamic WHERE enabled=1", { Slice => {} }); return (undef, $e) if $e;
    return ({ map { $_->{domain_id} + 0 => 1 } @$rows }, undef);
}

# ---- Dynamic DHCP profiles ----
sub dyn_profiles_all {
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $rows, my $e) = _db_all($dbh, "SELECT p.id, p.name,
                                              (SELECT COUNT(*) FROM zone_dynamic z WHERE z.profile_id = p.id) AS zones
                                         FROM dyn_profiles p ORDER BY p.name", { Slice => {} });
    return (undef, $e) if $e;
    for my $p (@$rows) {
        $p->{id} += 0; $p->{zones} += 0;
        ($p->{cidrs}, $e) = _dyn_cidrs_of($dbh, 'dyn_profile_sources', 'profile_id', $p->{id}); return (undef, $e) if $e;
        ($p->{key},   $e) = _dyn_key_of($dbh, 'dyn_profile_keys', 'profile_id', $p->{id});     return (undef, $e) if $e;
        $p->{mode} = _dyn_mode_of(scalar @{ $p->{cidrs} }, $p->{key} ? 1 : 0);
    }
    return ($rows, undef);
}
# Check settings and get the key. ({mode, cidrs, key_id}, {created?, rotated?, id, name}|undef, undef) | (undef, undef, err).
sub _dyn_prepare {
    my ($in, $scope) = @_;
    (my $s, my $se) = _dyn_settings_check($in); return (undef, undef, $se) if $se;
    my ($kinfo, $key_id);
    if ($s->{key}) {
        (my $r, my $ke) = _dyn_key_ensure($s->{key}, $scope); return (undef, undef, $ke) if $ke;
        $key_id = $r->{id};
        $kinfo = { %$r, name => $s->{key}{name}, algorithm => $s->{key}{algorithm} };
    }
    return ({ mode => $s->{mode}, cidrs => $s->{cidrs}, key_id => $key_id }, $kinfo, undef);
}
# Create or rewrite a profile ($id undef = new). An edit rewrites all following zones and reconciles them
# in PowerDNS at once. ({id, name, zones, key_change?, warnings?}, undef) | (undef, err).
sub dyn_profile_save {
    my ($id, $in) = @_;
    $in ||= {};
    (my $name, my $ne) = _check_len($in->{name}, 'name', 64, 1); return (undef, $ne) if $ne;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    if (defined $id) {
        return (undef, 'invalid id') unless "$id" =~ /^\d+$/;
        (my $ex, my $e) = _db_exists($dbh, "SELECT 1 FROM dyn_profiles WHERE id=?", $id); return (undef, $e) if $e;
        return (undef, 'profile not found') unless $ex;
    }
    (my $dup, my $de) = _db_exists($dbh, "SELECT 1 FROM dyn_profiles WHERE name=? AND id<>?", $name, $id // 0); return (undef, $de) if $de;
    return (undef, "a profile named '$name' already exists") if $dup;
    (my $s, my $kinfo, my $pe) = _dyn_prepare($in, { profile_id => $id }); return (undef, $pe) if $pe;
    (my $old) = defined $id ? _dyn_key_of($dbh, 'dyn_profile_keys', 'profile_id', $id) : (undef);
    my @zones;
    my $ok = eval {
        $dbh->begin_work;
        if (defined $id) {
            $dbh->do("UPDATE dyn_profiles SET name=?, mode=? WHERE id=?", undef, $name, $s->{mode}, $id) or die _db_err_kind($dbh->err) . "\n";
            $dbh->do("DELETE FROM $_ WHERE profile_id=?", undef, $id) or die _db_err_kind($dbh->err) . "\n" for qw(dyn_profile_sources dyn_profile_keys);
        } else {
            $dbh->do("INSERT INTO dyn_profiles (name, mode) VALUES (?,?)", undef, $name, $s->{mode}) or die _db_err_kind($dbh->err) . "\n";
            $id = $dbh->last_insert_id(undef, undef, undef, undef);
        }
        $dbh->do("INSERT INTO dyn_profile_sources (profile_id, cidr) VALUES (?,?)", undef, $id, $_) or die _db_err_kind($dbh->err) . "\n" for @{ $s->{cidrs} };
        if ($s->{key_id}) { $dbh->do("INSERT INTO dyn_profile_keys (profile_id, tsig_key_id) VALUES (?,?)", undef, $id, $s->{key_id}) or die _db_err_kind($dbh->err) . "\n"; }
        _dyn_key_rotate_row($dbh, $kinfo);
        # Zones following the profile get its values in the same transaction.
        my $zr = $dbh->selectall_arrayref("SELECT domain_id, enabled FROM zone_dynamic WHERE profile_id=?", { Slice => {} }, $id)
            or die _db_err_kind($dbh->err) . "\n";
        for my $z (@$zr) { _dyn_zone_rows($dbh, $z->{domain_id}, $s, $z->{enabled}, $id); push @zones, $z->{domain_id}; }
        $dbh->commit or die "commit failed\n"; 1;
    };
    unless ($ok) {
        my $err = $@ || 'error'; chomp $err; eval { $dbh->rollback };
        tsig_keys_forget_unused($kinfo->{id}) if $kinfo && $kinfo->{created};
        return (undef, $err eq 'conflict' ? "a profile named '$name' already exists" : $err);
    }
    my $kw = _dyn_key_rotate_push($kinfo);
    (my $m, my $me) = _dyn_apply_zones(@zones);
    tsig_keys_forget_unused($old->{id}) if $old && (!$s->{key_id} || $old->{id} != $s->{key_id});
    my $w = _dyn_warnings($m, $me);
    unshift @$w, $kw if $kw;
    return ({ id => $id + 0, name => $name, mode => $s->{mode}, zones => scalar @zones,
              ($kinfo && ($kinfo->{created} || $kinfo->{rotated}) ? (key_change => $kinfo) : ()),
              (@$w ? (warnings => $w) : ()) }, undef);
}
# Delete a profile. Following zones keep their values (they live on the zone anyway) and are just
# unlinked. ({name, detached}, undef) | (undef, err).
sub dyn_profile_delete {
    my ($id) = @_;
    return (undef, 'invalid id') unless $id && "$id" =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $p, my $e) = _db_row($dbh, "SELECT id, name FROM dyn_profiles WHERE id=?", $id); return (undef, $e) if $e;
    return (undef, 'profile not found') unless $p;
    (my $n, $e) = _db_count($dbh, "SELECT COUNT(*) FROM zone_dynamic WHERE profile_id=?", $id); return (undef, $e) if $e;
    (my $key, $e) = _dyn_key_of($dbh, 'dyn_profile_keys', 'profile_id', $id); return (undef, $e) if $e;
    (my $ok, my $de) = _do($dbh, "DELETE FROM dyn_profiles WHERE id=?", $id); return (undef, $de) if $de;   # zones: SET NULL
    tsig_keys_forget_unused($key->{id}) if $key;
    return ({ id => $p->{id} + 0, name => $p->{name}, detached => $n + 0 }, undef);
}

# ---- Zone settings ----
# Save update acceptance for a zone. $in:
#   enabled         - accept (bool); absent - flag unchanged (the settings modal leaves it to Zone settings);
#   profile_id      - follow a profile: values are copied from it, and its edits propagate here;
#   otherwise cidrs / key - own values (the profile link is removed);
#   save_as_profile - a name: save the resulting values as a new profile and follow it.
# The flag may be enabled before settings exist: until then the zone accepts nothing (the "Dynamic updates"
# button appears by flag and holds the settings). Applied at once; the worker finishes failures.
# ({settings..., key_change?, created_profile?, warnings?}, undef) | (undef, err).
sub zone_dynamic_save {
    my ($domain_id, $in) = @_;
    $in ||= {};
    return (undef, 'invalid domain_id') unless $domain_id && "$domain_id" =~ /^\d+$/;
    my $pdns = connectPDNS() or return (undef, 'DB unavailable');
    (my $d, my $e) = _db_row($pdns, "SELECT id, name, type FROM domains WHERE id=?", $domain_id); return (undef, $e) if $e;
    return (undef, 'zone not found') unless $d;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    my ($s, $profile_id, $kinfo);
    (my $before) = zone_dynamic_get($domain_id);
    my $enabled = exists $in->{enabled} ? ($in->{enabled} ? 1 : 0) : (($before && $before->{enabled}) ? 1 : 0);
    if (defined $in->{profile_id} && length $in->{profile_id}) {
        return (undef, 'invalid profile id') unless "$in->{profile_id}" =~ /^\d+$/;
        (my $p, my $pe) = _db_row($dbh, "SELECT id FROM dyn_profiles WHERE id=?", $in->{profile_id}); return (undef, $pe) if $pe;
        return (undef, 'profile not found') unless $p;
        (my $c, my $ce) = _dyn_cidrs_of($dbh, 'dyn_profile_sources', 'profile_id', $p->{id}); return (undef, $ce) if $ce;
        (my $k, my $kerr) = _dyn_key_of($dbh, 'dyn_profile_keys', 'profile_id', $p->{id}); return (undef, $kerr) if $kerr;
        $s = { mode => _dyn_mode_of(scalar @$c, $k ? 1 : 0), cidrs => $c, key_id => ($k ? $k->{id} : undef) };
        $profile_id = $p->{id};
    } elsif (exists $in->{cidrs} || exists $in->{key}) {
        ($s, $kinfo, my $pe) = _dyn_prepare($in, { domain_id => $domain_id }); return (undef, $pe) if $pe;
    } else {
        # Flag only: values stay as they were (they may not exist yet).
        return ({ enabled => 0 }, undef) unless $before || $enabled;
        $s = $before ? { mode => $before->{mode}, cidrs => $before->{cidrs}, key_id => ($before->{key} ? $before->{key}{id} : undef) }
                      : { mode => undef, cidrs => [], key_id => undef };
        $profile_id = $before->{profile_id};
    }
    my $ok = eval { $dbh->begin_work; _dyn_zone_rows($dbh, $domain_id, $s, $enabled, $profile_id); _dyn_key_rotate_row($dbh, $kinfo);
                     $dbh->commit or die "commit failed\n"; 1 };
    unless ($ok) {
        my $err = $@ || 'error'; chomp $err; eval { $dbh->rollback };
        tsig_keys_forget_unused($kinfo->{id}) if $kinfo && $kinfo->{created};
        return (undef, $err);
    }
    my $kw = _dyn_key_rotate_push($kinfo);
    my $created;
    if (defined $in->{save_as_profile} && length _trim($in->{save_as_profile})) {
        (my $k) = $s->{key_id} ? _dyn_key_of($dbh, 'zone_dynamic_keys', 'domain_id', $domain_id) : (undef);
        (my $p, my $pe) = dyn_profile_save(undef, { name => $in->{save_as_profile}, cidrs => $s->{cidrs},
                                                    ($k ? (key => { name => $k->{name}, algorithm => $k->{algorithm}, secret => $k->{secret} }) : ()) });
        return (undef, "saved for the zone, but the profile was not created: $pe") if $pe;
        (my $lk, my $le) = _do($dbh, "UPDATE zone_dynamic SET profile_id=? WHERE domain_id=?", $p->{id}, $domain_id);
        if ($le) {   # a profile without the zone it was made for is useless - otherwise a retry hits "name already exists"
            dyn_profile_delete($p->{id});
            return (undef, "the zone is saved, but it was not linked to the new profile ($le) — the profile was not kept");
        }
        $created = { id => $p->{id}, name => $p->{name} };
    }
    (my $m, my $me) = _dyn_apply_zones($domain_id);
    tsig_keys_forget_unused($before->{key}{id}) if $before && $before->{key} && (!$s->{key_id} || $before->{key}{id} != $s->{key_id});
    (my $now) = zone_dynamic_get($domain_id);
    my $w = _dyn_warnings($m, $me);
    unshift @$w, $kw if $kw;
    return ({ %{ $now || {} },
              ($kinfo && ($kinfo->{created} || $kinfo->{rotated}) ? (key_change => $kinfo) : ()),
              ($created ? (created_profile => $created) : ()), (@$w ? (warnings => $w) : ()) }, undef);
}
# Disable acceptance keeping the settings (Make secondary). ({enabled=>0, warnings?}, undef) | (undef, err).
sub zone_dynamic_disable {
    my ($domain_id) = @_;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $ok, my $e) = _do($dbh, "UPDATE zone_dynamic SET enabled=0 WHERE domain_id=?", $domain_id); return (undef, $e) if $e;
    (my $m, my $me) = _dyn_apply_zones($domain_id);
    my $w = _dyn_warnings($m, $me);
    return ({ enabled => 0, (@$w ? (warnings => $w) : ()) }, undef);
}

sub direct_axfr_zones {
    my $dbh  = connectDB()   or return (undef, 'DB unavailable');
    my $pdns = connectPDNS() or return (undef, 'DB unavailable');
    (my $rows, my $e) = _db_all($dbh, "SELECT domain_id FROM zone_direct_axfr", { Slice => {} });
    return (undef, $e) if $e;
    return ([], undef) unless @$rows;
    my $ph = join(',', ('?') x @$rows);
    (my $z, my $ze) = _db_all($pdns, "SELECT id, name, type FROM domains WHERE id IN ($ph) ORDER BY name",
                              { Slice => {} }, map { $_->{domain_id} } @$rows);
    return (undef, $ze) if $ze;
    return ([ map { { domain_id => $_->{id} + 0, name => $_->{name}, type => uc($_->{type} // '') } } @$z ], undef);
}
# Recipients of DIRECT distribution: the whole Servers inventory. A node takes zones if its personal
# axfr_policy=allow or it is in at least one group with zone_axfr=1. Catalogs are irrelevant: a server may
# not support RFC 9432 and must still get a zone we give directly.
sub _inventory_zone_consumers {
    my ($dbh) = @_;
    (my $nodes, my $e) = _db_all($dbh,
        "SELECT id, name, supports_catalog, axfr_policy FROM secondary_nodes WHERE enabled=1", { Slice => {} });
    return (undef, $e) if $e;
    my @out;
    for my $nd (@$nodes) {
        my $pol = $nd->{axfr_policy} // 'inherit';
        next if $pol eq 'deny';
        my $on = ($pol eq 'allow') ? 1 : 0;
        unless ($on) {
            (my $c, my $ce) = _db_count($dbh,
                "SELECT COUNT(*) FROM secondary_group_members m JOIN secondary_groups g ON g.id=m.secondary_group_id
                  WHERE m.secondary_node_id=? AND g.zone_axfr=1", $nd->{id});
            return (undef, $ce) if $ce;
            $on = $c ? 1 : 0;
        }
        next unless $on;
        (my $ea, my $ee) = _node_effective_auth($dbh, $nd->{id}); return (undef, $ee) if $ee;
        next unless $ea->{authorized};
        push @out, { node_id => $nd->{id} + 0, name => $nd->{name}, source => 'direct',
                     catalog_capable => ($nd->{supports_catalog} ? 1 : 0),
                     auth_mode => $ea->{mode},
                     tsig_key_id => (defined $ea->{tsig_key_id} ? $ea->{tsig_key_id} + 0 : undef) };
    }
    return (\@out, undef);
}
# NOTIFY about a zone for a direct recipient: the personal notify_policy wins, else whether the node has any
# group with send_notify=1. _node_effective_notify asks the groups of ONE catalog and does not fit here.
sub _node_notify_any {
    my ($dbh, $node_id) = @_;
    (my $nr, my $e) = _db_row($dbh, "SELECT notify_policy FROM secondary_nodes WHERE id=?", $node_id);
    return (undef, $e) if $e;
    my $pol = ($nr && defined $nr->{notify_policy}) ? $nr->{notify_policy} : 'inherit';
    return (1, undef) if $pol eq 'on';
    return (0, undef) if $pol eq 'off';
    (my $c, my $ce) = _db_count($dbh,
        "SELECT COUNT(*) FROM secondary_group_members m JOIN secondary_groups g ON g.id=m.secondary_group_id
          WHERE m.secondary_node_id=? AND g.send_notify=1", $node_id);
    return (undef, $ce) if $ce;
    return (($c ? 1 : 0), undef);
}
# Catalog membership is ONE operation: set domains.catalog and reconcile rights. No intents, plans or
# queues; a failure is returned and the operator retries. Idempotent.
# ORDER: rights BEFORE switching the catalog on add (otherwise a subscriber sees the member and gets
# NOTAUTH on AXFR) and BEFORE removal (otherwise the zone is briefly announced without rights). Rights come
# from the shared computation over BOTH lists, so a zone also in direct distribution keeps them.
# $cat_id: catalog id or undef ("remove from catalog"). (1, undef) | (undef, err).
sub zone_catalog_set {
    my ($domain_id, $cat_id, $reason) = @_;
    return (undef, 'invalid domain_id') unless $domain_id && "$domain_id" =~ /^\d+$/;
    my $dbh  = connectDB()   or return (undef, 'DB unavailable');
    my $pdns = connectPDNS() or return (undef, 'DB unavailable');
    (my $z, my $ze) = _db_row($pdns, "SELECT id, name, type FROM domains WHERE id=?", $domain_id);
    return (undef, $ze) if $ze;
    return (undef, 'zone not found') unless $z;
    my $zn = _norm_fqdn($z->{name}); return (undef, 'invalid zone name') if $zn eq '';
    my $srv = _cfg('pdns_api', 'server', 'localhost');
    my $zid = "$zn.";

    my $want = '';
    if (defined $cat_id && "$cat_id" ne '') {
        return (undef, 'invalid catalog') unless "$cat_id" =~ /^\d+$/;
        # Only a primary zone can be announced: the PRODUCER announces its own zones, and a silent "fine, not
        # announced" would be false success.
        return (undef, 'only primary zones can be announced in a catalog')
            unless uc($z->{type} // '') eq 'MASTER';
        (my $c, my $ce) = _db_row($dbh, "SELECT fqdn, pdns_domain_id FROM catalogs WHERE id=?", $cat_id);
        return (undef, $ce) if $ce;
        return (undef, 'this catalog does not exist') unless $c;
        return (undef, 'this catalog is not created in PowerDNS yet') unless defined $c->{pdns_domain_id};
        $want = _norm_fqdn($c->{fqdn});
        return (undef, 'invalid catalog FQDN') if $want eq '';
    }

    # 1) rights for the future state, BEFORE switching membership
    (my $w, my $we) = zone_policy_materialize($domain_id, { assume_catalog_id => (defined $cat_id && "$cat_id" ne '' ? $cat_id + 0 : undef),
                                                            assume_no_catalog => ((defined $cat_id && "$cat_id" ne '') ? 0 : 1) });
    return (undef, $we) if $we;

    # Any failure AFTER the first write must return rights to the FACT, otherwise they reflect a state that
    # never happened: on removal the zone stays in the catalog without subscriber rights (REFUSED on AXFR), on
    # add it has rights its membership does not justify.
    my $fail = sub {
        my ($err) = @_;
        (my $r, my $re) = zone_policy_materialize($domain_id);
        return (undef, $re ? "$err (and the previous policy could not be restored: $re)" : $err);
    };

    # 2) membership in PowerDNS + read-back confirmation: PUT may report success without applying
    (my $u, my $uc, my $ue) = _pdns_api('PUT', "/api/v1/servers/$srv/zones/$zid", { catalog => ($want ne '' ? "$want." : '') });
    return $fail->($ue) if $ue;
    return $fail->("PowerDNS API set catalog → HTTP $uc") unless $uc == 204 || $uc == 200;
    (my $g, my $gc, my $ge) = _pdns_api('GET', "/api/v1/servers/$srv/zones/$zid");
    return $fail->($ge) if $ge;
    return $fail->("PowerDNS API GET zone → HTTP $gc") unless $gc == 200;
    my $got = _norm_fqdn($g->{catalog} // '');
    return $fail->("catalog not applied (got '" . ($g->{catalog} // '') . "')") unless $got eq $want;

    # 3) rights again, now by FACT. The first computation was an assumption.
    (my $w2, my $we2) = zone_policy_materialize($domain_id); return (undef, $we2) if $we2;
    return (1, undef);
}

# ZONE RECIPIENTS: the union of the two lists. The key function of the model.
# (\%{ direct, catalog_id, consumers, keys, knames, cidrs, notify }, undef) | (undef, err).
sub zone_recipients {
    my ($dbh, $domain_id, $opts) = @_;
    $opts ||= {};
    return (undef, 'invalid domain_id') unless $domain_id && "$domain_id" =~ /^\d+$/;
    (my $dm, my $de) = _db_exists($dbh, "SELECT 1 FROM zone_direct_axfr WHERE domain_id=?", $domain_id);
    return (undef, $de) if $de;
    (my $cat_id, my $ce) = zone_catalog_of($dbh, $domain_id); return (undef, $ce) if $ce;
    # assume_*: "compute as if membership were already so". Needed by exactly one caller, zone_catalog_set,
    # which must set rights BEFORE switching domains.catalog, i.e. before the fact changes.
    $cat_id = $opts->{assume_catalog_id} + 0 if $opts->{assume_catalog_id};
    $cat_id = undef                          if $opts->{assume_no_catalog};

    my (%seen, @cons);
    if ($dm) {
        (my $inv, my $ie) = _inventory_zone_consumers($dbh); return (undef, $ie) if $ie;
        for my $c (@$inv) { push @cons, $c unless $seen{ $c->{node_id} }++; }
    }
    if ($cat_id) {
        (my $sub, my $se) = _catalog_consumers($dbh, [$cat_id]); return (undef, $se) if $se;
        for my $c (@{ $sub->{$cat_id} || [] }) {
            next unless $c->{zone_axfr};   # a subscriber taking only the name list from us does not pull the zone
            push @cons, $c unless $seen{ $c->{node_id} }++;
        }
    }
    (my $keys, my $knames, my $cidrs, my $pe) = _consumers_to_policy($dbh, \@cons);
    return (undef, $pe) if $pe;
    (my $gp, my $gpe) = _zone_group_prefixes($dbh, $dm, $cat_id); return (undef, $gpe) if $gpe;
    $cidrs = [ sort keys %{ { map { $_ => 1 } @$cidrs, @$gp } } ];
    my (%nseen, @notify);
    for my $c (@cons) {
        my $on;
        if (($c->{source} // '') eq 'direct') { (my $v, my $ne) = _node_notify_any($dbh, $c->{node_id}); return (undef, $ne) if $ne; $on = $v; }
        else { (my $v, my $ne) = _node_effective_notify($dbh, $c->{node_id}, $cat_id); return (undef, $ne) if $ne; $on = $v->{on}; }
        next unless $on;
        (my $addrs, my $ae) = _node_notify_addrs($dbh, $c->{node_id}); return (undef, $ae) if $ae;
        for my $t (@$addrs) { push @notify, $t unless $nseen{$t}++; }
    }
    return ({ direct => ($dm ? 1 : 0), catalog_id => $cat_id, consumers => \@cons,
              keys => $keys, knames => $knames, cidrs => $cidrs, notify => [ sort @notify ] }, undef);
}
# THE ONLY APPLY PATH: one zone, a list or everything - one function. There used to be three (single edit,
# bulk, background pass) doing the same job slightly differently, and the differences were bugs: bulk
# reconciled keys up front while single returned BEFORE that if metadata matched (never fixing a lost key);
# the background pass visited catalog zones twice. One path closes that whole class.
# Shared data is computed ONCE per call: direct recipients, subscribers of each affected catalog, node
# NOTIFY addresses, key reconciliation with PowerDNS, current metadata of all zones. Per zone only compare
# and write differences remain.
# $ids: list of domain_id; undef = all distributable zones.
# (\@[{domain_id, name, direct, catalog_id, changed, error}], undef) | (undef, err).
sub apply_zones {
    my ($ids) = @_;
    my $dbh  = connectDB()   or return (undef, 'DB unavailable');
    my $pdns = connectPDNS() or return (undef, 'DB unavailable');

    my @want;
    if (defined $ids) {
        my %seen;
        for my $x (@$ids) {
            return (undef, 'invalid domain_id') unless defined $x && "$x" =~ /^\d+$/;
            next if $seen{$x + 0}++; push @want, $x + 0;
        }
    } else {
        (my $sz, my $se) = served_zones(); return (undef, $se) if $se;
        @want = map { $_->{domain_id} } @$sz;
    }
    return ([], undef) unless @want;
    my $ph = join(',', ('?') x @want);

    # --- shared data, read once ---------------------------------------------------------
    (my $zrows, my $ze) = _db_all($pdns, "SELECT id, name, type FROM domains WHERE id IN ($ph)", { Slice => {} }, @want);
    return (undef, $ze) if $ze;
    my %zone = map { $_->{id} + 0 => $_ } @$zrows;

    (my $drows, my $de) = _db_all($dbh, "SELECT domain_id FROM zone_direct_axfr WHERE domain_id IN ($ph)", { Slice => {} }, @want);
    return (undef, $de) if $de;
    my %direct = map { $_->{domain_id} + 0 => 1 } @$drows;

    (my $cmap, my $cme) = zone_catalog_map(); return (undef, $cme) if $cme;
    my %cat_of = map { $_ => $cmap->{$_}{id} } grep { $zone{$_} } keys %$cmap;

    # Recipients: the inventory is one list for everything; subscribers - one query per AFFECTED catalog.
    my $inv;
    if (grep { $direct{$_} } @want) { (my $i, my $ie) = _inventory_zone_consumers($dbh); return (undef, $ie) if $ie; $inv = $i; }
    my %cat_cons;
    { my %need; $need{ $cat_of{$_} } = 1 for grep { $cat_of{$_} } @want;
      if (%need) {
          (my $cc, my $cce) = _catalog_consumers($dbh, [ sort { $a <=> $b } keys %need ]); return (undef, $cce) if $cce;
          %cat_cons = %$cc;
      } }

    # NOTIFY decision and node addresses are node properties: computed once per node, not per zone.
    my (%notify_on, %notify_addr);
    my $node_notify = sub {
        my ($nid, $src, $cid) = @_;
        my $k = "$nid/" . ($src eq 'direct' ? 'd' : "c$cid");
        unless (exists $notify_on{$k}) {
            if ($src eq 'direct') { (my $v, my $e) = _node_notify_any($dbh, $nid); return (undef, $e) if $e; $notify_on{$k} = $v; }
            else { (my $v, my $e) = _node_effective_notify($dbh, $nid, $cid); return (undef, $e) if $e; $notify_on{$k} = $v->{on}; }
        }
        return ($notify_on{$k}, undef);
    };
    my $node_addrs = sub {
        my ($nid) = @_;
        unless (exists $notify_addr{$nid}) {
            (my $a, my $e) = _node_notify_addrs($dbh, $nid); return (undef, $e) if $e;
            $notify_addr{$nid} = $a;
        }
        return ($notify_addr{$nid}, undef);
    };

    # --- what each zone must have -----------------------------------------------------------------
    my (%plan, %allkeys);
    for my $id (@want) {
        next unless $zone{$id};
        my (%seen, @cons);
        if ($direct{$id}) { for my $c (@{ $inv || [] }) { push @cons, $c unless $seen{ $c->{node_id} }++; } }
        if (my $cid = $cat_of{$id}) {
            for my $c (@{ $cat_cons{$cid} || [] }) {
                next unless $c->{zone_axfr};   # a subscriber taking only the name list from us does not pull the zone
                push @cons, $c unless $seen{ $c->{node_id} }++;
            }
        }
        (my $keys, my $knames, my $cidrs, my $pe) = _consumers_to_policy($dbh, \@cons);
        return (undef, $pe) if $pe;
        (my $gp, my $gpe) = _zone_group_prefixes($dbh, $direct{$id}, $cat_of{$id}); return (undef, $gpe) if $gpe;
        $cidrs = [ sort keys %{ { map { $_ => 1 } @$cidrs, @$gp } } ];
        my (%nseen, @notify);
        for my $c (@cons) {
            (my $on, my $e) = $node_notify->($c->{node_id}, ($c->{source} // ''), $cat_of{$id});
            return (undef, $e) if $e;
            next unless $on;
            (my $addrs, my $ae) = $node_addrs->($c->{node_id}); return (undef, $ae) if $ae;
            for my $t (@$addrs) { push @notify, $t unless $nseen{$t}++; }
        }
        $plan{$id} = { keys => $keys, knames => $knames, cidrs => $cidrs, notify => [ sort @notify ] };
        $allkeys{ $_->{name} } ||= $_ for @$keys;
    }

    # Keys are reconciled ALWAYS, once: matching zone metadata says nothing about whether the key is alive
    # in PowerDNS, and without the key the zone's rights are useless.
    if (%allkeys) {
        my $srv = _cfg('pdns_api', 'server', 'localhost');
        (my $ek, my $eke) = _pdns_ensure_tsigkeys($srv, [ map { $allkeys{$_} } sort keys %allkeys ]);
        return (undef, $eke) if $eke;
    }

    # Current metadata of all zones in ONE query.
    (my $mrows, my $me) = _db_all($pdns,
        "SELECT domain_id, kind, content FROM domainmetadata
          WHERE domain_id IN ($ph) AND kind IN ('TSIG-ALLOW-AXFR','ALLOW-AXFR-FROM','ALSO-NOTIFY','SLAVE-RENOTIFY',?)",
        { Slice => {} }, @want, $DIST_POLICY_MARK);
    return (undef, $me) if $me;
    my %cur;
    push @{ $cur{ $_->{domain_id} + 0 }{ $_->{kind} } }, $_->{content} for @$mrows;

    # --- write only the differences -------------------------------------------------------------------------
    my @out;
    for my $id (@want) {
        my $st = { domain_id => $id, direct => ($direct{$id} ? 1 : 0), catalog_id => $cat_of{$id} };
        unless ($zone{$id}) { $st->{error} = 'zone not found'; push @out, $st; next; }
        $st->{name} = $zone{$id}{name};
        (my $w, my $we) = _write_zone_policy($zone{$id}, $plan{$id}, ($cur{$id} || {}));
        if ($we) { $st->{error} = $we } else { $st->{changed} = $w ? 1 : 0 }
        push @out, $st;
    }
    return (\@out, undef);
}
# Zones we serve at all: in direct distribution OR announced in some catalog. Only they have a policy;
# the rest must have none, and that must be applicable too (see zone_policy_materialize).
sub served_zones {
    my $dbh  = connectDB()   or return (undef, 'DB unavailable');
    my $pdns = connectPDNS() or return (undef, 'DB unavailable');
    (my $direct, my $de) = _db_all($dbh, "SELECT domain_id FROM zone_direct_axfr", { Slice => {} });
    return (undef, $de) if $de;
    my %ids = map { $_->{domain_id} + 0 => 1 } @$direct;
    (my $mem, my $me) = _db_all($pdns,
        "SELECT id FROM domains WHERE catalog IS NOT NULL AND catalog <> ''", { Slice => {} });
    return (undef, $me) if $me;
    $ids{ $_->{id} + 0 } = 1 for @$mem;
    return ([], undef) unless %ids;
    my @list = sort { $a <=> $b } keys %ids;
    my $ph = join(',', ('?') x @list);
    (my $z, my $ze) = _db_all($pdns, "SELECT id, name, type FROM domains WHERE id IN ($ph) ORDER BY name",
                              { Slice => {} }, @list);
    return (undef, $ze) if $ze;
    return ([ map { { domain_id => $_->{id} + 0, name => $_->{name}, type => uc($_->{type} // '') } } @$z ], undef);
}
# Apply ONE zone - the same path as a list. $opts exists for exactly one caller (zone_catalog_set), which
# must set rights BEFORE switching domains.catalog and asks to compute "as if it were already so".
sub zone_policy_materialize {
    my ($domain_id, $opts) = @_;
    return (undef, 'invalid domain_id') unless $domain_id && "$domain_id" =~ /^\d+$/;
    if ($opts && ($opts->{assume_catalog_id} || $opts->{assume_no_catalog})) {
        return _apply_one_assumed($domain_id, $opts);
    }
    (my $r, my $e) = apply_zones([$domain_id]); return (undef, $e) if $e;
    my $st = $r->[0] or return (undef, 'zone not found');
    return (undef, $st->{error}) if $st->{error};
    return ($st, undef);
}
# Same computation, but membership comes from an assumption instead of PowerDNS. A separate branch because
# the assumption is an exception: the shared path must read the fact.
sub _apply_one_assumed {
    my ($domain_id, $opts) = @_;
    my $dbh  = connectDB()   or return (undef, 'DB unavailable');
    my $pdns = connectPDNS() or return (undef, 'DB unavailable');
    (my $z, my $ze) = _db_row($pdns, "SELECT id, name, type FROM domains WHERE id=?", $domain_id);
    return (undef, $ze) if $ze;
    return (undef, 'zone not found') unless $z;
    (my $r, my $re) = zone_recipients($dbh, $domain_id, $opts); return (undef, $re) if $re;
    if (@{ $r->{keys} || [] }) {
        my $srv = _cfg('pdns_api', 'server', 'localhost');
        (my $ek, my $eke) = _pdns_ensure_tsigkeys($srv, $r->{keys}); return (undef, $eke) if $eke;
    }
    (my $mrows, my $me) = _db_all($pdns,
        "SELECT kind, content FROM domainmetadata WHERE domain_id=? AND kind IN
           ('TSIG-ALLOW-AXFR','ALLOW-AXFR-FROM','ALSO-NOTIFY','SLAVE-RENOTIFY',?)",
        { Slice => {} }, $domain_id, $DIST_POLICY_MARK);
    return (undef, $me) if $me;
    my %cur; push @{ $cur{ $_->{kind} } }, $_->{content} for @{ $mrows || [] };
    (my $w, my $we) = _write_zone_policy($z, $r, \%cur); return (undef, $we) if $we;
    return ($r, undef);
}
# Write ONE zone's policy from an already computed plan and already read current state.
# Returns (1, undef) if something was written, (0, undef) if nothing needed writing.
# renotify only makes sense for a secondary zone: it receives the zone from above and forwards NOTIFY down.
# ORDER matters and is asymmetric. _pdns_zone_set_axfr sets the panel marker FIRST on apply and removes it
# LAST on cleanup. So renotify must be REMOVED before it: if that failed after the marker was gone, the
# zone would keep SLAVE-RENOTIFY=1 without a marker and the recovery pass (which searches by marker) would
# never find it. Setting renotify, conversely, comes AFTER: the marker is already there.
sub _write_zone_policy {
    my ($z, $want, $cur) = @_;
    my $zn = _norm_fqdn($z->{name});
    return (undef, 'invalid zone name') if $zn eq '';
    my $srv = _cfg('pdns_api', 'server', 'localhost');
    my $slave = uc($z->{type} // '') eq 'SLAVE';
    my $want_renotify = @{ $want->{notify} || [] } ? 1 : 0;
    my $reno_is = (grep { $_ } @{ $cur->{'SLAVE-RENOTIFY'} || [] }) ? 1 : 0;
    my $wrote = 0;

    if ($slave && !$want_renotify && $reno_is) {
        (my $rr, my $rre) = _pdns_zone_set_renotify($srv, "$zn.", 0); return (undef, $rre) if $rre;
        $wrote = 1;
    }
    (my $w, my $we) = _pdns_zone_set_axfr($srv, "$zn.", $want->{knames}, $want->{cidrs}, $want->{notify}, $cur);
    return (undef, $we) if defined $we;
    $wrote += $w;
    if ($slave && $want_renotify && !$reno_is) {
        (my $rr, my $rre) = _pdns_zone_set_renotify($srv, "$zn.", 1); return (undef, $rre) if $rre;
        $wrote = 1;
    }
    return ($wrote, undef);
}
# Recipients -> TSIG keys and CIDRs: two recipient sources (catalog subscribers and allowed inventory
# servers), one rule turning them into rights. tsig_only gives a key; ip_only gives axfr_source addresses as
# /32 and /128. A tsig_only server's address is NOT added to the ACL: PowerDNS ORs ALLOW-AXFR-FROM and
# TSIG-ALLOW-AXFR, which would allow unsigned transfers.
sub _consumers_to_policy {
    my ($dbh, $cons) = @_;
    my (%keyids, %cidrs, @ipnodes);
    for my $c (@{ $cons || [] }) {
        my $m = $c->{auth_mode} // 'none';
        if    ($m eq 'tsig_only' && defined $c->{tsig_key_id}) { $keyids{ $c->{tsig_key_id} + 0 } = 1; }
        elsif ($m eq 'ip_only')                                { push @ipnodes, $c->{node_id} + 0; }
    }
    if (@ipnodes) {
        my $ph = join(',', ('?') x @ipnodes);
        (my $rows, my $ae) = _db_all($dbh,
            "SELECT address FROM secondary_node_endpoints
              WHERE purpose='axfr_source' AND enabled=1 AND secondary_node_id IN ($ph)",
            { Slice => {} }, @ipnodes); return (undef, undef, undef, $ae) if $ae;
        for my $r (@$rows) {
            my $a = $r->{address}; next unless defined $a && length $a;
            my $host = _is_ipv6($a) ? "$a/128" : _is_ipv4($a) ? "$a/32" : undef;
            $cidrs{$host} = 1 if defined $host;
        }
    }
    my @keys;
    for my $kid (sort { $a <=> $b } keys %keyids) {
        (my $tk, my $te) = tsig_key_secret($kid); return (undef, undef, undef, $te) if $te;
        push @keys, $tk;
    }
    return (\@keys, [ map { $_->{name} } @keys ], [ sort keys %cidrs ], undef);
}
# AXFR rights of a catalog are TWO different questions that must not be mixed:
#   'catalog' - the producer zone itself: ALL RFC 9432-capable subscribers get it. The catalog is a list of
#               names telling servers what to create; it goes also to those who take zone data elsewhere.
#   'zones'   - the zones THEMSELVES: groups we serve them to (secondary_groups.zone_axfr), regardless of
#               catalog support. Announcing a zone does not affect this list.
sub _catalog_effective_axfr {
    my ($dbh, $cid, $scope) = @_;
    $scope = 'catalog' unless defined $scope;
    (my $cons, my $e) = _catalog_consumers($dbh, [$cid]); return (undef, undef, undef, $e) if $e;
    my @picked;
    for my $c (@{ $cons->{$cid + 0} || [] }) {
        if ($scope eq 'catalog') { next unless $c->{catalog_capable}; }
        else                     { next unless $c->{zone_axfr}; }
        push @picked, $c;
    }
    return _consumers_to_policy($dbh, \@picked);
}
# Ensure TSIG keys exist and match in PowerDNS /tsigkeys (global, not per zone). (1,undef) | (undef,err).
sub _pdns_ensure_tsigkeys {
    my ($srv, $keys) = @_;
    (my $tl, my $tc, my $tge) = _pdns_api('GET', "/api/v1/servers/$srv/tsigkeys"); return (undef, $tge) if $tge;
    return (undef, "PowerDNS tsigkeys GET → HTTP $tc") unless $tc == 200;
    # Check the response shape: /tsigkeys must be a list; an unexpected reply used to die with
    # 'Not an ARRAY reference' instead of a clear error.
    return (undef, 'PowerDNS tsigkeys GET returned a non-list response') unless ref $tl eq 'ARRAY';
    my %have; for my $k (@$tl) { next unless ref $k eq 'HASH'; (my $n = lc($k->{name} // '')) =~ s/\.$//; $have{$n} = $k; }
    for my $k (@$keys) {
        my $ex = $have{ lc($k->{name}) };
        if (!$ex) { (my $r, my $pc, my $pe) = _pdns_api('POST', "/api/v1/servers/$srv/tsigkeys", { name => $k->{name}, algorithm => $k->{algorithm}, key => $k->{secret} }); return (undef, $pe) if $pe; return (undef, "PowerDNS tsigkey create '$k->{name}' → HTTP $pc") unless $pc == 201; }
        else {
            # The key is rewritten UNCONDITIONALLY, on purpose. The secret is only visible per key
            # (GET /tsigkeys/{id}), empty in the list, so checking would cost the same call as writing (plus a second
            # on mismatch). Comparing only the algorithm would miss a replaced secret - exactly what the check is for.
            # It is cheap: once PER CALL (see apply_zones), not per zone.
            my $kidp = $ex->{id} // $k->{name};
            (my $r, my $uc, my $ue) = _pdns_api('PUT', "/api/v1/servers/$srv/tsigkeys/$kidp", { algorithm => $k->{algorithm}, key => $k->{secret} });
            return (undef, $ue) if $ue;
            return (undef, "PowerDNS tsigkey update '$k->{name}' → HTTP $uc") unless $uc == 200;
        }
    }
    return (1, undef);
}
# Set delivery policy on a SPECIFIC zone: TSIG-ALLOW-AXFR (names) + ALLOW-AXFR-FROM (CIDR) + ALSO-NOTIFY
# (secondary IPs - otherwise PowerDNS changes the serial but BIND learns of it only at SOA refresh).
# PUT replaces whole values. (1,undef)|(undef,err).
# OWNERSHIP MARKER: these kinds (and SLAVE-RENOTIFY) may also be set by an admin by hand, and nothing told
# them from ours, so any scanning cleanup risked stripping a live ACL from someone else's zone. The panel
# marks ITS zones and touches only marked ones ($DIST_POLICY_MARK is declared above for _zone_policy_write).
# Order in both cases is mandatory and asymmetric:
#   apply  - marker FIRST: if the policy write fails next, the zone is still marked and the sweep finds it;
#   remove - marker LAST: while any field remains, the zone must stay in the sweep's selection.
# $cur: current zone metadata if the caller already read it; fields that are already right are not
# rewritten. Each write is a PowerDNS API call (~25 ms), noticeable on a batch; skipping is safe exactly
# because the value does not change, so there is nothing to invalidate in PowerDNS.
sub _pdns_zone_set_axfr {
    my ($srv, $zid, $knames, $cidrs, $notify, $cur) = @_;
    my $applying = (@{ $knames || [] } || @{ $cidrs || [] } || @{ $notify || [] }) ? 1 : 0;
    my $same = sub {
        my ($kind, $want) = @_;
        return 0 unless $cur;                       # current state unknown - write
        my @have = sort @{ $cur->{$kind} || [] };
        my @w    = sort @{ $want         || [] };
        return 0 unless @have == @w;
        $have[$_] eq $w[$_] or return 0 for 0 .. $#w;
        return 1;
    };
    my $mark_is = $cur ? ((@{ $cur->{$DIST_POLICY_MARK} || [] }) ? 1 : 0) : undef;
    my $wrote = 0;
    my $put = sub {
        my ($kind, $value) = @_;
        $wrote++;
        (my $r, my $c, my $e) = _pdns_api('PUT', "/api/v1/servers/$srv/zones/$zid/metadata/$kind", { metadata => $value });
        return $e if $e;
        return "$kind $zid → HTTP $c" unless $c == 200 || $c == 201;
        return undef;
    };
    # Marker FIRST on apply: if the policy write fails next, the zone is still marked and the sweep finds it.
    if ($applying && (!defined $mark_is || !$mark_is)) { my $e = $put->($DIST_POLICY_MARK, ['1']); return (undef, $e) if $e; }
    unless ($same->('TSIG-ALLOW-AXFR', $knames)) { my $e = $put->('TSIG-ALLOW-AXFR', $knames);        return (undef, $e) if $e; }
    unless ($same->('ALLOW-AXFR-FROM', $cidrs))  { my $e = $put->('ALLOW-AXFR-FROM', $cidrs);         return (undef, $e) if $e; }
    unless ($same->('ALSO-NOTIFY',     $notify)) { my $e = $put->('ALSO-NOTIFY', ($notify || []));    return (undef, $e) if $e; }
    # Marker LAST on cleanup: while any field remains, the zone must stay in the sweep's selection.
    if (!$applying && (!defined $mark_is || $mark_is)) { my $e = $put->($DIST_POLICY_MARK, []); return (undef, $e) if $e; }
    return ($wrote, undef);
}
# Where to send NOTIFY for this server: all enabled purpose='notify_target' endpoints, or if none, all
# enabled 'dns_listen' (fallback). notify_target is what docs/16-delivery.md promises; dns_listen stays
# because the inventory always has it, notify_target only when NOTIFY goes to a separate address/port.
# ALL enabled ones, not the first: a server may have several listen addresses. anycast_service never.
# PowerDNS form: "ip" or "ip:port" (port only if != 53). Sorted stably: ALSO-NOTIFY is written as a full
# replacement, and a varying order would look like a constant change. (\@targets, undef) | (undef, err).
sub _node_notify_addrs {
    my ($dbh, $node_id) = @_;
    my @out;
    for my $purpose (qw(notify_target dns_listen)) {
        (my $rows, my $e) = _db_all($dbh, "SELECT address, port FROM secondary_node_endpoints WHERE secondary_node_id=? AND purpose=? AND enabled=1 ORDER BY address, port", { Slice => {} }, $node_id, $purpose);
        return (undef, $e) if $e;
        next unless @$rows;
        for my $r (@$rows) { my $p = $r->{port} + 0; push @out, (($p && $p != 53) ? "$r->{address}:$p" : $r->{address}); }
        last;   # notify_target set -> dns_listen is not mixed in (otherwise NOTIFY would go where nobody asked)
    }
    my %seen; return ([ grep { !$seen{$_}++ } sort @out ], undef);
}
# NOTIFY targets for ZONE DATA: consumers that must get NOTIFY about changes of the zones themselves.
# The catalog zone itself is not here - it has a control channel, see _catalog_control_notify_targets.
# (\@targets, undef) | (undef, err).
sub _catalog_notify_targets {
    my ($dbh, $cid) = @_;
    # NOTIFY about the zone goes to everyone we give it to. Catalog support only decides whether the server
    # gets the catalog zone (_catalog_control_notify_targets). A former catalog_only flag, on by default for
    # member zones, made announcing a zone silently take NOTIFY away from statically configured secondaries.
    (my $cons, my $e) = _catalog_consumers($dbh, [$cid]); return (undef, $e) if $e;
    my (%seen, @out);
    for my $c (@{ $cons->{$cid + 0} || [] }) {
        next unless $c->{zone_axfr};   # does not take zones from us -> nothing to NOTIFY about
        (my $n, my $ne) = _node_effective_notify($dbh, $c->{node_id}, $cid); return (undef, $ne) if $ne;
        next unless $n->{on};
        (my $addrs, my $ae) = _node_notify_addrs($dbh, $c->{node_id}); return (undef, $ae) if $ae;
        for my $t (@$addrs) { push @out, $t unless $seen{$t}++; }   # no address - nowhere to send, the node just drops out
    }
    return ([ sort @out ], undef);
}
# NOTIFY targets of the catalog zone ITSELF - the CONTROL channel, going to ALL catalog subscribers
# regardless of notify_policy. Two different sources:
#   the catalog  - from our PowerDNS (global pdns_endpoints), one per installation;
#   zone data    - only to groups we serve (secondary_groups.zone_axfr); others take it from their upstream,
#                  a route the panel does not describe.
# notify_policy describes the second channel. It cannot apply to the first: a consumer ALWAYS takes the
# catalog from the producer, so only the producer can tell it about zones coming and going. An intermediate
# server cannot replace that - verified live (docs/16-delivery.md): its NOTIFY is rejected as `refused
# notify from non-primary`, and a zone not yet in the catalog is unknown to the consumer. With one shared
# list, notify_policy=off meant new zones arrived only at the catalog SOA refresh (3 hours here).
# The catalog_capable filter stays: a non-consumer has no catalog zone. (\@targets, undef) | (undef, err).
sub _catalog_control_notify_targets {
    my ($dbh, $cid) = @_;
    (my $cons, my $e) = _catalog_consumers($dbh, [$cid]); return (undef, $e) if $e;
    my (%seen, @out);
    for my $c (@{ $cons->{$cid + 0} || [] }) {
        next unless $c->{catalog_capable};
        (my $addrs, my $ae) = _node_notify_addrs($dbh, $c->{node_id}); return (undef, $ae) if $ae;
        for my $t (@$addrs) { push @out, $t unless $seen{$t}++; }
    }
    return ([ sort @out ], undef);
}
# Send NOTIFY to the server ABOUT THIS CATALOG? The effective value belongs to the (server, catalog) pair:
# ALSO-NOTIFY is written on a specific catalog's zones, so one server may be On for one catalog and Off
# for another. Rule:
#   notify_policy='on'|'off'  -> as is (source=override), groups do not matter;
#   'inherit'                 -> OR of send_notify of the server's groups ASSIGNED TO THIS catalog
#                               (catalog_groups). No such group (e.g. the server was added to the
#                               catalog directly) -> off.
# default_group_id does NOT take part: it is about AXFR authorization, not delivery.
# (\%{on,source,via=>[group names]}, undef) | (undef, err).
sub _node_effective_notify {
    my ($dbh, $node_id, $cid) = @_;
    (my $nr, my $e) = _db_row($dbh, "SELECT notify_policy FROM secondary_nodes WHERE id=?", $node_id); return (undef, $e) if $e;
    my $pol = ($nr && defined $nr->{notify_policy}) ? $nr->{notify_policy} : 'inherit';
    return ({ on => 1, source => 'override', via => [] }, undef) if $pol eq 'on';
    return ({ on => 0, source => 'override', via => [] }, undef) if $pol eq 'off';
    return ({ on => 0, source => 'none', via => [] }, undef) unless $cid && "$cid" =~ /^\d+$/;
    (my $rows, my $ge) = _db_all($dbh,
        "SELECT g.name, g.send_notify FROM catalog_groups b
           JOIN secondary_group_members m ON m.secondary_group_id = b.secondary_group_id
           JOIN secondary_groups g        ON g.id = b.secondary_group_id
          WHERE b.catalog_id=? AND m.secondary_node_id=? ORDER BY g.name", { Slice => {} }, $cid, $node_id);
    return (undef, $ge) if $ge;
    return ({ on => 0, source => 'none', via => [] }, undef) unless @$rows;   # got into the catalog not via a group
    my @on = map { $_->{name} } grep { $_->{send_notify} } @$rows;
    return ({ on => (@on ? 1 : 0), source => 'group',
              via => (@on ? \@on : [ map { $_->{name} } @$rows ]) }, undef);
}
# Do WE give this server the zones themselves - the same three-valued model as NOTIFY, for the same
# reason: a group is a convenient setting for fifty servers, but a single server must be able to differ.
# Previously a group member followed the group flag while a directly assigned server always got AXFR.
#   'allow'|'deny' -> as is (source=override), groups do not matter;
#   'inherit'      -> server assigned to THIS catalog DIRECTLY (catalog_nodes) -> allow: a named
#                    assignment means "serve", and a zone_axfr=0 group must not cancel it - otherwise
#                    adding the server to a group would silently switch off what the operator assigned;
#                    else OR of zone_axfr of the server's groups ASSIGNED TO THIS catalog;
#                    neither -> allow (nothing to inherit from).
# (\%{on,source,via=>[group names]}, undef) | (undef, err).
sub _node_effective_axfr {
    my ($dbh, $node_id, $cid) = @_;
    (my $nr, my $e) = _db_row($dbh, "SELECT axfr_policy FROM secondary_nodes WHERE id=?", $node_id); return (undef, $e) if $e;
    my $pol = ($nr && defined $nr->{axfr_policy}) ? $nr->{axfr_policy} : 'inherit';
    return ({ on => 1, source => 'override', via => [] }, undef) if $pol eq 'allow';
    return ({ on => 0, source => 'override', via => [] }, undef) if $pol eq 'deny';
    return ({ on => 1, source => 'none', via => [] }, undef) unless $cid && "$cid" =~ /^\d+$/;
    # A direct assignment is a standalone way in and means "serve". The resolver had lost this, leaving a
    # server assigned directly AND in a zone_axfr=0 group without zones. Not serving it = a personal deny.
    (my $dcnt, my $dce) = _db_count($dbh, "SELECT COUNT(*) FROM catalog_nodes WHERE catalog_id=? AND secondary_node_id=?", $cid, $node_id);
    return (undef, $dce) if $dce;
    return ({ on => 1, source => 'direct', via => [] }, undef) if $dcnt;
    (my $rows, my $ge) = _db_all($dbh,
        "SELECT g.name, g.zone_axfr FROM catalog_groups b
           JOIN secondary_group_members m ON m.secondary_group_id = b.secondary_group_id
           JOIN secondary_groups g        ON g.id = b.secondary_group_id
          WHERE b.catalog_id=? AND m.secondary_node_id=? ORDER BY g.name", { Slice => {} }, $cid, $node_id);
    return (undef, $ge) if $ge;
    return ({ on => 1, source => 'none', via => [] }, undef) unless @$rows;   # assigned directly, bypassing groups
    my @on = map { $_->{name} } grep { $_->{zone_axfr} } @$rows;
    return ({ on => (@on ? 1 : 0), source => 'group',
              via => (@on ? \@on : [ map { $_->{name} } @$rows ]) }, undef);
}
# ================= Direct AXFR distribution: zones that CANNOT be catalog members =================
# The producer lists catalog members with `d.type in ('MASTER','PRODUCER')`, so a SLAVE zone never gets
# into a catalog whatever domains.catalog says. It must still be passed down: the zone may belong to an
# external master with our PowerDNS as a middle tier. Hence direct distribution and the catalog are two
# INDEPENDENT lists, not "two ways to deliver one assignment".

# Catalogs the zone CAN be put in (what the picker asks).
# (\@[{catalog_id, name, fqdn, provisioned}], undef) | (undef, err).
sub catalogs_available {
    (my $cats, my $e) = catalogs_all(); return (undef, $e) if $e;
    return ([ map { { catalog_id => $_->{id}, name => $_->{name}, fqdn => $_->{fqdn},
                      provisioned => $_->{provisioned} } } @$cats ], undef);
}
# SLAVE-RENOTIFY on a zone. Without it PowerDNS sends NO NOTIFY for a secondary zone and the materialized
# ALSO-NOTIFY is silently useless -> derived from the policy, not an operator checkbox. (1,undef)|(undef,err).
sub _pdns_zone_set_renotify {
    my ($srv, $zid, $on) = @_;
    (my $r, my $c, my $e) = _pdns_api('PUT', "/api/v1/servers/$srv/zones/$zid/metadata/SLAVE-RENOTIFY", { metadata => ($on ? ['1'] : []) });
    return (undef, $e) if $e;
    return (undef, "SLAVE-RENOTIFY $zid → HTTP $c") unless $c == 200 || $c == 201;
    return (1, undef);
}
# Remove downstream policy from ONE zone (it left distribution). Only kinds the panel owns are removed
# (docs/16-delivery.md), NOTHING upstream - a secondary zone must keep receiving data from its master.
# (1,undef) | (undef,err).
sub zone_policy_clear {
    my ($domain_id) = @_;
    return (undef, 'invalid domain_id') unless $domain_id && "$domain_id" =~ /^\d+$/;
    my $pdns = connectPDNS() or return (undef, 'DB unavailable');
    (my $d, my $e) = _db_row($pdns, "SELECT id, name, type FROM domains WHERE id=?", $domain_id); return (undef, $e) if $e;
    return (1, undef) unless $d;   # zone already gone - nothing to remove
    my $zn = _norm_fqdn($d->{name}); return (1, undef) if $zn eq '';
    my $srv = _cfg('pdns_api', 'server', 'localhost');
    # SLAVE-RENOTIFY goes FIRST: the marker leaves last inside _pdns_zone_set_axfr, and while any field remains
    # the zone must stay marked, or it drops out of the sweep with leftovers.
    if (uc($d->{type} // '') eq 'SLAVE') { (my $rr, my $rre) = _pdns_zone_set_renotify($srv, "$zn.", 0); return (undef, $rre) if $rre; }
    (my $r, my $re) = _pdns_zone_set_axfr($srv, "$zn.", [], [], []); return (undef, $re) if $re;
    return (1, undef);
}
# --- Promote SLAVE -> MASTER without deleting the zone ---
# The zone moves into our ownership. Only the owner changes, not the distribution:
#   records and SOA serial are untouched (they came via AXFR and stay as they are);
#   upstream is removed (domains.master, AXFR-MASTER-TSIG, SLAVE-RENOTIFY) - it no longer means anything;
#   downstream policy (ALLOW-AXFR-FROM/TSIG-ALLOW-AXFR/ALSO-NOTIFY) is untouched - it is about serving down.
# The reverse (MASTER -> SLAVE) is zone_demote_to_secondary.
# (\%{zone, delivery_preserved}, undef) | (undef, err).
sub zone_promote_to_primary {
    my ($domain_id, $opts) = @_;
    $opts ||= {};
    return (undef, 'invalid domain_id') unless $domain_id && "$domain_id" =~ /^\d+$/;
    my $pdns = connectPDNS() or return (undef, 'DB unavailable');
    (my $d, my $de) = _db_row($pdns, "SELECT id, name, type, master FROM domains WHERE id=?", $domain_id); return (undef, $de) if $de;
    return (undef, 'zone not found') unless $d;
    return (undef, 'zone is not a secondary') unless uc($d->{type} // '') eq 'SLAVE';
    # The zone must actually be loaded: promoting an empty SLAVE zone would create an empty authoritative Primary.
    (my $soa, my $se) = _db_row($pdns, "SELECT content FROM records WHERE domain_id=? AND type='SOA' LIMIT 1", $domain_id); return (undef, $se) if $se;
    return (undef, 'zone has no SOA yet — it has not been transferred from its primary') unless $soa;
    my $zname = _norm_fqdn($d->{name}); return (undef, 'invalid zone name') if $zname eq '';

    # A migrated zone knows its old master's address, so arrival need not be guessed but can be ASKED. A SOA
    # alone proves nothing: we may hold serial 149 while the old server has 150, and promotion would replace
    # the working zone with a stale copy. Fail-closed: source unreachable or serial differs -> no promotion.
    # It can only be skipped explicitly (old server switched off, nothing to compare with) - never silently.
    # A signed zone keeps its chain of trust: the same keys the old server signs with (the DS at the registrar
    # stays), so every DNSKEY that arrived by AXFR needs its private key from the import. Checked before
    # anything changes; the keys are added before the role change and the presigned data removed after it.
    my $dnssec;
    {
        (my $sg, my $sge) = _db_row($pdns,
            "SELECT content FROM domainmetadata WHERE domain_id=? AND kind=? LIMIT 1", $domain_id, $DNSSEC_META);
        return (undef, $sge) if $sge;
        if ($sg && $sg->{content}) { ($dnssec, my $pe) = _dnssec_promote_plan($pdns, $domain_id, $zname); return (undef, $pe) if $pe; }
    }

    # Promotion with dynamic update acceptance ($opts->{dynamic}) only when the zone already has complete
    # "who may update" settings (set in Zone settings while still secondary): otherwise DHCP would be refused
    # after the role change and noticed only by missing records. Checked BEFORE the role change - there is no
    # rollback. A zone that accepted updates on the old server (X-DNSPANEL-IMPORT-DYNAMIC) is promoted ONLY
    # with acceptance, otherwise the role change would silently cut off DHCP. It can be disabled later,
    # deliberately, like on any zone.
    {
        (my $dm, my $dme) = _db_row($pdns,
            "SELECT content FROM domainmetadata WHERE domain_id=? AND kind=? LIMIT 1", $domain_id, $DYNAMIC_META);
        return (undef, $dme) if $dme;
        return (undef, 'the source server accepted dynamic updates for this zone — make it primary with dynamic updates on')
            if $dm && $dm->{content} && !$opts->{dynamic};
    }
    if ($opts->{dynamic}) {
        (my $z, my $ze) = zone_dynamic_get($domain_id); return (undef, $ze) if $ze;
        return (undef, 'set the DHCP server addresses or a TSIG key in Dynamic updates of the zone first')
            unless $z && $z->{mode};
    }

    unless ($opts->{skip_source_check}) {
        (my $src, my $ie) = _db_row($pdns,
            "SELECT content FROM domainmetadata WHERE domain_id=? AND kind=? LIMIT 1", $domain_id, $IMPORT_META);
        return (undef, $ie) if $ie;
        if ($src && defined $src->{content} && length $src->{content}) {
            my $mine = (split ' ', ($soa->{content} // ''))[2];
            my $r = dns_agent_call('soa_at', zone => $zname, server => $src->{content});
            return (undef, "the source server $src->{content} did not answer: " . ($r->{error} // 'no answer'))
                unless $r->{ok} && defined $r->{serial};
            return (undef, "we have serial " . ($mine // '?') . ", the source server $src->{content} has $r->{serial}"
                         . " — the transfer is not finished")
                unless defined $mine && $mine =~ /^\d+$/ && $r->{serial} + 0 == $mine + 0;
        }
    }

    # Promote does NOT touch distribution and need not preserve it: direct distribution and the catalog are
    # properties of the zone itself, independent of its type.
    my $preserved = 0;

    # Change the type and drop upstream via the PowerDNS API (zone-level properties + zone cache invalidation),
    # confirmed by re-read, as for a member zone's catalog change.
    # The "accept updates" intent is written BEFORE the role change, so a later failure cannot leave a Primary
    # without the flag (the worker finishes it). Without the checkbox acceptance is off (settings stay),
    # otherwise a flag left from an earlier attempt would silently make the zone dynamic. If the role change
    # fails, the flag returns to off and settings are untouched.
    { (my $x, my $xe) = _do(connectDB(), "UPDATE zone_dynamic SET enabled=? WHERE domain_id=?", ($opts->{dynamic} ? 1 : 0), $domain_id);
      return (undef, "dynamic updates: $xe") if $xe; }
    my @made_keys;
    my $undo = sub {
        my ($err) = @_;
        _do(connectDB(), "UPDATE zone_dynamic SET enabled=0 WHERE domain_id=?", $domain_id) if $opts->{dynamic};
        _pdns_api('DELETE', _cryptokeys_path($zname) . "/$_") for @made_keys;
        return (undef, $err);
    };
    # The keys go in while the zone is still a presigned secondary: PowerDNS keeps serving the old signatures,
    # and a failure here leaves the zone as it was.
    for my $k (@{ $dnssec ? $dnssec->{keys} : [] }) {
        (my $r, my $c, my $e) = _pdns_api('POST', _cryptokeys_path($zname),
            { keytype => ($k->{flags} == 257 ? 'ksk' : 'zsk'), active => ($k->{active} ? JSON::true : JSON::false),
              published => JSON::true, privatekey => $k->{privatekey} });
        return $undo->("DNSSEC key $k->{tag} was not added: " . ($e // (ref $r eq 'HASH' ? $r->{error} : undef) // "HTTP $c"))
            unless !$e && $c == 201 && ref $r eq 'HASH';
        push @made_keys, $r->{id};
    }
    # Before the point of no return: PowerDNS must hold exactly the DNSKEYs the zone is served with now.
    if (@made_keys) {
        (my $cur, my $ce) = zone_dnssec_get($domain_id);
        my %got = map { _dnskey_norm($_->{dnskey}) => 1 } @{ $cur ? $cur->{keys} : [] };
        my @bad = map { _dnskey_tag($_) } grep { !$got{$_} } @{ $dnssec->{dnskeys} };
        return $undo->($ce ? "the DNSSEC keys could not be read back: $ce"
                           : 'PowerDNS does not hold the same DNSKEY for ' . join(', ', @bad)) if $ce || @bad;
    }
    my $srv = _cfg('pdns_api', 'server', 'localhost');
    my $zid = "$zname.";
    # The outcome of the role change is decided by FACT, not the HTTP reply. A real PowerDNS refusal (an error
    # reply) - the role did not change, the intent is undone. A timeout or broken connection proves nothing:
    # PowerDNS may have changed the role and the reply was lost. Then the type is read from its DB: SLAVE -
    # definitely unchanged; MASTER - changed, continue; unreadable - stop WITHOUT undoing the intent (the zone
    # may already be Primary). Upstream and markers are left alone on an unknown outcome.
    my $fact = sub {
        (my $row, my $re) = _db_row($pdns, "SELECT type FROM domains WHERE id=?", $domain_id);
        return ($row && defined $row->{type}) ? uc($row->{type}) : '';
    };
    my $unknown = sub { return (undef, "it is not known whether the zone became primary ($_[0]) — check it before retrying") };
    my @warn;
    (my $u, my $uc, my $ue) = _pdns_api('PUT', "/api/v1/servers/$srv/zones/$zid", { kind => 'Master', masters => [] });
    if ($ue) {
        my $t = $fact->();
        return $undo->($ue) if $t eq 'SLAVE';
        return $unknown->($ue) unless $t eq 'MASTER';
        push @warn, "kind confirmed from the database (PowerDNS API: $ue)";
    } elsif (!($uc == 204 || $uc == 200)) {
        return $undo->("PowerDNS API set kind → HTTP $uc");
    } else {
        (my $g, my $gc, my $ge) = _pdns_api('GET', "/api/v1/servers/$srv/zones/$zid");
        if (!$ge && $gc == 200) {
            return $undo->("kind not applied (got '" . ($g->{kind} // '') . "')") unless lc($g->{kind} // '') eq 'master';
        } else {
            # API confirmation unavailable -> read the fact from the PowerDNS DB.
            my $t = $fact->();
            return $undo->($ge || "PowerDNS API GET zone → HTTP $gc") if $t eq 'SLAVE';   # the change definitely did NOT apply
            return $unknown->($ge || "GET → HTTP $gc") unless $t eq 'MASTER';
            push @warn, 'kind confirmed from the database (PowerDNS API did not answer)';
        }
    }

    # 3) upstream metadata is meaningless now (renotify too: it derives from downstream policy).
    #    Direct SQL, not the API: PowerDNS answers 422 "Unsupported metadata kind 'AXFR-MASTER-TSIG'" - its
    #    metadata endpoint does not serve this kind, and zone creation writes it via SQL as well.
    #    NOT fatal: the type is already changed (point of no return) and stale upstream metadata on a MASTER
    #    zone is inert; rolling back a successful role change over cosmetics is worse than a warning.
    # The removed key's name is remembered BEFORE deletion: if this was its last reference, the key is due for
    # cleanup (the caller runs it, together with the audit record).
    my $released = '';
    { (my $t, my $te) = _db_row($pdns, "SELECT content FROM domainmetadata WHERE domain_id=? AND kind='AXFR-MASTER-TSIG' LIMIT 1", $domain_id);
      $released = $t->{content} if !$te && $t && defined $t->{content}; }
    for my $kind (qw(AXFR-MASTER-TSIG SLAVE-RENOTIFY)) {
        (my $ok, my $e) = _do($pdns, "DELETE FROM domainmetadata WHERE domain_id=? AND kind=?", $domain_id, $kind);
        push @warn, "leftover $kind: $e" if $e;
    }
    # The migration marker is removed here too: the zone no longer mirrors the old server, and keeping the
    # source address would show it as "still migrating" wherever that is read.
    push @warn, 'the import marker is still on the zone'
        unless pdns_set_zone_metas($domain_id, [ [ $IMPORT_META, undef ] ]);
    # Update acceptance is applied right after the role change (a secondary cannot accept updates). A failure
    # is a warning, not a rollback: the role changed, the intent was written before, the worker finishes it.
    # The migration's "was dynamic on the old server" marker has served its purpose: the zone flag rules now.
    if ($opts->{dynamic}) {
        (my $dm, my $dme) = _dyn_apply_zones($domain_id);
        push @warn, @{ _dyn_warnings($dm, $dme) };
        push @warn, 'the dynamic-updates import marker is still on the zone'
            unless pdns_set_zone_metas($domain_id, [ [ $DYNAMIC_META, undef ] ]);
    }

    push @warn, _dnssec_promote_finish($pdns, $d, $zname, $dnssec) if $dnssec;

    # Distribution is returned as FACT, not assumption: the lists did not change, but the screen must show them
    # as they are, not as before the operation.
    my ($rec) = zone_recipients(connectDB(), $domain_id);
    return ({ zone => $zname, delivery_preserved => $preserved,
              direct     => (($rec && $rec->{direct}) ? 1 : 0),
              catalog_id => ($rec ? $rec->{catalog_id} : undef),
              tsig_released => $released,
              dynamic    => ($opts->{dynamic} ? 1 : 0),
              warnings   => \@warn }, undef);
}
# Secondary zone source: primary addresses and TSIG. ONE check for both places a source is set - the
# Primary -> Secondary role change and editing an existing secondary's source - otherwise one would
# eventually accept what the other rejects. (\@masters, $tsig, undef) | (undef, undef, 'reason').
# Upstream TSIG of a secondary zone, as a form sends it: the name of a key already in PowerDNS, or a new key
# (name, algorithm, secret) created here once and then referenced by name like any other. The zone keeps
# only the name (AXFR-MASTER-TSIG); one key serves every zone that names it. (name|'', made|undef, err)
sub upstream_tsig_resolve {
    my ($name, $new) = @_;
    if (ref $new eq 'HASH') {
        (my $m, my $e) = _tsig_key_new($new);
        return (undef, undef, $e) if $e;
        return ($m->{name}, $m, undef);
    }
    my $n = _trim($name);
    return ('', undef, undef) unless defined $n && length $n;
    # A missing key means an AXFR that silently fails; say so while the human is still in the form.
    my $pdns = connectPDNS() or return (undef, undef, 'DB unavailable');
    (my $ex, my $xe) = _db_exists($pdns, "SELECT 1 FROM tsigkeys WHERE name=?", $n); return (undef, undef, $xe) if $xe;
    return (undef, undef, "TSIG key '$n' does not exist in PowerDNS") unless $ex;
    return ($n, undef, undef);
}
# A key created for an operation that then failed is removed again, if nothing else took it meanwhile.
sub upstream_tsig_rollback {
    my ($made) = @_;
    tsig_keys_forget_unused($made->{id}) if $made && $made->{id};
    return;
}
# Keys a secondary zone can sign its transfer with: names and algorithms from PowerDNS, never secrets.
sub upstream_tsig_keys {
    my $pdns = connectPDNS() or return (undef, 'DB unavailable');
    (my $rows, my $e) = _db_all($pdns, "SELECT name, algorithm FROM tsigkeys ORDER BY name", { Slice => {} });
    return (undef, $e) if $e;
    return ([ map { { name => $_->{name}, algorithm => lc($_->{algorithm} // '') } } @$rows ], undef);
}
sub _secondary_source_fields {
    my ($pdns, $opts) = @_;
    $opts ||= {};
    return (undef, undef, 'masters must be an array') unless ref($opts->{masters}) eq 'ARRAY';
    my (@masters, %seen);
    for my $m (@{ $opts->{masters} }) {
        my $a = _trim($m); next unless defined $a && length $a;
        return (undef, undef, "invalid master address '$a' (expected IPv4/IPv6)") unless is_ip_addr($a);
        next if $seen{lc $a}++;
        push @masters, $a;
    }
    return (undef, undef, 'secondary zone requires at least one master') unless @masters;
    # TSIG: a key name in PowerDNS. Its existence is checked: a missing key means an AXFR that silently fails,
    # while the human is still in the form and can fix the typo.
    my $tsig = _trim($opts->{tsig});
    $tsig = '' unless defined $tsig;
    if (length $tsig) {
        (my $tl, my $tle) = _check_len($tsig, 'tsig', 255, 0); return (undef, undef, $tle) if $tle;
        (my $ex, my $xe) = _db_exists($pdns, "SELECT 1 FROM tsigkeys WHERE name=?", $tsig); return (undef, undef, $xe) if $xe;
        return (undef, undef, "TSIG key '$tsig' does not exist in PowerDNS") unless $ex;
    }
    return (\@masters, $tsig, undef);
}

# HAND THE ZONE TO A FOREIGN PRIMARY (Primary -> Secondary), the reverse of zone_promote_to_primary.
# The zone stops being ours: records arrive via AXFR and are not edited by hand, and our current records
# are replaced by what comes from above. Back only via Make primary.
# The CATALOG membership is removed: a PRODUCER announces only its own zones, a secondary is never in a
# catalog. We do it OURSELVES (the form says so up front) rather than making the human do by hand the only
# thing possible anyway. DIRECT distribution is untouched: a secondary can be served down too.
# $opts: { masters => [...], tsig => 'keyname'|'' }.
# (\%{zone, masters, tsig, catalog_removed, direct, sync, warnings}, undef) | (undef, err).
sub zone_demote_to_secondary {
    my ($domain_id, $opts) = @_;
    $opts ||= {};
    return (undef, 'invalid domain_id') unless $domain_id && "$domain_id" =~ /^\d+$/;
    my $pdns = connectPDNS() or return (undef, 'DB unavailable');
    (my $d, my $de) = _db_row($pdns, "SELECT id, name, type, catalog FROM domains WHERE id=?", $domain_id); return (undef, $de) if $de;
    return (undef, 'zone not found') unless $d;
    my $type = uc($d->{type} // '');
    return (undef, 'zone is already a secondary') if $type eq 'SLAVE';
    # PRODUCER/CONSUMER are catalog zones; their role is not editable - they are an inventory, not a served zone.
    return (undef, "zone type $type cannot be turned into a secondary") unless $type eq 'MASTER' || $type eq 'NATIVE';
    my $zname = _norm_fqdn($d->{name}); return (undef, 'invalid zone name') if $zname eq '';

    (my $masters, my $tsig, my $fe) = _secondary_source_fields($pdns, $opts);
    return (undef, $fe) if $fe;

    my @warn;
    # 1) Catalog BEFORE the type change: zone_catalog_set takes only primary zones and would refuse afterwards,
    #    leaving a secondary announced in the catalog. A refusal here is fatal.
    my $cat_removed = 0;
    my $cat_id;
    if (defined $d->{catalog} && length $d->{catalog}) {
        (my $cid, my $cide) = zone_catalog_of(connectDB(), $domain_id);
        return (undef, "zone stays primary: could not read its catalog: $cide") if $cide;
        $cat_id = $cid;
        (my $ok, my $ce) = zone_catalog_set($domain_id, undef, 'demote to secondary');
        return (undef, "zone stays primary: could not remove it from the catalog: $ce") if $ce;
        $cat_removed = 1;
    }
    # The catalog was removed BEFORE the type change, so on a CONFIRMED type change refusal the zone would stay
    # primary but outside the catalog - a silent half operation. Membership is restored and the outcome reported.
    my $fail = sub {
        my ($msg) = @_;
        return (undef, $msg) unless $cat_removed;
        (my $r, my $re) = zone_catalog_set($domain_id, $cat_id, 'make secondary failed');
        return (undef, $re ? "$msg; the zone stays primary but is NO LONGER in its catalog ($re) — put it back in Zone settings"
                           : "$msg; the zone stays primary and was put back into its catalog");
    };

    # 2) ALL PREPARATION IN ONE TRANSACTION, and only then is PowerDNS told.
    #    Type, primary addresses, key, last_check reset and wiping local records are one change. Split up,
    #    there is a window: PowerDNS sees a secondary with the new source, receives it, and the late wipe
    #    deletes records that ALREADY ARRIVED. So the PowerDNS DB is brought to its final state first, and
    #    PowerDNS is told below, in step 4.
    #    Direct SQL (as for zone creation and source edits): the API cannot do it whole - its metadata endpoint
    #    does not serve AXFR-MASTER-TSIG (422), and records are edited separately, with no atomicity.
    { (my $bo, my $be) = _txn_begin($pdns); return $fail->($be) if $be; }
    my $tfail = sub { my ($e) = @_; eval { $pdns->rollback }; return $fail->($e) };
    { my $rows = $pdns->do("UPDATE domains SET type='SLAVE', master=?, last_check=0
                             WHERE id=? AND type IN ('MASTER','NATIVE')",
                           undef, join(',', @$masters), $domain_id);
      return $tfail->(_db_err_kind($pdns->err)) unless defined $rows;
      return $tfail->('zone is no longer a primary') if $rows eq '0E0'; }
    { my $d = $pdns->do("DELETE FROM domainmetadata WHERE domain_id=? AND kind='AXFR-MASTER-TSIG'", undef, $domain_id);
      return $tfail->(_db_err_kind($pdns->err)) unless defined $d; }
    if (length $tsig) {
        my $i = $pdns->do("INSERT INTO domainmetadata (domain_id, kind, content) VALUES (?, 'AXFR-MASTER-TSIG', ?)",
                          undef, $domain_id, $tsig);
        return $tfail->(_db_err_kind($pdns->err)) unless defined $i;
    }
    # Local records are wiped: the zone is no longer ours and its content belongs to the primary. Keeping them
    # would serve a foreign zone with our stale data that looks alive. It also keeps state honest: until the
    # transfer arrives there is nothing to serve, and "served" again means "arrived".
    { my $d = $pdns->do("DELETE FROM records WHERE domain_id=?", undef, $domain_id);
      return $tfail->(_db_err_kind($pdns->err)) unless defined $d; }
    unless ($pdns->commit) { my $k = _db_err_kind($pdns->err); eval { $pdns->rollback }; return $fail->($k); }

    # 3) Downstream distribution is unchanged, but its DETAILS depend on the type: a secondary we serve further
    #    needs SLAVE-RENOTIFY. The shared recomputation handles it - the rule is not repeated here.
    { (my $res, my $ae) = apply_zones([ $domain_id + 0 ]);
      push @warn, "downstream policy was not applied: $ae" if $ae;
      push @warn, "downstream policy: $_->{error}" for grep { $_->{error} } @{ $res || [] }; }

    #    A secondary never accepts dynamic updates - its master updates it. The flag and our fields are removed.
    { (my $dr, my $dre) = zone_dynamic_disable($domain_id);
      push @warn, "dynamic updates were not turned off: $dre" if $dre;
      push @warn, @{ $dr->{warnings} } if $dr && $dr->{warnings}; }

    # 4) NOW tell PowerDNS: it reloads the zone and requests AXFR, the panel records the outcome.
    #    The same final step as zone creation, which is built for an empty SLAVE zone.
    my $sync = zone_activate_after_create($domain_id);

    my ($rec) = zone_recipients(connectDB(), $domain_id);
    return ({ zone => $zname, masters => $masters, tsig => $tsig,
              catalog_removed => $cat_removed,
              direct   => (($rec && $rec->{direct}) ? 1 : 0),
              sync     => $sync,
              warnings => \@warn }, undef);
}
# --- Secondary zone source (Edit upstream) ---
# Changes ONLY where the zone comes from: primary addresses and TSIG for AXFR. Records, SOA serial and
# downstream distribution (ALLOW-AXFR-FROM / TSIG-ALLOW-AXFR / ALSO-NOTIFY, catalog) are untouched.
# Written in ONE transaction directly to gmysql (as at zone creation): address and key are one source, and
# "new key with old address" must never exist even for a second. (An earlier API-based version rolled back
# by hand, missed branches and left zones with a mismatched source that silently stopped transferring;
# the API cannot do it whole anyway - no AXFR-MASTER-TSIG, 422.)
# After commit - rediscover (the zone cache holds the primary list too); AXFR is started by the sync loop.
# SLAVE-RENOTIFY is NOT touched here: it concerns serving the zone FURTHER, is derived from policy
# (_pdns_zone_set_renotify), and is not the operator's to set.
# $opts: { masters => [...], tsig => 'keyname'|'' }.
# (\%{zone, masters, tsig, warnings}, undef) | (undef, err).
sub zone_secondary_source_set {
    my ($domain_id, $opts) = @_;
    $opts ||= {};
    return (undef, 'invalid domain_id') unless $domain_id && "$domain_id" =~ /^\d+$/;
    my $pdns = connectPDNS() or return (undef, 'DB unavailable');
    (my $d, my $de) = _db_row($pdns, "SELECT id, name, type, master FROM domains WHERE id=?", $domain_id); return (undef, $de) if $de;
    return (undef, 'zone not found') unless $d;
    return (undef, 'zone is not a secondary') unless uc($d->{type} // '') eq 'SLAVE';
    my $zname = _norm_fqdn($d->{name}); return (undef, 'invalid zone name') if $zname eq '';
    # The old key, before writing: if the zone was its last reference, it is garbage after the source change.
    my $was_tsig = '';
    { (my $t, my $te) = _db_row($pdns, "SELECT content FROM domainmetadata WHERE domain_id=? AND kind='AXFR-MASTER-TSIG' LIMIT 1", $domain_id);
      $was_tsig = $t->{content} if !$te && $t && defined $t->{content}; }

    # Source check SHARED with the Primary -> Secondary role change: one rule, one place.
    (my $mref, my $tsig, my $fe) = _secondary_source_fields($pdns, $opts);
    return (undef, $fe) if $fe;
    my @masters = @$mref;
    # ONE transaction: address and key are one source with no intermediate states (see above).
    # UPDATE is limited to type='SLAVE': the type may change between check and write (concurrent Promote).
    { (my $bo, my $be) = _txn_begin($pdns); return (undef, $be) if $be; }
    my $fail = sub { my ($e) = @_; eval { $pdns->rollback }; return (undef, $e); };
    # last_check is reset with the address: the old "checked with primary" mark belongs to ANOTHER server, and
    # with 0 PowerDNS goes to the new one at once rather than on the old schedule.
    { my $rows = $pdns->do("UPDATE domains SET master=?, last_check=0 WHERE id=? AND type='SLAVE'", undef, join(',', @masters), $domain_id);
      return $fail->(_db_err_kind($pdns->err)) unless defined $rows;
      return $fail->('zone is not a secondary') if $rows eq '0E0'
          && !$pdns->selectrow_array("SELECT 1 FROM domains WHERE id=? AND type='SLAVE'", undef, $domain_id); }
    { my $d = $pdns->do("DELETE FROM domainmetadata WHERE domain_id=? AND kind='AXFR-MASTER-TSIG'", undef, $domain_id);
      return $fail->(_db_err_kind($pdns->err)) unless defined $d; }
    if (length $tsig) {
        my $i = $pdns->do("INSERT INTO domainmetadata (domain_id, kind, content) VALUES (?, 'AXFR-MASTER-TSIG', ?)", undef, $domain_id, $tsig);
        return $fail->(_db_err_kind($pdns->err)) unless defined $i;
    }
    unless ($pdns->commit) { my $k = _db_err_kind($pdns->err); eval { $pdns->rollback }; return (undef, $k); }

    # PowerDNS's zone cache holds the primary list too - without rediscover it would use the old address until
    # the next cache refresh. A failure here is NOT a rollback: the source is written, and the sync loop (and
    # the worker on its next pass) runs the same rediscover - hence a warning.
    my @warn;
    { my $rd = dns_agent_call('rediscover');
      push @warn, 'PowerDNS was not told to re-read the zone: ' . ($rd->{error} // 'agent error')
          unless $rd->{ok} && !$rd->{_unreachable}; }
    return ({ zone => $zname, masters => \@masters, tsig => $tsig,
              tsig_released => (lc($was_tsig) eq lc($tsig) ? '' : $was_tsig),
              warnings => \@warn }, undef);
}



# DRIFT NOBODY SEES: a zone nobody serves any more that still carries our policy (TSIG-ALLOW-AXFR /
# ALLOW-AXFR-FROM / ALSO-NOTIFY). Regular self-heal visits served zones only, so this leftover would live
# forever. It comes not only from deletes but from any change made while PowerDNS was down, so this is a
# general self-healing rule: our policy on an unserved zone is drift and is removed.
# ONLY marked zones (X-DNSPANEL-POLICY) are touched: without the marker ours cannot be told from a hand-set
# value, and a zone without it never enters the selection.
# Exclusions, all mandatory:
#   * catalog members (domains.catalog non-empty) - the catalog side owns them;
#   * catalog zones THEMSELVES (PRODUCER / a catalogs row) - they always carry policy and are an inventory,
#     not a served zone; without this the sweep stripped TSIG/ALSO-NOTIFY from a working catalog (seen live);
#   * zones someone serves (served_zones) - their policy is legitimate.
# (\@cleaned_names, \@errors).
sub orphan_policy_sweep {
    my $pdns = connectPDNS() or return ([], ['DB unavailable']);
    (my $rows, my $e) = _db_all($pdns,
        "SELECT DISTINCT d.id, d.name, d.type FROM domainmetadata m JOIN domains d ON d.id = m.domain_id
          WHERE m.kind = ?
            AND (d.catalog IS NULL OR d.catalog = '')
          ORDER BY d.name", { Slice => {} }, $DIST_POLICY_MARK);
    return ([], [$e]) if $e;
    my $dbh = connectDB() or return ([], ['DB unavailable']);
    (my $crows, my $ce0) = _db_all($dbh, "SELECT fqdn FROM catalogs", { Slice => {} });
    return ([], [$ce0]) if $ce0;
    my %is_catalog = map { (_norm_fqdn($_->{fqdn}) => 1) } @$crows;
    # "Someone serves the zone" is exactly two lists: direct distribution and catalog membership, asked
    # directly (ONE query per pass). It includes zones assigned to a catalog but not yet applied to
    # domains.catalog - otherwise the sweep would strip rights a catalog add just set.
    my %assigned;
    { (my $sz, my $sze) = served_zones(); return ([], [$sze]) if $sze;
      $assigned{ $_->{domain_id} + 0 } = 1 for @$sz; }
    my (@cleaned, @err);
    for my $d (@$rows) {
        next if uc($d->{type} // '') eq 'PRODUCER';           # the catalog zone itself is not served
        next if $is_catalog{ _norm_fqdn($d->{name}) };        # ...nor one listed as such in dns_panel
        next if $assigned{ $d->{id} + 0 };                    # someone serves the zone - the policy is legitimate
        (my $ok, my $ce) = zone_policy_clear($d->{id});
        if ($ce) { push @err, "zone $d->{name}: $ce"; next; }
        push @cleaned, $d->{name};
    }
    return (\@cleaned, \@err);
}
# Mutual exclusion for reconciling distribution (policy + membership). The worker APPLIES membership
# (retry after a PowerDNS failure), and two concurrent runs could race on domains.catalog. Live tests use
# the same lock to avoid overlapping a background run.
# ($got, undef) | (undef, err); $got=0 means "busy", not an error.
sub policy_lock {
    my ($timeout) = @_;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    my ($got) = $dbh->selectrow_array("SELECT GET_LOCK(?, ?)", undef, 'dns-panel:distribution-reconcile', ($timeout // 0) + 0);
    return (undef, 'lock acquisition error') unless defined $got;
    return ($got ? 1 : 0, undef);
}
sub policy_unlock {
    my $dbh = connectDB() or return;
    $dbh->do("DO RELEASE_LOCK(?)", undef, 'dns-panel:distribution-reconcile');
    return 1;
}
# ONE recomputation for everything: policy of all served zones plus policy of the catalog zones themselves.
# Zones are visited EXACTLY ONCE (the background pass used to visit catalog members twice: 19 runs for
# 13 zones). A catalog zone needs ITS OWN policy (all RFC 9432-capable subscribers get it), and only that is
# computed here. (\@errors).
sub policy_refresh {
    my @err;
    { (my $r, my $e) = apply_zones(undef);
      if ($e) { push @err, "zones: $e" }
      else { push @err, "$_->{name}: $_->{error}" for grep { $_->{error} } @$r } }
    my $dbh = connectDB() or return [@err, 'DB unavailable'];
    (my $cats, my $ce) = _db_all($dbh, "SELECT id FROM catalogs WHERE pdns_domain_id IS NOT NULL", { Slice => {} });
    return [@err, $ce] if $ce;
    for my $c (@$cats) {
        (my $r, my $e) = catalog_axfr_materialize($c->{id});
        if ($e) {
            push @err, "catalog #$c->{id}: $e";
            _do($dbh, "UPDATE catalogs SET last_error=? WHERE id=?", substr($e, 0, 255), $c->{id});
            next;
        }
        _do($dbh, "UPDATE catalogs SET last_error=NULL WHERE id=?", $c->{id});
    }
    return \@err;
}

# ================= Catalog provisioning =================
# RFC 9432: PowerDNS manages member zones itself (the `catalog` property); the panel does NOT write PTRs.
# desired = the WANTED configuration (no observed fields); observed = FACT. Strictly separate.
our @DIST_PLAN_ACTIONS = qw(CREATE_CATALOG ADD_MEMBER REMOVE_MEMBER MIGRATE_MEMBER DELETE_CATALOG);

# Canonical catalog FQDN (one form for storage/comparison/hashing) via dns_validate_zonename: lowercase, NO dot.
# An invalid/empty name -> '' (matches no valid one).
sub _norm_fqdn { my ($f) = @_; my ($n) = dns_validate_zonename($f); return defined $n ? $n : ''; }

# Consumers of one catalog, deduplicated by node_id (first wins).
sub _dedup_consumers {
    my ($list) = @_; my (%seen, @out);
    for my $c (@{ $list || [] }) { my $n = $c->{node_id} + 0; next if $seen{$n}++; push @out, $c; }
    return [ sort { ($a->{node_id} + 0) <=> ($b->{node_id} + 0) } @out ];
}









# --- catalog_nodes: direct (individual) assignment of a node to a catalog. ---
# Nodes assigned to the catalog directly (Catalog -> Servers -> Individual).
sub catalog_nodes_get {
    my ($cid) = @_;
    return (undef, 'invalid') unless $cid && "$cid" =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $rows, my $e) = _db_all($dbh,
        "SELECT secondary_node_id FROM catalog_nodes WHERE catalog_id=? ORDER BY secondary_node_id",
        { Slice => {} }, $cid); return (undef, $e) if $e;
    return ([ map { $_->{secondary_node_id}+0 } @$rows ], undef);
}
# Batch: node_id => [catalog_id,...] of direct assignments (Catalogs column/multiselect on the Servers tab).
sub nodes_catalogs_map {
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $rows, my $e) = _db_all($dbh, "SELECT secondary_node_id, catalog_id FROM catalog_nodes", { Slice => {} }); return (undef, $e) if $e;
    my %m; push @{ $m{ $_->{secondary_node_id}+0 } }, $_->{catalog_id}+0 for @$rows;
    return (\%m, undef);
}
# Atomic full replacement of a NODE's direct catalog assignments (Servers tab: add/edit server).
sub node_catalogs_set {
    my ($node_id, $cat_ids) = @_;
    return (undef, 'invalid node') unless $node_id && $node_id =~ /^\d+$/;
    $cat_ids = [] unless ref($cat_ids) eq 'ARRAY';
    my (%seen, @clean);
    for my $x (@$cat_ids) { return (undef, 'invalid catalog id') unless defined $x && "$x" =~ /^\d+$/ && $x > 0; next if $seen{$x+0}++; push @clean, $x+0; }
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $nx, my $ne) = _db_exists($dbh, "SELECT 1 FROM secondary_nodes WHERE id=?", $node_id); return (undef, $ne) if $ne;
    return (undef, 'unknown server') unless $nx;
    if (@clean) {
        my $ph = join(',', ('?') x @clean);
        (my $cnt, my $ce) = _db_count($dbh, "SELECT COUNT(*) FROM catalogs WHERE id IN ($ph)", @clean); return (undef, $ce) if $ce;
        return (undef, 'unknown catalog') unless $cnt == scalar(@clean);
    }
    { (my $bo, my $be) = _txn_begin($dbh); return (undef, $be) if $be; }
    (my $od, my $de) = _do($dbh, "DELETE FROM catalog_nodes WHERE secondary_node_id=?", $node_id);
    if ($de) { eval { $dbh->rollback }; return (undef, $de); }
    for my $aid (@clean) {
        (my $oi, my $ie) = _do($dbh, "INSERT INTO catalog_nodes (catalog_id, secondary_node_id) VALUES (?,?)", $aid, $node_id);
        if ($ie) { eval { $dbh->rollback }; return (undef, $ie); }
    }
    unless ($dbh->commit) { my $k = _db_err_kind($dbh->err); eval { $dbh->rollback }; return (undef, $k); }
    return (1, undef, \@clean);   # canonical list of assigned catalogs (for the endpoint response)
}
# Remove ONE direct assignment (Catalog -> Servers -> Individual -> Remove). Idempotent.
sub catalog_node_remove {
    my ($cid, $node_id) = @_;
    return (undef, 'invalid') unless $cid && "$cid" =~ /^\d+$/ && $node_id && $node_id =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $o, my $e) = _do($dbh, "DELETE FROM catalog_nodes WHERE catalog_id=? AND secondary_node_id=?", $cid, $node_id);
    return (undef, $e) if $e;
    return (1, undef);
}




# Is the node ready for AXFR in the group's context: group mode/ACL(cidr)/TSIG + coverage of the node's axfr-source. (bool, err).
sub _group_node_auth {
    my ($dbh, $gid, $node_id, $node_name) = @_;
    (my $grow, my $e) = _db_row($dbh, "SELECT axfr_auth_mode FROM secondary_groups WHERE id=?", $gid); return (0, $e) if $e;
    return (0, undef) unless $grow;
    my $mode = $grow->{axfr_auth_mode};
    (my $ntsig, $e) = _db_count($dbh, "SELECT COUNT(*) FROM secondary_group_tsig_keys WHERE secondary_group_id=? AND is_primary=1", $gid); return (0, $e) if $e;
    (my $srows, $e) = _db_all($dbh, "SELECT address FROM secondary_node_endpoints WHERE secondary_node_id=? AND purpose='axfr_source' AND enabled=1", { Slice => {} }, $node_id); return (0, $e) if $e;
    my @src = map { $_->{address} } @$srows;
    my $r = axfr_readiness({ mode => $mode, tsig_count => $ntsig,
                            nodes => [ { name => $node_name, has_axfr_source => (@src ? 1 : 0) } ] });
    # issues go out: "incomplete" without a reason is a useless badge, and the reason is already computed here.
    return ($r->{consumer_ready} ? 1 : 0, undef, $r->{issues});
}
sub _consumer_node_record {
    my ($n) = @_;
    return { node_id           => $n->{id} + 0,
             catalog_capable   => ($n->{supports_catalog} ? 1 : 0),
             zone_axfr         => ($n->{zone_axfr} ? 1 : 0),
             provisioning_mode => ($n->{provisioning_mode} // 'manual'),
             _auth             => 0 };
}

# Catalog subscribers: groups -> nodes (dedup by node_id) plus servers assigned to the catalog by name.
# Keyed by catalog_id. ({ cid => [ {node_id, zone_axfr, catalog_capable, auth_mode, tsig_key_id, ...} ] }, undef).
sub _catalog_consumers {
    my ($dbh, $cat_ids) = @_;
    my %out;
    for my $cid (@{ $cat_ids || [] }) {
        $cid += 0;
        (my $rows, my $e) = _db_all($dbh,
            "SELECT n.id, n.name, n.enabled, n.supports_catalog, n.axfr_policy, n.notify_policy,
                    g.id AS group_id, g.zone_axfr
               FROM catalog_groups cg
               JOIN secondary_groups g ON g.id = cg.secondary_group_id
               JOIN secondary_group_members m ON m.secondary_group_id = g.id
               JOIN secondary_nodes n ON n.id = m.secondary_node_id AND n.enabled = 1
              WHERE cg.catalog_id = ?
              UNION
             SELECT n.id, n.name, n.enabled, n.supports_catalog, n.axfr_policy, n.notify_policy,
                    NULL AS group_id, 1 AS zone_axfr
               FROM catalog_nodes cn
               JOIN secondary_nodes n ON n.id = cn.secondary_node_id AND n.enabled = 1
              WHERE cn.catalog_id = ?", { Slice => {} }, $cid, $cid);
        return (undef, $e) if $e;
        # A server may join a catalog by SEVERAL paths (two groups and/or by name). "Do we give it zones" is then
        # an OR: one allowing path is enough. Taking the first row would depend on DB result order, i.e. be random.
        my (%by, @order);
        for my $r (@$rows) {
            my $nid = $r->{id} + 0;
            push @order, $nid unless exists $by{$nid};
            $by{$nid} ||= { name => $r->{name}, supports_catalog => $r->{supports_catalog},
                            axfr_policy => $r->{axfr_policy}, zone_axfr => 0 };
            $by{$nid}{zone_axfr} = 1 if $r->{zone_axfr};
        }
        my @list;
        for my $nid (@order) {
            my $r = $by{$nid};
            (my $ea, my $ee) = _node_effective_auth($dbh, $nid); return (undef, $ee) if $ee;
            next unless $ea->{authorized};
            # A personal axfr_policy beats any group. It is about ZONE DATA only: a server denied AXFR still
            # subscribes to the catalog (it takes the zones from its own upstream) and must keep getting it.
            my $pol = $r->{axfr_policy} // 'inherit';
            push @list, { node_id => $nid, name => $r->{name}, source => 'catalog',
                          zone_axfr       => (($pol eq 'allow') ? 1 : ($pol eq 'deny') ? 0 : ($r->{zone_axfr} ? 1 : 0)),
                          # RFC 9432 support is a property of the server itself; groups answer another question - whether we
                          # give them the zones (zone_axfr).
                          catalog_capable => ($r->{supports_catalog} ? 1 : 0),
                          auth_mode   => $ea->{mode},
                          tsig_key_id => (defined $ea->{tsig_key_id} ? $ea->{tsig_key_id} + 0 : undef) };
        }
        $out{$cid} = \@list;
    }
    return (\%out, undef);
}




# ================= Apply executor (writes ONLY via the PowerDNS HTTP API) =================
# A deliberate transport choice: PowerDNS does not recommend raw SQL for mutations (the gmysql schema changes
# between versions - catalog support already required a migration). The HTTP API is the supported contract:
# it validates fields, hides the physical schema and knows kind/catalog as official properties. Reading via
# gmysql is fine.
# Local API client (config pdns_api.{url,key,server}). ($data|undef, $http_code, $transport_err); any HTTP reply -> err=undef.
sub _pdns_api {
    my ($method, $path, $body) = @_;
    my $url = get_config_value('pdns_api', 'url'); my $key = _secret_file('pdns_api', 'key_file');
    return (undef, 0, 'PowerDNS API not configured (config pdns_api.url/key)') unless defined $url && length $url && defined $key && length $key;
    require LWP::UserAgent; require HTTP::Request;
    my $ua = LWP::UserAgent->new(timeout => _cfg('pdns_api', 'timeout', 10) + 0);
    my $req = HTTP::Request->new($method => "$url$path");
    $req->header('X-API-Key' => $key);
    if (defined $body) { $req->header('Content-Type' => 'application/json'); $req->content(JSON->new->utf8->canonical->encode($body)); }
    my $res = $ua->request($req);
    # LWP marks client-side responses (no real HTTP reply: connection refused/timeout/DNS) with
    # "Client-Warning: Internal response" - lowercase r. It was compared with a capital R, so API unavailability
    # was never detected and looked like HTTP 500 from PowerDNS itself.
    return (undef, 0, 'PowerDNS API unreachable: ' . $res->status_line) if lc($res->header('Client-Warning') // '') eq 'internal response';
    my $data; my $c = $res->content; $data = eval { JSON->new->utf8->decode($c) } if defined $c && length $c;
    return ($data, $res->code + 0, undef);   # a real HTTP reply - the caller inspects the code
}

# Policy on the catalog's producer zone ITSELF plus the rights of its member zones.
# Two recipient sets, DIFFERENT questions: all RFC 9432-capable subscribers get the catalog (it tells servers
# what to create even if they take data elsewhere); zones go to groups we serve. ALSO-NOTIFY differs too:
# a catalog change must reach all subscribers at once, otherwise a new zone is seen only at the catalog's
# SOA refresh (hours here). Idempotent. (\%summary, undef) | (undef, err).
sub catalog_axfr_materialize {
    my ($cid) = @_;
    return (undef, 'not found') unless $cid && "$cid" =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $cat, my $e) = _db_row($dbh, "SELECT fqdn, pdns_domain_id FROM catalogs WHERE id=?", $cid); return (undef, $e) if $e;
    return (undef, 'not found') unless $cat;
    return ({ skipped => 'not provisioned' }, undef) unless defined $cat->{pdns_domain_id};
    my $fqdn = _norm_fqdn($cat->{fqdn}); return (undef, 'invalid catalog FQDN') if $fqdn eq '';
    (my $ckeys, my $cknames, my $ccidrs, my $cpe) = _catalog_effective_axfr($dbh, $cid, 'catalog'); return (undef, $cpe) if $cpe;
    (my $ctl, my $ce2) = _catalog_control_notify_targets($dbh, $cid); return (undef, $ce2) if $ce2;
    my $srv = _cfg('pdns_api', 'server', 'localhost');
    (my $ek, my $eke) = _pdns_ensure_tsigkeys($srv, $ckeys); return (undef, $eke) if $eke;
    # The producer zone's current state is read and compared, like any other; previously these four writes
    # went out on every pass whether anything changed or not.
    my $pdns = connectPDNS() or return (undef, 'DB unavailable');
    (my $mrows, my $me) = _db_all($pdns,
        "SELECT kind, content FROM domainmetadata WHERE domain_id=? AND kind IN
           ('TSIG-ALLOW-AXFR','ALLOW-AXFR-FROM','ALSO-NOTIFY',?)",
        { Slice => {} }, $cat->{pdns_domain_id}, $DIST_POLICY_MARK);
    return (undef, $me) if $me;
    my %cur; push @{ $cur{ $_->{kind} } }, $_->{content} for @{ $mrows || [] };
    (my $z1, my $ze1) = _pdns_zone_set_axfr($srv, "$fqdn.", $cknames, $ccidrs, $ctl, \%cur); return (undef, $ze1) if $ze1;
    # Member zone rights are NOT touched here: the shared path (apply_zones) already visited all served zones,
    # including these. A second visit gave 19 runs for 13 zones and added nothing.
    return ({ catalog_tsig_keys => $cknames, catalog_allow_from => $ccidrs,
              catalog_notify_targets => $ctl }, undef);
}

# Create the catalog's producer zone in PowerDNS. Idempotent: the zone exists and is a Producer -> success.
# (\%catalog, undef) | (undef, err).
sub catalog_provision {
    my ($cid) = @_;
    return (undef, 'not found') unless $cid && "$cid" =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $cat, my $e) = _db_row($dbh, "SELECT fqdn FROM catalogs WHERE id=?", $cid); return (undef, $e) if $e;
    return (undef, 'not found') unless $cat;
    my $fqdn = _norm_fqdn($cat->{fqdn}); return (undef, 'invalid catalog FQDN') if $fqdn eq '';
    my $zid = "$fqdn.";
    my $srv = _cfg('pdns_api', 'server', 'localhost');
    my $zbase = "/api/v1/servers/$srv/zones";

    (my $g, my $gc, my $ge) = _pdns_api('GET', "$zbase/$zid"); return (undef, $ge) if $ge;
    if ($gc == 200) {
        return (undef, "zone '$fqdn' already exists and is not a Producer (" . ($g->{kind} // '?') . ")")
            unless lc($g->{kind} // '') eq 'producer';
    } elsif ($gc == 404) {
        (my $p, my $pc, my $pe) = _pdns_api('POST', $zbase, { name => $zid, kind => 'Producer', nameservers => ['invalid.'] });
        return (undef, $pe) if $pe;
        return (undef, "PowerDNS API create failed (HTTP $pc)") unless $pc == 201;
        # Read-back confirmation: POST may report success and create something else.
        (my $v, my $vc, my $ve) = _pdns_api('GET', "$zbase/$zid"); return (undef, $ve) if $ve;
        return (undef, "catalog created but not verified as Producer (HTTP $vc)")
            unless $vc == 200 && lc($v->{kind} // '') eq 'producer';
    } else {
        return (undef, "PowerDNS API GET zone → HTTP $gc");
    }
    my $pdns = connectPDNS() or return (undef, 'DB unavailable');
    (my $did) = $pdns->selectrow_array("SELECT id FROM domains WHERE name=?", undef, $fqdn);
    return (undef, 'catalog created but not visible in backend') unless $did;
    (my $u, my $ue) = _do($dbh, "UPDATE catalogs SET pdns_domain_id=? WHERE id=?", $did, $cid); return (undef, $ue) if $ue;
    (my $mz, my $me) = catalog_axfr_materialize($cid);   # new producer -> keys and allow-axfr right away
    return (undef, $me) if $me;
    # The previous error is cleared ONLY here, when the zone exists and rights are applied. Otherwise a retry
    # would silently "not work": the catalog is ready while the screen still says Problem.
    (my $c, my $ce) = _do($dbh, "UPDATE catalogs SET last_error=NULL WHERE id=?", $cid); return (undef, $ce) if $ce;
    return catalog_get($cid);
}

# DELETE_CATALOG executor (via API): delete the producer zone from PowerDNS + confirm 404 + clear pdns_domain_id.
# Idempotent (zone already gone -> success). Members are removed before the call. (\%catalog_get, undef) | (undef, err).
sub catalog_provision_delete {
    my ($cid) = @_;
    return (undef, 'not found') unless $cid && "$cid" =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $cat, my $e) = _db_row($dbh, "SELECT fqdn, pdns_domain_id FROM catalogs WHERE id=?", $cid); return (undef, $e) if $e;
    return (undef, 'not found') unless $cat;
    my $fqdn = _norm_fqdn($cat->{fqdn});
    if ($fqdn ne '') {
        my $srv = _cfg('pdns_api', 'server', 'localhost');
        my $zid = "$fqdn.";
        (my $g, my $gc, my $ge) = _pdns_api('GET', "/api/v1/servers/$srv/zones/$zid"); return (undef, $ge) if $ge;
        if ($gc == 200) {   # exists -> delete ONLY if it is our Producer (a foreign MASTER is left alone)
            return (undef, "zone '$fqdn' is not a Producer (" . ($g->{kind} // '?') . ") — refusing to delete") unless lc($g->{kind} // '') eq 'producer';
            (my $d, my $dc, my $de) = _pdns_api('DELETE', "/api/v1/servers/$srv/zones/$zid"); return (undef, $de) if $de;
            return (undef, "PowerDNS API delete failed (HTTP $dc)") unless $dc == 204 || $dc == 200;
            (my $v, my $vc, my $ve) = _pdns_api('GET', "/api/v1/servers/$srv/zones/$zid"); return (undef, $ve) if $ve;   # confirm-404
            return (undef, "catalog deleted but still present (HTTP $vc)") unless $vc == 404;
        } elsif ($gc != 404) { return (undef, "PowerDNS API GET zone → HTTP $gc"); }
    }
    # Subscription observations of a DELETED catalog are garbage, not facts: rows live by catalog_id and would
    # resurface after Re-activate as fresh ("subscribed", verified_at from the catalog's past life). A pure
    # observation cache; the worker rebuilds it, so it is deleted.
    _do($dbh, "DELETE FROM catalog_subscriptions WHERE catalog_id=?", $cid);
    (my $u, my $ue) = _do($dbh, "UPDATE catalogs SET pdns_domain_id=NULL WHERE id=?", $cid); return (undef, $ue) if $ue;
    return catalog_get($cid);
}

# ================= Observing subscriptions via DNS (the panel does NOT provision BIND) =================
# Runs dig with an argument list (no shell injection). The ONLY place of a real run - replaced in tests.
# ($stdout, $exit). $exit: dig's code (0 = DNS reply received; 9 = no reply/timeout; else launch/usage error).
sub _dig_run {
    my (@cmd) = @_;
    my $out = eval {
        open(my $fh, '-|', @cmd) or die "exec\n";
        local $/; my $o = <$fh>; close($fh); $o;   # close -> $? = the process wait status
    };
    return (undef, -1) unless defined $out;         # could not even start dig
    return ($out, $? >> 8);
}

# PURE dig output parser (tested on fixed strings, no network). ($serial, $rcode, $status).
# $status (FAIL-CLOSED): 'present' - exit 0 + NOERROR + SOA in answer + authoritative `aa` flag;
#   'absent' - the server EXPLICITLY denies (NXDOMAIN/REFUSED/NOTAUTH); 'unknown' - exit!=0/no reply/SERVFAIL/
#   NOERROR without `aa`/unparsable (unprovable -> NOT treated as a deleted zone).
sub _parse_dig_soa {
    my ($out, $exit) = @_;
    return (undef, 'NOREPLY', 'unknown') unless defined $out && ($exit // -1) != -1;
    my ($rcode) = $out =~ /status:\s*([A-Z]+)/;   $rcode //= 'UNKNOWN';
    my ($flags) = $out =~ /flags:\s*([a-z ]*)/;    $flags //= '';
    my $aa = ($flags =~ /\baa\b/) ? 1 : 0;
    if (($exit // 1) != 0) {   # dig got no valid DNS reply (timeout/unreach/usage) -> unprovable
        return (undef, ($rcode ne 'UNKNOWN' ? $rcode : 'NOREPLY'), 'unknown');
    }
    # AUTHORITATIVE only (non-recursive query): proven absence = the server itself authoritatively denies the zone.
    if (($rcode eq 'NXDOMAIN' && $aa) || $rcode eq 'NOTAUTH') { return (undef, $rcode, 'absent'); }
    if ($rcode eq 'NOERROR') {
        my $serial; $serial = $1 + 0 if $out =~ /\bIN\s+SOA\s+\S+\s+\S+\s+(\d+)\b/i;   # zone. TTL IN SOA mname rname SERIAL ...
        return ($serial, $rcode, ($aa && defined $serial) ? 'present' : 'unknown');   # without aa/SOA - recursive/empty -> unprovable
    }
    # REFUSED (ACL), SERVFAIL, NXDOMAIN without aa (recursive) prove nothing about local loading
    return (undef, $rcode, 'unknown');
}

# Live SOA query to a SPECIFIC endpoint, STRICTLY non-recursive (+norecurse). ($serial, $rcode, $status), see _parse_dig_soa.
sub _dig_soa {
    my ($addr, $port, $zone) = @_;
    return (undef, 'NOADDR', 'unknown') unless defined $addr && length $addr;
    $port = ($port && "$port" =~ /^\d+$/) ? $port + 0 : 53;
    my $z = _norm_fqdn($zone); return (undef, 'BADZONE', 'unknown') if $z eq '';
    my $to = setting('dist_verify.timeout') + 0; $to = 3 if $to < 1;
    my ($out, $exit) = _dig_run('dig', '+norecurse', '+tries=1', "+time=$to", '+noall', '+comments', '+answer', "\@$addr", '-p', "$port", $z, 'SOA');
    return _parse_dig_soa($out, $exit);
}

# First enabled dns_listen endpoint of a node (consumer address for the SOA probe). ($addr, $port, undef) | (undef, undef, err).
sub _node_dns_listen {
    my ($dbh, $node_id) = @_;
    (my $r, my $e) = _db_row($dbh, "SELECT address, port FROM secondary_node_endpoints WHERE secondary_node_id=? AND purpose='dns_listen' AND enabled=1 ORDER BY port, address LIMIT 1", $node_id);
    return (undef, undef, $e) if $e;
    return (undef, undef, 'node has no dns_listen endpoint') unless $r;
    return ($r->{address}, $r->{port} + 0, undef);
}

# Reference consumer config (named.conf) for the operator: TWO signed fragments (BIND requires catalog-zones
# inside options/view, zone/key at zone scope). No `file` line is imposed. Strictly from cfg.
# -> \@fragments = [ {title, text}, {title, text} ]. TWO different sources that must not be mixed:
#   the catalog zone itself comes from our PowerDNS (pdns_endpoints - one install setting);
#   zones come from our PowerDNS too, but ONLY if the group is allowed (zone_axfr); otherwise their source is
#          outside the panel - its address and key are unknown, so a placeholder is printed.
# Direct zones follow the same flag as member zones, otherwise catalog zones would go via the group's
# upstream while direct ones suddenly came straight from our PowerDNS.
sub _render_bind_consumer_config {
    my ($cfg) = @_;
    my $z = $cfg->{catalog_fqdn};
    my $keyname = $cfg->{tsig} ? $cfg->{tsig}{name} : undef;
    my $keyref  = defined $keyname ? ' key "' . $keyname . '"' : '';
    my $fmt = sub {
        my ($eps, $what) = @_;
        my @l = map { '        ' . $_->{address} . ' port ' . $_->{port} . $keyref . ';' } @{ $eps || [] };
        return @l ? join("\n", @l) : "        # no enabled endpoints configured for the $what";
    };
    my $cat_prim  = $fmt->($cfg->{catalog_endpoints}, 'PowerDNS addresses');
    my $zone_prim = $fmt->($cfg->{zone_endpoints},    'zone AXFR source');
    # An HA pair is pulled from its service address, but NOTIFY leaves from the ACTIVE node's own address, and
    # BIND takes NOTIFY only from its primaries unless told otherwise.
    my @ns = @{ $cfg->{notify_sources} || [] };
    my $allow_notify = @ns ? 'allow-notify { ' . join('; ', @ns) . '; };' : '';
    my $has_cat = $cfg->{has_catalog} ? 1 : 0;
    my @a;   # fragment A: key + (if there is a catalog) the catalog zone itself, pulled from the producer
    if ($cfg->{tsig}) {
        push @a, 'key "' . $keyname . '" {';
        push @a, '    algorithm ' . $cfg->{tsig}{algorithm} . ';';
        push @a, '    secret "' . $cfg->{tsig}{secret} . '";';
        push @a, '};', '';
    }
    if ($has_cat) {
        push @a, '# The catalog zone itself always comes from our PowerDNS (the producer).';
        push @a, 'zone "' . $z . '" {';
        push @a, '    type secondary;';
        push @a, '    primaries {';
        push @a, $cat_prim;
        push @a, '    };';
        push @a, '    ' . $allow_notify if $allow_notify;
        push @a, '};';
    }
    pop @a while @a && $a[-1] eq '';   # without a catalog the key block left an empty tail
    my @frag;
    push @frag, { title => 'Add to named.conf.local (or the zone view)', text => join("\n", @a) . "\n" } if @a;
    if ($has_cat) {   # fragment B: catalog member zones - from us or from a foreign upstream (zone_axfr)
        # Where member zones come from depends on whether WE serve this group the zones. If not (zone_axfr=0),
        # the panel knows neither address nor KEY of that upstream (a foreign BIND with its own TSIG), so the
        # placeholder goes WITHOUT our key - it would not fit there, and printing it would be a lie.
        my @b = $cfg->{zone_axfr}
              ? ( '# Member zones are transferred from our PowerDNS (the same place the catalog comes from).',
                  ($allow_notify ? ('# NOTIFY comes from the pair nodes themselves, not from the service address.', $allow_notify) : ()),
                  'catalog-zones {', '    zone "' . $z . '" default-primaries {', $zone_prim, '    };', '};' )
              : ( '# This server does NOT take zone data from our PowerDNS — only the catalog.',
                  '# Point default-primaries at your own upstream and use ITS key.',
                  'catalog-zones {', '    zone "' . $z . '" default-primaries {',
                  '        <upstream address> key <upstream key>;', '    };', '};' );
        push @frag, { title => 'Add inside options { } (or the same view { })', text => join("\n", @b) . "\n" };
    }
    # fragment C: direct zones are not in the catalog, so the consumer must know about them itself.
    if (@{ $cfg->{direct_zones} || [] }) {
        # The same honest placeholder: if we do not serve this group the zones, its upstream's address and key are not ours.
        my $dprim = $cfg->{zone_axfr} ? $zone_prim : '        <upstream address> key <upstream key>;';
        my @c = ($cfg->{zone_axfr}
                 ? '# These zones are delivered directly (they cannot be catalog members) — declare them explicitly.'
                 : '# These zones cannot be catalog members — declare them explicitly, pointing at your own upstream.');
        for my $dz (@{ $cfg->{direct_zones} }) {
            push @c, 'zone "' . $dz . '" {', '    type secondary;', '    primaries {', $dprim, '    };', (($cfg->{zone_axfr} && $allow_notify) ? ('    ' . $allow_notify) : ()), '};', '';
        }
        pop @c if @c && $c[-1] eq '';
        push @frag, { title => 'Direct zones (not delivered by the catalog)', text => join("\n", @c) . "\n" };
    }
    return \@frag;
}

# REFERENCE BIND consumer configuration for (catalog, node) - what the operator sets up BY HAND.
# Strictly from the desired inventory (_catalog_consumers + source addresses + effective TSIG). Writes
# nothing, no lifecycle. (\%cfg with fragments, undef) | (undef, err).
sub catalog_subscription_config {
    my ($cid, $node_id) = @_;
    return (undef, 'not found') unless $cid && "$cid" =~ /^\d+$/ && $node_id && $node_id =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $cat, my $e) = _db_row($dbh, "SELECT id, fqdn FROM catalogs WHERE id=?", $cid); return (undef, $e) if $e;
    return (undef, 'not found') unless $cat;
    my $fqdn = _norm_fqdn($cat->{fqdn});
    return (undef, 'invalid catalog FQDN') if $fqdn eq '';
    (my $node, $e) = _db_row($dbh, "SELECT id, name FROM secondary_nodes WHERE id=?", $node_id); return (undef, $e) if $e;
    return (undef, 'node not found') unless $node;

    # TWO questions: the catalog always from our PowerDNS; zones from it too, but only for zone_axfr=1 groups.
    # TSIG is the authorization of THIS server (effective).
    (my $cons, $e) = _catalog_consumers($dbh, [$cid]); return (undef, $e) if $e;
    my ($cc) = grep { $_->{node_id} == $node_id + 0 } @{ $cons->{$cid + 0} || [] };
    return (undef, 'node is not a subscriber of this catalog') unless $cc;
    my $auth_mode = $cc->{auth_mode} // 'none';
    my $tsid = ($auth_mode eq 'tsig_only') ? $cc->{tsig_key_id} : undef;
    (my $cat_eps, $e) = _pdns_endpoints($dbh, $cid); return (undef, $e) if $e;
    my $zone_eps = $cc->{zone_axfr} ? $cat_eps : [];   # only groups we serve take zones from us
    my @eps = @$cat_eps;
    # Direct zones are declared by name in the reference config: the catalog does not list them. A zone that
    # is ALSO a member of this catalog arrives through it, and declaring it again would make BIND refuse it.
    (my $dzones, $e) = direct_axfr_zones(); return (undef, $e) if $e;
    (my $cmap, my $cme) = zone_catalog_map(); return (undef, $cme) if $cme;
    $dzones = [ grep { !($cmap->{ $_->{domain_id} } && $cmap->{ $_->{domain_id} }{id} == $cid + 0) } @$dzones ];
    my $tsig;
    if (defined $tsid) {
        (my $tk, my $te) = tsig_key_secret($tsid); return (undef, $te) if $te;
        $tsig = { name => $tk->{name}, algorithm => $tk->{algorithm}, secret => $tk->{secret} };
    }
    my %cfg = ( catalog_fqdn => $fqdn, has_catalog => 1, node_id => $node_id + 0, node_name => $node->{name},
                primary_endpoints => \@eps,
                catalog_endpoints => $cat_eps, zone_endpoints => $zone_eps,
                zone_axfr => ($cc->{zone_axfr} ? 1 : 0),
                direct_zones => [ map { $_->{name} } @$dzones ],
                notify_sources => [ ha_node_addresses() ],
                no_source => (@$cat_eps ? 0 : 1),        # no address of our PowerDNS configured
                no_zone_source => 0,                     # with zone_axfr=0 the zone source is outside our responsibility
                auth_mode => $auth_mode, tsig => $tsig );
    $cfg{fragments} = _render_bind_consumer_config(\%cfg);
    return (\%cfg, undef);
}

# Catalog consumer statuses for the Servers UI table. Per node: which of the catalog's assigned groups it is
# in (group_ids) + direct, readiness (catalog_capable/axfr_ready/blockers) + OBSERVED subscription. Reuses
# _catalog_consumers (desired) + catalog_subscriptions (observed). NO dedup (a node in 2 groups appears in
# both). (\@list, undef) | (undef, err).
sub catalog_consumers_state {
    my ($cid) = @_;
    return (undef, 'not found') unless $cid && "$cid" =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $cat, my $e) = _db_row($dbh, "SELECT id, pdns_domain_id FROM catalogs WHERE id=?", $cid); return (undef, $e) if $e;
    return (undef, 'not found') unless $cat;
    my $has_catalog = (defined $cat->{pdns_domain_id}) ? 1 : 0;
    # The address subscribers pull the catalog from is global (one PowerDNS). Is it set at all?
    (my $pe, my $pee) = _pdns_endpoints($dbh, $cid); return (undef, $pee) if $pee;
    my $has_source = @$pe ? 1 : 0;
    (my $dz, my $dze) = direct_axfr_zones(); return (undef, $dze) if $dze;
    my $has_direct = @$dz ? 1 : 0;
    # n.enabled=1 is required here too. Direct assignments were filtered but group ones were not, so the two
    # layers disagreed: _catalog_consumers dropped a disabled node while this counted it, and it surfaced in
    # the move dialog as loses/pending, could look like a confirmed recipient via a leftover
    # catalog_subscriptions row, and showed a FALSE reason ("not catalog-capable") in Propagation. Showing
    # disabled members, if ever needed, must be an explicit state, not a side effect of diverging JOINs.
    (my $grows, $e) = _db_all($dbh,
        "SELECT gm.secondary_node_id AS nid, b.secondary_group_id AS gid
           FROM catalog_groups b
           JOIN secondary_group_members gm ON gm.secondary_group_id=b.secondary_group_id
           JOIN secondary_nodes n ON n.id=gm.secondary_node_id
          WHERE b.catalog_id=? AND n.enabled=1", { Slice => {} }, $cid); return (undef, $e) if $e;
    (my $drows, $e) = _db_all($dbh, "SELECT cn.secondary_node_id AS nid FROM catalog_nodes cn JOIN secondary_nodes n ON n.id=cn.secondary_node_id WHERE cn.catalog_id=? AND n.enabled=1", { Slice => {} }, $cid); return (undef, $e) if $e;
    my %src;   # nid → { g => {gid=>1}, direct }
    $src{$_->{nid}+0}{g}{$_->{gid}+0} = 1 for @$grows;
    $src{$_->{nid}+0}{direct} = 1 for @$drows;
    (my $cons, $e) = _catalog_consumers($dbh, [$cid]); return (undef, $e) if $e;
    my %fact = map { ($_->{node_id}+0) => $_ } @{ $cons->{$cid+0} || [] };
    my %sub;
    if ($has_catalog) {   # ...and only for an EXISTING one: a dismantled catalog's subscription rows are stale observations
                          # of a deleted object and must not be shown as current
        (my $subs, $e) = _db_all($dbh, "SELECT secondary_node_id AS nid, observed_state, verified_at, observed_at, observed_serial, last_error FROM catalog_subscriptions WHERE catalog_id=?", { Slice => {} }, $cat->{id}); return (undef, $e) if $e;
        %sub = map { ($_->{nid}+0) => $_ } @$subs;
    }
    my @out;
    for my $nid (sort { $a <=> $b } keys %src) {
        (my $n, $e) = _db_row($dbh, "SELECT name FROM secondary_nodes WHERE id=?", $nid); return (undef, $e) if $e;
        my $f = $fact{$nid} || {};
        (my $ea, my $eae) = _node_effective_auth($dbh, $nid); return (undef, $eae) if $eae;   # server authorization (TSIG/IP)
        my @blk;
        push @blk, 'not catalog-capable' if $has_catalog && !$f->{catalog_capable};
        push @blk, 'no catalog source'   if $has_catalog && !$has_source;        # where to get the catalog itself
        push @blk, 'no AXFR authorization' unless $ea->{authorized};             # node-level (TSIG/IP)
        my $s = $sub{$nid};
        (my $nt, my $nte) = _node_effective_notify($dbh, $nid, $cid); return (undef, $nte) if $nte;
        push @out, {
            node_id => $nid, name => ($n ? $n->{name} : "#$nid"),
            notify => { on => ($nt->{on} ? 1 : 0), source => $nt->{source}, via => ($nt->{via} || []) },
            axfr   => do { (my $ax, my $axe) = _node_effective_axfr($dbh, $nid, $cid); return (undef, $axe) if $axe;
                           { on => ($ax->{on} ? 1 : 0), source => $ax->{source}, via => ($ax->{via} || []) } },
            group_ids => [ map { $_+0 } sort { $a <=> $b } keys %{ $src{$nid}{g} || {} } ],
            direct    => ($src{$nid}{direct} ? 1 : 0),
            catalog_capable => ($f->{catalog_capable} ? 1 : 0),
            # all subscribers get the catalog; the zones only go to groups we serve.
            zone_axfr           => ($f->{zone_axfr} ? 1 : 0),
            auth_mode       => ($ea->{mode} // 'none'),                                        # for the Authorization column
            auth_group_id   => (defined $ea->{group_id} ? $ea->{group_id}+0 : undef),
            blockers  => \@blk,
            subscription => ($s ? { verified => (defined $s->{verified_at} ? 1 : 0),
                                    observed_state => ($s->{observed_state} // 'unknown'),
                                    observed_at => $s->{observed_at}, last_error => $s->{last_error},
                                    observed_serial => (defined $s->{observed_serial} ? $s->{observed_serial}+0 : undef) } : undef),
        };
    }
    return (\@out, undef);
}



# The producer's own serial: try ALL addresses of our PowerDNS by priority until one gives an authoritative
# SOA (two in an HA pair). undef = producer unavailable (no address answered). ($serial|undef).
sub _catalog_producer_serial {
    my ($dbh, $fqdn) = @_;
    # Not the chosen published addresses but those PowerDNS listens on: the panel itself queries, and an
    # address published for secondaries (VIP, anycast, tunnel) may be unreachable from the panel.
    (my $eps) = _pdns_endpoints($dbh);
    for my $ep (@{ $eps || [] }) {
        (my $s, my $rc, my $st) = _dig_soa($ep->{address}, $ep->{port}, $fqdn);
        return $s if $st eq 'present' && defined $s;
    }
    return undef;
}
# Exported wrapper for the worker: get a catalog's producer serial ONCE (passed to all secondary checks).
sub catalog_producer_serial {
    my ($cid) = @_;
    return (undef, 'not found') unless $cid && "$cid" =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $cat, my $e) = _db_row($dbh, "SELECT fqdn FROM catalogs WHERE id=?", $cid); return (undef, $e) if $e;
    return (undef, 'catalog not configured') unless $cat;
    return (_catalog_producer_serial($dbh, $cat->{fqdn}), undef);
}
# Subscription OBSERVATION (Recheck / worker): live non-recursive SOA to the consumer + serial vs producer.
# $opts->{producer_serial}: if the key is given (the worker computes it ONCE per catalog) it is used
# (undef = producer unavailable); otherwise computed here. In sync ONLY on an exact serial match:
#   producer unavailable -> error(Producer unavailable); serial==producer -> subscribed(Synced);
#   serial<producer -> lagging; serial>producer -> error(Serial mismatch); absent -> unsubscribed; no reply -> error.
# The panel does NOT provision BIND - it only observes. (\%res, undef) | (undef, err).
sub catalog_subscription_recheck {
    my ($cid, $node_id, $opts) = @_; $opts ||= {};
    return (undef, 'not found') unless $cid && "$cid" =~ /^\d+$/ && $node_id && $node_id =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $cat, my $e) = _db_row($dbh, "SELECT id, fqdn FROM catalogs WHERE id=?", $cid); return (undef, $e) if $e;
    return (undef, 'catalog not configured') unless $cat;
    (my $nx, $e) = _db_exists($dbh, "SELECT 1 FROM secondary_nodes WHERE id=?", $node_id); return (undef, $e) if $e;
    return (undef, 'node not found') unless $nx;
    (my $addr, my $port, my $le) = _node_dns_listen($dbh, $node_id); return (undef, $le) if $le;
    my $pserial = exists $opts->{producer_serial} ? $opts->{producer_serial}
                : _catalog_producer_serial($dbh, $cat->{fqdn});   # undef = producer unavailable
    (my $serial, my $rcode, my $status) = _dig_soa($addr, $port, $cat->{fqdn});
    my ($state, $verified_sql, $err, $obs_serial);
    if ($status eq 'present') {
        $verified_sql = 'NOW()'; $obs_serial = $serial;   # the zone is loaded (verified) even if out of sync
        # RFC 1982 serial arithmetic (not plain </>): correct at the 32-bit serial wrap.
        if    (!defined $pserial)              { $state = 'error';      $err = "producer unavailable — sync unconfirmed"; }
        elsif (!defined $serial)               { $state = 'error';      $err = "serial unreadable from secondary"; }
        elsif ($serial == $pserial)            { $state = 'subscribed'; }
        elsif (!serial_ge($serial, $pserial))  { $state = 'lagging';     $err = "serial $serial behind producer $pserial"; }   # secondary OLDER than producer
        else                                   { $state = 'error';      $err = "serial mismatch: secondary $serial ahead of producer $pserial"; }   # secondary NEWER (odd)
    } elsif ($status eq 'absent') { $state = 'unsubscribed'; $verified_sql = 'verified_at'; $err = "catalog zone not served (rcode $rcode)"; }
    else {   # unknown -> server error (bad reply) vs unreachable (no reply), by rcode
        $state = 'error'; $verified_sql = 'verified_at';
        $err = ($rcode eq 'REFUSED' || $rcode eq 'SERVFAIL' || $rcode eq 'NOTIMP') ? "server error (rcode $rcode)" : "unreachable (no DNS response)";
    }
    (my $ok, my $de) = _do($dbh,
        "INSERT INTO catalog_subscriptions (catalog_id, secondary_node_id, observed_state, observed_at, verified_at, observed_serial, last_error)
         VALUES (?,?,?, NOW(), " . ($status eq 'present' ? 'NOW()' : 'NULL') . ", ?, ?)
         ON DUPLICATE KEY UPDATE observed_state=VALUES(observed_state), observed_at=NOW(),
                                 verified_at=$verified_sql, observed_serial=VALUES(observed_serial), last_error=VALUES(last_error)",
        $cat->{id}, $node_id + 0, $state, (defined $obs_serial ? $obs_serial : undef), $err);
    return (undef, $de) if $de;
    return ({ node_id => $node_id + 0, observed_state => $state, serial => $serial, producer_serial => $pserial, rcode => $rcode }, undef);
}

# Master key for TOTP secret encryption: base64 of 32 random bytes in the auth.master_key_file file.
# (Once deleted by accident with the old distribution model in 35e1e38 - second factor broke entirely.)
sub _auth_master_key {
    my ($version) = @_; $version ||= 1;                 # key_version reserved for rotation (only v1 for now)
    my $b64 = _secret_file('auth', 'master_key_file');
    die "auth.master_key_file is empty (needs base64 of 32 random bytes for TOTP encryption)\n"
        unless defined $b64 && length $b64;
    require MIME::Base64;
    my $key = MIME::Base64::decode_base64($b64);
    die "auth.master_key: base64-decoded key must be exactly 32 bytes (AES-256), got " . length($key) . "\n"
        unless length($key) == 32;
    return $key;
}
# blob = version(1) . iv(12) . tag(16) . ciphertext ; AAD='totp' (context binding).
sub _totp_encrypt {
    my ($plain) = @_;
    require Crypt::AuthEnc::GCM; require Crypt::URandom;
    my $ver = 1; my $key = _auth_master_key($ver);
    my $iv  = Crypt::URandom::urandom(12);
    my ($ct, $tag) = Crypt::AuthEnc::GCM::gcm_encrypt_authenticate('AES', $key, $iv, 'totp', $plain);
    return pack('C', $ver) . $iv . $tag . $ct;
}
sub _totp_decrypt {
    my ($blob) = @_;
    return undef unless defined $blob && length($blob) > 29;
    require Crypt::AuthEnc::GCM;
    my $ver = unpack('C', substr($blob, 0, 1));
    my $iv  = substr($blob, 1, 12);
    my $tag = substr($blob, 13, 16);
    my $ct  = substr($blob, 29);
    my $key = eval { _auth_master_key($ver) }; return undef unless defined $key;
    return eval { Crypt::AuthEnc::GCM::gcm_decrypt_verify('AES', $key, $iv, 'totp', $ct, $tag) };  # undef on a wrong tag/key
}

# ---- sessions on hashed tokens ----
sub _session_token_new { require Crypt::URandom; return unpack('H*', Crypt::URandom::urandom(32)); }  # 64 hex, NO rand() fallback
sub _session_hash      { require Digest::SHA; return Digest::SHA::sha256_hex(defined $_[0] ? $_[0] : ''); }

# Open a session; the DB stores SHA-256(raw). Returns (raw_token, undef) | (undef, err).
sub session_open {
    my (%a) = @_;
    my $uid = $a{user_id}; return (undef, 'user id required') unless $uid && $uid =~ /^\d+$/;
    my $stage = ($a{stage} && $a{stage} eq 'pending') ? 'pending' : 'full';
    my $ttl   = $a{ttl} || ($stage eq 'pending' ? 900 : user_session_ttl($uid));   # pending 15 min; full - the personal policy
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    my $raw = _session_token_new();
    my ($ok, $e) = _do($dbh,
        "INSERT INTO sessions (user_id, token, auth_type, stage, remember, pending_step, ip, user_agent, is_active, expires_at)
         VALUES (?,?,?,?,?,?,?,?,1, DATE_ADD(UTC_TIMESTAMP(), INTERVAL ? SECOND))",
        $uid, _session_hash($raw), $a{auth_type}, $stage, ($a{remember} ? 1 : 0), $a{pending_step}, $a{ip}, $a{user_agent}, $ttl);
    return (undef, $e) if $e;
    _audit_sign($uid, 'login', $a{auth_type}, $a{ip}) if $stage eq 'full';
    return ($raw, undef);
}
# Sign-in and sign-out in the audit log: only a FULL session counts as signed in (a password step alone does not).
sub _audit_sign {
    my ($uid, $action, $method, $ip) = @_;
    my $dbh = connectDB() or return;
    my ($name) = $dbh->selectrow_array("SELECT username FROM users WHERE id=?", undef, $uid);
    audit_log({ actor => $name, action => $action, target_type => 'user', target => $name, target_label => $name,
                ($method ? (after => { method => $method }) : ()), ip => $ip });
}
# Logout: close the session and record who left. Unknown or already closed token: nothing to record.
sub session_logout {
    my ($raw) = @_;
    my $s = session_by_raw($raw);
    session_close($raw);
    return unless $s && ($s->{stage} // '') eq 'full';
    my $dbh = connectDB() or return;
    my ($ip) = $dbh->selectrow_array("SELECT ip FROM sessions WHERE id=?", undef, $s->{id});
    _audit_sign($s->{user_id}, 'logout', undef, $ip);
}
# Active UNexpired session by raw token -> hashref {id,user_id,stage,pending_step,auth_type,expires_at(unix)} | undef.
sub session_by_raw {
    my ($raw) = @_;
    return undef unless defined $raw && length $raw;
    my $dbh = connectDB() or return undef;
    return $dbh->selectrow_hashref(
        "SELECT s.id, s.user_id, s.stage, s.pending_step, s.auth_type, UNIX_TIMESTAMP(s.expires_at) AS expires_at
           FROM sessions s JOIN users u ON u.id=s.user_id
          WHERE s.token=? AND s.is_active=1 AND u.is_active=1 AND s.expires_at > UTC_TIMESTAMP() LIMIT 1",
        undef, _session_hash($raw));
}
sub session_close { my ($raw) = @_; return unless defined $raw && length $raw;
    my $dbh = connectDB() or return; $dbh->do("UPDATE sessions SET is_active=0 WHERE token=?", undef, _session_hash($raw)); }

# Atomic promotion to a full session (no races between parallel requests with one pending token).
# One transaction: (1) "claim" the pending session exactly once (rows==1, else someone already promoted),
# (2) $consume->($dbh) consumes the factor - it does a conditional UPDATE itself and returns an error string
#     when rows!=1 (undef on success), (3) create a new full session. -> (new_raw, undef) | (undef, err).
sub _promote_txn {
    my ($sess, $consume) = @_;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $bo, my $be) = _txn_begin($dbh); return (undef, $be) if $be;
    my $fail = sub { my ($err) = @_; eval { $dbh->rollback }; return (undef, $err); };
    my $new; my $ttl; my $rem;
    my $done = eval {
        # Session lifetime is the user's PERSONAL POLICY only. "Remember this device" only decides whether the
        # cookie survives closing the browser. Previously without it the TTL was forced to 12 hours, ignoring
        # "Session lifetime: 5 years": after exactly 12 hours polling got 401, which the panel showed as HA breakage.
        ($rem) = $dbh->selectrow_array("SELECT remember FROM sessions WHERE id=?", undef, $sess->{id});
        $ttl = user_session_ttl($sess->{user_id});
        my $rc = $dbh->do("UPDATE sessions SET is_active=0 WHERE id=? AND stage='pending' AND is_active=1", undef, $sess->{id});
        die "db\n" if $dbh->err;
        die "gone\n" unless $rc && $rc == 1;                      # already consumed by a parallel request
        if ($consume) { my $cerr = $consume->($dbh); die "F:$cerr\n" if $cerr; }
        my $raw = _session_token_new();
        # ip/user_agent/remember are carried over from the pending session; TTL by policy.
        $dbh->do("INSERT INTO sessions (user_id, token, auth_type, stage, remember, is_active, expires_at, ip, user_agent)
                  SELECT user_id, ?, 'password', 'full', remember, 1, DATE_ADD(UTC_TIMESTAMP(), INTERVAL ? SECOND), ip, user_agent
                    FROM sessions WHERE id=?",
                 undef, _session_hash($raw), $ttl, $sess->{id}); die "db\n" if $dbh->err;
        $new = $raw; 1;
    };
    if (!$done) { my $err = $@ || 'failed'; $err =~ s/\n//g;
        return $fail->($err eq 'db'   ? (_db_err_kind($dbh->err) || 'DB error')
                     : $err eq 'gone' ? 'session invalid'
                     : $err =~ /^F:(.+)/ ? $1 : $err); }
    my $ok = $dbh->commit;
    if (!$ok || $dbh->err) { return $fail->(_db_err_kind($dbh->err) || 'commit failed'); }
    my ($ip) = $dbh->selectrow_array("SELECT ip FROM sessions WHERE id=?", undef, $sess->{id});
    _audit_sign($sess->{user_id}, 'login', 'password+2fa', $ip);
    return ($new, undef, $ttl, ($rem ? 1 : 0));
}

# ---- factor steps ----
# First required step: temporary password change -> app code. undef = no more steps, sign-in complete.
# The authenticator app is OPTIONAL (forced enrollment for everyone was a pointless ritual on an internal
# panel). Decided by fact:
#   app enrolled                   -> code (totp_verify);
#   not enrolled but EXPECTED      -> enroll (totp_enroll) - users.totp_required: an admin reset the app
#                                    ("lost the phone") or required a second factor;
#   not enrolled, not expected     -> no steps, the password completes sign-in.
sub _first_pending_step {
    my ($uid) = @_;
    my $dbh = connectDB() or return 'password_change';
    my ($must) = $dbh->selectrow_array("SELECT must_change FROM password_credentials WHERE user_id=?", undef, $uid);
    return 'password_change' if $must;
    my ($conf) = $dbh->selectrow_array("SELECT confirmed_at FROM totp_credentials WHERE user_id=?", undef, $uid);
    return 'totp_verify' if $conf;
    my ($req) = $dbh->selectrow_array("SELECT totp_required FROM users WHERE id=?", undef, $uid);
    return $req ? 'totp_enroll' : undef;
}

# base32 decode (RFC 4648, case-insensitive) -> raw key bytes.
sub _b32_decode {
    my ($s) = @_; $s = uc(defined $s ? $s : ''); $s =~ s/=+$//; $s =~ s/[^A-Z2-7]//g;
    my %v; my $i = 0; $v{$_} = $i++ for split //, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    my $bits = ''; $bits .= sprintf('%05b', $v{$_}) for split //, $s;
    my $bytes = ''; $bytes .= chr(oct('0b' . substr($bits, 0, 8, ''))) while length($bits) >= 8;
    return $bytes;
}
# Standard RFC 6238 TOTP code (SHA1, 30 s, 6 digits) for a given step; matches Google/MS Authenticator.
# (Not Auth::GoogleAuth->code: its 3rd argument is not an epoch and codes do not match the phone; checked with RFC vectors.)
sub _totp_code {
    my ($secret32, $step) = @_;
    require Digest::SHA;
    my $key = _b32_decode($secret32);
    my $h   = Digest::SHA::hmac_sha1(pack('Q>', $step), $key);
    my $off = ord(substr($h, -1)) & 0x0f;
    my $bin = unpack('N', substr($h, $off, 4)) & 0x7fffffff;
    return sprintf('%06d', $bin % 1000000);
}
# TOTP: check a 6-digit code against a base32 secret with anti-replay. -> matched_step(int) | undef.
sub _totp_check {
    my ($secret32, $code, $last_step) = @_;
    $code =~ s/\s+//g if defined $code;                   # the user may type "123 456"
    return undef unless defined $code && $code =~ /^\d{6}$/ && defined $secret32 && length $secret32;
    my $cur = int(time() / 30);
    for my $s ($cur - 1, $cur, $cur + 1) {                # +-1 window (network/clock drift)
        next if defined $last_step && $s <= $last_step;   # anti-replay: a code from an already accepted/past step is rejected
        return $s if _totp_code($secret32, $s) eq $code;
    }
    return undef;
}
# Random string of exactly $n chars from a fixed alphabet (rejection sampling -> no modulo bias).
my $_RC_ALPHA = '23456789abcdefghjkmnpqrstuvwxyz';   # no 0/o/1/l/i - not confused when copied by hand
sub _rand_str {
    my ($n) = @_;
    require Crypt::URandom;
    my $L = length $_RC_ALPHA; my $max = int(256 / $L) * $L;   # rejection threshold
    my $out = '';
    while (length($out) < $n) {
        for my $b (unpack 'C*', Crypt::URandom::urandom($n)) {
            next if $b >= $max;
            $out .= substr($_RC_ALPHA, $b % $L, 1);
            last if length($out) >= $n;
        }
    }
    return $out;
}
# 10 recovery codes xxxxx-xxxxx (strictly 5+5), all unique. Returns (\@plain, \@sha256hex).
sub _recovery_gen {
    require Digest::SHA;
    my (@plain, @hash); my %seen;
    while (@plain < 10) {
        my $c = _rand_str(5) . '-' . _rand_str(5);
        next if $seen{$c}++;
        push @plain, $c; push @hash, Digest::SHA::sha256_hex($c);
    }
    return (\@plain, \@hash);
}

# ---- password sign-in ----
# A precomputed dummy hash (our profile t=3,m=19M,p=1) - a CONSTANT, never generated on the request path.
# Verifying against it takes as long as a real one, so "no such user" and "wrong password" are
# indistinguishable by timing (user enumeration). Nobody knows its password (verify is always false).
my $_DUMMY_PW_HASH = '$argon2id$v=19$m=19456,t=3,p=1$7qv/eq5DPlrtshjh6Ca1+w$+T8rw0ktMqNx01OXqUeNBjof0/aGCHBh8pJf7O/NCwM';
sub _dummy_pw_hash { return $_DUMMY_PW_HASH; }

# Sign-in completed by password (the person has no second factor):
#   ({session, stage=>'full', ttl, remember, next=>undef, user_id, username}, undef)
# Another step needed (temporary password change or app code):
#   ({session, stage=>'pending', next, user_id, username}, undef)
# Error: (undef, 'invalid credentials'|'DB unavailable').
# One generic answer for any failure (no user / inactive / no password / mismatch) - no user enumeration.
sub login_password {
    my ($username, $password, $ip, $ua, $remember) = @_;
    return (undef, 'invalid credentials') unless defined $username && length $username && defined $password && length $password;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    my $row = $dbh->selectrow_hashref(
        "SELECT u.id, u.username, p.password_hash
           FROM users u JOIN password_credentials p ON p.user_id=u.id
          WHERE u.username=? AND u.is_active=1 LIMIT 1", undef, $username);
    # ALWAYS exactly one Argon2id verify (real or dummy) -> constant time.
    my $hash = ($row && $row->{password_hash}) ? $row->{password_hash} : _dummy_pw_hash();
    my $ok = password_verify($hash, $password);
    return (undef, 'invalid credentials') unless $row && $ok;
    my $step = _first_pending_step($row->{id});
    unless ($step) {   # nothing more to ask - a full session at once, as after a confirmed factor
        my $ttl = user_session_ttl($row->{id});
        my ($fraw, $fe) = session_open(user_id => $row->{id}, stage => 'full', ttl => $ttl,
                                       auth_type => 'password', ip => $ip, user_agent => $ua, remember => ($remember ? 1 : 0));
        return (undef, $fe) if $fe;
        return ({ session => $fraw, stage => 'full', ttl => $ttl, remember => ($remember ? 1 : 0),
                  next => undef, user_id => $row->{id}, username => $row->{username} }, undef);
    }
    my ($raw, $e) = session_open(user_id => $row->{id}, stage => 'pending', pending_step => $step,
                                 auth_type => 'password', ip => $ip, user_agent => $ua, remember => ($remember ? 1 : 0));
    return (undef, $e) if $e;
    return ({ session => $raw, stage => 'pending', next => $step, user_id => $row->{id}, username => $row->{username} }, undef);
}

# Shared check of a pending session at the expected step. -> ($sess, undef) | (undef, err).
sub _pending_at {
    my ($raw, $want_step) = @_;
    my $s = session_by_raw($raw); return (undef, 'session invalid') unless $s && $s->{stage} eq 'pending';
    return (undef, 'wrong step') if $want_step && ($s->{pending_step} // '') ne $want_step;
    return ($s, undef);
}

# Step 1: mandatory temporary password change; reusing the current (temporary) password is rejected.
# Atomic (one txn): password_hash + must_change=0 + advance pending_step. -> ({next}, undef) | (undef, err).
sub auth_step_password {
    my ($raw, $new_pw) = @_;
    my ($s, $e) = _pending_at($raw, 'password_change'); return (undef, $e) if $e;
    return (undef, 'password too short (min 8)') unless defined $new_pw && length $new_pw >= 8;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    my ($cur) = $dbh->selectrow_array("SELECT password_hash FROM password_credentials WHERE user_id=?", undef, $s->{user_id});
    return (undef, 'new password must differ from the current one') if $cur && password_verify($cur, $new_pw);
    my $hash = eval { password_hash($new_pw) }; return (undef, 'hashing failed') unless $hash;   # expensive - outside the txn
    my ($conf) = $dbh->selectrow_array("SELECT confirmed_at FROM totp_credentials WHERE user_id=?", undef, $s->{user_id});
    my ($req) = $dbh->selectrow_array("SELECT totp_required FROM users WHERE id=?", undef, $s->{user_id});
    # must_change becomes 0 in this txn. Then as in a normal sign-in: code, app enrollment or nothing.
    my $next = $conf ? 'totp_verify' : ($req ? 'totp_enroll' : undef);
    (my $bo, my $be) = _txn_begin($dbh); return (undef, $be) if $be;
    my $fail = sub { my ($err) = @_; eval { $dbh->rollback }; return (undef, $err); };
    my $done = eval {
        # must_change=1 in WHERE -> exactly one pending session wins; a stale one (password already changed) -> rows==0.
        my $pc = $dbh->do("UPDATE password_credentials SET password_hash=?, must_change=0 WHERE user_id=? AND must_change=1", undef, $hash, $s->{user_id}); die "db\n" if $dbh->err;
        die "gone\n" unless $pc && $pc == 1;
        # Close ALL other sessions of the user (including parallel pending ones with the same temporary password).
        $dbh->do("UPDATE sessions SET is_active=0 WHERE user_id=? AND id<>? AND is_active=1", undef, $s->{user_id}, $s->{id}); die "db\n" if $dbh->err;
        my $rc = $dbh->do("UPDATE sessions SET pending_step=? WHERE id=? AND stage='pending' AND pending_step='password_change'", undef, $next, $s->{id}); die "db\n" if $dbh->err;
        die "gone\n" unless $rc && $rc == 1;
        1;
    };
    if (!$done) { my $err = $@ || 'failed'; $err =~ s/\n//g;
        return $fail->($err eq 'db' ? (_db_err_kind($dbh->err) || 'DB error') : $err eq 'gone' ? 'session invalid' : $err); }
    my $ok = $dbh->commit;
    if (!$ok || $dbh->err) { return $fail->(_db_err_kind($dbh->err) || 'commit failed'); }
    return ({ next => $next }, undef) if $next;
    # Password changed and nothing else required - promote the session right here, no extra step.
    # If promotion fails the password is still new; the person just signs in with it again.
    my ($new, $pe, $ttl, $rem) = _promote_txn($s, undef);
    return (undef, $pe) if $pe;
    return ({ next => undef, session => $new, stage => 'full', ttl => $ttl, remember => $rem }, undef);
}

# Step 2a: start TOTP enrollment - generate a secret (unconfirmed yet), return otpauth/QR/secret.
# Idempotent: calling again before confirmation regenerates the secret. -> ({otpauth, qr_png_base64, secret}, undef) | (undef, err).
sub auth_step_totp_begin {
    my ($raw, $issuer_label) = @_;
    my ($s, $e) = _pending_at($raw, 'totp_enroll'); return (undef, $e) if $e;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    require Auth::GoogleAuth;
    my $secret = Auth::GoogleAuth->new->generate_secret32;
    my $enc = eval { _totp_encrypt($secret) }; return (undef, 'master key unavailable: ' . ($@ || '?')) unless defined $enc;
    # Never touch an already CONFIRMED credential (begin<->confirm race, also from another pending session of
    # the same user): IF(confirmed_at IS NULL, ...) makes the write a no-op on a confirmed row.
    my ($ok, $de) = _do($dbh,
        "INSERT INTO totp_credentials (user_id, secret_encrypted, key_version, confirmed_at, last_used_step)
         VALUES (?,?,1,NULL,NULL)
         ON DUPLICATE KEY UPDATE
           secret_encrypted = IF(confirmed_at IS NULL, VALUES(secret_encrypted), secret_encrypted),
           key_version      = IF(confirmed_at IS NULL, 1, key_version),
           last_used_step   = IF(confirmed_at IS NULL, NULL, last_used_step)",
        $s->{user_id}, $enc); return (undef, $de) if $de;
    # Re-read the current row: if already confirmed, enrollment is closed and the secret is not shown.
    my ($stored_enc, $conf) = $dbh->selectrow_array("SELECT secret_encrypted, confirmed_at FROM totp_credentials WHERE user_id=?", undef, $s->{user_id});
    return (undef, 'totp already enrolled') if $conf;
    my $stored_secret = _totp_decrypt($stored_enc); return (undef, 'totp secret unreadable') unless defined $stored_secret;
    my ($uname) = $dbh->selectrow_array("SELECT username FROM users WHERE id=?", undef, $s->{user_id});
    # The otpauth URI is built HERE: Auth::GoogleAuth->otpauth is unreliable across versions (1.03 in Ubuntu
    # 24.04 returns undef/arrayref with a hashref constructor -> empty QR). The format is standard.
    my $otpauth = _otpauth_uri($stored_secret, ($uname // 'user'), ($issuer_label || 'DNS Panel'));
    my $png_b64 = eval { _qr_png_base64($otpauth) };   # local PNG (Imager::QRCode), not an external chart URL
    return ({ otpauth => $otpauth, qr_png_base64 => $png_b64, secret => $stored_secret }, undef);
}

# otpauth://totp/{issuer}:{account}?secret=...&issuer=... - RFC-compatible URI for QR/manual entry;
# issuer/account are percent-encoded, secret32 is base32 (safe characters).
sub _otpauth_uri {
    my ($secret32, $account, $issuer) = @_;
    $issuer  = 'DNS Panel' unless defined $issuer  && length $issuer;
    $account = 'user'      unless defined $account && length $account;
    my $enc = sub { my $t = shift; $t =~ s/([^A-Za-z0-9_.~-])/sprintf('%%%02X', ord $1)/ge; return $t; };
    my ($ei, $ea) = ($enc->($issuer), $enc->($account));
    return "otpauth://totp/$ei:$ea?secret=$secret32&issuer=$ei";
}
# QR of an otpauth URI -> base64 PNG (the caller builds the data URI). undef if Imager::QRCode is missing.
sub _qr_png_base64 {
    my ($text) = @_;
    require Imager::QRCode; require MIME::Base64;
    my $qr  = Imager::QRCode->new(size => 5, margin => 2, level => 'M', casesensitive => 1);
    my $img = $qr->plot($text) or return undef;
    my $png = ''; $img->write(data => \$png, type => 'png') or return undef;
    return MIME::Base64::encode_base64($png, '');
}

# Step 2b: confirm TOTP with the first code -> enrollment done = a full session AT ONCE (recovery codes are optional).
# Atomic (one txn via _promote_txn): mark confirmed (for the secret that was read) + generate recovery codes
# + close pending + create full. Codes are returned once (the client offers Copy/Download/Skip, sign-in is done).
# -> ({session=>full_raw, stage=>'full', recovery_codes=>[...]}, undef) | (undef, 'invalid code'|err).
sub auth_step_totp_confirm {
    my ($raw, $code) = @_;
    my ($s, $e) = _pending_at($raw, 'totp_enroll'); return (undef, $e) if $e;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    my ($enc) = $dbh->selectrow_array("SELECT secret_encrypted FROM totp_credentials WHERE user_id=? AND confirmed_at IS NULL", undef, $s->{user_id});
    return (undef, 'no pending enrollment') unless defined $enc;
    my $secret = _totp_decrypt($enc); return (undef, 'totp secret unreadable') unless defined $secret;
    my $step = _totp_check($secret, $code, undef); return (undef, 'invalid code') unless defined $step;

    my ($plain, $hash) = _recovery_gen();
    my ($new, $pe, $ttl, $rem) = _promote_txn($s, sub {
        my ($dbh) = @_;
        # Confirm EXACTLY the secret that was read ($enc): a parallel begin that replaced it -> rows==0 -> 'invalid code'.
        my $rc = $dbh->do("UPDATE totp_credentials SET confirmed_at=UTC_TIMESTAMP(), last_used_step=? WHERE user_id=? AND confirmed_at IS NULL AND secret_encrypted=?", undef, $step, $s->{user_id}, $enc);
        return 'DB error' if $dbh->err;
        return 'invalid code' unless $rc && $rc == 1;
        $dbh->do("DELETE FROM recovery_codes WHERE user_id=?", undef, $s->{user_id}); return 'DB error' if $dbh->err;
        for my $h (@$hash) { $dbh->do("INSERT INTO recovery_codes (user_id, code_hash) VALUES (?,?)", undef, $s->{user_id}, $h); return 'DB error' if $dbh->err; }
        return undef;
    });
    return (undef, $pe) if $pe;
    return ({ session => $new, stage => q{full}, ttl => $ttl, remember => $rem, recovery_codes => $plain }, undef);
}

# Existing user sign-in: check the TOTP code (2FA) -> FULL session (atomic, anti-replay in WHERE).
# → ({session=>new_raw, stage=>'full'}, undef) | (undef, 'invalid code'|err).
sub auth_step_totp_verify {
    my ($raw, $code) = @_;
    my ($s, $e) = _pending_at($raw, 'totp_verify'); return (undef, $e) if $e;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    my ($enc, $last) = $dbh->selectrow_array("SELECT secret_encrypted, last_used_step FROM totp_credentials WHERE user_id=? AND confirmed_at IS NOT NULL", undef, $s->{user_id});
    return (undef, 'totp not enrolled') unless defined $enc;
    my $secret = _totp_decrypt($enc); return (undef, 'totp secret unreadable') unless defined $secret;
    my $step = _totp_check($secret, $code, $last); return (undef, 'invalid code') unless defined $step;
    # Step consumption is atomic: last_used_step < $step guarantees a parallel request cannot accept the same code.
    my ($new, $pe, $ttl, $rem) = _promote_txn($s, sub {
        my ($dbh) = @_;
        my $rc = $dbh->do("UPDATE totp_credentials SET last_used_step=? WHERE user_id=? AND confirmed_at IS NOT NULL AND (last_used_step IS NULL OR last_used_step < ?)",
                          undef, $step, $s->{user_id}, $step);
        return 'DB error' if $dbh->err;
        return 'invalid code' unless $rc && $rc == 1;   # lost the anti-replay race
        return undef;
    });
    return (undef, $pe) if $pe;
    return ({ session => $new, stage => q{full}, ttl => $ttl, remember => $rem }, undef);
}

# Sign-in by recovery code (TOTP device lost): a one-time code -> FULL session (atomic).
# Allowed at step 'totp_verify'. -> ({session=>new_raw, stage=>'full', remaining=>N}, undef) | (undef, 'invalid code'|err).
sub auth_step_recovery_use {
    my ($raw, $code) = @_;
    my ($s, $e) = _pending_at($raw, 'totp_verify'); return (undef, $e) if $e;
    return (undef, 'invalid code') unless defined $code && length $code;
    require Digest::SHA;
    my $h = Digest::SHA::sha256_hex(lc _trim($code));
    my ($new, $pe, $ttl, $remflag) = _promote_txn($s, sub {
        my ($dbh) = @_;
        # Code consumption is atomic: used_at IS NULL in WHERE -> single use even with parallel requests.
        my $rc = $dbh->do("UPDATE recovery_codes SET used_at=UTC_TIMESTAMP() WHERE user_id=? AND code_hash=? AND used_at IS NULL", undef, $s->{user_id}, $h);
        return 'DB error' if $dbh->err;
        return 'invalid code' unless $rc && $rc == 1;
        return undef;
    });
    return (undef, $pe) if $pe;
    my $dbh = connectDB();
    my ($rem) = $dbh->selectrow_array("SELECT COUNT(*) FROM recovery_codes WHERE user_id=? AND used_at IS NULL", undef, $s->{user_id});
    return ({ session => $new, stage => q{full}, ttl => $ttl, remember => $remflag, remaining => $rem }, undef);
}

# ---- authentication attempt throttling (DB, fixed sliding window) ----
# guard BEFORE the attempt; fail on failure; ok on success. $bucket: any key ('pw:<user>|<ip>' / 'totp:<uid>').
# guard -> (allowed(0|1), retry_after_sec). With the DB down - fail-open (the throttle layer must not block the panel).
sub auth_throttle_guard {
    my ($bucket) = @_;
    my $dbh = connectDB() or return (1, 0);
    my $r = $dbh->selectrow_hashref(
        "SELECT UNIX_TIMESTAMP(locked_until) AS lu, UNIX_TIMESTAMP(UTC_TIMESTAMP()) AS now
           FROM auth_throttle WHERE bucket=?", undef, $bucket);
    return (1, 0) unless $r && $r->{lu};
    return (0, $r->{lu} - $r->{now}) if $r->{lu} > $r->{now};
    return (1, 0);
}
# Record a failure: +1 in the current window (reset if expired); at attempts>=limit - block for $lock seconds.
sub auth_throttle_fail {
    my ($bucket, $limit, $window, $lock) = @_;
    $limit ||= 5; $window ||= 900; $lock ||= 900;
    my $dbh = connectDB() or return;
    $dbh->do(
        "INSERT INTO auth_throttle (bucket, attempts, window_start) VALUES (?, 1, UTC_TIMESTAMP())
         ON DUPLICATE KEY UPDATE
           locked_until = IF(IF(window_start < UTC_TIMESTAMP() - INTERVAL ? SECOND, 1, attempts + 1) >= ?,
                             UTC_TIMESTAMP() + INTERVAL ? SECOND, locked_until),
           attempts     = IF(window_start < UTC_TIMESTAMP() - INTERVAL ? SECOND, 1, attempts + 1),
           window_start = IF(window_start < UTC_TIMESTAMP() - INTERVAL ? SECOND, UTC_TIMESTAMP(), window_start)",
        undef, $bucket, $window, $limit, $lock, $window, $window);
}
# Success - clear the counter.
sub auth_throttle_ok { my ($bucket) = @_; my $dbh = connectDB() or return; $dbh->do("DELETE FROM auth_throttle WHERE bucket=?", undef, $bucket); }

# ============================================================================
# NS PULSE - testers, groups, checks, rules (spec: docs/25-ns-pulse.md).
# Three rules this storage layer must enforce itself, or nothing could fix them later:
#   1. A check targets a concrete ADDRESS. A name that gets switched cannot be checked: after the first
#      switch the check would start confirming itself.
#   2. A rule condition names a specific tester, and that tester MUST run the check (be in the assigned
#      group). Otherwise the condition waits for a result that never comes, while looking normal.
#   3. The task's meaning changes -> config_version grows. Earlier results stop being evidence.
# ============================================================================

sub _pulse_ip_ok {
    my ($ip, $type) = @_;
    return 0 unless defined $ip && length $ip;
    return _is_ipv6($ip) ? 1 : 0 if ($type // '') eq 'AAAA';
    return _is_ipv4($ip) ? 1 : 0 if ($type // '') eq 'A';
    return (_is_ipv4($ip) || _is_ipv6($ip)) ? 1 : 0;
}
sub _pulse_int {
    my ($v, $def, $min, $max) = @_;
    return $def unless defined $v && $v =~ /^\d+$/;
    my $n = $v + 0;
    return $min if $n < $min;
    return $max if $n > $max;
    return $n;
}

# ---- Testers --------------------------------------------------------------------------------------
# Agent state (online|silent) lives HERE, history in pulse_tester_intervals. History has no open intervals:
# the current segment is state + state_since.
# The agent is started on the machine first, then the panel says who it is - the panel cannot know a
# machine before it appears. The agent makes its own key, arrives with it and waits; a human sees the
# request and approves it, giving it a name.
# The code is the first eight characters of the key hash, split in half. The agent logs the same code at
# startup: when five machines arrive at once, codes are compared instead of guessing by address.
sub _pulse_code {
    my ($hash) = @_;
    return undef unless defined $hash && length $hash >= 8;
    return uc(substr($hash, 0, 4)) . '-' . uc(substr($hash, 4, 4));
}
sub pulse_testers_all {
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $rows, my $e) = _db_all($dbh,
        "SELECT t.*, (SELECT GROUP_CONCAT(g.name ORDER BY g.name SEPARATOR ', ')
                        FROM pulse_group_members m JOIN pulse_groups g ON g.id = m.group_id
                       WHERE m.tester_id = t.id) AS groups_label,
                     -- How many rules depend on this tester: it drives both the freshness window choice and the cost of deleting it.
                     (SELECT COUNT(DISTINCT b.rule_id) FROM pulse_condition_testers ct
                        JOIN pulse_conditions c ON c.id = ct.condition_id
                        JOIN pulse_branches b   ON b.id = c.branch_id
                       WHERE ct.tester_id = t.id) AS in_rules,
                     -- Age of the agent's last word in SECONDS, not a timestamp: silent is useless without how long, and
                     -- computing the difference in the browser would use a foreign time zone.
                     TIMESTAMPDIFF(SECOND, t.last_seen_at, UTC_TIMESTAMP()) AS last_seen_age
           FROM pulse_testers t ORDER BY t.approved_at IS NULL DESC, t.name", { Slice => {} });
    return (undef, $e) if $e;
    for my $r (@{ $rows || [] }) {
        $r->{code}    = _pulse_code($r->{key_hash});
        $r->{pending} = $r->{approved_at} ? 0 : 1;
        delete $r->{key_hash};   # the hash is never returned: nothing to show, and the field is superfluous
    }
    return ($rows || [], undef);
}
# A tester can NOT be created from the panel: the arriving agent creates the row. Here only editing an
# arrived one and approving it ($approve) - approval is when the request gets its name.
sub pulse_tester_save {
    my ($id, $f, $approve) = @_;
    $f ||= {};
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    return (undef, 'id required') unless $id && $id =~ /^\d+$/;
    (my $name, my $e) = _check_len($f->{name}, 'name', 64, 1); return (undef, $e) if $e;
    (my $loc, $e)     = _check_len($f->{location}, 'location', 64, 0); return (undef, $e) if $e;
    my $enabled = defined $f->{enabled} ? ($f->{enabled} ? 1 : 0) : 1;
    my $age = _pulse_int($f->{confirm_max_age_seconds}, 90, 5, 86400);
    # The name comes from a human and may easily collide (two machines in one DC with the same hostname, which
    # the panel suggests on approval). Say so plainly, not with a DB error code.
    (my $dup, $e) = _db_exists($dbh, "SELECT 1 FROM pulse_testers WHERE name=? AND id<>?", $name, $id);
    return (undef, $e) if $e;
    return (undef, "tester '$name' already exists") if $dup;
    {
        (my $bo, my $be) = _txn_begin($dbh); return (undef, $be) if $be;
        my $done = eval {
            $dbh->do(
                "UPDATE pulse_testers SET name=?, location=?, enabled=?, confirm_max_age_seconds=?"
                . ($approve ? ", approved_at=COALESCE(approved_at, NOW())" : "") . "
                  WHERE id=?", undef, $name, $loc, $enabled, $age, $id);
            die "db\n" if $dbh->err;
            # Same law as for a silent agent, applied to the switch: a disabled tester does not observe, and its
            # previous "healthy" stops being evidence.
            _pulse_disable_sync($dbh, undef, $id); die "db\n" if $dbh->err;
            # The tester itself too: disabling is a TRANSITION, not a pause. Otherwise after re-enabling the card
            # would say "online" from memory and the timeline would stretch the old state across the downtime.
            _pulse_tester_state($dbh, $id, $enabled ? 'silent' : 'disabled'); die "db\n" if $dbh->err;
            1;
        };
        unless ($done) { my $k = _db_err_kind($dbh->err) || 'DB error'; eval { $dbh->rollback }; return (undef, $k) }
        unless ($dbh->commit) { my $k = _db_err_kind($dbh->err); eval { $dbh->rollback }; return (undef, $k) }
        pulse_notify(0);   # a disabled tester = "no data" for all its pairs
        return ($id + 0, undef);
    }
}
sub pulse_tester_delete {
    my ($id) = @_;
    return (undef, 'id required') unless $id && $id =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    # An agent is one of a condition's observers; deleting it removes ONLY its row: the condition stays with
    # one observer fewer. Rules are still affected ("any of three" differs from "any of two"), so this is
    # counted and reported BEFORE, not after.
    (my $rows, my $e) = _db_all($dbh,
        "SELECT DISTINCT r.id, r.rr_name, r.rr_type FROM pulse_condition_testers ct
            JOIN pulse_conditions c ON c.id = ct.condition_id
            JOIN pulse_branches b   ON b.id = c.branch_id
            JOIN pulse_rules r      ON r.id = b.rule_id
           WHERE ct.tester_id = ?", { Slice => {} }, $id);
    return (undef, $e) if $e;
    (my $ok, my $de) = _do($dbh, "DELETE FROM pulse_testers WHERE id=?", $id);
    return (undef, $de) if $de;
    return ({ deleted => 1, affected_rules => [ map { "$_->{rr_name} $_->{rr_type}" } @{ $rows || [] } ] }, undef);
}
# The enrollment key is ONE per pair and identical in all agents, so it is shown as often as machines are
# added and stored in the clear (see the pulse_enrollment table comment). It grants one thing only:
# getting onto the pending list.
sub pulse_enroll_key {
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $r, my $e) = _db_row($dbh, "SELECT enroll_key FROM pulse_enrollment WHERE id=1");
    return (undef, $e) if $e;
    return ($r ? $r->{enroll_key} : undef, undef);
}
# Rotating the key does NOT affect approved agents: each has its own key. It only changes who gets into
# the queue from now on.
sub pulse_enroll_key_new {
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    require Crypt::URandom;
    my $key = substr(unpack('H*', Crypt::URandom::urandom(32)), 0, 40);
    (my $ok, my $e) = _do($dbh, "UPDATE pulse_enrollment SET enroll_key=? WHERE id=1", $key);
    return (undef, $e) if $e;
    return ($key, undef);
}

# ---- Groups ---------------------------------------------------------------------------------------
sub _pulse_ids {
    my ($csv) = @_;
    return [] unless defined $csv && length $csv;
    return [ sort { $a <=> $b } map { $_ + 0 } grep { /^\d+$/ } split /,/, $csv ];
}
sub pulse_groups_all {
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $rows, my $e) = _db_all($dbh,
        "SELECT g.*, (SELECT COUNT(*) FROM pulse_group_members m WHERE m.group_id=g.id) AS members,
                     (SELECT COUNT(*) FROM pulse_check_groups cg WHERE cg.group_id=g.id) AS checks,
                     (SELECT GROUP_CONCAT(m.tester_id) FROM pulse_group_members m WHERE m.group_id=g.id)
                       AS member_ids
           FROM pulse_groups g ORDER BY g.name", { Slice => {} });
    return (undef, $e) if $e;
    $_->{member_ids} = _pulse_ids(delete $_->{member_ids}) for @{ $rows || [] };
    return ($rows || [], undef);
}
sub pulse_group_save {
    my ($id, $f) = @_;
    $f ||= {};
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $name, my $e) = _check_len($f->{name}, 'name', 64, 1); return (undef, $e) if $e;
    (my $desc, $e) = _check_len($f->{description}, 'description', 255, 0); return (undef, $e) if $e;
    if ($id) {
        (my $ok, my $de) = _do($dbh, "UPDATE pulse_groups SET name=?, description=? WHERE id=?", $name, $desc, $id);
        return (undef, $de) if $de;
        return ($id + 0, undef);
    }
    (my $dup, $e) = _db_exists($dbh, "SELECT 1 FROM pulse_groups WHERE name=?", $name); return (undef, $e) if $e;
    return (undef, "group '$name' already exists") if $dup;
    (my $ok, my $de) = _do($dbh, "INSERT INTO pulse_groups (name, description) VALUES (?,?)", $name, $desc);
    return (undef, $de) if $de;
    return ($dbh->last_insert_id(undef,undef,undef,undef) + 0, undef);
}
# Group delete and pair recomputation in ONE transaction. Separately, the group was gone while state rows
# of non-existent pairs remained, and nobody learned of it because recomputation errors got lost.
sub pulse_group_delete {
    my ($id) = @_;
    return (undef, 'id required') unless $id && $id =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $bo, my $be) = _txn_begin($dbh); return (undef, $be) if $be;
    my $touched = [];
    my $done = eval {
        # The GROUP ROW is locked to protect its assignments - not a typo. A concurrent INSERT INTO
        # pulse_check_groups must take a shared lock on the parent pulse_groups row because of the FK, which
        # conflicts with an exclusive one. Without it the assignment list read before the transaction could go
        # stale: a new check assigned, cascaded away by the delete, missed by recomputation - leaving a pair
        # that no longer exists.
        my $live = $dbh->selectrow_array("SELECT id FROM pulse_groups WHERE id=? FOR UPDATE", undef, $id);
        die "db\n" if $dbh->err;
        die "gone\n" unless $live;
        my $cids = $dbh->selectcol_arrayref("SELECT check_id FROM pulse_check_groups WHERE group_id=?",
                                            undef, $id);
        die "db\n" if $dbh->err;
        $dbh->do("DELETE FROM pulse_groups WHERE id=?", undef, $id); die "db\n" if $dbh->err;
        # No group means no pairs it produced: their state rows go too, closing the tail.
        _pulse_sync_results($dbh, $cids); die "db\n" if $dbh->err;
        $touched = _pulse_sync_all_conditions($dbh, $cids); die "db\n" if $dbh->err;
        1;
    };
    unless ($done) {
        my $why = $@ // '';
        my $k = ($why =~ /^gone/) ? 'not found' : (_db_err_kind($dbh->err) || 'DB error');
        eval { $dbh->rollback };
        return (undef, $k);
    }
    unless ($dbh->commit) { my $k = _db_err_kind($dbh->err); eval { $dbh->rollback }; return (undef, $k) }
    pulse_notify($_) for @{ $touched || [] };
    return (1, undef);
}
sub pulse_group_members_set {
    my ($gid, $tester_ids) = @_;
    return (undef, 'group id required') unless $gid && $gid =~ /^\d+$/;
    my @ids = grep { defined && /^\d+$/ } @{ $tester_ids || [] };
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $ex, my $e) = _db_exists($dbh, "SELECT 1 FROM pulse_groups WHERE id=?", $gid); return (undef, $e) if $e;
    return (undef, 'group not found') unless $ex;
    (my $bo, my $be) = _txn_begin($dbh); return (undef, $be) if $be;
    my $fail = sub { my ($x) = @_; eval { $dbh->rollback }; return (undef, $x) };
    my $touched = [];
    my $done = eval {
        $dbh->do("DELETE FROM pulse_group_members WHERE group_id=?", undef, $gid); die "db\n" if $dbh->err;
        for my $t (@ids) {
            $dbh->do("INSERT IGNORE INTO pulse_group_members (group_id, tester_id) VALUES (?,?)", undef, $gid, $t);
            die "db\n" if $dbh->err;
        }
        # The pair set changed with the group membership: new pairs get a row, dissolved ones lose it (closing
        # the tail in history). The check version does NOT grow: the executor changed, not the measurement, and
        # other agents' results remain evidence.
        my $cids = $dbh->selectcol_arrayref("SELECT check_id FROM pulse_check_groups WHERE group_id=?",
                                            undef, $gid);
        die "db\n" if $dbh->err;
        _pulse_sync_results($dbh, $cids); die "db\n" if $dbh->err;
        $touched = _pulse_sync_all_conditions($dbh, $cids); die "db\n" if $dbh->err;
        1;
    };
    return $fail->(_db_err_kind($dbh->err) || 'DB error') unless $done;
    unless ($dbh->commit) { my $k = _db_err_kind($dbh->err); eval { $dbh->rollback }; return (undef, $k) }
    # "All observers" may have changed with the group membership, so the rule must be recomputed now, not at
    # the next measurement.
    pulse_notify($_) for @{ $touched || [] };
    return (1, undef);
}

# ---- Checks -------------------------------------------------------------------------------------
# State change = a closed segment in history + a new current one. ONLY state is compared: the unknown
# reason changes by itself while grey stays grey, and the timeline must not be cut on it (§4.1).
sub _pulse_set_unknown {
    my ($dbh, $where, $reason, @args) = @_;
    $dbh->do(
        "INSERT INTO pulse_intervals (check_id, tester_id, state, started_at, ended_at)
         SELECT r.check_id, r.tester_id, r.state, r.since, NOW() FROM pulse_results r
          WHERE $where AND r.state <> 'unknown'", undef, @args);
    return if $dbh->err;
    $dbh->do(
        "UPDATE pulse_results r SET r.since = IF(r.state <> 'unknown', NOW(), r.since),
                r.state = 'unknown', r.unknown_reason = ?, r.confirmed_at = NULL
          WHERE $where", undef, $reason, @args);
}
# The measurement changed: the previous result describes something else and is no longer evidence.
sub _pulse_stale {
    my ($dbh, $cid) = @_;
    _pulse_set_unknown($dbh, "r.check_id = ?", 'stale_config', $cid);
}
# A panel switch is not "the agent vanished": a human stopped the observation. Disabled on EITHER side
# (tester or check) - no observation, so the old "healthy" must not read as evidence. Re-enabled -
# wait for the first result rather than reviving the old one.
sub _pulse_disable_sync {
    my ($dbh, $cid, $tid) = @_;
    my (@w, @a);
    if (defined $cid) { push @w, "r.check_id = ?";  push @a, $cid }
    if (defined $tid) { push @w, "r.tester_id = ?"; push @a, $tid }
    my $scope = @w ? join(' AND ', @w) : '1=1';
    my $off = "EXISTS(SELECT 1 FROM pulse_checks c  WHERE c.id = r.check_id  AND c.enabled = 0)
            OR EXISTS(SELECT 1 FROM pulse_testers t WHERE t.id = r.tester_id AND t.enabled = 0)";
    _pulse_set_unknown($dbh, "$scope AND ($off) AND NOT (r.state='unknown' AND r.unknown_reason='disabled')",
                       'disabled', @a);
    return if $dbh->err;
    # Re-enabled: the state stays unknown, but with an honest reason - no result yet.
    $dbh->do("UPDATE pulse_results r SET r.unknown_reason = 'no_result_yet'
               WHERE $scope AND r.unknown_reason = 'disabled' AND NOT ($off)", undef, @a);
}
# State change of the TESTER itself: close the previous segment in its history and open a new one.
# A transition to the same state is not a transition - nothing is touched.
# Re-enabled -> silent, not online: "online" must be proven by a confirmation, not a checkbox.
sub _pulse_tester_state {
    my ($dbh, $id, $want) = @_;
    my $cur = $dbh->selectrow_hashref("SELECT state, state_since FROM pulse_testers WHERE id=? FOR UPDATE",
                                      undef, $id);
    return if $dbh->err || !$cur || $cur->{state} eq $want;
    if ($cur->{state_since}) {
        $dbh->do("INSERT INTO pulse_tester_intervals (tester_id, state, started_at, ended_at)
                  VALUES (?,?,?,UTC_TIMESTAMP())", undef, $id, $cur->{state}, $cur->{state_since});
        return if $dbh->err;
        # Trim THIS agent's past, as everywhere, where we write. Segments are closed by two parties (the handler
        # when the agent goes silent, the panel when it is disabled); retention must be the same regardless of
        # which one closed the last.
        $dbh->do("DELETE h FROM pulse_tester_intervals h
                    JOIN settings s ON s.`key` = 'pulse_history_days'
                   WHERE h.tester_id = ?
                     AND s.`value` REGEXP '^[0-9]+\$'
                     AND CAST(s.`value` AS SIGNED) BETWEEN 1 AND 3650
                     AND h.ended_at < TIMESTAMPADD(DAY, -CAST(s.`value` AS SIGNED), UTC_TIMESTAMP())",
                 undef, $id);
        return if $dbh->err;
    }
    $dbh->do("UPDATE pulse_testers SET state=?, state_since=UTC_TIMESTAMP() WHERE id=?", undef, $want, $id);
}
# A pulse_results row is born WITH THE PAIR (a check assigned to a group the tester is in), not with the
# first result, so state never has "and sometimes there is no row":
#   1. transition order is held by the row lock (§4.1), and a missing row cannot be locked: two processes
#      would both read nothing and both insert;
#   2. "assigned, no result yet" is a state (unknown/no_result_yet) with an honest start: the assignment;
#   3. a dissolved pair has no row, so decision logic need not separately remember that a state belongs to
#      a pair that no longer exists. One source of truth instead of two.
# Called wherever the pair set changes: check-to-group assignment, group membership, group delete.
# Deleting the check or tester itself cascades the rows away (FK).
sub _pulse_sync_results {
    my ($dbh, $ids) = @_;
    return unless ref $ids eq 'ARRAY' && @$ids;
    my $runners = _pulse_runners_sql();
    for my $cid (@$ids) {
        # The tail of a dissolved pair goes into history as a closed segment - unless nothing ever happened to
        # the pair: nothing to remember.
        $dbh->do(
            "INSERT INTO pulse_intervals (check_id, tester_id, state, started_at, ended_at)
             SELECT r.check_id, r.tester_id, r.state, r.since, NOW()
               FROM pulse_results r
              WHERE r.check_id = ?
                AND NOT (r.state = 'unknown' AND r.unknown_reason = 'no_result_yet' AND r.last_report_at IS NULL)
                AND r.tester_id NOT IN $runners", undef, $cid, $cid, $cid);
        return if $dbh->err;
        $dbh->do(
            "DELETE FROM pulse_results
              WHERE check_id = ?
                AND tester_id NOT IN $runners", undef, $cid, $cid, $cid);
        return if $dbh->err;
        $dbh->do(
            "INSERT IGNORE INTO pulse_results (check_id, tester_id, state, unknown_reason, since)
             SELECT ?, x.tester_id, 'unknown', 'no_result_yet', NOW() FROM $runners AS x", undef, $cid, $cid, $cid);
        return if $dbh->err;
        # The pair may be born on a disabled side - then "waiting for the first result" would be false: nobody
        # observes. One function normalizes the reason.
        _pulse_disable_sync($dbh, $cid);
        return if $dbh->err;
    }
}
sub pulse_checks_all {
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $rows, my $e) = _db_all($dbh,
        "SELECT c.*, (SELECT GROUP_CONCAT(g.name ORDER BY g.name SEPARATOR ', ')
                        FROM pulse_check_groups cg JOIN pulse_groups g ON g.id=cg.group_id
                       WHERE cg.check_id=c.id) AS groups_label,
                     (SELECT GROUP_CONCAT(cg.group_id) FROM pulse_check_groups cg WHERE cg.check_id=c.id)
                       AS group_ids,
                     (SELECT GROUP_CONCAT(ca.tester_id) FROM pulse_check_agents ca WHERE ca.check_id=c.id)
                       AS agent_ids,
                     (SELECT COUNT(DISTINCT b.rule_id) FROM pulse_conditions pc
                        JOIN pulse_branches b ON b.id = pc.branch_id
                       WHERE pc.check_id = c.id) AS in_rules
           FROM pulse_checks c ORDER BY c.name", { Slice => {} });
    return (undef, $e) if $e;
    for my $r (@{ $rows || [] }) {
        $r->{group_ids} = _pulse_ids(delete $r->{group_ids});
        $r->{agent_ids} = _pulse_ids(delete $r->{agent_ids});
    }
    return ($rows || [], undef);
}
sub pulse_check_save {
    my ($id, $f) = @_;
    $f ||= {};
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $name, my $e) = _check_len($f->{name}, 'name', 64, 1); return (undef, $e) if $e;
    my $kind = lc($f->{kind} // '');
    return (undef, "kind must be icmp or tcp") unless $kind eq 'icmp' || $kind eq 'tcp';
    my $ip = $f->{target_ip};
    return (undef, 'target_ip must be an IP address, not a name — a name that switches would confirm itself')
        unless _pulse_ip_ok($ip);
    my $port;
    if ($kind eq 'tcp') {
        return (undef, 'port required for a TCP check')
            unless defined $f->{port} && $f->{port} =~ /^\d+$/ && $f->{port} >= 1 && $f->{port} <= 65535;
        $port = $f->{port} + 0;
    }
    # Whatever the form did not send comes from WHAT IS EDITED: a new check - the template in settings, an
    # existing one - itself. Otherwise renaming would silently move the measurement to today's template, and
    # the human would learn it from the rule's behaviour.
    my $fill = sub {
        my ($base) = @_;
        return (_pulse_int($f->{interval_seconds},   $base->{interval_seconds},   1, 86400),
                _pulse_int($f->{timeout_ms},         $base->{timeout_ms},        50, 60000),
                _pulse_int($f->{probes_per_run},     $base->{probes_per_run},     1, 20),
                _pulse_int($f->{fail_threshold},     $base->{fail_threshold},     1, 100),
                _pulse_int($f->{ok_threshold},       $base->{ok_threshold},       1, 100));
    };
    my ($iv, $to, $ppr, $ft, $ot) = $fill->(pulse_check_defaults());
    my $okp  = _pulse_int($f->{ok_probes_required}, pulse_check_defaults()->{ok_probes_required}, 1, $ppr);
    my $en   = defined $f->{enabled} ? ($f->{enabled} ? 1 : 0) : 1;
    if ($id) {
        return (undef, 'id required') unless $id =~ /^\d+$/;
        # The edit and its consequences are ONE transaction, and the PREVIOUS STATE is read INSIDE it, under the
        # same lock we write with. Otherwise: two read address old, the first changes it to new, the second only
        # renames but its form carries old; comparing with the pre-transaction read says "measurement unchanged",
        # so it restores old WITHOUT bumping the version, and stale results count as evidence again.
        (my $bo, my $be) = _txn_begin($dbh); return (undef, $be) if $be;
        my ($was, $measured);
        my $done = eval {
            $was = $dbh->selectrow_hashref("SELECT * FROM pulse_checks WHERE id=? FOR UPDATE", undef, $id);
            die "db\n" if $dbh->err;
            die "gone\n" unless $was;
            # Unsent numbers come from the check itself: it is already configured, the new-check template does not apply.
            ($iv, $to, $ppr, $ft, $ot) = $fill->($was);
            $okp = _pulse_int($f->{ok_probes_required}, $was->{ok_probes_required}, 1, $ppr);
            # The version grows ONLY when the measurement itself changes. Renaming does not make a result stale, and
            # enabled is handled separately: that is not "the result belongs to another measurement" but "no
            # observation any more".
            my %now = (kind => $kind, target_ip => $ip, port => $port,
                       interval_seconds => $iv, timeout_ms => $to, probes_per_run => $ppr,
                       ok_probes_required => $okp, fail_threshold => $ft, ok_threshold => $ot);
            $measured = grep { ($was->{$_} // '') ne ($now{$_} // '') } keys %now;
            $dbh->do(
                "UPDATE pulse_checks SET name=?, kind=?, target_ip=?, port=?, interval_seconds=?,
                        timeout_ms=?, probes_per_run=?, ok_probes_required=?, fail_threshold=?, ok_threshold=?,
                        enabled=?, config_version = config_version + ?
                  WHERE id=?", undef, $name, $kind, $ip, $port, $iv, $to, $ppr, $okp, $ft, $ot, $en,
                               ($measured ? 1 : 0), $id);
            die "db\n" if $dbh->err;
            # The measurement changed - previous results describe something else. Waiting for the daemon to notice
            # is not an option: until then the rule would decide on evidence from the old task.
            if ($measured) { _pulse_stale($dbh, $id); die "db\n" if $dbh->err }
            # Reason normalization ALWAYS, not only on an enabled change: it also rewrites stale_config to disabled
            # where a side is off. "Measurement first, then reason" follows naturally, and the reason lives in one place.
            _pulse_disable_sync($dbh, $id); die "db\n" if $dbh->err;
            1;
        };
        unless ($done) {
            my $why = $@ // '';
            my $k = ($why =~ /^gone/) ? 'not found' : (_db_err_kind($dbh->err) || 'DB error');
            eval { $dbh->rollback };
            return (undef, $k);
        }
        unless ($dbh->commit) { my $k = _db_err_kind($dbh->err); eval { $dbh->rollback }; return (undef, $k) }
        # What the rule looks at changed, not the rule: previous results are no longer evidence and any rule's
        # decision may have changed. "Recompute everything" is cheaper and more honest than working out who is
        # affected.
        pulse_notify(0);
        return ($id + 0, undef);
    }
    (my $dup, $e) = _db_exists($dbh, "SELECT 1 FROM pulse_checks WHERE name=?", $name); return (undef, $e) if $e;
    return (undef, "check '$name' already exists") if $dup;
    (my $ok, my $de) = _do($dbh,
        "INSERT INTO pulse_checks (name, kind, target_ip, port, interval_seconds, timeout_ms,
                                   probes_per_run, ok_probes_required, fail_threshold, ok_threshold, enabled)
         VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        $name, $kind, $ip, $port, $iv, $to, $ppr, $okp, $ft, $ot, $en);
    return (undef, $de) if $de;
    return ($dbh->last_insert_id(undef,undef,undef,undef) + 0, undef);
}
# Rule conditions reference the check directly: deleting it cascades them away (FK CASCADE), as with
# testers, so the answer must name the affected rules. A silent delete would leave a branch without
# conditions whose decision (unknown, docs/25 §6) holds the rule until a human intervenes - a human who
# would never be told.
sub pulse_check_delete {
    my ($id) = @_;
    return (undef, 'id required') unless $id && $id =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $rows, my $e) = _db_all($dbh,
        "SELECT DISTINCT r.id, r.rr_name, r.rr_type FROM pulse_conditions c
            JOIN pulse_branches b ON b.id = c.branch_id
            JOIN pulse_rules r    ON r.id = b.rule_id
           WHERE c.check_id = ?", { Slice => {} }, $id);
    return (undef, $e) if $e;
    (my $ok, my $de) = _do($dbh, "DELETE FROM pulse_checks WHERE id=?", $id);
    return (undef, $de) if $de;
    return ({ deleted => 1, affected_rules => [ map { "$_->{rr_name} $_->{rr_type}" } @{ $rows || [] } ] }, undef);
}
# Who runs the check: groups and optionally named agents. Third argument omitted (undef) - named
# assignments are left alone (that is how callers unaware of them call this).
sub pulse_check_groups_set {
    my ($cid, $group_ids, $agent_ids) = @_;
    return (undef, 'check id required') unless $cid && $cid =~ /^\d+$/;
    my @ids = grep { defined && /^\d+$/ } @{ $group_ids || [] };
    my @aids = defined $agent_ids ? (grep { defined && /^\d+$/ } @{ $agent_ids || [] }) : ();
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $ex, my $e) = _db_exists($dbh, "SELECT 1 FROM pulse_checks WHERE id=?", $cid); return (undef, $e) if $e;
    return (undef, 'check not found') unless $ex;
    (my $bo, my $be) = _txn_begin($dbh); return (undef, $be) if $be;
    my $fail = sub { my ($x) = @_; eval { $dbh->rollback }; return (undef, $x) };
    my $touched = [];
    my $done = eval {
        $dbh->do("DELETE FROM pulse_check_groups WHERE check_id=?", undef, $cid); die "db\n" if $dbh->err;
        for my $g (@ids) {
            $dbh->do("INSERT IGNORE INTO pulse_check_groups (check_id, group_id) VALUES (?,?)", undef, $cid, $g);
            die "db\n" if $dbh->err;
        }
        if (defined $agent_ids) {
            $dbh->do("DELETE FROM pulse_check_agents WHERE check_id=?", undef, $cid); die "db\n" if $dbh->err;
            for my $a (@aids) {
                $dbh->do("INSERT IGNORE INTO pulse_check_agents (check_id, tester_id) VALUES (?,?)",
                         undef, $cid, $a);
                die "db\n" if $dbh->err;
            }
        }
        # The version is NOT touched: the executor set is a set of pairs, not the meaning of the measurement.
        # Adding a second agent changes nothing for the first; its result is still honest. The pair set is
        # maintained by _pulse_sync_results, which needs no version.
        _pulse_sync_results($dbh, [ $cid ]); die "db\n" if $dbh->err;
        $touched = _pulse_sync_all_conditions($dbh, [ $cid ]); die "db\n" if $dbh->err;
        1;
    };
    return $fail->(_db_err_kind($dbh->err) || 'DB error') unless $done;
    unless ($dbh->commit) { my $k = _db_err_kind($dbh->err); eval { $dbh->rollback }; return (undef, $k) }
    pulse_notify($_) for @{ $touched || [] };
    return (1, undef);
}
# The "all agents running this check" condition is stored as the same observer rows as a hand-picked
# list: the engine reads ONE source and knows nothing about modes. The difference is that this set is
# rebuilt here on every change of who runs the check. Otherwise "all" would mean "all who were there that
# evening": a 21st agent added to the group would be silently ignored. Returns rules whose set changed
# (to be recomputed).
sub _pulse_sync_all_conditions {
    my ($dbh, $cids) = @_;              # undef or empty list = all checks
    my $only = ($cids && @$cids) ? " AND c.check_id IN (" . join(',', map { $_ + 0 } @$cids) . ")" : '';
    my $conds = $dbh->selectall_arrayref(
        "SELECT c.id, c.check_id, b.rule_id FROM pulse_conditions c
           JOIN pulse_branches b ON b.id = c.branch_id
          WHERE c.kind = 'check' AND c.check_id IS NOT NULL$only", { Slice => {} });
    return [] if $dbh->err;
    my (%touched, @order);
    for my $c (@{ $conds || [] }) {
        my $want = $dbh->selectcol_arrayref(
            "SELECT x.tester_id FROM " . _pulse_runners_sql() . " AS x",
            undef, $c->{check_id}, $c->{check_id});
        return [] if $dbh->err;
        my $have = $dbh->selectcol_arrayref(
            "SELECT tester_id FROM pulse_condition_testers WHERE condition_id = ?", undef, $c->{id});
        return [] if $dbh->err;
        my %w = map { $_ => 1 } @{ $want || [] };
        my %h = map { $_ => 1 } @{ $have || [] };
        next if keys(%w) == keys(%h) && !grep { !$h{$_} } keys %w;
        $dbh->do("DELETE FROM pulse_condition_testers WHERE condition_id = ?", undef, $c->{id});
        return [] if $dbh->err;
        for my $tid (keys %w) {
            $dbh->do("INSERT IGNORE INTO pulse_condition_testers (condition_id, tester_id) VALUES (?,?)",
                     undef, $c->{id}, $tid);
            return [] if $dbh->err;
        }
        push @order, $c->{rule_id} unless $touched{ $c->{rule_id} }++;
    }
    return \@order;
}
# Who RUNS the check - one query for the whole panel: agents of its groups plus named ones, no duplicates.
# This set used to be spelled out in four places, which would drift apart with a second assignment
# method. Used in IN/JOIN; the check id is bound TWICE.
sub _pulse_runners_sql {
    return "(SELECT m.tester_id FROM pulse_check_groups cg
               JOIN pulse_group_members m ON m.group_id = cg.group_id
              WHERE cg.check_id = ?
              UNION
             SELECT ca.tester_id FROM pulse_check_agents ca WHERE ca.check_id = ?)";
}
# Who the check is ASSIGNED to: testers of all assigned groups, WITHOUT duplicates (an agent in two groups
# runs it once). Disabled testers STAY here on purpose: a pair exists while the tester structurally belongs
# to the group, otherwise the switch would turn rule conditions into broken ones. A disabled tester just
# does not observe (its pairs sit in unknown/disabled) and is filtered by the returned enabled field when
# jobs are handed out.
sub pulse_check_testers {
    my ($cid) = @_;
    return (undef, 'check id required') unless $cid && $cid =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    my $runners = _pulse_runners_sql();
    (my $rows, my $e) = _db_all($dbh,
        "SELECT t.id, t.name, t.location, t.enabled, t.state
           FROM pulse_testers t WHERE t.id IN $runners ORDER BY t.name", { Slice => {} }, $cid, $cid);
    return (undef, $e) if $e;
    return ($rows || [], undef);
}
sub pulse_check_runs_on {
    my ($cid, $tid) = @_;
    return 0 unless $cid && $tid;
    my $dbh = connectDB() or return 0;
    my $runners = _pulse_runners_sql();
    my ($n) = $dbh->selectrow_array("SELECT 1 WHERE ? IN $runners", undef, $tid, $cid, $cid);
    return $n ? 1 : 0;
}

# ---- Slow sweep (§7): target list --------------------------------------------------------
# Sweep targets are ADDRESSES published in our zones (A and AAAA), not records: one address in three
# records is checked once. References to a target are kept per zone; when the last one goes, so does the
# target. The sweep follows what is published now, not memory. No voting: ONE collector takes a target
# per cycle (§7).
# The target list itself is maintained by pulse-server (store/sweepsync.go): after a zone edit the panel only
# tells it which zone changed. If the daemon is not listening the zone is flagged; the daemon rebuilds flagged
# zones, and everything on start.
sub pulse_sweep_after_write {
    my ($zid) = @_;
    return (0, 1) if pulse_sweep_notify($zid);
    pulse_sweep_mark_dirty($zid, 'pulse-server not reachable');
    return (1, 0);
}
sub pulse_sweep_mark_dirty {
    my ($zid, $err) = @_;
    return unless defined $zid && $zid =~ /^\d+$/;
    my $dbh = connectDB() or return;
    $dbh->do("INSERT INTO pulse_sweep_dirty (domain_id, since, last_error) VALUES (?, UTC_TIMESTAMP(), ?)
              ON DUPLICATE KEY UPDATE last_error = VALUES(last_error)",
             undef, $zid, _clip($err // 'sync failed', 255));
    return;
}
# Sweep parameter edits. The limits matter: a cycle per second would stop background work being
# background, and "zero days of retention" would wipe history. Out-of-range -> refused with a clear reason,
# not silently clamped: the human must learn they were not understood.
my %PULSE_POLICY_RANGE = (
    pulse_sweep_interval   => [ 60, 86400 ],
    pulse_sweep_batch      => [ 1, 500 ],
    pulse_sweep_parallel   => [ 1, 64 ],
    pulse_sweep_probes     => [ 1, 10 ],
    pulse_sweep_timeout_ms => [ 100, 10000 ],
    # 1 = the sweep also takes addresses of secondary zones (pulse-server follows their transfers by SOA).
    pulse_sweep_secondary  => [ 0, 1 ],
    pulse_history_days     => [ 1, 3650 ],
    # Defaults for a NEW check are a template, not control: a created check lives its own life and editing
    # these numbers does not touch existing ones. Otherwise one settings edit would silently change the
    # measurement of every check - exactly "the panel did something by itself".
    pulse_check_interval   => [ 1, 86400 ],
    pulse_check_timeout_ms => [ 50, 60000 ],
    pulse_check_probes     => [ 1, 20 ],
    pulse_check_ok_probes  => [ 1, 20 ],
    pulse_check_fail_runs  => [ 1, 100 ],
    pulse_check_ok_runs    => [ 1, 100 ],
);
# Some keys set sweep BEHAVIOUR, others only the new-check template. The split matters for the screen
# (different cards) and for meaning: the former act at once, the latter only at the next creation.
my %PULSE_CHECK_DEFAULT = (
    pulse_check_interval   => [ interval_seconds   => 5 ],
    pulse_check_timeout_ms => [ timeout_ms         => 1000 ],
    pulse_check_probes     => [ probes_per_run     => 3 ],
    pulse_check_ok_probes  => [ ok_probes_required => 1 ],
    pulse_check_fail_runs  => [ fail_threshold     => 3 ],
    pulse_check_ok_runs    => [ ok_threshold       => 3 ],
);
# Template for a new check, with fields named as the check names them. Settings rows may be missing - then
# the same numbers as before apply; the first edit in the panel creates them.
sub pulse_check_defaults {
    my %out = map { $PULSE_CHECK_DEFAULT{$_}[0] => $PULSE_CHECK_DEFAULT{$_}[1] } keys %PULSE_CHECK_DEFAULT;
    my $dbh = connectDB() or return \%out;
    my $rows = $dbh->selectall_arrayref(
        "SELECT `key`, `value` FROM settings WHERE `key` IN ("
        . join(',', map { '?' } keys %PULSE_CHECK_DEFAULT) . ")", { Slice => {} },
        sort keys %PULSE_CHECK_DEFAULT);
    for my $r (@{ $rows || [] }) {
        my $d = $PULSE_CHECK_DEFAULT{ $r->{key} } or next;
        my $lim = $PULSE_POLICY_RANGE{ $r->{key} };
        $out{ $d->[0] } = _pulse_int($r->{value}, $d->[1], $lim->[0], $lim->[1]);
    }
    # Never more confirmations than probes: the settings may diverge, the check must not.
    $out{ok_probes_required} = $out{probes_per_run} if $out{ok_probes_required} > $out{probes_per_run};
    return \%out;
}
# Slow sweep parameters. They are owned by settings rows: they are MEASUREMENT values, edited in the panel,
# not in the daemon config or code. Created here if missing. Deliberate initial values: one cycle per hour
# (the sweep is slow by design), batches of twenty targets, one second per probe and four probes at once -
# background work must not disturb checks. Two attempts per target (one lost packet is not an outage),
# and three months of history.
sub pulse_sweep_policy {
    my %def = (
        pulse_sweep_interval   => 3600,
        pulse_sweep_batch      => 20,
        pulse_sweep_timeout_ms => 1000,
        pulse_sweep_parallel   => 4,
        pulse_sweep_probes     => 2,
        pulse_sweep_secondary  => 0,
        # HISTORY retention, for both checks and the sweep. History answers "when did it start and has it
        # happened before", and three months suffice; unbounded history just grows until it gets in its own way.
        pulse_history_days     => 90,
    );
    my $dbh = connectDB() or return { %def };
    # Keys are listed EXPLICITLY: the pattern 'pulse_sweep\_%' did not cover pulse_history_days, so the value
    # the human edited was read only by the cleanup while the panel kept showing the default.
    my $rows = $dbh->selectall_arrayref(
        "SELECT `key`, `value` FROM settings WHERE `key` IN ("
        . join(',', map { '?' } sort keys %def) . ")", { Slice => {} }, sort keys %def);
    my %v = map { $_->{key} => $_->{value} } @{ $rows || [] };
    my %out;
    for my $k (sort keys %def) {
        unless (exists $v{$k}) {
            $v{$k} = $def{$k};
            $dbh->do("INSERT IGNORE INTO settings (`key`,`value`) VALUES (?, ?)", undef, $k, $def{$k});
        }
        # Limits are the same as when the setting is saved. A blanket "1..86400" would be two rules for one
        # number: the panel refuses 1000 parallel probes, yet reading would return them if the row was corrupted
        # outside the panel.
        my $lim = $PULSE_POLICY_RANGE{$k} || [ 1, 86400 ];
        $out{$k} = _pulse_int($v{$k}, $def{$k}, $lim->[0], $lim->[1]);
    }
    return \%out;
}
sub pulse_policy_fields { return [ sort keys %PULSE_POLICY_RANGE ] }
sub pulse_policy_set {
    my ($f) = @_;
    $f ||= {};
    my %want;
    for my $k (keys %$f) {
        my $r = $PULSE_POLICY_RANGE{$k} or return (undef, "unknown setting '$k'");
        my $v = $f->{$k};
        return (undef, "$k must be a whole number") unless defined $v && $v =~ /^\d+$/;
        return (undef, "$k must be between $r->[0] and $r->[1]") if $v < $r->[0] || $v > $r->[1];
        $want{$k} = $v + 0;
    }
    return (undef, 'nothing to save') unless %want;
    # "How many probes" and "how many must answer" are checked AFTER merging with what is stored: one field
    # may be sent, and the combination becomes impossible. Otherwise the panel would show a saved 5 of 2 while
    # a new check silently got 2 - two truths about one thing.
    my $now = pulse_check_defaults();
    my %eff = (probes => $want{pulse_check_probes}    // $now->{probes_per_run},
               ok     => $want{pulse_check_ok_probes} // $now->{ok_probes_required});
    return (undef, 'OK probes needed cannot exceed probes per run') if $eff{ok} > $eff{probes};
    my $was = pulse_sweep_policy()->{pulse_sweep_secondary};
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    for my $k (sort keys %want) {
        $dbh->do("INSERT INTO settings (`key`,`value`) VALUES (?,?)
                  ON DUPLICATE KEY UPDATE `value`=VALUES(`value`)", undef, $k, $want{$k});
        return (undef, _db_err_kind($dbh->err) || 'DB error') if $dbh->err;
    }
    # Which zones the sweep takes has changed: pulse-server rebuilds the whole list (if it is down, it does so on start).
    _pulse_control({ cmd => 'sweep', all => \1 })
        if exists $want{pulse_sweep_secondary} && $want{pulse_sweep_secondary} != $was;
    return (\%want, undef);
}
# What the sweep knows about ONE zone's addresses: address -> last state, when and by whom checked. The
# records table only needs to show problems (§7), but the page decides that, not this function.
sub pulse_sweep_zone_states {
    my ($zid, $scope) = @_;
    return (undef, 'zone id required') unless $zid && $zid =~ /^\d+$/;
    $scope = 'default' unless defined $scope && length $scope;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    # State is the LAST ACTUAL check and does not expire. The sweep does not promise to cover every address per
    # cycle: `pulse_sweep_interval` means "no more often than", not "at least once per". With one agent for
    # fifty thousand addresses the queue just stretches, and clearing the red dot because the address has not
    # been reached yet would lose exactly what the sweep is for: "this address has been silent for long, clean
    # the zone". The answer's age is shown alongside - that is the freshness answer.
    (my $rows, my $e) = _db_all($dbh,
        "SELECT DISTINCT t.target_ip, t.family, t.last_state, t.last_checked_at, t.state_since,
                p.name AS agent
           FROM pulse_sweep_targets t
           JOIN pulse_sweep_refs r ON r.target_id = t.id AND r.until IS NULL
           LEFT JOIN pulse_testers p ON p.id = t.last_checked_by
          WHERE r.domain_id = ? AND t.net_scope = ?", { Slice => {} }, $zid, $scope);
    return (undef, $e) if $e;
    $_->{state} = $_->{last_state} for @{ $rows || [] };
    my %by = map { $_->{target_ip} => $_ } @{ $rows || [] };
    return (\%by, undef);
}

# ---- History: state timelines ------------------------------------------------------------------
# "It switched" is half the answer; the other half is WHEN and WHY. Everything is already recorded - closed
# pair state segments (§4.1), the current open segment in pulse_results and rule events - and is only
# assembled into one timeline here. The window is chosen by the human; it is NOT a loop timer: nothing wakes
# up or polls, it is just another time range in the query.
my %PULSE_WINDOWS = ( '1d' => 86400, '1w' => 604800, '1m' => 2592000 );
sub pulse_history {
    my ($opt) = @_;
    my $win  = ($opt->{window} // '1d');
    my $secs = $PULSE_WINDOWS{$win} or return (undef, 'window must be 1d, 1w or 1m');
    my $only = $opt->{check_id};
    return (undef, 'check id required') if defined $only && $only !~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');

    # Window bounds WITHOUT fractional seconds: they are compared with segment rows, and "...56.000000" sorts
    # differently from "...56", shifting the left edge by a second.
    my ($from, $now) = $dbh->selectrow_array(
        "SELECT DATE_FORMAT(UTC_TIMESTAMP() - INTERVAL ? SECOND, '%Y-%m-%d %H:%i:%s'),
                DATE_FORMAT(UTC_TIMESTAMP(), '%Y-%m-%d %H:%i:%s')", undef, $secs);
    return (undef, 'DB error') unless $from;

    (my $checks, my $ce) = _db_all($dbh,
        "SELECT id, name, kind, target_ip, port FROM pulse_checks"
        . (defined $only ? " WHERE id = ?" : "") . " ORDER BY name", { Slice => {} },
        (defined $only ? ($only) : ()));
    return (undef, $ce) if $ce;

    for my $c (@{ $checks || [] }) {
        # Pair segments: closed ones from history plus the CURRENT one still running. Without it the timeline
        # would stop at the last transition, and "now" is its most needed part.
        (my $rows, my $re) = _db_all($dbh,
            "SELECT i.tester_id, t.name AS tester, i.state, i.started_at, i.ended_at
               FROM pulse_intervals i JOIN pulse_testers t ON t.id = i.tester_id
              WHERE i.check_id = ? AND i.ended_at > ?
              UNION ALL
             SELECT r.tester_id, t.name, r.state, r.since, NULL
               FROM pulse_results r JOIN pulse_testers t ON t.id = r.tester_id
              WHERE r.check_id = ?
              ORDER BY tester, started_at", { Slice => {} }, $c->{id}, $from, $c->{id});
        return (undef, $re) if $re;
        my (%by, @order);
        for my $r (@{ $rows || [] }) {
            my $a = $by{ $r->{tester_id} };
            unless ($a) {
                $a = $by{ $r->{tester_id} } = { tester_id => $r->{tester_id} + 0, name => $r->{tester},
                                                segments => [] };
                push @order, $a;
            }
            # A segment that started BEFORE the window is shown from its left edge: it is part of the picture too.
            my $st = ($r->{started_at} lt $from) ? $from : $r->{started_at};
            my $en = $r->{ended_at} // $now;
            next if $en le $st;
            push @{ $a->{segments} }, { state => $r->{state}, from => $st, to => $en };
        }
        $c->{agents} = \@order;

        # Switch events only of rules that ask about THIS check; otherwise timeline marks would answer another question.
        (my $evs, my $ee) = _db_all($dbh,
            "SELECT e.at, e.rule_id, e.from_set, e.to_set, e.reason, e.actor,
                    r.rr_name, r.rr_type
               FROM pulse_rule_events e
               JOIN pulse_rules r ON r.id = e.rule_id
              WHERE e.at >= ? AND EXISTS(SELECT 1 FROM pulse_rule_event_checks ec
                                          WHERE ec.event_id = e.id AND ec.check_id = ?)
              ORDER BY e.at", { Slice => {} }, $from, $c->{id});
        return (undef, $ee) if $ee;
        $c->{events} = $evs || [];
    }
    # Agents themselves get their own timeline: "who was silent when" is about observation quality, not about
    # the check. Built the same way: closed segments plus the unclosed tail from the agent card.
    (my $tst, my $terr) = _db_all($dbh,
        "SELECT id, name, state, DATE_FORMAT(state_since, '%Y-%m-%d %H:%i:%s') AS since, enabled
           FROM pulse_testers WHERE approved_at IS NOT NULL ORDER BY name", { Slice => {} });
    return (undef, $terr) if $terr;
    my %tby = map { $_->{id} => { id => $_->{id} + 0, name => $_->{name}, state => $_->{state},
                                 segments => [] } } @{ $tst || [] };
    (my $tiv, my $tie) = _db_all($dbh,
        "SELECT tester_id, state, DATE_FORMAT(started_at, '%Y-%m-%d %H:%i:%s') AS started_at,
                DATE_FORMAT(ended_at, '%Y-%m-%d %H:%i:%s') AS ended_at
           FROM pulse_tester_intervals WHERE ended_at >= ? ORDER BY started_at", { Slice => {} }, $from);
    return (undef, $tie) if $tie;
    for my $r (@{ $tiv || [] }) {
        my $t = $tby{ $r->{tester_id} } or next;
        my $st = ($r->{started_at} lt $from) ? $from : $r->{started_at};
        next if $r->{ended_at} le $st;
        push @{ $t->{segments} }, { state => $r->{state}, from => $st, to => $r->{ended_at} };
    }
    for my $r (@{ $tst || [] }) {
        my $t = $tby{ $r->{id} } or next;
        my $st = (!$r->{since} || $r->{since} lt $from) ? $from : $r->{since};
        push @{ $t->{segments} }, { state => $r->{state}, from => $st, to => $now } if $now gt $st;
    }
    return ({ from => $from, to => $now, window => $win, checks => $checks || [],
              testers => [ map { $tby{ $_->{id} } } @{ $tst || [] } ] }, undef);
}

# Slow sweep history for ONE RRset: one timeline per address, glued from closed segments and the target's
# open tail, and cut to the periods when the address ACTUALLY belonged to this record. Without the cut the
# first record would show an outage that happened after the address moved to a second one: the target is
# panel-wide, the question here is about this record.
sub pulse_sweep_rrset_history {
    my ($zid, $name, $type, $window) = @_;
    my $secs = $PULSE_WINDOWS{ $window // '1d' } or return (undef, 'window must be 1d, 1w or 1m');
    return (undef, 'zone id required') unless $zid && $zid =~ /^\d+$/;
    (my $nm, my $nerr) = dns_record_name_norm($name);
    return (undef, $nerr) if $nerr;
    my $tp = uc($type // '');
    return (undef, 'type must be A or AAAA') unless $tp eq 'A' || $tp eq 'AAAA';
    my $dbh = connectDB() or return (undef, 'DB unavailable');

    my ($from, $now) = $dbh->selectrow_array(
        "SELECT DATE_FORMAT(UTC_TIMESTAMP() - INTERVAL ? SECOND, '%Y-%m-%d %H:%i:%s'),
                DATE_FORMAT(UTC_TIMESTAMP(), '%Y-%m-%d %H:%i:%s')", undef, $secs);
    return (undef, 'DB error') unless $from;

    # Ownership periods: the address may have left and returned, each time a separate segment.
    (my $refs, my $rerr) = _db_all($dbh,
        "SELECT t.id AS target_id, t.target_ip, t.family, t.last_state, t.state_since,
                t.last_checked_at, t.unref_at, p.name AS agent,
                DATE_FORMAT(r.since, '%Y-%m-%d %H:%i:%s') AS ref_from,
                DATE_FORMAT(r.until, '%Y-%m-%d %H:%i:%s') AS ref_to
           FROM pulse_sweep_refs r
           JOIN pulse_sweep_targets t ON t.id = r.target_id
           LEFT JOIN pulse_testers p ON p.id = t.last_checked_by
          WHERE r.domain_id = ? AND r.rr_name = ? AND r.rr_type = ?
            AND (r.until IS NULL OR r.until >= ?)
          ORDER BY t.target_ip, r.since", { Slice => {} }, $zid, $nm, $tp, $from);
    return (undef, $rerr) if $rerr;
    return ({ from => $from, to => $now, window => ($window // '1d'), addresses => [] }, undef)
        unless @{ $refs || [] };

    my %own;                               # address -> ownership periods within the window
    my %meta;
    for my $r (@$refs) {
        my $a = ($own{ $r->{target_ip} } ||= []);
        my $b = ($r->{ref_from} gt $from) ? $r->{ref_from} : $from;
        my $e = (defined $r->{ref_to} && $r->{ref_to} lt $now) ? $r->{ref_to} : $now;
        push @$a, [ $b, $e ] if $e gt $b;
        $meta{ $r->{target_ip} } ||= { target_id => $r->{target_id}, family => $r->{family},
                                       last_state => $r->{last_state}, agent => $r->{agent},
                                       last_checked_at => $r->{last_checked_at},
                                       unref_at => $r->{unref_at}, state_since => $r->{state_since},
                                       current => 0 };
        # "Current" is about THIS record, not observation in general: the address may live on in another record
        # and is still former for ours.
        $meta{ $r->{target_ip} }{current} = 1 unless defined $r->{ref_to};
    }

    my @out;
    for my $ip (sort keys %own) {
        my $m = $meta{$ip};
        (my $iv, my $ie) = _db_all($dbh,
            "SELECT i.state, DATE_FORMAT(i.started_at, '%Y-%m-%d %H:%i:%s') AS f,
                    DATE_FORMAT(i.ended_at, '%Y-%m-%d %H:%i:%s') AS t, p.name AS ended_by
               FROM pulse_sweep_intervals i
               LEFT JOIN pulse_testers p ON p.id = i.ended_by
              WHERE i.target_id = ? AND i.ended_at >= ? ORDER BY i.started_at",
            { Slice => {} }, $m->{target_id}, $from);
        return (undef, $ie) if $ie;
        my @raw = map { { state => $_->{state}, from => $_->{f}, to => $_->{t},
                          ended_by => $_->{ended_by} } } @{ $iv || [] };
        # Open tail: what the target holds now. It ends where the target stopped being observed.
        my $tail_end = $m->{unref_at} ? substr($m->{unref_at}, 0, 19) : $now;
        my $tail_beg = $m->{state_since} ? substr($m->{state_since}, 0, 19) : $from;
        $tail_beg = $from if $tail_beg lt $from;
        push @raw, { state => $m->{last_state}, from => $tail_beg, to => $tail_end }
            if $tail_end gt $tail_beg;

        # Cut by ownership: only the time the address stood in THIS record.
        my @seg;
        for my $s (@raw) {
            for my $o (@{ $own{$ip} }) {
                my $b = ($s->{from} gt $o->[0]) ? $s->{from} : $o->[0];
                my $e = ($s->{to}   lt $o->[1]) ? $s->{to}   : $o->[1];
                push @seg, { state => $s->{state}, from => $b, to => $e } if $e gt $b;
            }
        }
        @seg = sort { $a->{from} cmp $b->{from} } @seg;

        # TRANSITIONS, not every probe: the human asks "when did it change" and "who saw it". The transition
        # moment comes from the segment that closed then - closed by whoever saw the change. A segment start that
        # coincides with the address joining the record is NOT a transition: ownership changed, not state, and
        # mixing them would lie about availability.
        my @tr;
        for my $i (1 .. $#raw) {
            next if $raw[$i]{state} eq $raw[$i - 1]{state};
            my $at = $raw[$i]{from};
            next unless grep { $at ge $_->[0] && $at le $_->[1] } @{ $own{$ip} };
            push @tr, { at => $at, state => $raw[$i]{state}, agent => $raw[$i - 1]{ended_by} };
        }
        @tr = reverse @tr;                 # newest first: the human looks at "what happened last"

        push @out, { ip => $ip, family => $m->{family},
                     state => $m->{last_state},
                     transitions => \@tr, state_since => $m->{state_since},
                     last_checked_at => $m->{last_checked_at}, agent => $m->{agent},
                     current => $m->{current},
                     owned => [ map { { from => $_->[0], to => $_->[1] } } @{ $own{$ip} } ],
                     segments => \@seg };
    }
    return ({ from => $from, to => $now, window => ($window // '1d'), addresses => \@out }, undef);
}
# History of ONE record: what Pulse published and why. Segments are not stored but derived from events:
# each says "was -> became", so between two events lies the set the first one installed. Left of the first
# event - what was BEFORE it; right of the last - what stands now.
sub pulse_rrset_history {
    my ($zid, $name, $type, $window) = @_;
    my $secs = $PULSE_WINDOWS{ $window // '1d' } or return (undef, 'window must be 1d, 1w or 1m');
    return (undef, 'zone id required') unless $zid && $zid =~ /^\d+$/;
    (my $nm, my $nerr) = dns_record_name_norm($name);
    return (undef, $nerr) if $nerr;
    my $dbh = connectDB() or return (undef, 'DB unavailable');

    my ($from, $now) = $dbh->selectrow_array(
        "SELECT DATE_FORMAT(UTC_TIMESTAMP() - INTERVAL ? SECOND, '%Y-%m-%d %H:%i:%s'),
                DATE_FORMAT(UTC_TIMESTAMP(), '%Y-%m-%d %H:%i:%s')", undef, $secs);
    return (undef, 'DB error') unless $from;

    (my $r, my $re) = _db_row($dbh,
        "SELECT id, state, enabled, active_branch_id,
                (SELECT b.position + 1 FROM pulse_branches b WHERE b.id = r.active_branch_id) AS branch_no
           FROM pulse_rules r WHERE domain_id=? AND rr_name=? AND rr_type=?", $zid, $nm, uc($type // ''));
    return (undef, $re) if $re;
    # No rule - say so: the tab has nothing to come from, and inventing an empty history is pointless.
    return ({ from => $from, to => $now, window => ($window // '1d'), rule => undef,
              events => [], segments => [] }, undef) unless $r;

    (my $evs, my $ee) = _db_all($dbh,
        "SELECT e.id, e.at, e.from_set, e.to_set, e.reason, e.actor,
                (SELECT b.position + 1 FROM pulse_branches b WHERE b.id = e.branch_id) AS branch_no
           FROM pulse_rule_events e WHERE e.rule_id = ? AND e.at >= ? ORDER BY e.at",
        { Slice => {} }, $r->{id}, $from);
    return (undef, $ee) if $ee;

    # A segment has not only a set but an OWNER: branch number N or the fallback set. The number comes from the
    # event that opened the segment. The leftmost one has none - it started before the window, and "unknown
    # owner" is not "fallback": attributing it to default would invent history.
    my @seg;
    my $cur = $from;
    my ($branch, $known) = (undef, 0);
    for my $e (@{ $evs || [] }) {
        push @seg, { from => $cur, to => $e->{at}, set => $e->{from_set},
                     branch_no => $branch, known => $known } if $e->{at} gt $cur;
        $cur    = $e->{at};
        $branch = $e->{branch_no};      # NULL for the "no rule matches" event - that is the fallback set
        $known  = 1;
    }
    # Tail: what is published now - the last event's "became", or if there were no events in the window,
    # what the rule holds as published.
    my $tail = @{ $evs || [] } ? $evs->[-1]{to_set} : undef;
    unless (defined $tail) {
        (my $vals, my $ve) = _db_all($dbh,
            "SELECT content, prio FROM pulse_rrset_values WHERE rule_id=? AND published=1 ORDER BY content",
            { Slice => {} }, $r->{id});
        return (undef, $ve) if $ve;
        $tail = _pulse_set_text(uc($type // ''), [ map { { content => $_->{content}, prio => $_->{prio} } }
                                                   @{ $vals || [] } ]) if @{ $vals || [] };
    }
    my $tail_branch = $known ? $branch : ((($r->{state} // '') eq 'switched') ? $r->{branch_no} : undef);
    my $tail_known  = ($known || ($r->{state} // '') ne 'held') ? 1 : 0;
    push @seg, { from => $cur, to => $now, set => $tail, branch_no => $tail_branch,
                 known => $tail_known } if $now gt $cur;

    return ({ from => $from, to => $now, window => ($window // '1d'),
              rule => { id => $r->{id} + 0, state => $r->{state}, enabled => $r->{enabled} + 0,
                        branch_no => $r->{branch_no} },
              events => $evs || [], segments => \@seg }, undef);
}

# ---- Rules --------------------------------------------------------------------------------------
# A record's canonical value - ONE function for saving variants and comparing with the zone. Without it
# "mx.example" and "MX.EXAMPLE." would be different strings, and the rule would either decide forever it
# was overridden or rewrite the zone every cycle (docs/25 §6).
# Names are lowercased and one trailing root dot is removed - exactly as dns_record_name_norm does for the
# record name. TXT is untouched: every character matters there.
sub pulse_canon_value {
    my ($type, $content, $prio) = @_;
    $type = uc($type // '');
    $content = '' unless defined $content;
    $content =~ s/^\s+//; $content =~ s/\s+$//;
    if ($type eq 'CNAME' || $type eq 'NS' || $type eq 'MX') {
        $content = lc $content;
        $content =~ s/\.$// unless $content eq '.';
    } elsif ($type eq 'SRV') {
        # "weight port target": the target is a name, the rest numbers.
        my @f = split /\s+/, $content;
        if (@f == 3) { $f[2] = lc $f[2]; $f[2] =~ s/\.$// unless $f[2] eq '.'; $content = join ' ', @f }
    } elsif ($type eq 'CAA') {
        my $c = canonicalize_caa($content);
        $content = $c if defined $c;
    }
    return { content => $content,
             prio => (defined $prio && $prio =~ /^\d+$/ ? $prio + 0 : undef) };
}
# A set as a COMPARABLE value: order is irrelevant, so it is sorted. The string serves both as a snapshot in
# switch history and to answer "is this still what we published".
sub pulse_canon_set {
    my ($type, $values) = @_;
    my @out;
    for my $v (@{ $values || [] }) {
        my ($c, $p) = ref $v eq 'HASH' ? ($v->{content}, $v->{prio}) : ($v, undef);
        my $one = pulse_canon_value($type, $c, $p);
        push @out, (defined $one->{prio} ? "$one->{prio} " : '') . $one->{content};
    }
    return join ' | ', sort @out;
}

# Is this RRset managed by an enabled Pulse rule? Returns the refusal text or undef.
sub _pulse_rrset_locked {
    my ($domain_id, $ops) = @_;
    my $dbh = connectDB() or return undef;   # without the panel DB stay silent: not its path
    for my $o (@{ ref $ops eq 'ARRAY' ? $ops : [] }) {
        my ($name, $nerr) = dns_record_name_norm($o->{name});
        next if $nerr;
        my ($id) = $dbh->selectrow_array(
            "SELECT id FROM pulse_rules WHERE domain_id=? AND rr_name=? AND rr_type=? AND enabled=1",
            undef, $domain_id, $name, uc($o->{type} // ''));
        next unless $id;
        return "$name " . uc($o->{type}) . " is managed by NS Pulse — switch the rule off to edit it by hand";
    }
    return undef;
}

# Types Pulse may manage. SOA, DNSSEC internals and catalog internals are excluded: neither humans nor
# Pulse own them. The rest are ordinary zone RRsets; Pulse knows only the name and the value set, and
# content is validated by the same part of the panel as regular records.
our @PULSE_RR_TYPES = qw(A AAAA CNAME MX NS SRV TXT);
our %PULSE_RR_OK = map { $_ => 1 } @PULSE_RR_TYPES;

# The current value set of a record, whole. A rule is bound to an RRset (name + type), not to a row or an
# address: MX usually has several, A sometimes too, and the "primary" is a SET.
sub _pulse_rrset_now {
    my ($domain_id, $rr_name, $rr_type) = @_;
    my $pdns = connectPDNS() or return (undef, 'DB unavailable');
    my $rows = $pdns->selectall_arrayref(
        "SELECT content, ttl, prio FROM records WHERE domain_id=? AND name=? AND type=? ORDER BY content",
        { Slice => {} }, $domain_id, $rr_name, $rr_type);
    return (undef, _db_err_kind($pdns->err) || 'DB error') if $pdns->err;
    return (undef, "there is no $rr_type record for $rr_name") unless $rows && @$rows;
    return ({ ttl => $rows->[0]{ttl},
              values => [ map { { content => $_->{content}, prio => $_->{prio} } } @$rows ] }, undef);
}

# Zones where Pulse may change anything. pulse.manage allows moving a record, so it also opens the
# candidate list: otherwise the human would type the name blind.
sub pulse_zones_writable {
    my $rows = pdns_list_domains();
    my @out;
    for my $d (@$rows) {
        next if _zone_type_write_error($d->{type});
        push @out, { id => $d->{id} + 0, name => $d->{name} };
    }
    return (\@out, undef);
}
sub pulse_control_socket {
    my $p = get_config_value('pulse', 'control_socket');
    return (defined $p && length $p) ? $p : '/run/dns-panel/pulse/control.sock';
}
# Pulse gets no timeout of its own: it is a local control socket like the HA manager's, answering at once
# or not at all. The same value the panel uses for a short manager question - one number for both
# socket calls, since two would eventually diverge.
sub _pulse_socket_timeout { return ha_manager_timeout('status') }
# Tell the daemon a rule changed. Otherwise it would learn of an enabled rule only from agents, and a
# schedule-only rule may have no agents at all - "Turn on" would look like a switch that switches nothing.
# A failure does NOT break saving: panel and daemon live apart, and failing a rule save because the
# daemon is down is worse than saving (pulse_server_alive shows it elsewhere).
# rule_id = 0 means "recompute everything": used when what rules look at changed, not a rule.
sub pulse_notify {
    my ($rule_id) = @_;
    return _pulse_control({ cmd => 'recompute', rule => (($rule_id // 0) + 0) });
}
# The sweep target list is behind: the zone was edited but could not be parsed. Tell the daemon - it
# retries with growing backoff. Called HERE, not after the mark is written: the typical failure makes the
# DB unavailable for both writes, leaving no mark in the DB but an event to report.
sub pulse_sweep_notify {
    my ($zid) = @_;
    return _pulse_control({ cmd => 'sweep', zone => (($zid // 0) + 0) });
}
sub _pulse_control {
    my ($cmd) = @_;
    my $path = pulse_control_socket();
    return 0 unless -S $path;
    require IO::Socket::UNIX;
    my $sock = IO::Socket::UNIX->new(Peer => $path, Timeout => _pulse_socket_timeout())
        or return 0;
    eval { print $sock encode_json($cmd) . "\n"; 1 };
    close $sock;
    return 1;
}
# Is anyone listening? The socket file may be left from a previous run, so this connects rather than
# checks existence: "the daemon is not up" is something to tell the human, not to guess.
sub pulse_server_alive {
    my $path = pulse_control_socket();
    return 0 unless -S $path;
    require IO::Socket::UNIX;
    my $sock = IO::Socket::UNIX->new(Peer => $path, Timeout => _pulse_socket_timeout())
        or return 0;
    close $sock;
    return 1;
}

# Everything to put into pulse-agent.toml: one answer to the human's one question, "what goes onto the
# machine that will check". The fingerprint is from the row the server made for itself - it belongs to the
# PAIR, not the node (docs/25 §1); without it the first connection is trust-on-first-use.
sub pulse_server_hint {
    my $dbh = connectDB() or return {};
    my ($fp) = $dbh->selectrow_array("SELECT fingerprint FROM pulse_server_tls WHERE id=1");
    # The address comes from PAIR settings, not a file on disk: agents connect to the service address, one for
    # both nodes, and a second copy on the other node would eventually diverge. Not set - say so; a plausible
    # substitute is worse than a blank because a wrong value goes unnoticed.
    my ($addr) = $dbh->selectrow_array("SELECT `value` FROM settings WHERE `key`='pulse_server_address'");
    my ($key)  = $dbh->selectrow_array("SELECT enroll_key FROM pulse_enrollment WHERE id=1");
    # Is the handler up? Without it rules can be configured and enabled but nobody switches them, and the
    # screen must say so rather than look alive.
    return { address => $addr, fingerprint => $fp, enroll_key => $key, running => (pulse_server_alive() ? 1 : 0) };
}
# Address where agents find Pulse, stored with the other pair settings.
sub pulse_server_address_set {
    my ($addr) = @_;
    $addr = _trim($addr) // '';
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    if (!length $addr) {
        (my $ok, my $de) = _do($dbh, "DELETE FROM settings WHERE `key`='pulse_server_address'");
        return (undef, $de) if $de;
        return (1, undef);
    }
    return (undef, 'address must look like host:port') unless $addr =~ /^(\S+):(\d{1,5})\z/;
    return (undef, 'port must be 1..65535') if $2 < 1 || $2 > 65535;
    return (undef, 'address is too long') if length($addr) > 128;
    (my $ok, my $e) = _do($dbh,
        "INSERT INTO settings (`key`, `value`) VALUES ('pulse_server_address', ?)
         ON DUPLICATE KEY UPDATE `value`=VALUES(`value`)", $addr);
    return (undef, $e) if $e;
    return (1, undef);
}

# Rule draft for an RRset that has NO rule yet. Opening Pulse settings creates nothing: nothing appears in
# the DB until the human saves. Returns the same as pulse_rule_get, without id and with empty branches.
sub pulse_rrset_draft {
    my ($domain_id, $rr_name, $rr_type) = @_;
    return (undef, 'domain_id required') unless $domain_id && $domain_id =~ /^\d+$/;
    my $type = uc($rr_type // '');
    return (undef, 'Pulse does not manage ' . ($type || 'that type') . ' records') unless $PULSE_RR_OK{$type};
    (my $name, my $nerr) = dns_record_name_norm($rr_name);
    return (undef, $nerr) if $nerr;
    if (my $we = pdns_zone_write_error($domain_id)) { return (undef, $we) }
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $have, my $he) = _db_row($dbh,
        "SELECT id FROM pulse_rules WHERE domain_id=? AND rr_name=? AND rr_type=?", $domain_id, $name, $type);
    return (undef, $he) if $he;
    return pulse_rule_get($have->{id}) if $have;   # settings already exist - return them
    (my $cur, my $ce) = _pulse_rrset_now($domain_id, $name, $type);
    return (undef, $ce) if $ce;
    return ({ id => undef, domain_id => $domain_id + 0, rr_name => $name, rr_type => $type,
              ttl => ($cur->{ttl} || 300), default_hold_seconds => 300, schedule_tz => 'UTC',
              enabled => 0, state => 'default', branches => [],
              values => $cur->{values} }, undef);
}

# A candidate is any RRset of a managed type. The number of values no longer matters: a rule manages a
# SET, not one address.
sub pulse_rule_candidates {
    my ($domain_id) = @_;
    return (undef, 'domain_id required') unless $domain_id && $domain_id =~ /^\d+$/;
    if (my $we = pdns_zone_write_error($domain_id)) { return (undef, $we) }
    my $pdns = connectPDNS() or return (undef, 'DB unavailable');
    my $in = join ',', map { $pdns->quote($_) } @PULSE_RR_TYPES;
    my $rows = $pdns->selectall_arrayref(
        "SELECT name, type, COUNT(*) AS n, GROUP_CONCAT(content ORDER BY content SEPARATOR ' | ') AS vals
           FROM records WHERE domain_id=? AND type IN ($in) GROUP BY name, type ORDER BY name, type",
        { Slice => {} }, $domain_id);
    return (undef, _db_err_kind($pdns->err) || 'DB error') if $pdns->err;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    # Already configured ones are NOT hidden: the list also serves copying settings to other records, and a
    # hidden target looks like "no such record". Show it and say it is configured - the human decides.
    my $taken = $dbh->selectall_hashref(
        "SELECT CONCAT(rr_name, ' ', rr_type) AS k, id, enabled FROM pulse_rules WHERE domain_id=?",
        'k', undef, $domain_id);
    return (undef, _db_err_kind($dbh->err) || 'DB error') if $dbh->err;
    return ([ map { my $t = $taken->{ "$_->{name} $_->{type}" };
                    { name => $_->{name}, type => $_->{type}, values => $_->{vals}, count => $_->{n} + 0,
                      rule_id => ($t ? $t->{id} + 0 : undef), enabled => ($t && $t->{enabled} ? 1 : 0) } }
              @{ $rows || [] } ], undef);
}
sub pulse_rules_all {
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $rows, my $e) = _db_all($dbh,
        "SELECT r.*, (SELECT COUNT(*) FROM pulse_branches b WHERE b.rule_id = r.id) AS branches,
                     -- Condition count: the rule list shows at once where real logic is and where a stub, which is
                     -- the first question when picking a rule to copy from.
                     (SELECT COUNT(*) FROM pulse_conditions c JOIN pulse_branches b2 ON b2.id = c.branch_id
                       WHERE b2.rule_id = r.id) AS conditions,
                     (SELECT GROUP_CONCAT(v.content ORDER BY v.position SEPARATOR ' | ')
                        FROM pulse_rrset_values v WHERE v.rule_id = r.id AND v.branch_id IS NULL)
                       AS primary_label,
                     -- Not just switched but WHICH branch: with several branches that is the first question, and the
                     -- answer is already in the DB.
                     (SELECT b.position + 1 FROM pulse_branches b WHERE b.id = r.active_branch_id)
                       AS active_branch_no
           FROM pulse_rules r ORDER BY r.rr_name, r.rr_type", { Slice => {} });
    return (undef, $e) if $e;
    _pulse_attach_zone($rows);
    return ($rows || [], undef);
}
# The zone name lives in another DB, no JOIN possible: fetched in one query for the whole list.
# zone => undef means the zone was deleted bypassing the panel - the rule is shown orphaned, not hidden.
sub _pulse_attach_zone {
    my ($rows) = @_;
    return unless $rows && @$rows;
    my %ids = map { $_->{domain_id} => 1 } grep { $_->{domain_id} } @$rows;
    return unless %ids;
    my $pdns = connectPDNS() or return;
    my $in = join ',', ('?') x scalar(keys %ids);
    my $m = $pdns->selectall_hashref("SELECT id, name FROM domains WHERE id IN ($in)", 'id', undef, keys %ids);
    return if $pdns->err;
    $_->{zone} = ($m->{ $_->{domain_id} } || {})->{name} for @$rows;
}
# Full rule for the builder: branches in order, conditions inside, plus an orphaned mark on a condition
# whose tester no longer runs that check: silently treating it as false is not allowed.
sub pulse_rule_get {
    my ($id) = @_;
    return (undef, 'id required') unless $id && $id =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $r, my $e) = _db_row($dbh, "SELECT * FROM pulse_rules WHERE id=?", $id);
    return (undef, $e) if $e;
    return (undef, 'not found') unless $r;
    _pulse_attach_zone([ $r ]);
    (my $brs, my $be) = _db_all($dbh,
        "SELECT * FROM pulse_branches WHERE rule_id=? ORDER BY position", { Slice => {} }, $id);
    return (undef, $be) if $be;
    # Value sets: the primary (branch_id IS NULL) and per branch, in one query rather than one per branch.
    (my $vals, my $ve) = _db_all($dbh,
        "SELECT branch_id, content, prio, published FROM pulse_rrset_values WHERE rule_id=?
          ORDER BY branch_id, position", { Slice => {} }, $id);
    return (undef, $ve) if $ve;
    my %by_branch;
    $r->{values} = [];
    for my $v (@{ $vals || [] }) {
        my $one = { content => $v->{content}, prio => $v->{prio} };
        if (defined $v->{branch_id}) { push @{ $by_branch{ $v->{branch_id} } }, $one }
        else                         { push @{ $r->{values} }, $one }
    }
    $_->{values} = $by_branch{ $_->{id} } || [] for @{ $brs || [] };
    for my $b (@{ $brs || [] }) {
        (my $cs, my $ce) = _db_all($dbh,
            "SELECT c.*, ck.name AS check_name,
                    ck.kind AS check_kind, ck.target_ip AS check_target_ip, ck.port AS check_port
               FROM pulse_conditions c
               LEFT JOIN pulse_checks ck ON ck.id = c.check_id
              WHERE c.branch_id=? ORDER BY c.position, c.id", { Slice => {} }, $b->{id});
        return (undef, $ce) if $ce;
        for my $c (@{ $cs || [] }) {
            # Condition observers with their LIVE state and whether the agent runs this check at all. Without the live
            # state the screen showed "no data" where data existed - the browser declared the rule unresolvable while
            # the handler decided on real data and switched.
            $c->{testers} = [];
            if ($c->{kind} eq 'check') {
                (my $ts, my $te) = _db_all($dbh,
                    "SELECT ct.tester_id, t.name, r.state AS live_state,
                            r.unknown_reason AS live_reason,
                            (ct.tester_id IN " . _pulse_runners_sql() . ") AS assigned
                       FROM pulse_condition_testers ct
                       JOIN pulse_testers t ON t.id = ct.tester_id
                       LEFT JOIN pulse_results r ON r.check_id = ? AND r.tester_id = ct.tester_id
                      WHERE ct.condition_id = ? ORDER BY t.name",
                    { Slice => {} }, $c->{check_id}, $c->{check_id}, $c->{check_id}, $c->{id});
                return (undef, $te) if $te;
                $c->{testers} = $ts || [];
            }
            # A condition is orphaned when NO observer runs the check: while at least one does, it is resolvable,
            # just with fewer observers than intended.
            $c->{orphaned} = ($c->{kind} eq 'check'
                              && !grep { $_->{assigned} } @{ $c->{testers} }) ? 1 : 0;
            # Time goes out in the form it is ACCEPTED in: HH:MM. A TIME column returns "09:00:00", which could not be
            # sent back - saving one's own scheduled rule failed with "time must look like HH:MM" without any change.
            # The loop is closed where it is read: the API has one time format, not two.
            for my $k (qw(time_from time_to)) {
                $c->{$k} = substr($c->{$k}, 0, 5) if defined $c->{$k} && length $c->{$k} > 5;
            }
        }
        $b->{conditions} = $cs || [];
    }
    $r->{branches} = $brs || [];
    return ($r, undef);
}
# Create: the zone must be our primary (SLAVE is never writable), the type one Pulse may manage, and no
# other rule may manage this RRset. The current set is written as the PRIMARY - what the rule returns to.
sub pulse_rule_create {
    my ($f) = @_;
    $f ||= {};
    my $domain_id = $f->{domain_id};
    return (undef, 'domain_id required') unless $domain_id && $domain_id =~ /^\d+$/;
    my $type = uc($f->{rr_type} // '');
    return (undef, 'Pulse does not manage ' . ($type || 'that type') . ' records — '
                 . join(', ', @PULSE_RR_TYPES) . ' only') unless $PULSE_RR_OK{$type};
    (my $name, my $nerr) = dns_record_name_norm($f->{rr_name});
    return (undef, $nerr) if $nerr;
    if (my $we = pdns_zone_write_error($domain_id)) { return (undef, $we) }
    (my $cur, my $ce) = _pulse_rrset_now($domain_id, $name, $type);
    return (undef, $ce) if $ce;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $dup, my $de) = _db_exists($dbh,
        "SELECT 1 FROM pulse_rules WHERE domain_id=? AND rr_name=? AND rr_type=?", $domain_id, $name, $type);
    return (undef, $de) if $de;
    return (undef, "$name $type is already managed by another Pulse rule") if $dup;
    my $tz = $f->{schedule_tz};
    $tz = 'UTC' unless defined $tz && length $tz;
    return (undef, 'schedule_tz looks wrong') unless $tz =~ m{^[A-Za-z0-9_+\-/]{1,64}$};
    my $hold = _pulse_int($f->{default_hold_seconds}, 300, 1, 86400);

    (my $bo, my $be) = _txn_begin($dbh); return (undef, $be) if $be;
    my $id;
    my $done = eval {
        $dbh->do("INSERT INTO pulse_rules (domain_id, rr_name, rr_type, ttl, default_hold_seconds,
                                           schedule_tz, enabled, state)
                  VALUES (?,?,?,?,?,?,0,'default')",
                 undef, $domain_id, $name, $type, ($cur->{ttl} || 300), $hold, $tz);
        die "db\n" if $dbh->err;
        $id = $dbh->last_insert_id(undef,undef,undef,undef);
        my $pos = 0;
        for my $v (@{ $cur->{values} }) {
            # The primary set is what the zone holds now, and it is published: the rule has changed nothing yet.
            my $cv = pulse_canon_value($type, $v->{content}, $v->{prio});
            $dbh->do("INSERT INTO pulse_rrset_values (rule_id, branch_id, position, content, prio, published)
                      VALUES (?, NULL, ?, ?, ?, 1)", undef, $id, $pos++, $cv->{content}, $cv->{prio});
            die "db\n" if $dbh->err;
        }
        1;
    };
    unless ($done) { my $k = _db_err_kind($dbh->err) || 'DB error'; eval { $dbh->rollback }; return (undef, $k) }
    unless ($dbh->commit) { my $k = _db_err_kind($dbh->err); eval { $dbh->rollback }; return (undef, $k) }
    return ($id + 0, undef);
}
sub pulse_rule_update {
    my ($id, $f) = @_;
    return (undef, 'id required') unless $id && $id =~ /^\d+$/;
    $f ||= {};
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $r, my $e) = _db_row($dbh, "SELECT * FROM pulse_rules WHERE id=?", $id);
    return (undef, $e) if $e;
    return (undef, 'not found') unless $r;
    my $hold = exists $f->{default_hold_seconds}
        ? _pulse_int($f->{default_hold_seconds}, $r->{default_hold_seconds}, 1, 86400) : $r->{default_hold_seconds};
    my $tz = exists $f->{schedule_tz} ? ($f->{schedule_tz} // '') : $r->{schedule_tz};
    return (undef, 'schedule_tz looks wrong') unless $tz =~ m{^[A-Za-z0-9_+\-/]{1,64}$};
    my $en = exists $f->{enabled} ? ($f->{enabled} ? 1 : 0) : $r->{enabled};
    # Enabling a rule without a single branch is pointless: nothing to decide, yet it looks like it works.
    if ($en && !$r->{enabled}) {
        (my $n, my $ne) = _db_row($dbh, "SELECT COUNT(*) AS n FROM pulse_branches WHERE rule_id=?", $id);
        return (undef, $ne) if $ne;
        return (undef, 'add at least one rule branch before enabling') unless $n && $n->{n};
        # A condition is orphaned when NO observer runs its check; while at least one does it is resolvable.
        # A condition with no observers at all is orphaned too: nobody to wait for.
        (my $bad, my $be2) = _db_row($dbh,
            "SELECT COUNT(*) AS n FROM pulse_conditions c
               JOIN pulse_branches b ON b.id = c.branch_id
              WHERE b.rule_id = ? AND c.kind = 'check'
                AND NOT EXISTS(SELECT 1 FROM pulse_condition_testers ct
                                WHERE ct.condition_id = c.id
                                  AND (EXISTS(SELECT 1 FROM pulse_check_groups cg
                                                JOIN pulse_group_members m ON m.group_id = cg.group_id
                                               WHERE cg.check_id = c.check_id AND m.tester_id = ct.tester_id)
                                       OR EXISTS(SELECT 1 FROM pulse_check_agents ca
                                                  WHERE ca.check_id = c.check_id AND ca.tester_id = ct.tester_id)))", $id);
        return (undef, $be2) if $be2;
        return (undef, 'a condition has no agent that runs its check — fix it before enabling')
            if $bad && $bad->{n};
        (my $empty, my $ee) = _db_row($dbh,
            "SELECT COUNT(*) AS n FROM pulse_branches b
              WHERE b.rule_id = ?
                AND NOT EXISTS(SELECT 1 FROM pulse_conditions c WHERE c.branch_id = b.id)", $id);
        return (undef, $ee) if $ee;
        return (undef, 'a branch has no conditions left — deleting a check or a tester emptied it; '
                     . 'fix it before enabling')
            if $empty && $empty->{n};
    }
    # ENABLING RE-CAPTURES THE PRIMARY SET FROM THE ZONE. While Pulse is off the record belongs to the human and
    # is edited by hand (the write path does not protect it, rightly). So at enable time the zone no longer
    # holds what was captured at rule creation, and the first "return to primary" would silently wipe whatever
    # the human added. The primary set is not memory of the past but what to return to - at enable time, what
    # is in the zone now. State is reset: nothing switched yet, the first recomputation decides.
    # ONLY if the rule was on the primary set. From switched or held the zone holds a branch set (possibly
    # edited), and taking it as primary would lose forever what to return to - "return" would go to the
    # emergency address. For those two the state is derived by the reconciliation below, sets untouched.
    if ($en && !$r->{enabled} && $r->{state} eq 'default') {
        (my $cur, my $ce) = _pulse_rrset_now($r->{domain_id}, $r->{rr_name}, $r->{rr_type});
        return (undef, $ce) if $ce;
        return (undef, 'there is no such record in the zone any more') unless $cur && @{ $cur->{values} };
        (my $bo, my $be) = _txn_begin($dbh); return (undef, $be) if $be;
        my $done = eval {
            $dbh->do("DELETE FROM pulse_rrset_values WHERE rule_id=? AND branch_id IS NULL", undef, $id);
            die "db\n" if $dbh->err;
            my $pos = 0;
            for my $v (@{ $cur->{values} }) {
                my $cv = pulse_canon_value($r->{rr_type}, $v->{content}, $v->{prio});
                $dbh->do("INSERT INTO pulse_rrset_values (rule_id, branch_id, position, content, prio, published)
                          VALUES (?, NULL, ?, ?, ?, 1)", undef, $id, $pos++, $cv->{content}, $cv->{prio});
                die "db\n" if $dbh->err;
            }
            $dbh->do("UPDATE pulse_rrset_values SET published=0 WHERE rule_id=? AND branch_id IS NOT NULL",
                     undef, $id); die "db\n" if $dbh->err;
            $dbh->do("UPDATE pulse_rules SET default_hold_seconds=?, schedule_tz=?, enabled=1,
                             state='default', active_branch_id=NULL, ttl=? WHERE id=?",
                     undef, $hold, $tz, ($cur->{ttl} || $r->{ttl}), $id);
            die "db\n" if $dbh->err;
            1;
        };
        unless ($done) { my $k = _db_err_kind($dbh->err) || 'DB error'; eval { $dbh->rollback }; return (undef, $k) }
        unless ($dbh->commit) { my $k = _db_err_kind($dbh->err); eval { $dbh->rollback }; return (undef, $k) }
        pulse_notify($id);
        return (1, undef);
    }
    (my $ok, my $ue) = _do($dbh,
        "UPDATE pulse_rules SET default_hold_seconds=?, schedule_tz=?, enabled=? WHERE id=?",
        $hold, $tz, $en, $id);
    return (undef, $ue) if $ue;
    # Leaving held and returning from switched: sets are untouched, and which of them is in the zone now is
    # derived by the same reconciliation as after a logic edit. Without it the rule would stay held forever.
    if ($en && !$r->{enabled} && $r->{state} ne 'default') {
        (my $bo2, my $be2) = _txn_begin($dbh); return (undef, $be2) if $be2;
        my $done2 = eval {
            $dbh->selectrow_hashref("SELECT id FROM pulse_rules WHERE id=? FOR UPDATE", undef, $id);
            die "db\n" if $dbh->err;
            _pulse_resync_published($dbh, $id) or die "db\n";
            1;
        };
        unless ($done2) { my $k = _db_err_kind($dbh->err) || 'DB error'; eval { $dbh->rollback }; return (undef, $k) }
        unless ($dbh->commit) { my $k = _db_err_kind($dbh->err); eval { $dbh->rollback }; return (undef, $k) }
    }
    pulse_notify($id);
    return (1, undef);
}
# WHAT IS PUBLISHED NOW - by reconciling with the zone, not by memory. Memory lies exactly where it costs
# most: branches are recreated on every logic save, so the old active_branch_id points nowhere. Keeping
# state='switched' would make the handler treat the set as primary (no branch) and do nothing, while the
# zone still holds the old branch's emergency set.
# So after any set edit the state is DERIVED by comparing the zone with our sets:
#   matches the primary       -> default;
#   matches some branch       -> switched by that branch;
#   matches nothing           -> switched without a branch. Honest: the set is not primary, and whose it
#                                is Pulse no longer knows. The handler will not take that as a target
#                                and will apply the decision anew.
sub _pulse_resync_published {
    my ($dbh, $rule_id) = @_;
    return 0 unless $dbh;
    my $r = $dbh->selectrow_hashref("SELECT domain_id, rr_name, rr_type FROM pulse_rules WHERE id=?",
                                    undef, $rule_id);
    return 0 if $dbh->err;
    return 0 unless $r;
    (my $cur, my $ce) = _pulse_rrset_now($r->{domain_id}, $r->{rr_name}, $r->{rr_type});
    my $zone = $cur ? pulse_canon_set($r->{rr_type}, $cur->{values}) : undef;
    my $rows = $dbh->selectall_arrayref(
        "SELECT branch_id, content, prio FROM pulse_rrset_values WHERE rule_id=? ORDER BY position",
        { Slice => {} }, $rule_id) || [];
    my %by;
    push @{ $by{ defined $_->{branch_id} ? $_->{branch_id} : 0 } }, $_ for @$rows;
    my $match;
    if (defined $zone) {
        for my $k (sort { $a <=> $b } keys %by) {
            next unless pulse_canon_set($r->{rr_type}, $by{$k}) eq $zone;
            $match = $k;
            last;   # 0 = the primary set comes first: if both match, "primary" is more honest
        }
    }
    $dbh->do("UPDATE pulse_rrset_values SET published=0 WHERE rule_id=?", undef, $rule_id);
    return 0 if $dbh->err;
    if (defined $match) {
        $dbh->do("UPDATE pulse_rrset_values SET published=1 WHERE rule_id=? AND "
                 . ($match ? "branch_id=?" : "branch_id IS NULL"),
                 undef, $rule_id, ($match ? ($match) : ()));
    }
    my ($state, $branch) = !defined $match ? ('switched', undef)
                         : $match          ? ('switched', $match)
                         :                   ('default', undef);
    $dbh->do("UPDATE pulse_rules SET state=?, active_branch_id=? WHERE id=?",
             undef, $state, $branch, $rule_id);
    return $dbh->err ? 0 : 1;
}

# RECONCILIATION: did someone else edit the record? Called on every recomputation with nothing to switch -
# the state a rule spends most of its life in. An edit bypassing the panel cannot be detected instantly
# (it has no event by definition), but it must be noticed at the NEXT recomputation, otherwise the panel
# shows "default" while the zone holds something else.
# Runs under the same rule row lock as switching: otherwise we could read the zone, decide "overridden"
# while Pulse itself was writing, and the rule would go held because of its own work.
sub pulse_rule_verify {
    my ($rule_id) = @_;
    return (undef, 'rule id required') unless $rule_id && $rule_id =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $bo, my $be) = _txn_begin($dbh); return (undef, $be) if $be;
    my $fail = sub { my ($x) = @_; eval { $dbh->rollback }; return (undef, $x) };
    my $r = $dbh->selectrow_hashref("SELECT * FROM pulse_rules WHERE id=? FOR UPDATE", undef, $rule_id);
    return $fail->(_db_err_kind($dbh->err) || 'DB error') if $dbh->err;
    return $fail->('not found') unless $r;
    if (!$r->{enabled} || $r->{state} eq 'held') { $dbh->commit; return ({ held => 0 }, undef) }

    my $pub = $dbh->selectall_arrayref(
        "SELECT content, prio FROM pulse_rrset_values WHERE rule_id=? AND published=1 ORDER BY position",
        { Slice => {} }, $rule_id);
    return $fail->(_db_err_kind($dbh->err) || 'DB error') if $dbh->err;
    # An empty published is not someone else's edit but our own ignorance after a set change; it is cured by
    # applying the decision, not by stopping.
    unless ($pub && @$pub) { $dbh->commit; return ({ held => 0 }, undef) }

    (my $cur, my $cerr) = _pulse_rrset_now($r->{domain_id}, $r->{rr_name}, $r->{rr_type});
    return $fail->($cerr) if $cerr && $cerr !~ /^there is no /;
    my $published = pulse_canon_set($r->{rr_type}, $pub);
    my $in_zone   = $cur ? pulse_canon_set($r->{rr_type}, $cur->{values}) : '';
    if ($published eq $in_zone) { $dbh->commit; return ({ held => 0 }, undef) }

    $dbh->do("UPDATE pulse_rules SET state='held', last_reason=? WHERE id=?", undef,
             _clip('the record was changed outside NS Pulse', 255), $rule_id);
    return $fail->(_db_err_kind($dbh->err) || 'DB error') if $dbh->err;
    unless ($dbh->commit) { my $k = _db_err_kind($dbh->err); eval { $dbh->rollback }; return (undef, $k) }
    audit_log({ actor => 'pulse', source => 'system', action => 'pulse_held',
                target_type => 'pulse_rule', target => $rule_id,
                target_label => "$r->{rr_name} $r->{rr_type}",
                detail => { published => $published, in_zone => ($in_zone || 'no record') } });
    return ({ held => 1, published => $published, in_zone => $in_zone }, undef);
}

# SWITCHING A SET - the only place Pulse changes DNS.
# pulse-server makes the decision (it has live results, deadlines and the HA verdict). This function WRITES,
# via pdns_apply_rrsets - the same path as humans and MCP: transaction, zone role under lock, serial,
# audit. Pulse has no SQL of its own and never will, otherwise two ways of changing a zone would silently
# diverge (docs/25 §2).
# Order: DNS first, then the switch mark. The reverse would leave the panel recording a switch that never
# happened; this order at worst leaves "switched but not yet recorded": the next recomputation applies the
# same again (a no-op) and adds the mark.
sub pulse_rule_apply {
    my ($rule_id, $branch_id, $reason, $actor) = @_;
    return (undef, 'rule id required') unless $rule_id && $rule_id =~ /^\d+$/;
    return (undef, 'branch id must be a number') if defined $branch_id && $branch_id !~ /^\d+$/;
    $actor = 'pulse' unless defined $actor && length $actor;
    my $dbh = connectDB() or return (undef, 'DB unavailable');

    (my $bo, my $be) = _txn_begin($dbh); return (undef, $be) if $be;
    my $fail = sub { my ($x) = @_; eval { $dbh->rollback }; return (undef, $x) };
    my $r = $dbh->selectrow_hashref("SELECT * FROM pulse_rules WHERE id=? FOR UPDATE", undef, $rule_id);
    return $fail->(_db_err_kind($dbh->err) || 'DB error') if $dbh->err;
    return $fail->('not found') unless $r;
    # The switch-off is checked UNDER THE SAME lock we write with: the rule may have been disabled between the
    # server's decision and this line, and switching it then would act behind the human's back.
    return $fail->('rule is switched off') unless $r->{enabled};

    if (defined $branch_id) {
        (my $ok, my $e) = _db_exists($dbh, "SELECT 1 FROM pulse_branches WHERE id=? AND rule_id=?",
                                     $branch_id, $rule_id);
        return $fail->($e) if $e;
        return $fail->('that branch does not belong to this rule') unless $ok;
    }
    my $vals = $dbh->selectall_arrayref(
        "SELECT content, prio FROM pulse_rrset_values
          WHERE rule_id=? AND " . (defined $branch_id ? "branch_id=?" : "branch_id IS NULL") . "
          ORDER BY position", { Slice => {} }, $rule_id, (defined $branch_id ? ($branch_id) : ()));
    return $fail->(_db_err_kind($dbh->err) || 'DB error') if $dbh->err;
    return $fail->('there is nothing to publish here') unless $vals && @$vals;

    # Already where it should be - neither zone nor serial is touched: a switch to the same state is not a
    # switch, and a needless SOA bump would NOTIFY every secondary for nothing.
    my $want_state = defined $branch_id ? 'switched' : 'default';
    my $same = ($r->{state} eq $want_state)
            && ((defined $branch_id ? $branch_id : 0) == ($r->{active_branch_id} || 0));
    if ($same) { $dbh->commit; return ({ changed => 0, state => $want_state }, undef) }

    my $before = $dbh->selectall_arrayref(
        "SELECT content, prio FROM pulse_rrset_values WHERE rule_id=? AND published=1 ORDER BY position",
        { Slice => {} }, $rule_id);
    return $fail->(_db_err_kind($dbh->err) || 'DB error') if $dbh->err;

    # Does the zone ALREADY hold exactly what is to be published? Then it must not be touched: pdns_apply_rrsets
    # cannot be a no-op - it rewrites the set and bumps the serial, i.e. NOTIFY to every secondary. This happens
    # after a failure between the two databases (zone written, mark not) and after a manual edit that happens
    # to match our set. Only bookkeeping is fixed.
    (my $cur, my $cerr) = _pulse_rrset_now($r->{domain_id}, $r->{rr_name}, $r->{rr_type});
    my $zone_same = $cur && pulse_canon_set($r->{rr_type}, $cur->{values})
                         eq pulse_canon_set($r->{rr_type}, $vals);

    # THE RECORD WAS CHANGED BY SOMEONE OTHER THAN PULSE. The panel write path refuses that, but zones are also
    # edited by hand in SQL or with other tools. Fighting over the record is wrong: rewriting every cycle
    # looks like "the panel lies", silence like Pulse managing what it no longer manages. So the rule goes
    # held and waits for a human (docs/25 §6).
    # The SET is compared as a set, in the form PowerDNS stores it: comparing strings "as typed" would give
    # either endless "overridden" or a zone rewrite every cycle. Checked only when there IS something to
    # compare with: an empty published means "we do not know what is published" - our own ignorance, cured by
    # applying.
    if (@{ $before || [] } && $cur && !$zone_same) {
        my $published = pulse_canon_set($r->{rr_type}, $before);
        my $in_zone   = pulse_canon_set($r->{rr_type}, $cur->{values});
        if ($published ne $in_zone) {
            $dbh->do("UPDATE pulse_rules SET state='held', last_reason=? WHERE id=?", undef,
                     _clip('the record was changed outside NS Pulse', 255), $rule_id);
            my $k = $dbh->err ? (_db_err_kind($dbh->err) || 'DB error') : undef;
            return $fail->($k) if $k;
            $dbh->commit;
            audit_log({ actor => $actor, source => 'system', action => 'pulse_held',
                        target_type => 'pulse_rule', target => $rule_id,
                        target_label => "$r->{rr_name} $r->{rr_type}",
                        detail => { published => $published, in_zone => $in_zone } });
            return (undef, 'the record was changed outside NS Pulse — switch the rule off and on to take '
                         . 'it over again');
        }
    }

    my ($ok, $aerr) = $zone_same ? (1, undef) : pdns_apply_rrsets($r->{domain_id}, [ {
        name => $r->{rr_name}, type => $r->{rr_type}, changetype => 'REPLACE', ttl => $r->{ttl},
        records => [ map { { content => $_->{content}, prio => $_->{prio} } } @$vals ],
    } ], $actor, 'pulse');
    return $fail->($aerr || 'apply failed') unless $ok;

    my $done = eval {
        $dbh->do("UPDATE pulse_rules SET state=?, active_branch_id=?, last_switch_at=NOW(), last_reason=?
                   WHERE id=?", undef, $want_state, $branch_id, _clip($reason, 255), $rule_id);
        die "db\n" if $dbh->err;
        # "Published" is exactly one set. The flag lives here rather than being derived from state: a rule may have
        # many branches, and searching them by state is derivation where a fact exists.
        $dbh->do("UPDATE pulse_rrset_values SET published=0 WHERE rule_id=?", undef, $rule_id);
        die "db\n" if $dbh->err;
        $dbh->do("UPDATE pulse_rrset_values SET published=1 WHERE rule_id=? AND "
                 . (defined $branch_id ? "branch_id=?" : "branch_id IS NULL"),
                 undef, $rule_id, (defined $branch_id ? ($branch_id) : ()));
        die "db\n" if $dbh->err;
        $dbh->do("INSERT INTO pulse_rule_events (rule_id, from_set, to_set, branch_id, reason, actor)
                  VALUES (?,?,?,?,?,?)", undef, $rule_id,
                 _pulse_set_text($r->{rr_type}, $before), _pulse_set_text($r->{rr_type}, $vals),
                 $branch_id, _clip($reason, 255), $actor);
        die "db\n" if $dbh->err;
        # What the rule asked the world RIGHT NOW. Next week it may be reconfigured to another check, and computing
        # this link retroactively would be a lie: the mark would move to another timeline.
        my $eid = $dbh->last_insert_id(undef, undef, undef, undef);
        $dbh->do("INSERT IGNORE INTO pulse_rule_event_checks (event_id, check_id)
                  SELECT ?, c.check_id FROM pulse_conditions c
                    JOIN pulse_branches b ON b.id = c.branch_id
                   WHERE b.rule_id = ? AND c.check_id IS NOT NULL", undef, $eid, $rule_id);
        die "db\n" if $dbh->err;
        # Trim THIS rule's past right here: history grows where life happens and is trimmed there too. There is no
        # scheduled pass in this loop and there will not be. Retention lives in settings; no row - nothing is
        # deleted (hence JOIN rather than a subquery). The value is validated here: garbage would CAST to zero,
        # i.e. "keep zero days", and the trim would wipe all history at once. An unclear value means "delete
        # nothing".
        $dbh->do("DELETE e FROM pulse_rule_events e
                    JOIN settings s ON s.`key` = 'pulse_history_days'
                   WHERE e.rule_id = ?
                     AND s.`value` REGEXP '^[0-9]+\$'
                     AND CAST(s.`value` AS SIGNED) BETWEEN 1 AND 3650
                     AND e.at < TIMESTAMPADD(DAY, -CAST(s.`value` AS SIGNED), UTC_TIMESTAMP())",
                 undef, $rule_id);
        die "db\n" if $dbh->err;
        1;
    };
    return $fail->(_db_err_kind($dbh->err) || 'DB error') unless $done;
    unless ($dbh->commit) { my $k = _db_err_kind($dbh->err); eval { $dbh->rollback }; return (undef, $k) }

    # Switching a record is an event of the shared audit log, not only of rule history: whoever asks tomorrow
    # "who changed aaa" must see Pulse here too.
    # Zone untouched - no event and no audit either: nothing was switched. Bookkeeping is now correct, and the
    # next decision compares against the truth.
    return ({ changed => 0, state => $want_state, set => _pulse_set_text($r->{rr_type}, $vals) }, undef)
        if $zone_same;

    audit_log({ actor => $actor, source => 'system', action => 'pulse_switch',
                target_type => 'pulse_rule', target => $rule_id,
                target_label => "$r->{rr_name} $r->{rr_type}",
                detail => { from => _pulse_set_text($r->{rr_type}, $before),
                            to   => _pulse_set_text($r->{rr_type}, $vals),
                            reason => $reason } });
    return ({ changed => 1, state => $want_state,
              set => _pulse_set_text($r->{rr_type}, $vals) }, undef);
}
sub _pulse_set_text {
    my ($type, $vals) = @_;
    return '' unless $vals && @$vals;
    return join ' | ', map { (defined $_->{prio} && $_->{prio} ne '' ? "$_->{prio} " : '') . $_->{content} }
                       @$vals;
}
sub _clip { my ($s, $n) = @_; return undef unless defined $s && length $s; return substr($s, 0, $n) }

sub pulse_rule_delete {
    my ($id) = @_;
    return (undef, 'id required') unless $id && $id =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $ok, my $e) = _do($dbh, "DELETE FROM pulse_rules WHERE id=?", $id);
    return (undef, $e) if $e;
    return (1, undef);
}

# Copying settings to other records. Done HERE, not by a dozen browser requests: the rule of "what exactly
# is copied" is one and must live in one place.
#   * logic (branches, conditions, mode, holds) is always copied;
#   * publish values only for a MATCHING type: MX and A values have different shapes;
#   * for another type each branch publishes the target's CURRENT set. A rule cannot be saved with an empty
#     branch, and borrowing foreign values could one day send mail to a web server. "Publish what is
#     already published" breaks nothing: the copy arrives disabled and enabling it changes nothing until
#     values are edited;
#   * the primary set is never copied - it belongs to the record and is captured from the zone at creation.
sub _pulse_clone_values {
    my ($dbh, $rid) = @_;
    my $rows = $dbh->selectall_arrayref(
        "SELECT content, prio FROM pulse_rrset_values WHERE rule_id=? AND branch_id IS NULL ORDER BY position",
        { Slice => {} }, $rid);
    return $rows || [];
}
sub _pulse_clone_one {
    my ($src, $t) = @_;
    my $dbh = connectDB() or return 'DB unavailable';
    my $type = uc($t->{rr_type} // '');
    (my $name, my $nerr) = dns_record_name_norm($t->{rr_name});
    return $nerr if $nerr;
    my ($rid) = $dbh->selectrow_array(
        "SELECT id FROM pulse_rules WHERE domain_id=? AND rr_name=? AND rr_type=?",
        undef, $t->{domain_id}, $name, $type);
    return 'already set up — tick «replace» to overwrite' if $rid && !$t->{overwrite};
    unless ($rid) {
        (my $new, my $ce) = pulse_rule_create({ domain_id => $t->{domain_id}, rr_name => $name,
                                                rr_type => $type, schedule_tz => $src->{schedule_tz},
                                                default_hold_seconds => $src->{default_hold_seconds} });
        return $ce if $ce;
        $rid = $new;
    }
    my $same = ($type eq uc($src->{rr_type})) ? 1 : 0;
    my $own  = $same ? undef : _pulse_clone_values($dbh, $rid);
    return 'this record publishes nothing to keep' if !$same && !@$own;
    my @branches = map {
        my $b = $_;
        { match_mode  => $b->{match_mode},
          hold_seconds => $b->{hold_seconds},
          values      => $same ? [ map { { content => $_->{content}, prio => $_->{prio} } } @{ $b->{values} } ]
                               : [ map { { content => $_->{content}, prio => $_->{prio} } } @$own ],
          conditions  => [ map {
              $_->{kind} eq 'schedule'
                ? { kind => 'schedule', days_mask => $_->{days_mask}, time_from => $_->{time_from},
                    time_to => $_->{time_to}, date_from => $_->{date_from}, date_to => $_->{date_to} }
                : { kind => 'check', check_id => $_->{check_id}, expect => $_->{expect},
                    agg => $_->{agg}, agg_n => $_->{agg_n} }
          } @{ $b->{conditions} } ] };
    } @{ $src->{branches} || [] };
    return 'nothing to copy — this setup has no rules' unless @branches;
    (my $ok, my $be) = pulse_rule_branches_set($rid, \@branches, $src->{default_hold_seconds});
    return $be if $be;
    return undef;
}
sub pulse_rule_clone_to {
    my ($src_id, $targets) = @_;
    return (undef, 'rule id required') unless $src_id && $src_id =~ /^\d+$/;
    return (undef, 'targets must be a list') unless ref $targets eq 'ARRAY';
    return (undef, 'pick at least one record') unless @$targets;
    # The limit is not caution for its own sake: a hundred targets are a hundred DNS records in one click, and
    # the human must confirm that deliberately, in portions.
    return (undef, 'too many records at once — up to 100') if @$targets > 100;
    (my $src, my $se) = pulse_rule_get($src_id);
    return (undef, $se) if $se;
    return (undef, 'not found') unless $src;
    my (@done, @failed);
    for my $t (@{ $targets }) {
        next unless ref $t eq 'HASH';
        my $label = ($t->{rr_name} // '?') . ' ' . uc($t->{rr_type} // '?');
        # One failed target does not cancel the others, nor is it hidden: both sides are returned.
        my $err = eval { _pulse_clone_one($src, $t) };
        $err = ($@ =~ /^db$/m ? 'DB error' : $@) if $@;
        if ($err) { push @failed, { target => $label, error => $err } }
        else      { push @done,   $label }
    }
    return ({ done => \@done, failed => \@failed }, undef);
}
# Branches and conditions are saved WHOLE and atomically: the builder sends what is on screen, not single
# edits. Array order is branch order - i.e. behaviour.
sub pulse_rule_branches_set {
    my ($rule_id, $branches, $default_hold) = @_;
    return (undef, 'rule id required') unless $rule_id && $rule_id =~ /^\d+$/;
    return (undef, 'branches must be a list') unless ref $branches eq 'ARRAY';
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $r, my $e) = _db_row($dbh, "SELECT * FROM pulse_rules WHERE id=?", $rule_id);
    return (undef, $e) if $e;
    return (undef, 'not found') unless $r;

    # Validate EVERYTHING first, then write: half a saved rule is worse than a refusal.
    my @clean;
    my $pos = 0;
    for my $b (@$branches) {
        my $mode = lc($b->{match_mode} // $b->{match} // 'any');
        return (undef, 'match must be any or all') unless $mode eq 'any' || $mode eq 'all';
        # A branch publishes a SET, not one value (MX usually has several, A sometimes). Content is validated by
        # the same part of the panel as regular records - no second validation here.
        my @vals;
        for my $v (@{ ref $b->{values} eq 'ARRAY' ? $b->{values} : [] }) {
            my ($content, $prio) = ref $v eq 'HASH' ? ($v->{content}, $v->{prio}) : ($v, undef);
            next unless defined $content && length $content;
            # Canonicalize ON SAVE, not only on compare: otherwise the DB holds what the human typed while something
            # else is compared.
            push @vals, pulse_canon_value($r->{rr_type}, $content, $prio);
        }
        return (undef, "branch " . ($pos + 1) . ": add at least one value to publish") unless @vals;
        # CNAME is always single by the standard: a set of two would make the zone invalid.
        return (undef, "branch " . ($pos + 1) . ": a CNAME set holds exactly one value")
            if $r->{rr_type} eq 'CNAME' && @vals > 1;
        for my $v (@vals) {
            my $why = dns_validate($r->{rr_type}, $r->{rr_name}, undef, $v->{content}, $v->{prio});
            return (undef, "branch " . ($pos + 1) . ": $why") if $why;
        }
        my $hold = _pulse_int($b->{hold_seconds}, 30, 1, 86400);
        my @conds;
        my $cpos = 0;
        for my $c (@{ $b->{conditions} || [] }) {
            my $kind = lc($c->{kind} // 'check');
            if ($kind eq 'check') {
                my $cid = $c->{check_id};
                return (undef, "branch " . ($pos + 1) . ": condition needs a check")
                    unless $cid && $cid =~ /^\d+$/;
                # Condition observers are ALL the check's executors, taken from the check itself (pulse_check_testers).
                # There is no separate "which of them we listen to": two sets instead of one confused people, and their
                # difference never paid for a single "so how many?" question. (A single tester_id from cloning or other
                # clients is still accepted.)
                (my $runners, my $rerr) = pulse_check_testers($cid);
                return (undef, $rerr) if $rerr;
                my @tids = map { $_->{id} + 0 } @{ $runners || [] };
                return (undef, "branch " . ($pos + 1) . ": no agent runs this check yet — assign it to a "
                             . "group or an agent first")
                    unless @tids;
                my $expect = lc($c->{expect} // 'unavailable');
                return (undef, "expect must be available, degraded or unavailable")
                    unless $expect =~ /^(available|degraded|unavailable)$/;
                # What an answer from SEVERAL observers means. With one observer the question did not arise and "any" was
                # implied; it remains the default.
                my $agg = lc($c->{agg} // 'any');
                return (undef, "agg must be any, all or at_least")
                    unless $agg =~ /^(any|all|at_least)$/;
                # N is not silently clamped to the agent count: "at least three" with two observers is a design mistake,
                # and a quietly converted "at least two" would mean something else.
                my $aggn = _pulse_int($c->{agg_n}, 1, 1, 255);
                return (undef, "branch " . ($pos + 1) . ": «at least N» needs N no greater than the "
                             . "number of agents")
                    if $agg eq 'at_least' && $aggn > @tids;
                push @conds, { kind => 'check', check_id => $cid + 0, testers => \@tids,
                               expect => $expect, agg => $agg, agg_n => $aggn, position => $cpos++ };
            } elsif ($kind eq 'schedule') {
                my $days = (defined $c->{days_mask} && $c->{days_mask} =~ /^\d+$/) ? ($c->{days_mask} & 127) : undef;
                my ($tf, $tt) = ($c->{time_from}, $c->{time_to});
                for my $t ($tf, $tt) {
                    next unless defined $t && length $t;
                    return (undef, "time must look like HH:MM") unless $t =~ /^([01]\d|2[0-3]):[0-5]\d$/;
                }
                # A time window is a PAIR. "From 09:00 until nothing" looks meaningful but means nothing: one bound applies
                # to nothing, and the condition would quietly stop working.
                return (undef, "a time window needs both from and to")
                    if (length($tf // '') xor length($tt // ''));
                my ($df, $dt) = ($c->{date_from}, $c->{date_to});
                for my $t ($df, $dt) {
                    next unless defined $t && length $t;
                    return (undef, "date must look like YYYY-MM-DD") unless $t =~ /^\d{4}-\d{2}-\d{2}$/;
                }
                return (undef, "dates run the wrong way: $df is after $dt")
                    if length($df // '') && length($dt // '') && $df gt $dt;
                # For dates one bound is meaningful: "from" and "until" are different but complete conditions.
                return (undef, "a schedule condition needs at least one of: days, time range, dates")
                    unless defined $days || length($tf // '') || length($df // '') || length($dt // '');
                push @conds, { kind => 'schedule', days_mask => $days,
                               time_from => (length($tf // '') ? "$tf:00" : undef),
                               time_to   => (length($tt // '') ? "$tt:00" : undef),
                               date_from => (length($df // '') ? $df : undef),
                               date_to   => (length($dt // '') ? $dt : undef), position => $cpos++ };
            } else {
                return (undef, "unknown condition kind '$kind'");
            }
        }
        # A branch without conditions is not saved. With match_mode='all', "all conditions true" is trivially true
        # on an empty set - such a branch would switch unconditionally and shadow everything below. It can still
        # become empty (deleting a check or tester cascades conditions away), so the handler has a second rule:
        # an empty branch = unknown, see docs/25 §6.
        return (undef, "branch " . ($pos + 1) . ": add at least one condition — a branch with none would "
                     . "either match everything or nothing, and neither is what anybody meant")
            unless @conds;
        push @clean, { position => $pos++, match_mode => $mode, values => \@vals, hold_seconds => $hold,
                       conditions => \@conds };
    }

    (my $bo, my $be) = _txn_begin($dbh); return (undef, $be) if $be;
    my $fail = sub { my ($x) = @_; eval { $dbh->rollback }; return (undef, $x) };
    my $done = eval {
        # Lock the rule row AT ONCE: the switcher (pulse_rule_apply) works under it, and without it could slip in
        # between replacing branches and deriving state - exactly the gap where the rule no longer knows what is
        # published.
        $dbh->selectrow_hashref("SELECT id FROM pulse_rules WHERE id=? FOR UPDATE", undef, $rule_id);
        die "db\n" if $dbh->err;
        # The held branch may be gone - clear the reference, otherwise it points nowhere.
        $dbh->do("UPDATE pulse_rules SET active_branch_id=NULL WHERE id=?", undef, $rule_id); die "db\n" if $dbh->err;
        # The fallback hold is a field of THE SAME form and goes with the same button. A separate request on
        # field blur would save it even for a rule that does not exist yet, and out of step with the branches.
        if (defined $default_hold) {
            $dbh->do("UPDATE pulse_rules SET default_hold_seconds=? WHERE id=?", undef,
                     _pulse_int($default_hold, $r->{default_hold_seconds}, 1, 86400), $rule_id);
            die "db\n" if $dbh->err;
        }
        # Branch values go with the branches; the PRIMARY set (branch_id IS NULL) is untouched - it belongs to the
        # rule, not a branch.
        $dbh->do("DELETE FROM pulse_rrset_values WHERE rule_id=? AND branch_id IS NOT NULL",
                 undef, $rule_id); die "db\n" if $dbh->err;
        $dbh->do("DELETE FROM pulse_branches WHERE rule_id=?", undef, $rule_id); die "db\n" if $dbh->err;
        for my $b (@clean) {
            $dbh->do("INSERT INTO pulse_branches (rule_id, position, match_mode, hold_seconds)
                      VALUES (?,?,?,?)", undef, $rule_id, $b->{position}, $b->{match_mode},
                     $b->{hold_seconds}); die "db\n" if $dbh->err;
            my $bid = $dbh->last_insert_id(undef,undef,undef,undef);
            my $vpos = 0;
            for my $v (@{ $b->{values} }) {
                $dbh->do("INSERT INTO pulse_rrset_values (rule_id, branch_id, position, content, prio)
                          VALUES (?,?,?,?,?)", undef, $rule_id, $bid, $vpos++, $v->{content}, $v->{prio});
                die "db\n" if $dbh->err;
            }
            for my $c (@{ $b->{conditions} }) {
                $dbh->do("INSERT INTO pulse_conditions (branch_id, position, kind, check_id, expect, agg,
                                                        agg_n, days_mask, time_from, time_to,
                                                        date_from, date_to)
                          VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", undef,
                         $bid, $c->{position}, $c->{kind}, $c->{check_id}, $c->{expect},
                         ($c->{agg} // 'any'), ($c->{agg_n} // 1),
                         $c->{days_mask}, $c->{time_from}, $c->{time_to}, $c->{date_from}, $c->{date_to});
                die "db\n" if $dbh->err;
                my $cond_id = $dbh->last_insert_id(undef,undef,undef,undef);
                for my $tid (@{ $c->{testers} || [] }) {
                    $dbh->do("INSERT INTO pulse_condition_testers (condition_id, tester_id) VALUES (?,?)",
                             undef, $cond_id, $tid);
                    die "db\n" if $dbh->err;
                }
            }
        }
        # Sets changed, so the old "what is published" means nothing. It is derived again here, under the same
        # lock and in the same transaction: a separate pass after commit would be "saved, and state as it goes".
        _pulse_resync_published($dbh, $rule_id) or die "db\n";
        1;
    };
    return $fail->(_db_err_kind($dbh->err) || 'DB error') unless $done;
    unless ($dbh->commit) { my $k = _db_err_kind($dbh->err); eval { $dbh->rollback }; return (undef, $k) }
    pulse_notify($rule_id);
    return (1, undef);
}

# ============================================================================
# EXTERNAL ACCESS: API tokens, OIDC bearer tokens, anonymous read (docs/11-api.md, docs/10-mcp.md)
# ============================================================================
# Every way in ends as an ordinary panel user: a token acts as its owner, an OIDC token as the user its
# username claim names, anonymous as a read-only pseudo-user. Permissions, the HA gate and the audit are the
# same as in the UI. Tokens are stored as they are: the owner copies one again whenever it is needed.

# How the current request authenticated, for the audit ('token laptop', 'oidc Entra', 'anonymous'); undef for
# a panel session and for local tools. Reset per request in request_begin().
our $_request_via;
sub set_request_via { $_request_via = $_[0]; return; }

sub external_settings {
    return {
        mcp_http       => setting('external.mcp_http') ? 1 : 0,
        anonymous_read => setting('external.anonymous_read') ? 1 : 0,
        mcp_readonly   => setting('mcp.readonly') ? 1 : 0,
    };
}
# Partial update; only the keys sent change. -> (settings, undef) | (undef, err)
sub external_settings_set {
    my ($f) = @_; $f ||= {};
    my %w;
    for my $k (qw(mcp_http anonymous_read mcp_readonly)) {
        next unless exists $f->{$k};
        (my $b, my $e) = strict_bool($f->{$k}); return (undef, "$k: $e") if $e;
        $w{ $k eq 'mcp_readonly' ? 'mcp.readonly' : "external.$k" } = $b;
    }
    return (undef, 'nothing to save') unless %w;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    for my $k (sort keys %w) {
        (my $ok, my $e) = _do($dbh, "INSERT INTO settings (`key`,`value`) VALUES (?,?) ON DUPLICATE KEY UPDATE `value`=VALUES(`value`)", $k, $w{$k});
        return (undef, $e) if $e;
    }
    $settings_cache = undef;
    return (external_settings(), undef);
}

# ---- OIDC providers: any number; a token is checked by the provider whose issuer it names ----
sub _oidc_iss_norm { my ($s) = @_; $s //= ''; $s =~ s/^\s+|\s+$//g; $s =~ s{/+$}{}; return $s; }
sub oidc_provider_list {
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    my ($rows, $e) = _db_all($dbh, "SELECT id, name, issuer, audience, username_claim, enabled FROM oidc_providers ORDER BY name", { Slice => {} });
    return (undef, $e) if $e;
    for (@$rows) { $_->{id} += 0; $_->{enabled} += 0; }
    return ($rows, undef);
}
sub _oidc_provider_fields {
    my ($f, $create) = @_;
    my %v;
    for ([name => 64], [issuer => 255], [audience => 255], [username_claim => 64]) {
        my ($k, $max) = @$_;
        next unless $create || exists $f->{$k};
        (my $x, my $e) = _check_len($f->{$k}, $k, $max, $k ne 'username_claim'); return (undef, $e) if $e;
        $v{$k} = $x;
    }
    $v{issuer} = _oidc_iss_norm($v{issuer}) if exists $v{issuer};
    return (undef, 'issuer must be an https:// URL') if exists $v{issuer} && $v{issuer} !~ m{^https://[^\s/]+}i;
    $v{username_claim} = 'preferred_username' if exists $v{username_claim} && !length($v{username_claim} // '');
    return (undef, 'username claim: letters, digits and _ only') if exists $v{username_claim} && $v{username_claim} !~ /^\w+$/;
    if (exists $f->{enabled}) { (my $b, my $e) = strict_bool($f->{enabled}); return (undef, "enabled: $e") if $e; $v{enabled} = $b; }
    return (\%v, undef);
}
sub oidc_provider_create {
    my ($f) = @_;
    (my $v, my $e) = _oidc_provider_fields($f || {}, 1); return (undef, $e) if $e;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    my @k = sort keys %$v;
    (my $ok, $e) = _do($dbh, "INSERT INTO oidc_providers (" . join(',', @k) . ") VALUES (" . join(',', map { '?' } @k) . ")", @{$v}{@k});
    return (undef, $e eq 'conflict' ? 'a provider with this name or issuer already exists' : $e) if $e;
    return ($dbh->last_insert_id(undef, undef, undef, undef) + 0, undef);
}
sub oidc_provider_update {
    my ($id, $f) = @_;
    return (undef, 'id required') unless $id && $id =~ /^\d+$/;
    (my $v, my $e) = _oidc_provider_fields($f || {}, 0); return (undef, $e) if $e;
    return (1, undef) unless %$v;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    my @k = sort keys %$v;
    (my $ok, $e) = _do($dbh, "UPDATE oidc_providers SET " . join(',', map { "$_=?" } @k) . " WHERE id=?", @{$v}{@k}, $id);
    return (undef, $e eq 'conflict' ? 'a provider with this name or issuer already exists' : $e) if $e;
    return (1, undef);
}
sub oidc_provider_delete {
    my ($id) = @_;
    return (undef, 'id required') unless $id && $id =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $ok, my $e) = _do($dbh, "DELETE FROM oidc_providers WHERE id=?", $id); return (undef, $e) if $e;
    return (1, undef);
}
sub oidc_provider_get {
    my ($id) = @_;
    my $dbh = connectDB() or return undef;
    return $dbh->selectrow_hashref("SELECT id, name, issuer FROM oidc_providers WHERE id=?", undef, $id);
}
sub oidc_issuers_enabled {
    my $dbh = connectDB() or return [];
    return $dbh->selectcol_arrayref("SELECT issuer FROM oidc_providers WHERE enabled=1 ORDER BY name") || [];
}

# ---- API tokens ----
sub api_token_list {
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    my ($rows, $e) = _db_all($dbh,
        "SELECT t.id, t.name, t.token, t.enabled, t.expires_at, t.created_at, t.last_used_at, t.last_used_ip,
                t.user_id, u.username
           FROM api_tokens t JOIN users u ON u.id = t.user_id ORDER BY u.username, t.name", { Slice => {} });
    return (undef, $e) if $e;
    for (@$rows) { $_->{id} += 0; $_->{user_id} += 0; $_->{enabled} += 0; }
    return ($rows, undef);
}
sub _api_token_fields {
    my ($f, $create) = @_;
    my %v;
    if ($create || exists $f->{name}) {
        (my $n, my $e) = _check_len($f->{name}, 'name', 64, 1); return (undef, $e) if $e; $v{name} = $n;
    }
    if (exists $f->{expires_at}) {
        my $x = _trim($f->{expires_at});
        $x = undef if defined $x && $x eq '';
        return (undef, 'expires_at must be YYYY-MM-DD') if defined $x && $x !~ /^\d{4}-\d{2}-\d{2}$/;
        $v{expires_at} = $x;
    }
    if (exists $f->{enabled}) { (my $b, my $e) = strict_bool($f->{enabled}); return (undef, "enabled: $e") if $e; $v{enabled} = $b; }
    return (\%v, undef);
}
# -> ({id, token, ...}, undef) | (undef, err)
sub api_token_create {
    my ($f) = @_; $f ||= {};
    my $uid = $f->{user_id};
    return (undef, 'user_id required') unless defined $uid && $uid =~ /^\d+$/;
    (my $v, my $e) = _api_token_fields($f, 1); return (undef, $e) if $e;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $u, $e) = _db_row($dbh, "SELECT id, username FROM users WHERE id=?", $uid); return (undef, $e) if $e;
    return (undef, 'unknown user') unless $u;
    require Crypt::URandom;
    my $token = 'dnsp_' . unpack('H*', Crypt::URandom::urandom(20));
    (my $ok, $e) = _do($dbh, "INSERT INTO api_tokens (user_id, name, token, enabled, expires_at) VALUES (?,?,?,?,?)",
        $uid, $v->{name}, $token, ($v->{enabled} // 1), $v->{expires_at});
    return (undef, $e eq 'conflict' ? "user '$u->{username}' already has a token named '$v->{name}'" : $e) if $e;
    return ({ id => $dbh->last_insert_id(undef, undef, undef, undef) + 0, token => $token,
              username => $u->{username}, name => $v->{name} }, undef);
}
sub api_token_update {
    my ($id, $f) = @_; $f ||= {};
    return (undef, 'id required') unless $id && $id =~ /^\d+$/;
    (my $v, my $e) = _api_token_fields($f, 0); return (undef, $e) if $e;
    return (1, undef) unless %$v;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    my @k = sort keys %$v;
    (my $ok, $e) = _do($dbh, "UPDATE api_tokens SET " . join(',', map { "$_=?" } @k) . " WHERE id=?", @{$v}{@k}, $id);
    return (undef, $e) if $e;
    return (1, undef);
}
sub api_token_delete {
    my ($id) = @_;
    return (undef, 'id required') unless $id && $id =~ /^\d+$/;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    (my $ok, my $e) = _do($dbh, "DELETE FROM api_tokens WHERE id=?", $id); return (undef, $e) if $e;
    return (1, undef);
}
sub api_token_get {
    my ($id) = @_;
    my $dbh = connectDB() or return undef;
    return $dbh->selectrow_hashref("SELECT t.id, t.name, u.username FROM api_tokens t JOIN users u ON u.id=t.user_id WHERE t.id=?", undef, $id);
}

# ---- Bearer: API token or OIDC token -> (user, via) | (undef, error) ----
sub authenticate_bearer {
    my ($raw) = @_;
    return (undef, 'empty token') unless defined $raw && length $raw;
    if ($raw =~ /^dnsp_[0-9a-f]{40}$/) {
        my $dbh = connectDB() or return (undef, 'DB unavailable');
        my $t = $dbh->selectrow_hashref(
            "SELECT t.id, t.name, t.user_id FROM api_tokens t JOIN users u ON u.id = t.user_id
              WHERE t.token = ? AND t.enabled = 1 AND u.is_active = 1
                AND (t.expires_at IS NULL OR t.expires_at >= UTC_DATE())", undef, $raw);
        return (undef, 'invalid token') unless $t;
        # At most one write a minute per token; fails quietly on a read-only STANDBY.
        { local $dbh->{PrintError} = 0; local $dbh->{RaiseError} = 0;
          $dbh->do("UPDATE api_tokens SET last_used_at = UTC_TIMESTAMP(), last_used_ip = ?
                     WHERE id = ? AND (last_used_at IS NULL OR last_used_at < UTC_TIMESTAMP() - INTERVAL 1 MINUTE)",
                   undef, get_client_ip(), $t->{id}); }
        my $u = get_user_by_id($t->{user_id}) or return (undef, 'invalid token');
        return ($u, "token $t->{name}");
    }
    if ($raw =~ /^[\w-]+\.[\w-]+\.[\w-]+$/) {
        (my $claims, my $p, my $e) = oidc_verify($raw); return (undef, $e) if $e;
        my $cl = $p->{username_claim} || 'preferred_username';
        my $who = $claims->{$cl};
        return (undef, "token has no '$cl' claim") unless defined $who && !ref $who && length $who;
        (my $u, $e) = oidc_user_for($who); return (undef, $e) if $e;
        return ($u, "oidc $p->{name}");
    }
    return (undef, 'invalid token');
}

# The panel user an identity-provider name refers to, with no mapping to maintain: exactly equal to a
# username, an e-mail or any certificate CN of one user. All matches are collected; they must all be the
# same user, otherwise nobody is chosen (never the first match, never the one with more rights).
# -> (user, undef) | (undef, error)
sub oidc_user_for {
    my ($who) = @_;
    my $dbh = connectDB() or return (undef, 'DB unavailable');
    my $ids = $dbh->selectcol_arrayref(
        "SELECT id FROM users WHERE LOWER(username) = LOWER(?) OR LOWER(email) = LOWER(?)
         UNION
         SELECT user_id FROM auth_identities WHERE type = 'cert' AND provider = '' AND is_active = 1 AND LOWER(principal) = LOWER(?)",
        undef, $who, $who, $who);
    return (undef, 'DB error') unless $ids;
    return (undef, "no panel user matches '$who'") unless @$ids;
    return (undef, "'$who' matches several panel users") if @$ids > 1;
    my ($active) = $dbh->selectrow_array("SELECT is_active FROM users WHERE id=?", undef, $ids->[0]);
    return (undef, "no panel user matches '$who'") unless $active;
    return (get_user_by_id($ids->[0]), undef);
}
# Save-time guard for the same rule: a certificate CN or an e-mail must not name another user.
# -> undef | error
sub identity_name_conflict {
    my ($name, $uid) = @_;
    return undef unless defined $name && length $name;
    my $dbh = connectDB() or return 'DB unavailable';
    my ($other) = $dbh->selectrow_array(
        "SELECT u.username FROM users u WHERE u.id <> ? AND (LOWER(u.username) = LOWER(?) OR LOWER(u.email) = LOWER(?))
         UNION
         SELECT u.username FROM auth_identities ai JOIN users u ON u.id = ai.user_id
          WHERE ai.user_id <> ? AND ai.type = 'cert' AND ai.provider = '' AND LOWER(ai.principal) = LOWER(?) LIMIT 1",
        undef, $uid, $name, $name, $uid, $name);
    return defined $other ? "'$name' already identifies user '$other'" : undef;
}

# OIDC access token check: signature by a key from the issuer's JWKS, iss, aud, exp/nbf. The key set is kept
# in the process and fetched again only for an unknown key id (key rotation), at most once a minute.
our %_oidc_jwks;   # issuer -> { keys => {kid => jwk}, fetched => epoch }
sub _b64url_dec { my ($s) = @_; $s =~ tr{-_}{+/}; $s .= '=' x ((4 - length($s) % 4) % 4); return decode_base64($s); }
sub _oidc_keys {
    my ($iss, $force) = @_;
    my $c = $_oidc_jwks{$iss};
    return ($c->{keys}, undef) if $c && !$force;
    return ($c->{keys}, undef) if $c && time - $c->{fetched} < 60;
    require HTTP::Tiny;
    my $http = HTTP::Tiny->new(timeout => 5, verify_SSL => 1);
    my $r = $http->get("$iss/.well-known/openid-configuration");
    return (undef, "issuer discovery failed: $r->{status}") unless $r->{success};
    my $meta = eval { decode_json($r->{content}) } || {};
    return (undef, 'issuer has no jwks_uri') unless $meta->{jwks_uri};
    $r = $http->get($meta->{jwks_uri});
    return (undef, "JWKS fetch failed: $r->{status}") unless $r->{success};
    my $set = eval { decode_json($r->{content}) } || {};
    my %k = map { (($_->{kid} // '') => $_) } grep { ref $_ eq 'HASH' } @{ $set->{keys} || [] };
    $_oidc_jwks{$iss} = { keys => \%k, fetched => time };
    return (\%k, undef);
}
# -> (claims, provider, undef) | (undef, undef, error). The issuer named in the token only picks the provider;
# nothing in the token is trusted before its signature is checked with that provider's keys.
sub oidc_verify {
    my ($jwt) = @_;
    my ($h64, $p64, $s64) = split /\./, $jwt;
    my $hdr = eval { decode_json(_b64url_dec($h64)) };
    my $cl  = eval { decode_json(_b64url_dec($p64)) };
    return (undef, undef, 'malformed token') unless ref $hdr eq 'HASH' && ref $cl eq 'HASH';
    my $dbh = connectDB() or return (undef, undef, 'DB unavailable');
    my $iss = _oidc_iss_norm($cl->{iss});
    my $p = $dbh->selectrow_hashref("SELECT id, name, issuer, audience, username_claim FROM oidc_providers WHERE enabled=1 AND issuer=?", undef, $iss)
        or return (undef, undef, 'token issuer is not a configured OIDC provider');
    my @aud = grep { length } map { s/^\s+|\s+$//gr } split /,/, ($p->{audience} // '');
    (my $ok, my $e) = _oidc_check($h64, $p64, $s64, $hdr, $cl, $iss, \@aud);
    return $e ? (undef, undef, $e) : ($cl, $p, undef);
}
sub _oidc_check {
    my ($h64, $p64, $s64, $hdr, $cl, $iss, $audr) = @_;
    my @aud = @$audr;
    my %HASH = (RS256 => 'SHA256', RS384 => 'SHA384', RS512 => 'SHA512', ES256 => 'SHA256', ES384 => 'SHA384');
    my $alg = $hdr->{alg} // '';
    return (undef, "unsupported token algorithm '$alg'") unless $HASH{$alg};
    my $kid = $hdr->{kid} // '';
    (my $keys, my $e) = _oidc_keys($iss); return (undef, $e) if $e;
    unless ($keys->{$kid}) { ($keys, $e) = _oidc_keys($iss, 1); return (undef, $e) if $e; }
    my $jwk = $keys->{$kid} or return (undef, 'token signed by an unknown key');
    my $sig = _b64url_dec($s64);
    my $ok = eval {
        if ($alg =~ /^RS/) { require Crypt::PK::RSA; Crypt::PK::RSA->new($jwk)->verify_message($sig, "$h64.$p64", $HASH{$alg}, 'v1.5') }
        else               { require Crypt::PK::ECC; Crypt::PK::ECC->new($jwk)->verify_message_rfc7518($sig, "$h64.$p64", $HASH{$alg}) }
    };
    return (undef, 'bad token signature') unless $ok;
    my @taud = ref $cl->{aud} eq 'ARRAY' ? @{ $cl->{aud} } : ($cl->{aud} // ());
    my %want = map { $_ => 1 } @aud;
    return (undef, 'token audience does not match') unless grep { $want{$_} } @taud;
    my $now = time;
    return (undef, 'token expired') unless ($cl->{exp} // 0) > $now - 60;
    return (undef, 'token not valid yet') if defined $cl->{nbf} && $cl->{nbf} > $now + 60;
    return (1, undef);
}

# The token of an external request: "Authorization: Bearer <token>", or "X-API-Key: <token>" for clients that
# can only set a named key header (API-key auth in Copilot Studio and similar). undef when neither is sent.
sub request_bearer {
    my $ah = $ENV{HTTP_AUTHORIZATION} || $ENV{REDIRECT_HTTP_AUTHORIZATION} || '';
    return $1 if $ah =~ /^Bearer\s+(\S+)\s*$/i || $ah =~ /^\s*(dnsp_[0-9a-f]{40})\s*$/;   # a bare API token too
    my $k = $ENV{HTTP_X_API_KEY} // '';
    return $k =~ /^\s*(\S+)\s*$/ ? $1 : undef;
}

# Anonymous: read access to all zones, no capabilities (id 0 matches no grant). Only when switched on.
sub anonymous_user { return { id => 0, username => 'anonymous', anonymous => 1 }; }

1;
