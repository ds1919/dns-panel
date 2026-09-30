-- DNS Panel — the panel's own database schema (NOT PowerDNS; PowerDNS uses its own gmysql schema).
--
-- Identity (who the user is) is separate from login methods (how they sign in). The primary method is a
-- client certificate (mTLS); TOTP and OAuth fit without a schema migration. See DOCS/08-auth.md.

-- ---------------------------------------------------------------------------
-- users — identity (method-independent)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id           INT UNSIGNED NOT NULL AUTO_INCREMENT,
    username     VARCHAR(64)  NOT NULL,
    email        VARCHAR(255) DEFAULT NULL,
    display_name VARCHAR(128) DEFAULT NULL,
    is_active    TINYINT(1)   NOT NULL DEFAULT 1,
    session_ttl  INT UNSIGNED DEFAULT NULL,                -- per-user session TTL, seconds (NULL = auth.session_ttl)
    -- Personal settings (Account). NULL = default: browser time zone, default theme.
    timezone        VARCHAR(64)  DEFAULT NULL,
    date_format     VARCHAR(8)   DEFAULT NULL,       -- dmy | iso | mdy; NULL = the browser's
    theme           VARCHAR(32)  DEFAULT NULL,
    -- The second factor is optional (docs/08-auth.md). 1 = this user is expected to have one but has no app
    -- enrolled, so the next login asks to enroll. This is how admin Reset ("lost phone") and Require work.
    totp_required   TINYINT(1)   NOT NULL DEFAULT 0,
    created_at   TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uniq_username (username),
    UNIQUE KEY uniq_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------------------------------------------------------------
-- auth_identities — EXTERNAL login methods (identities, not credentials); several per user.
--   type=cert  : principal = client certificate CN (SSL_CLIENT_S_DN_CN)
--   type=oauth : provider='google'; principal = OIDC 'sub' or email
-- Password / TOTP / recovery codes live in the separate *_credentials tables below.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS auth_identities (
    id           INT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id      INT UNSIGNED NOT NULL,
    type         ENUM('cert','oauth') NOT NULL,
    -- provider/principal are NOT NULL: NULLs never collide in a UNIQUE key, so one CN could be bound to
    -- several users. provider='' for cert; the provider name for oauth.
    provider     VARCHAR(32)  NOT NULL DEFAULT '',
    principal    VARCHAR(255) NOT NULL,                  -- cert CN / oauth sub
    data         JSON         DEFAULT NULL,              -- method-specific details (cert serial, oauth claims)
    is_active    TINYINT(1)   NOT NULL DEFAULT 1,
    created_at   TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at DATETIME     DEFAULT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uniq_principal (type, provider, principal),
    KEY idx_user (user_id),
    CONSTRAINT fk_auth_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- password_credentials — local password (Argon2id encoded hash, salt embedded). One per user.
CREATE TABLE IF NOT EXISTS password_credentials (
    user_id       INT UNSIGNED NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    must_change   TINYINT(1)   NOT NULL DEFAULT 0,      -- temporary password: force a change at login
    changed_at    TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    created_at    TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id),
    CONSTRAINT fk_pwd_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- totp_credentials — second factor (RFC 6238). The secret is encrypted with the panel master key.
-- last_used_step is anti-replay: the last ACCEPTED time step, so one code cannot be accepted twice.
CREATE TABLE IF NOT EXISTS totp_credentials (
    user_id          INT UNSIGNED NOT NULL,
    secret_encrypted VARBINARY(255)  NOT NULL,
    key_version      INT UNSIGNED NOT NULL DEFAULT 1,   -- master key version (rotation)
    confirmed_at     DATETIME     DEFAULT NULL,         -- NULL = enrollment not finished (first code not confirmed)
    last_used_step   BIGINT UNSIGNED DEFAULT NULL,
    -- Authenticator replacement: the candidate lives here until confirmed by a code. The old secret keeps
    -- working meanwhile, otherwise a replacement abandoned halfway would lock the user out.
    pending_secret_encrypted VARBINARY(255) DEFAULT NULL,
    pending_created_at       DATETIME       DEFAULT NULL,
    created_at       TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id),
    CONSTRAINT fk_totp_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- recovery_codes — one-time recovery codes. Only the hash is stored; the code is shown once.
CREATE TABLE IF NOT EXISTS recovery_codes (
    id         INT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id    INT UNSIGNED NOT NULL,
    code_hash  VARCHAR(255) NOT NULL,
    used_at    DATETIME     DEFAULT NULL,
    created_at TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_rc_user (user_id),
    CONSTRAINT fk_rc_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------------------------------------------------------------
-- sessions — active sessions (cookie session_token)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sessions (
    id         INT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id    INT UNSIGNED NOT NULL,
    token      VARCHAR(128) NOT NULL,       -- hex SHA-256 of the cookie token; the bearer itself is never stored
    auth_type  VARCHAR(16)  DEFAULT NULL,   -- method that created it (cert/password), for audit
    stage      ENUM('pending','full') NOT NULL DEFAULT 'full',  -- pending = password passed, factors not done: NO panel/API access
    remember   TINYINT(1)   NOT NULL DEFAULT 0,   -- "Remember this device": full TTL + persistent cookie (otherwise a short session cookie)
    pending_step VARCHAR(24) DEFAULT NULL,  -- next step of a pending session: password_change|totp_enroll|totp_verify|recovery
    ip         VARCHAR(45)  DEFAULT NULL,   -- IP at creation time
    user_agent VARCHAR(255) DEFAULT NULL,
    is_active  TINYINT(1)   NOT NULL DEFAULT 1,
    created_at TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME     NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uniq_token (token),
    KEY idx_user (user_id),
    CONSTRAINT fk_sessions_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- auth_throttle — login attempt rate limiting (password/TOTP/recovery), fixed window.
-- bucket is an arbitrary key ('pw:<user>|<ip>' / 'totp:<user_id>'); exceeding attempts per window sets locked_until.
CREATE TABLE IF NOT EXISTS auth_throttle (
    bucket       VARCHAR(96) NOT NULL,
    attempts     INT UNSIGNED NOT NULL DEFAULT 0,
    window_start TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    locked_until DATETIME     DEFAULT NULL,
    PRIMARY KEY (bucket)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------------------------------------------------------------
-- PERMISSIONS: zone access (none/read/write) + admin capabilities, via groups with personal overrides.
-- See DOCS/20-permissions.md.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS groups (
    id          INT UNSIGNED NOT NULL AUTO_INCREMENT,
    name        VARCHAR(64)  NOT NULL,
    description VARCHAR(255) DEFAULT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uniq_group_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS user_groups (
    user_id  INT UNSIGNED NOT NULL,
    group_id INT UNSIGNED NOT NULL,
    PRIMARY KEY (user_id, group_id),
    CONSTRAINT fk_ug_user  FOREIGN KEY (user_id)  REFERENCES users (id)  ON DELETE CASCADE,
    CONSTRAINT fk_ug_group FOREIGN KEY (group_id) REFERENCES groups (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Zone access for a subject (group or user override). scope: all | zone; zone beats all.
-- A personal override is subject_type='user'; no row = Inherit.
CREATE TABLE IF NOT EXISTS zone_access (
    id           INT UNSIGNED NOT NULL AUTO_INCREMENT,
    subject_type ENUM('group','user') NOT NULL,
    subject_id   INT UNSIGNED NOT NULL,
    scope        ENUM('all','zone') NOT NULL,
    zone_id      INT UNSIGNED DEFAULT NULL,   -- for scope=zone (logical ref to pdns.domains.id)
    access       ENUM('none','read','write') NOT NULL,
    PRIMARY KEY (id),
    KEY idx_subject (subject_type, subject_id),
    KEY idx_zone (zone_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS capability_grants (
    id           INT UNSIGNED NOT NULL AUTO_INCREMENT,
    subject_type ENUM('group','user') NOT NULL,
    subject_id   INT UNSIGNED NOT NULL,
    capability   ENUM('users.manage','secondary.manage','catalog.manage','distribution.manage',
                      'ha.manage','ha.emergency','audit.read','zones.manage',
                      'labels.manage','pulse.manage') NOT NULL,
    -- Personal deny: a group grants the capability but this user does not get it. Groups have no deny,
    -- since for a group "no grant" and "deny" are the same. See docs/20-permissions.md.
    effect       ENUM('allow','deny') NOT NULL DEFAULT 'allow',
    PRIMARY KEY (id),
    UNIQUE KEY uniq_grant (subject_type, subject_id, capability)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Panel operational settings managed by the administrator (sync timeouts, MCP policy, session TTL).
-- Defaults live in code: a fresh install works with no rows here, and the table holds only what was changed.
-- OIDC providers (docs/10-mcp.md): a bearer JWT is checked by the provider whose issuer it names; the user is
-- found by username_claim. Any number of providers; they all lead to the same local users.
CREATE TABLE IF NOT EXISTS oidc_providers (
    id             INT UNSIGNED NOT NULL AUTO_INCREMENT,
    name           VARCHAR(64)  NOT NULL,
    issuer         VARCHAR(255) NOT NULL,      -- exactly the token's iss, without a trailing slash
    audience       VARCHAR(255) NOT NULL,      -- accepted aud values, comma-separated
    username_claim VARCHAR(64)  NOT NULL DEFAULT 'preferred_username',
    enabled        TINYINT(1)   NOT NULL DEFAULT 1,
    created_at     TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uniq_name (name),
    UNIQUE KEY uniq_issuer (issuer)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- API tokens (docs/11-api.md). A token acts as its owner with the owner's permissions. Stored as is: the owner
-- can copy it again from Settings → External access.
CREATE TABLE IF NOT EXISTS api_tokens (
    id           INT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id      INT UNSIGNED NOT NULL,
    name         VARCHAR(64)  NOT NULL,
    token        VARCHAR(64)  NOT NULL,
    enabled      TINYINT(1)   NOT NULL DEFAULT 1,
    expires_at   DATE         DEFAULT NULL,      -- valid through this day (UTC); NULL = no expiry
    created_at   TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at DATETIME     DEFAULT NULL,
    last_used_ip VARCHAR(45)  DEFAULT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uniq_token (token),
    UNIQUE KEY uniq_user_name (user_id, name),
    CONSTRAINT fk_api_tokens_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Applied upgrades (deploy/migrations/NNNN-*.sql). schema.sql is always the full current schema, so a clean
-- install records every migration shipped with it as applied; an update runs only the missing ones.
CREATE TABLE IF NOT EXISTS schema_migrations (
    version    VARCHAR(64) NOT NULL,           -- file name without .sql
    applied_at TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (version)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS settings (
    `key`      VARCHAR(64)  NOT NULL,
    `value`    TEXT         NOT NULL,
    updated_at TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- HA roles and operations are deliberately NOT here. The old Perl implementation kept them in the
-- replicated dns_panel, so a node learned its role from a table that arrives from the other node and
-- becomes unavailable exactly when it is needed most. The Go HA manager keeps them in the local,
-- non-replicated `dns_ha` database (embedded in dns-ha-manager: src/dns-ha/internal/store/dns_ha.sql) and the right to be ACTIVE in a durable
-- safety store outside the DB. See docs/23-ha-manager.md §4. Installs upgraded from the Perl version may
-- drop ha_cluster / ha_operations / ha_operation_steps manually; the panel does not read them.

CREATE TABLE IF NOT EXISTS audit_log (
    id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    ts          TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    actor       VARCHAR(64)  DEFAULT NULL,   -- username/CN; NULL for system actions
    actor_role  VARCHAR(32)  DEFAULT NULL,
    source      ENUM('panel','api','mcp','ha-agent','system','cli','emergency-cli') NOT NULL DEFAULT 'panel',
    via         VARCHAR(96)  DEFAULT NULL,   -- how an external request signed in: 'token <name>' / 'oidc <provider>' / 'anonymous'
    action      VARCHAR(64)  NOT NULL,       -- create_record | update_record | delete_zone | switchover | login | ...
    target_type VARCHAR(32)  DEFAULT NULL,   -- record | zone | session | ha-operation
    target      VARCHAR(255) DEFAULT NULL,   -- FQDN / zone name / object id
    target_label VARCHAR(255) DEFAULT NULL,  -- SNAPSHOT of the object's human-readable name at event time;
                                             -- survives deletion of the object
    before_val  JSON         DEFAULT NULL,
    after_val   JSON         DEFAULT NULL,
    result      VARCHAR(16)  NOT NULL DEFAULT 'ok',  -- ok | denied | error | partial
    detail      VARCHAR(255) DEFAULT NULL,   -- reason for denial/error
    ip          VARCHAR(45)  DEFAULT NULL,
    request_id  VARCHAR(64)  DEFAULT NULL,   -- correlation id
    PRIMARY KEY (id),
    KEY idx_ts (ts),
    KEY idx_actor (actor),
    KEY idx_target (target_type, target)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ===========================================================================
-- SECONDARY DISTRIBUTION — inventory (docs/16-delivery.md).
--
-- Cross-DB honesty: FK/CASCADE only inside dns_panel.
--
-- Permissions:
--   secondary.manage    — secondary_nodes/groups, membership, node endpoints
--   distribution.manage — ip_groups, tsig_keys, group<->IP/TSIG bindings
--
-- Delete protection: an entity in use is protected by FK RESTRICT on its own side, not only by a
-- precheck COUNT (otherwise a precheck/DELETE race or direct SQL changes policy silently). Policy
-- bindings (secondary_group_ip_groups/_tsig_keys) are RESTRICT on BOTH sides. CASCADE only for rows owned
-- by their parent: members and node endpoints.
-- ===========================================================================

-- TSIG keys (materialized into pdns.tsigkeys by name). A key is IMMUTABLE: name/algorithm/secret are set
-- only at creation and PATCH rejects them (changing them under the same id would silently desync
-- subscribers; rotation = new key + make it active). The secret is available via a capability-gated reveal
-- endpoint and is NEVER written to audit_log.
CREATE TABLE IF NOT EXISTS tsig_keys (
    id         INT UNSIGNED NOT NULL AUTO_INCREMENT,
    name       VARCHAR(255) NOT NULL,
    algorithm  VARCHAR(64)  NOT NULL DEFAULT 'hmac-sha256',
    secret     VARBINARY(512) NOT NULL,                     -- base64 TSIG secret; sensitive, never returned
    created_at TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_tsig_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS ip_groups (
    id          INT UNSIGNED NOT NULL AUTO_INCREMENT,
    name        VARCHAR(64)  NOT NULL,
    description VARCHAR(255) DEFAULT NULL,
    created_at  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_ipg_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS ip_group_members (
    id          INT UNSIGNED NOT NULL AUTO_INCREMENT,
    ip_group_id INT UNSIGNED NOT NULL,
    cidr        VARCHAR(64)  NOT NULL,                       -- IP or CIDR (v4/v6)
    PRIMARY KEY (id),
    UNIQUE KEY uq_ipg_cidr (ip_group_id, cidr),
    CONSTRAINT fk_ipgm_group FOREIGN KEY (ip_group_id) REFERENCES ip_groups (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
-- Our own PowerDNS addresses are deliberately not stored anywhere: the panel reads them from PowerDNS
-- itself (local-address/local-port via its API), minus 127.0.0.0/8. A hand-typed list was wrong by
-- construction.

-- axfr_auth_mode — AXFR authorization (Require TSIG on/off):
--   ip_only    — ALLOW-AXFR-FROM only (needs >=1 IP group);
--   tsig_only  — TSIG-ALLOW-AXFR only (needs >=1 TSIG key).
-- Node axfr_source endpoints are for inventory/diagnostics/ACL coverage checks and do NOT widen the ACL
-- (ALLOW-AXFR-FROM comes from secondary_group_ip_groups).
CREATE TABLE IF NOT EXISTS secondary_groups (
    id             INT UNSIGNED NOT NULL AUTO_INCREMENT,
    name           VARCHAR(64)  NOT NULL,
    description    VARCHAR(255) DEFAULT NULL,
    axfr_auth_mode ENUM('ip_only','tsig_only') NOT NULL DEFAULT 'tsig_only',
    -- DEFAULT NOTIFY for this group's servers (ALSO-NOTIFY on the zones it receives). Turned off where a
    -- server gets updates from an intermediate DNS rather than from us. Not a hard filter: a server may
    -- override it with secondary_nodes.notify_policy.
    send_notify    TINYINT(1)   NOT NULL DEFAULT 1,
    -- Whether we serve the ZONES themselves to this group (AXFR of member zones + NOTIFY about them).
    -- The catalog goes to ALL subscribers regardless: it is only the list of names BIND uses to add and
    -- remove zones. The flag is for secondaries that take only the catalog from us and zone data from their
    -- own upstream. Which upstream is not known or stored here: that is their routing and BIND config.
    zone_axfr      TINYINT(1)   NOT NULL DEFAULT 1,
    created_at     TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at     TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_sg_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS secondary_nodes (
    id                     INT UNSIGNED NOT NULL AUTO_INCREMENT,
    name                   VARCHAR(64)  NOT NULL,
    location               VARCHAR(64)  DEFAULT NULL,
    enabled                TINYINT(1)   NOT NULL DEFAULT 1,
    implementation         ENUM('bind','powerdns') NOT NULL DEFAULT 'bind',
    provisioning_mode      ENUM('manual','agent')  NOT NULL DEFAULT 'manual',
    supports_catalog       TINYINT(1)   NOT NULL DEFAULT 0,  -- RFC 9432 consumer
    supports_coo           TINYINT(1)   NOT NULL DEFAULT 0,  -- Change of Ownership
    -- default_group_id: the group whose TSIG key authorizes this server's AXFR (priority: node's own TSIG
    -- -> default group's TSIG -> IP ACL). Other groups are tags / catalog assignment and do NOT take part in
    -- key selection. SET NULL on group delete; the app keeps it equal to one of the node's groups.
    default_group_id       INT UNSIGNED DEFAULT NULL,
    -- Explicit NOTIFY override for THIS server. inherit = OR of send_notify over the groups through which
    -- the server belongs to the catalog in question (no such groups, e.g. assigned individually -> off);
    -- on/off are final. The effective value belongs to the (server, catalog) pair, since ALSO-NOTIFY is
    -- set on a given catalog's zones. default_group_id has nothing to do with NOTIFY.
    notify_policy          ENUM('inherit','on','off') NOT NULL DEFAULT 'inherit',
    -- Explicit AXFR override for THIS server, same three-state model as notify_policy: a group covers
    -- dozens of servers at once, but a single server must be able to differ. inherit = OR of zone_axfr over
    -- the groups through which the server belongs to the Distribution; none (assigned directly) -> allow.
    axfr_policy            ENUM('inherit','allow','deny') NOT NULL DEFAULT 'inherit',
    created_at             TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at             TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_sn_name (name),
    KEY idx_sn_dgroup (default_group_id),
    CONSTRAINT fk_sn_dgroup FOREIGN KEY (default_group_id) REFERENCES secondary_groups (id) ON DELETE SET NULL,
    -- COO builds on catalog support.
    CONSTRAINT ck_sn_caps CHECK (supports_coo = 0 OR supports_catalog = 1)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- A node may be in SEVERAL groups (M:N), otherwise overlapping subscriber sets are impossible.
-- Networks an IP ACL group allows to transfer its zones (ALLOW-AXFR-FROM), for clients that are a network, not a server.
CREATE TABLE IF NOT EXISTS secondary_group_prefixes (
    id                 INT UNSIGNED NOT NULL AUTO_INCREMENT,
    secondary_group_id INT UNSIGNED NOT NULL,
    cidr               VARCHAR(64)  NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_sgp (secondary_group_id, cidr),
    CONSTRAINT fk_sgp_group FOREIGN KEY (secondary_group_id) REFERENCES secondary_groups (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS secondary_group_members (
    secondary_group_id INT UNSIGNED NOT NULL,
    secondary_node_id  INT UNSIGNED NOT NULL,
    PRIMARY KEY (secondary_group_id, secondary_node_id),
    KEY idx_sgm_node (secondary_node_id),
    CONSTRAINT fk_sgm_group FOREIGN KEY (secondary_group_id) REFERENCES secondary_groups (id) ON DELETE CASCADE,
    CONSTRAINT fk_sgm_node  FOREIGN KEY (secondary_node_id)  REFERENCES secondary_nodes  (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Typed node endpoints (docs/16-delivery.md): the AXFR ACL uses axfr_source, NOTIFY uses notify_target,
-- health uses health_check, so an anycast address never ends up in the AXFR ACL.
CREATE TABLE IF NOT EXISTS secondary_node_endpoints (
    id                INT UNSIGNED NOT NULL AUTO_INCREMENT,
    secondary_node_id INT UNSIGNED NOT NULL,
    purpose           ENUM('dns_listen','notify_target','axfr_source','management',
                           'health_check','anycast_service') NOT NULL,
    address           VARCHAR(45)  NOT NULL,
    port              SMALLINT UNSIGNED NOT NULL DEFAULT 53,
    enabled           TINYINT(1)   NOT NULL DEFAULT 1,
    PRIMARY KEY (id),
    UNIQUE KEY uq_sne (secondary_node_id, purpose, address, port),
    CONSTRAINT fk_sne_node FOREIGN KEY (secondary_node_id) REFERENCES secondary_nodes (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Group-level ACL/TSIG sources (several TSIG keys allow rotation).
CREATE TABLE IF NOT EXISTS secondary_group_ip_groups (
    secondary_group_id INT UNSIGNED NOT NULL,
    ip_group_id        INT UNSIGNED NOT NULL,
    PRIMARY KEY (secondary_group_id, ip_group_id),
    KEY idx_sgig_ipg (ip_group_id),
    -- RESTRICT on BOTH sides: a binding is AXFR policy (distribution.manage). An IP group cannot be deleted
    -- while bound, and deleting a group (secondary.manage) cannot cascade the policy away: a
    -- distribution.manage operator must remove the binding first. This keeps the permissions truly separate.
    CONSTRAINT fk_sgig_group FOREIGN KEY (secondary_group_id) REFERENCES secondary_groups (id) ON DELETE RESTRICT,
    CONSTRAINT fk_sgig_ipg   FOREIGN KEY (ip_group_id)        REFERENCES ip_groups        (id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS secondary_group_tsig_keys (
    secondary_group_id INT UNSIGNED NOT NULL,
    tsig_key_id        INT UNSIGNED NOT NULL,
    is_primary         TINYINT(1) NOT NULL DEFAULT 0,   -- the group's active key (radio)
    -- "At most one active key per group" is a DB invariant, not a code convention: three code paths
    -- (add/remove/set_primary) used to maintain it, and one mistake was enough for the UI to show two radios
    -- checked. NULLs do not collide in UNIQUE, so any number of inactive rows is fine.
    primary_group      INT UNSIGNED AS (IF(is_primary = 1, secondary_group_id, NULL)) VIRTUAL,
    PRIMARY KEY (secondary_group_id, tsig_key_id),
    UNIQUE KEY uq_sgtk_primary (primary_group),
    KEY idx_sgtk_key (tsig_key_id),
    -- RESTRICT on BOTH sides (see secondary_group_ip_groups).
    CONSTRAINT fk_sgtk_group FOREIGN KEY (secondary_group_id) REFERENCES secondary_groups (id) ON DELETE RESTRICT,
    CONSTRAINT fk_sgtk_key   FOREIGN KEY (tsig_key_id)        REFERENCES tsig_keys        (id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Per-NODE TSIG keys: override group keys for this server's AXFR authorization (priority: node key ->
-- key of the group assigned to the catalog -> IP ACL). Multiple keys, at most one active (is_primary).
-- node CASCADE (the binding belongs to the node); key RESTRICT (a key in use cannot be deleted).
CREATE TABLE IF NOT EXISTS secondary_node_tsig_keys (
    secondary_node_id INT UNSIGNED NOT NULL,
    tsig_key_id       INT UNSIGNED NOT NULL,
    is_primary        TINYINT(1) NOT NULL DEFAULT 0,
    primary_node      INT UNSIGNED AS (IF(is_primary = 1, secondary_node_id, NULL)) VIRTUAL,   -- at most one active per node
    PRIMARY KEY (secondary_node_id, tsig_key_id),
    UNIQUE KEY uq_sntk_primary (primary_node),
    KEY idx_sntk_key (tsig_key_id),
    CONSTRAINT fk_sntk_node FOREIGN KEY (secondary_node_id) REFERENCES secondary_nodes (id) ON DELETE CASCADE,
    CONSTRAINT fk_sntk_key  FOREIGN KEY (tsig_key_id)       REFERENCES tsig_keys        (id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ===========================================================================
-- ZONE DISTRIBUTION — catalogs and direct distribution, on top of the inventory.
-- The panel creates the producer zone in PowerDNS itself (catalog_provision); zone membership lives in
-- pdns.domains.catalog.
--
-- Distribution of a zone = TWO independent lists, neither derived from the other:
--   direct   — zone_direct_axfr (recipients = all permitted Servers inventory);
--   catalog  — pdns.domains.catalog (PowerDNS is the source of truth; the panel keeps no copy).
-- There are no automatic assignment rules: a human decides.
-- ===========================================================================

CREATE TABLE IF NOT EXISTS catalogs (
    id                 INT UNSIGNED NOT NULL AUTO_INCREMENT,
    name               VARCHAR(190) NOT NULL,                 -- display name
    fqdn               VARCHAR(255) NOT NULL,                 -- producer catalog zone name
    -- Where secondaries pull the catalog itself from is NOT stored per catalog: there is one producer, and
    -- that is a property of PowerDNS (its local-address), not of each catalog.
    pdns_domain_id     INT UNSIGNED DEFAULT NULL,             -- pdns.domains id (cross-DB, no FK); NULL = not created yet
    last_error         VARCHAR(255) DEFAULT NULL,             -- last policy reconcile error, shown as a banner
    created_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_catalogs_name (name),
    UNIQUE KEY uq_cat_fqdn (fqdn),
    UNIQUE KEY uq_cat_domain (pdns_domain_id)                 -- NULLs don't collide: many "not created yet"
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Catalog subscribers: server groups and individual servers (plain M:N).
CREATE TABLE IF NOT EXISTS catalog_groups (
    catalog_id         INT UNSIGNED NOT NULL,
    secondary_group_id INT UNSIGNED NOT NULL,
    PRIMARY KEY (catalog_id, secondary_group_id),
    KEY idx_cg_group (secondary_group_id),
    CONSTRAINT fk_cg_catalog FOREIGN KEY (catalog_id)         REFERENCES catalogs         (id) ON DELETE CASCADE,
    CONSTRAINT fk_cg_group   FOREIGN KEY (secondary_group_id) REFERENCES secondary_groups (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS catalog_nodes (
    catalog_id         INT UNSIGNED NOT NULL,
    secondary_node_id  INT UNSIGNED NOT NULL,
    PRIMARY KEY (catalog_id, secondary_node_id),
    KEY idx_cn_node (secondary_node_id),
    CONSTRAINT fk_cn_catalog FOREIGN KEY (catalog_id)        REFERENCES catalogs        (id) ON DELETE CASCADE,
    CONSTRAINT fk_cn_node    FOREIGN KEY (secondary_node_id) REFERENCES secondary_nodes (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Our PowerDNS addresses that the catalog publishes to subscribers.
CREATE TABLE IF NOT EXISTS catalog_primary_endpoints (
    catalog_id         INT UNSIGNED NOT NULL,
    secondary_group_id INT UNSIGNED DEFAULT NULL,
    address            VARCHAR(64) NOT NULL,
    port               INT NOT NULL DEFAULT 53,
    -- Multiple NULLs are not duplicates in a UNIQUE KEY, so the key uses a derived column where
    -- "no group" is 0.
    grp_key            INT UNSIGNED AS (IFNULL(secondary_group_id, 0)) STORED,
    UNIQUE KEY uq_cpe (catalog_id, grp_key, address, port),
    KEY idx_cpe_group (secondary_group_id),
    CONSTRAINT fk_cpe_catalog FOREIGN KEY (catalog_id)         REFERENCES catalogs         (id) ON DELETE CASCADE,
    CONSTRAINT fk_cpe_group   FOREIGN KEY (secondary_group_id) REFERENCES secondary_groups (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS zone_direct_axfr (
    domain_id  INT UNSIGNED NOT NULL,                 -- pdns.domains.id (cross-DB, no FK; cleaned up by the panel)
    reason     VARCHAR(255) NULL,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (domain_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ===== Dynamic updates (RFC 2136) =====
-- Settings live on each zone (mode, DHCP addresses, keys); a Dynamic DHCP profile is a saved set a zone
-- can follow (profile edits are copied into it). The panel lays it out into PowerDNS.
CREATE TABLE IF NOT EXISTS dyn_profiles (
    id         INT UNSIGNED NOT NULL AUTO_INCREMENT,
    name       VARCHAR(64)  NOT NULL,
    mode       ENUM('ip','tsig','ip_tsig') NOT NULL,
    created_at TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_dynp_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS dyn_profile_sources (
    profile_id INT UNSIGNED NOT NULL,
    cidr       VARCHAR(64)  NOT NULL,                 -- DHCP server IP or network (v4/v6)
    PRIMARY KEY (profile_id, cidr),
    CONSTRAINT fk_dps_profile FOREIGN KEY (profile_id) REFERENCES dyn_profiles (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS dyn_profile_keys (
    profile_id  INT UNSIGNED NOT NULL,
    tsig_key_id INT UNSIGNED NOT NULL,
    PRIMARY KEY (profile_id, tsig_key_id),
    KEY idx_dpk_key (tsig_key_id),
    CONSTRAINT fk_dpk_profile FOREIGN KEY (profile_id)  REFERENCES dyn_profiles (id) ON DELETE CASCADE,
    CONSTRAINT fk_dpk_key     FOREIGN KEY (tsig_key_id) REFERENCES tsig_keys (id)   ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Zone settings. Values ALWAYS live on the zone, even when it follows a profile (profile edits are copied
-- in), so detaching (editing the zone, unticking, deleting the profile) loses nothing: profile_id just
-- becomes NULL. enabled=0: updates off, settings kept, our config removed from the zone in PowerDNS.
-- Only a primary actually accepts updates; on a secondary the settings wait for Make primary.
CREATE TABLE IF NOT EXISTS zone_dynamic (
    domain_id  INT UNSIGNED NOT NULL,                 -- pdns.domains.id (cross-DB, no FK; cleaned up with the zone)
    enabled    TINYINT(1)   NOT NULL DEFAULT 1,
    mode       ENUM('ip','tsig','ip_tsig') NULL,
    profile_id INT UNSIGNED NULL,                     -- followed profile; NULL = own values
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (domain_id),
    KEY idx_zd_profile (profile_id),
    CONSTRAINT fk_zd_profile FOREIGN KEY (profile_id) REFERENCES dyn_profiles (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS zone_dynamic_sources (
    domain_id INT UNSIGNED NOT NULL,
    cidr      VARCHAR(64)  NOT NULL,
    PRIMARY KEY (domain_id, cidr),
    CONSTRAINT fk_zds_zone FOREIGN KEY (domain_id) REFERENCES zone_dynamic (domain_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS zone_dynamic_keys (
    domain_id   INT UNSIGNED NOT NULL,
    tsig_key_id INT UNSIGNED NOT NULL,
    PRIMARY KEY (domain_id, tsig_key_id),
    KEY idx_zdk_key (tsig_key_id),
    CONSTRAINT fk_zdk_zone FOREIGN KEY (domain_id)   REFERENCES zone_dynamic (domain_id) ON DELETE CASCADE,
    CONSTRAINT fk_zdk_key  FOREIGN KEY (tsig_key_id) REFERENCES tsig_keys (id)          ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Observed catalog subscription of a consumer node. RFC 9432: PowerDNS maintains the producer catalog
-- itself (kind=PRODUCER zone + `catalog` property on member zones); the panel does NOT write member PTRs
-- and does NOT configure BIND (secondaries are configured by hand). This table only caches the result of
-- a live DNS check (Recheck).
CREATE TABLE IF NOT EXISTS catalog_subscriptions (
    id                 INT UNSIGNED NOT NULL AUTO_INCREMENT,
    catalog_id         INT UNSIGNED NOT NULL,
    secondary_node_id  INT UNSIGNED NOT NULL,
    observed_state     ENUM('unknown','subscribed','unsubscribed','error','lagging') NOT NULL DEFAULT 'unknown',
    observed_at        TIMESTAMP NULL DEFAULT NULL,           -- last check (any result)
    verified_at        TIMESTAMP NULL DEFAULT NULL,           -- last authoritative SOA of the catalog received (connected)
    observed_serial    BIGINT UNSIGNED DEFAULT NULL,          -- catalog serial on the secondary (vs producer -> lagging)
    last_error         VARCHAR(255) DEFAULT NULL,
    created_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_sub (catalog_id, secondary_node_id),
    KEY idx_sub_node (secondary_node_id),
    -- Both CASCADE: the row is a derived observation cache that lives as long as the catalog and node.
    CONSTRAINT fk_sub_cat  FOREIGN KEY (catalog_id)        REFERENCES catalogs (id)        ON DELETE CASCADE,
    CONSTRAINT fk_sub_node FOREIGN KEY (secondary_node_id) REFERENCES secondary_nodes (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Zone profiles — editable presets for zone creation (Settings -> Zone profiles). A zone stores only the
-- immutable code (metadata X-DNSPANEL-PROFILE), so renaming a profile does not touch zones.
-- A profile is ONE set of NS/SOA/catalog: if those differ, it is a different profile ("FXTM Internal" vs
-- "FXTM External"), not a variant. Changing a zone's profile does NOT rewrite SOA/NS of an existing zone.
CREATE TABLE IF NOT EXISTS zone_profiles (
    id            INT UNSIGNED NOT NULL AUTO_INCREMENT,
    code          VARCHAR(64)  NOT NULL,                          -- immutable, written to X-DNSPANEL-PROFILE
    name          VARCHAR(64)  NOT NULL,                          -- display name (editable)
    -- Default catalog for this profile's zones: prefilled in the create-zone form, the operator decides.
    -- NULL = None.
    default_catalog_id INT UNSIGNED DEFAULT NULL,
    primary_ns    VARCHAR(255) NOT NULL DEFAULT '',
    hostmaster    VARCHAR(255) NOT NULL DEFAULT '',
    soa_ttl       INT UNSIGNED NOT NULL DEFAULT 3600,
    soa_refresh   INT UNSIGNED NOT NULL DEFAULT 7200,
    soa_retry     INT UNSIGNED NOT NULL DEFAULT 3600,
    soa_expire    INT UNSIGNED NOT NULL DEFAULT 1209600,
    soa_minimum   INT UNSIGNED NOT NULL DEFAULT 3600,
    enabled       TINYINT(1)   NOT NULL DEFAULT 1,
    created_at    TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_zp_code (code),
    UNIQUE KEY uq_zp_name (name),
    -- SET NULL: deleting a catalog does not block; the profile loses its default (zones get None).
    CONSTRAINT fk_zp_catalog FOREIGN KEY (default_catalog_id) REFERENCES catalogs (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS zone_profile_nameservers (
    id          INT UNSIGNED NOT NULL AUTO_INCREMENT,
    profile_id  INT UNSIGNED NOT NULL,
    nameserver  VARCHAR(255) NOT NULL,
    ord         INT UNSIGNED NOT NULL DEFAULT 0,
    PRIMARY KEY (id),
    KEY idx_zpn_profile (profile_id),
    CONSTRAINT fk_zpn_profile FOREIGN KEY (profile_id) REFERENCES zone_profiles (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- No zone_distribution_state table: reconcile reads zone membership live from PowerDNS (domains.catalog);
-- a mirrored copy would contradict the single source of truth.

-- ---------------------------------------------------------------------------
-- Observability: CURRENT state + policy only. Time series/logs go to VictoriaMetrics/VictoriaLogs,
-- not here. Filled by the evaluator. See DOCS/18,19.
-- ---------------------------------------------------------------------------

-- Liveness check policies (health checks of A/PTR targets by IP)
CREATE TABLE IF NOT EXISTS probe_policies (
    id               INT UNSIGNED NOT NULL AUTO_INCREMENT,
    name             VARCHAR(64)  NOT NULL,
    method           VARCHAR(32)  NOT NULL,   -- icmp | tcp:443 | https:/health | dns:53 | none
    interval_seconds INT UNSIGNED NOT NULL DEFAULT 300,
    expected         VARCHAR(64)  DEFAULT NULL,  -- e.g. expected HTTP status
    enabled          TINYINT(1)   NOT NULL DEFAULT 1,
    PRIMARY KEY (id),
    UNIQUE KEY uniq_policy_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Current health of a target IP; linked to A/PTR via records.content / the IP from a PTR.
CREATE TABLE IF NOT EXISTS record_health (
    target_ip           VARCHAR(45)  NOT NULL,
    policy_id           INT UNSIGNED DEFAULT NULL,
    state               ENUM('UNKNOWN','HEALTHY','DEGRADED','UNREACHABLE','STALE_CANDIDATE') NOT NULL DEFAULT 'UNKNOWN',
    last_success_at     DATETIME     DEFAULT NULL,
    last_failure_at     DATETIME     DEFAULT NULL,
    consecutive_failures INT UNSIGNED NOT NULL DEFAULT 0,
    probes_ok           INT UNSIGNED NOT NULL DEFAULT 0,
    probes_total        INT UNSIGNED NOT NULL DEFAULT 0,
    stale_candidate     TINYINT(1)   NOT NULL DEFAULT 0,
    updated_at          TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (target_ip),
    KEY idx_state (state),
    CONSTRAINT fk_health_policy FOREIGN KEY (policy_id) REFERENCES probe_policies (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Current zone usage state from usage analytics. zone_id -> pdns.domains.id (logical ref).
CREATE TABLE IF NOT EXISTS zone_lifecycle (
    zone_id       INT UNSIGNED NOT NULL,
    usage_state   ENUM('ACTIVE','LOW_USAGE','DORMANT','STALE_CANDIDATE','PROTECTED') NOT NULL DEFAULT 'ACTIVE',
    queries_24h   BIGINT UNSIGNED DEFAULT NULL,
    queries_30d   BIGINT UNSIGNED DEFAULT NULL,
    last_query_at DATETIME     DEFAULT NULL,
    protected     TINYINT(1)   NOT NULL DEFAULT 0,
    owner         VARCHAR(128) DEFAULT NULL,
    updated_at    TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (zone_id),
    KEY idx_usage (usage_state)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Known health-check/monitoring sources (Zabbix etc.), excluded from TOP/QPS
CREATE TABLE IF NOT EXISTS monitoring_sources (
    id      INT UNSIGNED NOT NULL AUTO_INCREMENT,
    cidr    VARCHAR(64)  NOT NULL,     -- IP or CIDR
    label   VARCHAR(64)  DEFAULT NULL, -- 'zabbix', 'healthcheck', ...
    exclude TINYINT(1)   NOT NULL DEFAULT 1,
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Durable zone sync status with PowerDNS: an honest trace when SQL succeeded but activation/deactivation
-- in PowerDNS did not, so the background worker (or an operator) can retry.
-- pdns_state: active / pending_transfer / transfer_problem / activation_failed / removed /
-- deactivation_failed / still_served / orphaned. notify_state: notified / notify_failed / not_attempted /
-- not_applicable (NATIVE/SLAVE: we send no NOTIFY). attempts = CONSECUTIVE failures (0 on success).
-- next_retry_at = when the worker retries (NULL = healthy). See functions.pm
-- (zone_activate/zone_deactivate/retry_zone_activation) and the dns-sync-worker daemon (libexec/sync-task.pl).
CREATE TABLE IF NOT EXISTS zone_sync_state (
    zone_name       VARCHAR(255) NOT NULL,
    pdns_state      VARCHAR(32)  NOT NULL DEFAULT 'unknown',
    -- Desired operation: activate (zone must be served) | deactivate (after deletion, must NOT be).
    -- Selects the worker path: activate -> verify+notify, deactivate -> verify-not-served.
    operation       VARCHAR(16)  NOT NULL DEFAULT 'activate',
    notify_state    VARCHAR(32)  DEFAULT NULL,
    last_detail     VARCHAR(512) DEFAULT NULL,
    attempts        INT UNSIGNED NOT NULL DEFAULT 0,
    -- State version (CAS), bumped on EVERY write. The worker takes a job with its version, re-reads after
    -- GET_LOCK and writes the result conditionally on the version, so concurrent zone create/delete wins.
    state_version   BIGINT UNSIGNED NOT NULL DEFAULT 0,
    last_attempt_at TIMESTAMP    NULL DEFAULT NULL,
    next_retry_at   TIMESTAMP    NULL DEFAULT NULL,
    -- When a SLAVE first entered pending_transfer; no AXFR before the timeout -> transfer_problem.
    pending_since   TIMESTAMP    NULL DEFAULT NULL,
    updated_at      TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (zone_name),
    KEY idx_state (pdns_state),
    KEY idx_retry (next_retry_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Labels: panel-only zone classification (PowerDNS knows nothing about them, no effect on DNS).
-- Categories (single|multiple) -> values -> zone assignments (M:N). Managed in Settings -> Labels.
CREATE TABLE IF NOT EXISTS label_categories (
    id          INT UNSIGNED NOT NULL AUTO_INCREMENT,
    name        VARCHAR(64)  NOT NULL,
    slug        VARCHAR(64)  NOT NULL,
    cardinality ENUM('single','multiple') NOT NULL DEFAULT 'multiple',
    sort_order  INT NOT NULL DEFAULT 0,
    enabled     TINYINT(1) NOT NULL DEFAULT 1,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_slug (slug)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS label_values (
    id          INT UNSIGNED NOT NULL AUTO_INCREMENT,
    category_id INT UNSIGNED NOT NULL,
    name        VARCHAR(96)  NOT NULL,
    color       VARCHAR(16)  DEFAULT NULL,
    sort_order  INT NOT NULL DEFAULT 0,
    enabled     TINYINT(1) NOT NULL DEFAULT 1,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_cat_name (category_id, name),
    KEY idx_cat (category_id),
    CONSTRAINT fk_lv_cat FOREIGN KEY (category_id) REFERENCES label_categories(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- domain_id -> pdns.domains.id (cross-DB, no FK; the panel cleans up on zone deletion).
CREATE TABLE IF NOT EXISTS zone_labels (
    domain_id      INT UNSIGNED NOT NULL,
    label_value_id INT UNSIGNED NOT NULL,
    created_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by     VARCHAR(64) DEFAULT NULL,
    PRIMARY KEY (domain_id, label_value_id),
    KEY idx_value (label_value_id),
    CONSTRAINT fk_zl_val FOREIGN KEY (label_value_id) REFERENCES label_values(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------------------------------------------------------------
-- NS Pulse: testers (agents), their groups, checks and record switching rules. See docs/25-ns-pulse.md.
-- ---------------------------------------------------------------------------

-- Pulse server certificate. Stored HERE rather than as a file on the node because the server listens on
-- a service address that moves between the pair's nodes while agents pin the fingerprint; a per-node
-- certificate would make a planned role switch look like server impersonation. dns_panel is replicated,
-- so both nodes present the same one. The active node generates it (the standby is read_only=1); one row.
CREATE TABLE IF NOT EXISTS pulse_server_tls (
    id          TINYINT UNSIGNED NOT NULL DEFAULT 1,
    cert_pem    TEXT         NOT NULL,
    key_pem     TEXT         NOT NULL,          -- sensitive: never returned, like a TSIG secret
    fingerprint CHAR(64)     NOT NULL,          -- SHA-256 of the DER certificate; shown to humans
    created_at  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    CONSTRAINT chk_pulse_tls_single CHECK (id = 1)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Testers. location = where we check FROM (a machine property). Current agent state lives HERE, history
-- in pulse_tester_intervals, which holds only closed intervals, so "two open intervals" cannot exist.
CREATE TABLE IF NOT EXISTS pulse_testers (
    id            INT UNSIGNED NOT NULL AUTO_INCREMENT,
    -- Name and location are given by a HUMAN on approval. Until then the row is a request, not a tester.
    name          VARCHAR(64)  DEFAULT NULL,
    location      VARCHAR(64)  DEFAULT NULL,
    -- The agent generates its own key on first start and keeps it; only its SHA-256 is stored here.
    -- So the config file is identical on all machines: it holds no per-machine secret.
    key_hash      CHAR(64)     NOT NULL,
    hostname      VARCHAR(128) DEFAULT NULL,          -- the machine's self-reported name, used to recognize it
    -- NULL = awaiting approval: such an agent gets no jobs and writes no results.
    approved_at   DATETIME     DEFAULT NULL,
    enabled       TINYINT(1)   NOT NULL DEFAULT 1,
    -- How long a work confirmation stays fresh. A silent agent means unknown for its checks, not failure
    -- of the checked hosts.
    confirm_max_age_seconds INT UNSIGNED NOT NULL DEFAULT 90,
    -- Verified OUTBOUND reachability, not "kernel has IPv6": the slow sweep hands AAAA only to such agents,
    -- and if there are none, AAAA stays unknown (§7).
    can_ipv4        TINYINT(1) NOT NULL DEFAULT 1,
    can_ipv6        TINYINT(1) NOT NULL DEFAULT 0,
    -- disabled is not silent: the OPERATOR stopped observation. Without a third state the card would
    -- claim "online" after re-enabling, and the timeline would stretch the old online across the outage.
    state         ENUM('online','silent','disabled') NOT NULL DEFAULT 'silent',
    state_since   DATETIME     DEFAULT NULL,
    last_seen_at  DATETIME     DEFAULT NULL,          -- had a connection
    last_confirm_at DATETIME   DEFAULT NULL,          -- confirmed EXECUTING jobs
    addr          VARCHAR(64)  DEFAULT NULL,
    agent_version VARCHAR(32)  DEFAULT NULL,
    created_at    TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uniq_pulse_tester_name (name),
    UNIQUE KEY uniq_pulse_tester_key (key_hash)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Agent enrollment key: one per pair and IDENTICAL in all agents, so the config file can be baked into
-- an image or distributed by config management without a per-machine secret.
-- Stored in PLAIN TEXT on purpose, unlike passwords and agent keys: it is shown again every time another
-- machine is added, and a hash would mean "see it once". It grants exactly one thing: appearing in the
-- pending list. No jobs and no result writes until a human approves.
CREATE TABLE IF NOT EXISTS pulse_enrollment (
    id         TINYINT UNSIGNED NOT NULL DEFAULT 1,
    enroll_key VARCHAR(64)  NOT NULL,
    created_at TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    CONSTRAINT chk_pulse_enroll_single CHECK (id = 1)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
-- Created WITH the schema: otherwise the first page read would be a write, and the standby is read-only.
INSERT IGNORE INTO pulse_enrollment (id, enroll_key)
VALUES (1, SUBSTRING(SHA2(CONCAT(UUID(), RAND(), NOW(6)), 256), 1, 40));

-- Tester groups: "who checks". Not the same as a location or a view: an agent may be in several groups.
CREATE TABLE IF NOT EXISTS pulse_groups (
    id          INT UNSIGNED NOT NULL AUTO_INCREMENT,
    name        VARCHAR(64)  NOT NULL,
    description VARCHAR(255) DEFAULT NULL,
    created_at  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uniq_pulse_group_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS pulse_group_members (
    group_id  INT UNSIGNED NOT NULL,
    tester_id INT UNSIGNED NOT NULL,
    PRIMARY KEY (group_id, tester_id),
    KEY idx_pgm_tester (tester_id),
    CONSTRAINT fk_pgm_group  FOREIGN KEY (group_id)  REFERENCES pulse_groups  (id) ON DELETE CASCADE,
    CONSTRAINT fk_pgm_tester FOREIGN KEY (tester_id) REFERENCES pulse_testers (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Checks target a CONCRETE address, not the switched name: checking by name would, after the first
-- switch, check a different host and confirm itself.
--
-- config_version is the MEASUREMENT version. It grows only when WHAT is measured changes: probe kind,
-- address, port, interval, limits, thresholds; a result of an older version is not evidence.
-- It does NOT grow on rename, on enabled (that is "no observation", i.e. unknown/disabled), or on a
-- change of executors: the other agents' results stay valid. Executors are a set of PAIRS living in
-- pulse_results rows, not in the version.
CREATE TABLE IF NOT EXISTS pulse_checks (
    id               INT UNSIGNED NOT NULL AUTO_INCREMENT,
    name             VARCHAR(64)  NOT NULL,
    kind             ENUM('icmp','tcp') NOT NULL,
    target_ip        VARCHAR(45)  NOT NULL,
    port             SMALLINT UNSIGNED DEFAULT NULL,  -- tcp only
    interval_seconds INT UNSIGNED NOT NULL DEFAULT 5,
    timeout_ms       INT UNSIGNED NOT NULL DEFAULT 1000,
    -- One attempt = probes_per_run probes; it succeeds if at least ok_probes_required answered.
    -- Hence "degraded": some probes were lost but the attempt still succeeded.
    probes_per_run     TINYINT UNSIGNED NOT NULL DEFAULT 3,
    ok_probes_required TINYINT UNSIGNED NOT NULL DEFAULT 1,
    fail_threshold   TINYINT UNSIGNED NOT NULL DEFAULT 3,   -- consecutive failed attempts -> down
    ok_threshold     TINYINT UNSIGNED NOT NULL DEFAULT 3,   -- consecutive successes -> healthy
    enabled          TINYINT(1)   NOT NULL DEFAULT 1,
    config_version   INT UNSIGNED NOT NULL DEFAULT 1,
    created_at       TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uniq_pulse_check_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS pulse_check_groups (
    check_id INT UNSIGNED NOT NULL,
    group_id INT UNSIGNED NOT NULL,
    PRIMARY KEY (check_id, group_id),
    KEY idx_pcg_group (group_id),
    CONSTRAINT fk_pcg_check FOREIGN KEY (check_id) REFERENCES pulse_checks (id) ON DELETE CASCADE,
    CONSTRAINT fk_pcg_group FOREIGN KEY (group_id) REFERENCES pulse_groups (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- pulse_results — CURRENT state of each (check x tester) pair; decisions are made from it.
-- unknown_reason: different reasons, one state. Otherwise the decision logic would have to enumerate them
-- all, and the first forgotten value would read as "not unknown, so proven".
CREATE TABLE IF NOT EXISTS pulse_results (
    check_id       INT UNSIGNED NOT NULL,
    tester_id      INT UNSIGNED NOT NULL,
    state          ENUM('healthy','degraded','down','unknown') NOT NULL DEFAULT 'unknown',
    -- disabled: the OPERATOR stopped observation (tester or check turned off). Decision logic looks at
    -- state, not reason, so this costs nothing there; on the card "operator disabled" vs "agent gone" is
    -- visible at once, and they are fixed differently.
    unknown_reason ENUM('silent','no_result_yet','stale_config','disabled') DEFAULT 'no_result_yet',
    since          DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,   -- start of the CURRENT segment
    -- No copy of the job version here on purpose: the version lives on the check and is compared under
    -- the same lock that writes the result. A copy had no reader and silently drifted from the truth.
    last_ok_at     DATETIME     DEFAULT NULL,
    last_fail_at   DATETIME     DEFAULT NULL,
    last_report_at DATETIME     DEFAULT NULL,                        -- when the last RESULT arrived
    -- Freshness is PER JOB, not per agent: §3 requires telling "agent alive" from "this check runs",
    -- otherwise a stuck check would look fresh while the agent confirms the others. Both a result for this
    -- check and a confirmation listing the jobs move it. NULL = never confirmed (unknown/no_result_yet),
    -- nothing to close in history.
    confirmed_at   DATETIME     DEFAULT NULL,
    detail         VARCHAR(255) DEFAULT NULL,
    PRIMARY KEY (check_id, tester_id),
    KEY idx_pr_tester (tester_id),
    CONSTRAINT fk_pr_check  FOREIGN KEY (check_id)  REFERENCES pulse_checks  (id) ON DELETE CASCADE,
    CONSTRAINT fk_pr_tester FOREIGN KEY (tester_id) REFERENCES pulse_testers (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- History holds only CLOSED segments; the current one is in pulse_results (state + since). So "two open
-- intervals" cannot exist: MariaDB NULLs don't conflict in UNIQUE, and a race would silently leave two
-- open rows.
CREATE TABLE IF NOT EXISTS pulse_intervals (
    id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    check_id   INT UNSIGNED NOT NULL,
    tester_id  INT UNSIGNED NOT NULL,
    state      ENUM('healthy','degraded','down','unknown') NOT NULL,
    started_at DATETIME NOT NULL,
    ended_at   DATETIME NOT NULL,
    PRIMARY KEY (id),
    KEY idx_pi_span (check_id, tester_id, started_at),
    CONSTRAINT fk_pi_check  FOREIGN KEY (check_id)  REFERENCES pulse_checks  (id) ON DELETE CASCADE,
    CONSTRAINT fk_pi_tester FOREIGN KEY (tester_id) REFERENCES pulse_testers (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- The agent's own timeline: connected/silent is a SEPARATE question from host state.
CREATE TABLE IF NOT EXISTS pulse_tester_intervals (
    id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    tester_id  INT UNSIGNED NOT NULL,
    state      ENUM('online','silent','disabled') NOT NULL,
    started_at DATETIME NOT NULL,
    ended_at   DATETIME NOT NULL,
    PRIMARY KEY (id),
    KEY idx_pti_span (tester_id, started_at),
    CONSTRAINT fk_pti_tester FOREIGN KEY (tester_id) REFERENCES pulse_testers (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Rules belong to an existing RRset (name + type), not to a single row or address: Pulse knows that for
-- "www.example.com / MX" a given SET of values must be published now. domain_id -> pdns.domains.id
-- (logical ref, other DB). One RRset has exactly one rule, enforced by a UNIQUE key. Content is validated
-- by the same panel code as ordinary records.
-- Types: ordinary managed RRsets. SOA, DNSSEC and catalog internals are excluded.
CREATE TABLE IF NOT EXISTS pulse_rules (
    id                   INT UNSIGNED NOT NULL AUTO_INCREMENT,
    domain_id            INT UNSIGNED NOT NULL,
    rr_name              VARCHAR(255) NOT NULL,
    rr_type              ENUM('A','AAAA','CNAME','MX','NS','SRV','TXT') NOT NULL,
    ttl                  INT UNSIGNED NOT NULL DEFAULT 300,
    default_hold_seconds INT UNSIGNED NOT NULL DEFAULT 300,   -- hold before returning to the default set
    schedule_tz          VARCHAR(64)  NOT NULL DEFAULT 'UTC', -- schedule time zone, one per rule
    enabled              TINYINT(1)   NOT NULL DEFAULT 0,     -- created disabled: review first
    -- The set is default, switched by a branch, or held by a human; which branch is in active_branch_id
    -- (shown as "Rule 2"), since with several branches "switched" alone answers nothing.
    state                ENUM('default','switched','held') NOT NULL DEFAULT 'default',
    active_branch_id     INT UNSIGNED DEFAULT NULL,   -- branch currently holding the set
    last_switch_at       DATETIME     DEFAULT NULL,
    last_reason          VARCHAR(255) DEFAULT NULL,
    created_at           TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uniq_pulse_rule_rrset (domain_id, rr_name, rr_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Set values for the default set and for each branch. branch_id IS NULL = the default set: what was in
-- the zone when the rule was created and where the rule returns to.
-- published = 1 on the set Pulse last published, to detect edits made outside Pulse.
CREATE TABLE IF NOT EXISTS pulse_rrset_values (
    id        INT UNSIGNED NOT NULL AUTO_INCREMENT,
    rule_id   INT UNSIGNED NOT NULL,
    branch_id INT UNSIGNED DEFAULT NULL,
    position  SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    -- TEXT, not VARCHAR: a long TXT must fit, as in the zone itself.
    content   TEXT         NOT NULL,
    -- MX/SRV priority is a separate column, as elsewhere in the panel; gluing it into the string would
    -- create a second format for the same thing.
    prio      INT UNSIGNED DEFAULT NULL,
    published TINYINT(1)   NOT NULL DEFAULT 0,
    PRIMARY KEY (id),
    KEY idx_prv_rule (rule_id, branch_id, position),
    CONSTRAINT fk_prv_rule FOREIGN KEY (rule_id) REFERENCES pulse_rules (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Branches: order is BEHAVIOUR. The first satisfied branch from the top wins and overrides those below.
-- What a satisfied branch publishes lives in pulse_rrset_values (a set, not a single value).
CREATE TABLE IF NOT EXISTS pulse_branches (
    id            INT UNSIGNED NOT NULL AUTO_INCREMENT,
    rule_id       INT UNSIGNED NOT NULL,
    position      SMALLINT UNSIGNED NOT NULL,
    match_mode    ENUM('any','all') NOT NULL DEFAULT 'any',
    hold_seconds  INT UNSIGNED NOT NULL DEFAULT 30,
    PRIMARY KEY (id),
    UNIQUE KEY uniq_pb_pos (rule_id, position),
    CONSTRAINT fk_pb_rule FOREIGN KEY (rule_id) REFERENCES pulse_rules (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Extra check executors named per agent, besides groups: creating a group for a single observer is
-- ceremony. Executors of a check = agents of its groups UNION these, deduplicated.
CREATE TABLE IF NOT EXISTS pulse_check_agents (
    check_id  INT UNSIGNED NOT NULL,
    tester_id INT UNSIGNED NOT NULL,
    PRIMARY KEY (check_id, tester_id),
    KEY idx_pca_tester (tester_id),
    CONSTRAINT fk_pca_check  FOREIGN KEY (check_id)  REFERENCES pulse_checks  (id) ON DELETE CASCADE,
    CONSTRAINT fk_pca_tester FOREIGN KEY (tester_id) REFERENCES pulse_testers (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Conditions of two kinds (check | schedule). The expected state is chosen EXPLICITLY
-- (available|degraded|unavailable): there is no logical NOT, because with four states "not available"
-- would include unknown, which must not switch anything.
CREATE TABLE IF NOT EXISTS pulse_conditions (
    id         INT UNSIGNED NOT NULL AUTO_INCREMENT,
    branch_id  INT UNSIGNED NOT NULL,
    position   SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    kind       ENUM('check','schedule') NOT NULL DEFAULT 'check',
    check_id   INT UNSIGNED DEFAULT NULL,
    expect     ENUM('available','degraded','unavailable') DEFAULT NULL,
    -- A condition is ONE check across ANY number of agents, not a (check x agent) pair; pairs turned one
    -- check on twenty sites into twenty conditions. agg says what the condition means across agents:
    -- any = one is enough, all = every one, at_least = agg_n of them. The branch's any/all combines
    -- DIFFERENT conditions (e.g. a check with a schedule), not answers of one check from several observers.
    agg        ENUM('any','all','at_least') NOT NULL DEFAULT 'any',
    agg_n      SMALLINT UNSIGNED NOT NULL DEFAULT 1,   -- for at_least
    days_mask  TINYINT UNSIGNED DEFAULT NULL,   -- bits 0..6 = Mon..Sun; NULL = any day
    time_from  TIME     DEFAULT NULL,           -- may wrap past midnight (22:00-06:00)
    time_to    TIME     DEFAULT NULL,
    date_from  DATE     DEFAULT NULL,
    date_to    DATE     DEFAULT NULL,
    PRIMARY KEY (id),
    KEY idx_pc_branch (branch_id, position),
    CONSTRAINT fk_pc_branch FOREIGN KEY (branch_id) REFERENCES pulse_branches (id) ON DELETE CASCADE,
    CONSTRAINT fk_pc_check  FOREIGN KEY (check_id)  REFERENCES pulse_checks   (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Observers of a condition = ALL executors of its check; there is deliberately no separate "which of them
-- we listen to" set. Rows are rebuilt whenever the check's assignment or its groups change; the evaluator
-- reads only these. Deleting an agent removes only its row, not the whole condition (a branch must not
-- empty out because one agent of twenty was deleted).
CREATE TABLE IF NOT EXISTS pulse_condition_testers (
    condition_id INT UNSIGNED NOT NULL,
    tester_id    INT UNSIGNED NOT NULL,
    PRIMARY KEY (condition_id, tester_id),
    KEY idx_pct_tester (tester_id),
    CONSTRAINT fk_pct_cond   FOREIGN KEY (condition_id) REFERENCES pulse_conditions (id) ON DELETE CASCADE,
    CONSTRAINT fk_pct_tester FOREIGN KEY (tester_id)    REFERENCES pulse_testers    (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- What Pulse changed and why. Separate from the general audit: the history of ONE record, shown next to it.
CREATE TABLE IF NOT EXISTS pulse_rule_events (
    id        BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    rule_id   INT UNSIGNED NOT NULL,
    at        DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- Snapshot of the SET before/after, not an address: MX, NS, SRV have no addresses at all.
    from_set  TEXT         DEFAULT NULL,
    to_set    TEXT         DEFAULT NULL,
    branch_id INT UNSIGNED DEFAULT NULL,
    reason    VARCHAR(255) DEFAULT NULL,
    actor     VARCHAR(128) DEFAULT NULL,        -- 'pulse' or a user name (manual return)
    PRIMARY KEY (id),
    KEY idx_pre_rule (rule_id, at),
    CONSTRAINT fk_pre_rule FOREIGN KEY (rule_id) REFERENCES pulse_rules (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Which CHECKS the rule consulted at event time. "Why did it switch" must answer as of THEN: the rule may
-- later be pointed at another check, and the timeline marks would move to the wrong one or vanish.
CREATE TABLE IF NOT EXISTS pulse_rule_event_checks (
    event_id BIGINT UNSIGNED NOT NULL,
    check_id INT UNSIGNED NOT NULL,
    PRIMARY KEY (event_id, check_id),
    KEY idx_prec_check (check_id),
    CONSTRAINT fk_prec_event FOREIGN KEY (event_id) REFERENCES pulse_rule_events (id) ON DELETE CASCADE,
    CONSTRAINT fk_prec_check FOREIGN KEY (check_id) REFERENCES pulse_checks      (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Slow sweep: a shared queue with time-limited leases. Key = address WITHIN a network scope.
CREATE TABLE IF NOT EXISTS pulse_sweep_targets (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    target_ip       VARCHAR(45)  NOT NULL,
    net_scope       VARCHAR(64)  NOT NULL DEFAULT 'default',
    -- A goes to IPv4 agents, AAAA only to agents that actually reach IPv6. With no suitable agent the target
    -- stays unknown, not "unavailable" (§7).
    family          ENUM('ipv4','ipv6') NOT NULL DEFAULT 'ipv4',
    last_checked_at DATETIME     DEFAULT NULL,
    last_checked_by INT UNSIGNED DEFAULT NULL,
    state_since     DATETIME     DEFAULT NULL,
    -- Since when no record references the address. The target is NOT deleted: an IP removed and restored a
    -- week later continues the same history. Such targets are not handed to agents; retention cleanup
    -- deletes them.
    unref_at        DATETIME     DEFAULT NULL,
    -- No voting in the sweep: ONE collector checks a target per cycle, so this is just the last answer.
    last_state      ENUM('available','unavailable','unknown') NOT NULL DEFAULT 'unknown',
    -- Lease: who holds the target and until when. The lease generation fences off late answers from an
    -- agent that hung and came back after its lease expired and was reissued. An answer is accepted only
    -- if both holder AND generation match, otherwise a stale "unavailable" could overwrite a fresh
    -- "available" and show an outage that is already over.
    leased_by       INT UNSIGNED DEFAULT NULL,
    leased_until    DATETIME     DEFAULT NULL,
    lease_generation INT UNSIGNED NOT NULL DEFAULT 0,
    PRIMARY KEY (id),
    UNIQUE KEY uniq_pst_target (target_ip, net_scope),
    KEY idx_pst_queue (net_scope, last_checked_at),
    KEY idx_pst_lease (unref_at, family, leased_until, last_checked_at),
    CONSTRAINT fk_pst_tester FOREIGN KEY (leased_by) REFERENCES pulse_testers (id) ON DELETE SET NULL,
    CONSTRAINT fk_pst_by     FOREIGN KEY (last_checked_by) REFERENCES pulse_testers (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
-- A zone whose sweep targets could not be rebuilt. The "address appeared/disappeared" event arrives once
-- and must not be swallowed: DNS has already changed, and the sweep would not learn of the address until
-- the next edit of this zone. The row lives until a rebuild succeeds and is picked up by the retry.
CREATE TABLE IF NOT EXISTS pulse_sweep_dirty (
    domain_id INT UNSIGNED NOT NULL,          -- no FK: zones are in another DB (pdns)
    since     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- Stores the FACT (event lost) and the failure count shown to humans. No retry schedule here: the
    -- handler already has its own backoff for event retries, and a second one would diverge.
    attempts   INT UNSIGNED NOT NULL DEFAULT 0,
    last_error VARCHAR(255) DEFAULT NULL,
    PRIMARY KEY (domain_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Slow sweep (§7): WHO referenced an address and WHEN. A reference is an INTERVAL, not a fact: addresses
-- move between records, and "when it belonged to this record" differs from "when it was unavailable".
-- Without intervals, the Pinger tab of test1 would show an outage that happened after the address moved
-- to test2. Rows are never deleted: deleting a record is a history event, not an erase command.
CREATE TABLE IF NOT EXISTS pulse_sweep_refs (
    id        BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    target_id BIGINT UNSIGNED NOT NULL,
    domain_id INT UNSIGNED    NOT NULL,      -- no FK: zones live in another DB (pdns)
    rr_name   VARCHAR(255)    NOT NULL,
    rr_type   VARCHAR(10)     NOT NULL,
    since     DATETIME NOT NULL,
    until     DATETIME DEFAULT NULL,          -- NULL = the address is still in this record
    PRIMARY KEY (id),
    KEY idx_psr_open (domain_id, until),
    KEY idx_psr_rrset (domain_id, rr_name, rr_type, since),
    KEY idx_psr_target (target_id, since),
    CONSTRAINT fk_psr_target FOREIGN KEY (target_id) REFERENCES pulse_sweep_targets (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Sweep history: closed state intervals of an address, same idea as check intervals (§4.1).
CREATE TABLE IF NOT EXISTS pulse_sweep_intervals (
    id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    target_id  BIGINT UNSIGNED NOT NULL,
    state      ENUM('available','unavailable','unknown') NOT NULL,
    started_at DATETIME NOT NULL,
    ended_at   DATETIME NOT NULL,
    -- Who CLOSED the interval, i.e. saw the change; the target stores only the last checker.
    -- NULL = closed by the panel (address left the zone), rather than blaming an agent.
    ended_by   INT UNSIGNED DEFAULT NULL,
    PRIMARY KEY (id),
    KEY idx_psi_target (target_id, started_at),
    CONSTRAINT fk_psi_target FOREIGN KEY (target_id) REFERENCES pulse_sweep_targets (id) ON DELETE CASCADE,
    CONSTRAINT fk_psi_by FOREIGN KEY (ended_by) REFERENCES pulse_testers (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================================
-- MIGRATION FROM AN OLD BIND (docs/26)
-- A parsed `named-checkconf -p` is loaded ONCE and then lives as a list: it gets enriched (serial,
-- record count), filtered and imported from, in as many batches as needed. Reloading an export of the
-- same master updates rows by name.
-- ============================================================================
CREATE TABLE IF NOT EXISTS import_sources (
    id          INT UNSIGNED NOT NULL AUTO_INCREMENT,
    master      VARCHAR(64)  NOT NULL,                 -- old DNS address, also the key (one server, one list)
    zone_count  INT UNSIGNED NOT NULL DEFAULT 0,
    file_hash   CHAR(64)     DEFAULT NULL,             -- sha256 of the loaded export: same file or new
    loaded_at   TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    probe_tsig  VARCHAR(255) DEFAULT NULL,             -- probe key (name in PowerDNS), NULL = unsigned
    updated_at  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_is_master (master)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- One row per zone of the old server. Columns hold what is filtered and decided on; everything else
-- parsed (ACL, also-notify, forwarders, keys, unknown directives) goes to config_json for human review.
CREATE TABLE IF NOT EXISTS import_zones (
    id                  INT UNSIGNED NOT NULL AUTO_INCREMENT,
    source_id           INT UNSIGNED NOT NULL,
    zone_name           VARCHAR(255) NOT NULL,
    source_type         VARCHAR(32)  NOT NULL DEFAULT '',   -- master|slave|forward|hint... as written in the config
    source_master       VARCHAR(255) NOT NULL DEFAULT '',   -- for a slave zone: where the OLD server itself gets it
    dynamic             TINYINT(1)   NOT NULL DEFAULT 0,    -- allow-update / update-policy
    needs_review        TINYINT(1)   NOT NULL DEFAULT 0,    -- unknown directives, forwarders, two views
    -- Filled only once the old server is probed (SOA/AXFR). NULL = "not asked", not zero.
    source_serial       VARCHAR(32)  DEFAULT NULL,
    source_record_count INT UNSIGNED DEFAULT NULL,
    probed_at           TIMESTAMP    NULL DEFAULT NULL,
    probe_state         ENUM('queued','ok','failed') NULL,   -- probe of the old server: waiting for worker / ok / failed
    probe_error         VARCHAR(255) NULL,                  -- why it failed (REFUSED, SERVFAIL, no answer)
    -- Our side. panel_zone_id is set only when THIS migration created the zone; a pre-existing zone stays
    -- NULL, which tells "I migrated it" from "it was already here".
    panel_zone_id       INT UNSIGNED DEFAULT NULL,
    status              ENUM('pending','imported','reviewed','failed') NOT NULL DEFAULT 'pending',
    note                VARCHAR(255) DEFAULT NULL,          -- failure reason or a human note
    imported_at         TIMESTAMP    NULL DEFAULT NULL,
    config_hash         CHAR(64)     NOT NULL DEFAULT '',   -- detects a changed zone block on reload
    config_json         MEDIUMTEXT   DEFAULT NULL,
    last_seen_at        TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- What the LAST config load brought: otherwise "one more zone" is visible but not which one.
    -- Reset at the start of each load of this source.
    new_in_last_load     TINYINT(1) NOT NULL DEFAULT 0,
    changed_in_last_load TINYINT(1) NOT NULL DEFAULT 0,
    PRIMARY KEY (id),
    UNIQUE KEY uq_iz_zone (source_id, zone_name),
    KEY idx_iz_status (source_id, status),
    KEY idx_iz_probe (probe_state),
    CONSTRAINT fk_iz_source FOREIGN KEY (source_id) REFERENCES import_sources (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
