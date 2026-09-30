-- dns_ha is the LOCAL database of the HA layer. One per node, NOT replicated (binlog-ignore-db/replicate-ignore-db).
--
-- Why not in the shared replicated database: HA must work exactly when replication is broken or the node is
-- read-only. State that HA writes about replication itself cannot travel through that same replication; that is
-- the whole class of mutual deadlocks this database was split out to avoid.
--
-- What IS here:
--   CONFIG      pair configuration revisions (identical on both nodes, compared by fingerprint);
--   OPERATIONS  durable journal of operations (switchover, emergency, reseed) and their steps;
--   STATE       a PROJECTION of observed state for the panel, so it does not depend on the daemon;
--   LEDGER      deduplication of mutating peer messages.
--
-- What is NOT here and must not be: any safety authority. The right to be ACTIVE, the max seen epoch, fencing and
-- the config commit proof live in the on-disk safety file (§4.4.1), which must be readable when MariaDB is down.
--
-- Losing THIS database is a factory reset of the local control plane: the node gets a new UUID, no longer
-- recognizes itself in the safety file and refuses to act until the pair is recreated. A visible, safe
-- failure, not a silent identity swap.
--
-- The manager deploys the schema itself on first start; the database and its grants are the installer's job:
--   CREATE DATABASE dns_ha; GRANT ALL ON dns_ha.* TO 'dns-ha'@'localhost';
--
-- There is deliberately NO `SET SESSION sql_log_bin = 0`, although this database has no business in the binlog.
-- It requires BINLOG ADMIN, a "may write around the log" privilege, and granting it to a network-facing process
-- as insurance for something node config already guarantees is a bad deal. The guarantee: `binlog_ignore_db =
-- dns_ha` and `replicate_ignore_db = dns_ha` are in the MariaDB config the product installs. One mechanism
-- instead of two, and the one that survives restarts.

CREATE TABLE IF NOT EXISTS ha_schema (
    schema_version INT UNSIGNED NOT NULL,
    applied_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (schema_version)
) ENGINE=InnoDB;
INSERT IGNORE INTO ha_schema (schema_version) VALUES (1);

-- Identity and trust.
--
-- Node identity and its trusted peer live HERE, not in separate files: the database is local and non-replicated,
-- exactly what it exists for. Two files remain in var/, each for an objective reason: the safety store is read
-- when MariaDB is down, and the root agent state must survive an unavailable or compromised database.

CREATE TABLE IF NOT EXISTS ha_identity (
    -- Exactly one row. The UUID is issued once on first start and never changes: peer message signing,
    -- safety, fencing, handoff and the operation journal depend on it.
    only_row  TINYINT UNSIGNED NOT NULL DEFAULT 1,
    node_id   CHAR(36) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (only_row),
    CONSTRAINT ck_identity_single CHECK (only_row = 1)
) ENGINE=InnoDB;

-- Trusted peer: the result of pairing (§14.5). The relation "we trust THIS node", not pair configuration: the
-- address here is only for bootstrap, the first connection. Once an effective revision exists addresses come
-- from it: two address sources would one day diverge.
CREATE TABLE IF NOT EXISTS ha_trusted_peer (
    only_row      TINYINT UNSIGNED NOT NULL DEFAULT 1,
    -- States exist ONLY after admin approval: before that pairing lives in manager memory and vanishes on
    -- restart. committing: the key is being derived and installed on both sides.
    state         ENUM('committing','trusted') NOT NULL,
    pairing_id    CHAR(36)     NOT NULL,
    peer_node_id  CHAR(36)     NOT NULL,
    peer_endpoint VARCHAR(128) NOT NULL,   -- host:port for the FIRST connection; afterwards from the revision
    key_fp        CHAR(64)     NOT NULL,   -- shared secret fingerprint: confirms both sides hold the same key
    -- The transcript lets an interrupted pairing be COMPLETED after a restart: ephemeral keys live only in
    -- memory, while completion is signed with the permanent key over this same transcript.
    transcript_fp CHAR(64)     NOT NULL,
    approved_by   VARCHAR(64)  DEFAULT NULL,
    approved_at   TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (only_row),
    CONSTRAINT ck_trust_single CHECK (only_row = 1)
) ENGINE=InnoDB;

-- Config.
--
-- A revision is the pair's AGREEMENT, not a local setting. The sides compare not table contents but a
-- fingerprint of canonical bytes: the same payload_hash on both nodes is what "configuration" means.

CREATE TABLE IF NOT EXISTS ha_config_revision (
    revision      BIGINT UNSIGNED NOT NULL,
    status        ENUM('STAGED','EFFECTIVE','REJECTED') NOT NULL,
    payload_hash  CHAR(64)     NOT NULL,
    -- payload_blob holds the CANONICAL bytes payload_hash is computed over, and is the ONLY source of the
    -- manager's working configuration. The tables below are a projection for the panel and SQL; drift from them
    -- shows as config_projection_drift, but the node is driven by the content it vouches for to the peer.
    payload_blob  LONGBLOB     NOT NULL,
    created_by    VARCHAR(64)  DEFAULT NULL,
    created_at    TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    committed_at  DATETIME     DEFAULT NULL,
    PRIMARY KEY (revision),
    KEY idx_status (status, revision)
) ENGINE=InnoDB;

-- peer_listen_* is where the node OF THIS ROW LISTENS (not "the peer address": the old ambiguous name allowed
-- taking one's own address instead of the peer's, which would only surface in production).
-- replication_host is this node's MariaDB address as a replication SOURCE: the source follows the role, and
-- after a switchover replication runs the other way.
CREATE TABLE IF NOT EXISTS ha_nodes (
    revision          BIGINT UNSIGNED NOT NULL,
    -- node_id is the node UUID (local ha_identity). Immutable: safety, peer, fencing and the operation journal
    -- depend on it. All human data is below in the same row: a separate metadata table would be a third place
    -- describing the same node.
    node_id           CHAR(36)     NOT NULL,
    name              VARCHAR(64)  DEFAULT NULL,   -- what the human calls the node; defaults to hostname
    hostname          VARCHAR(255) DEFAULT NULL,   -- snapshot of the observed OS name; NOT identity
    location          VARCHAR(64)  DEFAULT NULL,
    description       VARCHAR(255) DEFAULT NULL,
    admin_ip          VARCHAR(64)  DEFAULT NULL,
    peer_listen_host  VARCHAR(64)  NOT NULL,
    peer_listen_port  INT UNSIGNED NOT NULL,
    replication_host  VARCHAR(64)  DEFAULT NULL,
    enabled           TINYINT(1)   NOT NULL DEFAULT 1,
    PRIMARY KEY (revision, node_id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS ha_settings (
    revision  BIGINT UNSIGNED NOT NULL,
    name      VARCHAR(64)  NOT NULL,
    value     VARCHAR(255) NOT NULL,
    PRIMARY KEY (revision, name)
) ENGINE=InnoDB;

-- The replication secret is NOT stored here, only a reference to a root file: a password in the database ends
-- up in backups, dumps and peer messages along with revision content.
CREATE TABLE IF NOT EXISTS ha_replication (
    revision    BIGINT UNSIGNED NOT NULL,
    port        INT UNSIGNED NOT NULL DEFAULT 3306,
    user        VARCHAR(64)  NOT NULL,
    secret_ref  VARCHAR(255) DEFAULT NULL,
    PRIMARY KEY (revision)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS ha_publication (
    revision  BIGINT UNSIGNED NOT NULL,
    provider  ENUM('marker','floating_ip','anycast','external_health') NOT NULL,
    params    TEXT DEFAULT NULL,
    PRIMARY KEY (revision)
) ENGINE=InnoDB;

-- Operations.
--
-- An operation is an INTENT with a durable trace: who started it, in which epoch, where it is now and how it
-- ended. The panel creates the intent, the manager executes it. The operation ID goes into every agent command,
-- so a retry after a break does not run an action twice.

CREATE TABLE IF NOT EXISTS ha_operations (
    operation_id  VARCHAR(64)  NOT NULL,
    kind          ENUM('planned_switchover','emergency_promote','reseed','bootstrap','dismantle') NOT NULL,
    state         ENUM('PENDING','RUNNING','COMPLETED','FAILED','ABORTED') NOT NULL,
    epoch         BIGINT UNSIGNED NOT NULL,   -- epoch the operation started in
    source_node   VARCHAR(64)  DEFAULT NULL,  -- who hands over the role (or the target node for reseed)
    target_node   VARCHAR(64)  DEFAULT NULL,  -- who takes over the role
    requested_by  VARCHAR(64)  DEFAULT NULL,  -- operator/panel
    -- Basis for emergency promotion: the operator's typed confirmation that the former ACTIVE is down, and
    -- their separate consent to continue if relay-log drain cannot be proven (i.e. with data loss). Stored in
    -- the operation itself: a month later "on what basis did this node become active" must have an answer.
    ack               VARCHAR(64) DEFAULT NULL,
    accept_relay_loss TINYINT(1)  NOT NULL DEFAULT 0,
    reason        TEXT         DEFAULT NULL,  -- rejection reason or operator note
    started_at    TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at   DATETIME     DEFAULT NULL,
    PRIMARY KEY (operation_id),
    KEY idx_state (state, started_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS ha_operation_steps (
    operation_id  VARCHAR(64)  NOT NULL,
    seq           INT UNSIGNED NOT NULL,
    step          VARCHAR(64)  NOT NULL,      -- agent primitive or state machine phase
    node_id       VARCHAR(64)  DEFAULT NULL,  -- where the step ran
    ok            TINYINT(1)   DEFAULT NULL,  -- NULL = still running
    noop          TINYINT(1)   NOT NULL DEFAULT 0,
    state_proven  TINYINT(1)   NOT NULL DEFAULT 0,  -- reply confirmed the node's physical state (see agent durable retry)
    error         VARCHAR(255) DEFAULT NULL,
    detail        TEXT         DEFAULT NULL,
    at            TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (operation_id, seq)
) ENGINE=InnoDB;

-- State (projection).
--
-- Exactly one row: how THIS node saw the world in the last observation cycle. Lets the panel show state with a
-- plain SELECT regardless of whether the daemon is alive and the socket answers.
--
-- It is a PROJECTION, not the source of truth. Decisions use the safety file, physical observation and the
-- peer's reply; this row only relays them, so losing it breaks nothing.
CREATE TABLE IF NOT EXISTS ha_state (
    node_id              VARCHAR(64)  NOT NULL,
    role                 ENUM('active','standby','unknown') NOT NULL DEFAULT 'unknown',
    epoch                BIGINT UNSIGNED DEFAULT NULL,   -- max_seen_epoch from the safety file
    authority            VARCHAR(32)  DEFAULT NULL,      -- state of the right to be ACTIVE
    fenced_node          VARCHAR(64)  DEFAULT NULL,
    current_operation_id VARCHAR(64)  DEFAULT NULL,
    config_revision      BIGINT UNSIGNED DEFAULT NULL,
    config_hash          CHAR(64)     DEFAULT NULL,
    read_only            TINYINT(1)   DEFAULT NULL,
    notifier_on          TINYINT(1)   DEFAULT NULL,
    route_announced      TINYINT(1)   DEFAULT NULL,
    service_ready        TINYINT(1)   DEFAULT NULL,
    ha_healthy           TINYINT(1)   DEFAULT NULL,
    peer_node_id         VARCHAR(64)  DEFAULT NULL,
    peer_role            VARCHAR(16)  DEFAULT NULL,
    peer_reachable       TINYINT(1)   DEFAULT NULL,
    replication_io       VARCHAR(16)  DEFAULT NULL,
    replication_sql      VARCHAR(16)  DEFAULT NULL,
    replication_source   VARCHAR(64)  DEFAULT NULL,
    observed_at          DATETIME     DEFAULT NULL,
    checks               TEXT         DEFAULT NULL,      -- JSON: failed checks with reasons
    PRIMARY KEY (node_id)
) ENGINE=InnoDB;

-- Ledger.
--
-- Deduplication of mutating peer messages. Request registration and the action itself run in ONE transaction,
-- so there is never a state "change applied, request not recorded" after which a retry would run it again.
CREATE TABLE IF NOT EXISTS ha_peer_requests (
    sender_node_id  VARCHAR(64)  NOT NULL,
    message_id      VARCHAR(128) NOT NULL,   -- LOGICAL action ID (survives retries)
    cmd             VARCHAR(64)  NOT NULL,
    epoch           BIGINT NOT NULL,
    request_hash    CHAR(64)     NOT NULL,   -- MEANING fingerprint: same id with different content = conflict
    status          ENUM('IN_PROGRESS','DONE','REJECTED') NOT NULL,
    result_code     VARCHAR(64)  DEFAULT NULL,
    result_payload  BLOB         DEFAULT NULL,
    created_at      TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at    DATETIME     DEFAULT NULL,
    PRIMARY KEY (sender_node_id, message_id),
    KEY idx_created (created_at)
) ENGINE=InnoDB;

-- Amending already created tables.
--
-- The only non-CREATE statement in this file. All tables above use IF NOT EXISTS, so on a node with the
-- database already deployed a column definition change would never reach it: dismantling would get "Data
-- truncated for column 'kind'" on a live pair upgraded without recreating the database.
--
-- The value is appended AT THE END of the enum; MariaDB does that instantly without rewriting the table, so the
-- statement is safe to repeat on every manager start.
ALTER TABLE ha_operations
    MODIFY kind ENUM('planned_switchover','emergency_promote','reseed','bootstrap','dismantle') NOT NULL;
