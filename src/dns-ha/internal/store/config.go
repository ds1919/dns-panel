package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// queryer is the common denominator of *sql.DB and *sql.Tx. Everything below works both inside a transaction
// (opened by the ledger together with request registration) and outside one, for reads.
type queryer interface {
	QueryContext(ctx context.Context, q string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, q string, args ...any) *sql.Row
	ExecContext(ctx context.Context, q string, args ...any) (sql.Result, error)
}

// LoadConfigState reads the current configuration state.
//
// The "effective" revision is the one with the HIGHEST number among EFFECTIVE. Older EFFECTIVE rows are not
// rewritten: they are the commit history, and erasing it for a tidier status would lose the trace of what
// was once in force.
func LoadConfigState(ctx context.Context, q queryer, dbName string) (ConfigState, error) {
	var st ConfigState
	eff, err := loadRevision(ctx, q, dbName, "status='EFFECTIVE' ORDER BY revision DESC")
	if err != nil {
		return st, err
	}
	stg, err := loadRevision(ctx, q, dbName, "status='STAGED' ORDER BY revision DESC")
	if err != nil {
		return st, err
	}
	st.Effective, st.Staged = eff, stg
	// A staged revision not newer than the effective one is debris from a failed attempt: it will never be
	// committed and must not be shown to the rules, or it would block new staging.
	if st.Staged != nil && st.Effective != nil && st.Staged.Revision <= st.Effective.Revision {
		st.Staged = nil
	}
	return st, nil
}

func loadRevision(ctx context.Context, q queryer, dbName, where string) (*RevisionView, error) {
	var v RevisionView
	var blobLen sql.NullInt64
	err := q.QueryRowContext(ctx, "SELECT revision, payload_hash, OCTET_LENGTH(payload_blob) FROM "+
		dbName+".ha_config_revision WHERE "+where+" LIMIT 1").Scan(&v.Revision, &v.PayloadHash, &blobLen)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("config_state_query: %w", err)
	}
	v.HasBlob = blobLen.Valid && blobLen.Int64 > 0
	return &v, nil
}

// LoadRevisionPayload reads a revision's canonical content and verifies its fingerprint.
func LoadRevisionPayload(ctx context.Context, q queryer, dbName string, rev int64) (ConfigPayload, string, error) {
	var blob []byte
	var hash string
	err := q.QueryRowContext(ctx, "SELECT payload_hash, payload_blob FROM "+dbName+
		".ha_config_revision WHERE revision=?", rev).Scan(&hash, &blob)
	if errors.Is(err, sql.ErrNoRows) {
		return ConfigPayload{}, "", fmt.Errorf("config_revision_absent: revision %d does not exist", rev)
	}
	if err != nil {
		return ConfigPayload{}, "", fmt.Errorf("config_payload_query: %w", err)
	}
	p, err := ParseConfigPayload(blob, hash)
	return p, hash, err
}

// StageRevision writes a staged revision IN FULL: canonical bytes and normalized node rows. It runs inside the
// ledger transaction, so either everything appears or nothing does.
func StageRevision(ctx context.Context, tx *sql.Tx, dbName string, rev int64, p ConfigPayload, by string) (Decision, error) {
	if err := p.Validate(); err != nil {
		return reject(CodeRevisionInvalid, err.Error()), nil
	}
	blob, err := p.Canonical()
	if err != nil {
		return Decision{}, err
	}
	hash, err := p.Hash()
	if err != nil {
		return Decision{}, err
	}
	st, err := LoadConfigState(ctx, tx, dbName)
	if err != nil {
		return Decision{}, err
	}
	d := StageDecision(st, rev, hash)
	if d.Action != ActStage {
		return d, nil
	}
	// The pair channel (§7.4) is not changed by a normal revision, and not out of tidiness but to avoid a
	// dead end: the sides apply a revision at different times, and a node that moves to a new address before
	// its peer loses the link, and with it the only way to finish agreeing on that very revision.
	if st.Effective != nil {
		cur, _, err := LoadRevisionPayload(ctx, tx, dbName, st.Effective.Revision)
		if err != nil {
			return Decision{}, err
		}
		if TransportChanged(cur, p) {
			return reject(CodeTransportChange,
				"the peer channel address or port is changed by a separate rotation procedure, not by an ordinary revision"), nil
		}
	}
	// Drop any previous staged revision explicitly: two stagings at once are not allowed, or it is unclear
	// which one the next commit refers to.
	if _, err := tx.ExecContext(ctx, "UPDATE "+dbName+
		".ha_config_revision SET status='REJECTED' WHERE status='STAGED' AND revision<>?", rev); err != nil {
		return Decision{}, fmt.Errorf("config_stage_clear: %w", err)
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM "+dbName+".ha_nodes WHERE revision=?", rev); err != nil {
		return Decision{}, fmt.Errorf("config_stage_nodes_clear: %w", err)
	}
	if _, err := tx.ExecContext(ctx, "REPLACE INTO "+dbName+".ha_config_revision "+
		"(revision, status, payload_hash, payload_blob, created_by) VALUES (?,'STAGED',?,?,?)",
		rev, hash, blob, by); err != nil {
		return Decision{}, fmt.Errorf("config_stage_insert: %w", err)
	}
	if err := writeProjection(ctx, tx, dbName, rev, p); err != nil {
		return Decision{}, err
	}
	return d, nil
}

// writeProjection spreads revision content over the normalized tables for the panel and SQL. The manager is
// not driven by them (see EffectiveConfig), but the UI must not show falsehoods either.
func writeProjection(ctx context.Context, tx *sql.Tx, dbName string, rev int64, p ConfigPayload) error {
	// Clear exactly the tables we fill: touching ones nobody writes to would require them to exist for no
	// reason.
	for _, t := range []string{"ha_nodes", "ha_settings", "ha_replication", "ha_publication"} {
		if _, err := tx.ExecContext(ctx, "DELETE FROM "+dbName+"."+t+" WHERE revision=?", rev); err != nil {
			return fmt.Errorf("config_projection_clear %s: %w", t, err)
		}
	}
	for _, n := range p.Nodes {
		if _, err := tx.ExecContext(ctx, "INSERT INTO "+dbName+".ha_nodes "+
			"(revision, node_id, name, hostname, location, description, admin_ip, "+
			" peer_listen_host, peer_listen_port, replication_host, enabled) "+
			"VALUES (?,?,?,?,?,?,?,?,?,?,?)",
			rev, n.NodeID, nullIfEmpty(n.Name), nullIfEmpty(n.Hostname), nullIfEmpty(n.Location),
			nullIfEmpty(n.Description), n.AdminIP, n.PeerListenHost, n.PeerListenPort,
			nullIfEmpty(n.ReplicationHost), n.Enabled); err != nil {
			return fmt.Errorf("config_projection_node %s: %w", n.NodeID, err)
		}
	}
	for k, v := range p.Settings {
		if _, err := tx.ExecContext(ctx, "INSERT INTO "+dbName+
			".ha_settings (revision, name, value) VALUES (?,?,?)", rev, k, v); err != nil {
			return fmt.Errorf("config_projection_setting %s: %w", k, err)
		}
	}
	if r := p.Replication; r != nil {
		if _, err := tx.ExecContext(ctx, "INSERT INTO "+dbName+
			".ha_replication (revision, port, user, secret_ref) VALUES (?,?,?,?)",
			rev, r.Port, r.User, nullIfEmpty(r.SecretRef)); err != nil {
			return fmt.Errorf("config_projection_replication: %w", err)
		}
	}
	if pub := p.Publication; pub != nil {
		if _, err := tx.ExecContext(ctx, "INSERT INTO "+dbName+
			".ha_publication (revision, provider, params) VALUES (?,?,?)",
			rev, pub.Provider, nullIfEmpty(pub.Params)); err != nil {
			return fmt.Errorf("config_projection_publication: %w", err)
		}
	}
	return nil
}

// CommitRevision makes the staged revision effective.
//
// Ordering against the durable proof (§7.4) matters: the proof is written to the safety store BEFORE this call,
// not after. Otherwise "the peer considers the revision committed while we remember nothing after a crash" is
// possible, and the sides diverge forever. The reverse order (proof -> SQL) leaves only a narrow "proof present,
// row not updated" window, which RecoverCommitted closes.
func CommitRevision(ctx context.Context, tx *sql.Tx, dbName string, rev int64, hash string) (Decision, error) {
	st, err := LoadConfigState(ctx, tx, dbName)
	if err != nil {
		return Decision{}, err
	}
	d := CommitDecision(st, rev, hash)
	if d.Action != ActCommit {
		return d, nil
	}
	// A matching payload_hash STRING is not enough: it only claims what the content should be. Before the
	// revision is declared effective the content is parsed and rehashed, or a revision with corrupt bytes under
	// a correct fingerprint could become effective.
	payload, _, err := LoadRevisionPayload(ctx, tx, dbName, rev)
	if err != nil {
		return Decision{}, err
	}
	if err := payload.Validate(); err != nil {
		return reject(CodeRevisionInvalid, err.Error()), nil
	}
	if _, err := tx.ExecContext(ctx, "UPDATE "+dbName+
		".ha_config_revision SET status='EFFECTIVE', committed_at=NOW() WHERE revision=? AND status='STAGED'",
		rev); err != nil {
		return Decision{}, fmt.Errorf("config_commit: %w", err)
	}
	return d, nil
}

// RecoverCommitted completes a commit interrupted between writing the proof and the SQL update.
//
// It relies on SEMANTIC idempotency (revision + fingerprint), not message_id: after a restart the message is
// gone but the proof remains, and the proof says the commit happened. Returns true if something was completed.
func RecoverCommitted(ctx context.Context, db *sql.DB, dbName string, rev int64, hash string) (bool, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("config_recover_begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	d, err := CommitRevision(ctx, tx, dbName, rev, hash)
	if err != nil {
		return false, err
	}
	switch d.Action {
	case ActIdempotent:
		return false, nil // already completed: the usual case on every start
	case ActCommit:
		if err := tx.Commit(); err != nil {
			return false, fmt.Errorf("config_recover_commit: %w", err)
		}
		return true, nil
	}
	// A proof with no staged revision under it. This does not self-heal and must not be silent: proof and
	// data diverging calls for human intervention.
	return false, fmt.Errorf("config_recover_impossible: %s (%s)", d.Code, d.Reason)
}

// SeedRevision writes the FIRST revision at pair creation.
//
// Separate from StageRevision/CommitRevision on purpose: those implement agreement between TWO sides, while here
// the second side does not exist yet; the peer channel cannot come up while its address is itself part of the
// configuration being created. Both sides converge not over the network but because they were given the same
// pair description: identical canonical bytes give an identical fingerprint.
//
// Idempotent: a retry with the same content changes nothing; one with DIFFERENT content is refused, not
// silently overwritten.
func SeedRevision(ctx context.Context, db *sql.DB, dbName string, rev int64, p ConfigPayload, by string) error {
	blob, err := p.Canonical()
	if err != nil {
		return err
	}
	hash, err := p.Hash()
	if err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var haveHash string
	err = tx.QueryRowContext(ctx, "SELECT payload_hash FROM "+dbName+
		".ha_config_revision WHERE revision=?", rev).Scan(&haveHash)
	switch {
	case err == nil && haveHash == hash:
		return nil // already seeded with the same content
	case err == nil:
		return fmt.Errorf("config_seed_conflict: revision %d already exists with different content (%s)", rev, haveHash)
	case !errors.Is(err, sql.ErrNoRows):
		return fmt.Errorf("config_seed_lookup: %w", err)
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO "+dbName+".ha_config_revision "+
		"(revision, status, payload_hash, payload_blob, created_by, committed_at) VALUES (?,'EFFECTIVE',?,?,?,NOW())",
		rev, hash, blob, by); err != nil {
		return fmt.Errorf("config_seed: %w", err)
	}
	if err := writeProjection(ctx, tx, dbName, rev, p); err != nil {
		return err
	}
	return tx.Commit()
}

// CurrentOperationID returns the ID of THIS node's running operation.
//
// Observation must see it: without it health does not know the node is mid-switchover, and the planner
// treats the pair's intermediate state as a divergence to "fix".
func CurrentOperationID(ctx context.Context, socket, dbName string, timeout time.Duration) string {
	dsn, err := DSN(socket)
	if err != nil {
		return ""
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return ""
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	c, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var id string
	err = db.QueryRowContext(c, "SELECT operation_id FROM "+dbName+
		".ha_operations WHERE state IN ('PENDING','RUNNING') ORDER BY started_at DESC LIMIT 1").Scan(&id)
	if err != nil {
		return "" // no operation or DB unavailable: either way no running operation is observed
	}
	return id
}
