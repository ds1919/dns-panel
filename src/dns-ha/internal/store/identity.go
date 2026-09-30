package store

import (
	"context"
	"database/sql"
	"fmt"

	"dnspanel/dns-ha/internal/identity"
)

// Node identity and its trusted peer live in the LOCAL dns_ha.
//
// No separate files on purpose: the database is non-replicated and exists precisely for the local control
// plane, and a file per state next to it would multiply places describing the same thing. Files hold only what
// must be readable with the database DOWN: the safety store (the right to be ACTIVE) and the root agent state.

// EnsureIdentity returns this node's UUID, creating it on first start.
//
// An existing value is never overwritten: identity is part of peer message signing, safety and the operation
// journal, and changing it makes the node a stranger to its own pair.
func EnsureIdentity(ctx context.Context, db *sql.DB, dbName string) (string, error) {
	if id, err := LoadIdentity(ctx, db, dbName); err != nil {
		return "", err
	} else if id != "" {
		return id, nil
	}
	uuid, err := identity.NewUUID()
	if err != nil {
		return "", err
	}
	// INSERT IGNORE, not INSERT: two processes starting at once must not get different UUIDs.
	if _, err := db.ExecContext(ctx,
		"INSERT IGNORE INTO "+dbName+".ha_identity (only_row, node_id) VALUES (1, ?)", uuid); err != nil {
		return "", fmt.Errorf("identity_write: %w", err)
	}
	return LoadIdentity(ctx, db, dbName)
}

// LoadIdentity reads the node UUID. An empty string means the node has not named itself yet.
func LoadIdentity(ctx context.Context, db *sql.DB, dbName string) (string, error) {
	var id string
	err := db.QueryRowContext(ctx, "SELECT node_id FROM "+dbName+".ha_identity WHERE only_row = 1").Scan(&id)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("identity_read: %w", err)
	}
	if !identity.ValidUUID(id) {
		return "", fmt.Errorf("identity_invalid: node_id %q is not a UUID", id)
	}
	return id, nil
}

// TrustedPeer is the result of pairing: whom this node trusts.
type TrustedPeer struct {
	State        string // committing | trusted (no record at all before human approval)
	PairingID    string
	PeerNodeID   string
	PeerEndpoint string // host:port for the FIRST connection
	KeyFP        string
	TranscriptFP string
	ApprovedBy   string
}

// Trust states. Before human approval there is no record at all: pairing lives in memory.
const (
	TrustCommitting = "committing" // agreed; the key is being derived and installed on both sides
	TrustTrusted    = "trusted"    // both sides confirmed they hold the same key
)

// SaveTrustedPeer records trust in the committing state, BEFORE the key is installed.
//
// The reverse order would leave an orphaned key file after a crash that the manager knows nothing about: whose
// it is, what its fingerprint is, whether it may be removed.
//
// Idempotent per attempt: a retry of THE SAME attempt with the same peer and fingerprint succeeds (a lost reply
// must not look like a second pairing). Any mismatch is refused: the node already trusts someone, and only an
// explicit dismantle can change that.
func SaveTrustedPeer(ctx context.Context, db *sql.DB, dbName string, t TrustedPeer) error {
	cur, err := LoadTrustedPeer(ctx, db, dbName)
	if err != nil {
		return err
	}
	if cur != nil {
		if cur.PairingID == t.PairingID && cur.PeerNodeID == t.PeerNodeID && cur.KeyFP == t.KeyFP {
			return nil
		}
		return fmt.Errorf("trust_already_set: the node already trusts %s (attempt %s)", cur.PeerNodeID, cur.PairingID)
	}
	_, err = db.ExecContext(ctx, "INSERT INTO "+dbName+".ha_trusted_peer "+
		"(only_row, state, pairing_id, peer_node_id, peer_endpoint, key_fp, transcript_fp, approved_by) "+
		"VALUES (1,?,?,?,?,?,?,?)",
		TrustCommitting, t.PairingID, t.PeerNodeID, t.PeerEndpoint, t.KeyFP, t.TranscriptFP, nullable(t.ApprovedBy))
	if err != nil {
		return fmt.Errorf("trust_write: %w", err)
	}
	return nil
}

// PromoteTrustedPeer moves committing -> trusted, only for the NAMED attempt: completing someone else's
// pairing must not touch ours.
func PromoteTrustedPeer(ctx context.Context, db *sql.DB, dbName, pairingID string) error {
	res, err := db.ExecContext(ctx, "UPDATE "+dbName+".ha_trusted_peer SET state=? "+
		"WHERE only_row=1 AND pairing_id=?", TrustTrusted, pairingID)
	if err != nil {
		return fmt.Errorf("trust_promote: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		// Zero rows means either already trusted (a completion retry, normal) or a foreign attempt. Tell them
		// apart by reading, not guessing.
		cur, err := LoadTrustedPeer(ctx, db, dbName)
		if err != nil {
			return err
		}
		if cur == nil || cur.PairingID != pairingID {
			return fmt.Errorf("trust_wrong_pairing: finishing attempt %s, but there is no record of it", pairingID)
		}
	}
	return nil
}

// DeleteTrustedPeer removes the trust record. Called AFTER the key is removed: the reverse order would leave
// a key nobody knows about.
func DeleteTrustedPeer(ctx context.Context, db *sql.DB, dbName string) error {
	if _, err := db.ExecContext(ctx, "DELETE FROM "+dbName+".ha_trusted_peer WHERE only_row=1"); err != nil {
		return fmt.Errorf("trust_delete: %w", err)
	}
	return nil
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// LoadTrustedPeer returns the trusted peer, or nil if the node is not paired.
func LoadTrustedPeer(ctx context.Context, db *sql.DB, dbName string) (*TrustedPeer, error) {
	var t TrustedPeer
	var by sql.NullString
	err := db.QueryRowContext(ctx, "SELECT state, pairing_id, peer_node_id, peer_endpoint, key_fp, "+
		"transcript_fp, approved_by FROM "+dbName+".ha_trusted_peer WHERE only_row = 1").
		Scan(&t.State, &t.PairingID, &t.PeerNodeID, &t.PeerEndpoint, &t.KeyFP, &t.TranscriptFP, &by)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("trust_read: %w", err)
	}
	t.ApprovedBy = by.String
	return &t, nil
}
