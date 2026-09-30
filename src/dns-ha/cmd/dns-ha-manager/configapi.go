package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"dnspanel/dns-ha/internal/config"
	"dnspanel/dns-ha/internal/configsync"
	"dnspanel/dns-ha/internal/safety"
	"dnspanel/dns-ha/internal/store"
)

// Reading and changing the HA configuration via the control socket.
//
// The panel does NOT write to `dns_ha`: it sends the content, and the manager runs the revision through the
// existing protocol (§7.2): stage locally -> get the peer to stage -> commit locally -> send the commit.
// A second place changing pair configuration would sooner or later make the sides diverge.

// configView is what the operator sees: both the effective and the staged revision, because "applied" and
// "proposed but not committed" are different states.
type configView struct {
	Revision    *int64               `json:"revision"`
	PayloadHash string               `json:"payload_hash,omitempty"`
	Payload     *store.ConfigPayload `json:"payload"`
	Staged      *stagedView          `json:"staged,omitempty"`
	Editable    bool                 `json:"editable"`
	Reason      string               `json:"reason,omitempty"`
}

type stagedView struct {
	Revision    int64  `json:"revision"`
	PayloadHash string `json:"payload_hash"`
}

func openConfigDB(cfg config.Config) (*sql.DB, error) {
	dsn, err := store.WriteDSN(cfg.Database.Socket)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(2)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// getConfig returns the effective revision content as THIS node sees it.
func getConfig(cfg config.Config, snap *snapshot) (any, error) {
	db, err := openConfigDB(cfg)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	st, err := store.LoadConfigState(ctx, db, cfg.Database.Database)
	if err != nil {
		return nil, err
	}
	v := configView{}
	if st.Effective != nil {
		p, hash, err := store.LoadRevisionPayload(ctx, db, cfg.Database.Database, st.Effective.Revision)
		if err != nil {
			return nil, err
		}
		rev := st.Effective.Revision
		v.Revision, v.PayloadHash, v.Payload = &rev, hash, &p
	}
	if st.Staged != nil {
		v.Staged = &stagedView{Revision: st.Staged.Revision, PayloadHash: st.Staged.PayloadHash}
	}
	v.Editable, v.Reason = configEditable(snap)
	return v, nil
}

// configEditable reports whether THIS node may propose a revision.
//
// Only the ACTIVE may: the proposer must be the one currently in charge of the pair, or both sides could
// start competing revisions and whichever came first would win. The panel shows the same answer up front so
// the form is not editable where saving would fail anyway.
func configEditable(snap *snapshot) (bool, string) {
	v, _, _ := snap.get()
	if v.Role != "active" {
		return false, "configuration is changed on the ACTIVE node — this node is " + orUnknownRole(v.Role)
	}
	if v.Execution.Operation != "" {
		return false, "an HA operation is running (" + v.Execution.Operation + ")"
	}
	if !v.Pair.Peer.Reachable {
		return false, "the peer is unreachable — a revision must be staged on both nodes before it applies"
	}
	return true, ""
}

func orUnknownRole(r string) string {
	if r == "" {
		return "unknown"
	}
	return r
}

// applyConfig runs the submitted content as the NEXT revision.
//
// The manager assigns the revision number (current+1), not the client: a panel open in two tabs could easily
// send the same number for different content.
func applyConfig(cfg config.Config, snap *snapshot, raw json.RawMessage, by string) (any, error) {
	if ok, why := configEditable(snap); !ok {
		return nil, fmt.Errorf("config_not_editable: %s", why)
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("config_payload_missing: empty revision payload")
	}
	// Strict parsing: an unknown field is a typo or another panel version and must not be silently dropped.
	var p store.ConfigPayload
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("config_payload_invalid: %v", err)
	}
	if p.Version == 0 {
		p.Version = store.PayloadVersion
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}

	db, err := openConfigDB(cfg)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	st, err := store.LoadConfigState(ctx, db, cfg.Database.Database)
	if err != nil {
		return nil, err
	}
	var next int64 = 1
	if st.Effective != nil {
		next = st.Effective.Revision + 1
		// Nothing changed: don't create a revision; an empty one documents nothing and burns a number.
		cur, _, err := store.LoadRevisionPayload(ctx, db, cfg.Database.Database, st.Effective.Revision)
		if err != nil {
			return nil, err
		}
		curHash, err := cur.Hash()
		if err != nil {
			return nil, err
		}
		newHash, err := p.Hash()
		if err != nil {
			return nil, err
		}
		if curHash == newHash {
			return map[string]any{"revision": st.Effective.Revision, "payload_hash": curHash,
				"unchanged": true}, nil
		}
		// A nonexistent replication address is not "a setting for later" but a broken pair: STANDBY connects to it
		// right after commit. Check BEFORE creating the revision; unchanged addresses are skipped, or renaming a node
		// would require the peer to be alive right now.
		if err := configsync.CheckReplicationHosts(ctx, cur, p, 3306, 3*time.Second); err != nil {
			return nil, err
		}
	}
	if st.Staged != nil && st.Staged.Revision >= next {
		next = st.Staged.Revision + 1
	}

	client, err := peerClientOnly(cfg)
	if err != nil {
		return nil, fmt.Errorf("peer channel is unavailable: %w", err)
	}
	epoch := int64(0)
	if e := snapshotEpoch(snap); e != nil {
		epoch = *e
	}
	pr := &configsync.Proposer{
		NodeID: cfg.Node, DBName: cfg.Database.Database, DB: db,
		Safety: safety.NewStore(config.SafetyPath), Client: client, Epoch: epoch,
	}
	res, err := pr.Propose(ctx, next, p)
	if err != nil {
		return res, err
	}
	fmt.Printf("dns-ha-manager: configuration: revision %d committed (%s), author %s\n",
		res.Revision, res.PayloadHash[:12], orEnv(by))
	return res, nil
}

func snapshotEpoch(snap *snapshot) *int64 {
	v, _, _ := snap.get()
	return v.Pair.Self.Epoch
}

// ensureIdentity returns this node's UUID from the local dns_ha, creating it on first start.
//
// The schema is applied here too: a node with an empty database must be able to name itself without a
// separate install step. After that the identity is only read.
func ensureIdentity(cfg config.Config) (string, error) {
	db, err := openConfigDB(cfg)
	if err != nil {
		return "", err
	}
	defer db.Close()
	// No deadline of our own: this is daemon start, bounded by systemd (TimeoutStartSec) and by per-connection
	// timeouts. A deadline over the whole schema cut table creation short on the first start on a fresh database
	// and crashed the manager for no reason.
	ctx := context.Background()
	if err := store.ApplySchema(ctx, db, cfg.Database.Database); err != nil {
		return "", err
	}
	return store.EnsureIdentity(ctx, db, cfg.Database.Database)
}
