// Package configsync is the receiving side of the configuration revision protocol (DOCS/23-ha-manager.md §7).
//
// Separate from `peer` on purpose: the transport must not know what configuration is, and the store must not
// know what a network is. They meet here and only here.
package configsync

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"dnspanel/dns-ha/internal/peer"
	"dnspanel/dns-ha/internal/safety"
	"dnspanel/dns-ha/internal/store"
)

// Receiver executes the peer's configuration commands. Each call runs INSIDE the transaction opened by the
// durable registry: request registration and its result commit together with the change itself.
type Receiver struct {
	NodeID string
	DBName string
	Safety *safety.Store
}

// Execute is what goes into peer.ServerConfig.Executor.
func (r *Receiver) Execute(ctx context.Context, tx *sql.Tx, req *peer.Request) (peer.LedgerResult, error) {
	switch req.Cmd {
	case peer.CmdConfigStage:
		return r.stage(ctx, tx, req)
	case peer.CmdConfigCommit:
		return r.commit(ctx, tx, req)
	}
	return peer.LedgerResult{}, fmt.Errorf("configsync: command %q is not addressed here", req.Cmd)
}

func (r *Receiver) stage(ctx context.Context, tx *sql.Tx, req *peer.Request) (peer.LedgerResult, error) {
	var in peer.ConfigStagePayload
	if err := json.Unmarshal(req.Payload, &in); err != nil {
		return reject(peer.ErrBadRequest)
	}
	// The content is proven BEFORE writing: the received bytes must be exactly those whose fingerprint is
	// declared (§7.5), or we would store under an honest hash something the sender never sent.
	payload, err := store.ParseConfigPayload(in.PayloadBlob, in.PayloadHash)
	if err != nil {
		return result(store.CodeRevisionInvalid, ack(r.NodeID, in.Revision, in.PayloadHash, ""))
	}
	d, err := store.StageRevision(ctx, tx, r.DBName, in.Revision, payload, req.SenderNodeID)
	if err != nil {
		return peer.LedgerResult{}, err
	}
	if d.Action == store.ActReject {
		return result(d.Code, ack(r.NodeID, in.Revision, in.PayloadHash, "rejected"))
	}
	res := "staged"
	if d.Action == store.ActIdempotent {
		res = "idempotent"
	}
	return result("", ack(r.NodeID, in.Revision, in.PayloadHash, res))
}

// commit is the RECEIVER's commit. Same order as the initiator (§7.5): durable proof to disk first, SQL second.
// The reverse would leave a node that "already applied but does not remember it", and after a restart the
// sides would diverge with no chance of converging automatically.
func (r *Receiver) commit(ctx context.Context, tx *sql.Tx, req *peer.Request) (peer.LedgerResult, error) {
	var in peer.ConfigCommitPayload
	if err := json.Unmarshal(req.Payload, &in); err != nil {
		return reject(peer.ErrBadRequest)
	}

	// First check that committing is allowed at all: no proof is issued for something we do not have.
	st, err := store.LoadConfigState(ctx, tx, r.DBName)
	if err != nil {
		return peer.LedgerResult{}, err
	}
	if d := store.CommitDecision(st, in.Revision, in.PayloadHash); d.Action == store.ActReject {
		return result(d.Code, ack(r.NodeID, in.Revision, in.PayloadHash, "rejected"))
	}

	if _, err := r.Safety.Update(func(s *safety.State) error {
		proof := safety.CommittedConfig{Revision: in.Revision, PayloadHash: in.PayloadHash,
			Epoch: req.Epoch, CommittedBy: req.SenderNodeID, CommittedAt: time.Now().UTC().Format(time.RFC3339)}
		switch v, why := s.CheckConfigProof(proof); v {
		case safety.ConfigProofIdempotent:
			return nil // proof already exists; nothing to rewrite
		case safety.ConfigProofAccept:
			s.CommittedConfig = &proof
			return nil
		default:
			return fmt.Errorf("%s: %s", v, why)
		}
	}); err != nil {
		return peer.LedgerResult{}, fmt.Errorf("config_commit_proof: %w", err)
	}

	d, err := store.CommitRevision(ctx, tx, r.DBName, in.Revision, in.PayloadHash)
	if err != nil {
		return peer.LedgerResult{}, err
	}
	if d.Action == store.ActReject {
		return result(d.Code, ack(r.NodeID, in.Revision, in.PayloadHash, "rejected"))
	}
	res := "committed"
	if d.Action == store.ActIdempotent {
		res = "idempotent"
	}
	return result("", ack(r.NodeID, in.Revision, in.PayloadHash, res))
}

func ack(node string, rev int64, hash, res string) peer.ConfigAck {
	return peer.ConfigAck{NodeID: node, Revision: rev, PayloadHash: hash, Result: res}
}

func result(code string, a peer.ConfigAck) (peer.LedgerResult, error) {
	raw, err := json.Marshal(a)
	if err != nil {
		return peer.LedgerResult{}, err
	}
	return peer.LedgerResult{Code: code, Payload: raw}, nil
}

func reject(code string) (peer.LedgerResult, error) {
	return peer.LedgerResult{Code: code}, nil
}
