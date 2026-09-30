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

// Proposer is the initiating side (§7.2). ONLY the ACTIVE may initiate a change: it is the sole config
// authority and is responsible for the content physically being on the peer before declaring the revision
// effective.
type Proposer struct {
	NodeID string
	DBName string
	DB     *sql.DB
	Safety *safety.Store
	Client *peer.ClientConfig
	Epoch  int64 // our epoch: sent with every command and checked by the peer's gate
}

// Result records what happened, step by step. Given to the operator and logs as is.
type Result struct {
	Revision    int64  `json:"revision"`
	PayloadHash string `json:"payload_hash"`
	LocalStage  string `json:"local_stage"`
	PeerStage   string `json:"peer_stage"`
	LocalCommit string `json:"local_commit"`
	PeerCommit  string `json:"peer_commit"`
}

// Propose runs a revision through both sides.
//
// The order is the one §7.2 derives all guarantees from, and it is not rearranged:
//
//  1. stage LOCALLY                 (otherwise we propose what we do not have)
//  2. get the PEER to stage         (after this the content physically exists on both sides)
//  3. commit LOCALLY                (durable proof -> SQL, §7.5)
//  4. send the commit to the PEER   (losing this step is normal: the peer stays STAGED, visible as
//     config_commit_unsynced, and a retry finishes the job)
//
// No step is "skipped when unreachable": an unreachable peer means the revision is not applied, not that it may
// be applied alone.
func (p *Proposer) Propose(ctx context.Context, rev int64, payload store.ConfigPayload) (Result, error) {
	res := Result{Revision: rev}
	if err := payload.Validate(); err != nil {
		return res, err
	}
	blob, err := payload.Canonical()
	if err != nil {
		return res, err
	}
	hash, err := payload.Hash()
	if err != nil {
		return res, err
	}
	res.PayloadHash = hash

	// Step 1: local staging.
	d, err := p.localStage(ctx, rev, payload)
	if err != nil {
		return res, err
	}
	if d.Action == store.ActReject {
		return res, fmt.Errorf("local staging refused: %s (%s)", d.Code, d.Reason)
	}
	res.LocalStage = d.Action

	// Step 2: staging on the peer. message_id is stable for the LOGICAL action: a retry after a lost reply
	// must return the same result, not stage the revision twice.
	ack, err := p.call(ctx, peer.CmdConfigStage, fmt.Sprintf("cfg-stage-%d-%s", rev, hash[:8]),
		peer.ConfigStagePayload{Revision: rev, PayloadHash: hash, PayloadBlob: blob})
	if err != nil {
		return res, fmt.Errorf("the peer did not stage the revision: %w", err)
	}
	res.PeerStage = ack.Result

	// Step 3: local commit: proof to disk, then SQL.
	if err := p.localCommit(ctx, rev, hash); err != nil {
		return res, err
	}
	res.LocalCommit = "committed"

	// Step 4: commit on the peer.
	ack, err = p.call(ctx, peer.CmdConfigCommit, fmt.Sprintf("cfg-commit-%d-%s", rev, hash[:8]),
		peer.ConfigCommitPayload{Revision: rev, PayloadHash: hash})
	if err != nil {
		// The revision is already effective here, and rightly so: we waited until the content was on the peer.
		// The inconsistency shows as config_commit_unsynced and is fixed by retrying this step.
		return res, fmt.Errorf("config_commit_unsynced: the peer did not confirm the commit: %w", err)
	}
	res.PeerCommit = ack.Result
	return res, nil
}

// ResendCommit runs only step 4, for when the peer has the content but the acknowledgement was lost.
func (p *Proposer) ResendCommit(ctx context.Context, rev int64, hash string) (peer.ConfigAck, error) {
	return p.call(ctx, peer.CmdConfigCommit, fmt.Sprintf("cfg-commit-%d-%s", rev, hash[:8]),
		peer.ConfigCommitPayload{Revision: rev, PayloadHash: hash})
}

// ResendStage runs only step 2 (the peer lost the staging, e.g. its dns_ha was recreated).
func (p *Proposer) ResendStage(ctx context.Context, rev int64, hash string, blob []byte) (peer.ConfigAck, error) {
	return p.call(ctx, peer.CmdConfigStage, fmt.Sprintf("cfg-stage-%d-%s", rev, hash[:8]),
		peer.ConfigStagePayload{Revision: rev, PayloadHash: hash, PayloadBlob: blob})
}

func (p *Proposer) localStage(ctx context.Context, rev int64, payload store.ConfigPayload) (store.Decision, error) {
	tx, err := p.DB.BeginTx(ctx, nil)
	if err != nil {
		return store.Decision{}, err
	}
	defer func() { _ = tx.Rollback() }()
	d, err := store.StageRevision(ctx, tx, p.DBName, rev, payload, p.NodeID)
	if err != nil || d.Action == store.ActReject {
		return d, err
	}
	return d, tx.Commit()
}

func (p *Proposer) localCommit(ctx context.Context, rev int64, hash string) error {
	if _, err := p.Safety.Update(func(s *safety.State) error {
		proof := safety.CommittedConfig{Revision: rev, PayloadHash: hash, Epoch: p.Epoch,
			CommittedBy: p.NodeID, CommittedAt: time.Now().UTC().Format(time.RFC3339)}
		switch v, why := s.CheckConfigProof(proof); v {
		case safety.ConfigProofIdempotent:
			return nil
		case safety.ConfigProofAccept:
			s.CommittedConfig = &proof
			return nil
		default:
			return fmt.Errorf("%s: %s", v, why)
		}
	}); err != nil {
		return fmt.Errorf("config_commit_proof: %w", err)
	}
	tx, err := p.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	d, err := store.CommitRevision(ctx, tx, p.DBName, rev, hash)
	if err != nil {
		return err
	}
	if d.Action == store.ActReject {
		return fmt.Errorf("local commit refused: %s (%s)", d.Code, d.Reason)
	}
	return tx.Commit()
}

func (p *Proposer) call(ctx context.Context, cmd, messageID string, payload any) (peer.ConfigAck, error) {
	var a peer.ConfigAck
	cfg := *p.Client
	cfg.MessageID, cfg.Epoch = messageID, p.Epoch
	res, err := peer.Call(ctx, cfg, cmd, payload)
	if err != nil {
		return a, err
	}
	if !res.Response.OK {
		return a, fmt.Errorf("the peer refused %s: %s", cmd, res.Response.Error)
	}
	if len(res.Response.Payload) > 0 {
		if err := json.Unmarshal(res.Response.Payload, &a); err != nil {
			return a, err
		}
	}
	return a, nil
}
