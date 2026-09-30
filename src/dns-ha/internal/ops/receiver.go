package ops

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"dnspanel/dns-ha/internal/observe"
	"dnspanel/dns-ha/internal/peer"
	"dnspanel/dns-ha/internal/safety"
)

// Receiver is the side that TAKES the role. It only answers the source's questions; who switches and
// when is decided by the source, which holds the authority to hand the role over.
type Receiver struct {
	NodeID  string
	DBName  string
	Safety  *safety.Store
	Observe func(context.Context) observe.Observation
	// Release dismantles the pair on the ACTIVE's command. It is a func so the receiver state machine
	// can be exercised without MariaDB or the agent.
	Release func(ctx context.Context, in peer.DismantlePayload) error
}

// Execute is plugged into peer.ServerConfig.Executor alongside the config commands.
func (r *Receiver) Execute(ctx context.Context, tx *sql.Tx, req *peer.Request) (peer.LedgerResult, error) {
	switch req.Cmd {
	case peer.CmdPrepareSwitchover:
		return r.prepare(ctx, tx, req)
	case peer.CmdAwaitGTID:
		return r.awaitGTID(ctx, tx, req)
	case peer.CmdHandoffCertificate:
		return r.handoff(ctx, tx, req)
	case peer.CmdClearFencing:
		return r.clearFencing(ctx, req)
	case peer.CmdReleasePair:
		return r.releasePair(ctx, req)
	}
	return peer.LedgerResult{}, fmt.Errorf("ops: command %q is not addressed here", req.Cmd)
}

// releasePair makes this node standalone again, on the ACTIVE's command during dismantle.
//
// Order matters: detach from the source, then drop fail-safe, and only then allow writes. The reverse
// order would briefly leave a writable node still applying the peer's changes.
//
// Data is untouched: the drain already proved we have every ACTIVE transaction.
func (r *Receiver) releasePair(ctx context.Context, req *peer.Request) (peer.LedgerResult, error) {
	var in peer.DismantlePayload
	if err := json.Unmarshal(req.Payload, &in); err != nil {
		return ackResult(peer.OpAck{NodeID: r.NodeID, Reason: "request could not be parsed"})
	}
	if r.Release == nil {
		return ackResult(peer.OpAck{NodeID: r.NodeID, Reason: "this node cannot dismantle the pair"})
	}
	if err := r.Release(ctx, in); err != nil {
		return ackResult(peer.OpAck{NodeID: r.NodeID, Reason: err.Error()})
	}
	return ackResult(peer.OpAck{NodeID: r.NodeID, Applied: true})
}

// prepare reports whether we can take the role. "Yes" changes nothing and promises nothing: it reflects
// only what is visible NOW; the real permission arrives as the certificate.
func (r *Receiver) prepare(ctx context.Context, tx *sql.Tx, req *peer.Request) (peer.LedgerResult, error) {
	var in peer.SwitchoverPreparePayload
	if err := json.Unmarshal(req.Payload, &in); err != nil {
		return ackResult(peer.OpAck{NodeID: r.NodeID, Reason: "request could not be parsed"})
	}
	o := r.Observe(ctx)
	if why := r.notReady(o, in.Epoch, in.ConfigHash); why != "" {
		return ackResult(peer.OpAck{NodeID: r.NodeID, Reason: why})
	}
	// No local operation is created: the switchover may be cancelled right after prepare, and a record
	// of a non-existent operation would block the node. It appears with the commitment, at handoff.
	return ackResult(peer.OpAck{NodeID: r.NodeID, Ready: true})
}

func (r *Receiver) notReady(o observe.Observation, epoch int64, configHash string) string {
	switch {
	case o.IsActive():
		return "node considers itself active — there is nobody to take the role from"
	case o.Safety.FencedNode == r.NodeID:
		return "node is fenced and needs a reseed"
	case o.Safety.MaxSeenEpoch == nil:
		return "epoch is unknown"
	case epoch <= *o.Safety.MaxSeenEpoch:
		// The epoch must be NEWER than seen; otherwise it is a replay of a past transition.
		return fmt.Sprintf("epoch %d is not newer than the seen %d", epoch, *o.Safety.MaxSeenEpoch)
	case o.Config.PayloadHash == "" || o.Config.PayloadHash != configHash:
		return "the two sides disagree on configuration"
	case !o.Local.AgentOK:
		// Include the full reason: this also covers "publication interface not found", and a bare
		// "local agent is unavailable" would send the operator looking in the wrong place.
		return "local agent is unavailable: " + o.Local.AgentError
	case !o.Local.Preflight.Observed || !o.Local.Preflight.OK:
		return "node preflight not confirmed: " + o.Local.Preflight.Code + o.Local.Preflight.Error
	case !o.Replication.Observed || o.Replication.IORunning != "Yes" || o.Replication.SQLRunning != "Yes":
		// Taking the role while not a healthy replica means taking it with unknown data lag.
		return "replication is not healthy — data may lag"
	}
	// The service address must have somewhere to go. Check BEFORE the point of no return: otherwise the
	// source would already have dropped the address and handed over the role, causing an avoidable outage.
	if addr, dev := o.Config.Payload.PublicationTargetOf(r.NodeID); addr != "" {
		if dev == "" {
			return "service interface for this node is not configured"
		}
		if !o.Local.PublicationDeviceOK {
			return fmt.Sprintf("service interface %s is not available on this node", dev)
		}
	}
	return ""
}

// awaitGTID applies everything the source has written and PROVES it.
//
// This is the only no-data-loss proof in a planned switchover: the source no longer accepts writes, so
// reaching its position is enough. NULL or timeout means "not proven", not "probably applied".
func (r *Receiver) awaitGTID(ctx context.Context, tx *sql.Tx, req *peer.Request) (peer.LedgerResult, error) {
	var in peer.AwaitGTIDPayload
	if err := json.Unmarshal(req.Payload, &in); err != nil {
		return ackResult(peer.OpAck{NodeID: r.NodeID, Reason: "request could not be parsed"})
	}
	if in.Position == "" {
		return ackResult(peer.OpAck{NodeID: r.NodeID, Reason: "position not given"})
	}
	timeout := in.TimeoutSeconds
	if timeout <= 0 || timeout > 300 {
		timeout = 60
	}
	var rc sql.NullInt64
	if err := tx.QueryRowContext(ctx, "SELECT MASTER_GTID_WAIT(?, ?)", in.Position, timeout).Scan(&rc); err != nil {
		return ackResult(peer.OpAck{NodeID: r.NodeID, Reason: "waiting for position failed: " + err.Error()})
	}
	if !rc.Valid || rc.Int64 < 0 {
		return ackResult(peer.OpAck{NodeID: r.NodeID,
			Reason: fmt.Sprintf("position %s was not applied within %d s", in.Position, timeout)})
	}
	return ackResult(peer.OpAck{NodeID: r.NodeID, Applied: true})
}

// handoff accepts the authority to be active.
//
// Authority is written durably BEFORE replying: if the reply is lost, the source retries while we are
// already entitled, and our own convergence loop finishes the job. Reply-then-write could leave the
// pair with no ACTIVE at all.
func (r *Receiver) handoff(ctx context.Context, tx *sql.Tx, req *peer.Request) (peer.LedgerResult, error) {
	var in peer.HandoffPayload
	if err := json.Unmarshal(req.Payload, &in); err != nil {
		return ackResult(peer.OpAck{NodeID: r.NodeID, Reason: "request could not be parsed"})
	}
	o := r.Observe(ctx)
	if r.alreadyAccepted(o, in) {
		// A repeated certificate must look like success (the source may have missed the reply). "Same"
		// means epoch, sender AND operation match, not just the epoch.
		return ackResult(peer.OpAck{NodeID: r.NodeID, Accepted: true})
	}
	// The certificate grants authority, the most dangerous thing accepted over the network: everything
	// is checked, and any mismatch is a refusal.
	switch {
	case in.OperationID == "":
		return ackResult(peer.OpAck{NodeID: r.NodeID, Reason: "certificate without an operation"})
	case in.From == "" || in.From != req.SenderNodeID:
		// The sender must grant authority in its OWN name: the signature proves who speaks, and the
		// payload cannot claim otherwise.
		return ackResult(peer.OpAck{NodeID: r.NodeID, Reason: "sender does not match the certificate issuer"})
	case o.Safety.FencedNode == r.NodeID:
		return ackResult(peer.OpAck{NodeID: r.NodeID, Reason: "node is fenced"})
	case o.Safety.MaxSeenEpoch == nil:
		return ackResult(peer.OpAck{NodeID: r.NodeID, Reason: "epoch is unknown"})
	case in.Epoch != *o.Safety.MaxSeenEpoch+1:
		// Exactly the next epoch: a gap means a transition we did not see, a repeat means a replay.
		return ackResult(peer.OpAck{NodeID: r.NodeID,
			Reason: fmt.Sprintf("epoch %d, expected %d", in.Epoch, *o.Safety.MaxSeenEpoch+1)})
	case o.Config.PayloadHash == "" || o.Config.PayloadHash != in.ConfigHash:
		return ackResult(peer.OpAck{NodeID: r.NodeID, Reason: "the two sides disagree on configuration"})
	case o.Local.PhysicallyActive():
		// Already physically active means we misunderstand who is active in the pair.
		return ackResult(peer.OpAck{NodeID: r.NodeID, Reason: "node is already physically active"})
	}
	if _, err := r.Safety.Update(func(st *safety.State) error {
		if st.MaxSeenEpoch == nil || *st.MaxSeenEpoch < in.Epoch {
			e := in.Epoch
			st.MaxSeenEpoch = &e
		}
		e := in.Epoch
		st.Authority = &safety.Authority{Type: safety.AuthorityHandoff, Epoch: &e, Role: "active",
			IssuedAt: time.Now().UTC().Format(time.RFC3339), Source: in.From}
		// Drop our old handoff trace: it belonged to a previous transfer.
		st.Handoff = nil
		return nil
	}); err != nil {
		return peer.LedgerResult{}, fmt.Errorf("handoff_accept: %w", err)
	}
	if err := r.markOperation(ctx, tx, in.OperationID, in.Epoch, in.From, in.RequestedBy); err != nil {
		return peer.LedgerResult{}, err
	}
	return ackResult(peer.OpAck{NodeID: r.NodeID, Accepted: true})
}

// alreadyAccepted reports whether EXACTLY this certificate was accepted: same epoch, author and
// authority type. The epoch alone is not enough; a different decision may have been made in it.
func (r *Receiver) alreadyAccepted(o observe.Observation, in peer.HandoffPayload) bool {
	a := o.Safety.Authority
	return a.State == safety.AuthValidCurrent && a.Type == safety.AuthorityHandoff &&
		a.Epoch != nil && *a.Epoch == in.Epoch && a.Source == in.From
}

// markOperation records the operation on the receiving side. Each side has its own journal describing
// what THIS node does, not the pair's shared state.
func (r *Receiver) markOperation(ctx context.Context, tx *sql.Tx, id string, epoch int64, source, by string) error {
	if id == "" {
		return nil
	}
	// The author comes from the initiator, the only side that knows who pressed the button; falling back
	// to the source node would record that a server requested it.
	if by == "" {
		by = source
	}
	_, err := tx.ExecContext(ctx, "INSERT INTO "+r.DBName+".ha_operations "+
		"(operation_id, kind, state, epoch, source_node, target_node, requested_by) VALUES (?,?,?,?,?,?,?) "+
		"ON DUPLICATE KEY UPDATE state=VALUES(state), epoch=VALUES(epoch), requested_by=VALUES(requested_by)",
		id, KindPlanned, StateRunning, epoch, source, r.NodeID, by)
	if err != nil {
		return fmt.Errorf("operation_mark: %w", err)
	}
	return nil
}

// FinishAccepted closes the operation on the receiving side once its own loop has brought the node into the role.
//
// It is separate from accepting the certificate on purpose: accepting authority and becoming a working
// ACTIVE are different events.
func (s Store) FinishAccepted(ctx context.Context, o observe.Observation) error {
	op, err := s.Current(ctx)
	if err != nil || op == nil || op.TargetNode != o.NodeID {
		return err
	}
	if !o.IsActive() || !o.Local.PhysicallyActive() {
		return nil
	}
	return s.SetState(ctx, op.ID, StateCompleted, "")
}

func ackResult(a peer.OpAck) (peer.LedgerResult, error) {
	raw, err := json.Marshal(a)
	if err != nil {
		return peer.LedgerResult{}, err
	}
	// A refusal on the merits is a command result, not a transport error: the initiator must see the
	// reason instead of retrying blindly. It is not cached either (Transient): conditions change, and a
	// repaired node looks different a minute later.
	return peer.LedgerResult{Payload: raw, Transient: !a.Ready && !a.Applied && !a.Accepted}, nil
}

// clearFencing lifts fencing from a node that has proven it is repaired.
//
// Not on its word: our own observation must show it as a healthy replica of US; otherwise "reseed
// done" would only mean the command returned ok.
func (r *Receiver) clearFencing(ctx context.Context, req *peer.Request) (peer.LedgerResult, error) {
	var in peer.ClearFencingPayload
	if err := json.Unmarshal(req.Payload, &in); err != nil {
		return ackResult(peer.OpAck{NodeID: r.NodeID, Reason: "request could not be parsed"})
	}
	o := r.Observe(ctx)
	switch {
	case in.Node == "" || in.Node != req.SenderNodeID:
		return ackResult(peer.OpAck{NodeID: r.NodeID, Reason: "a node may only clear fencing on itself"})
	case o.Safety.FencedNode == "":
		return ackResult(peer.OpAck{NodeID: r.NodeID, Accepted: true}) // already cleared: a retry
	case o.Safety.FencedNode != in.Node:
		return ackResult(peer.OpAck{NodeID: r.NodeID, Reason: "a different node is fenced"})
	case !o.IsActive():
		// Only the current ACTIVE may clear fencing: it set it and sees the whole pair.
		return ackResult(peer.OpAck{NodeID: r.NodeID, Reason: "node is not active and does not own fencing"})
	case !o.Peer.Reachable || o.Peer.Stale:
		// Name what was observed, so the operator does not have to guess what was missing.
		return ackResult(peer.OpAck{NodeID: r.NodeID, Reason: fmt.Sprintf(
			"the repaired node state is not observed (reachable=%v, stale=%v, role=%q, error=%q)",
			o.Peer.Reachable, o.Peer.Stale, o.Peer.Role, o.Peer.Error)})
	case !isOneInt(o.Peer.ReadOnly):
		// A repaired node must be read-only: unfencing a node that accepts writes means a second ACTIVE.
		return ackResult(peer.OpAck{NodeID: r.NodeID, Reason: "a repaired node must be read-only"})
	}
	if _, err := r.Safety.Update(func(st *safety.State) error {
		st.Fenced = ""
		return nil
	}); err != nil {
		return peer.LedgerResult{}, fmt.Errorf("clear_fencing: %w", err)
	}
	return ackResult(peer.OpAck{NodeID: r.NodeID, Accepted: true})
}

func isOneInt(v *int) bool { return v != nil && *v == 1 }
