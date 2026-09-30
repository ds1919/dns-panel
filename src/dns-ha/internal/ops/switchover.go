package ops

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"dnspanel/dns-ha/internal/agent"
	"dnspanel/dns-ha/internal/observe"
	"dnspanel/dns-ha/internal/peer"
	"dnspanel/dns-ha/internal/safety"
)

// Planned role switchover, driven by the SOURCE (the side giving up the role): only it can prove it has
// stopped accepting writes, and only then may the role be handed over.
//
// The step order is fixed; each step buys a property that would otherwise be lost:
//
//	preflight_local    — we are ACTIVE with authority and healthy
//	preflight_peer     — target is ready (STANDBY, healthy, same config, not fenced)
//	disable_notifier   — stop serving zones
//	withdraw_panel     — withdraw the publication
//	demote             — read_only=1: writes stopped, and proven
//	drain_gtid         — target APPLIED everything we wrote (otherwise the handoff loses data)
//	handoff_record     — durable handoff trace + drop own authority  ← POINT OF NO RETURN
//	handoff_deliver    — target accepts the epoch and the authority to be active
//	rejoin_replica     — rejoin as a replica of the new source
//	verify             — both sides proved the new state
//
// After handoff_record we may never become active again, even if a later step fails; otherwise an
// interrupted handoff would leave two candidates with equally valid proof, i.e. split-brain.
const (
	StepPreflightLocal = "preflight_local"
	StepPreflightPeer  = "preflight_peer"
	StepDisableNotify  = "disable_notifier"
	StepWithdraw       = "withdraw_panel"
	StepDemote         = "demote"
	StepDrainGTID      = "drain_gtid"
	StepHandoffRecord  = "handoff_record"
	StepHandoffDeliver = "handoff_deliver"
	StepRejoin         = "rejoin_replica"
	StepVerify         = "verify"
)

// Mutator is the subset of the agent a switchover needs.
type Mutator interface {
	DisableNotifier(ctx context.Context, op agent.Op) (agent.CommandResult, error)
	WithdrawPanel(ctx context.Context, op agent.Op, address, device, provider string) (agent.CommandResult, error)
	Demote(ctx context.Context, op agent.Op) (agent.CommandResult, error)
	RejoinReplica(ctx context.Context, op agent.Op, primary string, seedFromBinlog bool) (agent.CommandResult, error)
}

// Switchover runs a planned switchover on the source side.
type Switchover struct {
	NodeID  string
	Ops     Store
	Safety  *safety.Store
	Mutator Mutator
	Peer    *peer.ClientConfig
	// Call reaches the peer; a field so the whole state machine can be tested without a node or network.
	Call func(cmd, messageID string, epoch int64, payload any) (peer.OpAck, error)
	// Observe returns a FRESH observation. State is re-read between steps: an agent reply that did not
	// prove the physical state, or any refusal, leaves the picture unknown.
	Observe func(context.Context) observe.Observation
	// Wait is the pause between state polls; injectable so tests do not really sleep.
	Wait func(time.Duration)
	// AwaitTimeout bounds how long to wait for a state to be confirmed.
	AwaitTimeout time.Duration
}

// Run drives the operation to completion or to a typed refusal.
//
// It is RESUMABLE: after a daemon restart it is called again with the same operation, and completed
// steps are skipped via the journal. Where the journal write may have been lost, a repeat is safe on its
// own: the agent remembers (operation_id, command), and safety writes are idempotent.
func (s *Switchover) Run(ctx context.Context, op Operation) error {
	steps, err := s.Ops.Steps(ctx, op.ID)
	if err != nil {
		return err
	}
	done := func(name string) bool { return s.Ops.Done(steps, name) }

	// Before the point of no return, actions use the CURRENT epoch, not the new one.
	//
	// The agent durably remembers the highest accepted epoch. If services were stopped at N+1 and the
	// operation then aborted (safety stays at N), normal convergence would try to restore the node at N,
	// get stale_epoch and leave it down although nobody took the role. The new epoch is adopted exactly
	// where the role is handed over: in handoff_record.
	cur := op.Epoch - 1
	if e := s.Observe(ctx).Safety.MaxSeenEpoch; e != nil && *e > cur {
		cur = *e
	}
	preOp := agent.Op{OperationID: op.ID, ClusterEpoch: cur}
	postOp := agent.Op{OperationID: op.ID, ClusterEpoch: op.Epoch}

	if err := s.Ops.SetState(ctx, op.ID, StateRunning, ""); err != nil {
		return err
	}

	if !done(StepPreflightLocal) {
		if err := s.step(ctx, op.ID, StepPreflightLocal, s.NodeID, func() error { return s.preflightLocal(ctx, op) }); err != nil {
			return s.abort(ctx, op, err)
		}
	}
	if !done(StepPreflightPeer) {
		if err := s.step(ctx, op.ID, StepPreflightPeer, op.TargetNode, func() error { return s.preflightPeer(ctx, op) }); err != nil {
			return s.abort(ctx, op, err)
		}
	}

	// Before the point of no return any failure can still be undone: we only stopped our services and
	// kept the authority, so after abort the node's own convergence loop restores them.
	for _, st := range []struct {
		name string
		run  func() (agent.CommandResult, error)
	}{
		{StepDisableNotify, func() (agent.CommandResult, error) { return s.Mutator.DisableNotifier(ctx, preOp) }},
		{StepWithdraw, func() (agent.CommandResult, error) {
			// Use the address from the current revision, not the node's file: withdraw exactly the
			// address this node brought up per the pair config.
			addr, dev, provider := s.Observe(ctx).Config.Payload.PublicationOf(s.NodeID)
			return s.Mutator.WithdrawPanel(ctx, preOp, addr, dev, provider)
		}},
		{StepDemote, func() (agent.CommandResult, error) { return s.Mutator.Demote(ctx, preOp) }},
	} {
		if done(st.name) {
			continue
		}
		if err := s.agentStep(ctx, op.ID, st.name, s.NodeID, st.run); err != nil {
			return s.abort(ctx, op, err)
		}
	}
	// Prove writes stopped by observation, not by the command reply.
	if err := s.awaitLocal(ctx, func(o observe.Observation) bool {
		return o.Local.ReadOnly != nil && *o.Local.ReadOnly == 1
	}, "node did not become read-only"); err != nil {
		return s.abort(ctx, op, err)
	}

	if !done(StepDrainGTID) {
		if err := s.step(ctx, op.ID, StepDrainGTID, op.TargetNode, func() error { return s.drainToTarget(ctx, op) }); err != nil {
			return s.abort(ctx, op, err)
		}
	}

	// Point of no return.
	if !done(StepHandoffRecord) {
		if err := s.step(ctx, op.ID, StepHandoffRecord, s.NodeID, func() error { return s.recordHandoff(ctx, op) }); err != nil {
			return s.abort(ctx, op, err)
		}
	}
	// No rollback from here on: the authority is handed over. Failure means "not finished", not "undo".
	if !done(StepHandoffDeliver) {
		if err := s.step(ctx, op.ID, StepHandoffDeliver, op.TargetNode, func() error { return s.deliverHandoff(ctx, op) }); err != nil {
			return s.fail(ctx, op, err)
		}
	}

	// Do not rejoin as a replica until the target holds the role: otherwise both sides would briefly
	// replicate from each other and the outcome would depend on whose loop fires first.
	if err := s.awaitLocal(ctx, func(o observe.Observation) bool {
		return o.Peer.Reachable && o.Peer.Role == "active" && o.Peer.ServiceReady
	}, "target did not confirm it became active"); err != nil {
		return s.fail(ctx, op, err)
	}

	if !done(StepRejoin) {
		src, ok := s.Observe(ctx).ExpectedReplicationSource()
		if !ok {
			return s.fail(ctx, op, fmt.Errorf("the new replication source address is unknown"))
		}
		if err := s.agentStep(ctx, op.ID, StepRejoin, s.NodeID, func() (agent.CommandResult, error) {
			// Start from our own binlog position: drain_gtid PROVED the target applied everything up to
			// it, while the saved replica position is from the previous role and points into history the
			// new source no longer has.
			return s.Mutator.RejoinReplica(ctx, postOp, src, true)
		}); err != nil {
			return s.fail(ctx, op, err)
		}
	}

	if err := s.step(ctx, op.ID, StepVerify, "", func() error { return s.verify(ctx, op) }); err != nil {
		return s.fail(ctx, op, err)
	}
	return s.Ops.SetState(ctx, op.ID, StateCompleted, "")
}

// preflightLocal checks that we are the one entitled to hand over the role.
func (s *Switchover) preflightLocal(ctx context.Context, op Operation) error {
	o := s.Observe(ctx)
	switch {
	case !o.IsActive():
		return fmt.Errorf("node is not ACTIVE (right: %s)", o.Safety.Authority.State)
	case o.Safety.FencedNode == s.NodeID:
		return fmt.Errorf("node is fenced — it cannot hand over the role")
	case o.Safety.MaxSeenEpoch == nil:
		return fmt.Errorf("epoch is unknown")
	case op.Epoch != *o.Safety.MaxSeenEpoch+1:
		// The new epoch must be exactly the next one; a gap means a switchover we did not see.
		return fmt.Errorf("operation epoch %d, expected %d", op.Epoch, *o.Safety.MaxSeenEpoch+1)
	case !o.Local.Preflight.Observed || !o.Local.Preflight.OK:
		return fmt.Errorf("node preflight not confirmed: %s %s", o.Local.Preflight.Code, o.Local.Preflight.Error)
	case !o.Peer.Reachable || o.Peer.Stale:
		return fmt.Errorf("the target state is not observed — switching blind is not allowed")
	case !o.Config.AgreesWithPeer(o.Peer):
		return fmt.Errorf("the two sides disagree on configuration — the role is not handed to such a node")
	}
	return nil
}

// preflightPeer asks the target to confirm it is ready to take the role.
func (s *Switchover) preflightPeer(ctx context.Context, op Operation) error {
	ack, err := s.call(ctx, peer.CmdPrepareSwitchover, "sw-prep-"+op.ID, op.Epoch,
		peer.SwitchoverPreparePayload{OperationID: op.ID, Epoch: op.Epoch, ConfigHash: s.Observe(ctx).Config.PayloadHash})
	if err != nil {
		return err
	}
	if !ack.Ready {
		return fmt.Errorf("target is not ready: %s", ack.Reason)
	}
	return nil
}

// drainToTarget waits until the target has applied everything we wrote.
//
// This is the only no-data-loss proof in a planned switchover: after demote there are no new
// transactions, so reaching our current position is enough.
func (s *Switchover) drainToTarget(ctx context.Context, op Operation) error {
	o := s.Observe(ctx)
	if !o.Replication.GTIDBinlogPosKnown {
		return fmt.Errorf("own GTID position is unknown — there is no way to prove the target caught up")
	}
	pos := o.Replication.GTIDBinlogPos
	if pos == "" {
		// An empty position means our binlog has no transactions (a freshly created pair): nothing to
		// apply or prove, so there is no reason to refuse.
		return nil
	}
	ack, err := s.call(ctx, peer.CmdAwaitGTID, "sw-drain-"+op.ID, op.Epoch,
		peer.AwaitGTIDPayload{OperationID: op.ID, Position: pos, TimeoutSeconds: 60})
	if err != nil {
		return err
	}
	if !ack.Applied {
		return fmt.Errorf("target did not apply position %s: %s", pos, ack.Reason)
	}
	return nil
}

// recordHandoff writes the durable handoff trace and drops our own authority.
//
// Both happen in ONE write: two separate writes would leave a window where the node has announced the
// handoff but still considers itself entitled to be active.
func (s *Switchover) recordHandoff(ctx context.Context, op Operation) error {
	hash := s.Observe(ctx).Config.PayloadHash
	_, err := s.Safety.Update(func(st *safety.State) error {
		if st.MaxSeenEpoch == nil || *st.MaxSeenEpoch < op.Epoch {
			e := op.Epoch
			st.MaxSeenEpoch = &e // adopt the epoch BEFORE handing over, so we remember which one we gave it in
		}
		st.Handoff = &safety.Handoff{OperationID: op.ID, Epoch: op.Epoch, To: op.TargetNode, From: s.NodeID,
			ConfigHash: hash, IssuedAt: time.Now().UTC().Format(time.RFC3339)}
		st.Authority = nil
		return nil
	})
	return err
}

func (s *Switchover) deliverHandoff(ctx context.Context, op Operation) error {
	ack, err := s.call(ctx, peer.CmdHandoffCertificate, "sw-handoff-"+op.ID, op.Epoch,
		peer.HandoffPayload{OperationID: op.ID, Epoch: op.Epoch, From: s.NodeID,
			ConfigHash: s.Observe(ctx).Config.PayloadHash, RequestedBy: op.RequestedBy})
	if err != nil {
		return err
	}
	if !ack.Accepted {
		return fmt.Errorf("target did not accept the right: %s", ack.Reason)
	}
	return nil
}

// verify waits until both sides prove the new state; otherwise "switchover completed" would only mean
// "no command returned an error".
func (s *Switchover) verify(ctx context.Context, op Operation) error {
	return s.awaitLocal(ctx, func(o observe.Observation) bool {
		return o.Local.ReadOnly != nil && *o.Local.ReadOnly == 1 && // we no longer accept writes
			o.Replication.Observed && o.Replication.IORunning == "Yes" && o.Replication.SQLRunning == "Yes" &&
			o.Peer.Reachable && o.Peer.Role == "active" && o.Peer.ServiceReady // target is actually serving
	}, "the new pair state is not confirmed")
}

func (s *Switchover) step(ctx context.Context, opID, name, node string, run func() error) error {
	return recordStep(ctx, s.Ops, opID, name, node, run)
}

func (s *Switchover) agentStep(ctx context.Context, opID, name, node string,
	run func() (agent.CommandResult, error)) error {
	return recordAgentStep(ctx, s.Ops, opID, name, node, run)
}

func (s *Switchover) awaitLocal(ctx context.Context, ok func(observe.Observation) bool, what string) error {
	return awaitState(ctx, s.Observe, s.Wait, s.AwaitTimeout, ok, what)
}

func (s *Switchover) call(ctx context.Context, cmd, messageID string, epoch int64, payload any) (peer.OpAck, error) {
	if s.Call != nil {
		return s.Call(cmd, messageID, epoch, payload)
	}
	var ack peer.OpAck
	cfg := *s.Peer
	cfg.MessageID, cfg.Epoch = messageID, epoch
	res, err := peer.Call(ctx, cfg, cmd, payload)
	if err != nil {
		return ack, err
	}
	if !res.Response.OK {
		return ack, fmt.Errorf("peer refused %s: %s", cmd, res.Response.Error)
	}
	if len(res.Response.Payload) > 0 {
		if err := json.Unmarshal(res.Response.Payload, &ack); err != nil {
			return ack, err
		}
	}
	return ack, nil
}

// abort handles a failure BEFORE the point of no return: we keep the role, and normal convergence
// brings the node back into service.
func (s *Switchover) abort(ctx context.Context, op Operation, cause error) error {
	_ = s.Ops.SetState(ctx, op.ID, StateAborted, cause.Error())
	return fmt.Errorf("switchover rolled back: %w", cause)
}

// fail handles a failure AFTER the point of no return. The operation stays RUNNING, and the next loop
// resumes it from the same place.
//
// It must not be FAILED: Current() only picks PENDING/RUNNING, so FAILED means the manager never comes
// back to it. The authority is already handed over, so the same loop, not a human, must finish the
// switchover; otherwise one lost packet on handoff_deliver would leave the pair without an ACTIVE until
// a manual Resume.
//
// Retrying is safe by construction: handoff_deliver has a fixed message_id answered from the durable
// ledger, the target comes up via its own convergence, rejoin_replica is idempotent in the agent, and
// verify only observes. Steps before the point of no return are skipped via done().
//
// So: before the point of no return a failure means ABORTED (undo), after it RUNNING (finish).
func (s *Switchover) fail(ctx context.Context, op Operation, cause error) error {
	_ = s.Ops.SetState(ctx, op.ID, StateRunning, cause.Error())
	return fmt.Errorf("switchover %s will be retried after the right was handed over: %w", op.ID, cause)
}
