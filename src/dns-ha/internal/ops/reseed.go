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

// Reseed brings a node that dropped out in an emergency back into the pair.
//
// Unlike a switchover, a reseed does NOT bump the epoch: the epoch changes only when the authority to be
// active changes, and a spurious bump would look like a role transition that never happened.
const (
	StepAcceptEpoch = "accept_epoch"
	StepReseed      = "reseed_replica"
	StepUnfence     = "unfence"
)

// Reseed runs a reseed on the node being repaired.
type Reseed struct {
	NodeID  string
	Ops     Store
	Safety  *safety.Store
	Mutator ReseedMutator
	Peer    *peer.ClientConfig
	Call    func(cmd, messageID string, epoch int64, payload any) (peer.OpAck, error)
	Observe func(context.Context) observe.Observation
	Wait    func(time.Duration)

	AwaitTimeout time.Duration
	Operator     string
}

// ReseedMutator is the subset of the agent a reseed needs.
type ReseedMutator interface {
	ReseedReplica(ctx context.Context, op agent.Op, primary string) (agent.CommandResult, error)
}

// Run performs the reseed.
func (r *Reseed) Run(ctx context.Context, op Operation) error {
	steps, err := r.Ops.Steps(ctx, op.ID)
	if err != nil {
		return err
	}
	done := func(name string) bool { return r.Ops.Done(steps, name) }

	if err := r.Ops.SetState(ctx, op.ID, StateRunning, ""); err != nil {
		return err
	}
	if !done(StepPreflightLocal) {
		if err := r.step(ctx, op.ID, StepPreflightLocal, r.NodeID, func() error { return r.preflight(ctx, op) }); err != nil {
			return r.abort(ctx, op, err)
		}
	}

	// Accept the pair's epoch without gaining authority: the node is repaired as a replica, but agent
	// commands must carry the current epoch, not the one the node dropped out at.
	if !done(StepAcceptEpoch) {
		if err := r.step(ctx, op.ID, StepAcceptEpoch, r.NodeID, func() error { return r.acceptEpoch(op) }); err != nil {
			return r.abort(ctx, op, err)
		}
	}

	aop := agent.Op{OperationID: op.ID, ClusterEpoch: op.Epoch}
	if !done(StepReseed) {
		src, ok := r.Observe(ctx).ExpectedReplicationSource()
		if !ok {
			return r.abort(ctx, op, fmt.Errorf("replication source address is unknown"))
		}
		if err := r.agentStep(ctx, op.ID, StepReseed, r.NodeID, func() (agent.CommandResult, error) {
			return r.Mutator.ReseedReplica(ctx, aop, src)
		}); err != nil {
			return r.fail(ctx, op, err)
		}
	}

	// Prove the node is a healthy replica of this exact source. The command reply is not proof: the
	// reseed may succeed and replication stop a second later.
	if err := r.step(ctx, op.ID, StepVerify, r.NodeID, func() error { return r.verify(ctx) }); err != nil {
		return r.fail(ctx, op, err)
	}

	// Fencing is cleared by the side that set it: a node declared unsafe cannot decide by itself that it
	// is fine again.
	if !done(StepUnfence) {
		if err := r.step(ctx, op.ID, StepUnfence, r.NodeID, func() error { return r.unfence(ctx, op) }); err != nil {
			return r.fail(ctx, op, err)
		}
	}
	return r.Ops.SetState(ctx, op.ID, StateCompleted, "")
}

func (r *Reseed) preflight(ctx context.Context, op Operation) error {
	o := r.Observe(ctx)
	switch {
	case o.IsActive():
		return fmt.Errorf("node is active — the serving ACTIVE cannot be reseeded")
	case !o.Local.AgentOK:
		return fmt.Errorf("local agent is unavailable")
	case !o.Peer.Reachable || o.Peer.Stale:
		return fmt.Errorf("source is not observed — there is nothing to reseed from")
	case o.Peer.Role != "active":
		return fmt.Errorf("peer is not active — no source for a reseed")
	case o.Peer.MaxSeenEpoch == nil:
		return fmt.Errorf("peer epoch is unknown")
	case op.Epoch != *o.Peer.MaxSeenEpoch:
		// A reseed runs in the pair's current epoch; a mismatch means the pair moved on and the
		// operation's premises no longer hold.
		return fmt.Errorf("operation is at epoch %d, the pair at %d", op.Epoch, *o.Peer.MaxSeenEpoch)
	case !o.Config.AgreesWithPeer(o.Peer):
		return fmt.Errorf("the two sides disagree on configuration")
	}
	return nil
}

func (r *Reseed) acceptEpoch(op Operation) error {
	_, err := r.Safety.Update(func(st *safety.State) error {
		if st.MaxSeenEpoch == nil || *st.MaxSeenEpoch < op.Epoch {
			e := op.Epoch
			st.MaxSeenEpoch = &e
		}
		// No authority: the node returns as a replica. Leftover proof from before is the most dangerous
		// thing here, since it belongs to an epoch that no longer exists.
		st.Authority = nil
		st.Handoff = nil
		return nil
	})
	return err
}

func (r *Reseed) verify(ctx context.Context) error {
	want, _ := r.Observe(ctx).ExpectedReplicationSource()
	return awaitState(ctx, r.Observe, r.Wait, r.AwaitTimeout, func(o observe.Observation) bool {
		return o.Local.ReadOnly != nil && *o.Local.ReadOnly == 1 &&
			o.Replication.Observed && o.Replication.IORunning == "Yes" && o.Replication.SQLRunning == "Yes" &&
			(want == "" || o.Replication.MasterHost == want)
	}, "node did not become a healthy replica of the source")
}

func (r *Reseed) unfence(ctx context.Context, op Operation) error {
	ack, err := r.call(ctx, peer.CmdClearFencing, "reseed-unfence-"+op.ID, op.Epoch,
		peer.ClearFencingPayload{OperationID: op.ID, Node: r.NodeID, Epoch: op.Epoch})
	if err != nil {
		return err
	}
	if !ack.Accepted {
		return fmt.Errorf("fencing was not cleared: %s", ack.Reason)
	}
	return nil
}

func (r *Reseed) call(ctx context.Context, cmd, messageID string, epoch int64, payload any) (peer.OpAck, error) {
	if r.Call != nil {
		return r.Call(cmd, messageID, epoch, payload)
	}
	var ack peer.OpAck
	cfg := *r.Peer
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

func (r *Reseed) step(ctx context.Context, opID, name, node string, run func() error) error {
	return recordStep(ctx, r.Ops, opID, name, node, run)
}

func (r *Reseed) agentStep(ctx context.Context, opID, name, node string,
	run func() (agent.CommandResult, error)) error {
	return recordAgentStep(ctx, r.Ops, opID, name, node, run)
}

func (r *Reseed) abort(ctx context.Context, op Operation, cause error) error {
	_ = r.Ops.SetState(ctx, op.ID, StateAborted, cause.Error())
	return fmt.Errorf("reseed rolled back: %w", cause)
}

func (r *Reseed) fail(ctx context.Context, op Operation, cause error) error {
	_ = r.Ops.SetState(ctx, op.ID, StateFailed, cause.Error())
	return fmt.Errorf("reseed did not finish: %w", cause)
}
