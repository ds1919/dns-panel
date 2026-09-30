package ops

import (
	"context"
	"fmt"
	"time"

	"dnspanel/dns-ha/internal/agent"
	"dnspanel/dns-ha/internal/observe"
	"dnspanel/dns-ha/internal/safety"
)

// Emergency promotion. The one difference from a planned switchover is that the old ACTIVE does not
// take part, so nobody can prove it is stopped: the OPERATOR asserts it, and the assertion is recorded.
//
// There is no automatic emergency promotion by design: a two-node pair cannot tell "peer died" from
// "network between us broke". In the first case promotion saves the service, in the second it creates
// a second ACTIVE with diverging data. A human decides; the system makes it safe and leaves a trail.
const (
	StepFenceRecord       = "fence_record"
	StepRelayLossAccepted = "relay_loss_accepted"
	StepEmergencyPromote  = "emergency_promote"
	StepEnableNotifier    = "enable_notifier"
	StepAnnouncePanel     = "announce_panel"
)

// Operator ack types. They are deliberately distinct: "I stopped its database" and "I powered off the
// host" are different grounds, and the journal must record which one it was.
const (
	AckDatabaseStopped = "old_active_database_stopped" // old ACTIVE's database is provably stopped
	AckHostDown        = "old_active_host_down"        // host is off/unreachable at the infrastructure level
	AckIsolated        = "operator_isolated"           // operator isolated the node manually
)

var validAcks = map[string]bool{AckDatabaseStopped: true, AckHostDown: true, AckIsolated: true}

// ValidAck reports whether the ack type is known.
func ValidAck(a string) bool { return validAcks[a] }

// Emergency is an emergency promotion run on the surviving node.
type Emergency struct {
	NodeID  string
	Ops     Store
	Safety  *safety.Store
	Mutator EmergencyMutator
	Observe func(context.Context) observe.Observation
	Wait    func(time.Duration)

	AwaitTimeout time.Duration
	// Ack is the operator's typed confirmation that the old ACTIVE is down.
	Ack string
	// Operator is who made the decision; it goes into the durable record.
	Operator string
	// AcceptRelayLoss lets the promotion proceed even if the relay-log drain cannot be proven.
	// This is DATA LOSS and is off by default.
	AcceptRelayLoss bool
}

// EmergencyMutator is the subset of the agent an emergency promotion needs.
type EmergencyMutator interface {
	EmergencyPromote(ctx context.Context, op agent.Op, acceptRelayLoss bool) (agent.CommandResult, error)
	EnableNotifier(ctx context.Context, op agent.Op) (agent.CommandResult, error)
	AnnouncePanel(ctx context.Context, op agent.Op, address, device, provider string) (agent.CommandResult, error)
}

// Run performs the emergency promotion.
func (e *Emergency) Run(ctx context.Context, op Operation) error {
	steps, err := e.Ops.Steps(ctx, op.ID)
	if err != nil {
		return err
	}
	done := func(name string) bool { return e.Ops.Done(steps, name) }
	aop := agent.Op{OperationID: op.ID, ClusterEpoch: op.Epoch}

	if err := e.Ops.SetState(ctx, op.ID, StateRunning, ""); err != nil {
		return err
	}
	if !done(StepPreflightLocal) {
		if err := e.step(ctx, op.ID, StepPreflightLocal, e.NodeID, func() error { return e.preflight(ctx, op) }); err != nil {
			return e.abort(ctx, op, err)
		}
	}

	// Point of no return and the only guard against split-brain: epoch, authority and fencing of the old
	// ACTIVE are written durably BEFORE the node becomes writable. In the reverse order a sudden reboot
	// would leave a writable node that remembers neither the new epoch nor the fencing, and a returning
	// peer would never learn of the transition: two ACTIVE nodes with diverged data.
	if !done(StepFenceRecord) {
		if err := e.step(ctx, op.ID, StepFenceRecord, e.NodeID, func() error { return e.recordFencing(op) }); err != nil {
			return e.abort(ctx, op, err)
		}
	}

	// Record consent to losing the relay tail durably BEFORE the dangerous step, every time it changes;
	// otherwise safety would say "no loss allowed" while the tail was actually discarded.
	if e.AcceptRelayLoss {
		if err := e.step(ctx, op.ID, StepRelayLossAccepted, e.NodeID, func() error {
			return e.recordRelayLossAccepted(op)
		}); err != nil {
			return e.fail(ctx, op, err)
		}
	}

	for _, st := range []struct {
		name string
		run  func() (agent.CommandResult, error)
	}{
		// The agent drains the relay log and promotes under ONE lock: separate calls would leave a window
		// where a stray rejoin restarts replication and builds a new backlog that promote silently drops.
		{StepEmergencyPromote, func() (agent.CommandResult, error) {
			return e.Mutator.EmergencyPromote(ctx, aop, e.AcceptRelayLoss)
		}},
		{StepEnableNotifier, func() (agent.CommandResult, error) { return e.Mutator.EnableNotifier(ctx, aop) }},
		{StepAnnouncePanel, func() (agent.CommandResult, error) {
			addr, dev, provider := e.Observe(ctx).Config.Payload.PublicationOf(e.NodeID)
			return e.Mutator.AnnouncePanel(ctx, aop, addr, dev, provider)
		}},
	} {
		if done(st.name) {
			continue
		}
		if err := e.agentStep(ctx, op.ID, st.name, e.NodeID, st.run); err != nil {
			// No rollback: the authority is already ours and the old ACTIVE is not answering.
			// A human sorts out an incomplete promotion; the node stays where it got to.
			return e.fail(ctx, op, err)
		}
	}

	if err := e.step(ctx, op.ID, StepVerify, e.NodeID, func() error { return e.verify(ctx) }); err != nil {
		return e.fail(ctx, op, err)
	}
	return e.Ops.SetState(ctx, op.ID, StateCompleted, "")
}

func (e *Emergency) preflight(ctx context.Context, op Operation) error {
	o := e.Observe(ctx)
	switch {
	case !ValidAck(e.Ack):
		return fmt.Errorf("a typed operator ack is required (%s|%s|%s)", AckDatabaseStopped, AckHostDown, AckIsolated)
	case e.Operator == "":
		return fmt.Errorf("emergency promote must name who requested it")
	case o.IsActive():
		return fmt.Errorf("node is already active — nothing to promote")
	case o.Safety.MaxSeenEpoch == nil:
		return fmt.Errorf("epoch is unknown")
	case op.Epoch != *o.Safety.MaxSeenEpoch+1:
		return fmt.Errorf("operation epoch %d, expected %d", op.Epoch, *o.Safety.MaxSeenEpoch+1)
	case o.Safety.FencedNode == e.NodeID:
		return fmt.Errorf("this node is fenced itself and needs a reseed")
	case !o.Local.AgentOK:
		return fmt.Errorf("local agent is unavailable")
	case o.Peer.Reachable && !o.Peer.Stale && o.Peer.Role == "active" && o.Peer.ServiceReady:
		// Refuse ONLY if the peer provably SERVES: fresh snapshot, thinks it is active, and reports
		// service_ready. Taking the role from a working node is a planned switchover.
		//
		// "Peer answers but does not serve" is exactly the case emergency exists for: the manager process
		// is alive and reporting while its database is down. Requiring full silence here would make the
		// most common failure unrecoverable.
		return fmt.Errorf("the peer answers and is SERVING (service_ready) — this is a planned switchover, not an emergency")
	}
	return nil
}

// recordFencing durably grants this node authority and fences the old ACTIVE.
func (e *Emergency) recordFencing(op Operation) error {
	_, err := e.Safety.Update(func(st *safety.State) error {
		if st.MaxSeenEpoch == nil || *st.MaxSeenEpoch < op.Epoch {
			ep := op.Epoch
			st.MaxSeenEpoch = &ep
		}
		ep := op.Epoch
		st.Authority = &safety.Authority{Type: safety.AuthorityEmergency, Epoch: &ep, Role: "active",
			IssuedAt: time.Now().UTC().Format(time.RFC3339), Source: e.Operator}
		// Fencing is a safety condition, not a note: on return the old ACTIVE sees it in our state and
		// neither promotes itself nor rejoins as a replica on its own.
		st.Fenced = op.TargetNode
		st.Emergency = emergencyRecord(op, e.Ack, e.Operator, e.AcceptRelayLoss)
		st.Handoff = nil
		return nil
	})
	return err
}

// recordRelayLossAccepted updates the durable record: the operator accepted losing the relay tail.
func (e *Emergency) recordRelayLossAccepted(op Operation) error {
	_, err := e.Safety.Update(func(st *safety.State) error {
		st.Emergency = emergencyRecord(op, e.Ack, e.Operator, true)
		return nil
	})
	return err
}

func (e *Emergency) verify(ctx context.Context) error {
	return awaitState(ctx, e.Observe, e.Wait, e.AwaitTimeout, func(o observe.Observation) bool {
		return o.Local.PhysicallyActive() && o.IsActive()
	}, "node did not confirm it became active")
}

func (e *Emergency) step(ctx context.Context, opID, name, node string, run func() error) error {
	return recordStep(ctx, e.Ops, opID, name, node, run)
}

func (e *Emergency) agentStep(ctx context.Context, opID, name, node string,
	run func() (agent.CommandResult, error)) error {
	return recordAgentStep(ctx, e.Ops, opID, name, node, run)
}

func (e *Emergency) abort(ctx context.Context, op Operation, cause error) error {
	_ = e.Ops.SetState(ctx, op.ID, StateAborted, cause.Error())
	return fmt.Errorf("emergency promote rolled back: %w", cause)
}

func (e *Emergency) fail(ctx context.Context, op Operation, cause error) error {
	_ = e.Ops.SetState(ctx, op.ID, StateFailed, cause.Error())
	return fmt.Errorf("emergency promote did not finish: %w", cause)
}
