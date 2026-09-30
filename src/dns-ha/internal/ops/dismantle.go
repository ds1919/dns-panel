package ops

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"dnspanel/dns-ha/internal/agent"
	"dnspanel/dns-ha/internal/observe"
	"dnspanel/dns-ha/internal/peer"
)

// Planned DISMANTLE of the pair: HA is turned off and each node serves itself again.
//
// The nodes do NOT become standalone; the pairing stays. Product states:
//
//	Standalone → (Pair) → Paired · HA not configured → (Configure HA) → Paired · HA active
//
// Dismantle moves exactly one step left, to "Paired · HA not configured". Going back to Standalone is a
// separate decision ("Undo pairing") with its own button. This makes HA a setting rather than a one-way
// state, and lets the publication mode (Floating IP → Anycast) change by rebuilding the pair the same
// way it was created instead of switching providers on a live pair.
//
// DATA IS UNTOUCHED: zones, records, users, catalogs and settings stay on BOTH nodes; after the drain
// both databases hold the same copy and simply diverge from then on.
//
// Steps:
//
//	preflight       — pair healthy, I am ACTIVE, peer reachable and STANDBY, no other operation
//	freeze_writes   — I stop accepting writes (read_only=1)
//	drain_gtid      — peer applied EVERYTHING I wrote (otherwise the last changes would be lost)
//	peer_release    — peer: stop replication, drop fail-safe, become writable, serve zones, drop address
//	local_release   — me: withdraw the publication (the pair address no longer exists), stay writable
//	verify          — HA off on both and both writable; checked BEFORE the channel goes away
//
// Local cleanup runs last and is not journaled: it erases the journal itself.
//
// Trust between the machines is NOT touched; that is "Undo pairing". Two standalone servers still know
// each other and can be re-paired (e.g. in Anycast mode), and we avoid "delete the channel, then confirm
// over it that you deleted it". Everything that needs both sides is checked in verify, before that line.
const (
	StepDismantlePreflight = "preflight"
	StepDismantleFreeze    = "freeze_writes"
	StepDismantleDrain     = "drain_gtid"
	StepDismantlePeerRel   = "peer_release"
	StepDismantleLocalRel  = "local_release"
	StepDismantleVerify    = "verify"
)

// KindDismantle is the journal operation kind.
const KindDismantle = "dismantle"

// DismantleMutator is the set of primitives dismantle needs on its OWN node.
type DismantleMutator interface {
	ReleasePublication(ctx context.Context, op agent.Op, address, device string) (agent.CommandResult, error)
	StopReplication(ctx context.Context, op agent.Op) (agent.CommandResult, error)
	EnableNotifier(ctx context.Context, op agent.Op) (agent.CommandResult, error)
	// Demote/Promote freeze writes for the drain and restore them afterwards.
	Demote(ctx context.Context, op agent.Op) (agent.CommandResult, error)
	Promote(ctx context.Context, op agent.Op) (agent.CommandResult, error)
}

// Dismantle runs the dismantle on the ACTIVE side.
type Dismantle struct {
	NodeID  string
	Ops     Store
	Mutator DismantleMutator
	// Call replaces Peer in tests.
	Peer    *peer.ClientConfig
	Call    func(cmd, messageID string, epoch int64, payload any) (peer.OpAck, error)
	Observe func(context.Context) observe.Observation
	// Forget removes pair records on THIS node (local dns_ha pair data, epoch, safety); trust and the
	// channel key stay. A func so the state machine can be tested without a database.
	Forget func(ctx context.Context) error
	// Failsafe drops our own fail-safe. It lives outside the mutation contract (a MariaDB config file,
	// not a pair action), and is a func so the state machine can be tested without the agent.
	Failsafe     func(ctx context.Context) (agent.CommandResult, error)
	Wait         func(time.Duration)
	AwaitTimeout time.Duration
}

// Run drives the dismantle to completion or to a typed refusal.
func (d *Dismantle) Run(ctx context.Context, op Operation) error {
	steps, err := d.Ops.Steps(ctx, op.ID)
	if err != nil {
		return err
	}
	done := func(name string) bool { return d.Ops.Done(steps, name) }

	// The epoch does not change: nobody hands over the role, the same node stays active, only the pair
	// goes away.
	epoch := op.Epoch
	if e := d.Observe(ctx).Safety.MaxSeenEpoch; e != nil && *e > epoch {
		epoch = *e
	}
	aop := agent.Op{OperationID: op.ID, ClusterEpoch: epoch}

	if err := d.Ops.SetState(ctx, op.ID, StateRunning, ""); err != nil {
		return err
	}

	if !done(StepDismantlePreflight) {
		if err := d.step(ctx, op.ID, StepDismantlePreflight, d.NodeID, func() error { return d.preflight(ctx) }); err != nil {
			return d.abort(ctx, op, err)
		}
	}

	// Writes stop BEFORE the drain. The drain proves the peer applied the position taken at that
	// moment; if we kept accepting writes, transactions X+1, X+2… would never reach the peer once
	// replication is gone, and the databases would silently diverge. Same as a planned switchover:
	// stop writing first, then prove.
	if !done(StepDismantleFreeze) {
		if err := d.agentStep(ctx, op.ID, StepDismantleFreeze, d.NodeID, func() (agent.CommandResult, error) {
			return d.Mutator.Demote(ctx, aop)
		}); err != nil {
			return d.abort(ctx, op, err)
		}
	}

	// Drain: the peer must have EVERY one of our transactions; after dismantle there is no replication
	// to catch up.
	if !done(StepDismantleDrain) {
		if err := d.step(ctx, op.ID, StepDismantleDrain, op.TargetNode, func() error { return d.drain(ctx, op) }); err != nil {
			// Dismantle did not happen, so the node must accept writes again; leaving it frozen would stop
			// the service over a cancelled operation.
			d.unfreeze(ctx, op, aop)
			return d.abort(ctx, op, err)
		}
	}

	// From here on the dismantle is only driven FORWARD.
	//
	// peer_release turns the peer into a standalone server, and part of that (replication stopped,
	// fail-safe dropped) cannot meaningfully be undone. So a failure is not ABORTED: every action is
	// idempotent (no replication → noop, fail-safe gone → noop) and the next loop simply retries.
	// ABORTED would mean the manager never comes back to it.
	if !done(StepDismantlePeerRel) {
		if err := d.step(ctx, op.ID, StepDismantlePeerRel, op.TargetNode, func() error {
			addr, dev := d.pubTarget(ctx, op.TargetNode)
			ack, err := d.call(ctx, peer.CmdReleasePair, op.ID+":release", epoch,
				peer.DismantlePayload{OperationID: op.ID, Address: addr, Device: dev})
			if err != nil {
				return err
			}
			if !ack.Applied {
				return fmt.Errorf("the other node did not become standalone: %s", reasonOr(ack.Reason))
			}
			return nil
		}); err != nil {
			return d.retry(op, err)
		}
	}

	if !done(StepDismantleLocalRel) {
		if err := d.agentStep(ctx, op.ID, StepDismantleLocalRel, d.NodeID, func() (agent.CommandResult, error) {
			// Our own replication config too: an ACTIVE that was STANDBY before a switchover keeps a stopped
			// "replica of peer" config. With fail-safe dropped below, it would start by itself on the next
			// MariaDB restart and two standalone nodes would replicate into each other. Seen live
			// 2026-09-25 (eq after dismantle: Master_Host=de, IO/SQL=No). Absent → noop.
			if res, err := d.Mutator.StopReplication(ctx, aop); err != nil || !res.OK {
				return res, err
			}
			// Re-enable writes: the node serves on its own again instead of standing as a frozen ACTIVE.
			if res, err := d.Mutator.Promote(ctx, aop); err != nil || !res.OK {
				return res, err
			}
			// The node keeps serving zones: it remains the source for its own secondaries; only the pair
			// service address goes away.
			if res, err := d.Mutator.EnableNotifier(ctx, aop); err != nil || !res.OK {
				return res, err
			}
			// Drop fail-safe here too, not only on the peer: it is on BOTH nodes (verified live: the
			// 61-dns-panel-ha.cnf symlink exists on the ACTIVE too). Left in place, the next MariaDB restart
			// would bring the "standalone" node up read_only=ON, silently refusing writes.
			if d.Failsafe != nil {
				if res, err := d.Failsafe(ctx); err != nil || !res.OK {
					return res, err
				}
			}
			addr, dev := d.pubTarget(ctx, d.NodeID)
			return d.Mutator.ReleasePublication(ctx, aop, addr, dev)
		}); err != nil {
			return d.retry(op, err)
		}
	}

	// Last check while the channel is still alive: both nodes are standalone.
	if !done(StepDismantleVerify) {
		if err := d.step(ctx, op.ID, StepDismantleVerify, d.NodeID, func() error { return d.verify(ctx) }); err != nil {
			return d.retry(op, err)
		}
	}

	// Only local cleanup is left; the peer already removed its pair records in the step that made it
	// standalone.
	//
	// A failure here is not a failed dismantle: both nodes already run standalone. The operation stays
	// RUNNING and the next loop retries; FAILED would mean the manager never returns to it (Current()
	// only picks PENDING/RUNNING).
	//
	// The cleanup is not journaled and needs no SetState: it erases the pair records together with the
	// operation journal, so a "journal erased" step would be an orphan row and SetState would update
	// zero rows. The operation disappearing is the normal end of dismantle.
	//
	// A failure is safe to retry: the cleanup transaction did not commit, so the operation and the
	// peer's recorded step are still there and the next loop repeats only the local part.
	if d.Forget == nil {
		return fmt.Errorf("dismantle: no way to forget the pair locally")
	}
	if err := d.Forget(ctx); err != nil {
		return fmt.Errorf("dismantling: local cleanup will be retried: %w", err)
	}
	return nil
}

// preflight allows dismantling only a HEALTHY pair, and only from the ACTIVE.
//
// A dead peer is not a dismantle but an emergency, which needs a deliberate human decision about the
// data; the two must not share a button.
//
// Replication state is deliberately not checked: o.Replication describes THIS node as a replica, and
// an ACTIVE always shows IO=No SQL=No, so the check would reject a perfectly healthy pair (as it did on
// the live .69). The real guarantee is the drain: the peer must PROVE it applied our position, and
// stopped replication fails that by waiting, not by assumption.
func (d *Dismantle) preflight(ctx context.Context) error {
	o := d.Observe(ctx)
	switch {
	case !o.IsActive():
		return fmt.Errorf("dismantling is done from the ACTIVE node")
	case o.Config.PayloadHash == "":
		return fmt.Errorf("this node has no effective configuration revision")
	case !o.Peer.Reachable:
		return fmt.Errorf("the other node is not reachable — a broken pair is taken apart by recovery, not by this operation")
	case o.Peer.Stale:
		return fmt.Errorf("the state of the other node is stale")
	case o.Peer.Role == "active":
		return fmt.Errorf("both nodes report the ACTIVE role")
	case o.Peer.ConfigHash != "" && o.Peer.ConfigHash != o.Config.PayloadHash:
		return fmt.Errorf("the nodes have different configuration revisions")
	case o.Local.ReadOnly != nil && *o.Local.ReadOnly != 0:
		return fmt.Errorf("this node is read-only")
	}
	return nil
}

// drain requires the peer to apply everything we wrote.
func (d *Dismantle) drain(ctx context.Context, op Operation) error {
	o := d.Observe(ctx)
	if !o.Replication.GTIDBinlogPosKnown {
		return fmt.Errorf("own GTID position is unknown — there is no way to prove the other node caught up")
	}
	pos := o.Replication.GTIDBinlogPos
	if pos == "" {
		// Empty position: we have written no transactions (a freshly created pair), nothing to apply.
		return nil
	}
	ack, err := d.call(ctx, peer.CmdAwaitGTID, op.ID+":drain", op.Epoch,
		peer.AwaitGTIDPayload{OperationID: op.ID, Position: pos, TimeoutSeconds: 60})
	if err != nil {
		return err
	}
	if !ack.Applied {
		return fmt.Errorf("the other node has not applied everything written here: %s", reasonOr(ack.Reason))
	}
	return nil
}

// verify checks that HA is off on BOTH nodes: both accept writes, serve zones and are not linked by
// replication.
//
// Not "both became standalone": dismantle keeps the pairing, and "Standalone" means trust removed.
func (d *Dismantle) verify(ctx context.Context) error {
	// Use the operation context, not Background: the wait must be cancelled with the operation.
	return awaitState(ctx, d.Observe, d.Wait, d.AwaitTimeout, func(o observe.Observation) bool {
		if o.Local.ReadOnly == nil || *o.Local.ReadOnly != 0 {
			return false
		}
		if o.Local.RouteAnnounced != nil && *o.Local.RouteAnnounced != 0 {
			return false
		}
		// No local replication either: a stopped but not removed config would revive on MariaDB restart.
		if !o.Replication.Observed || o.Replication.Configured {
			return false
		}
		return o.Peer.Reachable && o.Peer.ReadOnly != nil && *o.Peer.ReadOnly == 0
	}, "HA is off on both nodes and both accept writes")
}

// pubTarget returns the pair address and interface of a SPECIFIC node from the current revision.
func (d *Dismantle) pubTarget(ctx context.Context, nodeID string) (string, string) {
	addr, dev := d.Observe(ctx).Config.Payload.PublicationTargetOf(nodeID)
	return addr, dev
}

func (d *Dismantle) step(ctx context.Context, opID, name, node string, run func() error) error {
	return recordStep(ctx, d.Ops, opID, name, node, run)
}

func (d *Dismantle) agentStep(ctx context.Context, opID, name, node string,
	run func() (agent.CommandResult, error)) error {
	return recordAgentStep(ctx, d.Ops, opID, name, node, run)
}

func (d *Dismantle) abort(ctx context.Context, op Operation, cause error) error {
	_ = d.Ops.SetState(ctx, op.ID, StateAborted, cause.Error())
	return fmt.Errorf("dismantling was not started: %w", cause)
}

// unfreeze restores writes after a cancelled dismantle.
//
// It is recorded as a step so the journal shows the node was unfrozen, not only that dismantle was
// cancelled. A failure is recorded too, and convergence restores the node: its ACTIVE authority was
// never taken away.
func (d *Dismantle) unfreeze(ctx context.Context, op Operation, aop agent.Op) {
	if d.Mutator == nil {
		return
	}
	_ = d.agentStep(ctx, op.ID, "unfreeze_writes", d.NodeID, func() (agent.CommandResult, error) {
		return d.Mutator.Promote(ctx, aop)
	})
}

// retry handles a failure AFTER the point of no return. The state is left RUNNING so the next loop
// retries the step; FAILED would mean the manager never returns to it (Current() only picks
// PENDING/RUNNING), leaving a half-released peer.
func (d *Dismantle) retry(op Operation, cause error) error {
	return fmt.Errorf("dismantling %s will be retried: %w", op.ID, cause)
}

// call sends a request to the peer: the test stub if set, otherwise the real pair channel.
func (d *Dismantle) call(ctx context.Context, cmd, messageID string, epoch int64, payload any) (peer.OpAck, error) {
	if d.Call != nil {
		return d.Call(cmd, messageID, epoch, payload)
	}
	var ack peer.OpAck
	if d.Peer == nil {
		return ack, fmt.Errorf("no channel to the other node")
	}
	cfg := *d.Peer
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

func reasonOr(s string) string {
	if s == "" {
		return "no reason given"
	}
	return s
}
