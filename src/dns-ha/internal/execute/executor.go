// Package execute runs an already-built mutation plan.
//
// Nothing is DECIDED here; the decision is made upstream and fixed in the plan:
//
//	Observation → planner.Plan → shadow.Build → MutationPlan → execute → agent.Mutator
//
// So there are no read_only checks, replication source choices or permission logic here: any of them
// would be a second decision point that would eventually disagree with the first.
package execute

import (
	"context"
	"fmt"
	"sync/atomic"

	"dnspanel/dns-ha/internal/agent"
	"dnspanel/dns-ha/internal/planner"
	"dnspanel/dns-ha/internal/shadow"
)

// Mutator is the subset of the agent the executor needs; an interface also makes it explicit that
// nothing else can be called.
type Mutator interface {
	Promote(ctx context.Context, op agent.Op) (agent.CommandResult, error)
	Demote(ctx context.Context, op agent.Op) (agent.CommandResult, error)
	EnableNotifier(ctx context.Context, op agent.Op) (agent.CommandResult, error)
	DisableNotifier(ctx context.Context, op agent.Op) (agent.CommandResult, error)
	AnnouncePanel(ctx context.Context, op agent.Op, address, device, provider string) (agent.CommandResult, error)
	WithdrawPanel(ctx context.Context, op agent.Op, address, device, provider string) (agent.CommandResult, error)
	RejoinReplica(ctx context.Context, op agent.Op, primary string, seedFromBinlog bool) (agent.CommandResult, error)
	// DropAddress only cleans up a PAST anycast address, so it has no epoch by design.
	DropAddress(ctx context.Context, address, device string) (agent.CommandResult, error)
}

const (
	OutcomeNothingToDo    = "nothing_to_do"   // steady state
	OutcomeBlocked        = "blocked"         // no plan or no operation context
	OutcomeDone           = "done"            // all steps done
	OutcomeFailed         = "failed"          // protective steps: some failed (the rest still ran)
	OutcomeRolledBack     = "rolled_back"     // promotion aborted and rolled back
	OutcomeNeedsReobserve = "needs_reobserve" // replied, but the node state is not proven
)

// StepResult is the result of one step.
type StepResult struct {
	Command     string `json:"command"`
	OK          bool   `json:"ok"`
	Noop        bool   `json:"noop,omitempty"`
	StateProven bool   `json:"state_proven"`
	Error       string `json:"error,omitempty"`
}

// Outcome is the result of executing a plan.
type Outcome struct {
	Action   planner.Action `json:"action"`
	Status   string         `json:"status"`
	Steps    []StepResult   `json:"steps,omitempty"`
	Rollback []StepResult   `json:"rollback,omitempty"`
	Reason   string         `json:"reason,omitempty"`
}

// Executor executes plans.
type Executor struct {
	// Enabled is the master switch: while false, NO agent call is made. It separates "able to execute"
	// from "allowed to execute"; it is not a debug flag.
	Enabled bool
	Mutator Mutator

	attempted atomic.Int64 // mutation calls attempted (live check that disabled mode really calls nothing)
}

// Attempted returns the number of mutations attempted in this process.
func (e *Executor) Attempted() int64 { return e.attempted.Load() }

// Execute runs the plan. Step failures are part of the Outcome, not returned as error.
func (e *Executor) Execute(ctx context.Context, p shadow.MutationPlan, op agent.Op) Outcome {
	out := Outcome{Action: p.Action}
	switch {
	case p.Blocked != "":
		out.Status, out.Reason = OutcomeBlocked, p.Blocked
		return out
	case p.Empty():
		out.Status = OutcomeNothingToDo
		return out
	case e.Mutator == nil:
		out.Status, out.Reason = OutcomeBlocked, "executor without an agent client"
		return out
	case op.OperationID == "" || op.ClusterEpoch < 0 || (op.ClusterEpoch == 0 && !op.NoHAConfig):
		// Fail-closed: without operation context a retry would be a new action in someone else's epoch.
		// The single exception is DECLARED, not inferred from epoch 0: without HA there is no epoch
		// (see agent.Op.NoHAConfig).
		out.Status, out.Reason = OutcomeBlocked, "no operation_id/cluster_epoch"
		return out
	}

	if p.StopOnError {
		return e.sequential(ctx, p, op, out)
	}
	return e.protective(ctx, p, op, out)
}

// protective runs ALL steps independently: one failure does not cancel the rest, since the node must stop
// being dangerous by every available means.
func (e *Executor) protective(ctx context.Context, p shadow.MutationPlan, op agent.Op, out Outcome) Outcome {
	ok := true
	for _, s := range p.Steps {
		r := e.step(ctx, s, op)
		out.Steps = append(out.Steps, r)
		if !r.OK {
			ok = false
		}
	}
	if ok {
		out.Status = OutcomeDone
	} else {
		out.Status, out.Reason = OutcomeFailed, "some protective steps were not carried out"
	}
	return out
}

// sequential runs promoting steps in order, stopping at the first failure OR first uncertainty.
//
// Uncertainty is a success that does NOT prove node state (a durable agent retry answers from its journal
// without looking at the node). Continuing would build the next step on an assumption, so we roll back to the
// safe side and ask for a fresh observation; the loop returns here with proven state.
func (e *Executor) sequential(ctx context.Context, p shadow.MutationPlan, op agent.Op, out Outcome) Outcome {
	for _, s := range p.Steps {
		r := e.step(ctx, s, op)
		out.Steps = append(out.Steps, r)
		if !r.OK {
			out.Status, out.Reason = OutcomeRolledBack, "step "+s.Command+" was not carried out: "+r.Error
			out.Rollback = e.rollback(ctx, p, op)
			return out
		}
		if !r.StateProven {
			out.Status = OutcomeNeedsReobserve
			out.Reason = "the response to " + s.Command + " does not prove the state of the node"
			out.Rollback = e.rollback(ctx, p, op)
			return out
		}
	}
	out.Status = OutcomeDone
	return out
}

// rollback returns to the safe side and, like protective steps, runs every step regardless of failures.
func (e *Executor) rollback(ctx context.Context, p shadow.MutationPlan, op agent.Op) []StepResult {
	var res []StepResult
	// Rollback is a SEPARATE operation: under the same operation_id the agent would answer from its journal
	// and do nothing. NoHAConfig is inherited: same node, same (absent) epoch as the plan.
	rop := agent.Op{OperationID: op.OperationID + "-rollback", ClusterEpoch: op.ClusterEpoch, NoHAConfig: op.NoHAConfig}
	for _, s := range p.Rollback {
		res = append(res, e.step(ctx, s, rop))
	}
	return res
}

// step is the only place a primitive name becomes a method call; nothing beyond this list can be called.
func (e *Executor) step(ctx context.Context, s shadow.Step, op agent.Op) StepResult {
	e.attempted.Add(1)
	var (
		res agent.CommandResult
		err error
	)
	switch s.Command {
	case shadow.CmdPromote:
		res, err = e.Mutator.Promote(ctx, op)
	case shadow.CmdDemote:
		res, err = e.Mutator.Demote(ctx, op)
	case shadow.CmdEnableNotifier:
		res, err = e.Mutator.EnableNotifier(ctx, op)
	case shadow.CmdDisableNotifier:
		res, err = e.Mutator.DisableNotifier(ctx, op)
	case shadow.CmdAnnouncePanel:
		res, err = e.Mutator.AnnouncePanel(ctx, op, s.PubAddress, s.PubDevice, s.PubProvider)
	case shadow.CmdWithdrawPanel:
		res, err = e.Mutator.WithdrawPanel(ctx, op, s.PubAddress, s.PubDevice, s.PubProvider)
	case shadow.CmdDropAddress:
		res, err = e.Mutator.DropAddress(ctx, s.PubAddress, s.PubDevice)
	case shadow.CmdRejoinReplica:
		// Regular convergence proved nothing about the source position, so resume from the replica's saved
		// position: skipping unreceived events would be silent data loss.
		res, err = e.Mutator.RejoinReplica(ctx, op, s.Primary, false)
	default:
		return StepResult{Command: s.Command, Error: fmt.Sprintf("unknown primitive %q", s.Command)}
	}
	if err != nil {
		// Link error: node state is UNKNOWN, unlike a typed agent refusal.
		return StepResult{Command: s.Command, Error: err.Error()}
	}
	out := StepResult{Command: s.Command, OK: res.OK, Noop: res.Noop, StateProven: res.StateProven, Error: res.Error}
	if !res.OK && res.Message != "" {
		out.Error = res.Error + ": " + res.Message
	}
	return out
}
