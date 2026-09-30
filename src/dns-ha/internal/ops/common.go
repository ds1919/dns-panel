package ops

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"dnspanel/dns-ha/internal/agent"
	"dnspanel/dns-ha/internal/observe"
	"dnspanel/dns-ha/internal/safety"
)

func recordStep(ctx context.Context, st Store, opID, name, node string, run func() error) error {
	err := run()
	rec := StepResult{Step: name, NodeID: node, OK: err == nil, StateProven: err == nil}
	if err != nil {
		rec.Error = err.Error()
	}
	_ = st.RecordStep(ctx, opID, rec)
	return err
}

// recordAgentStep records a step run by the agent. A reply that did not prove the physical state (a durable
// replay) counts as success but is recorded as unproven: the next step relies on a fresh observation anyway.
func recordAgentStep(ctx context.Context, st Store, opID, name, node string,
	run func() (agent.CommandResult, error)) error {
	res, err := run()
	rec := StepResult{Step: name, NodeID: node, Noop: res.Noop, StateProven: res.StateProven}
	switch {
	case err != nil:
		rec.Error = err.Error()
	case !res.OK:
		// Keep code and message together: the code alone rarely explains the cause.
		rec.Error = res.Error
		if res.Message != "" {
			rec.Error = res.Error + ": " + res.Message
		}
	default:
		rec.OK = true
	}
	if len(res.Status) > 0 {
		rec.Detail = string(res.Status)
	}
	_ = st.RecordStep(ctx, opID, rec)
	if rec.Error != "" {
		return fmt.Errorf("%s: %s", name, rec.Error)
	}
	return nil
}

// awaitState waits until an observation confirms the condition. The wait is bounded: waiting forever
// would leave the pair stuck in an intermediate state with no error reported.
func awaitState(ctx context.Context, observeFn func(context.Context) observe.Observation, wait func(time.Duration),
	limit time.Duration, ok func(observe.Observation) bool, what string) error {
	if limit <= 0 {
		limit = 60 * time.Second
	}
	// The limit is a context deadline, not a timestamp checked between rounds: an observation calls the
	// peer over the network, and a time check after a stalled call bounds nothing.
	parent := ctx
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	for {
		// Check cancellation before observing, on every path (including the injected wait).
		if err := ctx.Err(); err != nil {
			if parent.Err() != nil {
				return parent.Err()
			}
			return fmt.Errorf("%s", what)
		}
		o := observeFn(ctx)
		if ctx.Err() != nil {
			// An interrupted observation is not proof, whatever it looks like. Our own deadline means
			// "state not confirmed"; a parent cancellation means "interrupted".
			if parent.Err() != nil {
				return parent.Err()
			}
			return fmt.Errorf("%s", what)
		}
		if ok(o) {
			return nil
		}
		if wait != nil {
			wait(time.Second) // test seam: no real sleep
			continue
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

// emergencyRecord is the durable record of the operator's decision, stored in safety next to the authority
// it created, so "why did this node become active" always has a written answer.
func emergencyRecord(op Operation, ack, operator string, acceptRelayLoss bool) *json.RawMessage {
	raw, err := json.Marshal(map[string]any{
		"operation_id": op.ID, "epoch": op.Epoch, "fenced_node": op.TargetNode,
		"ack": ack, "operator": operator, "accept_relay_loss": acceptRelayLoss,
		"at": time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		return nil
	}
	m := json.RawMessage(raw)
	return &m
}

var _ = safety.AuthorityEmergency
