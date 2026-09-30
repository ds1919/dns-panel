package agent

import (
	"context"
	"errors"
	"sync"
	"time"

	"dnspanel/dns-pulse/internal/logs"
	"dnspanel/dns-pulse/internal/probe"
	"dnspanel/dns-pulse/internal/wire"
)

// sweeper runs the agent's side of the slow sweep (docs/25 §7):
//
//   - it is background work: the agent measures exactly the batch it asked for; parallelism and limits
//     come with the batch, the agent has no measurement settings of its own;
//   - unlike checks, the sweep belongs to the SESSION: the lease is tied to this connection, and after a
//     disconnect the answer would be rejected anyway while the target goes to someone else;
//   - "could not measure" is silence, not "unavailable": the target is left out of the answer, its
//     lease expires and someone else checks it.
func (a *Agent) sweeper(ctx context.Context, c *wire.Conn, batches <-chan wire.Msg) {
	if !a.canICMP {
		logs.Infof("pulse-agent: no ICMP here — not taking part in the slow sweep")
		return
	}
	for ctx.Err() == nil {
		if err := c.Send(wire.Msg{Type: wire.TypeSweepClaim}); err != nil {
			return
		}
		var m wire.Msg
		select {
		case <-ctx.Done():
			return
		case m = <-batches:
		}
		if len(m.Sweep) == 0 {
			// Zero means no sweep this session (no settings in the panel yet, or nothing for this agent);
			// asking again is pointless until a new connection.
			if m.SweepAgainSec == 0 {
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Duration(m.SweepAgainSec) * time.Second):
			}
			continue
		}
		answers := a.sweepBatch(ctx, m.Sweep, m.SweepParallel)
		// The link dropped mid-measurement: the lease belonged to this session, so the answers are moot.
		if ctx.Err() != nil {
			return
		}
		if len(answers) > 0 {
			if err := c.Send(wire.Msg{Type: wire.TypeSweepResult, Answers: answers}); err != nil {
				return
			}
		}
	}
}

// sweepBatch measures a batch with the parallelism the server asked for. Answer order does not matter:
// each carries its own lease.
func (a *Agent) sweepBatch(ctx context.Context, tasks []wire.SweepTask, parallel uint32) []wire.SweepAnswer {
	if parallel < 1 {
		parallel = 1
	}
	var mu sync.Mutex
	out := make([]wire.SweepAnswer, 0, len(tasks))
	sem := make(chan struct{}, parallel)
	var wg sync.WaitGroup
	for _, t := range tasks {
		select {
		case <-ctx.Done():
			wg.Wait()
			return out
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(t wire.SweepTask) {
			defer wg.Done()
			defer func() { <-sem }()
			state, measured := a.sweepOne(ctx, t)
			if !measured {
				return
			}
			mu.Lock()
			out = append(out, wire.SweepAnswer{TargetID: t.TargetID, Generation: t.Generation, State: state})
			mu.Unlock()
		}(t)
	}
	wg.Wait()
	return out
}

// sweepOne measures one target: any reply means available, none means unavailable, and a failure to
// measure yields no answer at all. The server sets the number of tries, so one lost packet is not an outage.
func (a *Agent) sweepOne(ctx context.Context, t wire.SweepTask) (string, bool) {
	timeout := time.Duration(t.TimeoutMS) * time.Millisecond
	tries := int(t.Probes)
	if tries < 1 {
		tries = 1
	}
	// No route to the address is "unknown", not an outage; otherwise an agent without a route to a
	// network would paint it red without ever reaching it.
	if !probe.RoutableTo(t.IP) {
		logs.Debugf("pulse-agent: sweep %s — no route from here, cannot measure", t.IP)
		return "", false
	}
	for i := 0; i < tries; i++ {
		if ctx.Err() != nil {
			return "", false
		}
		err := probe.One(ctx, "icmp", t.IP, 0, timeout)
		if err == nil {
			return "available", true
		}
		if errors.Is(err, probe.ErrCannotMeasure) {
			logs.Debugf("pulse-agent: sweep %s — cannot measure: %v", t.IP, err)
			return "", false
		}
	}
	return "unavailable", true
}
