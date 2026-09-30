// Package agent connects to the server on its own, runs the assigned tasks and sends ONLY transitions.
//
// Reconnecting is normal, not a failure: the service address moves between HA nodes and the stream
// breaks. The agent KEEPS probing while disconnected (docs/25 §1), so probes belong to the PROCESS, not
// the connection; tying them to the session would reset hysteresis on every reconnect.
//
// Nothing accumulated during an outage is replayed (docs/25 §3). The send queue therefore holds the
// LATEST state per check rather than a list of events: a new transition replaces the unsent one, so
// after an outage of any length exactly the current picture is sent and the queue cannot overflow.
package agent

import (
	"context"
	"crypto/tls"
	"fmt"
	"math/rand"
	"os"
	"sync"
	"time"

	"dnspanel/dns-pulse/internal/config"
	"dnspanel/dns-pulse/internal/logs"
	"dnspanel/dns-pulse/internal/pinning"
	"dnspanel/dns-pulse/internal/probe"
	"dnspanel/dns-pulse/internal/wire"
)

type Agent struct {
	cfg     config.Agent
	runID   string
	version string // build version, shown in the tester card
	canICMP bool
	canV4   bool // real outbound path (route and source address), not just kernel IPv6 support
	canV6   bool
	key     string // own key from StateDirectory, not from the config; see identity.go
	host    string // self-reported hostname, a human label in the pending list
	lastBye string // last refusal reason, so it is not logged every reconnect

	mu    sync.Mutex
	tasks map[uint32]*runner
	pend  map[string]wire.Msg // key -> latest unsent message of that kind
	wake  chan struct{}
}

type runner struct {
	task   wire.Task
	state  probe.State
	cancel context.CancelFunc
}

func New(cfg config.Agent, version string) *Agent {
	// A fresh run_id per process start lets the server tell a reconnect of the same agent from a
	// second copy running alongside (docs/25 §3).
	return &Agent{cfg: cfg, version: version,
		runID:   fmt.Sprintf("%d-%d", time.Now().UnixNano(), rand.Int63()),
		canICMP: probe.ICMPAvailable(), tasks: map[uint32]*runner{},
		canV4: probe.Routable("ipv4"), canV6: probe.Routable("ipv6"),
		pend: map[string]wire.Msg{}, wake: make(chan struct{}, 1)}
}

// DisableICMP tells the server ICMP is not run here, even if the capability is present.
func (a *Agent) DisableICMP() { a.canICMP = false }

func (a *Agent) Run(ctx context.Context) error {
	if !a.canICMP {
		logs.Warnf("ICMP is unavailable here (no CAP_NET_RAW and no ping socket) — " +
			"not taking tasks of this kind: \"cannot check\" is not \"host unreachable\"")
	}
	pin, err := pinning.New(a.cfg.Fingerprint, a.cfg.StateDir)
	if err != nil {
		return err
	}
	if a.key, err = agentKey(a.cfg.StateDir); err != nil {
		return err
	}
	a.host, _ = os.Hostname()
	// Print the code BEFORE the first connection: it is how a human finds this machine in the
	// pending list.
	logs.Infof("pulse-agent: approval code — %s (host %s); in the panel: NS Pulse → Waiting for approval",
		enrollCode(a.key), a.host)
	defer a.stopAll()
	backoff := a.cfg.ReconnectMin
	lastErr := ""
	for ctx.Err() == nil {
		started := time.Now()
		err := a.session(ctx, pin)
		if ctx.Err() != nil {
			return nil
		}
		// A session that outlived the backoff cap means the link was fine; don't carry the backoff over.
		if time.Since(started) > a.cfg.ReconnectMax {
			backoff = a.cfg.ReconnectMin
			lastErr = ""
		}
		// Repeated identical reasons go to debug: a pending agent reconnects every half minute for days,
		// and at info level the one change of reason would drown in noise.
		if msg := fmt.Sprint(err); msg == lastErr {
			logs.Debugf("pulse-agent: connection closed: %v (retrying in %s)", err, backoff)
		} else {
			lastErr = msg
			logs.Infof("pulse-agent: connection closed: %v (retrying in %s)", err, backoff)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > a.cfg.ReconnectMax {
			backoff = a.cfg.ReconnectMax
		}
	}
	return nil
}

// session runs one connection. Probes do NOT stop when it drops: they live in the process ctx.
func (a *Agent) session(procCtx context.Context, pin *pinning.Pin) error {
	raw, err := tls.Dial("tcp", a.cfg.Server, pin.TLSConfig())
	if err != nil {
		return err
	}
	c := wire.New(raw)
	defer c.Close()

	ctx, cancel := context.WithCancel(procCtx)
	defer cancel()
	// Shutdown must BREAK the connection, not wait for it: the session blocks in Recv while the server
	// is silent, and without this SIGTERM left the agent to be SIGKILLed by systemd.
	stopOnDone := context.AfterFunc(ctx, func() { c.Close() })
	defer stopOnDone()

	// Capabilities are re-evaluated on EVERY connection: outbound routes come and go, and advertising
	// stale IPv6 would turn AAAA checks red because of a missing route.
	a.canV4, a.canV6 = probe.Routable("ipv4"), probe.Routable("ipv6")
	if err := c.Send(wire.Msg{Type: wire.TypeHello, AgentKey: a.key, EnrollKey: a.cfg.EnrollKey,
		Hostname: a.host, RunID: a.runID, Version: a.version, CanICMP: a.canICMP,
		CanIPv4: a.canV4, CanIPv6: a.canV6}); err != nil {
		return err
	}
	first, err := c.Recv()
	if err != nil {
		return err
	}
	if first.Type == wire.TypeGoodbye {
		// "Awaiting approval" is the normal state of a freshly installed agent; log it once per reason.
		if first.Reason != a.lastBye {
			a.lastBye = first.Reason
			logs.Infof("pulse-agent: server not accepting us yet: %s (code %s)", first.Reason, enrollCode(a.key))
		}
		return fmt.Errorf("server refused: %s", first.Reason)
	}
	a.lastBye = ""
	if first.Type != wire.TypeWelcome {
		return fmt.Errorf("expected welcome, got %q", first.Type)
	}
	if err := pin.Commit(); err != nil { // commit only after a complete session
		logs.Warnf("fingerprint not saved: %v", err)
	}
	logs.Infof("pulse-agent: connected as %q (id %d), check-in every %d s",
		first.TesterName, first.TesterID, first.ConfirmEvery)

	// After a reconnect, report the current state of ALL checks, changed or not: the server may have
	// missed a change while disconnected.
	a.republish()

	go a.sender(ctx, c)
	go a.confirmer(ctx, time.Duration(max32(first.ConfirmEvery, 1))*time.Second)
	// The sweep shares the connection but runs its own request/measure/reply cycle. It lives exactly
	// this session (see sweep.go), hence the session ctx.
	batches := make(chan wire.Msg, 1)
	go a.sweeper(ctx, c, batches)

	for {
		m, err := c.Recv()
		if err != nil {
			return err
		}
		switch m.Type {
		case wire.TypeAssign:
			a.apply(procCtx, m.Tasks)
		case wire.TypeNextFP:
			if err := pin.Next(m.Fingerprint); err == nil {
				a.enqueue("fp", wire.Msg{Type: wire.TypeFPAck, Fingerprint: m.Fingerprint})
			}
		case wire.TypeSweepBatch:
			// Hand off the batch without blocking: a stuck sweep must not stall tasks and transitions.
			// A dropped batch simply expires by its lease.
			select {
			case batches <- m:
			default:
				logs.Debugf("pulse-agent: sweep batch arrived while the previous one is still being measured — skipping")
			}
		case wire.TypeGoodbye:
			return fmt.Errorf("server closed the stream: %s", m.Reason)
		}
	}
}

// apply takes the task set WHOLE, not as a delta, so nothing can drift. A running check of the same
// version is not restarted, otherwise editing a neighbouring task would reset its hysteresis.
func (a *Agent) apply(ctx context.Context, tasks []wire.Task) {
	keep := map[uint32]bool{}
	have := make([]wire.CheckVersion, 0, len(tasks))
	for _, t := range tasks {
		keep[t.CheckID] = true
		have = append(have, wire.CheckVersion{CheckID: t.CheckID, ConfigVersion: t.ConfigVersion})
		a.mu.Lock()
		cur, ok := a.tasks[t.CheckID]
		a.mu.Unlock()
		if ok && cur.task.ConfigVersion == t.ConfigVersion {
			continue
		}
		if ok {
			cur.cancel() // a different version is a different measurement; hysteresis restarts
		}
		a.start(ctx, t)
	}
	a.mu.Lock()
	for id, r := range a.tasks {
		if !keep[id] {
			r.cancel()
			delete(a.tasks, id)
			delete(a.pend, transitionKey(id))
		}
	}
	a.mu.Unlock()
	a.enqueue("accepted", wire.Msg{Type: wire.TypeAccepted, Checks: have})
	logs.Infof("pulse-agent: tasks accepted: %d", len(tasks))
}

func (a *Agent) start(ctx context.Context, t wire.Task) {
	ctx, cancel := context.WithCancel(ctx)
	r := &runner{task: t, cancel: cancel}
	a.mu.Lock()
	a.tasks[t.CheckID] = r
	a.mu.Unlock()

	go func() {
		iv := time.Duration(max32(t.IntervalSec, 1)) * time.Second // guards against division by zero, not a policy
		tick := time.NewTicker(iv)
		defer tick.Stop()
		for {
			run := a.probeOnce(ctx, t)
			if ctx.Err() != nil {
				return
			}
			a.mu.Lock()
			state, changed := r.state.Step(run, int(max32(t.FailThreshold, 1)), int(max32(t.OKThreshold, 1)))
			a.mu.Unlock()
			if changed {
				a.enqueue(transitionKey(t.CheckID), wire.Msg{Type: wire.TypeTransition,
					CheckID: t.CheckID, ConfigVersion: t.ConfigVersion, State: state,
					Detail: fmt.Sprintf("%d/%d probes ok", run.OK, run.Total)})
			}
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
		}
	}()
}

func transitionKey(checkID uint32) string { return fmt.Sprintf("t:%d", checkID) }

func (a *Agent) probeOnce(ctx context.Context, t wire.Task) probe.Run {
	run := probe.Run{Total: int(max32(t.ProbesPerRun, 1)), Need: int(max32(t.OKProbes, 1))}
	timeout := time.Duration(max32(t.TimeoutMS, 1)) * time.Millisecond // the panel sets the limit; here only non-zero
	for i := 0; i < run.Total; i++ {
		if err := probe.One(ctx, t.Kind, t.TargetIP, t.Port, timeout); err == nil {
			run.OK++
		}
	}
	return run
}

// republish queues the current state of all checks after a reconnect.
func (a *Agent) republish() {
	a.mu.Lock()
	msgs := make(map[string]wire.Msg, len(a.tasks))
	for id, r := range a.tasks {
		if r.state.Current == "" {
			continue // no run yet, nothing to assert
		}
		msgs[transitionKey(id)] = wire.Msg{Type: wire.TypeTransition, CheckID: id,
			ConfigVersion: r.task.ConfigVersion, State: r.state.Current, Detail: "state after reconnect"}
	}
	for k, m := range msgs {
		a.pend[k] = m
	}
	a.mu.Unlock()
	a.notify()
}

// confirmer periodically reports which checks run at which version. An EMPTY list is sent too:
// without it an agent assigned its very first check would learn of it only after reconnecting.
func (a *Agent) confirmer(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		a.mu.Lock()
		have := make([]wire.CheckVersion, 0, len(a.tasks))
		for id, r := range a.tasks {
			have = append(have, wire.CheckVersion{CheckID: id, ConfigVersion: r.task.ConfigVersion})
		}
		a.mu.Unlock()
		a.enqueue("confirm", wire.Msg{Type: wire.TypeConfirm, Checks: have})
	}
}

// enqueue replaces any unsent message of the same key: the server gets "how it is now", not the
// history of the outage.
func (a *Agent) enqueue(key string, m wire.Msg) {
	a.mu.Lock()
	a.pend[key] = m
	a.mu.Unlock()
	a.notify()
}

func (a *Agent) notify() {
	select {
	case a.wake <- struct{}{}:
	default:
	}
}

func (a *Agent) sender(ctx context.Context, c *wire.Conn) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-a.wake:
		}
		for {
			a.mu.Lock()
			var key string
			var m wire.Msg
			for k, v := range a.pend {
				key, m = k, v
				break
			}
			if key == "" {
				a.mu.Unlock()
				break
			}
			delete(a.pend, key)
			a.mu.Unlock()
			if err := c.Send(m); err != nil {
				// Put it back unless a fresher state for the same key has appeared meanwhile.
				a.mu.Lock()
				if _, newer := a.pend[key]; !newer {
					a.pend[key] = m
				}
				a.mu.Unlock()
				return
			}
		}
	}
}

func (a *Agent) stopAll() {
	a.mu.Lock()
	defer a.mu.Unlock()
	for id, r := range a.tasks {
		r.cancel()
		delete(a.tasks, id)
	}
}

func max32(a, b uint32) uint32 {
	if a > b {
		return a
	}
	return b
}
