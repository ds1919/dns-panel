package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"dnspanel/dns-pulse/internal/logs"
	"dnspanel/dns-pulse/internal/wire"
)

// Serve runs the whole conversation with one agent. Order is fixed: hello, welcome, tasks, then events.
func (s *Server) Serve(ctx context.Context, c *wire.Conn) error {
	defer c.Close()
	if !s.CanObserve(ctx) {
		// Refuse explicitly with a reason: accepting the stream and silently dropping writes would show agents
		// online in the panel with no states appearing (docs/25 §2).
		_ = c.Send(wire.Msg{Type: wire.TypeGoodbye,
			Reason: "this node is not active — connect to the service address"})
		return errors.New("standby: connection rejected")
	}

	first, err := c.Recv()
	if err != nil {
		return err
	}
	if first.Type != wire.TypeHello || first.AgentKey == "" || first.RunID == "" {
		_ = c.Send(wire.Msg{Type: wire.TypeGoodbye,
			Reason: "first message must be hello with agent_key and run_id"})
		return errors.New("first message must be hello")
	}
	// Host only, for both enrollment and connection records: the outgoing port is random, and recording it
	// would log an "address change" on every reconnect.
	host := c.RemoteAddr()
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	tester, err := s.DB.Auth(ctx, first.AgentKey)
	if err != nil {
		return dbErr("agent identification", err)
	}
	// An unknown agent is an ENROLLMENT REQUEST, not an error: that is how a fresh machine looks. Queue it and
	// say what it is waiting for; no tasks and no writes until a human approves it in the panel (docs/25 §1).
	if tester == nil {
		ok, err := s.DB.Enroll(ctx, first.AgentKey, first.EnrollKey, first.Hostname, host, first.Version)
		if err != nil {
			return dbErr("agent enrollment request", err)
		}
		if !ok {
			_ = c.Send(wire.Msg{Type: wire.TypeGoodbye, Reason: "enrollment key rejected"})
			return errors.New("enrollment key rejected")
		}
		logs.Infof("pulse: enrollment request from %s (host %q, version %s) — waiting for approval in the panel",
			host, first.Hostname, first.Version)
		_ = c.Send(wire.Msg{Type: wire.TypeGoodbye, Reason: "waiting for approval in the panel"})
		return nil
	}
	// Known but not approved is a DIFFERENT refusal: "unknown" is fixed with a key, "not approved" with a
	// click in the panel.
	if !tester.Approved {
		if _, err := s.DB.Enroll(ctx, first.AgentKey, first.EnrollKey, first.Hostname, host, first.Version); err != nil {
			return dbErr("enrollment request update", err)
		}
		_ = c.Send(wire.Msg{Type: wire.TypeGoodbye, Reason: "waiting for approval in the panel"})
		return nil
	}
	if !tester.Enabled {
		_ = c.Send(wire.Msg{Type: wire.TypeGoodbye, Reason: "this tester is switched off in the panel"})
		return errors.New("tester is disabled")
	}

	// Promotion arrives as an event by itself: when the service address moves, agents reconnect here. The first
	// handshake arms ALL deadlines, including those of agents that already died and will send nothing.
	if err := s.Activate(ctx); err != nil {
		logs.Warnf("setting deadlines after promotion: %v", err)
	}

	// Fence with the server-issued generation, not run_id: run_id is per agent process and survives a normal
	// reconnect, so a superseded stream would pass the check.
	gen := s.take(tester.ID, first.RunID)
	defer s.release(tester.ID, gen)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	s.setCancel(tester.ID, gen, cancel)
	// Takeover must actually CLOSE the old stream, not just mark it.
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()

	logs.Infof("pulse: tester %d (%s) connected from %s, run_id=%s version %s icmp=%v ipv4=%v ipv6=%v",
		tester.ID, tester.Name, c.RemoteAddr(), first.RunID, first.Version, first.CanICMP,
		first.CanIPv4, first.CanIPv6)
	// Record the connection on the tester card so address changes are visible without the log (docs/25 §1).
	if err := s.DB.SeenFrom(ctx, tester.ID, host, first.Version, first.CanIPv4, first.CanIPv6); err != nil {
		return dbErr("connection record", err)
	}

	// The check-in interval is derived from the freshness in the database, a few times shorter so one lost
	// message does not look like a vanished agent.
	every := confirmEvery(tester.ConfirmMaxAge)
	if err := c.Send(wire.Msg{Type: wire.TypeWelcome, TesterID: tester.ID, TesterName: tester.Name,
		ConfirmEvery: every}); err != nil {
		return err
	}
	if err := s.sendTasks(ctx, c, tester.ID, first.CanICMP); err != nil {
		return err
	}
	// Sweep leases belong to the SESSION, not the process: after a drop the answers would be rejected anyway,
	// so unfinished targets go back to the round right away instead of waiting for lease expiry.
	sweep := newSweepState(first.CanIPv4, first.CanIPv6)
	defer s.releaseSweep(tester.ID, sweep)

	for {
		msg, err := c.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) || ctx.Err() != nil {
				return nil
			}
			return err
		}
		// The role may change while states are steady; ask on EVERY message, or a node that became STANDBY
		// would keep live agents just because nothing happened.
		if !s.CanObserve(ctx) {
			logs.Infof("pulse: node lost the right to observe — dropping deadlines and releasing agents")
			s.lostRole()
			_ = c.Send(wire.Msg{Type: wire.TypeGoodbye,
				Reason: "this node is no longer active — reconnect to the service address"})
			return errors.New("role lost")
		}
		// A superseded stream must not write; checked per message since one may be in flight during takeover.
		if !s.current(tester.ID, gen) {
			_ = c.Send(wire.Msg{Type: wire.TypeGoodbye, Reason: "superseded by a newer connection"})
			return errors.New("stream superseded by a newer one")
		}
		// Re-read working parameters: the tester may have been deleted, disabled, re-keyed or had its freshness
		// changed. This replaces a sweep: a revoked agent is cut off by its own next message.
		alive, age, err := s.DB.Params(ctx, tester.ID, first.AgentKey)
		if err != nil {
			return dbErr("tester runtime parameters", err)
		}
		if !alive {
			_ = c.Send(wire.Msg{Type: wire.TypeGoodbye, Reason: "this tester is no longer allowed to report"})
			return errors.New("tester revoked")
		}
		// Freshness changed in the panel: the agent still checks in on the OLD interval and with a shorter
		// deadline would flap. The new interval comes with a new welcome, so just close the stream.
		if now := confirmEvery(age); now != every {
			_ = c.Send(wire.Msg{Type: wire.TypeGoodbye,
				Reason: "check-in interval changed — reconnect for the new one"})
			logs.Infof("pulse: tester %d — check-in interval changed (%d → %d s), asking to reconnect",
				tester.ID, every, now)
			return nil
		}
		if err := s.handle(ctx, tester.ID, age, first.CanICMP, c, msg, sweep); err != nil {
			return err
		}
	}
}

// dbErr logs the real database cause on the SERVER; the agent gets no DB details. Without the log,
// "database unavailable" is unexplainable after the fact, which is exactly how the first live run stalled.
func dbErr(what string, err error) error {
	logs.Warnf("%s: %v", what, err)
	return fmt.Errorf("%s: %w", what, err)
}

func (s *Server) handle(ctx context.Context, testerID uint32, age time.Duration, canICMP bool,
	c *wire.Conn, m wire.Msg, sweep *sweepState) error {
	switch m.Type {
	case wire.TypeSweepClaim:
		return s.onSweepClaim(ctx, testerID, c, sweep)
	case wire.TypeSweepResult:
		return s.onSweepResult(ctx, testerID, sweep, m.Answers)
	case wire.TypeConfirm:
		if err := s.onConfirm(ctx, testerID, age, m.Checks); err != nil {
			return err
		}
		s.watchSecondaries()
		// A check-in lists the task versions the agent runs, so an outdated set is visible here and resent in
		// full. No "has anything changed" polling: the trigger is a message that arrived anyway (docs/25 §3).
		want, err := s.effective(ctx, testerID, canICMP)
		if err != nil {
			return err
		}
		if outdated(want, m.Checks) {
			logs.Infof("pulse: tester %d is running an outdated task set — resending", testerID)
			return c.Send(wire.Msg{Type: wire.TypeAssign, Tasks: want})
		}
		return nil
	case wire.TypeAccepted:
		// Accepting tasks also proves the agent runs exactly this list.
		return s.onConfirm(ctx, testerID, age, m.Checks)
	case wire.TypeTransition:
		changed, err := s.DB.Transition(ctx, testerID, m.CheckID, m.ConfigVersion, m.State, m.Detail)
		if err != nil {
			return dbErr("transition", err)
		}
		if changed {
			logs.Infof("pulse: tester %d, check %d → %s", testerID, m.CheckID, m.State)
			// Recompute ONLY the rules that ask about this pair, and only now: there is no rule timer sweep.
			s.RecomputeFor(ctx, m.CheckID, testerID)
		}
		// A result itself proves the check is running, so it re-arms the deadlines too.
		s.arm(m.CheckID, testerID, age)
		s.arm(0, testerID, age)
		return nil
	case wire.TypeFPAck:
		logs.Debugf("tester %d saved next fingerprint %s", testerID, m.Fingerprint)
		return nil
	}
	return nil
}

func (s *Server) onConfirm(ctx context.Context, testerID uint32, age time.Duration,
	checks []wire.CheckVersion) error {
	if err := s.DB.Confirm(ctx, testerID, checks); err != nil {
		return dbErr("check-in", err)
	}
	// The agent's own deadline is a separate clock: a tester with no tasks has no pair deadlines.
	s.arm(0, testerID, age)
	for _, c := range checks {
		s.arm(c.CheckID, testerID, age)
	}
	return nil
}

// confirmDivisor is how many times more often than freshness the agent checks in; three means two lost
// check-ins in a row are not yet a missing agent.
const confirmDivisor uint32 = 3

// confirmEvery derives the check-in interval from the freshness stored in the database.
func confirmEvery(maxAge time.Duration) uint32 {
	every := uint32(maxAge.Seconds()) / confirmDivisor
	if every < 1 {
		every = 1
	}
	return every
}

func (s *Server) sendTasks(ctx context.Context, c *wire.Conn, testerID uint32, canICMP bool) error {
	tasks, err := s.effective(ctx, testerID, canICMP)
	if err != nil {
		return err
	}
	return c.Send(wire.Msg{Type: wire.TypeAssign, Tasks: tasks})
}

// effective returns what this agent ACTUALLY runs, given its capabilities. One answer for both issuing and
// version comparison: when only issuing filtered ICMP, an agent without ICMP got "set differs" and the
// same set again on every check-in, forever.
func (s *Server) effective(ctx context.Context, testerID uint32, canICMP bool) ([]wire.Task, error) {
	tasks, err := s.DB.Tasks(ctx, testerID)
	if err != nil {
		return nil, dbErr("task list", err)
	}
	out := make([]wire.Task, 0, len(tasks))
	for _, t := range tasks {
		if t.Kind == "icmp" && !canICMP {
			// Assigning ICMP anyway would yield "unavailable" instead of "cannot check" and switch records over a
			// missing capability (docs/25 §1). The pair gets no fresh data and goes unknown on its deadline.
			logs.Infof("pulse: tester %d cannot do ICMP — check %d not assigned to it", testerID, t.CheckID)
			continue
		}
		out = append(out, wire.Task{
			CheckID: t.CheckID, ConfigVersion: t.ConfigVersion, Kind: t.Kind, TargetIP: t.TargetIP,
			Port: t.Port, IntervalSec: uint32(t.Interval.Seconds()), TimeoutMS: uint32(t.Timeout.Milliseconds()),
			ProbesPerRun: t.ProbesPerRun, OKProbes: t.OKProbes,
			FailThreshold: t.FailThreshold, OKThreshold: t.OKThreshold,
		})
	}
	return out, nil
}

// outdated reports whether the confirmed versions differ from the assigned set.
func outdated(want []wire.Task, have []wire.CheckVersion) bool {
	if len(want) != len(have) {
		return true
	}
	got := make(map[uint32]uint32, len(have))
	for _, cv := range have {
		got[cv.CheckID] = cv.ConfigVersion
	}
	for _, t := range want {
		if v, ok := got[t.CheckID]; !ok || v != t.ConfigVersion {
			return true
		}
	}
	return false
}
