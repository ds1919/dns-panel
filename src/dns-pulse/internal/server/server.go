// Package server is pulse-server: it accepts agent streams, hands out tasks, records transitions and
// arms DEADLINES instead of periodic sweeps. Spec: docs/25-ns-pulse.md.
package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"dnspanel/dns-pulse/internal/config"
	"dnspanel/dns-pulse/internal/logs"
	"dnspanel/dns-pulse/internal/store"
)

type Server struct {
	DB  *store.DB
	Cfg config.Server // all durations come from here; no numbers in this file
	// CanObserve reports whether this node may observe. It is asked on handshake AND on every incoming agent
	// message, not only before writes: the node may lose its role while states are steady.
	CanObserve func(context.Context) bool

	active  atomic.Bool                     // deadlines armed by this node
	cert    atomic.Pointer[tls.Certificate] // served to agents; see cert.go
	certFP  string
	mu      sync.Mutex
	streams map[uint32]*session       // exactly one live stream per tester
	timers  map[pairKey]*armed        // deadline and its generation
	retry   map[pairKey]time.Duration // backoff for a failed deadline
	// Per-rule hold before switching and wake-up at a schedule boundary: deadlines too, same lock (switch.go).
	switches map[uint32]*pendingSwitch
	bounds   map[uint32]*armed
	// Retry of a LOST recompute: the event comes once, and a DB blip must not leave a stale decision.
	retries   map[uint32]*armed
	ruleRetry map[uint32]time.Duration
	// Retry of a whole event (cold start or promotion) when the rule list itself could not be read.
	allTimer *armed
	allRetry time.Duration
	// Sweep target list catch-up. Zones are kept in memory because the failure case is exactly the one where
	// the panel could not write the marker either.
	sweepAll   bool
	sweepZones map[uint32]bool
	sweepTimer *armed
	sweepRetry time.Duration
	// SOA of each secondary zone as of the last look (sweep.go): a changed one was transferred again.
	sweepSerials  map[uint32]string
	sweepSerialAt time.Time
	// RUNNING rebuilds; demotion must cancel them, since the panel program knows nothing about roles.
	sweepJobs map[uint64]context.CancelFunc
	seq       uint64 // generation counter for sessions and deadlines
}

// pendingSwitch is the target a rule is holding and its hold timer. The target distinguishes "same one,
// hold in progress" from "changed, start over".
type pendingSwitch struct {
	target string
	timer  *time.Timer
	gen    uint64
}

// armed is a timer with a GENERATION. The callback acts only if its generation is still current;
// otherwise a timer already inside its handler could unregister a newer one armed meanwhile.
type armed struct {
	timer *time.Timer
	gen   uint64
}

// pairKey is a check x tester pair. check == 0 is the agent's OWN deadline: a tester with no tasks has no
// pair deadlines but can go silent just the same.
type pairKey struct{ check, tester uint32 }

// session is a stream GENERATION, not something the agent sent. run_id is per agent process and stays the
// same across reconnects, so it cannot fence a superseded stream. run_id is kept for humans: to tell
// "agent restarted" from "a second copy is running" (docs/25 §3).
type session struct {
	gen    uint64
	runID  string
	cancel context.CancelFunc
}

func New(db *store.DB, cfg config.Server, canObserve func(context.Context) bool) *Server {
	if canObserve == nil {
		canObserve = func(context.Context) bool { return true }
	}
	return &Server{DB: db, Cfg: cfg, CanObserve: canObserve, streams: map[uint32]*session{},
		timers: map[pairKey]*armed{}, retry: map[pairKey]time.Duration{},
		switches: map[uint32]*pendingSwitch{}, bounds: map[uint32]*armed{},
		retries: map[uint32]*armed{}, ruleRetry: map[uint32]time.Duration{},
		sweepZones: map[uint32]bool{}, sweepJobs: map[uint64]context.CancelFunc{}}
}

// Activate arms ALL deadlines from the database, for pairs and for agents. It is called on cold start and on
// promotion to active; deadlines already in the past fire at once, same event, no special path (docs/25 §5).
//
// On start it runs BEFORE the server listens, or an agent's fresh state could be overwritten retroactively.
func (s *Server) Activate(ctx context.Context) error {
	if !s.CanObserve(ctx) {
		logs.Infof("pulse: node is not active — no deadlines set, agents not accepted")
		return nil
	}
	if s.active.Swap(true) {
		return nil // already armed
	}
	// Just promoted: the node may hold another database than when it started (pair creation), so reload the
	// certificate before agents connect to it.
	if err := s.LoadCert(ctx); err != nil {
		logs.Warnf("pulse-server: certificate not reloaded: %v", err)
	}
	pairs, err := s.DB.Pending(ctx)
	if err != nil {
		s.active.Store(false)
		return fmt.Errorf("pair deadlines: %w", err)
	}
	testers, err := s.DB.PendingTesters(ctx)
	if err != nil {
		s.active.Store(false)
		return fmt.Errorf("agent deadlines: %w", err)
	}
	for _, p := range pairs {
		s.arm(p.CheckID, p.TesterID, time.Until(p.Deadline))
	}
	for _, t := range testers {
		s.arm(0, t.TesterID, time.Until(t.Deadline))
	}
	logs.Infof("pulse: deadlines set: pairs %d, agents %d", len(pairs), len(testers))
	// Refresh the sweep target list too: zones changed while this node was not active. In a goroutine, since
	// the rebuild calls the panel and deadline arming (reached from agent handshake) must not wait for it.
	// No overall time limit: every zone of the rebuild has its own, and demotion cancels the run.
	go s.SweepRefresh(context.Background())
	// Decide all enabled rules: a newly active node must catch up rather than wait for events.
	//
	// An error HERE does not roll back active: agents are accepted and deadlines armed. But promotion happens
	// once and a schedule-only rule may get no other trigger, so failed rules are already queued for retry
	// inside RecomputeAll, and a distinct error is returned so the caller does not treat it as fatal.
	if err := s.RecomputeAll(ctx); err != nil {
		return fmt.Errorf("%w: %v", ErrRecomputePending, err)
	}
	return nil
}

// ErrRecomputePending means deadlines are armed but not all rules were decided; failed ones are retrying.
// Not fatal on start: the server cannot work without deadlines, but can briefly run on stale decisions.
var ErrRecomputePending = errors.New("rule recompute scheduled for retry")

// lostRole is called when the node stops being the observer: drop deadlines and release agents, so they
// move to the new active now instead of on their own timeout. Detected by events, on any agent's next message.
func (s *Server) lostRole() {
	s.active.Store(false)
	var cancels []context.CancelFunc
	s.mu.Lock()
	for k, a := range s.timers {
		a.timer.Stop()
		delete(s.timers, k)
	}
	// Holds and wake-ups are this node's deadlines too; a leftover timer would fire after losing the role.
	for id, p := range s.switches {
		p.timer.Stop()
		delete(s.switches, id)
	}
	for id, b := range s.bounds {
		b.timer.Stop()
		delete(s.bounds, id)
	}
	for id, r := range s.retries {
		r.timer.Stop()
		delete(s.retries, id)
		delete(s.ruleRetry, id)
	}
	if s.allTimer != nil {
		s.allTimer.timer.Stop()
		s.allTimer = nil
		s.allRetry = 0
	}
	// Same for sweep catch-up; the pending-zone memory is dropped too, the new ACTIVE does a full rebuild.
	if s.sweepTimer != nil {
		s.sweepTimer.timer.Stop()
		s.sweepTimer = nil
	}
	s.sweepAll, s.sweepZones, s.sweepRetry, s.sweepSerials = false, map[uint32]bool{}, 0, nil
	for id, stop := range s.sweepJobs {
		cancels = append(cancels, stop)
		delete(s.sweepJobs, id)
	}
	for id, sess := range s.streams {
		if sess.cancel != nil {
			cancels = append(cancels, sess.cancel)
		}
		delete(s.streams, id)
	}
	s.mu.Unlock()
	for _, c := range cancels {
		c()
	}
}

// arm sets one deadline per pair. A confirmation re-arms it and nothing happens; without one, exactly one
// timer fires for exactly one pair, exactly when its state changes.
func (s *Server) arm(check, tester uint32, in time.Duration) {
	if in < 0 {
		in = 0
	}
	k := pairKey{check, tester}
	s.mu.Lock()
	defer s.mu.Unlock()
	if a, ok := s.timers[k]; ok {
		a.timer.Stop()
	}
	delete(s.retry, k)
	s.seq++
	gen := s.seq
	s.timers[k] = &armed{gen: gen, timer: time.AfterFunc(in, func() { s.fire(k, gen) })}
}

// forget unregisters a deadline ONLY if it is still the same generation, so a stray handler cannot erase
// someone else's entry.
func (s *Server) forget(k pairKey, gen uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a, ok := s.timers[k]; ok && a.gen == gen {
		delete(s.timers, k)
		delete(s.retry, k)
	}
}

// stale reports that the generation is no longer current: the deadline was re-armed meanwhile.
func (s *Server) stale(k pairKey, gen uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.timers[k]
	return !ok || a.gen != gen
}

// fire handles an expired deadline. If the write fails the deadline RETRIES: the timer has already fired
// and a silent agent will not create a new trigger, so giving up would leave "healthy" forever. Backoff
// grows so an unavailable database does not turn into a hot loop over all pairs.
func (s *Server) fire(k pairKey, gen uint64) {
	ctx, cancel := context.WithTimeout(context.Background(), s.Cfg.DBTimeout)
	defer cancel()
	if !s.CanObserve(ctx) {
		// Role lost: drop EVERYTHING, not just this deadline, or s.active would stay true and a later
		// promotion would think "already active" and restore nothing.
		logs.Infof("pulse: node lost the right to observe — dropping deadlines and releasing agents")
		s.lostRole()
		return
	}
	var changed bool
	var next time.Time
	var err error
	if k.check == 0 {
		changed, next, err = s.DB.ExpireTester(ctx, k.tester)
	} else {
		changed, next, err = s.DB.Expire(ctx, k.check, k.tester)
	}
	if err != nil {
		s.mu.Lock()
		if a, ok := s.timers[k]; !ok || a.gen != gen {
			s.mu.Unlock() // re-armed meanwhile: nothing to retry
			return
		}
		back := s.retry[k]
		if back == 0 {
			back = s.Cfg.RetryMin
		} else {
			back *= 2
			if back > s.Cfg.RetryMax {
				back = s.Cfg.RetryMax
			}
		}
		s.retry[k] = back
		s.seq++
		next := s.seq
		s.timers[k] = &armed{gen: next, timer: time.AfterFunc(back, func() { s.fire(k, next) })}
		s.mu.Unlock()
		logs.Warnf("deadline for pair %d/%d not recorded (%v) — retrying in %s", k.check, k.tester, err, back)
		return
	}
	if changed {
		if k.check == 0 {
			logs.Infof("pulse: tester %d stopped checking in — silent", k.tester)
		} else {
			logs.Infof("pulse: check %d on tester %d — no confirmations, state unknown/silent",
				k.check, k.tester)
		}
		// Losing data is an input change too: the rule's answer is "cannot decide", not "switch back",
		// but it must learn about it (docs/25 §6).
		if k.check != 0 {
			s.RecomputeFor(ctx, k.check, k.tester)
		} else {
			s.recomputeTester(ctx, k.tester)
		}
	}
	if s.stale(k, gen) {
		return // re-armed meanwhile: not ours to touch
	}
	s.forget(k, gen)
	// Wrong deadline (confirmed later than expected, or extended in the panel): re-arm to the real one.
	if !next.IsZero() {
		s.arm(k.check, k.tester, time.Until(next))
	}
}

// take lets a new connection supersede the previous one. Refusing the new one is wrong: after an agent
// restart the old stream may be a half-dead TCP connection, and refusing means blindness until it drops.
// A different run_id on takeover means a second copy is running alongside (docs/25 §3).
func (s *Server) take(testerID uint32, runID string) uint64 {
	s.mu.Lock()
	prev, had := s.streams[testerID]
	s.seq++
	gen := s.seq
	s.streams[testerID] = &session{gen: gen, runID: runID}
	s.mu.Unlock()
	if had && prev.cancel != nil {
		if prev.runID != runID {
			logs.Infof("pulse: tester %d — connection with a different run_id (%s → %s): a second copy is running alongside",
				testerID, prev.runID, runID)
		}
		prev.cancel()
	}
	return gen
}

func (s *Server) setCancel(testerID uint32, gen uint64, cancel context.CancelFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cur, ok := s.streams[testerID]; ok && cur.gen == gen {
		cur.cancel = cancel
	}
}

// release removes a finished stream only if it is still current, so a superseded stream cannot erase
// its successor.
func (s *Server) release(testerID uint32, gen uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cur, ok := s.streams[testerID]; ok && cur.gen == gen {
		delete(s.streams, testerID)
	}
}

// current is the fence: a superseded stream may not write any result, checked on EVERY message, since a
// message may have been in flight while the takeover happened.
func (s *Server) current(testerID uint32, gen uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.streams[testerID]
	return ok && cur.gen == gen
}
