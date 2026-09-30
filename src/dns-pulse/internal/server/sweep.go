package server

import (
	"context"
	"fmt"
	"sync"
	"time"

	"dnspanel/dns-pulse/internal/logs"
	"dnspanel/dns-pulse/internal/store"
	"dnspanel/dns-pulse/internal/wire"
)

// Server side of the slow sweep (docs/25 §7). The server never wakes anyone: a batch is issued ONLY when
// an agent asks, so the sweep has no rhythm of its own and cannot interfere with checks.

// sweepState tracks what was leased to THIS stream and is still unanswered. It lives as long as the
// connection: leases are bound to the session, and answers after a drop would be rejected anyway.
type sweepState struct {
	canV4, canV6 bool
	mu           sync.Mutex
	open         map[uint64]store.SweepTarget
}

func newSweepState(canV4, canV6 bool) *sweepState {
	return &sweepState{canV4: canV4, canV6: canV6, open: map[uint64]store.SweepTarget{}}
}

func (st *sweepState) add(ts []store.SweepTarget) {
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, t := range ts {
		st.open[t.ID] = t
	}
}

// peek looks up an answered target; a foreign or duplicate id is not found and never reaches the database.
func (st *sweepState) peek(id uint64) (store.SweepTarget, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	t, ok := st.open[id]
	return t, ok
}

// done drops a target once the answer is recorded or fenced off, and ONLY after the database call: dropping
// it earlier would lose track of the lease on a transient DB error, leaving it stuck until expiry.
func (st *sweepState) done(id uint64) {
	st.mu.Lock()
	defer st.mu.Unlock()
	delete(st.open, id)
}

func (st *sweepState) rest() []store.SweepTarget {
	st.mu.Lock()
	defer st.mu.Unlock()
	out := make([]store.SweepTarget, 0, len(st.open))
	for _, t := range st.open {
		out = append(out, t)
	}
	st.open = map[uint64]store.SweepTarget{}
	return out
}

// onSweepClaim handles a batch request. An empty batch is still an answer: it says when to ask again,
// computed by the database, not the agent.
func (s *Server) onSweepClaim(ctx context.Context, testerID uint32, c *wire.Conn, st *sweepState) error {
	if !st.canV4 && !st.canV6 {
		return c.Send(wire.Msg{Type: wire.TypeSweepBatch})
	}
	p, ok, err := s.DB.SweepPolicy(ctx)
	if err != nil {
		return dbErr("sweep parameters", err)
	}
	if !ok {
		// No parameters yet: the first target-list rebuild creates them, and on a fresh install it may be running
		// right now. Ask to come back LATER rather than disable the sweep for the whole session.
		logs.Infof("pulse: sweep parameters not yet configured in the panel — asking the agent to come back later")
		return c.Send(wire.Msg{Type: wire.TypeSweepBatch, SweepAgainSec: atLeastSecond(s.Cfg.RetryMin)})
	}
	targets, err := s.DB.ClaimSweep(ctx, testerID, st.canV4, st.canV6, p.Batch,
		time.Now().UTC().Add(-p.Interval), p.Lease())
	if err != nil {
		return dbErr("issuing sweep targets", err)
	}
	if len(targets) == 0 {
		wait, err := s.DB.SweepWait(ctx, p, st.canV4, st.canV6)
		if err != nil {
			return dbErr("next sweep request time", err)
		}
		// At most a minute: the server does not wake agents, and new addresses (a zone edit, a transfer, an empty
		// list filled after start) would otherwise wait for a round, an hour by default. The ask is one cheap query.
		if wait > time.Minute {
			wait = time.Minute
		}
		return c.Send(wire.Msg{Type: wire.TypeSweepBatch, SweepAgainSec: atLeastSecond(wait)})
	}
	st.add(targets)
	tasks := make([]wire.SweepTask, 0, len(targets))
	for _, t := range targets {
		tasks = append(tasks, wire.SweepTask{TargetID: t.ID, Generation: t.Generation, IP: t.IP,
			TimeoutMS: uint32(p.Timeout.Milliseconds()), Probes: uint32(p.Probes)})
	}
	logs.Debugf("pulse: sweep batch issued to tester %d: %d targets", testerID, len(tasks))
	return c.Send(wire.Msg{Type: wire.TypeSweepBatch, Sweep: tasks, SweepParallel: uint32(p.Parallel)})
}

// atLeastSecond keeps "come back" from being instant: there is nothing to hand out, so avoid a hot loop.
func atLeastSecond(d time.Duration) uint32 {
	if secs := uint32(d.Seconds()); secs >= 1 {
		return secs
	}
	return 1
}

// onSweepResult handles batch answers. Each measurement passes the lease fence in the database; here we only
// track what this stream holds and log state changes.
func (s *Server) onSweepResult(ctx context.Context, testerID uint32, st *sweepState, answers []wire.SweepAnswer) error {
	for _, a := range answers {
		t, mine := st.peek(a.TargetID)
		// Check the generation HERE too: the database would reject it anyway, but a foreign or mismatched
		// generation must not drop the CURRENT lease this stream is still responsible for.
		if !mine || a.Generation != t.Generation {
			continue
		}
		ok, changed, err := s.DB.ApplySweepResult(ctx, testerID, a.TargetID, a.Generation, a.State)
		if err != nil {
			// Keep the target tracked: a disconnect after this error returns it to the round immediately.
			return dbErr("sweep result", err)
		}
		st.done(a.TargetID)
		if !ok {
			logs.Debugf("pulse: sweep result for target %d (%s) rejected — lease no longer held by this tester", t.ID, t.IP)
			continue
		}
		if changed {
			logs.Infof("pulse: sweep — %s is now %s (tester %d)", t.IP, a.State, testerID)
		}
	}
	return nil
}

// releaseSweep returns this stream's unanswered targets to the round. Only ITS leases with their
// generations are released: on reconnect a new session of the same agent may already hold them (docs/25 §7).
//
// It uses its own context: streams usually end by cancellation, which is exactly when cleanup is needed.
func (s *Server) releaseSweep(testerID uint32, st *sweepState) {
	rest := st.rest()
	if len(rest) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.Cfg.DBTimeout)
	defer cancel()
	if err := s.DB.ReleaseSweep(ctx, testerID, rest); err != nil {
		logs.Warnf("returning sweep targets to the pool: %v", err)
		return
	}
	logs.Debugf("pulse: tester %d disconnected — %d sweep targets returned to the pool", testerID, len(rest))
}

// Target list upkeep (store/sweepsync.go), on events, not a schedule:
//
//   - START and promotion: zones changed while this node was not maintaining the list, so a full rebuild;
//   - a zone EDIT: the panel names the zone over the control socket.
//
// Failures retry with growing backoff, like failed rule recomputes. Zones are remembered in daemon memory
// because a failure may be the database being unavailable, when no flag can be written either; a daemon
// restart is covered by the full rebuild.

// SweepRefresh does a full rebuild, on cold start and on promotion: a new ACTIVE must reconcile the target
// list with current zones rather than assume it stayed current while another node was writing.
func (s *Server) SweepRefresh(ctx context.Context) { s.sweepCatchUp(ctx, true, 0) }

// SweepZone handles a zone edit named by the panel. Zero means "just process the flagged zones".
func (s *Server) SweepZone(zone uint32) { s.sweepCatchUp(context.Background(), false, zone) }

// watchSecondaries follows transfers of secondary zones, when the Pinger includes them. The panel does not see
// a transfer, so the SOA of every secondary is compared with the last look; a changed zone is rebuilt. It runs
// on an agent check-in, a message that arrives anyway, at most once a minute: one indexed query, and without
// agents there is nobody to ping for.
func (s *Server) watchSecondaries() {
	s.mu.Lock()
	if s.sweepSerials == nil || time.Since(s.sweepSerialAt) < time.Minute {
		s.mu.Unlock()
		return // before the first full rebuild there is nothing to compare with
	}
	s.sweepSerialAt = time.Now()
	s.mu.Unlock()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), s.Cfg.DBTimeout)
		defer cancel()
		if on, err := s.DB.SweepSecondary(ctx); err != nil || !on {
			return
		}
		now, err := s.DB.SweepSecondarySerials(ctx)
		if err != nil {
			logs.Warnf("pulse: secondary zones not checked for transfers: %v", err)
			return
		}
		s.mu.Lock()
		changed := 0
		for z, soa := range now {
			if s.sweepSerials != nil && s.sweepSerials[z] != soa {
				s.sweepZones[z] = true
				changed++
			}
		}
		if s.sweepSerials != nil {
			s.sweepSerials = now
		}
		s.mu.Unlock()
		if changed > 0 {
			logs.Infof("pulse: %d secondary zone(s) transferred again — updating their sweep targets", changed)
			s.sweepCatchUp(context.Background(), false, 0)
		}
	}()
}

func (s *Server) sweepCatchUp(ctx context.Context, refresh bool, zone uint32) {
	// The target list is a write to the panel database like deadlines and switches, so it needs the role.
	// Ask HERE, not only on entry: the node may have become STANDBY between the panel's nudge and a retry.
	if !s.CanObserve(ctx) {
		logs.Debugf("pulse: node is not active — leaving the sweep target list alone")
		return
	}
	// Demotion must abort a running rebuild, so each run gets a cancellable context visible to lostRole.
	ctx, stop := context.WithCancel(ctx)
	defer stop()
	s.mu.Lock()
	s.seq++
	job := s.seq
	s.sweepJobs[job] = stop
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.sweepJobs, job)
		s.mu.Unlock()
	}()
	// The role was checked BEFORE the run became visible to cleanup, and demotion could slip in between with
	// nothing to cancel. Re-check right after registering; from here demotion either sees us or cancels us.
	if !s.active.Load() {
		logs.Debugf("pulse: node demoted while the run was being registered — leaving the target list alone")
		return
	}

	s.mu.Lock()
	if refresh {
		s.sweepAll = true
	}
	if zone != 0 {
		s.sweepZones[zone] = true
	}
	all := s.sweepAll
	zones := make([]uint32, 0, len(s.sweepZones))
	for z := range s.sweepZones {
		zones = append(zones, z)
	}
	s.mu.Unlock()

	// Demotion aborts the run at any step: no extra writes after the role is gone.
	lost := func() bool { return !s.active.Load() }
	failed := false
	step := func() (context.Context, context.CancelFunc) {
		return context.WithTimeout(ctx, s.Cfg.DBTimeout+s.Cfg.ApplyTimeout)
	}
	if all {
		// A full rebuild covers both flagged and remembered zones.
		if n, err := s.sweepRefresh(ctx); err != nil {
			failed = true
			logs.Warnf("sweep target list not rebuilt: %v", err)
		} else {
			logs.Infof("pulse: sweep target list rebuilt: %d targets", n)
			s.mu.Lock()
			s.sweepAll = false
			s.sweepZones = map[uint32]bool{}
			s.mu.Unlock()
			zones = nil
		}
	}
	if lost() {
		return
	}
	if !all || failed {
		c, cancel := step()
		n, err := s.DB.SweepRetryDirty(c, s.lockWait())
		cancel()
		if err != nil || n > 0 {
			if err == nil {
				err = fmt.Errorf("%d zone(s) not parsed", n)
			}
			failed = true
			logs.Warnf("flagged sweep zones not parsed: %v", err)
		}
	}
	for _, z := range zones {
		if lost() {
			return
		}
		c, cancel := step()
		_, err := s.DB.SweepSyncZone(c, z, s.lockWait())
		cancel()
		if err != nil {
			failed = true
			s.DB.SweepMarkDirty(ctx, z, err) // once the flag is written, the dirty retry takes over
			logs.Warnf("sweep zone %d not parsed: %v", z, err)
			continue
		}
		s.mu.Lock()
		delete(s.sweepZones, z)
		s.mu.Unlock()
	}
	if failed {
		// No retry after a mid-rebuild demotion: the work is no longer ours, and a new timer would outlive the
		// cleanup demotion already did.
		if !s.active.Load() {
			logs.Debugf("pulse: node demoted mid-rebuild of the target list — not scheduling a retry")
			return
		}
		s.retrySweep()
		return
	}
	s.mu.Lock()
	s.sweepRetry = 0
	s.mu.Unlock()
}

// retrySweep schedules a catch-up retry with capped backoff: an unavailable database must not become a
// hot loop, and the event must not be lost.
func (s *Server) retrySweep() {
	s.mu.Lock()
	back := s.sweepRetry
	if back == 0 {
		back = s.Cfg.RetryMin
	} else if back *= 2; back > s.Cfg.RetryMax {
		back = s.Cfg.RetryMax
	}
	s.sweepRetry = back
	if s.sweepTimer != nil {
		s.sweepTimer.timer.Stop()
	}
	s.seq++
	gen := s.seq
	s.sweepTimer = &armed{gen: gen, timer: time.AfterFunc(back, func() {
		s.mu.Lock()
		if s.sweepTimer != nil && s.sweepTimer.gen == gen {
			s.sweepTimer = nil
		}
		s.mu.Unlock()
		s.sweepCatchUp(context.Background(), false, 0) // re-arms itself if it fails again
	})}
	s.mu.Unlock()
	logs.Warnf("pulse: sweep target list is stale — retrying in %s", back)
}

// sweepRefresh rebuilds the whole target list; zones that failed are flagged and reported. The SOA of the
// secondaries is taken BEFORE the rebuild: a transfer during it is then seen as a change by the next look.
func (s *Server) sweepRefresh(ctx context.Context) (int, error) {
	c, cancel := context.WithTimeout(ctx, s.Cfg.DBTimeout)
	serials, err := s.DB.SweepSecondarySerials(c)
	cancel()
	if err != nil {
		return 0, err
	}
	n, failed, err := s.DB.SweepRefresh(ctx, s.lockWait(), s.Cfg.DBTimeout+s.Cfg.ApplyTimeout)
	if err == nil && failed > 0 {
		err = fmt.Errorf("zones not parsed: %d", failed)
	}
	if err == nil {
		s.mu.Lock()
		s.sweepSerials, s.sweepSerialAt = serials, time.Now()
		s.mu.Unlock()
	}
	return n, err
}

// lockWait is how long a zone rebuild waits for another rebuild of the same zone, in seconds.
func (s *Server) lockWait() int { return int(s.Cfg.DBTimeout.Seconds()) }
