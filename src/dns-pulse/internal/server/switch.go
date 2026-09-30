// Rule handler: the §6 decision and the record switch.
//
// Recompute always starts FROM AN EVENT: a transition, an expired deadline, a schedule boundary, a panel
// signal that the rule changed, or promotion. There is no timer sweep over the rules table.
//
// A HOLD ("after N s of the same state") sits between decision and switch. Without it a flapping target
// would rewrite the zone back and forth, bump the serial and NOTIFY all secondaries on every bounce. The
// hold is a per-rule timer, cancelled as soon as the target changes.
//
// The write itself is done by pulse-apply.pl: zones change only via pdns_apply_rrsets, and write permission
// is checked there by the same function the panel uses (docs/25 §2). There is no separate HA model here.
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"

	"dnspanel/dns-pulse/internal/logs"
	"dnspanel/dns-pulse/internal/rules"
	"dnspanel/dns-pulse/internal/store"
)

// targetKey encodes "what should be published" as one string, compared with both the current state and the
// target of an armed hold.
func targetKey(t *rules.Target) string {
	if t == nil || t.Branch == nil {
		return "default"
	}
	return fmt.Sprintf("branch:%d", *t.Branch)
}

func appliedKey(a *store.Applied) string {
	switch {
	case a.State == "switched" && a.ActiveBranch != 0:
		return fmt.Sprintf("branch:%d", a.ActiveBranch)
	case a.State == "switched":
		// Switched, but to an unknown branch (e.g. right after branches were recreated). Treating it as
		// "default" would leave a vanished branch's set in the zone, so this key matches NO target.
		return "switched:unknown"
	case a.State == "held":
		return "held"
	}
	return "default"
}

// RecomputeFor recomputes only the rules that ask about a pair whose state changed.
func (s *Server) RecomputeFor(ctx context.Context, checkID, testerID uint32) {
	ids, err := s.DB.RulesForPair(ctx, checkID, testerID)
	if err != nil {
		// There will be no second trigger: the state is already recorded. Retry the EVENT itself with backoff,
		// like failed deadlines.
		logs.Warnf("rules for pair %d/%d: %v", checkID, testerID, err)
		s.retryPair(checkID, testerID)
		return
	}
	for _, id := range ids {
		if err := s.recompute(ctx, id); err != nil {
			s.retryRule(id, err)
		}
	}
}

// recomputeTester handles a silent agent: data is lost for all its pairs at once.
func (s *Server) recomputeTester(ctx context.Context, testerID uint32) {
	ids, err := s.DB.RulesForTester(ctx, testerID)
	if err != nil {
		logs.Warnf("rules for tester %d: %v", testerID, err)
		s.retryPair(0, testerID)
		return
	}
	for _, id := range ids {
		if err := s.recompute(ctx, id); err != nil {
			s.retryRule(id, err)
		}
	}
}

// RecomputeAll runs on cold start and on promotion: a newly active node must catch up, not wait for events.
// It returns an ERROR so Activate knows its second half failed; a schedule-only rule may get no other trigger.
func (s *Server) RecomputeAll(ctx context.Context) error {
	ids, err := s.DB.EnabledRules(ctx)
	if err != nil {
		// The LIST itself failed, so the whole event is lost. Nobody else will retry it: Activate already marked
		// the node active and a second "activate" from HA returns "already active". The retry is armed here only.
		s.retryAll(err)
		return fmt.Errorf("enabled rules list: %w", err)
	}
	s.clearAllRetry()
	var first error
	for _, id := range ids {
		if e := s.recompute(ctx, id); e != nil {
			s.retryRule(id, e)
			if first == nil {
				first = e
			}
		}
	}
	if len(ids) > 0 {
		logs.Infof("pulse: rules under observation: %d", len(ids))
	}
	return first
}

// Recompute recomputes one rule on an external trigger (panel signal).
func (s *Server) Recompute(ctx context.Context, id uint32) error {
	err := s.recompute(ctx, id)
	if err != nil {
		s.retryRule(id, err)
	}
	return err
}

func (s *Server) recompute(ctx context.Context, id uint32) error {
	// Check the role here too, so a demoted node does not keep waking schedule timers and deciding for the
	// new active; its writes would be refused anyway, but it must not spam attempts and logs.
	if !s.CanObserve(ctx) {
		s.lostRole()
		return nil
	}
	a, err := s.DB.LoadRule(ctx, id)
	if err != nil {
		return fmt.Errorf("cannot read rule %d: %w", id, err)
	}
	if a == nil || !a.Enabled {
		s.dropRule(id) // disabled or deleted: drop hold and wake-up
		return nil
	}
	// held: a human stopped automatic control. Not "nothing to do" but "not your call": the set stays as it is
	// until control is handed back.
	if a.State == "held" {
		s.dropRule(id)
		return nil
	}
	states, err := s.DB.RuleStates(ctx, id)
	if err != nil {
		return fmt.Errorf("states of rule %d: %w", id, err)
	}
	now := time.Now()
	// Schedules create no events but change the answer at known instants; sleep until the next one.
	s.armBoundary(id, rules.NextBoundary(a.Rule, now))

	t := rules.Decide(a.Rule, states, now)
	if t == nil {
		// Nothing to decide on. This is NOT "revert to default": lost observation is not an event and the record
		// stays. But verify it for foreign edits: rules spend most time here, when such edits are most likely.
		s.dropSwitch(id)
		return s.verify(ctx, a)
	}
	want := targetKey(t)
	if want == appliedKey(a) {
		// Unchanged decision, nothing to switch. The other main case where a foreign edit would stay unseen:
		// the panel would show "default" while the zone holds something else.
		s.dropSwitch(id)
		return s.verify(ctx, a)
	}
	s.armSwitch(id, want, t.Hold)
	return nil
}

// verify checks whether someone else edited the record. It is a LIGHT check run only when there is nothing
// to switch; on the switch path the switcher does the same under the lock before writing.
//
// If the zone diverges from what Pulse thinks is published, the rule goes to held via the same program under
// the same pulse_rules lock as a switch; otherwise we would race with Pulse's own write.
func (s *Server) verify(ctx context.Context, a *store.Applied) error {
	out, err := s.runApply(ctx, "--rule", fmt.Sprint(a.ID), "--verify")
	if err != nil {
		return err
	}
	// Failure is read from the REPLY, not the exit code, and must not be swallowed: DB down, HA freeze or an
	// unreadable rule mean "verification did not happen", not "all fine". Treating it as success would skip
	// the retry and hide a foreign edit until a next trigger that a schedule may never produce.
	if !out.OK {
		return fmt.Errorf("zone reconciliation failed: %s", out.Error)
	}
	if out.Held != 0 {
		logs.Warnf("pulse: %s — record was changed by someone else: %s", a.Label, out.Error)
	}
	return nil
}

// retryRule retries a LOST EVENT; it is not a sweep. The state is recorded and nobody will report it again,
// so a DB blip at that moment would leave a stale decision until a next trigger that may never come.
// Backoff grows so an unavailable database does not become a hot loop over all rules.
func (s *Server) retryRule(id uint32, cause error) {
	back := s.backoff(id)
	s.mu.Lock()
	if r, ok := s.retries[id]; ok {
		r.timer.Stop()
	}
	s.seq++
	gen := s.seq
	s.retries[id] = &armed{gen: gen, timer: time.AfterFunc(back, func() {
		ctx, cancel := context.WithTimeout(context.Background(), s.Cfg.DBTimeout+s.Cfg.ApplyTimeout)
		defer cancel()
		s.mu.Lock()
		cur, ok := s.retries[id]
		if ok && cur.gen == gen {
			delete(s.retries, id)
		}
		s.mu.Unlock()
		if err := s.recompute(ctx, id); err != nil {
			s.retryRule(id, err)
			return
		}
		s.clearRetry(id)
	})}
	s.mu.Unlock()
	logs.Warnf("pulse: rule %d — recompute failed (%v), retrying in %s", id, cause, back)
}

// retrySwitch retries a MATURED switch. Unlike retryRule it does not restart the hold: it already elapsed,
// and a DB blip must not make the condition hold twice. The target is re-checked on each retry; if it
// changed, the retry becomes a normal recompute.
func (s *Server) retrySwitch(id uint32, want string, cause error) {
	back := s.backoff(id)
	s.mu.Lock()
	if r, ok := s.retries[id]; ok {
		r.timer.Stop()
	}
	s.seq++
	gen := s.seq
	s.retries[id] = &armed{gen: gen, timer: time.AfterFunc(back, func() {
		ctx, cancel := context.WithTimeout(context.Background(), s.Cfg.DBTimeout+s.Cfg.ApplyTimeout)
		defer cancel()
		s.mu.Lock()
		if cur, ok := s.retries[id]; ok && cur.gen == gen {
			delete(s.retries, id)
		}
		s.mu.Unlock()
		s.mature(ctx, id, want)
	})}
	s.mu.Unlock()
	logs.Warnf("pulse: rule %d — switch failed (%v), retrying in %s", id, cause, back)
}

// backoff is the per-rule growing delay, shared by both retry kinds so a failing rule does not hit the
// database twice.
func (s *Server) backoff(id uint32) time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	back := s.ruleRetry[id]
	if back == 0 {
		back = s.Cfg.RetryMin
	} else if back *= 2; back > s.Cfg.RetryMax {
		back = s.Cfg.RetryMax
	}
	s.ruleRetry[id] = back
	return back
}

// clearRetry resets the backoff after success.
func (s *Server) clearRetry(id uint32) {
	s.mu.Lock()
	delete(s.ruleRetry, id)
	s.mu.Unlock()
}

// retryAll retries a LOST cold start or promotion. One per server: no rules are known yet, so the only
// thing to repeat is the question "which rules are enabled".
func (s *Server) retryAll(cause error) {
	s.mu.Lock()
	back := s.allRetry
	if back == 0 {
		back = s.Cfg.RetryMin
	} else if back *= 2; back > s.Cfg.RetryMax {
		back = s.Cfg.RetryMax
	}
	s.allRetry = back
	if s.allTimer != nil {
		s.allTimer.timer.Stop()
	}
	s.seq++
	gen := s.seq
	s.allTimer = &armed{gen: gen, timer: time.AfterFunc(back, func() {
		ctx, cancel := context.WithTimeout(context.Background(), s.Cfg.DBTimeout+s.Cfg.ApplyTimeout)
		defer cancel()
		s.mu.Lock()
		if s.allTimer != nil && s.allTimer.gen == gen {
			s.allTimer = nil
		}
		s.mu.Unlock()
		_ = s.RecomputeAll(ctx) // re-arms itself if it fails again
	})}
	s.mu.Unlock()
	logs.Warnf("pulse: cannot read rule list (%v) — retrying in %s", cause, back)
}

func (s *Server) clearAllRetry() {
	s.mu.Lock()
	s.allRetry = 0
	s.mu.Unlock()
}

// retryPair retries when the rule LIST for a pair could not be read; the whole event is repeated rather
// than guessing which rules it affected.
func (s *Server) retryPair(checkID, testerID uint32) {
	k := pairKey{checkID, testerID}
	s.mu.Lock()
	back := s.retry[k]
	if back == 0 {
		back = s.Cfg.RetryMin
	} else if back *= 2; back > s.Cfg.RetryMax {
		back = s.Cfg.RetryMax
	}
	s.retry[k] = back
	s.mu.Unlock()
	time.AfterFunc(back, func() {
		ctx, cancel := context.WithTimeout(context.Background(), s.Cfg.DBTimeout+s.Cfg.ApplyTimeout)
		defer cancel()
		if checkID == 0 {
			s.recomputeTester(ctx, testerID)
		} else {
			s.RecomputeFor(ctx, checkID, testerID)
		}
	})
}

func (s *Server) armSwitch(id uint32, want string, hold time.Duration) {
	s.mu.Lock()
	if p, ok := s.switches[id]; ok {
		if p.target == want {
			s.mu.Unlock() // same target: the hold keeps running, not restarted
			return
		}
		p.timer.Stop()
	}
	s.seq++
	gen := s.seq
	s.switches[id] = &pendingSwitch{target: want, gen: gen,
		timer: time.AfterFunc(hold, func() { s.doSwitch(id, gen, want) })}
	s.mu.Unlock()
	logs.Infof("pulse: rule %d — target \"%s\", waiting %s continuously", id, want, hold)
}

func (s *Server) dropSwitch(id uint32) {
	s.mu.Lock()
	if p, ok := s.switches[id]; ok {
		p.timer.Stop()
		delete(s.switches, id)
	}
	s.mu.Unlock()
}

func (s *Server) dropRule(id uint32) {
	s.dropSwitch(id)
	s.mu.Lock()
	if b, ok := s.bounds[id]; ok {
		b.timer.Stop()
		delete(s.bounds, id)
	}
	s.mu.Unlock()
}

// armBoundary arms a wake-up at a schedule window boundary; a zero time means no schedules.
func (s *Server) armBoundary(id uint32, at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if b, ok := s.bounds[id]; ok {
		b.timer.Stop()
		delete(s.bounds, id)
	}
	if at.IsZero() {
		return
	}
	in := time.Until(at)
	if in < 0 {
		in = 0
	}
	s.seq++
	gen := s.seq
	s.bounds[id] = &armed{gen: gen, timer: time.AfterFunc(in, func() {
		ctx, cancel := context.WithTimeout(context.Background(), s.Cfg.DBTimeout+s.Cfg.ApplyTimeout)
		defer cancel()
		// The most fragile event: the timer has fired and a single-window rule gets no other trigger until the
		// window's other edge, so losing it keeps the record switched for hours.
		if err := s.recompute(ctx, id); err != nil {
			s.retryRule(id, err)
		}
	})}
}

// doSwitch runs when the hold elapsed. The decision is made AGAIN: anything, including the rule itself,
// may have changed. The timer means "look again", not "switch now".
func (s *Server) doSwitch(id uint32, gen uint64, want string) {
	ctx, cancel := context.WithTimeout(context.Background(), s.Cfg.DBTimeout+s.Cfg.ApplyTimeout)
	defer cancel()
	s.mu.Lock()
	p, ok := s.switches[id]
	if !ok || p.gen != gen {
		s.mu.Unlock()
		return // target changed meanwhile: another timer owns the switch
	}
	delete(s.switches, id)
	s.mu.Unlock()
	s.mature(ctx, id, want)
}

// mature handles a MATURED switch: the hold elapsed, confirm the target is unchanged and apply. It is
// separate from doSwitch because retries come back here: a transient apply failure must not restart the hold.
func (s *Server) mature(ctx context.Context, id uint32, want string) {
	// Check the role here too: a matured switch survives demotion, and the old active would otherwise keep
	// invoking pulse-apply.pl on backoff with writes that are refused anyway.
	if !s.CanObserve(ctx) {
		s.lostRole()
		return
	}
	a, err := s.DB.LoadRule(ctx, id)
	if err != nil {
		s.retrySwitch(id, want, err)
		return
	}
	if a == nil || !a.Enabled || a.State == "held" {
		// No longer ours to apply; a normal recompute drops hold and wake-up. Retrying apply would fail the same way.
		if err := s.recompute(ctx, id); err != nil {
			s.retryRule(id, err)
		}
		return
	}
	states, err := s.DB.RuleStates(ctx, id)
	if err != nil {
		s.retrySwitch(id, want, err)
		return
	}
	t := rules.Decide(a.Rule, states, time.Now())
	if t == nil || targetKey(t) != want || want == appliedKey(a) {
		s.clearRetry(id)
		if err := s.recompute(ctx, id); err != nil { // target changed: restart the hold
			s.retryRule(id, err)
		}
		return
	}
	if err := s.apply(ctx, a, t); err != nil {
		// The HOLD ALREADY ELAPSED: retry the APPLY, not the hold. Otherwise a one-second DB blip would restart
		// the "after" wait, and a long HA freeze would run pulse-apply.pl on every recompute instead of backing off.
		s.retrySwitch(id, want, err)
		return
	}
	s.clearRetry(id)
	if err := s.recompute(ctx, id); err != nil {
		s.retryRule(id, err)
	}
}

type applyOut struct {
	OK      bool   `json:"ok"`
	Changed int    `json:"changed"`
	State   string `json:"state"`
	Error   string `json:"error"`
	HA      string `json:"ha"`
	// int, not bool: Perl emits 0/1, which does not decode into bool and would fail every verification.
	Held int `json:"held"`
}

// runApply runs pulse-apply.pl. Switch and verify share one JSON reply since both inspect the zone under
// the rule lock.
func (s *Server) runApply(ctx context.Context, args ...string) (applyOut, error) {
	var r applyOut
	out, err := exec.CommandContext(ctx, s.Cfg.ApplyCommand, args...).Output()
	if jerr := json.Unmarshal(out, &r); jerr != nil {
		return r, fmt.Errorf("%s: %v (output: %q)", s.Cfg.ApplyCommand, err, string(out))
	}
	return r, nil
}

// apply returns an error so a matured switch is retried after any transient failure (database, HA gate,
// the program itself) instead of being lost.
func (s *Server) apply(ctx context.Context, a *store.Applied, t *rules.Target) error {
	args := []string{"--rule", fmt.Sprint(a.ID)}
	if t.Branch != nil {
		args = append(args, "--branch", fmt.Sprint(*t.Branch))
	}
	args = append(args, "--reason", t.Why)
	r, err := s.runApply(ctx, args...)
	if err != nil {
		return fmt.Errorf("switch failed: %w", err)
	}
	if !r.OK {
		// "Not our node" and "HA operation in progress" are expected refusals, not faults: the active node will
		// write. Still retry, since the freeze ends and the switch must happen; only the log level differs.
		if r.HA == "skip" {
			logs.Infof("pulse: %s — switch is not ours to make yet: %s", a.Label, r.Error)
		} else {
			logs.Warnf("pulse: %s — switch rejected: %s", a.Label, r.Error)
		}
		return fmt.Errorf("%s", r.Error)
	}
	if r.Changed != 0 {
		logs.Infof("pulse: %s — %s (%s)", a.Label, r.State, t.Why)
	}
	return nil
}
