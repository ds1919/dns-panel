// Package rules decides which record set should be published RIGHT NOW.
//
// The logic is pure: no database and no clock of its own; pair states and the moment come from outside,
// so it can be tested whole. The law is the same everywhere it is described (docs/25 §6):
//
//  1. the FIRST branch from the top whose conditions hold wins and overrides everything below;
//  2. "unavailable" and "no data" are DIFFERENT. A branch that is neither true nor false blocks the ones
//     below and leaves the record as is; otherwise a vanished agent would look like an event and move DNS;
//  3. an empty branch asserts nothing: it is unknown, not false. It can empty by cascade (a check or
//     tester deleted), and treating it as false would move DNS because of a DELETION.
package rules

import (
	"fmt"
	"time"
)

// Verdict is deliberately three-valued; there is no NOT in the rule builder, because negating two
// states cannot express the third.
type Verdict int

const (
	False Verdict = iota
	True
	Unknown
)

// Pair is "this check at this tester", the key of live states.
type Pair struct {
	CheckID  uint32
	TesterID uint32
}

// Agg says how the answers of SEVERAL observers of one check combine: "unavailable" at twenty sites may
// mean "at any", "at all" or "at least three". The branch-level Any/All does not fit: it joins
// DIFFERENT conditions, not one check's answers from different observers.
type Agg int

const (
	AggAny     Agg = iota // one is enough (the old single-observer behaviour)
	AggAll                // every single one
	AggAtLeast            // at least N
)

// Cond is a branch condition: either about a measurement or about the clock.
type Cond struct {
	Schedule bool
	Pairs    []Pair // observers: one check at any number of agents
	Agg      Agg
	AggN     int
	Expect   string // available | degraded | unavailable

	DaysMask uint8  // bits 0..6 = Mon..Sun; 0 = no day constraint
	TimeFrom string // "15:04"; empty = no time window
	TimeTo   string
	DateFrom string // "2006-01-02"; empty = no bound
	DateTo   string
}

type Branch struct {
	ID       uint32
	MatchAll bool // all conditions true; otherwise any
	Hold     time.Duration
	Conds    []Cond
}

type Rule struct {
	ID          uint32
	TZ          *time.Location
	DefaultHold time.Duration
	Branches    []Branch
}

// Target is what should be published; Branch == nil means the default set.
type Target struct {
	Branch *uint32
	Hold   time.Duration
	Why    string
}

// condVerdict evaluates one condition. A pair with no state reads as unknown: a condition nobody can
// answer asserts nothing.
func condVerdict(c Cond, states map[Pair]string, now time.Time) Verdict {
	if c.Schedule {
		return scheduleVerdict(c, now)
	}
	// Count each observer separately, then aggregate. "No data" from an observer is not "no".
	var yes, no, unknown int
	for _, p := range c.Pairs {
		switch pairVerdict(states[p], c.Expect) {
		case True:
			yes++
		case False:
			no++
		default:
			unknown++
		}
	}
	total := yes + no + unknown
	if total == 0 {
		return Unknown // no observers at all
	}
	switch c.Agg {
	case AggAll:
		if no > 0 {
			return False // one "no" makes "all" impossible
		}
		if unknown > 0 {
			return Unknown
		}
		return True
	case AggAtLeast:
		n := c.AggN
		if n < 1 {
			n = 1
		}
		if yes >= n {
			return True // reached; silent observers cannot undo it
		}
		if yes+unknown < n {
			return False // even if every silent one says yes, N is out of reach
		}
		return Unknown
	}
	if yes > 0 {
		return True
	}
	if unknown > 0 {
		return Unknown
	}
	return False
}

// pairVerdict is the answer of ONE observer. A pair missing from the map has no result, which is unknown.
func pairVerdict(st, expect string) Verdict {
	if st == "" || st == "unknown" {
		return Unknown
	}
	var actual string
	switch st {
	case "healthy":
		actual = "available"
	case "degraded":
		actual = "degraded"
	default:
		actual = "unavailable"
	}
	if actual == expect {
		return True
	}
	return False
}

// scheduleVerdict is always decidable: the clock never has "no data".
func scheduleVerdict(c Cond, now time.Time) Verdict {
	if c.DaysMask != 0 {
		// Go counts from Sunday = 0; our bits start on Monday.
		bit := uint8((int(now.Weekday()) + 6) % 7)
		if c.DaysMask&(1<<bit) == 0 {
			return False
		}
	}
	if c.DateFrom != "" && now.Format("2006-01-02") < c.DateFrom {
		return False
	}
	if c.DateTo != "" && now.Format("2006-01-02") > c.DateTo {
		return False
	}
	if c.TimeFrom != "" && c.TimeTo != "" {
		hm := now.Format("15:04")
		if c.TimeFrom <= c.TimeTo {
			if hm < c.TimeFrom || hm >= c.TimeTo {
				return False
			}
		} else if hm < c.TimeFrom && hm >= c.TimeTo {
			// A window across midnight (22:00-06:00) is a legitimate case.
			return False
		}
	}
	return True
}

func branchVerdict(b Branch, states map[Pair]string, now time.Time) Verdict {
	if len(b.Conds) == 0 {
		return Unknown
	}
	var t, f, u int
	for _, c := range b.Conds {
		switch condVerdict(c, states, now) {
		case True:
			t++
		case False:
			f++
		default:
			u++
		}
	}
	if b.MatchAll {
		if f > 0 {
			return False
		}
		if u > 0 {
			return Unknown
		}
		return True
	}
	if t > 0 {
		return True
	}
	if u > 0 {
		return Unknown
	}
	return False
}

// Decide returns what to publish. nil means "nothing to decide on, the record stays as is", which is
// NOT the same as "the default set".
//
// Time is converted to the RULE's time zone before any comparison: "09:00 to 18:00" is someone's
// working hours, not those of whichever node runs the daemon.
func Decide(r Rule, states map[Pair]string, now time.Time) *Target {
	if r.TZ != nil {
		now = now.In(r.TZ)
	}
	for i := range r.Branches {
		b := r.Branches[i]
		switch branchVerdict(b, states, now) {
		case True:
			id := b.ID
			return &Target{Branch: &id, Hold: b.Hold,
				Why: fmt.Sprintf("rule %d matched", i+1)}
		case Unknown:
			return nil
		}
	}
	return &Target{Hold: r.DefaultHold, Why: "no rule matches"}
}

// NextBoundary returns the next moment the schedule answer may CHANGE, so we sleep until then instead
// of polling: window edges and midnight (which changes both weekday and date). Zero means no schedules.
func NextBoundary(r Rule, now time.Time) time.Time {
	loc := r.TZ
	if loc == nil {
		loc = time.UTC
	}
	now = now.In(loc)
	var best time.Time
	add := func(t time.Time) {
		if t.After(now) && (best.IsZero() || t.Before(best)) {
			best = t
		}
	}
	at := func(day time.Time, hm string) {
		var h, m int
		if _, err := fmt.Sscanf(hm, "%d:%d", &h, &m); err != nil {
			return
		}
		add(time.Date(day.Year(), day.Month(), day.Day(), h, m, 0, 0, loc))
	}
	tomorrow := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc).AddDate(0, 0, 1)
	for _, b := range r.Branches {
		for _, c := range b.Conds {
			if !c.Schedule {
				continue
			}
			add(tomorrow) // midnight: both weekday and date change
			for _, hm := range []string{c.TimeFrom, c.TimeTo} {
				if hm == "" {
					continue
				}
				at(now, hm)
				at(tomorrow, hm)
			}
		}
	}
	return best
}
