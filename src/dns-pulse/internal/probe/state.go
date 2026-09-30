package probe

// State is the state of a (check, tester) pair. The AGENT computes it and sends only transitions to the
// server: nobody needs the raw probe stream, the history bar is built from changes (docs/25 §3, §4).
//
//	all probes in a run succeeded                 -> clean run
//	some lost, but at least ok_probes succeeded   -> partial run
//	fewer than ok_probes succeeded                -> failed run
//
//	fail_threshold failed runs in a row  -> down
//	ok_threshold clean runs in a row     -> healthy
//	anything else                        -> degraded
//
// The hysteresis matters: without it one lost burst of packets would move DNS.
type State struct {
	Current  string // healthy | degraded | down | "" (not decided yet)
	cleanRun int
	failRun  int
}

type Run struct {
	OK    int
	Total int
	Need  int // ok_probes_required
}

// Step applies one run and returns the new state and whether it CHANGED; only changes go to the server.
func (s *State) Step(r Run, failThreshold, okThreshold int) (string, bool) {
	switch {
	case r.Total > 0 && r.OK == r.Total:
		s.cleanRun++
		s.failRun = 0
	case r.OK >= r.Need:
		s.cleanRun, s.failRun = 0, 0 // partial losses accumulate neither failure nor recovery
	default:
		s.failRun++
		s.cleanRun = 0
	}

	// Thresholds win; until one is reached the state is degraded, including the first run and partial
	// losses. "Healthy" and "down" are claims, and each needs its own threshold.
	next := "degraded"
	switch {
	case s.failRun >= failThreshold:
		next = "down"
	case s.cleanRun >= okThreshold:
		next = "healthy"
	}
	if next == s.Current {
		return next, false
	}
	s.Current = next
	return next, true
}
