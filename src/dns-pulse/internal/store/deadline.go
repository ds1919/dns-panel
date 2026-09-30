package store

import (
	"context"
	"database/sql"
	"time"
)

// Pair is a check x tester pair and the moment its knowledge goes stale. There is no background sweep:
// the server arms a deadline for a SPECIFIC moment and re-arms it on each confirmation (docs/25 §5).
type Pair struct {
	CheckID  uint32
	TesterID uint32
	Deadline time.Time // zero = no deadline: never confirmed
}

// Pending returns the pairs to arm on start: both sides ENABLED and confirmed at least once. Disabled pairs
// are excluded on purpose: expiry would write `silent` over `disabled`, making an operator action look
// like an outage. On cold start some deadlines are already past and fire at once; same event, no special path.
func (d *DB) Pending(ctx context.Context) ([]Pair, error) {
	rows, err := d.sql.QueryContext(ctx, `
		SELECT r.check_id, r.tester_id,
		       TIMESTAMPADD(SECOND, t.confirm_max_age_seconds, r.confirmed_at) AS dl
		  FROM pulse_results r
		  JOIN pulse_testers t ON t.id = r.tester_id
		  JOIN pulse_checks  c ON c.id = r.check_id
		 WHERE r.confirmed_at IS NOT NULL AND t.enabled = 1 AND c.enabled = 1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Pair
	for rows.Next() {
		var p Pair
		var dl sql.NullTime
		if err := rows.Scan(&p.CheckID, &p.TesterID, &dl); err != nil {
			return nil, err
		}
		if dl.Valid {
			p.Deadline = dl.Time
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// Expire moves a pair to unknown/silent when its deadline fires. It rechecks the conditions, since things
// may have changed between arming and firing:
//   - both sides must be enabled, otherwise it is `disabled` and must not be overwritten;
//   - a confirmation may have arrived later than expected, so there is no deadline any more;
//   - an interval never ends before it starts: `confirm_max_age_seconds` is edited by people and the
//     boundary can move into the past (docs/25 §5).
//
// It returns (state changed, actual deadline). A non-zero time means "too early, re-arm for this moment":
// a stray or early timer must converge to the real deadline, not vanish, or the pair is left without one.
func (d *DB) Expire(ctx context.Context, checkID, testerID uint32) (bool, time.Time, error) {
	tx, err := d.sql.BeginTx(ctx, nil)
	if err != nil {
		return false, time.Time{}, err
	}
	defer tx.Rollback()

	var state, reason string
	var since, confirmed sql.NullTime
	var maxAge uint32
	var bothOn bool
	err = tx.QueryRowContext(ctx, `
		SELECT r.state, COALESCE(r.unknown_reason, ''), r.since, r.confirmed_at, t.confirm_max_age_seconds,
		       (t.enabled = 1 AND c.enabled = 1) AS both_on
		  FROM pulse_results r
		  JOIN pulse_testers t ON t.id = r.tester_id
		  JOIN pulse_checks  c ON c.id = r.check_id
		 WHERE r.check_id = ? AND r.tester_id = ? FOR UPDATE`, checkID, testerID).
		Scan(&state, &reason, &since, &confirmed, &maxAge, &bothOn)
	if err == sql.ErrNoRows {
		return false, time.Time{}, nil
	}
	if err != nil {
		return false, time.Time{}, err
	}
	if !bothOn || !confirmed.Valid {
		return false, time.Time{}, nil
	}
	ended := confirmed.Time.Add(time.Duration(maxAge) * time.Second)
	if now := time.Now().UTC(); ended.After(now) {
		// Confirmed later than expected (or the deadline was extended): return it so the timer is re-armed.
		return false, ended, nil
	}
	if state == "unknown" {
		// Already unknown: change only the REASON without a new interval, since a same-state transition is not
		// a transition (docs/25 §4.1). This stops a pair that died before its first result from showing
		// "waiting for first result" forever.
		if reason == "silent" {
			return false, time.Time{}, nil
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE pulse_results SET unknown_reason = 'silent', confirmed_at = NULL
			  WHERE check_id = ? AND tester_id = ?`, checkID, testerID); err != nil {
			return false, time.Time{}, err
		}
		return true, time.Time{}, tx.Commit()
	}
	if since.Valid && ended.Before(since.Time) {
		ended = since.Time // an interval never ends before it starts
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO pulse_intervals (check_id, tester_id, state, started_at, ended_at)
		VALUES (?, ?, ?, ?, ?)`, checkID, testerID, state, since.Time, ended); err != nil {
		return false, time.Time{}, err
	}
	if err := trimHistory(ctx, tx, "pulse_intervals", "h.check_id = ? AND h.tester_id = ?",
		checkID, testerID); err != nil {
		return false, time.Time{}, err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE pulse_results SET state = 'unknown', unknown_reason = 'silent', since = ?,
		       confirmed_at = NULL WHERE check_id = ? AND tester_id = ?`,
		ended, checkID, testerID); err != nil {
		return false, time.Time{}, err
	}
	return true, time.Time{}, tx.Commit()
}

// ExpireTester fires the deadline of the agent ITSELF. This is a separate clock: a tester with no tasks has
// no pair deadlines and would otherwise stay "online" forever after its first confirmation.
// It returns (state changed, actual deadline if too early).
func (d *DB) ExpireTester(ctx context.Context, testerID uint32) (bool, time.Time, error) {
	// Read the previous state UNDER the row lock, as for pairs: otherwise a concurrent fresh confirmation
	// could be overwritten with "silent" based on a stale last_confirm_at.
	tx, err := d.sql.BeginTx(ctx, nil)
	if err != nil {
		return false, time.Time{}, err
	}
	defer tx.Rollback()

	var confirmed, since sql.NullTime
	var maxAge uint32
	var state string
	var enabled bool
	err = tx.QueryRowContext(ctx,
		`SELECT state, state_since, enabled, last_confirm_at, confirm_max_age_seconds
		   FROM pulse_testers WHERE id = ? FOR UPDATE`,
		testerID).Scan(&state, &since, &enabled, &confirmed, &maxAge)
	if err == sql.ErrNoRows {
		return false, time.Time{}, nil
	}
	if err != nil {
		return false, time.Time{}, err
	}
	// Disabled is excluded on purpose: rewriting an operator decision as "silent" would erase the difference
	// between a decision and an outage.
	if !enabled || !confirmed.Valid || state != "online" {
		return false, time.Time{}, nil
	}
	ended := confirmed.Time.Add(time.Duration(maxAge) * time.Second)
	if ended.After(time.Now().UTC()) {
		return false, ended, nil // too early: the timer must be re-armed, not dropped
	}
	if err := closeTesterInterval(ctx, tx, testerID, state, since, ended); err != nil {
		return false, time.Time{}, err
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE pulse_testers SET state = 'silent', state_since = ? WHERE id = ?`, ended, testerID); err != nil {
		return false, time.Time{}, err
	}
	return true, time.Time{}, tx.Commit()
}

// closeTesterInterval records the agent's own online/silent history. It is a separate question from the
// pairs: a green connection does not mean tasks are running (§3, §4.1). Only CLOSED intervals are stored;
// the current state lives in pulse_testers.state + state_since.
func closeTesterInterval(ctx context.Context, tx *sql.Tx, testerID uint32, state string,
	since sql.NullTime, ended time.Time) error {
	if !since.Valid {
		return nil // nothing to close
	}
	if ended.Before(since.Time) {
		ended = since.Time // never end before start
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO pulse_tester_intervals (tester_id, state, started_at, ended_at)
		VALUES (?, ?, ?, ?)`, testerID, state, since.Time, ended); err != nil {
		return err
	}
	return trimHistory(ctx, tx, "pulse_tester_intervals", "h.tester_id = ?", testerID)
}

// PendingTesters returns the agents' own deadlines: a tester without tasks has no pair deadlines, and
// without this a server restart would leave a dead agent "online" forever.
func (d *DB) PendingTesters(ctx context.Context) ([]Pair, error) {
	rows, err := d.sql.QueryContext(ctx, `
		SELECT id, TIMESTAMPADD(SECOND, confirm_max_age_seconds, last_confirm_at)
		  FROM pulse_testers
		 WHERE enabled = 1 AND last_confirm_at IS NOT NULL AND state = 'online'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Pair
	for rows.Next() {
		var p Pair
		var dl sql.NullTime
		if err := rows.Scan(&p.TesterID, &dl); err != nil {
			return nil, err
		}
		if dl.Valid {
			p.Deadline = dl.Time
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
