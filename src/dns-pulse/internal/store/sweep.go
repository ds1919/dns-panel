package store

import (
	"context"
	"database/sql"
	"time"
)

// Slow sweep (docs/25 §7). Targets are addresses published in zones; the panel maintains the list on its
// write path, and this file is just the queue: which target goes to whom and how answers are accepted.
// There is no voting: each round ONE executor checks a target and its state is the last accepted answer,
// so all the strictness lives in the lease fence.

// Policy holds the sweep parameters. They are owned by the PANEL (settings rows) and there are
// deliberately no defaults here: no rows means no sweep, so the daemon never diverges from what the UI shows.
type Policy struct {
	Interval time.Duration // round: how often each address is checked
	Timeout  time.Duration // limit for one probe
	Batch    int           // targets handed out at once
	Parallel int           // concurrent probes per agent
	Probes   int           // attempts per target: one lost packet is not an outage
}

// Lease is the batch lease duration. It is derived from the batch, not configured: the time the batch can
// honestly take (targets / parallelism, each up to the probe timeout), doubled for transit and slow networks.
//
// Whole seconds, at least one: leases are stored in seconds, and a sub-second lease (e.g. one target with
// a 100 ms timeout) would round to zero and every answer would be rejected as expired.
func (p Policy) Lease() time.Duration {
	rounds := (p.Batch + p.Parallel - 1) / p.Parallel
	full := 2 * time.Duration(rounds*p.Probes) * p.Timeout
	secs := (full + time.Second - 1) / time.Second // round up: too short is worse than too long
	if secs < 1 {
		secs = 1
	}
	return secs * time.Second
}

// SweepPolicy reads the parameters. ok=false means the panel has not set them yet: the sweep does not run
// at all, and that shows in the log instead of silently running on invented numbers.
func (d *DB) SweepPolicy(ctx context.Context) (Policy, bool, error) {
	rows, err := d.sql.QueryContext(ctx, `
		SELECT `+"`key`, `value`"+` FROM settings
		 WHERE `+"`key`"+` IN ('pulse_sweep_interval','pulse_sweep_timeout_ms',
		                       'pulse_sweep_batch','pulse_sweep_parallel','pulse_sweep_probes')`)
	if err != nil {
		return Policy{}, false, err
	}
	defer rows.Close()
	v := map[string]int{}
	for rows.Next() {
		var k string
		var n int
		if err := rows.Scan(&k, &n); err != nil {
			return Policy{}, false, err
		}
		v[k] = n
	}
	if err := rows.Err(); err != nil {
		return Policy{}, false, err
	}
	if len(v) != 5 || v["pulse_sweep_interval"] < 1 || v["pulse_sweep_timeout_ms"] < 1 ||
		v["pulse_sweep_batch"] < 1 || v["pulse_sweep_parallel"] < 1 || v["pulse_sweep_probes"] < 1 {
		return Policy{}, false, nil
	}
	return Policy{
		Interval: time.Duration(v["pulse_sweep_interval"]) * time.Second,
		Timeout:  time.Duration(v["pulse_sweep_timeout_ms"]) * time.Millisecond,
		Batch:    v["pulse_sweep_batch"],
		Parallel: v["pulse_sweep_parallel"],
		Probes:   v["pulse_sweep_probes"],
	}, true, nil
}

// SweepWait returns how long until the nearest eligible target CAN BE TAKEN, computed by the database so
// agents neither wake up idle nor run half a round late.
//
// Both bounds are required. Round: a checked target is due interval after its last check, an unchecked one
// is due now. Lease: a due target may have just been leased by another agent and stays taken until the lease
// ends. Considering only the round gives either a hot loop (due but leased: "wait zero", ask again) or an
// hour-long sleep where a lease on an unchecked target would expire in twenty seconds.
func (d *DB) SweepWait(ctx context.Context, p Policy, canV4, canV6 bool) (time.Duration, error) {
	var secs sql.NullInt64
	err := d.sql.QueryRowContext(ctx, `
		SELECT MIN(GREATEST(0, TIMESTAMPDIFF(SECOND, UTC_TIMESTAMP(), GREATEST(
		           COALESCE(TIMESTAMPADD(SECOND, ?, last_checked_at), UTC_TIMESTAMP()),
		           COALESCE(leased_until, UTC_TIMESTAMP())))))
		  FROM pulse_sweep_targets
		 WHERE unref_at IS NULL
		   AND ((family = 'ipv4' AND ?) OR (family = 'ipv6' AND ?))`,
		int(p.Interval.Seconds()), canV4, canV6).Scan(&secs)
	if err != nil {
		return 0, err
	}
	if !secs.Valid {
		return p.Interval, nil // no eligible targets: ask again in a round
	}
	return time.Duration(secs.Int64) * time.Second, nil
}

// SweepTarget is a leased target. The generation round-trips with the answer; without it a stalled agent's
// answer could not be told apart from the current lease holder's.
type SweepTarget struct {
	ID         uint64
	IP         string
	Family     string // ipv4 | ipv6
	Generation uint32
}

// ClaimSweep leases a batch of targets. Selection and lease happen in ONE transaction with SKIP LOCKED, so
// concurrent agents take different rows. The family comes from the executor: only agents that really have
// IPv6 get AAAA targets, since "cannot check" is unknown, not unavailable.
//
// Order: least recently checked first, never checked before all. due is the earliest time a target may be
// taken again: the round is set by the panel, not by agent speed.
func (d *DB) ClaimSweep(ctx context.Context, testerID uint32, canV4, canV6 bool,
	limit int, due time.Time, lease time.Duration) ([]SweepTarget, error) {
	if limit <= 0 || (!canV4 && !canV6) {
		return nil, nil
	}
	tx, err := d.sql.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	rows, err := tx.QueryContext(ctx, `
		SELECT id FROM pulse_sweep_targets
		 WHERE unref_at IS NULL
		   AND ((family = 'ipv4' AND ?) OR (family = 'ipv6' AND ?))
		   AND (leased_until IS NULL OR leased_until <= UTC_TIMESTAMP())
		   AND (last_checked_at IS NULL OR last_checked_at <= ?)
		 ORDER BY last_checked_at IS NOT NULL, last_checked_at, id
		 LIMIT ? FOR UPDATE SKIP LOCKED`, canV4, canV6, due.UTC(), limit)
	if err != nil {
		return nil, err
	}
	var ids []any
	for rows.Next() {
		var id uint64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, nil
	}

	in := placeholders(len(ids))
	args := append([]any{testerID, int(lease.Seconds())}, ids...)
	if _, err := tx.ExecContext(ctx, `
		UPDATE pulse_sweep_targets
		   SET leased_by = ?, leased_until = TIMESTAMPADD(SECOND, ?, UTC_TIMESTAMP()),
		       lease_generation = lease_generation + 1
		 WHERE id IN (`+in+`)`, args...); err != nil {
		return nil, err
	}
	trows, err := tx.QueryContext(ctx, `
		SELECT id, target_ip, family, lease_generation FROM pulse_sweep_targets
		 WHERE id IN (`+in+`)`, ids...)
	if err != nil {
		return nil, err
	}
	var out []SweepTarget
	for trows.Next() {
		var t SweepTarget
		if err := trows.Scan(&t.ID, &t.IP, &t.Family, &t.Generation); err != nil {
			trows.Close()
			return nil, err
		}
		out = append(out, t)
	}
	trows.Close()
	if err := trows.Err(); err != nil {
		return nil, err
	}
	return out, tx.Commit()
}

// ApplySweepResult accepts an answer only if the target is still leased by the SAME executor, with the SAME
// generation, and the lease has NOT EXPIRED. Otherwise an agent that stalled for an hour would write its
// stale "unavailable" over a fresh "available" and show an outage that no longer exists.
//
// Orphaned targets reject answers too: the address may have left the zone while being measured. When the
// panel orphans a target it voids the lease and bumps the generation, so an address that comes back is
// checked afresh rather than "already checked" by an answer obtained before it disappeared.
//
// Expiry is checked separately from generation: after a lease expires and before someone else takes the
// target, the generation is still old. A lease is PERMISSION to answer: too late means the answer is dropped
// and the target returns to the round. A second answer on the same lease fails the same check, since
// accepting clears the lease.
//
// It returns (answer accepted, state changed).
func (d *DB) ApplySweepResult(ctx context.Context, testerID uint32, targetID uint64, generation uint32,
	state string) (bool, bool, error) {
	// Only measurements are valid answers. `unknown` is a SERVER state (no current measurement) and agents may
	// not send it: if an agent could not measure, let the lease expire. Otherwise history would show
	// "checked at 12:00, unknown" when nobody touched the target at 12:00.
	if state != "available" && state != "unavailable" {
		return false, false, nil
	}
	tx, err := d.sql.BeginTx(ctx, nil)
	if err != nil {
		return false, false, err
	}
	defer tx.Rollback()

	var prev string
	var since sql.NullTime
	err = tx.QueryRowContext(ctx, `
		SELECT last_state, state_since FROM pulse_sweep_targets
		 WHERE id = ? AND leased_by = ? AND lease_generation = ?
		   AND leased_until > UTC_TIMESTAMP() AND unref_at IS NULL FOR UPDATE`,
		targetID, testerID, generation).Scan(&prev, &since)
	if err == sql.ErrNoRows {
		return false, false, nil // late, expired, foreign or duplicate: ignore silently
	}
	if err != nil {
		return false, false, err
	}

	changed := prev != state
	// History stores only CLOSED intervals (§4.1); the open one is last_state + state_since on the target.
	if changed && since.Valid {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO pulse_sweep_intervals (target_id, state, started_at, ended_at, ended_by)
			VALUES (?,?,?, UTC_TIMESTAMP(), ?)`, targetID, prev, since.Time, testerID); err != nil {
			return false, false, err
		}
		// Prune this target's history right where it grows.
		if err := trimHistory(ctx, tx, "pulse_sweep_intervals", "h.target_id = ?", targetID); err != nil {
			return false, false, err
		}
	}
	q := `UPDATE pulse_sweep_targets
	         SET last_checked_at = UTC_TIMESTAMP(), last_checked_by = ?,
	             leased_by = NULL, leased_until = NULL`
	args := []any{testerID}
	if changed || !since.Valid {
		q += `, last_state = ?, state_since = UTC_TIMESTAMP()`
		args = append(args, state)
	}
	args = append(args, targetID)
	if _, err := tx.ExecContext(ctx, q+` WHERE id = ?`, args...); err != nil {
		return false, false, err
	}
	return true, changed, tx.Commit()
}

// ReleaseSweep returns targets to the round when no answer will come (the agent disconnected mid-batch),
// instead of waiting for the lease to expire.
//
// Only the NAMED leases with their issued generation are released. Releasing everything held by the
// executor is wrong: on reconnect the old and new sessions of one agent briefly coexist, and the old one
// would drop leases the new one just took.
func (d *DB) ReleaseSweep(ctx context.Context, testerID uint32, leases []SweepTarget) error {
	if len(leases) == 0 {
		return nil
	}
	q := `UPDATE pulse_sweep_targets SET leased_by = NULL, leased_until = NULL WHERE leased_by = ? AND (`
	args := []any{testerID}
	for i, l := range leases {
		if i > 0 {
			q += " OR "
		}
		q += "(id = ? AND lease_generation = ?)"
		args = append(args, l.ID, l.Generation)
	}
	_, err := d.sql.ExecContext(ctx, q+")", args...)
	return err
}

func placeholders(n int) string {
	if n <= 0 {
		return "NULL"
	}
	s := make([]byte, 0, n*3)
	for i := 0; i < n; i++ {
		if i > 0 {
			s = append(s, ',')
		}
		s = append(s, '?')
	}
	return string(s)
}
