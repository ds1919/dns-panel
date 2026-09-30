package store

// Slow sweep target list (docs/25 §7). Targets are ADDRESSES published in our zones (A and AAAA), not
// records: one address in three records is checked once. References to a target are kept per zone as
// segments "this address belonged to THIS record from..to"; when the last one closes, the target becomes
// unreferenced, and after the history retention period it goes away.
//
// The panel tells the daemon which zone changed (control socket `sweep`); a zone whose rebuild failed is
// flagged in pulse_sweep_dirty and retried from there.

import (
	"context"
	"database/sql"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

func sweepFamily(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return "" // not an address - cannot be a target
	}
	if a.Is4() {
		return "ipv4"
	}
	return "ipv6"
}

type sweepRef struct{ name, typ, ip string }

func (r sweepRef) key() string {
	return strings.ToLower(r.name) + "\x00" + strings.ToUpper(r.typ) + "\x00" + r.ip
}

// SweepSecondary reports the Pinger setting "include secondary zones" (pulse_sweep_secondary = 1).
func (d *DB) SweepSecondary(ctx context.Context) (bool, error) {
	var v string
	err := d.sql.QueryRowContext(ctx, "SELECT `value` FROM settings WHERE `key` = 'pulse_sweep_secondary'").Scan(&v)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return v == "1", err
}

// SweepSecondarySerials returns the SOA of every secondary zone: a zone whose SOA changed was transferred
// again and its addresses may have moved. The panel does not see transfers, so this is how the list follows them.
func (d *DB) SweepSecondarySerials(ctx context.Context) (map[uint32]string, error) {
	rows, err := d.pdns.QueryContext(ctx, `
		SELECT d.id, r.content FROM domains d JOIN records r ON r.domain_id = d.id AND r.type = 'SOA'
		 WHERE d.type = 'SLAVE'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[uint32]string{}
	for rows.Next() {
		var z uint32
		var soa string
		if err := rows.Scan(&z, &soa); err != nil {
			return nil, err
		}
		out[z] = soa
	}
	return out, rows.Err()
}

// SweepSyncZone brings one zone's references in line with what it publishes now. Returns the number of
// distinct addresses in the zone. On success the zone's dirty flag is cleared.
func (d *DB) SweepSyncZone(ctx context.Context, zone uint32, lockWait int) (int, error) {
	secondary, err := d.SweepSecondary(ctx)
	if err != nil {
		return 0, err
	}
	n, err := d.syncZone(ctx, zone, lockWait, secondary)
	if err != nil {
		return 0, err
	}
	return n, d.sweepTidy(ctx)
}

// syncZone is SweepSyncZone without the list-wide tidy-up, which a full rebuild runs once at the end.
// A zone that is gone, or a secondary while secondaries are off, publishes nothing to the sweep.
func (d *DB) syncZone(ctx context.Context, zone uint32, lockWait int, secondary bool) (int, error) {
	const scope = "default"
	conn, err := d.sql.Conn(ctx)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	// Rebuilds of ONE zone are serialized: two near-simultaneous edits would both see no open link and both
	// open one, splitting the address's ownership history. A named lock, taken on this connection.
	lock := fmt.Sprintf("psweep:%d", zone)
	var got sql.NullInt64
	if err := conn.QueryRowContext(ctx, "SELECT GET_LOCK(?, ?)", lock, lockWait).Scan(&got); err != nil {
		return 0, err
	}
	if !got.Valid || got.Int64 != 1 {
		return 0, fmt.Errorf("zone %d: sweep sync is already running", zone)
	}
	defer conn.ExecContext(context.Background(), "SELECT RELEASE_LOCK(?)", lock)

	// The zone is read UNDER the lock: otherwise a rebuild started earlier but locked later would lay its
	// stale snapshot over the fresh zone. Disabled records are not published, so there is nothing to check.
	rows, err := d.pdns.QueryContext(ctx, `
		SELECT r.name, r.type, r.content FROM records r JOIN domains d ON d.id = r.domain_id
		 WHERE r.domain_id = ? AND r.type IN ('A','AAAA') AND (r.disabled IS NULL OR r.disabled = 0)
		   AND (d.type <> 'SLAVE' OR ?)`, zone, secondary)
	if err != nil {
		return 0, err
	}
	want := map[string]sweepRef{}
	fam := map[string]string{}
	for rows.Next() {
		var r sweepRef
		var name sql.NullString
		if err := rows.Scan(&name, &r.typ, &r.ip); err != nil {
			rows.Close()
			return 0, err
		}
		r.name = name.String
		f := sweepFamily(r.ip)
		if f == "" {
			continue
		}
		fam[r.ip] = f
		want[r.key()] = r
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}

	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	// 1) Targets: an address in three records is one target.
	tid := map[string]uint64{}
	for ip, f := range fam {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO pulse_sweep_targets (target_ip, net_scope, family) VALUES (?,?,?)
			ON DUPLICATE KEY UPDATE family = VALUES(family)`, ip, scope, f); err != nil {
			return 0, err
		}
		var id uint64
		if err := tx.QueryRowContext(ctx, `SELECT id FROM pulse_sweep_targets WHERE target_ip = ? AND net_scope = ?`,
			ip, scope).Scan(&id); err != nil {
			return 0, err
		}
		tid[ip] = id
	}
	// 2) Open references of this zone: a reference gone from the zone is CLOSED, not deleted - "the address
	//    belonged to this record then" is history, needed exactly when the address has moved on.
	open, err := tx.QueryContext(ctx, `
		SELECT r.id, r.rr_name, r.rr_type, t.target_ip
		  FROM pulse_sweep_refs r JOIN pulse_sweep_targets t ON t.id = r.target_id
		 WHERE r.domain_id = ? AND r.until IS NULL AND t.net_scope = ?`, zone, scope)
	if err != nil {
		return 0, err
	}
	have := map[string]bool{}
	var closeIDs []uint64
	for open.Next() {
		var id uint64
		var r sweepRef
		if err := open.Scan(&id, &r.name, &r.typ, &r.ip); err != nil {
			open.Close()
			return 0, err
		}
		if _, ok := want[r.key()]; ok {
			have[r.key()] = true
		} else {
			closeIDs = append(closeIDs, id)
		}
	}
	open.Close()
	if err := open.Err(); err != nil {
		return 0, err
	}
	for _, id := range closeIDs {
		if _, err := tx.ExecContext(ctx, `UPDATE pulse_sweep_refs SET until = UTC_TIMESTAMP() WHERE id = ?`, id); err != nil {
			return 0, err
		}
	}
	// 3) New links get a new segment. A "record x address" pair has exactly one open link; MySQL has no
	//    partial UNIQUE, so the condition lives in the insert itself.
	for k, r := range want {
		if have[k] {
			continue
		}
		t := tid[r.ip]
		name, typ := strings.ToLower(r.name), strings.ToUpper(r.typ)
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO pulse_sweep_refs (target_id, domain_id, rr_name, rr_type, since)
			SELECT ?,?,?,?, UTC_TIMESTAMP() FROM DUAL
			 WHERE NOT EXISTS(SELECT 1 FROM pulse_sweep_refs x
			                   WHERE x.target_id = ? AND x.domain_id = ? AND x.rr_name = ?
			                     AND x.rr_type = ? AND x.until IS NULL)`,
			t, zone, name, typ, t, zone, name, typ); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	if _, err := conn.ExecContext(ctx, `DELETE FROM pulse_sweep_dirty WHERE domain_id = ?`, zone); err != nil {
		return 0, err
	}
	return len(fam), nil
}

// sweepTidy settles targets whose references came and went. It looks at the whole list, so a full rebuild runs
// it once, not per zone.
func (d *DB) sweepTidy(ctx context.Context) error {
	// A target without an OPEN reference has nobody to observe it: its last answer goes into history, the
	// state becomes unknown and a lease is cancelled (generation bumped, so an in-flight answer fails). If a
	// reference returns, freshness is not inherited: a week-old answer does not describe today's address.
	const hasOpen = "EXISTS(SELECT 1 FROM pulse_sweep_refs r WHERE r.target_id = t.id AND r.until IS NULL)"
	for _, q := range []string{
		`INSERT INTO pulse_sweep_intervals (target_id, state, started_at, ended_at)
		 SELECT t.id, t.last_state, COALESCE(t.state_since, t.last_checked_at, UTC_TIMESTAMP()), UTC_TIMESTAMP()
		   FROM pulse_sweep_targets t
		  WHERE t.unref_at IS NULL AND t.last_state <> 'unknown' AND NOT ` + hasOpen,
		`UPDATE pulse_sweep_targets t
		    SET t.unref_at = UTC_TIMESTAMP(), t.last_state = 'unknown', t.state_since = UTC_TIMESTAMP(),
		        t.leased_by = NULL, t.leased_until = NULL, t.lease_generation = t.lease_generation + 1
		  WHERE t.unref_at IS NULL AND NOT ` + hasOpen,
		`UPDATE pulse_sweep_targets t
		    SET t.unref_at = NULL, t.last_checked_at = NULL, t.last_checked_by = NULL,
		        t.last_state = 'unknown', t.state_since = UTC_TIMESTAMP()
		  WHERE t.unref_at IS NOT NULL AND ` + hasOpen,
		// Unreferenced for longer than the history retention: gone with references and segments (cascade).
		"DELETE t FROM pulse_sweep_targets t JOIN settings s ON s.`key` = 'pulse_history_days'" + `
		  WHERE t.unref_at IS NOT NULL
		    AND s.` + "`value`" + ` REGEXP '^[0-9]+$'
		    AND CAST(s.` + "`value`" + ` AS SIGNED) BETWEEN 1 AND 3650
		    AND t.unref_at < TIMESTAMPADD(DAY, -CAST(s.` + "`value`" + ` AS SIGNED), UTC_TIMESTAMP())
		    AND NOT ` + hasOpen,
	} {
		if _, err := d.sql.ExecContext(ctx, q); err != nil {
			return err
		}
	}
	return nil
}

// SweepMarkDirty flags a zone whose rebuild failed. The event comes once and DNS has already changed:
// without the flag the sweep would learn of the new address only at the next edit of the same zone.
func (d *DB) SweepMarkDirty(ctx context.Context, zone uint32, cause error) {
	msg := "sync failed"
	if cause != nil {
		msg = cause.Error()
	}
	if len(msg) > 255 {
		msg = msg[:255]
	}
	d.sql.ExecContext(ctx, `
		INSERT INTO pulse_sweep_dirty (domain_id, since, last_error) VALUES (?, UTC_TIMESTAMP(), ?)
		ON DUPLICATE KEY UPDATE attempts = attempts + 1, last_error = VALUES(last_error)`, zone, msg)
}

func (d *DB) sweepDirty(ctx context.Context) ([]uint32, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT domain_id FROM pulse_sweep_dirty ORDER BY since`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []uint32
	for rows.Next() {
		var z uint32
		if err := rows.Scan(&z); err != nil {
			return nil, err
		}
		out = append(out, z)
	}
	return out, rows.Err()
}

// SweepRetryDirty tries each flagged zone once; a failure keeps its flag.
func (d *DB) SweepRetryDirty(ctx context.Context, lockWait int) (failed int, err error) {
	zones, err := d.sweepDirty(ctx)
	if err != nil {
		return 0, err
	}
	for _, z := range zones {
		if _, e := d.SweepSyncZone(ctx, z, lockWait); e != nil {
			failed++
			d.SweepMarkDirty(ctx, z, e)
		}
	}
	return failed, nil
}

// SweepRefresh rebuilds every zone: our primaries, secondaries when the setting includes them, and zones the
// list still holds open references for (turned off or deleted, they are closed). Flagged zones go first.
// Each zone gets its own time limit, so a large installation is not cut off halfway. One failing zone does not
// stop the rest: it is flagged and the pass continues.
func (d *DB) SweepRefresh(ctx context.Context, lockWait int, perZone time.Duration) (targets, failed int, err error) {
	secondary, err := d.SweepSecondary(ctx)
	if err != nil {
		return 0, 0, err
	}
	dirty, err := d.sweepDirty(ctx)
	if err != nil {
		return 0, 0, err
	}
	zones, err := zoneIDs(ctx, d.pdns, `SELECT id FROM domains`)
	if err != nil {
		return 0, 0, err
	}
	held, err := zoneIDs(ctx, d.sql, `SELECT DISTINCT domain_id FROM pulse_sweep_refs WHERE until IS NULL`)
	if err != nil {
		return 0, 0, err
	}
	seen := map[uint32]bool{}
	for _, z := range append(append(dirty, zones...), held...) {
		if seen[z] {
			continue
		}
		seen[z] = true
		if ctx.Err() != nil {
			return targets, failed, ctx.Err()
		}
		zctx, cancel := context.WithTimeout(ctx, perZone)
		n, e := d.syncZone(zctx, z, lockWait, secondary)
		cancel()
		if e != nil {
			failed++
			d.SweepMarkDirty(ctx, z, e)
			continue
		}
		targets += n
	}
	tctx, cancel := context.WithTimeout(ctx, perZone)
	defer cancel()
	return targets, failed, d.sweepTidy(tctx)
}

func zoneIDs(ctx context.Context, db *sql.DB, q string) ([]uint32, error) {
	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []uint32
	for rows.Next() {
		var z uint32
		if err := rows.Scan(&z); err != nil {
			return nil, err
		}
		out = append(out, z)
	}
	return out, rows.Err()
}
