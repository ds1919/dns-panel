// Package store is pulse-server's access to dns_panel. It also holds the invariants agreed in docs/25:
// transitions are written under a row lock, history stores only CLOSED intervals, a transition to the
// same state is not a transition, and the unknown reason does not affect intervals.
package store

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"

	"dnspanel/dns-pulse/internal/wire"

	_ "github.com/go-sql-driver/mysql"
)

// sql is the panel database (dns_panel); pdns the PowerDNS one, opened read-only for the slow sweep.
type DB struct {
	sql  *sql.DB
	pdns *sql.DB
}

func Open(socket, name, user, pass string) (*DB, error) {
	dsn := fmt.Sprintf("%s:%s@unix(%s)/%s?parseTime=true&loc=UTC&time_zone=%%27%%2B00%%3A00%%27",
		user, pass, socket, name)
	h, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}
	h.SetMaxOpenConns(8)
	h.SetConnMaxLifetime(time.Hour)
	return &DB{sql: h}, nil
}

// OpenPDNS connects to the PowerDNS database with the daemon's own account (unix_socket authentication, no
// password): the sweep only reads which addresses the zones publish.
func (d *DB) OpenPDNS(socket, name, user string) error {
	h, err := sql.Open("mysql", fmt.Sprintf("%s@unix(%s)/%s?parseTime=true&loc=UTC", user, socket, name))
	if err != nil {
		return err
	}
	h.SetMaxOpenConns(2)
	h.SetConnMaxLifetime(time.Hour)
	d.pdns = h
	return nil
}

func (d *DB) Close() error                   { return d.sql.Close() }
func (d *DB) Ping(ctx context.Context) error { return d.sql.PingContext(ctx) }

type Tester struct {
	ID            uint32
	Name          string
	Enabled       bool
	Approved      bool
	ConfirmMaxAge time.Duration
}

// Auth identifies an agent by its OWN self-generated key; only the hash is stored, like passwords.
//
// Unapproved agents pass too: "not approved yet" and "unknown to me" are different news for the person
// on that machine, and the agent must say which. Whether it gets tasks is decided by the caller.
func (d *DB) Auth(ctx context.Context, agentKey string) (*Tester, error) {
	sum := sha256.Sum256([]byte(agentKey))
	row := d.sql.QueryRowContext(ctx,
		`SELECT id, COALESCE(name,''), enabled, approved_at IS NOT NULL, confirm_max_age_seconds
		   FROM pulse_testers WHERE key_hash = ?`,
		hex.EncodeToString(sum[:]))
	var t Tester
	var secs uint32
	if err := row.Scan(&t.ID, &t.Name, &t.Enabled, &t.Approved, &secs); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	t.ConfirmMaxAge = time.Duration(secs) * time.Second
	return &t, nil
}

// Enroll registers a request from an unknown machine. The site enrollment key grants only a place in the
// pending list: no tasks and no results until a human approves, so a leaked key means queue garbage, not
// influence on DNS.
//
// Reconnects of the same machine do not add rows: the agent key is unique and the request just refreshes
// address, version and time. Otherwise a forgotten agent would pile up thousands overnight.
func (d *DB) Enroll(ctx context.Context, agentKey, enrollKey, hostname, addr, version string) (bool, error) {
	var want string
	err := d.sql.QueryRowContext(ctx, `SELECT enroll_key FROM pulse_enrollment WHERE id = 1`).Scan(&want)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if want == "" || subtle.ConstantTimeCompare([]byte(want), []byte(enrollKey)) != 1 {
		return false, nil
	}
	sum := sha256.Sum256([]byte(agentKey))
	_, err = d.sql.ExecContext(ctx, `
		INSERT INTO pulse_testers (key_hash, hostname, addr, agent_version, state, state_since, last_seen_at)
		VALUES (?,?,?,?, 'silent', UTC_TIMESTAMP(), UTC_TIMESTAMP())
		ON DUPLICATE KEY UPDATE hostname = VALUES(hostname), addr = VALUES(addr),
		                        agent_version = VALUES(agent_version), last_seen_at = UTC_TIMESTAMP()`,
		hex.EncodeToString(sum[:]), nullable(hostname), nullable(addr), nullable(version))
	if err != nil {
		return false, err
	}
	return true, nil
}

// Params is the ONE question asked on every agent message: its current working parameters. It answers
// both whether it may still talk (deleted, disabled, approval revoked) and the freshness window (which
// may have changed in the panel). Two separate mechanisms for these would drift apart.
func (d *DB) Params(ctx context.Context, id uint32, agentKey string) (bool, time.Duration, error) {
	sum := sha256.Sum256([]byte(agentKey))
	var secs uint32
	err := d.sql.QueryRowContext(ctx,
		`SELECT confirm_max_age_seconds FROM pulse_testers
		  WHERE id = ? AND enabled = 1 AND key_hash = ? AND approved_at IS NOT NULL`,
		id, hex.EncodeToString(sum[:])).Scan(&secs)
	if err == sql.ErrNoRows {
		return false, 0, nil
	}
	if err != nil {
		return false, 0, err
	}
	return true, time.Duration(secs) * time.Second, nil
}

// SeenFrom records where and with what version the agent connected. Address changes are informative,
// not a restriction: the token identifies the agent (docs/25 §1).
func (d *DB) SeenFrom(ctx context.Context, testerID uint32, addr, version string, canV4, canV6 bool) error {
	// Agent capabilities are observations, not settings; the panel shows WHY an agent gets no AAAA targets.
	_, err := d.sql.ExecContext(ctx, `
		UPDATE pulse_testers SET addr = ?, agent_version = ?, can_ipv4 = ?, can_ipv6 = ?,
		       last_seen_at = UTC_TIMESTAMP()
		 WHERE id = ?`, nullable(addr), nullable(version), canV4, canV6, testerID)
	return err
}

// trimHistory prunes each object's history where it is written: closing an interval drops that object's
// old intervals, so no scheduled sweep is needed and growth is bounded by retention.
//
// Retention lives in panel settings and there is deliberately NO default here: no setting row means no
// pruning. Hence the JOIN: an empty setting means "delete nothing", not a number made up by the daemon.
func trimHistory(ctx context.Context, tx *sql.Tx, table, where string, args ...any) error {
	// Validate the value HERE too: garbage would CAST to zero, i.e. "keep zero days", and wipe all history.
	// An unparseable value deletes nothing; losing history is worse than keeping it.
	_, err := tx.ExecContext(ctx, `
		DELETE h FROM `+table+` h
		  JOIN settings s ON s.`+"`key`"+` = 'pulse_history_days'
		 WHERE `+where+`
		   AND s.`+"`value`"+` REGEXP '^[0-9]+$'
		   AND CAST(s.`+"`value`"+` AS SIGNED) BETWEEN 1 AND 3650
		   AND h.ended_at < TIMESTAMPADD(DAY, -CAST(s.`+"`value`"+` AS SIGNED), UTC_TIMESTAMP())`, args...)
	return err
}

type Task struct {
	CheckID       uint32
	ConfigVersion uint32
	Kind          string
	TargetIP      string
	Port          uint32
	Interval      time.Duration
	Timeout       time.Duration
	ProbesPerRun  uint32
	OKProbes      uint32
	FailThreshold uint32
	OKThreshold   uint32
}

// Tasks returns what this agent must run: checks assigned to one of its groups or to it by name (the same
// union as the panel's _pulse_runners_sql). A pair exists while the assignment exists, but a TASK is issued
// only when both sides are enabled; these are different questions (docs/25 §4).
func (d *DB) Tasks(ctx context.Context, testerID uint32) ([]Task, error) {
	rows, err := d.sql.QueryContext(ctx, `
		SELECT c.id, c.config_version, c.kind, c.target_ip, COALESCE(c.port,0),
		       c.interval_seconds, c.timeout_ms, c.probes_per_run, c.ok_probes_required,
		       c.fail_threshold, c.ok_threshold
		  FROM pulse_checks c
		  JOIN pulse_testers t ON t.id = ?
		 WHERE c.enabled = 1 AND t.enabled = 1
		   AND c.id IN (SELECT cg.check_id FROM pulse_check_groups cg
		                  JOIN pulse_group_members m ON m.group_id = cg.group_id
		                 WHERE m.tester_id = ?
		                UNION
		                SELECT ca.check_id FROM pulse_check_agents ca WHERE ca.tester_id = ?)
		 ORDER BY c.id`, testerID, testerID, testerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Task
	for rows.Next() {
		var t Task
		var ivSec, toMs uint32
		if err := rows.Scan(&t.CheckID, &t.ConfigVersion, &t.Kind, &t.TargetIP, &t.Port,
			&ivSec, &toMs, &t.ProbesPerRun, &t.OKProbes, &t.FailThreshold, &t.OKThreshold); err != nil {
			return nil, err
		}
		t.Interval = time.Duration(ivSec) * time.Second
		t.Timeout = time.Duration(toMs) * time.Millisecond
		out = append(out, t)
	}
	return out, rows.Err()
}

// Confirm refreshes freshness; a result refreshes it too, since it proves the check is running (docs/25 §3).
// The version must match: confirming an old task says nothing about the current one.
func (d *DB) Confirm(ctx context.Context, testerID uint32, checks []wire.CheckVersion) error {
	// An empty list is a valid answer ("running nothing") and still proves the agent is alive.
	tx, err := d.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, cv := range checks {
		if _, err := tx.ExecContext(ctx, `
			UPDATE pulse_results r
			   JOIN pulse_checks c ON c.id = r.check_id
			   SET r.confirmed_at = UTC_TIMESTAMP()
			 WHERE r.check_id = ? AND r.tester_id = ? AND c.config_version = ?`,
			cv.CheckID, testerID, cv.ConfigVersion); err != nil {
			return err
		}
	}
	// The agent spoke. If it was silent, this is a TRANSITION: close the silence interval and open a new
	// current one. A same-state transition is not a transition, so an online agent is left alone.
	var state string
	var since sql.NullTime
	if err := tx.QueryRowContext(ctx,
		`SELECT state, state_since FROM pulse_testers WHERE id = ? FOR UPDATE`, testerID).
		Scan(&state, &since); err != nil {
		return err
	}
	if state != "online" {
		if err := closeTesterInterval(ctx, tx, testerID, state, since, time.Now().UTC()); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE pulse_testers SET last_confirm_at = UTC_TIMESTAMP(), last_seen_at = UTC_TIMESTAMP(),
		        state = 'online', state_since = IF(state = 'online', state_since, UTC_TIMESTAMP())
		  WHERE id = ?`, testerID); err != nil {
		return err
	}
	return tx.Commit()
}

// Transition changes a pair's state. The transaction starts by locking the result row and reads the
// previous state UNDER that lock: computing from a `since` read earlier would eventually write two
// intervals with the same start (docs/25 §4.1).
//
// It returns true if the state actually changed.
func (d *DB) Transition(ctx context.Context, testerID, checkID, version uint32, state, detail string) (bool, error) {
	tx, err := d.sql.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	var cur string
	var since time.Time
	var curVersion uint32
	err = tx.QueryRowContext(ctx, `
		SELECT r.state, r.since, c.config_version FROM pulse_results r
		  JOIN pulse_checks c ON c.id = r.check_id
		 WHERE r.check_id = ? AND r.tester_id = ? FOR UPDATE`, checkID, testerID).Scan(&cur, &since, &curVersion)
	if err == sql.ErrNoRows {
		return false, nil // the pair no longer exists
	}
	if err != nil {
		return false, err
	}
	if curVersion != version {
		return false, nil // a result for an old task version proves nothing
	}
	if cur == state {
		// Not a transition: otherwise a repeated report after reconnect would split history where nothing changed.
		_, err = tx.ExecContext(ctx,
			`UPDATE pulse_results SET confirmed_at = UTC_TIMESTAMP(), last_report_at = UTC_TIMESTAMP(),
			        detail = ? WHERE check_id = ? AND tester_id = ?`, nullable(detail), checkID, testerID)
		if err != nil {
			return false, err
		}
		return false, tx.Commit()
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO pulse_intervals (check_id, tester_id, state, started_at, ended_at)
		VALUES (?, ?, ?, ?, UTC_TIMESTAMP())`, checkID, testerID, cur, since); err != nil {
		return false, err
	}
	if err := trimHistory(ctx, tx, "pulse_intervals", "h.check_id = ? AND h.tester_id = ?",
		checkID, testerID); err != nil {
		return false, err
	}
	okAt, failAt := "last_ok_at", "last_fail_at"
	if state != "healthy" {
		okAt, failAt = failAt, okAt
	}
	_, err = tx.ExecContext(ctx, fmt.Sprintf(`
		UPDATE pulse_results SET state = ?, unknown_reason = NULL, since = UTC_TIMESTAMP(),
		       confirmed_at = UTC_TIMESTAMP(), last_report_at = UTC_TIMESTAMP(),
		       %s = UTC_TIMESTAMP(), detail = ? WHERE check_id = ? AND tester_id = ?`, okAt),
		state, nullable(detail), checkID, testerID)
	if err != nil {
		return false, err
	}
	_ = failAt
	return true, tx.Commit()
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}
