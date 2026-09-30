package agentd

import (
	"bufio"
	"context"
	"database/sql"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Local MariaDB control: node role (writable/read-only) and replication direction.
//
// Every action is idempotent and verifies its result: SET GLOBAL can succeed without taking effect, and
// START SLAVE can return ok while the thread is stuck in Connecting. Trusting such answers would declare a
// switchover complete on a dead replica.

// ReseedBudget is the executor's reseed ceiling. Exported for one check: executor < client < socket deadlines.
// It must match what the client allots (agent.executorReseed), and the client waits longer
// (agent.ReseedTimeout = +10 s). An external deadline, if earlier, wins via context.WithTimeout.
const ReseedBudget = 600 * time.Second

// Phase timeouts. The worst-case drain (IO stop + apply wait) must fit the client's deadline.
const (
	ioStopTimeout = 15 * time.Second
	drainTimeout  = 30 * time.Second
	rejoinTimeout = 15 * time.Second
	// Per-query timeout, not just connect: otherwise a hung SHOW SLAVE STATUS or SET GLOBAL ignores the
	// phase timeouts. Must exceed the longest intentional wait (MASTER_GTID_WAIT for drainTimeout).
	queryTimeout = drainTimeout + 30*time.Second
)

// One connection pool per process (per DSN), not per request: Node is copied per request (WithContext),
// so a pool held in a field would be recreated on every status poll and never closed.
var (
	poolsMu sync.Mutex
	pools   = map[string]*sql.DB{}
)

// pool returns the shared pool for this node's DSN, so per-request copies of Node reuse it.
func (n *Node) pool() (*sql.DB, error) {
	dsn := fmt.Sprintf("%s@unix(%s)/?parseTime=true&timeout=5s&readTimeout=%s&writeTimeout=10s",
		n.Cfg.MySQL.User, n.Cfg.MySQL.Socket, queryTimeout)
	poolsMu.Lock()
	defer poolsMu.Unlock()
	if db := pools[dsn]; db != nil {
		return db, nil
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fail("db_connect_failed", err.Error())
	}
	db.SetMaxOpenConns(2)
	pools[dsn] = db
	return db, nil
}

// db deliberately does not ping: a successful ping promises nothing to the next query, whose error must be
// handled anyway. Reachability is checked where it is the goal (Preflight/Status).
func (n *Node) db() (*sql.DB, error) { return n.pool() }

func (n *Node) readOnly() (*int64, error) {
	db, err := n.db()
	if err != nil {
		return nil, err
	}
	var v int64
	if err := db.QueryRowContext(n.ctx(), "SELECT @@global.read_only").Scan(&v); err != nil {
		return nil, fail("read_only_unknown", err.Error())
	}
	return &v, nil
}

// replicaStatus is the single reader of replication state. A failed SHOW means "unknown", not "no replica":
// the difference decides whether the node may become writable.
func (n *Node) replicaStatus() (*ReplicaStatus, bool) {
	db, err := n.db()
	if err != nil {
		return nil, false
	}
	answered := false
	for _, q := range []string{"SHOW REPLICA STATUS", "SHOW SLAVE STATUS"} {
		rows, err := db.QueryContext(n.ctx(), q)
		if err != nil {
			continue // new/old command name: try the other one
		}
		answered = true
		st, ok := scanReplicaStatus(rows)
		rows.Close()
		if !ok {
			return nil, false
		}
		if st.Present {
			return st, true
		}
		// Successful SHOW with no row: replica not configured. Confirm with the second name.
		if q == "SHOW SLAVE STATUS" {
			return st, true
		}
	}
	// No SHOW succeeded: "unknown", not "no replica". Otherwise an unreachable DB would pass as proven
	// absence of replication and detach would report success having done nothing.
	if !answered {
		return nil, false
	}
	return &ReplicaStatus{}, true
}

func scanReplicaStatus(rows *sql.Rows) (*ReplicaStatus, bool) {
	cols, err := rows.Columns()
	if err != nil {
		return nil, false
	}
	if !rows.Next() {
		// An empty result and an aborted read both end with Next()==false; only rows.Err() tells them
		// apart. A failed SHOW must not pass as proven absence of replication (that permits writable).
		if err := rows.Err(); err != nil {
			return nil, false
		}
		return &ReplicaStatus{}, true // clean empty result: replica not configured
	}
	vals := make([]any, len(cols))
	ptrs := make([]any, len(cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	if err := rows.Scan(ptrs...); err != nil {
		return nil, false
	}
	m := map[string]string{}
	for i, c := range cols {
		m[c] = asString(vals[i])
	}
	st := &ReplicaStatus{
		Present:      true,
		IORunning:    first(m, "Replica_IO_Running", "Slave_IO_Running"),
		SQLRunning:   first(m, "Replica_SQL_Running", "Slave_SQL_Running"),
		MasterHost:   first(m, "Master_Host", "Source_Host"),
		GtidIOPos:    first(m, "Gtid_IO_Pos"),
		LastIOError:  first(m, "Last_IO_Error"),
		LastSQLError: first(m, "Last_SQL_Error", "Last_Error"),
	}
	return st, true
}

// Promote makes the node the write source.
//
// Replication is stopped and proven stopped (strictly No/No) before read_only is cleared; the reverse order
// allows a node that is both ACTIVE and a replica, i.e. circular replication.
func (n *Node) Promote() (Response, error) {
	db, err := n.db()
	if err != nil {
		return failResp(err), nil
	}
	db.ExecContext(n.ctx(), "STOP SLAVE")
	st, showOK := n.replicaStatus()
	if err := PromoteReady(st, showOK); err != nil {
		return failResp(err), nil
	}
	ro, err := n.readOnly()
	if err != nil {
		return failResp(err), nil
	}
	if *ro == 0 {
		return Response{OK: true, Noop: true, Status: map[string]any{"read_only": 0}}, nil
	}
	if _, err := db.ExecContext(n.ctx(), "SET GLOBAL read_only = 0"); err != nil {
		return failResp(fail("set_writable_failed", err.Error())), nil
	}
	// Verify: an unreadable value is not success.
	if ro, err = n.readOnly(); err != nil || *ro != 0 {
		return failResp(fail("read_only_unverified", "read_only != 0 or unreadable after promote")), nil
	}
	return Response{OK: true, Status: map[string]any{"read_only": 0}}, nil
}

// Demote returns the node to read-only.
func (n *Node) Demote() (Response, error) {
	db, err := n.db()
	if err != nil {
		return failResp(err), nil
	}
	ro, err := n.readOnly()
	if err != nil {
		return failResp(err), nil
	}
	if *ro == 1 {
		return Response{OK: true, Noop: true, Status: map[string]any{"read_only": 1}}, nil
	}
	if _, err := db.ExecContext(n.ctx(), "SET GLOBAL read_only = 1"); err != nil {
		return failResp(fail("set_readonly_failed", err.Error())), nil
	}
	if ro, err = n.readOnly(); err != nil || *ro != 1 {
		return failResp(fail("read_only_unverified", "read_only != 1 or unreadable after demote")), nil
	}
	return Response{OK: true, Status: map[string]any{"read_only": 1}}, nil
}

// RejoinReplica attaches this node as a replica of primary and verifies it came up.
//
// seedFromBinlog starts from the node's own position. It is for a former source after a planned handover:
// it provably has nothing newer than the target applied, while its stale gtid_slave_pos points into history
// the new source no longer has (error 1236). Without that proof the flag would silently skip missed data.
func (n *Node) RejoinReplica(primary string, seedFromBinlog bool) (Response, error) {
	db, err := n.db()
	if err != nil {
		return failResp(err), nil
	}
	db.ExecContext(n.ctx(), "SET GLOBAL read_only = 1")
	db.ExecContext(n.ctx(), "STOP SLAVE")

	// A node that was never a replica has an empty gtid_slave_pos, and MASTER_USE_GTID=slave_pos would pull
	// the source binlog from the start. Seed it with what the node already has.
	//
	// gtid_current_pos, not gtid_binlog_pos: current merges own binlog and replicated-applied, i.e. the data
	// the node actually holds. The binlog can be empty with non-empty data (freshly reseeded after RESET
	// MASTER, or a shift with no writes); an empty position would replay the source's whole history.
	var slavePos sql.NullString
	db.QueryRowContext(n.ctx(), "SELECT @@gtid_slave_pos").Scan(&slavePos)
	if seedFromBinlog || !slavePos.Valid || slavePos.String == "" {
		var curPos sql.NullString
		db.QueryRowContext(n.ctx(), "SELECT @@gtid_current_pos").Scan(&curPos)
		if !curPos.Valid || curPos.String == "" {
			// No position at all: the node is empty or its history unknown. Refuse and require a reseed.
			return failResp(fail("seed_gtid_empty",
				"the node has no GTID position — an incremental attach is impossible, a reseed is required")), nil
		}
		if _, err := db.ExecContext(n.ctx(), "SET GLOBAL gtid_slave_pos = ?", curPos.String); err != nil {
			return failResp(fail("seed_gtid_failed", err.Error())), nil
		}
	}
	if err := n.changeMaster(db, primary); err != nil {
		return failResp(err), nil
	}
	if _, err := db.ExecContext(n.ctx(), "START SLAVE"); err != nil {
		return failResp(fail("start_slave_failed", err.Error())), nil
	}
	if err := n.verifyReplica(primary); err != nil {
		return failResp(err), nil
	}
	return Response{OK: true, Status: map[string]any{"read_only": 1, "replicating_from": primary}}, nil
}

func (n *Node) changeMaster(db *sql.DB, primary string) error {
	pass, err := n.Cfg.replicationSecret()
	if err != nil {
		return err
	}
	// CHANGE MASTER does not support placeholders, so values are quoted explicitly.
	q := fmt.Sprintf("CHANGE MASTER TO MASTER_HOST=%s, MASTER_PORT=%d, MASTER_USER=%s, MASTER_PASSWORD=%s, MASTER_USE_GTID=slave_pos",
		quote(primary), n.Cfg.Replication.Port, quote(n.Cfg.Replication.User), quote(pass))
	if _, err := db.ExecContext(n.ctx(), q); err != nil {
		return fail("change_master_failed", err.Error())
	}
	return nil
}

// pause sleeps between polls; it returns false if the operation was cancelled.
func (n *Node) pause(d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-n.ctx().Done():
		return false
	case <-t.C:
		return true
	}
}

// verifyReplica proves the replica is actually connected to the expected source.
func (n *Node) verifyReplica(primary string) error {
	// The phase limit applies to the queries themselves, not only to the gaps, or one hung SHOW defeats it.
	ctx, cancel := context.WithTimeout(n.ctx(), rejoinTimeout)
	defer cancel()
	pn := n.WithContext(ctx)
	deadline := time.Now().Add(rejoinTimeout)
	var st *ReplicaStatus
	for {
		st, _ = pn.replicaStatus()
		if ReplicaHealthy(st, primary) {
			return nil
		}
		if time.Now().After(deadline) {
			break
		}
		if !pn.pause(time.Second) {
			break // cancelled or phase limit reached
		}
	}
	io, sqlt, mh, lerr := "", "", "", ""
	if st != nil {
		io, sqlt, mh, lerr = st.IORunning, st.SQLRunning, st.MasterHost, st.LastIOError
	}
	code := ReplicaFailureCode(lerr)
	msg := fmt.Sprintf("IO=%s SQL=%s master_host=%s expected=%s", or(io), or(sqlt), or(mh), primary)
	if lerr != "" {
		msg += "; last_io_error: " + lerr
	}
	if code == "replica_needs_reseed" {
		msg += "; the histories diverged — this node must be reseeded from the current source"
	}
	return fail(code, msg)
}

// DrainRelay lets the SQL thread apply already received transactions before an emergency promote.
//
// Otherwise the promote's STOP SLAVE would stop the SQL thread too and silently lose received but unapplied
// transactions. read_only is not touched here.
func (n *Node) DrainRelay() (Response, error) {
	return n.drainRelay(drainTimeout)
}

func (n *Node) drainRelay(timeout time.Duration) (Response, error) {
	db, err := n.db()
	if err != nil {
		return failResp(err), nil
	}
	// Step 1: stop only the IO thread and prove it. MariaDB does not stop it immediately, and a live IO
	// thread would fetch more after the position snapshot.
	db.ExecContext(n.ctx(), "STOP SLAVE IO_THREAD")
	var st *ReplicaStatus
	var showOK bool
	ioDeadline := time.Now().Add(ioStopTimeout)
	for {
		st, showOK = n.replicaStatus()
		if !showOK || IOStopped(st) || time.Now().After(ioDeadline) {
			break
		}
		if !n.pause(500 * time.Millisecond) {
			break
		}
	}
	target, err := RelayDrainTarget(st, showOK)
	if err != nil {
		return failResp(err), nil
	}
	if target.Noop {
		return Response{OK: true, Noop: true,
			Status: map[string]any{"relay_drained": 1, "replica": "not_configured"}}, nil
	}

	// Step 2: non-blocking check whether the target GTID is already applied, so a repeated drain is a noop.
	applied := false
	var rc0 sql.NullInt64
	if err := db.QueryRowContext(n.ctx(), "SELECT MASTER_GTID_WAIT(?, 0)", target.GTID).Scan(&rc0); err == nil {
		applied = rc0.Valid && rc0.Int64 >= 0
	}
	switch RelayDrainSettled(st, applied) {
	case DrainDone:
		return Response{OK: true, Noop: true,
			Status: map[string]any{"relay_drained": 1, "gtid_applied": target.GTID, "replay": 1}}, nil
	case DrainResumeSQL:
		// Backlog with SQL thread stopped: start only SQL; IO is proven stopped, no new data arrives.
		if _, err := db.ExecContext(n.ctx(), "START SLAVE SQL_THREAD"); err != nil {
			return failResp(fail("sql_thread_start_failed", err.Error())), nil
		}
		fallthrough
	case DrainWait:
		// Step 3: wait for the backlog to be applied and prove it.
		var rc sql.NullInt64
		var waitRC *int64
		if err := db.QueryRowContext(n.ctx(), "SELECT MASTER_GTID_WAIT(?, ?)", target.GTID, int(timeout.Seconds())).Scan(&rc); err == nil && rc.Valid {
			v := rc.Int64
			waitRC = &v
		}
		st2, ok2 := n.replicaStatus()
		if err := RelayDrainProven(waitRC, st2, ok2); err != nil {
			return failResp(err), nil
		}
	}

	// Step 4: stop replication fully and prove strictly No/No.
	db.ExecContext(n.ctx(), "STOP SLAVE")
	st3, ok3 := n.replicaStatus()
	if err := PromoteReady(st3, ok3); err != nil {
		return failResp(err), nil
	}
	return Response{OK: true, Status: map[string]any{"relay_drained": 1, "gtid_applied": target.GTID}}, nil
}

// EmergencyPromote drains the relay log and promotes under one lock.
//
// Separate calls would leave a window for a rejoin to restart replication and build a new backlog that the
// promote's STOP SLAVE would silently discard. acceptRelayLoss is the operator's explicit choice to proceed
// when the drain cannot be proven (source dead); the loss is reported in the response.
func (n *Node) EmergencyPromote(acceptRelayLoss bool) (Response, error) {
	d, _ := n.drainRelay(drainTimeout)
	if !d.OK {
		if !acceptRelayLoss {
			return d, nil // drain not proven: do not become writable
		}
	}
	p, _ := n.Promote()
	if !p.OK {
		return p, nil
	}
	status := map[string]any{}
	if m, ok := d.Status.(map[string]any); ok && d.OK {
		for k, v := range m {
			status[k] = v
		}
	}
	if !d.OK {
		status["relay_drained"] = "skipped_by_operator"
		status["relay_drain_error"] = d.Error
	}
	if m, ok := p.Status.(map[string]any); ok {
		for k, v := range m {
			status[k] = v
		}
	}
	return Response{OK: true, Noop: d.Noop && p.Noop, Status: status}, nil
}

var gtidPosRe = regexp.MustCompile(`^--\s*SET GLOBAL gtid_slave_pos\s*=\s*'([^']*)'`)

// gtidFromDump reads the snapshot position from the dump header (--master-data=2 writes it as a comment).
func gtidFromDump(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024) // long dump lines must not break the scan
	for sc.Scan() {
		if m := gtidPosRe.FindStringSubmatch(sc.Text()); m != nil {
			return m[1], nil
		}
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("the dump has no `-- SET GLOBAL gtid_slave_pos=` line (--master-data=2 is required) — the start position is unknown")
}

// ReseedReplica fully reseeds the node from the source, for diverged GTID histories (error 1236).
//
// Each step below was learned from a live incident:
//   - RESET MASTER before restore: a former source may be ahead in sequence numbers, and strict GTID mode
//     rejects its events as out-of-order (1950), stopping the SQL thread;
//   - the snapshot position comes from the dump itself (`--master-data=2`) and is set explicitly, otherwise
//     the replica starts from a stale gtid_slave_pos and hits 1236;
//   - restore runs with sql_log_bin=0, otherwise it creates local GTIDs and pushes the domain counter ahead
//     of the source again.
func (n *Node) ReseedReplica(primary string) (Response, error) {
	// The deadline covers the whole operation (prepare, dump, restore, verify) so the executor always
	// finishes before the client gives up and the outcome is not lost.
	ctx, cancel := context.WithTimeout(n.ctx(), ReseedBudget)
	defer cancel()
	rn := n.WithContext(ctx)

	db, err := rn.db()
	if err != nil {
		return failResp(err), nil
	}
	dumpPass, err := rn.Cfg.dumpSecret()
	if err != nil {
		return failResp(err), nil
	}
	db.ExecContext(ctx, "STOP SLAVE")
	db.ExecContext(ctx, "SET GLOBAL read_only = 1")
	if _, err := db.ExecContext(ctx, "RESET MASTER"); err != nil {
		return failResp(fail("reset_master_failed", err.Error())), nil
	}

	tmp, err := os.CreateTemp("", "ha-reseed-*.sql")
	if err != nil {
		return failResp(fail("reseed_dump_failed", err.Error())), nil
	}
	tmpName := tmp.Name()
	tmp.Close()
	defer os.Remove(tmpName)

	args := []string{"-h", primary, "-P", fmt.Sprint(n.Cfg.Replication.Port), "-u", n.Cfg.Replication.DumpUser,
		"--databases"}
	args = append(args, n.Cfg.Replication.Databases...)
	args = append(args, "--gtid", "--master-data=2", "--single-transaction", "--routines", "--triggers")
	cmd := guardedCmd(ctx, "mysqldump", args...)
	if dumpPass != "" {
		cmd.Env = append(os.Environ(), "MYSQL_PWD="+dumpPass) // not in argv: visible in ps
	}
	out, err := os.OpenFile(tmpName, os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return failResp(fail("reseed_dump_failed", err.Error())), nil
	}
	cmd.Stdout = out
	var stderr strings.Builder
	cmd.Stderr = &stderr
	runErr := cmd.Run()
	out.Close()
	if runErr != nil {
		// Include the run error too: empty stderr with a failure usually means the process never started.
		msg := strings.TrimSpace(stderr.String() + " [" + runErr.Error() + "]")
		if ctx.Err() != nil {
			// No number here: either our ceiling or the caller's deadline may have fired.
			msg = "the dump was interrupted (" + ctx.Err().Error() + "): " + msg
		}
		return failResp(fail("reseed_dump_failed", msg)), nil
	}

	gtid, err := gtidFromDump(tmpName)
	if err != nil {
		// Fail closed: never start replication from an unknown position.
		return failResp(fail("reseed_no_gtid_position", err.Error())), nil
	}

	// Stream the dump (can be gigabytes) after a one-line prefix.
	dump, err := os.Open(tmpName)
	if err != nil {
		return failResp(fail("reseed_restore_failed", err.Error())), nil
	}
	defer dump.Close()
	restore := guardedCmd(ctx, "mysql", "-S", n.Cfg.MySQL.Socket, "-u", n.Cfg.MySQL.User)
	restore.Stdin = io.MultiReader(strings.NewReader("SET SESSION sql_log_bin=0;\n"), dump)
	var rstderr strings.Builder
	restore.Stderr = &rstderr
	if err := restore.Run(); err != nil {
		msg := strings.TrimSpace(rstderr.String() + " [" + err.Error() + "]")
		if ctx.Err() != nil {
			msg = "the restore was interrupted (" + ctx.Err().Error() + "): " + msg
		}
		return failResp(fail("reseed_restore_failed", msg)), nil
	}

	if _, err := db.ExecContext(ctx, "SET GLOBAL gtid_slave_pos = ?", gtid); err != nil {
		return failResp(fail("set_gtid_slave_pos_failed", err.Error())), nil
	}
	if err := rn.changeMaster(db, primary); err != nil {
		return failResp(err), nil
	}
	if _, err := db.ExecContext(ctx, "START SLAVE"); err != nil {
		return failResp(fail("start_slave_failed", err.Error())), nil
	}
	if err := rn.verifyReplica(primary); err != nil {
		return failResp(err), nil
	}
	return Response{OK: true, Status: map[string]any{"read_only": 1, "reseeded_from": primary}}, nil
}

func quote(s string) string {
	return "'" + strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), "'", `\'`) + "'"
}

func asString(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case []byte:
		return string(t)
	case string:
		return t
	default:
		return fmt.Sprint(t)
	}
}

func first(m map[string]string, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok && v != "" {
			return v
		}
	}
	return ""
}
