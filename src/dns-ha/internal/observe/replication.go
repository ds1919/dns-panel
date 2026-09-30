package observe

import (
	"context"
	"database/sql"
	"fmt"
	"os/user"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

// ObserveReplication reads this node's actual replication state (`SHOW REPLICA STATUS`, read-only).
//
// Needs SLAVE MONITOR (MariaDB 10.5+; REPLICATION CLIENT before). Without it we report "not observed" with
// a reason, not "no replication": otherwise missing grants would look like a missing replica and the
// planner would decide on nothing. An empty result from a successful query means CHANGE MASTER was never
// run (normal for an ACTIVE that was never a replica).
func ObserveReplication(ctx context.Context, socket string, timeout time.Duration) ReplicationState {
	var st ReplicationState
	dsn, err := replicationDSN(socket)
	if err != nil {
		st.Error = err.Error()
		return st
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		st.Error = fmt.Sprintf("repl_open: %v", err)
		return st
	}
	defer db.Close()

	// Our own binlog position: after writes stop, a planned switchover target must apply it — the only proof
	// no data is lost. An empty position is legitimate (no transactions yet, e.g. right after RESET MASTER),
	// so "read" is a separate flag; otherwise empty would be indistinguishable from a failed read.
	var binPos sql.NullString
	if err := db.QueryRowContext(ctx, "SELECT @@gtid_binlog_pos").Scan(&binPos); err == nil && binPos.Valid {
		st.GTIDBinlogPos, st.GTIDBinlogPosKnown = binPos.String, true
	}
	db.SetMaxOpenConns(1)

	c, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	row, err := queryStatusRow(c, db, "SHOW REPLICA STATUS")
	if err != nil {
		// Older versions may lack the command: try the old name before giving up.
		if row2, err2 := queryStatusRow(c, db, "SHOW SLAVE STATUS"); err2 == nil {
			row, err = row2, nil
		} else {
			st.Error = fmt.Sprintf("repl_status_failed: %v", err)
			return st
		}
	}
	st.Observed = true
	if len(row) == 0 {
		return st // query succeeded, no row: replica not configured
	}
	st.Configured = true
	st.IORunning = pick(row, "Replica_IO_Running", "Slave_IO_Running")
	st.SQLRunning = pick(row, "Replica_SQL_Running", "Slave_SQL_Running")
	st.MasterHost = pick(row, "Source_Host", "Master_Host")
	st.LastIOError = pick(row, "Last_IO_Error")
	st.LastSQLError = pick(row, "Last_SQL_Error")
	st.GtidIOPos = pick(row, "Gtid_IO_Pos")
	if v := pick(row, "Seconds_Behind_Source", "Seconds_Behind_Master"); v != "" {
		var n int64
		if _, err := fmt.Sscan(v, &n); err == nil {
			st.SecondsBehind = &n
		}
	}
	// The applied GTID position is a separate variable, not part of the status.
	var slavePos string
	if err := db.QueryRowContext(c, "SELECT @@global.gtid_slave_pos").Scan(&slavePos); err == nil {
		st.GtidSlavePos = slavePos
	}
	return st
}

// replicationDSN connects as the process's OS user (unix_socket auth), without selecting a DB.
func replicationDSN(socket string) (string, error) {
	if socket == "" {
		return "", fmt.Errorf("repl: empty socket path")
	}
	u, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("repl: could not determine the OS user: %w", err)
	}
	return fmt.Sprintf("%s@unix(%s)/?timeout=5s&readTimeout=5s&writeTimeout=5s", u.Username, socket), nil
}

// queryStatusRow turns the wide SHOW ... STATUS row into a column map: the field set differs across
// MariaDB versions and a fixed struct would break for no reason.
func queryStatusRow(ctx context.Context, db *sql.DB, q string) (map[string]string, error) {
	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, err
		}
		return map[string]string{}, nil
	}
	raw := make([]sql.RawBytes, len(cols))
	ptrs := make([]any, len(cols))
	for i := range raw {
		ptrs[i] = &raw[i]
	}
	if err := rows.Scan(ptrs...); err != nil {
		return nil, err
	}
	out := make(map[string]string, len(cols))
	for i, c := range cols {
		out[c] = string(raw[i])
	}
	return out, rows.Err()
}

func pick(row map[string]string, names ...string) string {
	for _, n := range names {
		if v, ok := row[n]; ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
