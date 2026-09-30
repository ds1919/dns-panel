package agentd

import (
	"fmt"
	"strings"
)

// Pure node safety rules: no DB, file or process access — only decisions that can be tested exhaustively.
// Carried over from the Perl code (HAReplGuard, HAPdnsRole) with their reasons: each was paid for by a live
// incident and must not be reinvented.

// ReplicaStatus is the subset of SHOW REPLICA STATUS that decisions are based on.
type ReplicaStatus struct {
	Present      bool // whether a row existed (successful SHOW with no row = replica not configured)
	IORunning    string
	SQLRunning   string
	MasterHost   string
	GtidIOPos    string
	LastIOError  string
	LastSQLError string
}

// PromoteReady reports whether it is safe to make the node writable.
//
// Safe ONLY when SHOW succeeded AND (no row OR strictly IO=No and SQL=No). The IO thread has three states —
// Yes | Connecting | No — and Connecting means the thread IS running and may pull data at any moment.
// Anything not proven No/No is refused: being ACTIVE and a replica at once means circular replication.
func PromoteReady(st *ReplicaStatus, showOK bool) error {
	if !showOK {
		return fail("replica_status_failed", "SHOW REPLICA STATUS failed (SQL, privileges or connection)")
	}
	if st == nil || !st.Present {
		return nil
	}
	if st.IORunning != "No" || st.SQLRunning != "No" {
		return fail("replica_still_running",
			fmt.Sprintf("IO=%s SQL=%s (only No/No is safe)", or(st.IORunning), or(st.SQLRunning)))
	}
	return nil
}

// ReplicaHealthy reports whether the replica is ACTUALLY connected to the expected source.
//
// Without checking Master_Host and both threads, rejoin would report success with IO in 'Connecting' (e.g.
// Access denied), and the switchover would declare itself done with a dead replica.
func ReplicaHealthy(st *ReplicaStatus, expected string) bool {
	if st == nil || !st.Present || expected == "" {
		return false
	}
	return st.IORunning == "Yes" && st.SQLRunning == "Yes" && st.MasterHost == expected
}

// IOStopped reports whether the IO thread is PROVEN stopped (strictly No).
//
// 'Connecting' is not acceptable: the thread is alive and may pull transactions AFTER we read the position,
// making the snapshot incomplete. MariaDB does not guarantee an immediate stop after STOP SLAVE IO_THREAD,
// so the caller polls this.
func IOStopped(st *ReplicaStatus) bool {
	if st == nil || !st.Present {
		return true
	}
	return st.IORunning == "No"
}

// DrainTarget says what to drain. Used ONLY after the IO thread is proven stopped.
type DrainTarget struct {
	Noop bool   // replica not configured — nothing to drain
	GTID string // position whose application must be awaited
}

// RelayDrainTarget computes the relay-log drain target before emergency promotion.
//
// An empty Gtid_IO_Pos on a CONFIGURED replica is a refusal, not "nothing to wait for": applying received
// transactions cannot be proven, and silently losing them is exactly the bug draining exists for.
func RelayDrainTarget(st *ReplicaStatus, showOK bool) (DrainTarget, error) {
	if !showOK {
		return DrainTarget{}, fail("replica_status_failed", "SHOW REPLICA STATUS failed")
	}
	if st == nil || !st.Present {
		return DrainTarget{Noop: true}, nil
	}
	if st.LastSQLError != "" {
		return DrainTarget{}, fail("replica_sql_error", st.LastSQLError)
	}
	if !IOStopped(st) {
		return DrainTarget{}, fail("io_thread_still_running",
			fmt.Sprintf("IO=%s — the position may only be read while IO=No", or(st.IORunning)))
	}
	// The SQL thread state must be RECOGNISED: later "not Yes" is taken as "stopped", so an unknown value
	// would silently lead to the done/resume_sql branch.
	if st.SQLRunning != "Yes" && st.SQLRunning != "No" {
		return DrainTarget{}, fail("replica_sql_state_unknown",
			fmt.Sprintf("SQL=%s — strictly Yes or No is expected", or(st.SQLRunning)))
	}
	if st.GtidIOPos == "" {
		return DrainTarget{}, fail("relay_position_unknown",
			"Gtid_IO_Pos is empty on a configured replica — applying the received transactions cannot be proven")
	}
	return DrainTarget{GTID: st.GtidIOPos}, nil
}

// Next drain step once IO is stopped and it is known whether the target GTID is applied.
const (
	DrainDone      = "done"       // applied and SQL thread stopped — nothing to do
	DrainStopOnly  = "stop_only"  // applied but threads running — stop and prove No/No
	DrainResumeSQL = "resume_sql" // not applied, SQL stopped — start ONLY the SQL thread
	DrainWait      = "wait"       // not applied, SQL running — just wait
)

// RelayDrainSettled makes draining idempotent BY FACT: a repeat after a successful drain must return
// "nothing to do", not an error.
func RelayDrainSettled(st *ReplicaStatus, applied bool) string {
	sqlRunning := st != nil && st.Present && st.SQLRunning == "Yes"
	switch {
	case applied && sqlRunning:
		return DrainStopOnly
	case applied:
		return DrainDone
	case sqlRunning:
		return DrainWait
	}
	return DrainResumeSQL
}

// RelayDrainProven reports whether application of received transactions is proven.
//
// waitRC is the MASTER_GTID_WAIT(pos, timeout) result: 0 = reached, <0 = timeout, nil = unproven. Status is
// rechecked afterwards: a stopped or failed SQL thread would mean "reached" only because nothing was applying.
func RelayDrainProven(waitRC *int64, st *ReplicaStatus, showOK bool) error {
	if waitRC == nil {
		return fail("relay_drain_unproven", "MASTER_GTID_WAIT returned NULL or an error")
	}
	if *waitRC < 0 {
		return fail("relay_drain_timeout",
			fmt.Sprintf("MASTER_GTID_WAIT=%d (the backlog was not applied within the time allowed)", *waitRC))
	}
	if !showOK {
		return fail("replica_status_failed", "the repeated SHOW REPLICA STATUS failed")
	}
	if st != nil && st.Present {
		if st.LastSQLError != "" {
			return fail("replica_sql_error", st.LastSQLError)
		}
		if st.SQLRunning != "Yes" {
			return fail("replica_sql_stopped",
				fmt.Sprintf("SQL=%s — the thread is stopped, application is not proven", or(st.SQLRunning)))
		}
	}
	return nil
}

// ReplicaFailureCode explains why the replica did not come up.
//
// Error 1236 "binlog is missing the GTID" means DIVERGED HISTORIES: the source no longer has the GTIDs this
// node asks for. Incremental reconnect is impossible and only a reseed helps — say so plainly, otherwise the
// operator looks for a network or password problem.
func ReplicaFailureCode(lastIOError string) string {
	if lastIOError == "" {
		return "replica_not_connected"
	}
	low := strings.ToLower(lastIOError)
	if strings.Contains(low, "missing the gtid") || strings.Contains(low, "1236") {
		return "replica_needs_reseed"
	}
	return "replica_not_connected"
}

// PDNSRole is the node's COMPLETE PowerDNS role. primary (send NOTIFY) and secondary (check and fetch zones
// from their primary on SOA refresh and NOTIFY) both write to the database, and the STANDBY database is a
// read-only replica. So they change only together: ACTIVE and a standalone node are yes/yes, STANDBY is no/no.
// A mixed pair is an unfinished transition that convergence fixes.
//
// Both settings are owned by ONE file (90-ha-role.conf) and must not appear in the common config: PowerDNS
// reads include-dir alphabetically, and a line in dns-panel.conf would override the role HA sets.
type PDNSRole struct {
	Primary   string // "yes" | "no"
	Secondary string // "yes" | "no"
}

// RoleFor returns the full role from one decision: zone source (yes) or replica (no).
func RoleFor(want string) PDNSRole { return PDNSRole{Primary: want, Secondary: want} }

func (r PDNSRole) String() string {
	return "primary=" + or(r.Primary) + " secondary=" + or(r.Secondary)
}

// roleKeys lists the names a setting may appear under: master/slave are legacy aliases, and PowerDNS 4.8
// prints both names in diff.
var roleKeys = map[string][]string{"primary": {"primary", "master"}, "secondary": {"secondary", "slave"}}

// parseRoleKeys extracts each role setting from config text. A missing line means the PowerDNS default (no);
// an unrecognised value or a name/alias contradiction means "undetermined" (the caller fails closed).
func parseRoleKeys(text string) (PDNSRole, bool) {
	seen := map[string]map[string]string{"primary": {}, "secondary": {}}
	for _, line := range strings.Split(text, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		for setting, keys := range roleKeys {
			for _, key := range keys {
				if v, ok := cutKey(t, key); ok {
					seen[setting][key] = v
				}
			}
		}
	}
	val := func(setting string) (string, bool) {
		out := ""
		for _, v := range seen[setting] {
			norm, ok := normYesNo(v)
			if !ok || (out != "" && out != norm) {
				return "", false
			}
			out = norm
		}
		if out == "" {
			return "no", true // no line → PowerDNS default
		}
		return out, true
	}
	p, pok := val("primary")
	s, sok := val("secondary")
	if !pok || !sok {
		return PDNSRole{}, false
	}
	return PDNSRole{Primary: p, Secondary: s}, true
}

// ParseRunningRole reads the RUNNING PowerDNS role from `pdns_control current-config diff`.
//
// diff specifically: it prints ONLY non-default settings, so a missing line means the default (no). The full
// current-config prints the whole template commented out, and the role cannot be read from it.
func ParseRunningRole(diff string) (PDNSRole, bool) { return parseRoleKeys(diff) }

// ParseRoleConf reads the role from the role config (what applies on the NEXT pdns restart). An old-format
// file (primary= only) is read honestly: no secondary means default no, and convergence adds the pair.
func ParseRoleConf(text string) (PDNSRole, bool) { return parseRoleKeys(text) }

// RoleConfBody renders the role config: both role settings, always together.
func RoleConfBody(r PDNSRole) string {
	return "# managed by dns-ha-agent (HA role) — do not edit by hand\nprimary=" + r.Primary + "\nsecondary=" + r.Secondary + "\n"
}
func cutKey(line, key string) (string, bool) {
	if !strings.HasPrefix(strings.ToLower(line), key) {
		return "", false
	}
	rest := strings.TrimSpace(line[len(key):])
	if !strings.HasPrefix(rest, "=") {
		return "", false
	}
	return strings.TrimSpace(strings.TrimPrefix(rest, "=")), true
}

func normYesNo(v string) (string, bool) {
	switch strings.ToLower(strings.Fields(v + " ")[0]) {
	case "yes", "true", "1", "on":
		return "yes", true
	case "no", "false", "0", "off":
		return "no", true
	}
	return "", false
}

func or(v string) string {
	if v == "" {
		return "?"
	}
	return v
}
