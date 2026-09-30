package agentd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

// Node is the executor that actually touches the host: MariaDB (mariadb.go), PowerDNS and publication.
type Node struct {
	Cfg Config
	// Run executes external commands (`ip`, `pdns_control`); tests replace it to check the calls themselves.
	Run func(name string, args ...string) (string, error)
	// PingWait bounds the wait for pdns after a restart; 0 means 10 seconds.
	PingWait time.Duration
	// Ctx carries the operation deadline and cancellation for everything the node does in a request
	// (commands, SQL, waits). Nil means Background. Without one shared deadline, per-phase limits mean
	// nothing while a command inside runs on its own longer timer.
	Ctx context.Context
}

// WithContext returns a copy bound to the operation deadline. A copy, because connections are served
// concurrently and a shared field would leak one request's deadline into another.
func (n *Node) WithContext(ctx context.Context) *Node {
	c := *n
	c.Ctx = ctx
	return &c
}

func (n *Node) ctx() context.Context {
	if n.Ctx != nil {
		return n.Ctx
	}
	return context.Background()
}

// PowerDNS role (PDNSRole: primary and secondary together) lives only in a separate config (90-ha-role.conf).
// A standalone node starts yes/yes, the pair moves STANDBY to no/no, dissolving returns both to yes/yes.
//
// There are two role states: running (current-config diff) and persisted (the file, applied on the next
// restart). A noop is allowed only when both equal the target, or a restart would bring the old role back.

func (n *Node) currentRole() (PDNSRole, bool) {
	out, err := n.run(n.Cfg.PDNS.Control, "current-config", "diff")
	if err != nil {
		return PDNSRole{}, false
	}
	return ParseRunningRole(out)
}

func (n *Node) persistedRole() (PDNSRole, bool) {
	raw, err := os.ReadFile(n.Cfg.PDNS.RoleConf)
	if err != nil {
		return PDNSRole{}, false
	}
	return ParseRoleConf(string(raw))
}

func (n *Node) rpingOK() bool { return n.rpingCtx(n.ctx()) }

// pdnsVersion is the running PowerDNS version ("5.1.4"), or "" if it cannot be read.
func (n *Node) pdnsVersion() string {
	out, err := n.runCtx(n.ctx(), n.Cfg.PDNS.Control, "version")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

func (n *Node) rpingCtx(ctx context.Context) bool {
	out, err := n.runCtx(ctx, n.Cfg.PDNS.Control, "rping")
	return err == nil && strings.Contains(out, "PONG") // require PONG, not just exit code 0
}

func (n *Node) writeRole(want PDNSRole) error {
	dir := filepath.Dir(n.Cfg.PDNS.RoleConf)
	f, err := os.CreateTemp(dir, "ha-role.*")
	if err != nil {
		return fail("role_write_failed", err.Error())
	}
	tmp := f.Name()
	if _, err := f.WriteString(RoleConfBody(want)); err != nil {
		f.Close()
		os.Remove(tmp)
		return fail("role_write_failed", err.Error())
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return fail("role_write_failed", err.Error())
	}
	os.Chmod(tmp, 0o644)
	if err := os.Rename(tmp, n.Cfg.PDNS.RoleConf); err != nil {
		os.Remove(tmp)
		return fail("role_write_failed", err.Error())
	}
	return nil
}

// applyRole brings both the running role and the file to the target pair and verifies the running one.
//
// `pdns_control set`/`reload` cannot change the role: primary and secondary are read at startup, so one
// restart covers both. Order: write file, config check, restart, wait for PONG, verify. primary=no with
// secondary=yes is not STANDBY: that node still pulls from other primaries and writes to a read-only DB.
func (n *Node) applyRole(want string) error {
	target := RoleFor(want)
	prev, hadPrev := n.currentRole()
	if err := n.writeRole(target); err != nil {
		return err
	}
	if _, err := n.runShell(n.Cfg.PDNS.ConfigCheck); err != nil {
		// Roll the file back: a config that fails the check would stop any later pdns restart from starting.
		if hadPrev {
			n.writeRole(prev)
		} else {
			n.writeRole(RoleFor("no"))
		}
		return fail("config_check_failed", err.Error())
	}
	if _, err := n.runShell(n.Cfg.PDNS.Restart); err != nil {
		return fail("restart_failed", err.Error())
	}
	if !n.waitPing() {
		return fail("pdns_unresponsive", "no PONG after the restart")
	}
	now, ok := n.currentRole()
	if !ok || now != target {
		return fail("role_unverified", "the running role is not confirmed as "+target.String()+" (running: "+now.String()+")")
	}
	return nil
}

// waitPing waits for pdns within one deadline passed into each rping, so a hung rping cannot outlast it.
func (n *Node) waitPing() bool {
	limit := n.PingWait
	if limit <= 0 {
		limit = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(n.ctx(), limit)
	defer cancel()
	for {
		if n.rpingCtx(ctx) {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// stopAndVerify stops pdns and proves it (not active and not answering).
func (n *Node) stopAndVerify() bool {
	n.runShell(n.Cfg.PDNS.Stop)
	if _, err := n.runShell(n.Cfg.PDNS.IsActive); err == nil {
		return false
	}
	return !n.rpingOK()
}

// forceSafeNo proves primary=no secondary=no, or failing that a proven pdns stop.
// Returns "no" | "stopped" | "unproven".
func (n *Node) forceSafeNo() string {
	if err := n.applyRole("no"); err == nil {
		return "no"
	}
	if n.stopAndVerify() {
		return "stopped"
	}
	return "unproven"
}

// EnableNotifier sets the full source role, PowerDNS primary=yes secondary=yes (the name is historical).
//
// Only ACTIVE sends NOTIFY: primary mode writes notified_serial to `domains`, impossible on a read-only
// replica. Fail closed: the marker appears only after the role is proven, and any failure moves the node to
// a safe state; a false "primary=no" would give the pair two NOTIFY sources with different serials.
func (n *Node) EnableNotifier() (Response, error) { return n.setNotifier("yes") }

// DisableNotifier stops sending NOTIFY. The node still serves AXFR from its own DB copy; secondaries know
// both nodes and pull from any reachable one (§13).
func (n *Node) DisableNotifier() (Response, error) { return n.setNotifier("no") }

func (n *Node) setNotifier(want string) (Response, error) {
	target := RoleFor(want)
	cur, curOK := n.currentRole()
	file, fileOK := n.persistedRole()
	if curOK && fileOK && cur == target && file == target {
		if want == "yes" {
			if err := n.setMarker(n.markerNotifier()); err != nil {
				return n.safeFail("mark_write_failed"), nil
			}
		} else if err := n.clearMarker(n.markerNotifier()); err != nil {
			return failResp(fail("mark_unlink_failed", err.Error())), nil
		}
		return Response{OK: true, Noop: true,
			Status: map[string]any{"primary": want, "secondary": want, "notifier_on": boolInt(want == "yes")}}, nil
	}

	if want == "yes" {
		if err := n.applyRole("yes"); err != nil {
			return n.safeFail(codeOf(err)), nil
		}
		if err := n.setMarker(n.markerNotifier()); err != nil {
			return n.safeFail("mark_write_failed"), nil
		}
		return Response{OK: true, Status: map[string]any{"primary": "yes", "secondary": "yes", "notifier_on": 1}}, nil
	}

	switch n.forceSafeNo() {
	case "no":
		if err := n.clearMarker(n.markerNotifier()); err != nil {
			return failResp(fail("mark_unlink_failed", "primary=no secondary=no is proven, but the marker was not cleared")), nil
		}
		return Response{OK: true, Status: map[string]any{"primary": "no", "secondary": "no", "notifier_on": 0}}, nil
	case "stopped":
		return failResp(fail("demote_forced_stop",
			"primary=no secondary=no is not proven → pdns stopped and verified (safe)")), nil
	}
	return failResp(fail("pdns_safe_state_unproven",
		"primary=no secondary=no is not proven and the stop cannot be proven either")), nil
}

// safeFail brings the node to a safe state and returns a typed failure without false claims.
func (n *Node) safeFail(orig string) Response {
	switch n.forceSafeNo() {
	case "no":
		return failResp(fail(orig, orig+"; the node was brought to a proven primary=no secondary=no"))
	case "stopped":
		return failResp(fail(orig, orig+"; pdns stopped and verified (safe)"))
	}
	return failResp(fail("pdns_safe_state_unproven",
		orig+"; the safe state is NOT proven — pdns may still be primary"))
}

// Status reports the node's actual state.
//
// notifier_on is the running PowerDNS role, not the marker file. Unreachable pdns or an unknown role is a
// failure, not notifier_on=0, or HA would treat NOTIFY as off under a live primary=yes.
func (n *Node) Status(pubAddress, pubDevice, pubProvider string) (any, error) {
	ro, err := n.readOnly()
	if err != nil {
		return nil, err
	}
	if !n.rpingOK() {
		return nil, fail("pdns_unreachable", "no PONG from pdns_control rping")
	}
	role, ok := n.currentRole()
	if !ok {
		return nil, fail("pdns_role_unknown", "the role is not determined from current-config diff")
	}
	persisted, pok := n.persistedRole()
	if !pok || persisted != role {
		// Running and persisted roles differ: the next restart would change the role by itself.
		return nil, fail("pdns_role_drift",
			fmt.Sprintf("running %s, in the file %s", role.String(), orUnreadable(persisted.String(), pok)))
	}
	// route_announced is the fact of publication: with an own address it is read from the interface; only
	// with an external provider (no address) does the marker remain. An unreadable interface fails Status
	// rather than reporting "not published", or convergence would add the address blindly.
	// A mixed role (yes/no, no/yes) is not a failure: convergence brings ACTIVE to yes/yes, STANDBY to no/no.
	st := map[string]any{
		"read_only":       int(*ro),
		"notifier_on":     boolInt(role.Primary == "yes"),
		"secondary_on":    boolInt(role.Secondary == "yes"),
		"notifier_marker": boolInt(fileExists(n.markerNotifier())),
		"route_announced": boolInt(fileExists(n.markerRoute())),
	}
	if v := n.pdnsVersion(); v != "" {
		st["pdns_version"] = v // shown to the operator only; nothing decides on it
	}
	addr, dev := n.Cfg.Publication.Address, n.Cfg.Publication.Device
	if pubAddress != "" && pubDevice != "" {
		addr, dev = pubAddress, pubDevice
	}
	if addr != "" {
		present, err := n.addrPresent(addr, dev)
		if err != nil {
			return nil, fail("publication_state_unknown", err.Error())
		}
		// Anycast: both ACTIVE and STANDBY have the address on loopback, so the marker (exposed via the open
		// probe) stays the publication fact. The address is reported separately so convergence can restore it.
		if pubProvider == providerAnycast {
			st["anycast_address_up"] = boolInt(present)
			st["publication_provider"] = providerAnycast
		} else {
			st["route_announced"] = boolInt(present)
		}
		st["publication_address"] = addr
		st["publication_device"] = dev
	}
	return st, nil
}

// Preflight is a quick local health check: MariaDB reachable, read_only readable, replication not in error.
// It is not a source of truth about the pair.
func (n *Node) Preflight() (Response, error) {
	ro, err := n.readOnly()
	if err != nil {
		return failResp(err), nil
	}
	st, showOK := n.replicaStatus()
	status := map[string]any{"read_only": int(*ro)}
	if showOK && st != nil && st.Present {
		status["replica_io"], status["replica_sql"] = st.IORunning, st.SQLRunning
		if st.LastSQLError != "" {
			status["last_sql_error"] = st.LastSQLError
		}
		// Count the error only while a thread runs: a stopped replica (e.g. current ACTIVE) keeps a stale error
		// from its previous role. Whether replication is needed at all is the manager's call.
		if st.LastSQLError != "" && (st.IORunning == "Yes" || st.SQLRunning == "Yes") {
			return Response{OK: false, Error: "replica_error", Message: st.LastSQLError, Status: status}, nil
		}
	}
	return Response{OK: true, Status: status}, nil
}

func (n *Node) markerNotifier() string { return filepath.Join(n.Cfg.MarkerDir, "notifier_on") }
func (n *Node) markerRoute() string    { return filepath.Join(n.Cfg.MarkerDir, "route_announced") }

func (n *Node) setMarker(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	return f.Close()
}

func (n *Node) clearMarker(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	if fileExists(path) {
		return fmt.Errorf("could not remove %s", path)
	}
	return nil
}

// External command timeouts, so a hung pdns_control or systemctl cannot block us forever. Expiry is an
// error (state unknown), never success, and the process is killed.
const (
	cmdTimeout   = 10 * time.Second // pdns_control, ip
	shellTimeout = 60 * time.Second // systemctl restart/stop, config check
)

func (n *Node) run(name string, args ...string) (string, error) {
	return n.runCtx(n.ctx(), name, args...)
}

// runCtx runs a command under ctx; WithTimeout keeps the earlier deadline, so it cannot outlive its caller.
func (n *Node) runCtx(ctx context.Context, name string, args ...string) (string, error) {
	if n.Run != nil {
		return n.Run(name, args...)
	}
	return runProc(ctx, cmdTimeout, name, args...)
}

// runShell runs a command line from the root-owned node config, never anything received over the socket.
func (n *Node) runShell(cmdline string) (string, error) {
	return runProc(n.ctx(), shellTimeout, "/bin/sh", "-c", cmdline)
}

// runProc is the only place that starts external programs.
//
//   - the deadline comes from the operation; limit is only a ceiling;
//   - the whole process group is killed: /bin/sh children survive a killed shell;
//   - WaitDelay cuts output reading: a child holding the inherited pipe would otherwise block Wait.
func runProc(ctx context.Context, limit time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	cmd := guardedCmd(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return string(out), fmt.Errorf("%s: %w", name, ctx.Err())
	}
	return string(out), err
}

// guardedCmd applies the same hang protection; separate from runProc because dump/restore need their own I/O.
func guardedCmd(ctx context.Context, name string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) // negative pid: the whole group
	}
	cmd.WaitDelay = 5 * time.Second
	return cmd
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func orUnreadable(v string, ok bool) string {
	if !ok {
		return "unreadable"
	}
	return v
}
