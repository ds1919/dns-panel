// Control socket: the panel tells the daemon a rule changed.
//
// Without it the handler would learn about an enabled rule only from agents, and a schedule-only rule may
// have no agents at all, so "Turn on" would do nothing. Polling the rules table is not an option: this
// loop has no sweeps.
//
// The command carries no data, just "recompute": the daemon reads everything itself, so there is no
// second source of truth about a rule.
package server

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"os/user"
	"strconv"
	"time"

	"dnspanel/dns-pulse/internal/config"
	"dnspanel/dns-pulse/internal/logs"
)

type controlCmd struct {
	Cmd  string `json:"cmd"`
	Rule uint32 `json:"rule"`
	Zone uint32 `json:"zone"` // for sweep: the panel names the zone when it could not parse it itself
	All  bool   `json:"all"`  // for sweep: rebuild the whole target list
}

// ServeControl listens until ctx is cancelled. Failing to create the socket is NOT fatal: the daemon still
// runs on agent events and just sees panel edits later, but it must say so.
func (s *Server) ServeControl(ctx context.Context, path string) {
	if path == "" {
		return
	}
	// Do NOT create the directory: tmpfiles.d creates it with the right owner and group; one created by the
	// daemon would be unreachable for the panel. A missing directory is an install error.
	_ = os.Remove(path) // stale socket from a previous run would make listen fail
	ln, err := net.Listen("unix", path)
	if err != nil {
		logs.Warnf("control socket %s: %v — panel changes will only take effect on the next event "+
			"(the directory is created by tmpfiles.d: etc/tmpfiles/dns-panel.conf)", path, err)
		return
	}
	if err := os.Chmod(path, 0o660); err != nil {
		logs.Warnf("permissions on %s: %v", path, err)
	}
	// The panel (www-data) and the daemon run as different users, so 0660 needs a SHARED group; the daemon
	// may chown the socket to it because it is a member (SupplementaryGroups=). The directory is left alone:
	// tmpfiles.d owns it, and the daemon could not chown it anyway.
	if s.Cfg.ControlGroup != "" {
		if g, err := user.LookupGroup(s.Cfg.ControlGroup); err == nil {
			gid, _ := strconv.Atoi(g.Gid)
			if err := os.Chown(path, -1, gid); err != nil {
				logs.Warnf("group %s on socket: %v — the panel will not be able to reach it",
					s.Cfg.ControlGroup, err)
			}
		} else {
			logs.Warnf("group %q not found: %v", s.Cfg.ControlGroup, err)
		}
	}
	logs.Infof("pulse-server: control socket %s", path)
	// dns-ha-agentd hardcodes the default path: if the socket moves, the panel still reaches it but promotion
	// signals do not, and schedule-only rules will not arm after a role switch.
	if path != config.DefaultControlSocket {
		logs.Warnf("socket moved from %s — node promotion signals from dns-ha-agentd will not arrive here",
			config.DefaultControlSocket)
	}
	go func() {
		<-ctx.Done()
		ln.Close()
		_ = os.Remove(path)
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			logs.Warnf("control socket: %v", err)
			return
		}
		go s.control(ctx, conn)
	}
}

func (s *Server) control(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(s.Cfg.DBTimeout))
	var m controlCmd
	if err := json.NewDecoder(conn).Decode(&m); err != nil {
		return
	}
	ok, detail := true, ""
	switch m.Cmd {
	case "activate":
		// Node became ACTIVE. Recomputing rules is not enough: deadlines move with the role too, so run the full
		// Activate (deadlines, then decisions), the same path as cold start (docs/25 §5). Report the actual
		// outcome, not "accepted": dns-ha-agentd logs the reply, and an always-ok answer would hide failures.
		c, cancel := context.WithTimeout(ctx, s.Cfg.DBTimeout+s.Cfg.ApplyTimeout)
		if err := s.Activate(c); err != nil {
			ok, detail = false, err.Error()
			logs.Warnf("node promotion: %v — recompute scheduled for retry", err)
		}
		cancel()
	case "deactivate":
		// Node is no longer the write source. Hold timers started before demotion must stop, or a STANDBY
		// that observes nothing would count "after N s continuously" while the real active saw the condition
		// clear and return.
		//
		// Re-check the role: a late demotion retry may arrive after re-promotion, and then we are active again.
		if s.CanObserve(ctx) {
			logs.Infof("pulse: demotion received, but the node is active again — keeping deadlines")
			break
		}
		s.lostRole()
		logs.Infof("pulse: node demoted — deadlines, hold timers and agent streams dropped")
	case "sweep":
		// A zone was edited: bring its sweep targets in line. Run in the daemon
		// context so a dropped panel connection does not abort the catch-up.
		// All: the panel changed which zones the sweep takes (secondaries on/off), so the whole list is rebuilt.
		if m.All {
			go s.SweepRefresh(context.Background())
			break
		}
		zone := m.Zone
		go s.SweepZone(zone)
	case "recompute":
		// Daemon context, not the connection's: the panel does not wait, and a drop must not abort a decision.
		go func() {
			c, cancel := context.WithTimeout(context.Background(), s.Cfg.DBTimeout+s.Cfg.ApplyTimeout)
			defer cancel()
			if m.Rule != 0 {
				_ = s.Recompute(c, m.Rule)
			} else {
				_ = s.RecomputeAll(c)
			}
		}()
	default:
		ok, detail = false, "unknown command"
	}
	out := map[string]any{"ok": ok}
	if detail != "" {
		out["error"] = detail
	}
	_ = json.NewEncoder(conn).Encode(out)
}
