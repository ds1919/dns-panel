// Package config loads both daemons' configuration. The parser is our own and minimal, as in dns-ha.
//
// The file holds ONLY what the first connection needs. Intervals, thresholds and targets come from the
// panel over the stream; otherwise a second truth about a check would appear and drift (docs/25 §1).
package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// No durations are hard-coded. Every number has exactly one owner:
//   - measurement parameters (interval, limits, thresholds, freshness) live in the DATABASE, edited in the panel;
//   - what follows from them unambiguously (confirm rate, deadlines) is COMPUTED, never a separate setting;
//   - technical values with no source in the database (call timeouts, retry backoff) live HERE, as named
//     fields with defaults, overridable in TOML.
//
// A setting exists only when two installations must answer differently.

// Server is the pulse-server config. It runs on the panel node, so it reaches the database over a unix socket.
type Server struct {
	Listen   string // e.g. "0.0.0.0:7902"
	DBSocket string
	DBName   string
	DBUser   string
	DBPass   string // read from password_file; no secret in the config itself
	// PowerDNS database, READ ONLY: the slow sweep takes the A/AAAA addresses published in the zones. Its own
	// account (unix_socket, SELECT on domains and records): the daemon can read zones, never write them.
	PDNSSocket string
	PDNSName   string
	PDNSUser   string

	// Write permission is asked of dns-ha-manager; there is no second HA model here. The flag is local
	// because it is needed before and without the daemon: an unreachable daemon must not read as
	// "HA probably exists" and block writes on a node without HA.
	HAEnabled bool
	HASocket  string

	DBTimeout    time.Duration // limit for one bookkeeping write (deadline firing)
	HATimeout    time.Duration // limit for a dns-ha-manager call
	HAVerdictTTL time.Duration // how long a manager verdict is trusted, so confirms from dozens of agents
	// don't hit it more often than the role changes
	RetryMin time.Duration // first backoff after a failed deadline write
	RetryMax time.Duration // backoff cap, so an unreachable database does not become a hot loop
	// Pulse has no SQL of its own for zones: records change only via pdns_apply_rrsets, invoked by
	// this program.
	ApplyCommand string
	ApplyTimeout time.Duration // limit for one switch: zone transaction + SOA bump
	// Panel control socket: an enabled or edited rule is recomputed immediately; a schedule-only rule
	// may have no agents at all.
	ControlSocket string
	// Group owning the socket and its directory; the panel connects as its own user, and without a
	// shared group mode 0660 means "nobody but the daemon".
	ControlGroup string

	// How many times per freshness window the agent confirms. A ratio, not a duration: the window comes
	// from the database, and one lost confirm must not look like a missing agent.
	ConfirmDivisor uint32
}

// Agent is the pulse-agent config; everything else is known to the panel.
//
// There is NO per-machine secret here: the file is identical on every machine and can go into an image
// or config management. The agent creates its own key on first start and keeps it in StateDirectory.
type Agent struct {
	Server      string // pulse-server address
	EnrollKey   string // site-wide key: permission to queue for approval, nothing more
	Fingerprint string // server certificate fingerprint; empty = pin on first connection
	LogLevel    string // debug | info | warn
	// Reconnect backoff: the server cannot send it (we are not connected), so it is owned here.
	// The defaults are sensible and need not appear in a minimal config.
	ReconnectMin time.Duration
	ReconnectMax time.Duration
	// Where the pinned fingerprint is stored. Not read from the config: StateDirectory= in the unit
	// decides, so two settings for the same thing cannot diverge.
	StateDir string
}

// DefaultControlSocket is the same path dns-ha-agentd hard-codes; named so a path change is visible in
// code rather than discovered by a missing promotion signal.
const DefaultControlSocket = "/run/dns-panel/pulse/control.sock"

func ServerDefaults() Server {
	return Server{Listen: "0.0.0.0:7902", DBSocket: "/run/mysqld/mysqld.sock", DBName: "dns_panel",
		PDNSSocket: "/run/mysqld/mysqld.sock", PDNSName: "pdns", PDNSUser: "dns-pulse",
		HASocket:      "/run/dns-panel/ha/manager.sock",
		ApplyCommand:  "/opt/dns-panel/libexec/pulse-apply.pl",
		ControlSocket: DefaultControlSocket, ControlGroup: "www-data",
		DBTimeout: 10 * time.Second, HATimeout: 3 * time.Second, HAVerdictTTL: time.Second,
		ApplyTimeout: 30 * time.Second,
		RetryMin:     time.Second, RetryMax: time.Minute}
}

// DefaultAgentPort is where pulse-server listens for agents (ServerDefaults Listen).
const DefaultAgentPort = "7902"

func AgentDefaults() Agent {
	return Agent{LogLevel: "info", ReconnectMin: time.Second, ReconnectMax: 30 * time.Second}
}

func LoadServer(path string) (Server, error) {
	cfg := ServerDefaults()
	var passFile string
	err := walk(path, func(section, key, val string, line int) error {
		var err error
		switch section + "." + key {
		case ".listen":
			cfg.Listen = val
		case "db.socket":
			cfg.DBSocket = val
		case "db.name":
			cfg.DBName = val
		case "db.user":
			cfg.DBUser = val
		case "db.password_file":
			passFile = val
		case "pdns.socket":
			cfg.PDNSSocket = val
		case "pdns.name":
			cfg.PDNSName = val
		case "pdns.user":
			cfg.PDNSUser = val
		case "ha.enabled":
			cfg.HAEnabled = val == "true" || val == "1" || val == "yes"
		case "ha.socket":
			cfg.HASocket = val
		case "timeouts.db":
			cfg.DBTimeout, err = time.ParseDuration(val)
		case "timeouts.ha":
			cfg.HATimeout, err = time.ParseDuration(val)
		case "timeouts.ha_verdict_ttl":
			cfg.HAVerdictTTL, err = time.ParseDuration(val)
		case "timeouts.retry_min":
			cfg.RetryMin, err = time.ParseDuration(val)
		case "timeouts.retry_max":
			cfg.RetryMax, err = time.ParseDuration(val)
		case "timeouts.apply":
			cfg.ApplyTimeout, err = time.ParseDuration(val)
		case "apply.command":
			cfg.ApplyCommand = val
		case "control.socket":
			cfg.ControlSocket = val
		case "control.group":
			cfg.ControlGroup = val
		default:
			return fmt.Errorf("%s:%d: unknown key %q", path, line, key)
		}
		if err != nil {
			return fmt.Errorf("%s:%d: %q: %w", path, line, key, err)
		}
		return nil
	})
	if err != nil {
		return cfg, err
	}
	if cfg.DBUser == "" {
		return cfg, fmt.Errorf("%s: db.user is required", path)
	}
	if passFile != "" {
		raw, err := os.ReadFile(passFile)
		if err != nil {
			return cfg, fmt.Errorf("db.password_file: %w", err)
		}
		cfg.DBPass = strings.TrimSpace(string(raw))
	}
	return cfg, nil
}

func LoadAgent(path string) (Agent, error) {
	cfg := AgentDefaults()
	err := walk(path, func(section, key, val string, line int) error {
		var err error
		switch section + "." + key {
		case ".server":
			cfg.Server = val
		case ".enroll_key":
			cfg.EnrollKey = val
		case ".fingerprint":
			cfg.Fingerprint = strings.ToLower(val)
		case ".log_level":
			cfg.LogLevel = val
		case "reconnect.min":
			cfg.ReconnectMin, err = time.ParseDuration(val)
		case "reconnect.max":
			cfg.ReconnectMax, err = time.ParseDuration(val)
		default:
			// Reject EXPLICITLY: a silently ignored key looks like a working setting.
			return fmt.Errorf("%s:%d: unknown key %q — targets and thresholds come from the panel, "+
				"not from this file", path, line, key)
		}
		if err != nil {
			return fmt.Errorf("%s:%d: %q: %w", path, line, key, err)
		}
		return nil
	})
	if err != nil {
		return cfg, err
	}
	if cfg.Server == "" || cfg.EnrollKey == "" {
		return cfg, fmt.Errorf("%s: both server and enroll_key are required "+
			"(the panel shows the ready file: NS Pulse → Agent config)", path)
	}
	// A bare host means the server's default port: "10.0.0.10" is what people type, not a mistake.
	if _, _, err := net.SplitHostPort(cfg.Server); err != nil {
		cfg.Server = net.JoinHostPort(strings.Trim(cfg.Server, "[]"), DefaultAgentPort)
	}
	switch cfg.LogLevel {
	case "debug", "info", "warn":
	default:
		return cfg, fmt.Errorf("%s: log_level must be debug, info or warn", path)
	}
	if cfg.Fingerprint != "" && !validFingerprint(cfg.Fingerprint) {
		return cfg, fmt.Errorf("%s: fingerprint must be 64 hex characters (SHA-256 of the certificate)", path)
	}
	return cfg, nil
}

func validFingerprint(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func walk(path string, set func(section, key, val string, line int) error) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	section := ""
	for i, line := range strings.Split(string(raw), "\n") {
		s := strings.TrimSpace(line)
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		if strings.HasPrefix(s, "[") {
			if !strings.HasSuffix(s, "]") {
				return fmt.Errorf("%s:%d: unclosed section", path, i+1)
			}
			section = strings.TrimSpace(s[1 : len(s)-1])
			continue
		}
		eq := strings.Index(s, "=")
		if eq < 0 {
			return fmt.Errorf("%s:%d: expected `key = value`", path, i+1)
		}
		key := strings.TrimSpace(s[:eq])
		val := strings.TrimSpace(s[eq+1:])
		if v, err := strconv.Unquote(val); err == nil {
			val = v
		}
		if err := set(section, key, val, i+1); err != nil {
			return err
		}
	}
	return nil
}
