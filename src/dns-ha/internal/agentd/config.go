package agentd

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// Config is the privileged agent's local config.
//
// It STAYS on the node, unlike the manager's operational settings in the DB: the agent must work when the DB
// is unavailable or is itself the object of the operation. It holds only what is needed to reach the node:
// MariaDB access, replication credentials (as references to root files) and PowerDNS commands.
//
// No secrets are stored here — only paths to root-owned 0600 files. A password in a config sooner or later
// ends up in a backup, a diff or someone's clipboard. There is deliberately no node identity (see Agent).
type Config struct {
	StateDir  string // durable: survives reboot
	RunDir    string // socket, markers and the lock of the current run
	Socket    string
	MarkerDir string

	MySQL struct {
		Socket string
		User   string // unix_socket authentication: no password needed
	}
	Replication struct {
		User       string
		SecretFile string
		Port       int
		DumpUser   string
		DumpSecret string   // path to the file
		Databases  []string // what is transferred on reseed
	}
	PDNS struct {
		Control     string
		RoleConf    string
		ConfigCheck string
		Restart     string
		Stop        string
		IsActive    string
	}
	Publication struct {
		Address string // empty → marker only (the publication provider is external)
		Device  string
	}
	// PeerKey is the only file the agent writes for pairing, and its owner (the manager user: may read, not
	// write).
	PeerKey struct {
		Path  string
		Owner string
	}
	// Failsafe is the HA-role fail-safe: the product file and its symlink in the MariaDB config directory.
	// Pair creation installs it, dismantling removes it.
	Failsafe struct {
		Source string
		Link   string
	}
	// PanelSecretGroup is the web process group: auth-master.key must stay readable by the panel after pair
	// creation, otherwise nobody can decrypt TOTP after a switchover.
	PanelSecretGroup string
}

// DefaultConfig returns the values for a typical pair node.
func DefaultConfig() Config {
	var c Config
	c.StateDir = "/opt/dns-panel/var"
	c.RunDir = "/run/dns-panel/ha"
	c.Socket = c.RunDir + "/agent.sock"
	c.MarkerDir = c.RunDir
	c.MySQL.Socket = "/run/mysqld/mysqld.sock"
	c.MySQL.User = "root"
	c.Replication.User = "repl"
	c.Replication.SecretFile = "/opt/dns-panel/etc/secrets/repl.secret"
	c.Replication.Port = 3306
	c.Replication.DumpUser = "ha_monitor"
	c.Replication.DumpSecret = "/opt/dns-panel/etc/secrets/ha_monitor.secret"
	c.Replication.Databases = []string{"dns_panel", "pdns"}
	c.PDNS.Control = "pdns_control"
	c.PDNS.RoleConf = "/etc/powerdns/pdns.d/90-ha-role.conf"
	c.PDNS.ConfigCheck = "pdns_server --config=check"
	c.PDNS.Restart = "systemctl restart pdns"
	c.PDNS.Stop = "systemctl stop pdns"
	c.PDNS.IsActive = "systemctl is-active --quiet pdns"
	c.Publication.Device = "lo"
	c.PeerKey.Path = "/opt/dns-panel/etc/secrets/peer.key"
	c.PeerKey.Owner = "dns-ha"
	c.PanelSecretGroup = "www-data"
	c.Failsafe.Source = "/opt/dns-panel/etc/mariadb/ha-failsafe.cnf"
	c.Failsafe.Link = "/etc/mysql/mariadb.conf.d/61-dns-panel-ha.cnf"
	return c
}

// LoadConfig reads the agent config. Parsing is strict: an unknown key fails startup, because a silently
// ignored setting in HA means a node that behaves differently from what its config says.
func LoadConfig(path string) (Config, error) {
	c := DefaultConfig()
	raw, err := os.ReadFile(path)
	if err != nil {
		return c, fmt.Errorf("agent config: %w", err)
	}
	section := ""
	for i, line := range strings.Split(string(raw), "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
			section = strings.ToLower(strings.Trim(t, "[]"))
			continue
		}
		k, v, ok := strings.Cut(t, "=")
		if !ok {
			return c, fmt.Errorf("agent config, line %d: not `key = value`", i+1)
		}
		key := strings.ToLower(strings.TrimSpace(k))
		val := strings.Trim(strings.TrimSpace(v), `"`)
		full := key
		if section != "" {
			full = section + "." + key
		}
		if err := c.set(full, val); err != nil {
			return c, fmt.Errorf("agent config, line %d: %w", i+1, err)
		}
	}
	// Validate the publication address at startup, not at switchover: otherwise the error would surface
	// mid-operation, when the node has already stopped being what it was.
	if c.Publication.Address != "" {
		if _, _, err := net.ParseCIDR(c.Publication.Address); err != nil {
			return c, fmt.Errorf("agent config: publication.address must be a CIDR (for example 192.0.2.10/32): %v", err)
		}
		if c.Publication.Device == "" {
			return c, fmt.Errorf("agent config: publication.address is set without publication.device")
		}
	}
	return c, nil
}

func (c *Config) set(key, val string) error {
	switch key {
	case "node":
		// A dedicated case rather than "unknown key": an admin upgrading an old install should learn where
		// node identity lives now, not see "typo".
		return fmt.Errorf("the `node` key is no longer used — the agent has no identity at all, " +
			"the node UUID lives in the local dns_ha (table ha_identity)")
	case "state_dir":
		c.StateDir = val
	case "socket":
		c.Socket = val
	case "run_dir":
		c.RunDir = val
	case "marker_dir":
		c.MarkerDir = val
	case "mysql.socket":
		c.MySQL.Socket = val
	case "mysql.user":
		c.MySQL.User = val
	case "replication.user":
		c.Replication.User = val
	case "replication.secret_file":
		c.Replication.SecretFile = val
	case "replication.port":
		n, err := strconv.Atoi(val)
		if err != nil {
			return fmt.Errorf("replication port: %v", err)
		}
		c.Replication.Port = n
	case "replication.dump_user":
		c.Replication.DumpUser = val
	case "replication.dump_secret_file":
		c.Replication.DumpSecret = val
	case "replication.databases":
		c.Replication.Databases = splitList(val)
	case "pdns.control":
		c.PDNS.Control = val
	case "pdns.role_conf":
		c.PDNS.RoleConf = val
	case "pdns.config_check":
		c.PDNS.ConfigCheck = val
	case "pdns.restart":
		c.PDNS.Restart = val
	case "pdns.stop":
		c.PDNS.Stop = val
	case "pdns.is_active":
		c.PDNS.IsActive = val
	case "publication.address":
		c.Publication.Address = val
	case "publication.device":
		c.Publication.Device = val
	case "peer_key.path":
		c.PeerKey.Path = val
	case "peer_key.owner":
		c.PeerKey.Owner = val
	case "panel_secret_group":
		c.PanelSecretGroup = val
	case "failsafe.source":
		c.Failsafe.Source = val
	case "failsafe.link":
		c.Failsafe.Link = val
	default:
		return fmt.Errorf("unknown key %q", key)
	}
	return nil
}

func splitList(v string) []string {
	v = strings.Trim(v, "[]")
	var out []string
	for _, p := range strings.Split(v, ",") {
		p = strings.Trim(strings.TrimSpace(p), `"`)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (c Config) replicationSecret() (string, error) { return readSecret(c.Replication.SecretFile) }
func (c Config) dumpSecret() (string, error)        { return readSecret(c.Replication.DumpSecret) }

// readSecret reads a password from a root file. Empty password ONLY when no file is configured: a configured
// but unreadable file is an error, otherwise we would silently connect without a password.
func readSecret(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fail("secret_unreadable", err.Error())
	}
	return strings.TrimSpace(string(raw)), nil
}
