// Package config reads the manager's local bootstrap config (DOCS/23-ha-manager.md §5).
//
// DELIBERATELY MINIMAL: only what the node cannot start without, i.e. WHO it is and HOW to reach its database.
// Everything operational (intervals, timeouts, peer address, replication, publication) lives in `dns_ha` and
// arrives as configuration revisions; otherwise a year from now we would again be diffing two `.toml` files on
// two nodes to find out why they drifted.
//
// Socket/tool paths are platform constants (see platform.go), not settings: they are the same on every node,
// set by systemd/the package, and need configurability no more than /bin/sh does.
//
// A STRICT TOML subset is parsed: `key = value` and `[section]`, values are double-quoted strings or integers.
// Anything else is an ERROR, not "skip and use defaults": a silently ignored typo in an HA config means the node
// runs by rules other than the ones the operator believes.
//
// No external dependencies on purpose: the subset is tiny, and an extra dependency in an HA daemon is an extra
// failure surface at build and upgrade time.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Config is what the node must know locally, and nothing more.
type Config struct {
	// Node is this node's UUID. It is NOT in the file: the node assigns its identity itself and keeps it in
	// the local dns_ha (ha_identity). It is filled at startup rather than read from config, or there would be a
	// second identity source and a one-letter TOML edit would make the node a stranger.
	Node     string
	Database DatabaseConfig
}

type DatabaseConfig struct {
	Socket   string // local MariaDB unix socket
	Database string // name of the local NON-replicated HA database
	// There is NO user name: the connection always uses the process's OS user (unix_socket auth). A
	// setting would create an "OS user vs SQL account" mismatch that breaks only under the service and looks
	// fine when run by root.
}

// Defaults covers only fields whose correct value is the same everywhere.
func Defaults() Config {
	return Config{
		Database: DatabaseConfig{Socket: "/run/mysqld/mysqld.sock", Database: "dns_ha"},
	}
}

// Load reads and validates the config file.
func Load(path string) (Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("config: %w", err)
	}
	return Parse(string(raw))
}

// Parse parses config content. Separate from Load so it can be tested without files.
func Parse(text string) (Config, error) {
	cfg := Defaults()
	section := ""
	for i, line := range strings.Split(text, "\n") {
		lineNo := i + 1
		s := strings.TrimSpace(line)
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		if strings.HasPrefix(s, "[") {
			if !strings.HasSuffix(s, "]") {
				return Config{}, fmt.Errorf("config:%d: unclosed section %q", lineNo, s)
			}
			section = strings.TrimSpace(s[1 : len(s)-1])
			if section == "" {
				return Config{}, fmt.Errorf("config:%d: empty section name", lineNo)
			}
			continue
		}
		key, val, ok := splitKeyValue(s)
		if !ok {
			return Config{}, fmt.Errorf("config:%d: expected `key = value` or `[section]`, got %q", lineNo, s)
		}
		if err := assign(&cfg, section, key, val, lineNo); err != nil {
			return Config{}, err
		}
	}
	if cfg.Database.Socket == "" {
		return Config{}, fmt.Errorf("config: database.socket must not be empty")
	}
	if cfg.Database.Database == "" {
		return Config{}, fmt.Errorf("config: database.database must not be empty")
	}
	return cfg, nil
}

func splitKeyValue(s string) (string, string, bool) {
	eq := strings.Index(s, "=")
	if eq <= 0 {
		return "", "", false
	}
	key := strings.TrimSpace(s[:eq])
	val := strings.TrimSpace(stripComment(s[eq+1:]))
	if key == "" || val == "" {
		return "", "", false
	}
	return key, val, true
}

// Strip comments ONLY outside quotes, otherwise a '#' inside a value would be lost.
func stripComment(s string) string {
	inQuotes := false
	for i, r := range s {
		switch r {
		case '"':
			inQuotes = !inQuotes
		case '#':
			if !inQuotes {
				return s[:i]
			}
		}
	}
	return s
}

func assign(cfg *Config, section, key, val string, lineNo int) error {
	full := key
	if section != "" {
		full = section + "." + key
	}
	switch full {
	case "node":
		// The key is rejected rather than ignored: a config left over from a previous install would otherwise
		// silently imply an identity other than the one the node actually uses.
		return fmt.Errorf("config:%d: the `node` key is no longer used — the node identity lives in "+
			"the local dns_ha and is created automatically", lineNo)
	case "database.socket":
		return setString(&cfg.Database.Socket, val, full, lineNo)
	case "database.database":
		return setString(&cfg.Database.Database, val, full, lineNo)
	default:
		// An unknown key is an error. This also keeps operational knobs from creeping back into TOML: adding a
		// setting requires deliberately editing this list, not just appending a line to the file.
		return fmt.Errorf("config:%d: unknown key %q (operational parameters live in the database, not in ha.toml)", lineNo, full)
	}
}

func setString(dst *string, val, key string, lineNo int) error {
	if len(val) < 2 || !strings.HasPrefix(val, `"`) || !strings.HasSuffix(val, `"`) {
		return fmt.Errorf("config:%d: the value of %s must be a double-quoted string, got %s", lineNo, key, val)
	}
	unquoted := val[1 : len(val)-1]
	if strings.Contains(unquoted, `"`) {
		return fmt.Errorf("config:%d: the value of %s contains an unescaped quote", lineNo, key)
	}
	*dst = unquoted
	return nil
}

// setInt is kept for future numeric bootstrap fields, should any appear.
func setInt(dst *int, val, key string, lineNo int) error {
	n, err := strconv.Atoi(val)
	if err != nil {
		return fmt.Errorf("config:%d: the value of %s must be an integer, got %q", lineNo, key, val)
	}
	*dst = n
	return nil
}
