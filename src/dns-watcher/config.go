package main

import (
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// States lists every pair state the watcher sees; the config assigns a rule to each.
var States = []string{"node1_up", "node2_up", "both_down", "both_up"}

// Config holds nodes, check timing, command values and rules. The watcher doesn't know what each state means:
// route, nftables, iptables, BGP are all just rule commands.
type Config struct {
	Address     string            // address: the pair's service address ($ADDRESS)
	WatcherNode string            // watcher_node: address of THIS host where traffic is caught ($WATCHER_NODE)
	Nodes       [2]netip.AddrPort // node1/node1_port, node2/node2_port: node and its readiness probe port
	Interval    time.Duration
	Rise, Fall  int
	Timeout     time.Duration       // command_timeout: guard against a hung command
	Vars        map[string]string   // [variables]: custom command values
	Conditions  map[string]string   // state (or stop) → rule name
	Rules       map[string][]string // rule name → commands
}

func loadConfig(path string) (Config, error) {
	st, err := os.Stat(path)
	if err != nil {
		return Config{}, err
	}
	// Commands here run as root, so only root may be able to edit the file.
	if sys, ok := st.Sys().(*syscall.Stat_t); !ok || sys.Uid != 0 {
		return Config{}, fmt.Errorf("%s must be owned by root — it holds commands run as root", path)
	}
	if st.Mode().Perm()&0o022 != 0 {
		return Config{}, fmt.Errorf("%s is writable by group or others — it holds commands run as root", path)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	return parseConfig(string(raw))
}

// parseConfig parses a small TOML subset: key = value, [name] sections, values are a string, a number or a
// (possibly multi-line) string array.
func parseConfig(text string) (Config, error) {
	c := Config{Interval: time.Second, Rise: 2, Fall: 2, Timeout: 10 * time.Second,
		Vars: map[string]string{}, Conditions: map[string]string{}, Rules: map[string][]string{}}
	p := &partial{ports: [2]int{17900, 17900}}
	section := ""
	lines := strings.Split(text, "\n")
	for i := 0; i < len(lines); i++ {
		no := i + 1
		s := strings.TrimSpace(lines[i])
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
			section = strings.TrimSpace(s[1 : len(s)-1])
			if section == "" {
				return c, fmt.Errorf("line %d: empty section", no)
			}
			continue
		}
		k, v, ok := strings.Cut(s, "=")
		if !ok {
			return c, fmt.Errorf("line %d: expected key = value", no)
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if strings.HasPrefix(v, "[") {
			for !closed(v) && i+1 < len(lines) {
				i++
				v += "\n" + lines[i]
			}
			if !closed(v) {
				return c, fmt.Errorf("line %d: array is not closed", no)
			}
		}
		if err := c.set(section, k, v, p); err != nil {
			return c, fmt.Errorf("line %d (%s): %v", no, k, err)
		}
	}
	for i, a := range p.addrs {
		if a.IsValid() {
			c.Nodes[i] = netip.AddrPortFrom(a, uint16(p.ports[i]))
		}
	}
	return c, c.validate()
}

// partial collects nodes from two keys (address and port) in any order.
type partial struct {
	addrs [2]netip.Addr
	ports [2]int
}

func (c *Config) set(section, k, v string, p *partial) error {
	idx := map[string]int{"node1": 0, "node2": 1, "node1_port": 0, "node2_port": 1}
	var err error
	switch {
	case section == "variables":
		c.Vars[k] = str(v)
	case section == "conditions":
		c.Conditions[k] = str(v)
	case section != "" && k == "commands":
		var cmds []string
		if cmds, err = strList(v); err == nil {
			c.Rules[section] = cmds
		}
	case section != "":
		err = fmt.Errorf("unknown key")
	case k == "address":
		var a netip.Addr
		if a, err = netip.ParseAddr(str(v)); err == nil {
			c.Address = a.String()
		}
	case k == "watcher_node":
		var a netip.Addr
		if a, err = netip.ParseAddr(str(v)); err == nil {
			c.WatcherNode = a.String()
		}
	case k == "node1" || k == "node2":
		p.addrs[idx[k]], err = netip.ParseAddr(str(v))
	case k == "node1_port" || k == "node2_port":
		var n int
		if n, err = strconv.Atoi(str(v)); err == nil && (n < 1 || n > 65535) {
			err = fmt.Errorf("port out of range")
		}
		p.ports[idx[k]] = n
	case k == "interval":
		c.Interval, err = time.ParseDuration(str(v))
	case k == "command_timeout":
		c.Timeout, err = time.ParseDuration(str(v))
	case k == "rise":
		c.Rise, err = strconv.Atoi(str(v))
	case k == "fall":
		c.Fall, err = strconv.Atoi(str(v))
	default:
		err = fmt.Errorf("unknown key")
	}
	return err
}

// Reserved lists names the watcher passes to commands itself; [variables] can't override them.
var Reserved = []string{"ADDRESS", "WATCHER_NODE", "NODE1", "NODE1_PORT", "NODE2", "NODE2_PORT", "STATE", "ACTIVE_NODE", "ACTIVE_PORT"}

func (c Config) validate() error {
	if c.Address == "" {
		return fmt.Errorf("address is required (the service address of the pair, $ADDRESS in commands)")
	}
	for k := range c.Vars {
		if contains(Reserved, k) {
			return fmt.Errorf("[variables] %s is reserved — the watcher sets it itself", k)
		}
	}
	for i, n := range c.Nodes {
		if !n.IsValid() {
			return fmt.Errorf("node%d is required (address of the node; node%d_port — its readiness probe, 17900 by default)", i+1, i+1)
		}
	}
	if c.Interval <= 0 || c.Rise < 1 || c.Fall < 1 || c.Timeout <= 0 {
		return fmt.Errorf("interval, rise, fall and command_timeout must be positive")
	}
	for _, s := range append(append([]string{}, States...), "stop") {
		r, ok := c.Conditions[s]
		if !ok {
			if s == "stop" {
				continue // optional: do nothing on stop
			}
			return fmt.Errorf("[conditions] %s is required", s)
		}
		if _, ok := c.Rules[r]; !ok {
			return fmt.Errorf("[conditions] %s = %q: there is no [%s] with commands", s, r, r)
		}
	}
	for k := range c.Conditions {
		if k != "stop" && !contains(States, k) {
			return fmt.Errorf("[conditions] unknown state %q (known: %s, stop)", k, strings.Join(States, ", "))
		}
	}
	return nil
}

// closed reports whether v has a closing bracket outside strings.
func closed(v string) bool {
	in := false
	for i := 0; i < len(v); i++ {
		switch {
		case v[i] == '\\' && in:
			i++
		case v[i] == '"':
			in = !in
		case v[i] == ']' && !in:
			return true
		}
	}
	return false
}

// strList parses a TOML string array: ["a", "b"], allowing a trailing comma and comments between items.
func strList(v string) ([]string, error) {
	v = strings.TrimSpace(v)
	if !strings.HasPrefix(v, "[") {
		return nil, fmt.Errorf("expected an array of strings")
	}
	out := []string{}
	for i := 1; i < len(v); i++ {
		switch ch := v[i]; {
		case ch == ']':
			return out, nil
		case ch == '#':
			for i < len(v) && v[i] != '\n' {
				i++
			}
		case ch == '"':
			var b strings.Builder
			for i++; i < len(v) && v[i] != '"'; i++ {
				if v[i] == '\\' && i+1 < len(v) {
					i++
				}
				b.WriteByte(v[i])
			}
			out = append(out, b.String())
		case ch == ',' || ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r':
		default:
			return nil, fmt.Errorf("unexpected %q in array (strings must be quoted)", ch)
		}
	}
	return nil, fmt.Errorf("array is not closed")
}

// str returns a string value, quoted or bare, with a trailing comment stripped.
func str(v string) string {
	v = strings.TrimSpace(v)
	if strings.HasPrefix(v, `"`) {
		if end := strings.Index(v[1:], `"`); end >= 0 {
			return v[1 : end+1]
		}
	}
	if i := strings.Index(v, "#"); i >= 0 {
		v = v[:i]
	}
	return strings.TrimSpace(v)
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}
