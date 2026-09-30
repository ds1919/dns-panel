// Package observe observes the node's actual state. No mutations.
package observe

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Prerequisite is a required MariaDB setting (DOCS/23-ha-manager.md §12.3).
type Prerequisite struct {
	Option string   // name in the MariaDB config
	Want   string   // required value
	Got    []string // actual values from the persisted config (empty = unset); the option may repeat
	OK     bool
	Why    string // shown in the panel so it is an explanation, not a bare string
}

// GotString renders the actual value for humans.
func (p Prerequisite) GotString() string {
	if len(p.Got) == 0 {
		return ""
	}
	return strings.Join(p.Got, ",")
}

type requirement struct {
	option   string
	want     string
	why      string
	multi    bool // repeatable option; requirement = want is present among the values
	forDNSHA bool // needed only with the local non-replicated dns_ha
}

var requirements = []requirement{
	{option: "read_only", want: "ON", why: "fail-safe: after a (re)start the node does not become writable by itself"},
	{option: "skip-slave-start", want: "ON", why: "otherwise a replica starts its threads on its own after a restart — including a fenced node reattaching"},
	{option: "gtid_strict_mode", want: "ON", why: "provable replication positions and protection from out-of-order application"},
	{option: "binlog_format", want: "ROW", why: "prerequisite for per-database binlog filtering and replication semantics"},
	{option: "log_slave_updates", want: "ON", why: "the chain of roles after a switchover"},
	// Without these two, local dns_ha would reach the binlog and the peer: HA activity would move the GTID
	// (the 2026-08-03 livelock) and the control plane would sit inside the replication it manages.
	{option: "binlog-ignore-db", want: "dns_ha", why: "manager writes must not reach the binlog and move the GTID",
		multi: true, forDNSHA: true},
	{option: "replicate-ignore-db", want: "dns_ha", why: "the local HA state must not arrive from the other node",
		multi: true, forDNSHA: true},
}

// ParseMyPrintDefaults parses `my_print_defaults mysqld` output: `--key=value` or `--key` (a bare flag
// is "ON", as MariaDB treats booleans). Underscores and dashes are equivalent. Values are lists: some options
// (binlog-ignore-db, replicate-ignore-db, …) repeat, and last-wins would hide that the needed DB is listed.
func ParseMyPrintDefaults(out string) map[string][]string {
	res := make(map[string][]string)
	for _, line := range strings.Split(out, "\n") {
		s := strings.TrimSpace(line)
		if !strings.HasPrefix(s, "--") {
			continue
		}
		s = strings.TrimPrefix(s, "--")
		key, val := s, "ON"
		if eq := strings.Index(s, "="); eq >= 0 {
			key, val = s[:eq], s[eq+1:]
		}
		key = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(key), "_", "-"))
		if key == "" {
			continue
		}
		res[key] = append(res[key], strings.TrimSpace(val))
	}
	return res
}

// CheckPrerequisites checks the persisted config against the required set. includeDNSHA=false skips
// requirements that only matter with local dns_ha (see requirement.forDNSHA).
func CheckPrerequisites(opts map[string][]string, includeDNSHA bool) []Prerequisite {
	out := make([]Prerequisite, 0, len(requirements))
	for _, r := range requirements {
		if r.forDNSHA && !includeDNSHA {
			continue
		}
		got := opts[strings.ReplaceAll(r.option, "_", "-")]
		out = append(out, Prerequisite{
			Option: r.option,
			Want:   r.want,
			Got:    got,
			OK:     satisfied(r, got),
			Why:    r.why,
		})
	}
	return out
}

func satisfied(r requirement, got []string) bool {
	if len(got) == 0 {
		return false
	}
	if r.multi {
		// Repeatable option: the wanted value just has to be present.
		for _, g := range got {
			if normalizeOption(g) == normalizeOption(r.want) {
				return true
			}
		}
		return false
	}
	// Single option: MariaDB applies the last occurrence.
	return normalizeOption(got[len(got)-1]) == normalizeOption(r.want)
}

func normalizeOption(v string) string {
	s := strings.ToLower(strings.TrimSpace(v))
	switch s {
	case "on", "1", "true", "yes":
		return "on"
	case "off", "0", "false", "no":
		return "off"
	}
	return s
}

// MyPrintDefaults runs `my_print_defaults mysqld`. It reads only config files, needs no running server
// and no root, so the manager can check prerequisites without privileges or MariaDB availability.
func MyPrintDefaults(ctx context.Context, bin string, timeout time.Duration) (map[string][]string, error) {
	c, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	out, err := exec.CommandContext(c, bin, "mysqld").Output()
	if err != nil {
		return nil, fmt.Errorf("my_print_defaults: %w", err)
	}
	return ParseMyPrintDefaults(string(out)), nil
}
