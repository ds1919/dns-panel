// dns-watcher is an external executor of the DNS Panel Anycast pair's readiness probe where there is no Cisco IP SLA.
//
// The pair's only external contract: the readiness probe (TCP, 17900 by default) is open only on ACTIVE and only
// while it is ready to serve. The watcher checks both nodes' probes, reduces them to one state (node1_up,
// node2_up, both_down, both_up = split-brain) and runs that state's rule when the state CHANGES. What a rule
// does (route, nftables, iptables, birdc, a script) is up to the config, not the watcher.
//
// Rule commands run via /bin/sh -c strictly in order. The first failure stops the rule and it isn't considered
// applied: the next round retries it whole until it succeeds. On SIGTERM/SIGINT the stop rule runs, if set.
// Only changes are logged.
//
//	dns-watcher -config /opt/dns-panel/etc/dns-watcher.toml
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var revision = "dev"

type node struct {
	name  string
	probe netip.AddrPort
	ready bool
	ok    int // consecutive successful checks
	bad   int // consecutive failed checks
}

func main() {
	path := flag.String("config", "/opt/dns-panel/etc/dns-watcher.toml", "config file")
	flag.Parse()
	log.SetFlags(0)
	cfg, err := loadConfig(*path)
	if err != nil {
		log.Fatalf("dns-watcher: config %s: %v", *path, err)
	}
	nodes := []*node{{name: "node1", probe: cfg.Nodes[0]}, {name: "node2", probe: cfg.Nodes[1]}}
	log.Printf("dns-watcher %s: node1 %s, node2 %s, probe every %s (rise %d, fall %d)",
		revision, cfg.Nodes[0], cfg.Nodes[1], cfg.Interval, cfg.Rise, cfg.Fall)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	tick := time.NewTicker(cfg.Interval)
	defer tick.Stop()

	applied := "" // state whose rule has been applied; empty = none yet
	lastErr := "" // the same rule failure is logged once, not every second
	notified := false
	for {
		for _, n := range nodes {
			observe(n, open(n.probe, cfg.Interval), cfg)
		}
		state, target := decide(nodes)
		if state != applied {
			rule := cfg.Conditions[state]
			if err := runRule(cfg, rule, state, target); err != nil {
				if msg := fmt.Sprintf("%s → [%s]: %v", state, rule, err); msg != lastErr {
					log.Printf("dns-watcher: %s (will retry)", msg)
					lastErr = msg
				}
			} else {
				log.Printf("dns-watcher: %s → [%s] done", describe(state, target), rule)
				applied, lastErr = state, ""
			}
		}
		if applied != "" && !notified {
			sdNotify("READY=1") // first rule applied: the watcher is in service
			notified = true
		}
		select {
		case <-stop:
			if rule, ok := cfg.Conditions["stop"]; ok {
				if err := runRule(cfg, rule, "stop", netip.AddrPort{}); err != nil {
					log.Printf("dns-watcher: stop → [%s]: %v", rule, err)
				} else {
					log.Printf("dns-watcher: stop → [%s] done", rule)
				}
			}
			log.Printf("dns-watcher: stopped")
			return
		case <-tick.C:
		}
	}
}

// runRule runs the rule's commands in order; the first failure stops the rule.
//
// Commands get config values ($ADDRESS, $WATCHER_NODE, $NODE1, $NODE1_PORT, $NODE2, $NODE2_PORT, [variables])
// and per-state ones ($STATE, $ACTIVE_NODE, $ACTIVE_PORT; empty for both_* and stop).
//
// command_timeout is a safety guard, not a wait: a hung birdc or script would otherwise stall both the checks
// and stop handling. On timeout the command's whole process group is killed, not just sh.
func runRule(cfg Config, rule, state string, active netip.AddrPort) error {
	env := append(os.Environ(),
		"ADDRESS="+cfg.Address, "WATCHER_NODE="+cfg.WatcherNode,
		"NODE1="+cfg.Nodes[0].Addr().String(), "NODE1_PORT="+strconv.Itoa(int(cfg.Nodes[0].Port())),
		"NODE2="+cfg.Nodes[1].Addr().String(), "NODE2_PORT="+strconv.Itoa(int(cfg.Nodes[1].Port())),
		"STATE="+state)
	if active.IsValid() {
		env = append(env, "ACTIVE_NODE="+active.Addr().String(), "ACTIVE_PORT="+strconv.Itoa(int(active.Port())))
	} else {
		env = append(env, "ACTIVE_NODE=", "ACTIVE_PORT=")
	}
	for k, v := range cfg.Vars {
		env = append(env, k+"="+v)
	}
	for i, c := range cfg.Rules[rule] {
		ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
		cmd := exec.CommandContext(ctx, "/bin/sh", "-c", c)
		cmd.Env = env
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
		// Output matters only on failure and goes into the error, which the loop logs once. Successful commands
		// stay quiet; a rule can log itself (logger).
		out, err := cmd.CombinedOutput()
		timedOut := ctx.Err() == context.DeadlineExceeded
		cancel()
		if err != nil {
			if timedOut {
				err = fmt.Errorf("killed after command_timeout %s", cfg.Timeout)
			}
			if o := strings.TrimSpace(string(out)); o != "" {
				return fmt.Errorf("command %d %q: %v: %s", i+1, c, err, o)
			}
			return fmt.Errorf("command %d %q: %v", i+1, c, err)
		}
	}
	return nil
}

// open performs one probe check (TCP connect). The timeout is the interval: the next check is already due.
func open(p netip.AddrPort, timeout time.Duration) bool {
	c, err := net.DialTimeout("tcp", p.String(), timeout)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// observe applies rise/fall: a single stray failure (or success) doesn't change the node's state.
func observe(n *node, isOpen bool, c Config) {
	if isOpen {
		n.ok, n.bad = n.ok+1, 0
		if !n.ready && n.ok >= c.Rise {
			n.ready = true
			log.Printf("dns-watcher: %s %s probe open — ready", n.name, n.probe)
		}
		return
	}
	n.ok, n.bad = 0, n.bad+1
	if n.ready && n.bad >= c.Fall {
		n.ready = false
		log.Printf("dns-watcher: %s %s probe closed — not ready", n.name, n.probe)
	}
}

func decide(nodes []*node) (string, netip.AddrPort) {
	switch a, b := nodes[0].ready, nodes[1].ready; {
	case a && b:
		return "both_up", netip.AddrPort{}
	case a:
		return "node1_up", nodes[0].probe
	case b:
		return "node2_up", nodes[1].probe
	}
	return "both_down", netip.AddrPort{}
}

func describe(state string, target netip.AddrPort) string {
	switch state {
	case "both_up":
		return "SPLIT-BRAIN (probe open on both nodes)"
	case "both_down":
		return "no node is ready"
	}
	return state + " (" + target.Addr().String() + ")"
}

// sdNotify reports readiness to systemd (Type=notify); outside systemd there is no socket and it does nothing.
func sdNotify(state string) {
	addr := os.Getenv("NOTIFY_SOCKET")
	if addr == "" {
		return
	}
	os.Unsetenv("NOTIFY_SOCKET") // not meant for rule commands
	if addr[0] == '@' {
		addr = "\x00" + addr[1:]
	}
	if c, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: addr, Net: "unixgram"}); err == nil {
		c.Write([]byte(state))
		c.Close()
	} else {
		fmt.Fprintln(os.Stderr, "dns-watcher: sd_notify:", err)
	}
}
