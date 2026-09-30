// pulse-agent probes addresses from its site and reports state transitions to the server. Spec: docs/25-ns-pulse.md.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"dnspanel/dns-pulse/internal/agent"
	"dnspanel/dns-pulse/internal/config"
	"dnspanel/dns-pulse/internal/logs"
)

// Set at build time via -ldflags -X; without these declarations the flags silently do nothing.
var (
	version  = "dev"
	revision = "unknown"
)

func main() {
	path := flag.String("config", "/opt/dns-panel/etc/pulse-agent.toml", "path to the configuration file")
	showVersion := flag.Bool("version", false, "print version and exit")
	// ICMP may be forbidden by site policy even with the capability. The agent then advertises it and gets
	// no ICMP tasks, so "not checked" never reaches the server as "down".
	noICMP := flag.Bool("no-icmp", false, "do not run ICMP checks at this site")
	flag.Parse()
	if *showVersion {
		fmt.Printf("%s %s (%s)\n", "pulse-agent", version, revision)
		return
	}

	cfg, err := config.LoadAgent(*path)
	if err != nil {
		log.Fatalf("pulse-agent: %v", err)
	}
	// systemd (StateDirectory=) decides where the pinned fingerprint lives, not the config, so the two can
	// never disagree. Without systemd, next to the config.
	if d := os.Getenv("STATE_DIRECTORY"); d != "" {
		cfg.StateDir = strings.Split(d, ":")[0]
	} else if cfg.StateDir == "" {
		cfg.StateDir = filepath.Dir(*path)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	logs.SetLevel(cfg.LogLevel)
	a := agent.New(cfg, version+" ("+revision+")")
	if *noICMP {
		a.DisableICMP()
	}
	if err := a.Run(ctx); err != nil {
		log.Fatalf("pulse-agent: %v", err)
	}
}
