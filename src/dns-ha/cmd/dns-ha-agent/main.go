// dns-ha-agent is the node's privileged (root) executor.
//
// It listens only on a local unix socket and runs a fixed set of typed commands. It never decides when to
// switch over, never touches the network and knows nothing about the peer: that is the manager's job, and
// the manager must not run as root. Privilege separation is the only reason this is a separate process.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"dnspanel/dns-ha/internal/agentd"
	"dnspanel/dns-ha/internal/sdnotify"
)

var (
	version  = "dev"
	revision = "unknown"
)

func main() {
	cfgPath := flag.String("config", "/opt/dns-panel/etc/ha-agent.toml", "agent config")
	group := flag.String("socket-group", "dns-ha", "group owning the socket (who may issue commands)")
	once := flag.String("cmd", "", "run one command and exit (diagnostics: status|preflight)")
	showVersion := flag.Bool("version", false, "version and revision")
	flag.Parse()

	if *showVersion {
		fmt.Printf("dns-ha-agent %s (revision %s)\n", version, revision)
		return
	}
	cfg, err := agentd.LoadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "dns-ha-agent:", err)
		os.Exit(2)
	}
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		fmt.Fprintln(os.Stderr, "dns-ha-agent: state directory:", err)
		os.Exit(2)
	}
	if err := os.MkdirAll(cfg.MarkerDir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "dns-ha-agent: marker directory:", err)
		os.Exit(2)
	}

	agent := &agentd.Agent{StateDir: cfg.StateDir, RunDir: cfg.RunDir, Exec: &agentd.Node{Cfg: cfg},
		PeerKeyPath: cfg.PeerKey.Path, PeerKeyOwner: cfg.PeerKey.Owner,
		PanelSecretGroup: cfg.PanelSecretGroup}

	// One-shot call for on-node diagnostics without stopping the service. Mutations are not allowed here: they
	// require an operation_id and cluster_epoch issued by the manager, not typed by an operator.
	if *once != "" {
		if *once != "status" && *once != "preflight" {
			fmt.Fprintln(os.Stderr, "dns-ha-agent: only status or preflight can be run this way")
			os.Exit(2)
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		resp := agent.Handle(agentd.Request{Cmd: *once})
		_ = enc.Encode(resp)
		if !resp.OK {
			os.Exit(1)
		}
		return
	}

	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "dns-ha-agent: the agent must run as root — otherwise it cannot change the role of the node")
		os.Exit(2)
	}
	srv := &agentd.Server{Agent: agent, Socket: cfg.Socket, Group: *group}
	if err := srv.Listen(); err != nil {
		fmt.Fprintln(os.Stderr, "dns-ha-agent: socket:", err)
		os.Exit(2)
	}
	defer srv.Close()
	go srv.Serve()
	fmt.Fprintf(os.Stderr, "dns-ha-agent %s: socket %s\n", version, cfg.Socket)
	// Socket is open: signal readiness (Type=notify) so the manager and installer learn it as an event.
	if err := sdnotify.Notify("READY=1"); err != nil {
		fmt.Fprintln(os.Stderr, "dns-ha-agent: sd_notify:", err)
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
}
