// pulse-server accepts agents, hands out tasks and keeps state in dns_panel. Spec: docs/25-ns-pulse.md.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"os/signal"
	"syscall"

	"dnspanel/dns-pulse/internal/config"
	"dnspanel/dns-pulse/internal/hagate"
	"dnspanel/dns-pulse/internal/server"
	"dnspanel/dns-pulse/internal/store"
	"dnspanel/dns-pulse/internal/wire"
)

// Set at build time via -ldflags -X; without these declarations the flags silently do nothing.
var (
	version  = "dev"
	revision = "unknown"
)

func main() {
	path := flag.String("config", "/opt/dns-panel/etc/pulse-server.toml", "path to the configuration file")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Printf("%s %s (%s)\n", "pulse-server", version, revision)
		return
	}

	cfg, err := config.LoadServer(*path)
	if err != nil {
		log.Fatalf("pulse-server: %v", err)
	}
	db, err := store.Open(cfg.DBSocket, cfg.DBName, cfg.DBUser, cfg.DBPass)
	if err != nil {
		log.Fatalf("pulse-server: database: %v", err)
	}
	defer db.Close()
	if err := db.OpenPDNS(cfg.PDNSSocket, cfg.PDNSName, cfg.PDNSUser); err != nil {
		log.Fatalf("pulse-server: PowerDNS database: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := db.Ping(ctx); err != nil {
		log.Fatalf("pulse-server: database unavailable: %v", err)
	}

	gate := &hagate.Gate{Socket: cfg.HASocket, Enabled: cfg.HAEnabled,
		Timeout: cfg.HATimeout, TTL: cfg.HAVerdictTTL}
	srv := server.New(db, cfg, gate.CanObserve)
	if err := srv.LoadCert(ctx); err != nil {
		log.Fatalf("pulse-server: certificate: %v", err)
	}
	// Order matters: deadlines are set BEFORE the port opens, otherwise the startup pass would overwrite
	// fresh agent state retroactively (docs/25 §5). Bounded so a stuck database cannot hang startup:
	// on timeout Activate returns an error with a retry already scheduled, and the server starts listening.
	actCtx, actCancel := context.WithTimeout(ctx, cfg.DBTimeout+cfg.ApplyTimeout)
	err = srv.Activate(actCtx)
	actCancel()
	if err != nil {
		// Without deadlines the server cannot run. A failed recompute is not fatal: rules are already on
		// retry, and dying here would mean accepting no agents at all.
		if errors.Is(err, server.ErrRecomputePending) {
			log.Printf("pulse-server: %v", err)
		} else {
			log.Fatalf("pulse-server: %v", err)
		}
	}
	// Control socket: panel edits take effect immediately instead of on the next agent event.
	go srv.ServeControl(ctx, cfg.ControlSocket)

	lis, err := tls.Listen("tcp", cfg.Listen, &tls.Config{
		GetCertificate: srv.GetCertificate, MinVersion: tls.VersionTLS12})
	if err != nil {
		log.Fatalf("pulse-server: %v", err)
	}
	go func() {
		<-ctx.Done()
		log.Printf("pulse-server: shutting down")
		lis.Close()
	}()

	log.Printf("pulse-server: listening on %s", cfg.Listen)
	for {
		conn, err := lis.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("pulse-server: accept: %v", err)
			continue
		}
		go func() {
			// A session error concerns one agent, not the server.
			if err := srv.Serve(ctx, wire.New(conn)); err != nil {
				log.Printf("pulse: session ended: %v", err)
			}
		}()
	}
}
