package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"

	"dnspanel/dns-ha/internal/config"
	"dnspanel/dns-ha/internal/safety"
	"dnspanel/dns-ha/internal/store"
)

// Completing an interrupted configuration commit, and output of one-shot commands.
//
// `-bootstrap` used to live here: creating a pair from a description file placed on both nodes by hand. It is
// gone; a pair is created by pairing and `-pair build` (§14.5-14.6). Two independent ways to get revision 1
// would mean one of them bypasses donor choice, secret agreement and reseed, and someday someone would use it.

// emit prints a one-shot command's output: one JSON object on stdout, readable by eye and parseable by a
// program.
func emit(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// fail returns a one-shot command's exit code, with a clear reason on stderr.
func fail(err error) int {
	fmt.Fprintln(os.Stderr, "dns-ha-manager:", err)
	return 1
}

// recoverConfigCommit completes a revision commit interrupted between writing the proof and the SQL update (§7.5).
//
// It runs on EVERY start, before anything reads the effective revision, which supplies the peer listener
// address. It relies on SEMANTIC idempotency (revision + fingerprint), not message_id: after a restart the
// message is gone but the proof remains, and the proof says the commit happened.
// Returns true if the matter is closed (nothing to complete, or completed). With the database unavailable the
// caller retries later: starting while MariaDB is down is a normal "too early", not a failure.
func recoverConfigCommit(cfg config.Config) bool {
	proof := safety.NewStore(config.SafetyPath).Read()
	if !proof.Valid || proof.State == nil || proof.State.CommittedConfig == nil {
		return true
	}
	cc := proof.State.CommittedConfig
	dsn, err := store.WriteDSN(cfg.Database.Socket)
	if err != nil {
		fmt.Fprintln(os.Stderr, "dns-ha-manager: configuration recovery:", err)
		return false
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return false
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), config.AgentTimeout)
	defer cancel()

	if err := db.Ping(); err != nil {
		return false // database not up yet: retry next cycle
	}
	done, err := store.RecoverCommitted(ctx, db, cfg.Database.Database, cc.Revision, cc.PayloadHash)
	if err != nil {
		// A failure here does not bring the daemon down: observation and /health matter more, and the divergence
		// already shows in the config_agreement verdict. But it must not be silent.
		fmt.Fprintf(os.Stderr, "dns-ha-manager: WARNING, the commit proof for revision %d disagrees with the database: %v\n",
			cc.Revision, err)
		return true
	}
	if done {
		fmt.Fprintf(os.Stderr, "dns-ha-manager: the commit of revision %d was completed from the proof\n", cc.Revision)
	}
	return true
}
