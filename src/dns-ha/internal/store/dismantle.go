package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// Wiping pair data on dismantle.
//
// What is wiped and what stays is not an implementation detail but a product promise: dismantling returns two
// ordinary servers, not two servers with lost history.
//
// KEPT:
//   - ha_identity: the node UUID. It identifies the PHYSICAL machine, not a pair: dismantled and paired again,
//     the node must stay the same.
//   - ha_schema: local schema version, unrelated to the pair.
//   - ha_trusted_peer: TRUST between machines. Dismantling a pair and breaking trust are separate decisions with
//     separate buttons ("Dismantle HA pair" and "Undo pairing"). After dismantling the servers are standalone but
//     still know each other, which is exactly what lets a pair be rebuilt right away (e.g. in Anycast mode).
//   - ha_peer_requests: the peer-request registry. It must never be touched from here: peer commands run INSIDE
//     a transaction on this very table, so deleting from it would wait on our own lock. Old pair records do not
//     get in the new pair's way (message IDs contain unique operation IDs), and they are cleared at pair creation,
//     when no peer mutation is running.
//
// WIPED: everything else: configuration revisions, pair nodes, publication, replication, epoch and the right
// to be ACTIVE, operation journal.
//
// DNS panel (`dns_panel`) and PowerDNS (`pdns`) data are not touched at all: they live in other databases.

// pairTables are the local dns_ha tables describing the PAIR. Listed explicitly: wiping "everything but
// identity" via information_schema would one day drop a table added for another purpose.
var pairTables = []string{
	"ha_operation_steps",
	"ha_operations",
	"ha_state",
	"ha_publication",
	"ha_replication",
	"ha_settings",
	"ha_nodes",
	"ha_config_revision",
}

// WipePair erases everything that makes the node half of a pair while keeping its identity.
//
// Idempotent: a retry after interruption breaks nothing. Runs in one transaction so the node is never left with
// revisions but no trust, or the right to be ACTIVE without a pair.
func WipePair(ctx context.Context, dsn, dbName string, timeout time.Duration) error {
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, t := range pairTables {
		// The database name is EXPLICIT: the shared DSN connects without a database (the manager must be able
		// to check whether dns_ha exists), and an unqualified query gets "No database selected".
		if _, err := tx.ExecContext(ctx, "DELETE FROM "+dbName+"."+t); err != nil {
			return fmt.Errorf("wipe %s: %w", t, err)
		}
	}
	return tx.Commit()
}

// PairTables returns the list of wiped tables (for tests and diagnostics).
func PairTables() []string { return append([]string(nil), pairTables...) }

// ClearPeerLedger clears the peer-request registry BEFORE pair creation.
//
// The registry must not be touched during dismantling: peer commands run inside a transaction on this very
// table. Pair creation is a safe point: no peer mutation runs and there is no pair yet. Records of the previous
// pair do not interfere (message IDs contain unique operation IDs), but there is no reason to keep them: they
// describe a link that no longer exists.
func ClearPeerLedger(ctx context.Context, dsn, dbName string, timeout time.Duration) error {
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, "DELETE FROM "+dbName+".ha_peer_requests")
	return err
}
