package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"dnspanel/dns-ha/internal/peer"
)

// Ledger is durable deduplication of mutating peer messages on top of `dns_ha.ha_peer_requests`.
//
// Key property: REGISTERING the request and THE ACTION itself happen in ONE transaction, so there is never a
// state "configuration changed but request not recorded" after which a retry would run the action twice.
// Either both commit or neither does.
//
// This works precisely because dedup and configuration live in the same local database. An action touching an
// external system would need a two-phase protocol instead.
type Ledger struct {
	db      *sql.DB
	table   string
	timeout time.Duration
}

// NewLedger connects to the local database as the process's OS user (unix_socket auth).
func NewLedger(socket, dbName string, timeout time.Duration) (*Ledger, error) {
	dsn, err := WriteDSN(socket)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("ledger_open: %w", err)
	}
	db.SetMaxOpenConns(4)
	return &Ledger{db: db, table: dbName + ".ha_peer_requests", timeout: timeout}, nil
}

func (l *Ledger) Close() error { return l.db.Close() }

// Done returns the stored result of a request with the same meaning fingerprint. Read-only: no transaction, no gate.
func (l *Ledger) Done(ctx context.Context, e peer.LedgerEntry) (peer.LedgerResult, bool, error) {
	c, cancel := context.WithTimeout(ctx, l.timeout)
	defer cancel()
	var haveHash, code string
	var payload []byte
	err := l.db.QueryRowContext(c, "SELECT request_hash, COALESCE(result_code,''), result_payload FROM "+l.table+
		" WHERE sender_node_id=? AND message_id=? AND status='DONE'", e.Sender, e.MessageID).
		Scan(&haveHash, &code, &payload)
	if err != nil {
		return peer.LedgerResult{}, false, nil // no row or read failed: the normal path
	}
	if haveHash != e.RequestHash {
		return peer.LedgerResult{}, false, nil // same id with a different meaning is handled by Execute
	}
	return peer.LedgerResult{Code: code, Payload: payload}, true, nil
	// Execute implements peer.RequestLedger.
}

func (l *Ledger) Execute(ctx context.Context, e peer.LedgerEntry,
	run func(ctx context.Context, tx *sql.Tx) (peer.LedgerResult, error)) (peer.LedgerResult, bool, error) {

	c, cancel := context.WithTimeout(ctx, l.timeout)
	defer cancel()

	tx, err := l.db.BeginTx(c, nil)
	if err != nil {
		return peer.LedgerResult{}, false, fmt.Errorf("ledger_begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // no-op after a successful commit

	// Lock the request row (or confirm it is absent) BEFORE running the action: two concurrent connections
	// with the same message_id must not run it twice.
	var haveHash, code string
	var payload []byte
	err = tx.QueryRowContext(c, "SELECT request_hash, COALESCE(result_code,''), result_payload FROM "+l.table+
		" WHERE sender_node_id=? AND message_id=? FOR UPDATE", e.Sender, e.MessageID).Scan(&haveHash, &code, &payload)
	switch {
	case err == nil:
		// Already processed. Same meaning -> return the stored result without repeating the action.
		if haveHash != e.RequestHash {
			return peer.LedgerResult{}, false, peer.ErrRequestConflict
		}
		if cerr := tx.Commit(); cerr != nil {
			return peer.LedgerResult{}, false, fmt.Errorf("ledger_commit: %w", cerr)
		}
		return peer.LedgerResult{Code: code, Payload: payload}, true, nil
	case !errors.Is(err, sql.ErrNoRows):
		return peer.LedgerResult{}, false, fmt.Errorf("ledger_lookup: %w", err)
	}

	// New request: register and execute it right away, in this same transaction.
	if _, err := tx.ExecContext(c, "INSERT INTO "+l.table+
		" (sender_node_id, message_id, cmd, epoch, request_hash, status) VALUES (?,?,?,?,?,'IN_PROGRESS')",
		e.Sender, e.MessageID, e.Cmd, e.Epoch, e.RequestHash); err != nil {
		return peer.LedgerResult{}, false, fmt.Errorf("ledger_insert: %w", err)
	}
	res, err := run(c, tx)
	if err != nil {
		// The action failed: roll back EVERYTHING, including registration, so the sender may retry.
		return peer.LedgerResult{}, false, err
	}
	if res.Transient {
		// Nothing happened, so no record of it may remain. The rollback removes the registration entirely, so a
		// retry after the cause is fixed is considered afresh instead of getting the old refusal from the journal.
		return res, false, nil
	}
	status := "DONE"
	if res.Code != "" {
		status = "REJECTED"
	}
	if _, err := tx.ExecContext(c, "UPDATE "+l.table+
		" SET status=?, result_code=?, result_payload=?, completed_at=NOW() WHERE sender_node_id=? AND message_id=?",
		status, nullIfEmpty(res.Code), res.Payload, e.Sender, e.MessageID); err != nil {
		return peer.LedgerResult{}, false, fmt.Errorf("ledger_complete: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return peer.LedgerResult{}, false, fmt.Errorf("ledger_commit: %w", err)
	}
	return res, false, nil
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
