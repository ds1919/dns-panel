package peer

import (
	"context"
	"database/sql"
)

// RequestLedger is durable deduplication of mutating messages (DOCS/23-ha-manager.md §6.1, rule 1).
//
// Unlike the in-memory retransmit cache, which is forgotten on restart and not atomic with the action,
// mutations need the invariant "either both the action AND its record are committed, or neither". So the
// ledger runs the action IN THE SAME transaction that registers the request: there is no crash window of
// "config changed, dedup not recorded".
//
// The result is stored as MEANING (code + payload), not the old signed bytes: a reply is bound to a specific
// attempt's nonce, so on retry it is re-signed and bound to the new nonce.
type RequestLedger interface {
	// Execute atomically registers (sender, message_id), runs run in the same transaction and stores the result.
	//
	// A retry of THE SAME logical request (matching request_hash) returns the stored result with replay=true
	// WITHOUT running run again. The same message_id with different content is ErrIDConflict.
	Execute(ctx context.Context, e LedgerEntry, run func(ctx context.Context, tx *sql.Tx) (LedgerResult, error)) (res LedgerResult, replay bool, err error)

	// Done returns the result of an ALREADY executed request, if any, without executing anything.
	//
	// It lets a retry be answered BEFORE the current state is checked. A mutation may legitimately change the
	// world so the same new command would no longer pass the gate: dismantling wipes the epoch and the right
	// to be active, and a retry whose reply was lost would hit "not now". Asking how a completed action ended
	// is always possible: it is a read, not a mutation.
	Done(ctx context.Context, e LedgerEntry) (LedgerResult, bool, error)
}

// LedgerEntry identifies a logical request and is compared on retry.
type LedgerEntry struct {
	Sender      string
	MessageID   string
	Cmd         string
	Epoch       int64
	RequestHash string
}

// LedgerResult is the meaningful outcome of processing.
type LedgerResult struct {
	// Transient means the action was NOT performed: the recipient refused on the merits and changed nothing.
	// Such a reply must not be stored: the registry dedups actions that HAPPENED, while a refusal reflects
	// the world at request time. The operator fixes the cause and retries; a stored refusal would say "no" forever.
	Transient bool
	Code      string // "" = success; otherwise a typed rejection
	Payload   []byte // serialized reply payload
}

// MutationGate reports whether the peer may change our state RIGHT NOW. Checked BEFORE any writes: calm
// state (no fencing or running operation), the right peer, matching epoch. Returns a typed rejection reason.
type MutationGate func(req *Request) (ok bool, code string)
