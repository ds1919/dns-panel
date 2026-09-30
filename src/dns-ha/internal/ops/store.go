// Package ops implements HA operations: a durable journal and the state machines (planned switchover,
// emergency promotion, reseed).
//
// An operation is an intent with a durable trace: without "what I started and where I stopped", a daemon
// restart mid-switchover would leave a node that does not know what it is doing, exactly when the pair
// is most vulnerable.
//
// The journal lives in the LOCAL dns_ha (each side has its own) and is NOT the safety authority: the
// authority, epoch and handoff live in the safety file. The journal says "what we are doing", not
// "what we are allowed to do".
package ops

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Operation kinds and states; values match the schema.
const (
	KindPlanned   = "planned_switchover"
	KindEmergency = "emergency_promote"
	KindReseed    = "reseed"

	StatePending   = "PENDING"
	StateRunning   = "RUNNING"
	StateCompleted = "COMPLETED"
	StateFailed    = "FAILED"
	StateAborted   = "ABORTED"
)

// Operation is a journal record.
type Operation struct {
	ID          string `json:"operation_id"`
	Kind        string `json:"kind"`
	State       string `json:"state"`
	Epoch       int64  `json:"epoch"`
	SourceNode  string `json:"source_node,omitempty"`
	TargetNode  string `json:"target_node,omitempty"`
	RequestedBy string `json:"requested_by,omitempty"`
	Reason      string `json:"reason,omitempty"`
	// Ack and AcceptRelayLoss belong to an emergency promotion: the operator's grounds and consent to
	// possible data loss.
	Ack             string     `json:"ack,omitempty"`
	AcceptRelayLoss bool       `json:"accept_relay_loss"`
	StartedAt       time.Time  `json:"started_at"`
	FinishedAt      *time.Time `json:"finished_at,omitempty"`
}

// Active reports whether the operation is still in progress.
func (o Operation) Active() bool { return o.State == StatePending || o.State == StateRunning }

// Store is the operation journal in the local database.
type Store struct {
	DB     *sql.DB
	DBName string
}

// Create starts an operation. The caller picks the ID; it is passed to every agent command, so a retry
// after a disconnect does not repeat the action.
//
// Only ONE operation may run at a time: two state machines pulling the role in different directions is
// a race for authority, not parallelism.
func (s Store) Create(ctx context.Context, op Operation) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var busy string
	err = tx.QueryRowContext(ctx, "SELECT operation_id FROM "+s.DBName+
		".ha_operations WHERE state IN ('PENDING','RUNNING') LIMIT 1 FOR UPDATE").Scan(&busy)
	switch {
	case err == nil:
		if busy == op.ID {
			return nil // same operation created again
		}
		return fmt.Errorf("operation_busy: %s is already running", busy)
	case !errors.Is(err, sql.ErrNoRows):
		return fmt.Errorf("operation_lookup: %w", err)
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO "+s.DBName+".ha_operations "+
		"(operation_id, kind, state, epoch, source_node, target_node, requested_by, reason, ack, accept_relay_loss) "+
		"VALUES (?,?,?,?,?,?,?,?,?,?)",
		op.ID, op.Kind, StatePending, op.Epoch, nullIfEmpty(op.SourceNode), nullIfEmpty(op.TargetNode),
		nullIfEmpty(op.RequestedBy), nullIfEmpty(op.Reason), nullIfEmpty(op.Ack), op.AcceptRelayLoss); err != nil {
		return fmt.Errorf("operation_create: %w", err)
	}
	return tx.Commit()
}

// FreeID returns an ID for a NEW attempt.
//
// The base ID is derived from node and epoch so that a retry of a running attempt is the same action.
// But an aborted attempt stays in the journal forever and the epoch does not grow after an abort (it
// happens before the point of no return), so the next attempt would collide with it: a dead end, since
// only a switchover can move the epoch. Hence an attempt suffix; a running operation is still caught
// by the one-at-a-time check in Create.
func (s Store) FreeID(ctx context.Context, base string) (string, error) {
	for attempt := 1; attempt <= 20; attempt++ {
		id := base
		if attempt > 1 {
			id = fmt.Sprintf("%s-try%d", base, attempt)
		}
		op, err := s.Get(ctx, id)
		if err != nil {
			return "", err
		}
		if op == nil {
			return id, nil
		}
		if op.Active() {
			return id, nil // same running attempt: let Create report it as busy
		}
	}
	// Every attempt suffix is already taken.
	return "", fmt.Errorf("operation_id_exhausted: too many attempts for %s", base)
}

// Current returns this node's running operation, if any.
func (s Store) Current(ctx context.Context) (*Operation, error) {
	row := s.DB.QueryRowContext(ctx, "SELECT operation_id, kind, state, epoch, COALESCE(source_node,''), "+
		"COALESCE(target_node,''), COALESCE(requested_by,''), COALESCE(reason,''), COALESCE(ack,''), "+
		"accept_relay_loss, started_at FROM "+s.DBName+
		".ha_operations WHERE state IN ('PENDING','RUNNING') ORDER BY started_at DESC LIMIT 1")
	var op Operation
	err := row.Scan(&op.ID, &op.Kind, &op.State, &op.Epoch, &op.SourceNode, &op.TargetNode,
		&op.RequestedBy, &op.Reason, &op.Ack, &op.AcceptRelayLoss, &op.StartedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("operation_current: %w", err)
	}
	return &op, nil
}

// Get returns an operation by ID.
func (s Store) Get(ctx context.Context, id string) (*Operation, error) {
	row := s.DB.QueryRowContext(ctx, "SELECT operation_id, kind, state, epoch, COALESCE(source_node,''), "+
		"COALESCE(target_node,''), COALESCE(requested_by,''), COALESCE(reason,''), COALESCE(ack,''), "+
		"accept_relay_loss, started_at FROM "+s.DBName+".ha_operations WHERE operation_id=?", id)
	var op Operation
	err := row.Scan(&op.ID, &op.Kind, &op.State, &op.Epoch, &op.SourceNode, &op.TargetNode,
		&op.RequestedBy, &op.Reason, &op.Ack, &op.AcceptRelayLoss, &op.StartedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("operation_get: %w", err)
	}
	return &op, nil
}

// SetState moves the operation to a new state.
func (s Store) SetState(ctx context.Context, id, state, reason string) error {
	fin := "NULL"
	if state == StateCompleted || state == StateFailed || state == StateAborted {
		fin = "NOW()"
	}
	_, err := s.DB.ExecContext(ctx, "UPDATE "+s.DBName+".ha_operations SET state=?, reason=COALESCE(?, reason), "+
		"finished_at="+fin+" WHERE operation_id=?", state, nullIfEmpty(reason), id)
	if err != nil {
		return fmt.Errorf("operation_state: %w", err)
	}
	return nil
}

// StepResult is a step outcome as recorded in the journal.
type StepResult struct {
	Step        string `json:"step"`
	NodeID      string `json:"node_id,omitempty"`
	OK          bool   `json:"ok"`
	Noop        bool   `json:"noop,omitempty"`
	StateProven bool   `json:"state_proven"`
	Error       string `json:"error,omitempty"`
	Detail      string `json:"detail,omitempty"`
	// At is when the step was recorded, so the operator can see how long a switchover took and where it waited.
	At string `json:"at,omitempty"`
}

// RecordStep appends a step to the journal.
//
// The step is recorded AFTER it runs, and whether to repeat it is decided by the actions' idempotency,
// not by the journal: the write may not have reached disk, so a missing step is no proof it did not run.
func (s Store) RecordStep(ctx context.Context, opID string, r StepResult) error {
	_, err := s.DB.ExecContext(ctx, "INSERT INTO "+s.DBName+".ha_operation_steps "+
		"(operation_id, seq, step, node_id, ok, noop, state_proven, error, detail) "+
		"SELECT ?, COALESCE(MAX(seq),0)+1, ?, ?, ?, ?, ?, ?, ? FROM "+s.DBName+
		".ha_operation_steps WHERE operation_id=?",
		opID, r.Step, nullIfEmpty(r.NodeID), r.OK, r.Noop, r.StateProven,
		nullIfEmpty(r.Error), nullIfEmpty(r.Detail), opID)
	if err != nil {
		return fmt.Errorf("operation_step: %w", err)
	}
	return nil
}

// Steps returns the operation's recorded steps in order.
func (s Store) Steps(ctx context.Context, opID string) ([]StepResult, error) {
	rows, err := s.DB.QueryContext(ctx, "SELECT step, COALESCE(node_id,''), COALESCE(ok,0), noop, state_proven, "+
		"COALESCE(error,''), COALESCE(detail,''), COALESCE(DATE_FORMAT(at,'%H:%i:%s'),'') FROM "+s.DBName+
		".ha_operation_steps WHERE operation_id=? ORDER BY seq", opID)
	if err != nil {
		return nil, fmt.Errorf("operation_steps: %w", err)
	}
	defer rows.Close()
	out := []StepResult{}
	for rows.Next() {
		var r StepResult
		if err := rows.Scan(&r.Step, &r.NodeID, &r.OK, &r.Noop, &r.StateProven, &r.Error, &r.Detail, &r.At); err != nil {
			return nil, fmt.Errorf("operation_steps: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Done reports whether a step with this name has already succeeded.
func (s Store) Done(steps []StepResult, name string) bool {
	for _, st := range steps {
		if st.Step == name && st.OK {
			return true
		}
	}
	return false
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// Resume puts an interrupted operation back to work.
//
// It is not a restart: the step journal is kept, so the state machine continues where it stopped, once
// the cause of failure has been fixed.
//
// Only this node's operation, and only in its own epoch: if the pair has moved on, the old switchover's
// premises no longer hold.
func (s Store) Resume(ctx context.Context, id, nodeID string, epoch int64) error {
	op, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	switch {
	case op == nil:
		return fmt.Errorf("there is no operation %s", id)
	case op.Active():
		return nil // already running
	case op.State == StateCompleted:
		return fmt.Errorf("operation %s is already finished", id)
	case op.SourceNode != nodeID && op.TargetNode != nodeID:
		return fmt.Errorf("operation %s does not belong to this node", id)
	case op.Epoch != epoch && op.Epoch != epoch+1:
		// Two cases are allowed: the node already accepted the operation's epoch (past the point of no
		// return), or the operation targets the NEXT epoch and has not reached it yet.
		return fmt.Errorf("operation is at epoch %d, the node at %d — its premises no longer hold",
			op.Epoch, epoch)
	}
	other, err := s.Current(ctx)
	if err != nil {
		return err
	}
	if other != nil && other.ID != id {
		return fmt.Errorf("operation_busy: %s is already running", other.ID)
	}
	return s.SetState(ctx, id, StateRunning, "resumed by the operator")
}

// AcceptRelayLossFor records the operator's consent to continue even if the relay-log drain cannot be
// proven. This DELIBERATELY LOSES received but unapplied transactions.
//
// Consent is given to a specific operation, with its failure cause in view, and continues it instead of
// spending a new epoch. The operation keeps the trace of who agreed.
func (s Store) AcceptRelayLossFor(ctx context.Context, id, operator string) error {
	op, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	if op == nil {
		return fmt.Errorf("there is no operation %s", id)
	}
	if op.Kind != KindEmergency {
		return fmt.Errorf("accepting relay-tail loss only makes sense for an emergency promote")
	}
	_, err = s.DB.ExecContext(ctx, "UPDATE "+s.DBName+".ha_operations SET accept_relay_loss=1, "+
		"reason=CONCAT(COALESCE(reason,''), ?) WHERE operation_id=?",
		fmt.Sprintf("; %s agreed to continue with relay-tail loss", operator), id)
	if err != nil {
		return fmt.Errorf("operation_accept_relay_loss: %w", err)
	}
	return nil
}

// List returns the running operation and the most recent finished ones.
func (s Store) List(ctx context.Context, limit int) ([]Operation, error) {
	rows, err := s.DB.QueryContext(ctx, "SELECT operation_id, kind, state, epoch, COALESCE(source_node,''), "+
		"COALESCE(target_node,''), COALESCE(requested_by,''), COALESCE(reason,''), COALESCE(ack,''), "+
		"accept_relay_loss, started_at FROM "+s.DBName+".ha_operations ORDER BY started_at DESC LIMIT ?", limit)
	if err != nil {
		return nil, fmt.Errorf("operation_list: %w", err)
	}
	defer rows.Close()
	// An empty slice, not nil: nil encodes as JSON null, and the panel expects an array.
	out := []Operation{}
	for rows.Next() {
		var op Operation
		if err := rows.Scan(&op.ID, &op.Kind, &op.State, &op.Epoch, &op.SourceNode, &op.TargetNode,
			&op.RequestedBy, &op.Reason, &op.Ack, &op.AcceptRelayLoss, &op.StartedAt); err != nil {
			return nil, fmt.Errorf("operation_list: %w", err)
		}
		out = append(out, op)
	}
	return out, rows.Err()
}
