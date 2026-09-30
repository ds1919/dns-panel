package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"dnspanel/dns-ha/internal/agent"
	"dnspanel/dns-ha/internal/config"
	"dnspanel/dns-ha/internal/execute"
	"dnspanel/dns-ha/internal/observe"
	"dnspanel/dns-ha/internal/ops"
	"dnspanel/dns-ha/internal/peer"
	"dnspanel/dns-ha/internal/safety"
	"dnspanel/dns-ha/internal/store"
)

// openOps opens the operation journal in the local database.
func openOps(cfg config.Config) (*ops.Store, error) {
	dsn, err := store.WriteDSN(cfg.Database.Socket)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(4)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	return &ops.Store{DB: db, DBName: cfg.Database.Database}, nil
}

// currentOperation returns THIS cycle's running operation. Asked ONCE and before the readiness decision: a node
// must not declare itself ready and then start a switchover in the same cycle. "Operation first, then probe,
// then execute that same operation" is all that is needed; an operation that appears later starts next cycle.
func currentOperation(ctx context.Context, st *ops.Store) (*ops.Operation, error) {
	if st == nil {
		return nil, nil
	}
	return st.Current(ctx)
}

// runOperationsAndConverge is the only place where the manager CHANGES anything.
//
// The order is the point: the running operation first, and only without one, normal convergence. While the pair
// is switching over, the intermediate state (old node no longer active, new one not up yet) is the operation's
// normal course, not a divergence to "fix": converging at that moment would fight the state machine over the
// same knobs.
func runOperationsAndConverge(ctx context.Context, cfg config.Config, st *ops.Store, exec *execute.Executor,
	snap *snapshot, v *report, obs observe.Observation, client *peer.ClientConfig,
	cur *ops.Operation) execute.Outcome {

	if cur != nil {
		v.Execution.Operation = cur.ID
		switch {
		case cur.SourceNode == cfg.Node && cur.Kind == ops.KindEmergency:
			// Emergency promotion is driven by the surviving node. There is no peer to talk to by definition: the
			// basis is the operator's typed confirmation recorded in the operation itself.
			em := &ops.Emergency{NodeID: cfg.Node, Ops: *st, Safety: safety.NewStore(config.SafetyPath),
				Mutator: agent.Mutator{Client: agent.Client{Socket: config.AgentSocket, Timeout: config.AgentTimeout}},
				Observe: func(c context.Context) observe.Observation { return observe.Collect(c, cfg, client) },
				Ack:     cur.Ack, Operator: cur.RequestedBy, AcceptRelayLoss: cur.AcceptRelayLoss}
			if err := em.Run(ctx, *cur); err != nil {
				fmt.Fprintf(os.Stderr, "dns-ha-manager: operation %s: %v\n", cur.ID, err)
				return execute.Outcome{Status: execute.OutcomeFailed, Reason: err.Error()}
			}
			return execute.Outcome{Status: execute.OutcomeDone, Reason: "emergency promotion finished"}
		case cur.SourceNode == cfg.Node && cur.Kind == ops.KindReseed:
			if client == nil {
				return execute.Outcome{Status: execute.OutcomeBlocked, Reason: "no channel to the other node"}
			}
			rs := &ops.Reseed{NodeID: cfg.Node, Ops: *st, Safety: safety.NewStore(config.SafetyPath),
				Mutator: agent.Mutator{Client: agent.Client{Socket: config.AgentSocket, Timeout: config.AgentTimeout}},
				Peer:    client, Observe: func(c context.Context) observe.Observation { return observe.Collect(c, cfg, client) },
				Operator: cur.RequestedBy}
			if err := rs.Run(ctx, *cur); err != nil {
				fmt.Fprintf(os.Stderr, "dns-ha-manager: operation %s: %v\n", cur.ID, err)
				return execute.Outcome{Status: execute.OutcomeFailed, Reason: err.Error()}
			}
			return execute.Outcome{Status: execute.OutcomeDone, Reason: "reseed finished"}
		case cur.SourceNode == cfg.Node && cur.Kind == ops.KindDismantle:
			// Dismantling is driven by ACTIVE: it sends the peer ONE command (become standalone and remove its
			// pair records), then puts itself in order, checks both sides and removes its own records.
			//
			// The peer channel is required only while the peer still has something to do. Once it has forgotten the
			// pair there is nothing to ask and no way to ask, only local cleanup remains, and requiring the channel
			// for it would deadlock dismantling exactly where the peer is no longer needed.
			if client == nil && !dismantlePeerDone(ctx, st, cur.ID) {
				return execute.Outcome{Status: execute.OutcomeBlocked, Reason: "no channel to the other node"}
			}
			dis := &ops.Dismantle{NodeID: cfg.Node, Ops: *st,
				Mutator: agent.Mutator{Client: agent.Client{Socket: config.AgentSocket, Timeout: config.AgentTimeout}},
				Peer:    client,
				Observe: func(c context.Context) observe.Observation { return observe.Collect(c, cfg, client) },
				Forget:  forgetPairLocally(cfg, pairSvcRef),
				Failsafe: func(c context.Context) (agent.CommandResult, error) {
					return agent.PeerKeys{Client: agent.Client{Socket: config.AgentSocket,
						Timeout: config.AgentTimeout}}.DisableFailsafe(c)
				},
				AwaitTimeout: 60 * time.Second} // no Wait: waiting goes through the context and is cancelled with the operation
			if err := dis.Run(ctx, *cur); err != nil {
				fmt.Fprintf(os.Stderr, "dns-ha-manager: operation %s: %v\n", cur.ID, err)
				return execute.Outcome{Status: execute.OutcomeFailed, Reason: err.Error()}
			}
			return execute.Outcome{Status: execute.OutcomeDone, Reason: "the pair was dismantled"}
		case cur.SourceNode == cfg.Node && cur.Kind == ops.KindPlanned:
			// We hand over the role, so we drive the operation. It is resumable: after a daemon restart it continues
			// from the step it reached.
			if client == nil {
				return execute.Outcome{Status: execute.OutcomeBlocked, Reason: "no channel to the other node"}
			}
			sw := &ops.Switchover{NodeID: cfg.Node, Ops: *st, Safety: safety.NewStore(config.SafetyPath),
				Mutator: agent.Mutator{Client: agent.Client{Socket: config.AgentSocket, Timeout: config.AgentTimeout}},
				Peer:    client, Observe: func(c context.Context) observe.Observation { return observe.Collect(c, cfg, client) }}
			if err := sw.Run(ctx, *cur); err != nil {
				fmt.Fprintf(os.Stderr, "dns-ha-manager: operation %s: %v\n", cur.ID, err)
				return execute.Outcome{Status: execute.OutcomeFailed, Reason: err.Error()}
			}
			return execute.Outcome{Status: execute.OutcomeDone, Reason: "switchover finished"}
		case cur.TargetNode == cfg.Node:
			// We take over the role. The right was already granted by the certificate; the node then brings itself
			// to a working state through NORMAL convergence: the planner sees the right and the missing services and
			// says what to bring up. Skipping it here would be a closed loop: the operation waits for the node to
			// become active, and nothing makes it active.
			out := converge(ctx, exec, v, obs)
			if err := st.FinishAccepted(ctx, observe.Collect(ctx, cfg, client)); err != nil {
				return execute.Outcome{Status: execute.OutcomeBlocked, Reason: err.Error()}
			}
			return out
		}
		return execute.Outcome{Status: execute.OutcomeNothingToDo, Reason: "operation in progress: " + cur.ID}
	}

	return converge(ctx, exec, v, obs)
}

// converge is normal convergence: execute the planner's plan.
//
// The action ID is NEW on every attempt: the agent remembers successful (operation_id, command) pairs, and a
// retry with an old ID would return a noop from the journal without doing anything, while the node's state may
// have changed since the last attempt.
func converge(ctx context.Context, exec *execute.Executor, v *report, obs observe.Observation) execute.Outcome {
	if v.WouldExecute.Empty() {
		return exec.Execute(ctx, v.WouldExecute, agent.Op{})
	}
	// The epoch lives in the safety store, which exists only for a pair: after dismantling it is gone and
	// there is nothing to read. That is not "could not read" but "there is no epoch", and we must tell the
	// executor so, since nobody else here can tell the two apart (see agent.Op.NoHAConfig). Without this a
	// node with HA off would stay read-only forever: the plan tells it to write, and the mutation gate
	// demands proof from a pair that no longer exists.
	epoch := int64(0)
	if obs.Safety.MaxSeenEpoch != nil {
		epoch = *obs.Safety.MaxSeenEpoch
	}
	op := agent.Op{OperationID: fmt.Sprintf("conv-%d-%d", epoch, time.Now().UnixNano()),
		ClusterEpoch: epoch, NoHAConfig: obs.HANotConfigured()}
	return exec.Execute(ctx, v.WouldExecute, op)
}

// createSwitchover creates a planned switchover. It runs on the node GIVING UP the role: only it can prove it
// has stopped accepting writes.
//
// The command only creates the INTENT; the manager loop executes it. The panel works the same way: it does not
// poke nodes directly, it creates an operation.
func createSwitchover(cfg config.Config, target string, by string) int {
	res, err := intentSwitchover(cfg, target, by)
	if err != nil {
		return fail(err)
	}
	emit(res)
	return 0
}

// intentSwitchover creates the intent to switch roles. The ONLY path: both CLI and panel call it, so the checks
// cannot diverge between interfaces.
func intentSwitchover(cfg config.Config, target string, by string) (map[string]any, error) {
	ctx := context.Background()
	v, _, _, obs := observeOnce(ctx, cfg, nil)
	if v.Role != "active" {
		return nil, fmt.Errorf("a switchover is started by the ACTIVE node; this one is %s", v.Role)
	}
	if obs.Safety.MaxSeenEpoch == nil {
		return nil, fmt.Errorf("epoch is unknown — the safety file was not read")
	}
	if target == "" {
		target = obs.Config.PeerNodeID // in a pair the target is unambiguous: the peer
	}
	if target == "" || target == cfg.Node {
		return nil, fmt.Errorf("the switchover target is not defined")
	}
	st, err := openOps(cfg)
	if err != nil {
		return nil, err
	}
	defer st.DB.Close()

	epoch := *obs.Safety.MaxSeenEpoch + 1
	id, err := st.FreeID(ctx, fmt.Sprintf("sw-%s-%d", cfg.Node, epoch))
	if err != nil {
		return nil, err
	}
	op := ops.Operation{
		ID:          id,
		Kind:        ops.KindPlanned,
		Epoch:       epoch,
		SourceNode:  cfg.Node,
		TargetNode:  target,
		RequestedBy: by,
	}
	if err := st.Create(ctx, op); err != nil {
		return nil, err
	}
	return map[string]any{"operation_id": op.ID, "kind": op.Kind, "epoch": epoch,
		"source": op.SourceNode, "target": op.TargetNode, "state": "created; the manager is running it"}, nil
}

// dismantlePeerDone reports that the peer has done its part of dismantling and is no longer needed.
func dismantlePeerDone(ctx context.Context, st *ops.Store, opID string) bool {
	steps, err := st.Steps(ctx, opID)
	if err != nil {
		return false
	}
	return st.Done(steps, ops.StepDismantleVerify)
}

// listOperations returns the current operation and history. The panel shows it as is: the journal in dns_ha is
// the source of truth about operations.
func listOperations(cfg config.Config, limit int) (any, error) {
	if limit <= 0 || limit > 200 {
		limit = 20
	}
	st, err := openOps(cfg)
	if err != nil {
		return nil, err
	}
	defer st.DB.Close()
	return st.List(context.Background(), limit)
}

// getOperation returns an operation and its steps. Steps live ONLY on the node that executed the operation:
// local dns_ha is not replicated. So another node's operation journal is asked from the peer rather than faked
// as empty; otherwise after the service address moves the human sees a console without a single line of the
// switchover they just started.
func getOperation(cfg config.Config, id string, peers *peerRef) (any, error) {
	st, err := openOps(cfg)
	if err != nil {
		return nil, err
	}
	defer st.DB.Close()
	ctx := context.Background()
	op, err := st.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	var steps []ops.StepResult
	if op != nil {
		if steps, err = st.Steps(ctx, id); err != nil {
			return nil, err
		}
	}
	// The peer ran the operation, so fetch the journal from it. Our copy of the operation row stays: it
	// describes what THIS node did.
	return journalOf(cfg.Node, id, op, steps, func(opID string) (*journalView, error) {
		return peerJournal(peers, opID)
	})
}

// journalOf answers "show the operation" given that the PEER may have run it.
//
// The role moves, but the journal stays with whoever executed the steps: both nodes have the operation row,
// only the executor has the steps. So a question about the other node's operation goes over the peer channel.
// A separate function so this rule is tested on two real nodes, not only live.
func journalOf(node, id string, op *ops.Operation, steps []ops.StepResult,
	remote func(string) (*journalView, error)) (any, error) {

	journalErr := ""
	if op == nil || (op.SourceNode != "" && op.SourceNode != node && len(steps) == 0) {
		got, rerr := remote(id)
		switch {
		case rerr != nil:
			// Being unable to ask the peer is NOT "the journal is empty". An empty list without explanation reads
			// as "there were no steps", and that is exactly how an operation with ten steps once looked on screen.
			// The reply stays successful (the operation row is ours), but the failure travels with it.
			if op == nil {
				return nil, fmt.Errorf("operation %s: %w", id, rerr)
			}
			journalErr = rerr.Error()
		case got != nil:
			if op == nil {
				op = got.Operation
			}
			if len(got.Steps) > 0 {
				steps = got.Steps
			}
		case op == nil:
			return nil, fmt.Errorf("operation %s does not exist", id)
		}
	}
	if op == nil {
		return nil, fmt.Errorf("operation %s does not exist", id)
	}
	if steps == nil {
		steps = []ops.StepResult{}
	}
	out := map[string]any{"operation": op, "steps": steps}
	if journalErr != "" {
		out["journal_error"] = journalErr
	}
	return out, nil
}

// journalView is what the executing node returns: the operation and its steps.
type journalView struct {
	Operation *ops.Operation   `json:"operation"`
	Steps     []ops.StepResult `json:"steps"`
}

func peerJournal(peers *peerRef, id string) (*journalView, error) {
	if peers == nil {
		return nil, fmt.Errorf("no peer channel")
	}
	client := peers.get()
	if client == nil {
		return nil, fmt.Errorf("no peer channel")
	}
	// One-off informational CLI request: no operation is waiting on it, and it bounds its own timeout.
	res, err := peer.Call(context.Background(), *client, peer.CmdOperationJournal, peer.OperationJournalPayload{OperationID: id})
	if err != nil {
		return nil, err
	}
	if !res.OK || res.Response == nil {
		return nil, fmt.Errorf("%s", res.Code)
	}
	var out journalView
	if err := peer.DecodeResponsePayload(res.Response, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// localJournal returns THIS node's operation journal for the peer. Read-only.
func localJournal(cfg config.Config) func(string) (json.RawMessage, error) {
	return func(id string) (json.RawMessage, error) {
		st, err := openOps(cfg)
		if err != nil {
			return nil, err
		}
		defer st.DB.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		op, err := st.Get(ctx, id)
		if err != nil {
			return nil, err
		}
		steps, err := st.Steps(ctx, id)
		if err != nil {
			return nil, err
		}
		return json.Marshal(journalView{Operation: op, Steps: steps})
	}
}

// showOperation prints an operation's state and steps.
func showOperation(cfg config.Config, id string) int {
	ctx := context.Background()
	st, err := openOps(cfg)
	if err != nil {
		return fail(err)
	}
	defer st.DB.Close()

	var op *ops.Operation
	if id == "" {
		op, err = st.Current(ctx)
	} else {
		op, err = st.Get(ctx, id)
	}
	if err != nil {
		return fail(err)
	}
	if op == nil {
		emit(map[string]any{"operation": nil})
		return 0
	}
	steps, err := st.Steps(ctx, op.ID)
	if err != nil {
		return fail(err)
	}
	emit(map[string]any{"operation_id": op.ID, "kind": op.Kind, "state": op.State, "epoch": op.Epoch,
		"source": op.SourceNode, "target": op.TargetNode, "reason": op.Reason, "steps": steps})
	return 0
}

// resumeOperation puts an interrupted operation back to work: the cause is fixed, the manager must finish it.
func resumeOperation(cfg config.Config, id string, acceptRelayLoss bool, operator string) int {
	res, err := intentResume(cfg, id, acceptRelayLoss, operator)
	if err != nil {
		return fail(err)
	}
	emit(res)
	return 0
}

// intentResume puts an interrupted operation back to work.
func intentResume(cfg config.Config, id string, acceptRelayLoss bool, operator string) (map[string]any, error) {
	ctx := context.Background()
	_, _, _, obs := observeOnce(ctx, cfg, nil)
	if obs.Safety.MaxSeenEpoch == nil {
		return nil, fmt.Errorf("epoch is unknown — the safety file was not read")
	}
	st, err := openOps(cfg)
	if err != nil {
		return nil, err
	}
	defer st.DB.Close()

	// Dismantling is never resumed, by ANY path.
	//
	// Its journal keeps a completed drain_gtid: proof that the peer applied everything written up to that point.
	// Resuming would skip that step while the node accepts writes again, so the proof is stale and dismantling
	// would detach a lagging peer. The ban lives here, not in the browser: the manager is the common gate for UI,
	// API and CLI.
	if op, gerr := st.Get(ctx, id); gerr == nil && op != nil && op.Kind == ops.KindDismantle {
		return nil, fmt.Errorf("a dismantle is not resumed; start a new one")
	}

	if acceptRelayLoss {
		// Consent is recorded BEFORE resuming, or the loop could pick the operation up with the old basis.
		if err := st.AcceptRelayLossFor(ctx, id, operator); err != nil {
			return nil, err
		}
	}
	if err := st.Resume(ctx, id, cfg.Node, *obs.Safety.MaxSeenEpoch); err != nil {
		return nil, err
	}
	return map[string]any{"operation_id": id, "accept_relay_loss": acceptRelayLoss,
		"state": "resumed; the manager is continuing it"}, nil
}

// createEmergency creates an emergency promotion. It runs on the SURVIVING node.
//
// There is no automatic emergency promotion: a two-node pair cannot tell "peer died" from "network split", and
// in the latter case automation would create a second active node with diverging data. So a human and their
// typed confirmation that the former ACTIVE is really down are required.
func createEmergency(cfg config.Config, ack, operator string, acceptRelayLoss bool) int {
	res, err := intentEmergency(cfg, ack, operator, acceptRelayLoss)
	if err != nil {
		return fail(err)
	}
	emit(res)
	return 0
}

// intentEmergency is the intent to emergency-promote THIS node. Same requirements as the CLI: the operator's
// typed confirmation and name. The panel checks permissions, the manager checks justification.
func intentEmergency(cfg config.Config, ack, operator string, acceptRelayLoss bool) (map[string]any, error) {
	ctx := context.Background()
	// The peer is observed EXPLICITLY: the "it is alive and serving" refusal is the key protection against
	// turning an emergency into deliberately creating a second active node, and must not be taken blindly.
	client, _ := peerClientOnly(cfg)
	if !ops.ValidAck(ack) {
		return nil, fmt.Errorf("an acknowledgement is required: %s | %s | %s",
			ops.AckDatabaseStopped, ops.AckHostDown, ops.AckIsolated)
	}
	if operator == "" {
		return nil, fmt.Errorf("an emergency promotion must name its author")
	}
	_, _, _, obs := observeOnce(ctx, cfg, client)
	if obs.Safety.MaxSeenEpoch == nil {
		return nil, fmt.Errorf("epoch is unknown — the safety file was not read")
	}
	target := obs.Config.PeerNodeID // fence the former ACTIVE
	if target == "" {
		return nil, fmt.Errorf("the peer is not defined by the configuration")
	}
	st, err := openOps(cfg)
	if err != nil {
		return nil, err
	}
	defer st.DB.Close()

	epoch := *obs.Safety.MaxSeenEpoch + 1
	emID, err := st.FreeID(ctx, fmt.Sprintf("em-%s-%d", cfg.Node, epoch))
	if err != nil {
		return nil, err
	}
	op := ops.Operation{ID: emID, Kind: ops.KindEmergency, Epoch: epoch,
		SourceNode: cfg.Node, TargetNode: target, RequestedBy: operator,
		Ack: ack, AcceptRelayLoss: acceptRelayLoss}
	if err := st.Create(ctx, op); err != nil {
		return nil, err
	}
	return map[string]any{"operation_id": op.ID, "kind": op.Kind, "epoch": epoch, "fenced_node": target,
		"ack": ack, "operator": operator, "accept_relay_loss": acceptRelayLoss,
		"state": "created; the manager is running it"}, nil
}

// createReseed creates a reseed. It runs on the node being repaired.
//
// The epoch is NOT incremented: the right to be active does not change, the node is repaired within the current epoch.
func createReseed(cfg config.Config, operator string) int {
	res, err := intentReseed(cfg, operator)
	if err != nil {
		return fail(err)
	}
	emit(res)
	return 0
}

// intentReseed is the intent to reseed THIS node from the current ACTIVE.
func intentReseed(cfg config.Config, operator string) (map[string]any, error) {
	ctx := context.Background()
	// Observe TOGETHER with the peer: a reseed only makes sense relative to the current source, and its
	// epoch is the one the operation must run in. Without the peer channel we would decide blindly.
	client, err := peerClientOnly(cfg)
	if err != nil {
		return nil, err
	}
	_, _, _, obs := observeOnce(ctx, cfg, client)
	if !obs.Peer.Reachable || obs.Peer.MaxSeenEpoch == nil {
		return nil, fmt.Errorf("the source is not observed — there is nothing to reseed from")
	}
	st, err2 := openOps(cfg)
	if err2 != nil {
		return nil, err2
	}
	defer st.DB.Close()

	epoch := *obs.Peer.MaxSeenEpoch
	rsID, err := st.FreeID(ctx, fmt.Sprintf("rs-%s-%d", cfg.Node, epoch))
	if err != nil {
		return nil, err
	}
	op := ops.Operation{ID: rsID, Kind: ops.KindReseed, Epoch: epoch,
		SourceNode: cfg.Node, TargetNode: obs.Peer.NodeID, RequestedBy: operator}
	if err := st.Create(ctx, op); err != nil {
		return nil, err
	}
	return map[string]any{"operation_id": op.ID, "kind": op.Kind, "epoch": epoch,
		"source_of_data": obs.Peer.NodeID, "state": "created; the manager is running it"}, nil
}
