package main

import (
	"context"
	"fmt"
	"sync"
	"time"

	"dnspanel/dns-ha/internal/agent"
	"dnspanel/dns-ha/internal/config"
	"dnspanel/dns-ha/internal/identity"
	"dnspanel/dns-ha/internal/observe"
	"dnspanel/dns-ha/internal/ops"
	"dnspanel/dns-ha/internal/pairing"
	"dnspanel/dns-ha/internal/peer"
	"dnspanel/dns-ha/internal/safety"
	"dnspanel/dns-ha/internal/store"
)

// Daemon side of pair dismantling: the intent, the local "forget the pair", and the same on the peer's command.
//
// No data is touched anywhere: dismantling removes the link between nodes (replication, shared address,
// trust), while zones, records and users stay on both nodes as they were at drain time.

// pairSvcRef is this daemon's pairing service. Dismantling does not touch it (trust is removed by a
// separate action), but the rest of the pairing flow needs the reference.
var pairSvcRef *pairing.Service

// intentDismantle creates a dismantle operation. As with other operations, this is only the intent: the
// manager loop executes it, so dismantling resumes after a daemon restart.
func intentDismantle(cfg config.Config, by string) (map[string]any, error) {
	ctx := context.Background()
	v, _, _, obs := observeOnce(ctx, cfg, nil)
	if v.Role != "active" {
		return nil, fmt.Errorf("the pair is dismantled from the ACTIVE node; this one is %s", v.Role)
	}
	peerNode := obs.Config.PeerNodeID
	if peerNode == "" {
		return nil, fmt.Errorf("there is no pair to dismantle")
	}
	epoch := int64(0)
	if obs.Safety.MaxSeenEpoch != nil {
		epoch = *obs.Safety.MaxSeenEpoch
	}
	st, err := openOps(cfg)
	if err != nil {
		return nil, err
	}
	defer st.DB.Close()

	// ID from a UUID, not the epoch: the epoch does not grow on dismantle, and a retry after an interrupted
	// attempt must be a new operation rather than hit a taken name.
	uid, err := identity.NewUUID()
	if err != nil {
		return nil, err
	}
	id, err := st.FreeID(ctx, "dis-"+uid)
	if err != nil {
		return nil, err
	}
	op := ops.Operation{ID: id, Kind: ops.KindDismantle, Epoch: epoch,
		SourceNode: cfg.Node, TargetNode: peerNode, RequestedBy: by}
	if err := st.Create(ctx, op); err != nil {
		return nil, err
	}
	return map[string]any{"operation_id": op.ID, "kind": op.Kind, "epoch": epoch,
		"source": op.SourceNode, "target": op.TargetNode, "state": "created; the manager is running it"}, nil
}

// forgetPairLocally removes everything that makes this node half of a pair.
//
// Trust and the channel key stay: dismantling a pair and dissolving trust are separate decisions with separate
// buttons. Node identity (`ha_identity`) and the panel master key stay too: the former is the PHYSICAL
// machine's UUID, the latter is needed by the data, which survives dismantling.
func forgetPairLocally(cfg config.Config, svc *pairing.Service) func(context.Context) error {
	return func(ctx context.Context) error {
		// Trust and the channel key are NOT touched: after dismantling, the two standalone servers still know each
		// other and can be paired again, e.g. in Anycast mode.
		_ = svc
		// Both durable stores forget the epoch: the manager's safety file and the agent state. A new pair starts at
		// epoch 1, and a node remembering epoch 9 would refuse it (manager: "this node has already seen epoch 9",
		// agent: stale_epoch on any mutation). A dismantle after which no new pair can be built is no dismantle.
		// Order: database records first, then the agent epoch, and the safety file LAST.
		//
		// While safety is intact the node passes the mutation gate, so a retried dismantle command (e.g. the reply to
		// the peer was lost) reaches the registry and gets the stored result. Removing safety first would let a
		// half-finished cleanup leave a node that answers retries with "not now" and can no longer finish.
		dsn, err := store.WriteDSN(cfg.Database.Socket)
		if err != nil {
			return err
		}
		if err := store.WipePair(ctx, dsn, cfg.Database.Database, 15*time.Second); err != nil {
			return err
		}
		keys := agent.PeerKeys{Client: agent.Client{Socket: config.AgentSocket, Timeout: config.AgentTimeout}}
		if res, err := keys.ResetPairState(ctx); err != nil {
			return fmt.Errorf("agent pair state: %w", err)
		} else if !res.OK {
			return fmt.Errorf("agent pair state: %s %s", res.Error, res.Message)
		}
		return safety.NewStore(config.SafetyPath).ResetPair()
	}
}

// cycleMu keeps the manager cycle (observe -> plan -> execute) and a peer-commanded dismantle from running
// concurrently. The dismantle arrives on the pair channel in its own goroutine, while the cycle executes a plan
// built from an observation taken BEFORE it. Without this, a STANDBY that just became standalone (writable,
// yes/yes) got "demote + withdraw_panel" from its own planner a second later, for a pair epoch that no longer
// existed, and stayed read-only with the PowerDNS source off (caught live 2026-09-25, conv-3 after dismantle).
var cycleMu sync.Mutex

// releasePairLocally makes this node a standalone server on the ACTIVE's command.
//
// The order is mandatory: detach from the source -> drop fail-safe -> allow writes -> serve zones again ->
// remove the pair address. Allowing writes before detaching would briefly give a writable node still applying
// someone else's changes.
func releasePairLocally(cfg config.Config) func(context.Context, peer.DismantlePayload) error {
	return func(ctx context.Context, in peer.DismantlePayload) error {
		cycleMu.Lock()
		defer cycleMu.Unlock()
		m := agent.Mutator{Client: agent.Client{Socket: config.AgentSocket, Timeout: config.AgentTimeout}}
		// Use our current epoch: dismantling does not change it, and agent mutations require one.
		obs := observe.Collect(ctx, cfg, nil)
		epoch := int64(1)
		if obs.Safety.MaxSeenEpoch != nil && *obs.Safety.MaxSeenEpoch > 0 {
			epoch = *obs.Safety.MaxSeenEpoch
		}
		op := agent.Op{OperationID: in.OperationID + ":release", ClusterEpoch: epoch}

		steps := []struct {
			what string
			run  func() (agent.CommandResult, error)
		}{
			{"stop_replication", func() (agent.CommandResult, error) { return m.StopReplication(ctx, op) }},
			{"disable_failsafe", func() (agent.CommandResult, error) {
				keys := agent.PeerKeys{Client: agent.Client{Socket: config.AgentSocket, Timeout: config.AgentTimeout}}
				return keys.DisableFailsafe(ctx)
			}},
			{"promote", func() (agent.CommandResult, error) { return m.Promote(ctx, op) }},
			{"enable_notifier", func() (agent.CommandResult, error) { return m.EnableNotifier(ctx, op) }},
			{"release_publication", func() (agent.CommandResult, error) {
				return m.ReleasePublication(ctx, op, in.Address, in.Device)
			}},
		}
		for _, s := range steps {
			res, err := s.run()
			if err != nil {
				return fmt.Errorf("%s: %w", s.what, err)
			}
			if !res.OK {
				msg := res.Error
				if res.Message != "" {
					msg += ": " + res.Message
				}
				return fmt.Errorf("%s: %s", s.what, msg)
			}
		}
		// In the same step the node removes ITS pair records: epoch, revisions, operation log.
		//
		// There is deliberately no separate "forget the pair" command. It would ask to delete the channel and confirm
		// the deletion over that same channel, and its handler would run inside the peer-request registry transaction,
		// wiping the very table that transaction holds a lock on. Trust between machines is not touched at all: that
		// has its own action.
		return forgetPairLocally(cfg, pairSvcRef)(ctx)
	}
}
