package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// Mutator issues agent commands that CHANGE node state.
//
// It is a separate type so observing code holding a `Client` cannot mutate; there is no public `Run(cmd)`
// for the same reason.
//
// Every mutation requires an operation_id and cluster_epoch from the caller. The client never fills in the
// "current" epoch or invents an operation id: a default would run the action in an epoch nobody agreed on.
type Mutator struct {
	Client Client
}

// Mutation deadlines. `status` takes a fraction of a second, while `rejoin_replica` normally runs up to a
// minute (CHANGE MASTER + proving IO/SQL=Yes).
//
// The CLIENT WAITS LONGER THAN THE EXECUTOR. Otherwise the client drops the connection while the agent is
// still working normally, and an outcome that is actually determined becomes unknown, the worst kind of
// uncertainty in HA. The values are the ones proven in production.
const (
	mutationSlack        = 10 * time.Second
	executorDefault      = 15 * time.Second  // ha.agent.timeout
	executorRejoin       = 60 * time.Second  // rejoin_replica: CHANGE MASTER + proving IO/SQL=Yes
	executorEmergency    = 90 * time.Second  // relay-log drain + promote tail
	executorReseed       = 600 * time.Second // full dump from the peer
	MutationTimeout      = executorDefault + mutationSlack
	RejoinReplicaTimeout = executorRejoin + mutationSlack
	EmergencyTimeout     = executorEmergency + mutationSlack
	ReseedTimeout        = executorReseed + mutationSlack
)

func deadlineFor(cmd string) time.Duration {
	switch cmd {
	case "rejoin_replica":
		return RejoinReplicaTimeout
	case "emergency_promote", "drain_relay":
		return EmergencyTimeout
	case "reseed_replica":
		return ReseedTimeout
	}
	return MutationTimeout
}

// Op is the mandatory mutation context.
type Op struct {
	OperationID  string
	ClusterEpoch int64
	// NoHAConfig means HA is NOT configured on the node, so no epoch exists.
	//
	// The epoch belongs to the PAIR and proves a command is not from a past role lifetime; without HA there
	// is nothing to prove. Requiring it anyway locked a node after pair teardown: the plan ("become writable")
	// was right but could not run. The agent already accepts epoch 0 (`reset_pair_state` zeroes the durable
	// max_epoch on teardown; only negative is rejected).
	//
	// The flag is EXPLICIT rather than "epoch happened to be 0": "HA not configured" and "epoch unreadable"
	// both yield 0 but mean opposite things. Only the caller knows which; otherwise a failed safety-store read
	// on a node WITH HA would unlock epoch-less mutations. Peer trust is unaffected (see observe.HANotConfigured).
	NoHAConfig bool
}

func (o Op) validate() error {
	if o.OperationID == "" {
		return &Error{Code: CodeBadRequest, Err: fmt.Errorf("mutation without operation_id: a retry would be a new action")}
	}
	if o.ClusterEpoch < 0 || (o.ClusterEpoch == 0 && !o.NoHAConfig) {
		return &Error{Code: CodeBadRequest, Err: fmt.Errorf("mutation without cluster_epoch")}
	}
	return nil
}

// CodeBadRequest means the caller omitted mandatory context; our own error, raised before any I/O.
const CodeBadRequest = "agent_bad_request"

// CommandResult is the mutation outcome as reported by the agent.
//
// `OK=false` is NOT a link error but a typed command result: the agent answered and explained. It must not be
// merged with a dropped connection, where the node state is unknown.
type CommandResult struct {
	OK   bool `json:"ok"`
	Noop bool `json:"noop"` // already done earlier (idempotent retry)
	// Error is the typed refusal code, Message the agent's explanation. Keep both: without the message the
	// operator sees "reseed_dump_failed" with no hint where to look.
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
	// Status is the node state AFTER the action, as the agent sees it.
	Status json.RawMessage `json:"status,omitempty"`
	// StateProven means the agent confirmed the node state IN THIS reply.
	//
	// It is normally false on a durable retry (`ok=1, noop=1`): the agent answers from its done-set without
	// touching the node. That proves (operation_id, cmd) succeeded before, NOT that the node has not changed
	// since. The same holds for any refusal (`busy`, `stale_epoch`).
	// Rule for the executor: StateProven=false → take a fresh observation before the next step.
	StateProven bool `json:"state_proven"`
}

func (m Mutator) Promote(ctx context.Context, op Op) (CommandResult, error) {
	return m.run(ctx, "promote", op, "")
}
func (m Mutator) Demote(ctx context.Context, op Op) (CommandResult, error) {
	return m.run(ctx, "demote", op, "")
}
func (m Mutator) EnableNotifier(ctx context.Context, op Op) (CommandResult, error) {
	return m.run(ctx, "enable_notifier", op, "")
}
func (m Mutator) DisableNotifier(ctx context.Context, op Op) (CommandResult, error) {
	return m.run(ctx, "disable_notifier", op, "")
}

// AnnouncePanel publishes the service address (WithdrawPanel withdraws it). Address and device come from the
// active revision; empty means the node manages the address itself (local agent config or external provider).
func (m Mutator) AnnouncePanel(ctx context.Context, op Op, address, device, provider string) (CommandResult, error) {
	return m.runPub(ctx, "announce_panel", op, address, device, provider)
}
func (m Mutator) WithdrawPanel(ctx context.Context, op Op, address, device, provider string) (CommandResult, error) {
	return m.runPub(ctx, "withdraw_panel", op, address, device, provider)
}

// StopReplication and ReleasePublication tear down the pair. Data is untouched: only the link between nodes
// and the shared service address go, leaving each node a plain standalone server.
func (m Mutator) StopReplication(ctx context.Context, op Op) (CommandResult, error) {
	return m.run(ctx, "stop_replication", op, "")
}
func (m Mutator) ReleasePublication(ctx context.Context, op Op, address, device string) (CommandResult, error) {
	return m.runPub(ctx, "release_publication", op, address, device, "")
}

// RejoinReplica attaches replication to primary, which is mandatory: replicating from "whoever" is a way to
// replicate from the wrong node.
func (m Mutator) RejoinReplica(ctx context.Context, op Op, primary string, seedFromBinlog bool) (CommandResult, error) {
	if primary == "" {
		return CommandResult{}, &Error{Code: CodeBadRequest, Err: fmt.Errorf("rejoin_replica without a primary")}
	}
	return m.run(ctx, "rejoin_replica", op, primary, seedFromBinlog)
}

// EmergencyPromote drains the relay log and promotes under ONE agent lock.
//
// acceptRelayLoss is the operator's explicit decision to proceed when the drain cannot be proven (source dead,
// its position unreachable). That is DATA LOSS, so the flag has no default and is logged as a human decision.
func (m Mutator) EmergencyPromote(ctx context.Context, op Op, acceptRelayLoss bool) (CommandResult, error) {
	req := map[string]any{"cmd": "emergency_promote", "operation_id": op.OperationID,
		"cluster_epoch": op.ClusterEpoch, "accept_relay_loss": acceptRelayLoss}
	return m.send(ctx, "emergency_promote", op, req)
}

// ReseedReplica fully reseeds the node from primary; needed when GTID histories diverged and incremental
// rejoin is impossible.
func (m Mutator) ReseedReplica(ctx context.Context, op Op, primary string) (CommandResult, error) {
	if primary == "" {
		return CommandResult{}, &Error{Code: CodeBadRequest, Err: fmt.Errorf("reseed_replica without a primary")}
	}
	return m.run(ctx, "reseed_replica", op, primary)
}

func (m Mutator) run(ctx context.Context, cmd string, op Op, primary string, seedFromBinlog ...bool) (CommandResult, error) {
	if err := op.validate(); err != nil {
		return CommandResult{}, err
	}
	req := map[string]any{"cmd": cmd, "operation_id": op.OperationID, "cluster_epoch": op.ClusterEpoch}
	if primary != "" {
		req["primary"] = primary
	}
	if len(seedFromBinlog) > 0 && seedFromBinlog[0] {
		req["seed_from_binlog"] = true
	}
	return m.send(ctx, cmd, op, req)
}

// runPub sends the address only together with its device: the agent cannot bring up an address without one.
func (m Mutator) runPub(ctx context.Context, cmd string, op Op, address, device, provider string) (CommandResult, error) {
	if err := op.validate(); err != nil {
		return CommandResult{}, err
	}
	req := map[string]any{"cmd": cmd, "operation_id": op.OperationID, "cluster_epoch": op.ClusterEpoch}
	if address != "" && device != "" {
		req["publication_address"], req["publication_device"] = address, device
	}
	// The provider is sent independently: the agent needs it even when the address comes from its local file.
	if provider != "" {
		req["publication_provider"] = provider
	}
	return m.send(ctx, cmd, op, req)
}

func (m Mutator) send(ctx context.Context, cmd string, op Op, req map[string]any) (CommandResult, error) {
	if err := op.validate(); err != nil {
		return CommandResult{}, err
	}
	var raw struct {
		OK      *FlexBool       `json:"ok"`
		Noop    *FlexBool       `json:"noop"`
		Error   string          `json:"error,omitempty"`
		Message string          `json:"message,omitempty"`
		Status  json.RawMessage `json:"status,omitempty"`
	}
	// The observation timeout (5s) would cut off a normal long-running mutation.
	c := m.Client
	if c.Timeout < deadlineFor(cmd) {
		c.Timeout = deadlineFor(cmd)
	}
	if err := c.send(ctx, req, &raw); err != nil {
		return CommandResult{}, err
	}
	if raw.OK == nil {
		return CommandResult{}, &Error{Code: CodeMalformed, Err: fmt.Errorf("the response has no ok field")}
	}
	res := CommandResult{OK: raw.OK.Bool(), Noop: raw.Noop.Bool(), Error: raw.Error, Message: raw.Message,
		Status: raw.Status, StateProven: len(raw.Status) > 0}
	if !res.OK && res.Error == "" {
		res.Error = CodeCommand // a refusal without a reason is still a refusal
	}
	// A non-retry success must carry state, or we would count the action done with no confirmation.
	// A retry success (`noop=1`) legitimately carries none: the agent answers from its done-set.
	if res.OK && !res.Noop && !res.StateProven {
		return CommandResult{}, &Error{Code: CodeMalformed, Err: fmt.Errorf("successful mutation without status")}
	}
	return res, nil
}

// DropAddress removes a specific address from an interface.
//
// No operation context is required: this cleans up a leftover of a PAST pair configuration rather than
// changing a role, so no epoch applies, and a retry is harmless (noop if the address is already gone).
func (m Mutator) DropAddress(ctx context.Context, address, device string) (CommandResult, error) {
	if address == "" || device == "" {
		return CommandResult{}, &Error{Code: CodeBadRequest, Err: fmt.Errorf("drop_address without an address")}
	}
	return PeerKeys{Client: m.Client}.DropAddress(ctx, address, device)
}
