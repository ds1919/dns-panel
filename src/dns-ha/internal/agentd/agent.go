// Package agentd is the privileged (root) executor on a node.
//
// It does NOT decide when to switch over: the manager decides, and the agent safely and idempotently
// executes the EXACT command. Privilege separation is the whole point: the networked process must not be
// root, and the root process must not listen on the network.
//
// Contract guarantees (carried over from the Perl agent together with their reasons):
//   - a mutation requires operation_id and cluster_epoch; an epoch below the accepted one → stale_epoch;
//   - repeating the same (operation_id, cmd) pair → ok=1, noop=1 WITHOUT acting again;
//   - the highest accepted epoch is durable, with a directory fsync: it is the safety authority, and losing
//     it on a sudden reboot would mean agreeing to execute a command from an already past epoch;
//   - exactly one mutation runs at a time (flock), otherwise busy;
//   - status/preflight change nothing and take no lock.
package agentd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
)

// Response is the agent's reply, in exactly the format the manager's client expects.
type Response struct {
	OK      bool   `json:"ok"`
	Noop    bool   `json:"noop,omitempty"`
	Error   string `json:"error,omitempty"`
	Message string `json:"message,omitempty"`
	Status  any    `json:"status,omitempty"`
}

// Request is a command from the manager.
type Request struct {
	Cmd          string `json:"cmd"`
	OperationID  string `json:"operation_id"`
	ClusterEpoch *int64 `json:"cluster_epoch"`
	Primary      string `json:"primary"`
	// SeedFromBinlog starts replication from the node's OWN binlog position instead of the saved replica
	// position. Sent only when the caller has PROVEN the source applied everything up to that point (planned
	// handover): a former source cannot have data newer than its own binlog, while the old gtid_slave_pos
	// belongs to the previous role and points into history the new source does not have.
	SeedFromBinlog bool `json:"seed_from_binlog"`
	// AcceptRelayLoss deliberately skips draining the relay log on emergency promotion. It comes ONLY from
	// an explicit operator decision and is echoed in the response to leave a trace.
	AcceptRelayLoss bool `json:"accept_relay_loss"`
	// PublicationAddress/Device come from the active config revision. Empty means "use the local config":
	// the node must be able to publish even when the publication provider is external and the revision
	// carries no address.
	PublicationAddress string `json:"publication_address"`
	PublicationDevice  string `json:"publication_device"`
	// PublicationProvider (floating_ip or anycast) decides what happens to the address on withdrawal: a
	// floating_ip is removed (otherwise two nodes would hold one moving address), an anycast address stays on
	// loopback for good — there publication is turned off by closing the probe, not by the address.
	PublicationProvider string `json:"publication_provider"`
	// ProbePort is the readiness probe port (check_publication). A pointer because "unset" and "zero"
	// differ: absent means the probe is not used.
	ProbePort *int `json:"probe_port,omitempty"`
	// OwnAddress is the anycast address from this node's ACTIVE revision. The agent does not read the
	// config, so the caller must say which address is ours.
	OwnAddress string `json:"own_address,omitempty"`
	// PeerKey/KeyFP are the pair secret and its fingerprint (install_peer_key/remove_peer_key only). These
	// commands live OUTSIDE the mutation contract: see peerkey.go.
	PeerKey string `json:"peer_key,omitempty"`
	KeyFP   string `json:"key_fp,omitempty"`
	// Secret/Value negotiate pair secrets (install_secret). The name comes from an allowlist only: a command
	// taking a path from the networked process would mean writing any file as root.
	Secret string `json:"secret,omitempty"`
	Value  string `json:"value,omitempty"`
	// Host is the peer host pattern for ensure_pair_grants.
	Host string `json:"host,omitempty"`
}

// Executor is what actually touches the node; an interface so the agent core can be tested without MariaDB
// and PowerDNS.
type Executor interface {
	Status(pubAddress, pubDevice, pubProvider string) (any, error)
	Preflight() (Response, error)
	Promote() (Response, error)
	Demote() (Response, error)
	EnableNotifier() (Response, error)
	DisableNotifier() (Response, error)
	AnnouncePanel(address, device, provider string) (Response, error)
	WithdrawPanel(address, device, provider string) (Response, error)
	// Inventory reports what the node holds. Read-only; it lets a human choosing the data donor when
	// creating a pair (§14.6) see how many zones and users they would lose.
	Inventory() (Inventory, error)
	// EnsurePairGrants creates the replication account FOR THE PEER locally. Done on both nodes before
	// replication starts: afterwards account DDL goes into the binlog and can only be changed on ACTIVE.
	EnsurePairGrants(host string) (Response, error)
	// ResolveDevice finds the interface through which this node reaches the service address. NIC names on
	// the two machines need not match, and nobody should have to know them.
	ResolveDevice(address string) (Response, error)
	// CheckPublication checks that the probe port and service address are free on THIS node. Read-only:
	// called before pair creation so a predictable conflict is not found after reseeding someone's database.
	CheckPublication(provider, address string, probePort int) (Response, error)
	// CheckPublicationOwned is the same, but names OUR address from the active revision: only that one is
	// allowed on loopback, everything else belongs to someone else.
	CheckPublicationOwned(provider, address string, probePort int, own string) (Response, error)
	// DropAddress removes a specific address from an interface. Needed when the anycast address changes: it
	// lives on loopback permanently, so after a new revision the old one would linger next to the new one.
	DropAddress(addr, dev string) (Response, error)
	// AddressPresent reports whether a specific address is up. Read-only: convergence uses it to decide
	// whether anything is left to remove instead of sending the command every cycle.
	AddressPresent(addr, dev string) (Response, error)
	// EnableFailsafe/DisableFailsafe toggle the HA-role fail-safe (read_only + skip_slave_start on next start).
	EnableFailsafe() (Response, error)
	DisableFailsafe() (Response, error)
	RejoinReplica(primary string, seedFromBinlog bool) (Response, error)
	ReseedReplica(primary string) (Response, error)
	DrainRelay() (Response, error)
	EmergencyPromote(acceptRelayLoss bool) (Response, error)
	// StopReplication/ReleasePublication dismantle the pair: the node becomes a standalone server again.
	// Data is not touched at all — only what made two servers one pair is removed.
	StopReplication() (Response, error)
	ReleasePublication(address, device string) (Response, error)
}

// State-changing commands. Anything not listed here is not a mutation and bypasses the mutation contract.
var mutating = map[string]bool{
	"promote": true, "demote": true,
	"enable_notifier": true, "disable_notifier": true,
	"announce_panel": true, "withdraw_panel": true,
	"rejoin_replica": true, "reseed_replica": true,
	"drain_relay": true, "emergency_promote": true,
	"stop_replication": true, "release_publication": true,
}

var needsPrimary = map[string]bool{"rejoin_replica": true, "reseed_replica": true}

// Agent is the core: the mutation contract on top of the executor.
type Agent struct {
	// The agent deliberately has NO identity: it talks only to its own manager over a local unix socket,
	// so "am I talking to the right node" is not a question here. The node UUID lives in the local dns_ha,
	// which the agent need not access — it must work even with the database down.
	// StateDir holds durable state (survives reboot), RunDir the lock of the current run. Kept apart on
	// purpose: a lock file surviving a reboot reads as "someone is writing" when nobody is.
	StateDir string
	RunDir   string
	Exec     Executor
	// PeerKeyPath/PeerKeyOwner are the only file the agent places for pairing and the manager user who
	// gets it. The agent knows nothing else about pairing.
	PeerKeyPath  string
	PeerKeyOwner string
	// PanelSecretGroup is the group that must be able to read panel secrets (auth-master.key); the owner
	// stays root. Replication secrets are readable by the agent only.
	PanelSecretGroup string

	mu sync.Mutex // serialises within the process; flock does it across processes
}

// Handle processes one command with no external deadline (one-off run from cmd, checks).
func (a *Agent) Handle(req Request) Response { return a.HandleContext(context.Background(), req) }

// HandleContext processes a command under the OPERATION's deadline and cancellation. The server sets the
// deadline once per request and it covers everything: external commands, SQL, waits. They have no timers of
// their own — otherwise the operation limit means nothing while a call inside hangs on its own.
func (a *Agent) HandleContext(ctx context.Context, req Request) Response {
	exec := a.Exec
	if b, ok := exec.(interface{ WithContext(context.Context) *Node }); ok {
		exec = b.WithContext(ctx) // the executor gets a COPY with the deadline: requests run concurrently
	}
	return a.handle(ctx, exec, req)
}

func (a *Agent) handle(ctx context.Context, exec Executor, req Request) Response {
	switch req.Cmd {
	case "":
		return errResp("bad_request", "no command given")
	case "status":
		return a.status(exec, req.PublicationAddress, req.PublicationDevice, req.PublicationProvider)
	case "preflight":
		r, err := exec.Preflight()
		if err != nil {
			return errResp("executor_error", err.Error())
		}
		return r
	case "inventory":
		inv, err := exec.Inventory()
		if err != nil {
			return errResp(codeOf(err), err.Error())
		}
		return Response{OK: true, Status: inv}
	case "install_peer_key":
		a.mu.Lock()
		defer a.mu.Unlock()
		return a.installPeerKey(req.PeerKey, req.KeyFP)
	case "enable_failsafe", "disable_failsafe":
		a.mu.Lock()
		defer a.mu.Unlock()
		var (
			r   Response
			err error
		)
		if req.Cmd == "enable_failsafe" {
			r, err = exec.EnableFailsafe()
		} else {
			r, err = exec.DisableFailsafe()
		}
		if err != nil {
			return errResp("executor_error", err.Error())
		}
		return r
	case "reset_pair_state":
		// Pair dismantle: the node forgets the EPOCH. Otherwise the next pair could not be created — it starts
		// at epoch one, while the agent durably remembers, say, nine and rejects every mutation as stale.
		// Node identity and done-marks are left alone: the former belongs to the machine, the latter to
		// operations that no longer exist.
		a.mu.Lock()
		defer a.mu.Unlock()
		st, err := a.readState()
		if err != nil {
			return errResp(codeOf(err), err.Error())
		}
		if st.MaxEpoch == 0 && len(st.Done) == 0 {
			return Response{OK: true, Noop: true, Status: map[string]any{"max_epoch": 0}}
		}
		st.MaxEpoch = 0
		st.Done = doneSet{}
		if err := a.writeState(st); err != nil {
			return errResp("state_write_failed", err.Error())
		}
		return Response{OK: true, Status: map[string]any{"max_epoch": 0}}
	case "ensure_pair_grants":
		a.mu.Lock()
		defer a.mu.Unlock()
		r, err := exec.EnsurePairGrants(req.Host)
		if err != nil {
			return errResp("executor_error", err.Error())
		}
		return r
	case "read_secret":
		a.mu.Lock()
		defer a.mu.Unlock()
		return a.readSecret(req.Secret)
	case "resolve_publication_device":
		r, err := exec.ResolveDevice(req.Value)
		if err != nil {
			return errResp("executor_error", err.Error())
		}
		return r
	case "address_present":
		r, err := exec.AddressPresent(req.PublicationAddress, req.PublicationDevice)
		if err != nil {
			return errResp("executor_error", err.Error())
		}
		return r
	case "drop_address":
		// Deliberately outside the pair mutation contract: there is no epoch here — this cleans up a trace
		// of a previous configuration, it is not a role action.
		a.mu.Lock()
		defer a.mu.Unlock()
		r, err := exec.DropAddress(req.PublicationAddress, req.PublicationDevice)
		if err != nil {
			return errResp("executor_error", err.Error())
		}
		return r
	case "check_publication":
		// Read-only plus one socket-open attempt. The command exists so a conflict is found BEFORE any
		// destructive step.
		port := 0
		if req.ProbePort != nil {
			port = *req.ProbePort
		}
		// The CALLER names OwnAddress: the manager knows the active revision, the agent does not. Empty means
		// "no own address", so any host prefix found on loopback belongs to someone else.
		r, err := exec.CheckPublicationOwned(req.PublicationProvider, req.PublicationAddress, port, req.OwnAddress)
		if err != nil {
			return errResp("executor_error", err.Error())
		}
		return r
	case "install_secret":
		a.mu.Lock()
		defer a.mu.Unlock()
		return a.installSecret(req.Secret, req.Value)
	case "remove_peer_key":
		a.mu.Lock()
		defer a.mu.Unlock()
		return a.removePeerKey(req.KeyFP)
	}
	if !mutating[req.Cmd] {
		return errResp("unknown_command", "unknown command: "+req.Cmd)
	}
	return a.mutate(exec, req)
}

// status combines agent state (epoch, journal readability) with node state from the executor. Success is
// NOT forced: an unreadable journal or unreachable node must show up as a failure. The publication address
// comes FROM THE REQUEST: it is defined in the replicated revision, which the agent need not know, but the
// agent must truthfully say whether THAT address is up — otherwise observation would fall back to a marker
// file, i.e. intent instead of fact.
func (a *Agent) status(exec Executor, pubAddr, pubDev, pubProvider string) Response {
	st, serr := a.readState()
	node, nerr := exec.Status(pubAddr, pubDev, pubProvider)

	out := map[string]any{"state_ok": serr == nil, "node": node}
	if serr == nil {
		out["max_epoch"] = st.MaxEpoch
	} else {
		out["max_epoch"] = nil
	}
	resp := Response{OK: serr == nil && nerr == nil, Status: out}
	switch {
	case serr != nil:
		resp.Error, resp.Message = codeOf(serr), serr.Error()
	case nerr != nil:
		resp.Error, resp.Message = codeOf(nerr), nerr.Error()
	}
	return resp
}

func (a *Agent) mutate(exec Executor, req Request) Response {
	if req.OperationID == "" {
		return errResp("bad_request", "mutation without operation_id")
	}
	if req.ClusterEpoch == nil || *req.ClusterEpoch < 0 {
		return errResp("bad_request", "mutation without cluster_epoch")
	}
	if needsPrimary[req.Cmd] && req.Primary == "" {
		return errResp("bad_request", req.Cmd+" requires a primary")
	}
	epoch := *req.ClusterEpoch

	a.mu.Lock()
	defer a.mu.Unlock()

	// Non-blocking lock: contention is a `busy` reply, not a queue. A queue would let a command issued from
	// an already stale state run later.
	unlock, err := a.lock()
	if err != nil {
		return errResp("busy", err.Error())
	}
	defer unlock()

	st, serr := a.readState()
	if serr != nil {
		// Fail-closed: an unreadable journal means the highest epoch is unknown.
		return errResp(codeOf(serr), "the agent state journal is unreadable — the mutation is refused")
	}
	if epoch < st.MaxEpoch {
		return errResp("stale_epoch", fmt.Sprintf("cluster_epoch %d < accepted %d", epoch, st.MaxEpoch))
	}
	key := req.OperationID + "\x00" + req.Cmd
	if st.Done[key] {
		// Repeat of the SAME operation. We answer from the journal without looking at the node or reporting
		// its state — the caller must take a fresh observation itself.
		return Response{OK: true, Noop: true}
	}
	// The epoch is accepted BEFORE acting: otherwise a successful mutation followed by a failed write would
	// leave the node willing to execute a command from an already past epoch later.
	if epoch > st.MaxEpoch {
		st.MaxEpoch = epoch
		if err := a.writeState(st); err != nil {
			return errResp("state_write_failed", err.Error())
		}
	}

	resp := a.run(exec, req)
	if resp.OK {
		st.Done[key] = true
		if err := a.writeState(st); err != nil {
			// The action ran but could not be recorded. Claiming success would be a lie: a retry would run it
			// again, and the caller must learn the journal state is in doubt.
			return errResp("state_write_failed", "the action was carried out but not recorded in the journal: "+err.Error())
		}
	}
	return resp
}

func (a *Agent) run(exec Executor, req Request) Response {
	var (
		r   Response
		err error
	)
	switch req.Cmd {
	case "promote":
		r, err = exec.Promote()
		pulseRoleChanged(r, err, "activate")
	case "demote":
		r, err = exec.Demote()
		pulseRoleChanged(r, err, "deactivate")
	case "enable_notifier":
		r, err = exec.EnableNotifier()
	case "disable_notifier":
		r, err = exec.DisableNotifier()
	case "announce_panel":
		r, err = exec.AnnouncePanel(req.PublicationAddress, req.PublicationDevice, req.PublicationProvider)
	case "withdraw_panel":
		r, err = exec.WithdrawPanel(req.PublicationAddress, req.PublicationDevice, req.PublicationProvider)
	case "stop_replication":
		r, err = exec.StopReplication()
	case "release_publication":
		r, err = exec.ReleasePublication(req.PublicationAddress, req.PublicationDevice)
	case "rejoin_replica":
		r, err = exec.RejoinReplica(req.Primary, req.SeedFromBinlog)
	case "reseed_replica":
		r, err = exec.ReseedReplica(req.Primary)
	case "drain_relay":
		r, err = exec.DrainRelay()
	case "emergency_promote":
		r, err = exec.EmergencyPromote(req.AcceptRelayLoss)
		pulseRoleChanged(r, err, "activate")
	default:
		return errResp("unknown_command", req.Cmd)
	}
	if err != nil {
		return errResp("executor_error", err.Error())
	}
	return r
}

type state struct {
	MaxEpoch int64   `json:"max_epoch"`
	Done     doneSet `json:"done"`
}

// doneSet holds marks of completed operations. Parsing tolerates the value's FORM (true and 1 are the same)
// because different versions write this file, and tripping over a boolean encoding is a silly way to lose
// safety state. Garbage is still an error.
type doneSet map[string]bool

func (d *doneSet) UnmarshalJSON(raw []byte) error {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return err
	}
	out := make(doneSet, len(m))
	for k, v := range m {
		switch t := v.(type) {
		case bool:
			out[k] = t
		case float64:
			out[k] = t != 0
		default:
			return fmt.Errorf("the mark %q has an unrecognised value", k)
		}
	}
	*d = out
	return nil
}

func (a *Agent) stateFile() string { return filepath.Join(a.StateDir, "agent-state.json") }

// readState treats a missing file as the normal initial state. An existing but broken one is an ERROR:
// substituting zero would erase the safety authority and accept any epoch.
func (a *Agent) readState() (*state, error) {
	raw, err := os.ReadFile(a.stateFile())
	if os.IsNotExist(err) {
		return &state{Done: doneSet{}}, nil
	}
	if err != nil {
		return nil, &agentError{code: "state_unavailable", msg: err.Error()}
	}
	var s state
	if err := json.Unmarshal(raw, &s); err != nil || s.MaxEpoch < 0 {
		return nil, &agentError{code: "state_corrupt", msg: "the state journal could not be parsed"}
	}
	if s.Done == nil {
		s.Done = doneSet{}
	}
	return &s, nil
}

// writeState is durable: temp → fsync(file) → rename → fsync(dir). The directory fsync is required: max_epoch
// is the safety authority, and the file rolling back after a sudden reboot would mean a forgotten epoch.
func (a *Agent) writeState(s *state) error {
	raw, err := json.Marshal(s)
	if err != nil {
		return err
	}
	tmp := a.stateFile() + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(raw); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, a.stateFile()); err != nil {
		os.Remove(tmp)
		return err
	}
	d, err := os.Open(a.StateDir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func (a *Agent) lock() (func(), error) {
	f, err := os.OpenFile(filepath.Join(a.RunDir, "agent.lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("another mutation is already running")
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}

// Operations lists completed operations (diagnostics), sorted so the output is reproducible.
func (a *Agent) Operations() []string {
	st, err := a.readState()
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(st.Done))
	for k := range st.Done {
		out = append(out, strings.ReplaceAll(k, "\x00", "/"))
	}
	sort.Strings(out)
	return out
}

type agentError struct {
	code string
	msg  string
}

func (e *agentError) Error() string { return e.msg }
func (e *agentError) Code() string  { return e.code }

func codeOf(err error) string {
	if e, ok := err.(*agentError); ok {
		return e.code
	}
	return "executor_error"
}

func fail(code, msg string) error { return &agentError{code: code, msg: msg} }

func errResp(code, msg string) Response { return Response{OK: false, Error: code, Message: msg} }

// failResp turns an executor error into a typed failure response.
func failResp(err error) Response {
	if err == nil {
		return Response{OK: true}
	}
	return Response{OK: false, Error: codeOf(err), Message: err.Error()}
}
