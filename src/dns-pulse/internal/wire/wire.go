// Package wire is the agent-server protocol: one long-lived TLS connection, one JSON message per line.
//
// Why not gRPC: over plain TLS it only added keepalive, which docs/25 §3 deems insufficient anyway and
// replaces with per-task confirms. Bidirectionality, reconnects, pinning and framing are ours regardless;
// instead of protobuf and codegen we get the standard library and a spec readable by eye.
//
// The format is deliberately boring (an object with a type field, one per line), so anyone can write
// their own agent from this description without tooling.
package wire

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
)

// Message types. The agent sends hello/accepted/transition/confirm/fp_ack/sweep_claim/sweep_result;
// the server sends welcome/assign/next_fp/goodbye/sweep_batch.
const (
	TypeHello      = "hello"
	TypeWelcome    = "welcome"
	TypeAssign     = "assign"
	TypeAccepted   = "accepted"
	TypeTransition = "transition"
	TypeConfirm    = "confirm"
	TypeNextFP     = "next_fingerprint"
	TypeFPAck      = "fingerprint_ack"
	TypeGoodbye    = "goodbye"
	// Slow sweep (docs/25 §7): the agent asks for a batch of addresses, measures them and returns answers.
	// Low-priority background work on the same connection, in separate messages so it does not mix with
	// checks that have their own rhythm.
	TypeSweepClaim  = "sweep_claim"
	TypeSweepBatch  = "sweep_batch"
	TypeSweepResult = "sweep_result"
)

// Msg is one message: a flat envelope with a type field that any JSON decoder can parse.
type Msg struct {
	Type string `json:"type"`

	// hello
	// AgentKey identifies the agent; it generates the key itself on first start and the server knows only
	// its hash. EnrollKey is the site-wide key shared by all agents: it only lets an agent queue for approval.
	AgentKey  string `json:"agent_key,omitempty"`
	EnrollKey string `json:"enroll_key,omitempty"`
	// Self-reported hostname: a human label, not identification, to tell simultaneous requests apart.
	Hostname string `json:"hostname,omitempty"`
	RunID    string `json:"run_id,omitempty"` // new on EVERY process start, which reveals a second copy
	Version  string `json:"version,omitempty"`
	CanICMP  bool   `json:"can_icmp,omitempty"` // "cannot check" != "unavailable"
	// Verified outbound paths (a source address with a route), not kernel IPv6 support or ::1; otherwise
	// an agent without a route would paint every AAAA red (docs/25 §7).
	CanIPv4 bool `json:"can_ipv4,omitempty"`
	CanIPv6 bool `json:"can_ipv6,omitempty"`

	// welcome
	TesterID     uint32 `json:"tester_id,omitempty"`
	TesterName   string `json:"tester_name,omitempty"` // the agent learns its name HERE, not from its config
	ConfirmEvery uint32 `json:"confirm_every_seconds,omitempty"`

	// assign
	Tasks []Task `json:"tasks,omitempty"`

	// accepted / confirm: what runs and at which config version
	Checks []CheckVersion `json:"checks,omitempty"`

	// transition
	CheckID       uint32 `json:"check_id,omitempty"`
	ConfigVersion uint32 `json:"config_version,omitempty"`
	State         string `json:"state,omitempty"` // healthy | degraded | down
	Detail        string `json:"detail,omitempty"`

	// next_fingerprint / fingerprint_ack
	Fingerprint string `json:"fingerprint,omitempty"`

	// sweep_batch / sweep_result
	Sweep   []SweepTask   `json:"sweep,omitempty"`
	Answers []SweepAnswer `json:"answers,omitempty"`
	// Parallel probes and seconds until asking again when there is nothing to hand out. Both are set by
	// the server: the agent has no measurement parameters and no knowledge of other targets.
	SweepParallel uint32 `json:"sweep_parallel,omitempty"`
	SweepAgainSec uint32 `json:"sweep_again_seconds,omitempty"`

	// goodbye
	Reason string `json:"reason,omitempty"`
}

// SweepTask is one sweep target. The agent echoes the lease generation so the server can tell the
// current owner's answer from that of an agent that stalled and came back (docs/25 §7).
type SweepTask struct {
	TargetID   uint64 `json:"target_id"`
	Generation uint32 `json:"generation"`
	IP         string `json:"ip"`
	TimeoutMS  uint32 `json:"timeout_ms"`
	Probes     uint32 `json:"probes"` // tries per target: one lost packet is not an outage
}

// SweepAnswer is a measurement with exactly two states. "Unknown" is a SERVER state (no current
// measurement); an agent that could not measure stays silent.
type SweepAnswer struct {
	TargetID   uint64 `json:"target_id"`
	Generation uint32 `json:"generation"`
	State      string `json:"state"` // available | unavailable
}

type CheckVersion struct {
	CheckID       uint32 `json:"check_id"`
	ConfigVersion uint32 `json:"config_version"`
}

// Task is an agent task. The target is always an ADDRESS: names resolve through the very DNS being switched.
type Task struct {
	CheckID       uint32 `json:"check_id"`
	ConfigVersion uint32 `json:"config_version"`
	Kind          string `json:"kind"` // icmp | tcp
	TargetIP      string `json:"target_ip"`
	Port          uint32 `json:"port,omitempty"`
	IntervalSec   uint32 `json:"interval_seconds"`
	TimeoutMS     uint32 `json:"timeout_ms"`
	ProbesPerRun  uint32 `json:"probes_per_run"`
	OKProbes      uint32 `json:"ok_probes_required"`
	FailThreshold uint32 `json:"fail_threshold"`
	OKThreshold   uint32 `json:"ok_threshold"`
}

// maxLine caps one message, so an untrusted peer cannot make us allocate unbounded memory with one line.
const maxLine = 1 << 20

// Conn frames messages over an existing connection. Writes are mutex-guarded: several goroutines write
// (transitions and confirms are independent).
type Conn struct {
	rw  io.ReadWriteCloser
	in  *bufio.Scanner
	mu  sync.Mutex
	enc *json.Encoder
	w   *bufio.Writer
}

func New(rw io.ReadWriteCloser) *Conn {
	sc := bufio.NewScanner(rw)
	sc.Buffer(make([]byte, 0, 64*1024), maxLine)
	w := bufio.NewWriter(rw)
	return &Conn{rw: rw, in: sc, w: w, enc: json.NewEncoder(w)}
}

func (c *Conn) Send(m Msg) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.enc.Encode(m); err != nil { // Encode appends the newline itself
		return err
	}
	return c.w.Flush()
}

func (c *Conn) Recv() (Msg, error) {
	if !c.in.Scan() {
		if err := c.in.Err(); err != nil {
			return Msg{}, err
		}
		return Msg{}, io.EOF
	}
	var m Msg
	if err := json.Unmarshal(c.in.Bytes(), &m); err != nil {
		return Msg{}, fmt.Errorf("malformed message: %w", err)
	}
	if m.Type == "" {
		return Msg{}, fmt.Errorf("message has no type field")
	}
	return m, nil
}

func (c *Conn) Close() error { return c.rw.Close() }

// RemoteAddr returns the peer address if the transport is a network one. An observation, not
// authentication: the token identifies the agent (docs/25 §1).
func (c *Conn) RemoteAddr() string {
	type addrer interface{ RemoteAddr() net.Addr }
	if a, ok := c.rw.(addrer); ok {
		return a.RemoteAddr().String()
	}
	return ""
}
