// Package agent is a typed client for the local privileged `dns-ha-agent`.
//
// The manager talks to the agent rather than to MariaDB/pdns_control directly so that the node's root-level
// handles are not reachable from a network-facing process (docs/23 §2).
//
// There is deliberately no generic `Run(cmd)`: a "send any command" entry point would defeat the split.
// Observing commands (`status`, `preflight`) live on `Client`, state-changing ones on `Mutator` (mutator.go),
// so code holding a `Client` cannot issue a mutation at all.
package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"
)

// Failure codes are machine-distinguishable on purpose: "unreachable", "garbage reply" and "too slow" are
// three different node states and must not collapse into one string.
const (
	CodeUnavailable = "agent_unavailable"   // could not connect to the socket
	CodeTimeout     = "agent_timeout"       // did not finish in time
	CodeIO          = "agent_io"            // connection broke while writing/reading
	CodeMalformed   = "agent_bad_response"  // reply unparsable or not an agent reply
	CodeCommand     = "agent_command_error" // agent reported the command failed
)

// Error is an agent call failure with a typed code.
type Error struct {
	Code string
	Err  error
}

func (e *Error) Error() string {
	if e.Err == nil {
		return e.Code
	}
	return e.Code + ": " + e.Err.Error()
}
func (e *Error) Unwrap() error { return e.Err }

// CodeOf returns the failure code if err is an agent error, otherwise "".
func CodeOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

// Client connects to the local agent. It is stateless, one connection per request: a long-lived connection
// to a root process speeds nothing up but adds ways to hang.
type Client struct {
	Socket  string
	Timeout time.Duration
}

// Status is the `status` reply: the agent's read-only report of the node's actual state.
type Status struct {
	OK       bool
	Error    string
	StateOK  bool
	MaxEpoch *int64

	ReadOnly       *int64
	NotifierOn     *int64
	SecondaryOn    *int64 // second half of the PowerDNS role; nil when an older agent does not report it
	PDNSVersion    string // running PowerDNS version, for display; "" from an older agent
	RouteAnnounced *int64
	// The publication address is a property of the NODE, not the pair: the panel shows it as the service
	// address, and taking it from panel config would show intent instead of what the node actually holds.
	PublicationAddress string
	PublicationDevice  string
	// AnycastAddressUp reports whether the anycast address is on loopback. In this mode it is on BOTH nodes
	// and does not mean publication (the probe does); it is observed so convergence can restore it if lost.
	AnycastAddressUp *int64

	ActiveNode         string
	ClusterEpoch       *int64
	WritesFrozen       *int64
	CurrentOperationID string
	FencedNode         string
}

// Preflight is the `preflight` reply: a quick local "node is alive and sane" check.
//
// It is a CONFIRMATION, not a source of truth. The executor's contract is narrow: MariaDB reachable,
// `read_only` readable, and on a replica the replication threads not in an explicit error. The manager
// observes topology, epoch, grants, fencing and config agreement itself; preflight only adds that the
// root execution path on the node works.
type Preflight struct {
	OK      bool
	Code    string // refusal reason as the executor named it (db_unreachable, replica_error, …)
	Message string
	// Pointers because "not reported" and "zero" differ.
	ReadOnly   *int64
	ReplicaIO  string
	ReplicaSQL string
}

// Raw reply shapes: tolerant of HOW Perl encoded a value, not of the value being missing.
type rawStatus struct {
	OK     *FlexBool `json:"ok"`
	Error  string    `json:"error,omitempty"`
	Status *struct {
		StateOK  *FlexBool `json:"state_ok"`
		MaxEpoch *FlexInt  `json:"max_epoch"`
		Node     *struct {
			ReadOnly           *FlexInt `json:"read_only"`
			NotifierOn         *FlexInt `json:"notifier_on"`
			SecondaryOn        *FlexInt `json:"secondary_on"`
			RouteAnnounced     *FlexInt `json:"route_announced"`
			PublicationAddress string   `json:"publication_address"`
			PublicationDevice  string   `json:"publication_device"`
			AnycastAddressUp   *FlexInt `json:"anycast_address_up"`
			PDNSVersion        string   `json:"pdns_version"`
			Cluster            *struct {
				ActiveNode         string   `json:"active_node"`
				ClusterEpoch       *FlexInt `json:"cluster_epoch"`
				WritesFrozen       *FlexInt `json:"writes_frozen"`
				CurrentOperationID *string  `json:"current_operation_id"`
				FencedNode         *string  `json:"fenced_node"`
			} `json:"cluster"`
		} `json:"node"`
	} `json:"status"`
}

type rawPreflight struct {
	OK      *FlexBool `json:"ok"`
	Error   string    `json:"error,omitempty"`
	Message string    `json:"message,omitempty"`
	Status  *struct {
		ReadOnly   *FlexInt `json:"read_only"`
		ReplicaIO  string   `json:"replica_io"`
		ReplicaSQL string   `json:"replica_sql"`
	} `json:"status"`
}

// Status requests the node state. The publication address is passed so the agent checks exactly that address
// on the interface: it lives in the replicated revision, not in a local file.
func (c Client) Status(ctx context.Context, pubAddress, pubDevice, pubProvider string) (Status, error) {
	var raw rawStatus
	req := map[string]any{"cmd": "status"}
	if pubAddress != "" && pubDevice != "" {
		req["publication_address"], req["publication_device"] = pubAddress, pubDevice
	}
	// The provider changes the meaning: with anycast the loopback address is always present, so
	// route_announced comes from the marker instead.
	if pubProvider != "" {
		req["publication_provider"] = pubProvider
	}
	if err := c.send(ctx, req, &raw); err != nil {
		return Status{}, err
	}
	// A missing `ok` is an unrecognised reply (maybe not the agent at all), not a default false;
	// defaulting would invent an observation.
	if raw.OK == nil {
		return Status{}, &Error{Code: CodeMalformed, Err: fmt.Errorf("the response has no ok field")}
	}
	st := Status{OK: raw.OK.Bool(), Error: raw.Error}
	if !st.OK {
		return st, nil // the agent reported it could not; an observation, not a link failure
	}
	if raw.Status == nil {
		return Status{}, &Error{Code: CodeMalformed, Err: fmt.Errorf("successful response without status")}
	}
	st.StateOK = raw.Status.StateOK.Bool()
	st.MaxEpoch = raw.Status.MaxEpoch.Int64()
	if n := raw.Status.Node; n != nil {
		st.ReadOnly, st.NotifierOn, st.RouteAnnounced = n.ReadOnly.Int64(), n.NotifierOn.Int64(), n.RouteAnnounced.Int64()
		st.SecondaryOn = n.SecondaryOn.Int64()
		st.PublicationAddress, st.PublicationDevice = n.PublicationAddress, n.PublicationDevice
		st.AnycastAddressUp = n.AnycastAddressUp.Int64()
		st.PDNSVersion = n.PDNSVersion
		if cl := n.Cluster; cl != nil {
			st.ActiveNode, st.ClusterEpoch, st.WritesFrozen = cl.ActiveNode, cl.ClusterEpoch.Int64(), cl.WritesFrozen.Int64()
			if cl.CurrentOperationID != nil {
				st.CurrentOperationID = *cl.CurrentOperationID
			}
			if cl.FencedNode != nil {
				st.FencedNode = *cl.FencedNode
			}
		}
	}
	return st, nil
}

// Preflight requests the local node check.
//
// A negative verdict (`ok=0`) is a SUCCESSFUL observation of a negative result, not a call error: the reason
// is kept and shown rather than turned into "agent unavailable".
func (c Client) Preflight(ctx context.Context) (Preflight, error) {
	var raw rawPreflight
	if err := c.call(ctx, "preflight", &raw); err != nil {
		return Preflight{}, err
	}
	if raw.OK == nil {
		return Preflight{}, &Error{Code: CodeMalformed, Err: fmt.Errorf("the response has no ok field")}
	}
	p := Preflight{OK: raw.OK.Bool(), Code: raw.Error, Message: raw.Message}
	if !p.OK && p.Code == "" {
		p.Code = CodeCommand // a refusal without a reason must still show as a refusal
	}
	if s := raw.Status; s != nil {
		p.ReadOnly, p.ReplicaIO, p.ReplicaSQL = s.ReadOnly.Int64(), s.ReplicaIO, s.ReplicaSQL
	}
	return p, nil
}

// Inventory returns what the node holds in the transferable databases. Read-only, hence on Client.
//
// The content is NOT parsed: it is a human-readable description (databases, tables, row counts), and typing
// it in every layer would mean rewriting those types on every new table. It passes through as raw JSON.
func (c Client) Inventory(ctx context.Context) (json.RawMessage, error) {
	var raw struct {
		OK      *FlexBool       `json:"ok"`
		Error   string          `json:"error,omitempty"`
		Message string          `json:"message,omitempty"`
		Status  json.RawMessage `json:"status,omitempty"`
	}
	if err := c.call(ctx, "inventory", &raw); err != nil {
		return nil, err
	}
	if raw.OK == nil {
		return nil, &Error{Code: CodeMalformed, Err: fmt.Errorf("the response has no ok field")}
	}
	if !raw.OK.Bool() {
		return nil, &Error{Code: CodeCommand, Err: fmt.Errorf("%s: %s", raw.Error, raw.Message)}
	}
	if len(raw.Status) == 0 {
		return nil, &Error{Code: CodeMalformed, Err: fmt.Errorf("successful response without status")}
	}
	return raw.Status, nil
}

func (c Client) call(ctx context.Context, cmd string, dst any) error {
	return c.send(ctx, map[string]any{"cmd": cmd}, dst)
}

// send performs one exchange under a single deadline, so a hung agent cannot stall the observation loop.
func (c Client) send(ctx context.Context, req any, dst any) error {
	deadline := time.Now().Add(c.Timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	var d net.Dialer
	dialCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	conn, err := d.DialContext(dialCtx, "unix", c.Socket)
	if err != nil {
		return &Error{Code: classify(err, CodeUnavailable), Err: err}
	}
	defer conn.Close()
	if err := conn.SetDeadline(deadline); err != nil {
		return &Error{Code: CodeIO, Err: err}
	}
	body, err := json.Marshal(req)
	if err != nil {
		return &Error{Code: CodeIO, Err: err}
	}
	if _, err := conn.Write(append(body, '\n')); err != nil {
		return &Error{Code: classify(err, CodeIO), Err: err}
	}
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return &Error{Code: classify(err, CodeIO), Err: err}
	}
	if err := json.Unmarshal(line, dst); err != nil {
		return &Error{Code: CodeMalformed, Err: err}
	}
	return nil
}

func classify(err error, def string) string {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return CodeTimeout
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return CodeTimeout
	}
	return def
}
