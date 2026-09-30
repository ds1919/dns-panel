// Package statusapi is the manager's local control socket.
//
// The panel and operator use it to read state and to create intents (switchover, emergency, reseed).
// The manager always executes them itself: the panel never talks to nodes and holds no HA logic, so there
// is exactly one place that decides roles.
//
// The socket is local and group-accessible to the panel; no network. The panel checks permissions, and the
// manager records in the operation who asked.
package statusapi

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Request is a control socket command: one JSON line in, one JSON line out.
type Request struct {
	Cmd             string `json:"cmd"`
	ID              string `json:"id,omitempty"`
	Target          string `json:"target,omitempty"`
	RequestedBy     string `json:"requested_by,omitempty"`
	Ack             string `json:"ack,omitempty"`
	AcceptRelayLoss bool   `json:"accept_relay_loss,omitempty"`
	Limit           int    `json:"limit,omitempty"`
	// Address/Force are for pairing: the peer address to join, and explicit consent to drop existing
	// trust (dissolving a pair is not garbage collection).
	Address string `json:"address,omitempty"`
	Force   bool   `json:"force,omitempty"`
	// Provider is how the new pair's service address is published (floating_ip, anycast, marker).
	// No interface here on purpose: each node derives it from its route to the address.
	Provider string `json:"provider,omitempty"`
	// ProbePort is the anycast TCP probe port. The external checker only sees whether it is open;
	// the manager decides everything else about readiness.
	ProbePort int `json:"probe_port,omitempty"`
	// Payload is the raw config revision; the manager parses and validates it, the socket need not know the format.
	Payload json.RawMessage `json:"payload,omitempty"`
}

// Handlers is what the manager can do. The implementation lives in cmd; the socket only maps requests to calls.
type Handlers struct {
	Status      func() any
	Config      func() (any, error)
	ConfigApply func(req Request) (any, error)
	// PublicationApply changes a running pair's service address and probe port. Separate from ConfigApply
	// because the panel names two values rather than building a revision; the manager decides whether a
	// plain revision or one that also cleans up the old address is needed.
	PublicationApply func(req Request) (any, error)
	Operations       func(limit int) (any, error)
	Operation        func(id string) (any, error)
	Switchover       func(req Request) (any, error)
	Emergency        func(req Request) (any, error)
	Reseed           func(req Request) (any, error)
	// Dismantle turns HA off: each node serves itself again, pairing stays ("Paired · HA not configured"),
	// data is untouched.
	Dismantle func(req Request) (any, error)
	Resume    func(req Request) (any, error)
	// Pair handles all pairing commands; they differ by action, not by shape.
	Pair func(req Request) (any, error)
}

type Server struct {
	path string
	ln   net.Listener
	mu   sync.RWMutex
	last any
	h    Handlers
}

// New opens the socket. Mode 0660 and group come from the unit: who may control HA is the node admin's call.
func New(path string, h Handlers) (*Server, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	// Remove a stale socket, never a live one. An unconditional unlink would let a second, accidentally
	// started manager steal IPC from the running one, which stays "healthy" in systemd while the panel talks
	// to someone else or no one. The only honest test is to connect: an answer means someone is there.
	if c, err := net.DialTimeout("unix", path, time.Second); err == nil {
		c.Close()
		return nil, fmt.Errorf("status socket %s is already served by a running manager", path)
	}
	_ = os.Remove(path) // left over from a process that no longer exists
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o660); err != nil {
		ln.Close()
		return nil, err
	}
	return &Server{path: path, ln: ln, h: h}, nil
}

// Publish stores the latest observation verdict.
func (s *Server) Publish(v any) {
	s.mu.Lock()
	s.last = v
	s.mu.Unlock()
}

func (s *Server) Serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *Server) Close() error {
	err := s.ln.Close()
	os.Remove(s.path)
	return err
}

// handle serves one request with one response.
//
// The client must send a JSON line and close its write side (or send a newline). Empty input means
// `status`, handy for manual diagnostics, but the server still has to wait for the request.
func (s *Server) handle(conn net.Conn) {
	defer conn.Close()
	// Short deadline for reading the request so a silent client holds nothing. The execution deadline
	// depends on the command and is set after parsing: status is instant, pair creation lasts as long as a reseed.
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	line, _ := bufio.NewReader(io.LimitReader(conn, 64*1024)).ReadBytes('\n')
	req := Request{Cmd: "status"}
	if len(line) > 0 {
		if err := json.Unmarshal(line, &req); err != nil {
			writeJSON(conn, map[string]any{"ok": false, "error": "bad_request", "message": "request could not be parsed"})
			return
		}
		if req.Cmd == "" {
			req.Cmd = "status"
		}
	}
	_ = conn.SetDeadline(time.Now().Add(DeadlineFor(req.Cmd)))
	writeJSON(conn, s.dispatch(req))
}

// DeadlineFor is how long a command may run. Exported because the client must wait just as long: a pair
// build aborted client-side keeps running in the manager, leaving the human not knowing whether the node
// was rebuilt — the worst possible outcome, and avoiding it costs one constant.
func DeadlineFor(cmd string) time.Duration {
	switch cmd {
	case "pair_build":
		// A reseed takes up to ten minutes; the margin covers the rest of the sequence.
		return 15 * time.Minute
	case "pair_join", "pair_approve", "pair_reset", "pair_inventory", "publication_apply":
		// Network round trips to the peer, nothing long. publication_apply checks resources on both
		// sides and runs a two-phase revision commit: seconds, but over the network, twice.
		return 2 * time.Minute
	}
	return 30 * time.Second
}

func (s *Server) dispatch(req Request) any {
	switch req.Cmd {
	case "status":
		s.mu.RLock()
		last := s.last
		s.mu.RUnlock()
		if last == nil {
			return map[string]any{"ok": false, "error": "not_observed", "message": "no observation has been made yet"}
		}
		return last
	case "config":
		if s.h.Config == nil {
			return errResp("unknown_command", "reading the configuration is not wired up")
		}
		return wrap(s.h.Config())
	case "config_apply":
		return wrap(call(s.h.ConfigApply, req))
	case "publication_apply":
		return wrap(call(s.h.PublicationApply, req))
	case "operations":
		return wrap(s.h.Operations(req.Limit))
	case "operation":
		if req.ID == "" {
			return errResp("bad_request", "operation id is required")
		}
		return wrap(s.h.Operation(req.ID))
	case "switchover":
		return wrap(call(s.h.Switchover, req))
	case "emergency":
		return wrap(call(s.h.Emergency, req))
	case "reseed":
		return wrap(call(s.h.Reseed, req))
	case "dismantle":
		return wrap(call(s.h.Dismantle, req))
	case "resume":
		if req.ID == "" {
			return errResp("bad_request", "operation id is required")
		}
		return wrap(call(s.h.Resume, req))
	case "pair_status", "pair_inventory", "pair_devices", "pair_create", "pair_join", "pair_approve",
		"pair_reject", "pair_reset", "pair_build":
		return wrap(call(s.h.Pair, req))
	}
	return errResp("unknown_command", "unknown command: "+req.Cmd)
}

func call(f func(Request) (any, error), req Request) (any, error) {
	if f == nil {
		// An unwired handler is a build defect and must surface as such, not as a silent no-op.
		return nil, fmt.Errorf("handler is not wired")
	}
	return f(req)
}

func wrap(v any, err error) any {
	if err != nil {
		return map[string]any{"ok": false, "error": "failed", "message": err.Error()}
	}
	return map[string]any{"ok": true, "result": v}
}

func errResp(code, msg string) any {
	return map[string]any{"ok": false, "error": code, "message": msg}
}

func writeJSON(w io.Writer, v any) {
	raw, err := json.Marshal(v)
	if err != nil {
		return
	}
	w.Write(append(raw, '\n'))
}
