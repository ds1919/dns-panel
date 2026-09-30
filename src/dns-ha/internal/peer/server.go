package peer

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// ErrRequestConflict: the same message_id arrived with different content. A distinct error so the server
// can tell it from storage unavailability and reply with a typed code.
var ErrRequestConflict = errors.New("request_id_conflict")

// StatusProvider returns a SNAPSHOT of this node's state. The server does not compute state itself: it only
// relays what the watch loop already computed and must not change anything.
type StatusProvider func() (StatusPayload, HelloPayload)

// ServerConfig is everything the listener needs. Nothing operational comes from TOML: the address comes from the EFFECTIVE revision.
type ServerConfig struct {
	NodeID       string        // own node_id (sent in every reply)
	PeerNodeID   string        // the only sender we accept messages from
	Listen       string        // host:port from ha_nodes.peer_listen_* of OUR row
	Secret       []byte        // shared pair secret
	Window       time.Duration // allowed clock skew
	ReadTimeout  time.Duration
	MaxMessage   int64
	StatusSource StatusProvider
	// InventorySource reports the transferable databases. Asked from the local agent and relayed as is:
	// the manager does not look at the content and has no access to those databases.
	InventorySource func() (json.RawMessage, error)
	// JournalSource is THIS node's operation journal, read-only: the peer asks for it when we executed the
	// operation but the peer has to show it to the human.
	JournalSource func(operationID string) (json.RawMessage, error)
	// InitHandler runs pair-creation steps. Separate from Executor on purpose: that one runs PAIR mutations,
	// which have an epoch and a gate, while here there is no pair yet. The handler itself checks whether the step
	// is allowed now, by the presence of an effective revision.
	InitHandler func(cmd string, payload []byte) (any, error)
	// InitTimeout bounds a pair-creation step. Separate from ReadTimeout on purpose: observation takes
	// seconds, a database reseed takes minutes, and a shared deadline would cut the connection mid-work. Worse
	// than failure here is not knowing: the node is being rebuilt and the caller cannot tell how it ended.
	InitTimeout time.Duration
	// Ledger, Gate and Executor are needed ONLY for mutating commands. Without them the read-only layer still
	// works, but any mutation missing ANY of them is rejected: without durable dedup a retry could run twice,
	// and without Gate it would run with no epoch, fencing or current-operation check.
	Ledger RequestLedger
	Gate   MutationGate
	// Executor runs the mutation itself IN THE SAME transaction that registers the request.
	Executor func(ctx context.Context, tx *sql.Tx, req *Request) (LedgerResult, error)
}

type Server struct {
	cfg   ServerConfig
	ln    net.Listener
	cache *replayCache
	now   func() time.Time
}

// New builds a server WITHOUT its own listener: the port is held by the dispatcher, which decides on the same
// 7901, from local node state, whose conversation it is (pairing or an existing pair). Two listeners cannot
// share a port, and node state changes without a restart.
func New(cfg ServerConfig) (*Server, error) {
	if cfg.NodeID == "" || cfg.PeerNodeID == "" {
		return nil, fmt.Errorf("peer server: node_id and peer_node_id are required")
	}
	if len(cfg.Secret) == 0 {
		return nil, fmt.Errorf("peer server: no secret")
	}
	return &Server{cfg: cfg, cache: newReplayCache(2*cfg.Window, 10000), now: time.Now}, nil
}

// Listen is New with its own listener, kept for tests and one-off commands with no dispatcher. The address is
// specific (not 0.0.0.0): the HA channel is private and has no reason to listen on all interfaces.
func Listen(cfg ServerConfig) (*Server, error) {
	s, err := New(cfg)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return nil, fmt.Errorf("peer server: %w", err)
	}
	s.ln = ln
	return s, nil
}

func (s *Server) Addr() string { return s.ln.Addr().String() }

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
	if s.ln == nil {
		return nil
	}
	return s.ln.Close()
}

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()
	// One deadline for the whole exchange: a client that connects and goes silent must not hold resources.
	_ = conn.SetDeadline(s.now().Add(s.cfg.ReadTimeout))

	// The limit applies WHILE reading, not after, or the sender could fill memory before the size check.
	lr := io.LimitReader(conn, s.cfg.MaxMessage+1)
	line, err := bufio.NewReader(lr).ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return
	}
	s.ServeLine(conn, line)
}

// ServeLine serves a conversation whose first line the dispatcher already read. The connection is NOT closed
// here: whoever accepted it owns it.
func (s *Server) ServeLine(conn net.Conn, line []byte) {
	if int64(len(line)) > s.cfg.MaxMessage {
		s.reply(conn, nil, ErrTooLarge, nil)
		return
	}

	var req Request
	if code, err := open(s.cfg.Secret, line, &req); code != "" {
		// Before the signature is verified the content is untrusted, so the reply carries NO request binding.
		_ = err
		s.reply(conn, nil, code, nil)
		return
	}
	if code := s.validate(&req); code != "" {
		s.reply(conn, &req, code, nil)
		return
	}

	if IsInit(req.Cmd) {
		s.handleInit(conn, &req)
		return
	}

	if IsMutating(req.Cmd) {
		// For mutations the memory cache guards ONLY against nonce reuse: a repeated message_id with a new nonce
		// is a normal retry of the logical action, decided by the durable registry, not the cache.
		if s.cache.claimMutationNonce(req.SenderNodeID, req.MessageID, req.Nonce) == verdictReplay {
			s.reply(conn, &req, ErrReplay, nil)
			return
		}
		s.handleMutation(conn, &req)
		return
	}

	switch v, cached := s.cache.check(req.SenderNodeID, req.MessageID, req.Nonce); v {
	case verdictReplay:
		s.reply(conn, &req, ErrReplay, nil)
		return
	case verdictRetransmit:
		// Same result without re-execution; see replay.go.
		_, _ = conn.Write(append(cached, '\n'))
		return
	}

	var payload any
	switch req.Cmd {
	case CmdOperationJournal:
		var in OperationJournalPayload
		if err := json.Unmarshal(req.Payload, &in); err != nil || in.OperationID == "" {
			s.reply(conn, &req, ErrBadRequest, nil)
			return
		}
		if s.cfg.JournalSource == nil {
			s.reply(conn, &req, ErrJournal, nil)
			return
		}
		j, err := s.cfg.JournalSource(in.OperationID)
		if err != nil {
			s.reply(conn, &req, ErrJournal, nil)
			return
		}
		payload = j
	case CmdInventory:
		if s.cfg.InventorySource == nil {
			s.reply(conn, &req, ErrInventory, nil)
			return
		}
		inv, err := s.cfg.InventorySource()
		if err != nil {
			// An inventory that could not be taken is a refusal, not an empty reply: from an empty reply the
			// human would conclude the peer has no data and wipe it.
			s.reply(conn, &req, ErrInventory, nil)
			return
		}
		payload = inv
	default:
		status, hello := s.cfg.StatusSource()
		switch req.Cmd {
		case CmdHello:
			payload = hello
		case CmdStatus:
			payload = status
		}
	}
	raw := s.reply(conn, &req, "", payload)
	if raw != nil {
		s.cache.remember(req.SenderNodeID, req.MessageID, req.Nonce, raw)
	}
}

// handleInit runs a pair-creation step. It bypasses the durable registry, which relies on the epoch, a
// property of a pair that does not exist yet. Retries are safe because each step is safe on its own, not
// because something remembered it.
func (s *Server) handleInit(conn net.Conn, req *Request) {
	// Extend the connection deadline BEFORE executing: it was set for observation commands, and this step may
	// take minutes.
	timeout := s.cfg.InitTimeout
	if timeout <= 0 {
		timeout = 15 * time.Minute
	}
	_ = conn.SetDeadline(s.now().Add(timeout))
	if s.cfg.InitHandler == nil {
		s.reply(conn, req, ErrNoInit, nil)
		return
	}
	res, err := s.cfg.InitHandler(req.Cmd, req.Payload)
	if err != nil {
		// The reason goes to the peer as the rejection code: it shows it to the human creating the pair, and
		// "something went wrong" mid node rebuild is a useless answer.
		s.reply(conn, req, err.Error(), nil)
		return
	}
	s.reply(conn, req, "", res)
}

// handleMutation handles a state-changing command.
//
// The order is strict: first proof of authority (gate), then durable registration together with the action.
// No check runs AFTER the write, and no write happens without the ledger.
func (s *Server) handleMutation(conn net.Conn, req *Request) {
	// Fail closed on EACH required part separately. Previously a missing Gate just skipped the check, so a
	// forgotten init in one place silently turned the whole path fail-open.
	if s.cfg.Ledger == nil {
		s.reply(conn, req, ErrLedger, nil)
		return
	}
	if req.RequestHash == "" || req.RequestHash != RequestHash(req.Cmd, req.Epoch, req.RecipientNodeID, req.PayloadHash) {
		s.reply(conn, req, ErrBadRequest, nil) // the meaning fingerprint must match the content
		return
	}
	// A RETRY is answered BEFORE the gate.
	//
	// The gate asks "may this be done NOW", while a retry does nothing: it asks how an already completed action
	// ended. This matters where a mutation legitimately changes the world so a second run would be refused:
	// dismantling wipes the epoch and the right to be active, so a lost reply to a successful release_pair would
	// hit "not now" forever, and the durable dedup that all of this exists for would block itself.
	replayEntry := LedgerEntry{Sender: req.SenderNodeID, MessageID: req.MessageID, Cmd: req.Cmd,
		Epoch: req.Epoch, RequestHash: req.RequestHash}
	if done, ok, _ := s.cfg.Ledger.Done(context.Background(), replayEntry); ok {
		// The retry reply is re-signed and bound to the current attempt's nonce, as in the normal path: the
		// stored bytes of the old reply were bound to the previous nonce.
		s.replyRaw(conn, req, done.Code, done.Payload)
		return
	}
	// Executor and gate are required ONLY for a new mutation.
	//
	// They must not be checked before reading the registry: after dismantling, a node brings the channel up on
	// trust alone, without gate or executor, since there is nothing left to execute. But it must still return the
	// stored result; otherwise retrying a command whose reply was lost BEFORE a manager restart would get "no
	// registry" while a DONE record sits in that very registry. That retry is why records are kept.
	if s.cfg.Executor == nil {
		s.reply(conn, req, ErrLedger, nil)
		return
	}
	if s.cfg.Gate == nil {
		s.reply(conn, req, ErrNoGate, nil)
		return
	}
	if ok, code := s.cfg.Gate(req); !ok {
		s.reply(conn, req, orCode(code, ErrNotAllowedNow), nil)
		return
	}
	entry := LedgerEntry{Sender: req.SenderNodeID, MessageID: req.MessageID, Cmd: req.Cmd,
		Epoch: req.Epoch, RequestHash: req.RequestHash}
	res, replay, err := s.cfg.Ledger.Execute(context.Background(), entry,
		func(ctx context.Context, tx *sql.Tx) (LedgerResult, error) { return s.cfg.Executor(ctx, tx, req) })
	if err != nil {
		code := ErrLedger
		if errors.Is(err, ErrRequestConflict) {
			code = ErrIDConflict
		}
		s.reply(conn, req, code, nil)
		return
	}
	// A retry reply is re-signed and bound to the current attempt's nonce: the stored bytes of the old reply
	// were bound to the previous nonce and the client would reject them.
	_ = replay
	s.replyRaw(conn, req, res.Code, res.Payload)
}

func orCode(code, def string) string {
	if code == "" {
		return def
	}
	return code
}

// validate runs all pre-execution checks. Order matters: version and identity first, then time and command.
func (s *Server) validate(req *Request) string {
	if req.ProtocolVersion != Version {
		return ErrVersion
	}
	if req.SenderNodeID != s.cfg.PeerNodeID {
		return ErrIdentity
	}
	if req.RecipientNodeID != "" && req.RecipientNodeID != s.cfg.NodeID {
		return ErrRecipient // not addressed to us: must not run even with a valid signature
	}
	if req.MessageID == "" || req.Nonce == "" {
		return ErrBadRequest
	}
	drift := s.now().Unix() - req.TS
	if drift < 0 {
		drift = -drift
	}
	if time.Duration(drift)*time.Second > s.cfg.Window {
		return ErrTimestamp
	}
	if !allowedCommands[req.Cmd] {
		return ErrCommand
	}
	if PayloadHash(req.Payload) != req.PayloadHash {
		return ErrPayloadHash // we are talking about different payloads: stop here
	}
	return ""
}

// reply builds, signs and sends a response, returning the bytes sent (for the retransmit cache).
func (s *Server) reply(conn net.Conn, req *Request, errCode string, payload any) []byte {
	raw, hash, err := marshalPayload(payload)
	if err != nil {
		return nil
	}
	nonce, err := randomHex()
	if err != nil {
		return nil
	}
	resp := Response{
		ProtocolVersion: Version,
		SenderNodeID:    s.cfg.NodeID,
		TS:              s.now().Unix(),
		Nonce:           nonce,
		OK:              errCode == "",
		Error:           errCode,
		Payload:         raw,
		PayloadHash:     hash,
	}
	// Bind the reply to the request only for an AUTHENTICATED request: before signature verification its
	// fields are untrusted and must not go into a signed reply.
	if req != nil {
		resp.RecipientNodeID = req.SenderNodeID
		resp.RequestMessageID = req.MessageID
		resp.RequestNonce = req.Nonce
	}
	out, err := seal(s.cfg.Secret, resp)
	if err != nil {
		return nil
	}
	out = append(out, '\n')
	if _, err := conn.Write(out); err != nil {
		return nil
	}
	return out
}

// replyRaw is like reply, but with an already serialized payload (from the ledger).
func (s *Server) replyRaw(conn net.Conn, req *Request, errCode string, payload []byte) {
	nonce, err := randomHex()
	if err != nil {
		return
	}
	resp := Response{
		ProtocolVersion: Version, SenderNodeID: s.cfg.NodeID, TS: s.now().Unix(), Nonce: nonce,
		OK: errCode == "", Error: errCode, Payload: payload, PayloadHash: PayloadHash(payload),
	}
	if req != nil {
		resp.RecipientNodeID, resp.RequestMessageID, resp.RequestNonce = req.SenderNodeID, req.MessageID, req.Nonce
	}
	out, err := seal(s.cfg.Secret, resp)
	if err != nil {
		return
	}
	_, _ = conn.Write(append(out, '\n'))
}

// DecodeResponsePayload is a helper for clients and tests.
func DecodeResponsePayload(resp *Response, dst any) error {
	if len(resp.Payload) == 0 {
		return fmt.Errorf("empty payload")
	}
	return json.Unmarshal(resp.Payload, dst)
}
