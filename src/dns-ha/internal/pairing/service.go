package pairing

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"
)

// Service is the whole pairing of a node: both handling peer commands and human actions (create, join,
// approve, reset).
//
// Everything that touches the world sits behind ports: the durable trust record (TrustStore), the key file
// (KeyStore) and the network (Transport). The order of actions, which is the substance here, is thus testable
// without MariaDB, root or sockets.
type Service struct {
	Local     Local
	Trust     TrustStore
	Keys      KeyStore
	Transport Transport
	Window    *Window

	// WindowTTL is how long an open window lives. Pairing takes a minute; ten minutes is slack for walking
	// over to the second server, not an operating mode.
	WindowTTL time.Duration
}

// Local is what the node knows about itself. Identity is the UUID only; hostname is sent to the peer as a
// claim and never used in any check.
type Local struct {
	NodeID   string
	Hostname string
	// Port is where this node listens on the peer channel. The peer connects to the OBSERVED address with
	// this port: the claimed address may point at an interface not visible from the other side.
	Port int
}

// TrustRecord is the durable fact "we are paired with this node".
type TrustRecord struct {
	State        string // committing | trusted
	PairingID    string
	PeerNodeID   string
	PeerEndpoint string
	KeyFP        string
	TranscriptFP string
	ApprovedBy   string
}

// Trust states.
const (
	StateCommitting = "committing"
	StateTrusted    = "trusted"
)

// TrustStore holds the trust record in the local dns_ha database.
type TrustStore interface {
	Load(ctx context.Context) (*TrustRecord, error)
	Save(ctx context.Context, r TrustRecord) error
	Promote(ctx context.Context, pairingID string) error
	Delete(ctx context.Context) error
}

// KeyStore is the pair secret on disk. The privileged agent writes and removes it; the manager reads it itself.
type KeyStore interface {
	Install(ctx context.Context, keyHex, fp string) error
	Remove(ctx context.Context, fp string) error
	// Read returns the hex content of the installed key. A missing key is an EMPTY string with no error:
	// "no key" is the normal state of a standalone node, while an error means "could not read". The two must
	// not be confused, because on the former the node decides it is free to pair.
	Read(ctx context.Context) (string, error)
}

// Handle parses one line from the peer and returns the reply line. Protocol errors are REPLIES with a typed
// code, not silence: the peer must learn why it was refused.
func (s *Service) Handle(ctx context.Context, line []byte, observedFrom string) []byte {
	var head struct {
		Cmd string `json:"cmd"`
	}
	if err := json.Unmarshal(line, &head); err != nil {
		return reply(Ack{OK: false, Error: ErrState})
	}
	switch head.Cmd {
	case CmdHello:
		var m Hello
		if err := json.Unmarshal(line, &m); err != nil {
			return reply(HelloAck{OK: false, Error: ErrState})
		}
		return reply(s.hello(ctx, m, observedFrom))
	case CmdRequest:
		var m Request
		if err := json.Unmarshal(line, &m); err != nil {
			return reply(RequestAck{OK: false, Error: ErrState})
		}
		return reply(s.request(m))
	case CmdCommit:
		var m Commit
		if err := json.Unmarshal(line, &m); err != nil {
			return reply(Ack{OK: false, Error: ErrState})
		}
		return reply(s.commit(ctx, m))
	case CmdComplete:
		var m Complete
		if err := json.Unmarshal(line, &m); err != nil {
			return reply(Ack{OK: false, Error: ErrState})
		}
		return reply(s.complete(ctx, m))
	}
	return reply(Ack{OK: false, Error: ErrState})
}

// hello is the responder's first step: it picks the attempt ID and commits to its key.
func (s *Service) hello(ctx context.Context, m Hello, observedFrom string) HelloAck {
	if m.NodeID == "" || m.NodeID == s.Local.NodeID {
		// Our own UUID on the other end means a cloned node or a connection to ourselves; neither is pairing.
		return HelloAck{OK: false, Error: ErrWrongPeer}
	}
	if err := s.mustBeUnpaired(ctx); err != nil {
		// The peer gets a CODE, not text: it tells "already paired" from "not now" by machine, and details of an
		// unavailable database are this node's and its operator's business.
		return HelloAck{OK: false, Error: codeOf(err)}
	}
	pid, err := NewPairingID()
	if err != nil {
		return HelloAck{OK: false, Error: ErrState}
	}
	sess, err := s.newSession(RoleResponder, pid, m.NodeID, m.Hostname, endpointOf(observedFrom, m.Endpoint))
	if err != nil {
		return HelloAck{OK: false, Error: ErrState}
	}
	sess.ObservedFrom = observedFrom
	sess.Transcript = Transcript{PairingID: pid, InitiatorID: m.NodeID, ResponderID: s.Local.NodeID}
	if err := s.Window.Begin(sess, s.ttl()); err != nil {
		return HelloAck{OK: false, Error: err.Error()}
	}
	// Take the attempt ID from the ACCEPTED session: on a retried hello (lost reply) the window keeps the
	// previous one, and the reply must carry its values, not freshly generated ones.
	_, _, cur := s.Window.State()
	if cur == nil {
		return HelloAck{OK: false, Error: ErrClosed}
	}
	return HelloAck{OK: true, PairingID: cur.PairingID, NodeID: s.Local.NodeID, Hostname: s.Local.Hostname,
		Commitment: Commitment(cur.Ephemeral.Public(), cur.Nonce, cur.PairingID, RoleResponder)}
}

// request handles the initiator's reveal; the responder reveals in reply. Both then independently compute
// the same six digits.
func (s *Service) request(m Request) RequestAck {
	pub, err1 := hex.DecodeString(m.PubKey)
	nonce, err2 := hex.DecodeString(m.Nonce)
	if err1 != nil || err2 != nil {
		return RequestAck{OK: false, Error: ErrMismatch}
	}
	var out RequestAck
	err := s.Window.Update(m.PairingID, func(sess *Session) error {
		if sess.PeerNodeID != m.NodeID {
			return fmt.Errorf("%s", ErrWrongPeer)
		}
		if sess.Step != StepAwaitingReveal {
			return fmt.Errorf("%s", ErrState)
		}
		if err := sess.Reveal(pub, nonce, RoleInitiator); err != nil {
			return err
		}
		out = RequestAck{OK: true, NodeID: s.Local.NodeID,
			PubKey: hex.EncodeToString(sess.Ephemeral.Public()), Nonce: hex.EncodeToString(sess.Nonce)}
		return nil
	})
	if err != nil {
		return RequestAck{OK: false, Error: err.Error()}
	}
	return out
}

// commit: the human approved on the OTHER side. Verify the signature, record the trust, and only then install
// the key. "Record first, key second" is the only protection against an orphaned key file after a crash.
func (s *Service) commit(ctx context.Context, m Commit) Ack {
	if m.RecipientID != s.Local.NodeID {
		return Ack{OK: false, Error: ErrWrongPeer}
	}
	var (
		keys Keys
		rec  TrustRecord
	)
	err := s.Window.Update(m.PairingID, func(sess *Session) error {
		if sess.PeerNodeID != m.SenderID {
			return fmt.Errorf("%s", ErrWrongPeer)
		}
		k, err := sess.AcceptCommit(m.SenderID, m.RecipientID, m.KeyFP, m.MAC)
		if err != nil {
			return err
		}
		keys = k
		rec = TrustRecord{State: StateCommitting, PairingID: sess.PairingID, PeerNodeID: sess.PeerNodeID,
			PeerEndpoint: sess.PeerEndpoint, KeyFP: k.PeerKeyFP, TranscriptFP: sess.TranscriptFP()}
		return nil
	})
	if err != nil {
		return Ack{OK: false, Error: err.Error()}
	}
	if err := s.persist(ctx, rec, keys); err != nil {
		return Ack{OK: false, Error: err.Error()}
	}
	// The counter-signature proves our key is the same; it tells the peer it may complete.
	return Ack{OK: true, MAC: SignCommit(keys.Session, m.PairingID, mustHash(rec.TranscriptFP),
		s.Local.NodeID, m.SenderID, keys.PeerKeyFP)}
}

// complete brings the pair to TRUSTED. Signed with the PERMANENT key, so it works after a restart when the
// ephemeral keys are gone. Idempotent: a retry from an already trusted peer succeeds, otherwise a lost reply
// would leave the other side in committing forever.
func (s *Service) complete(ctx context.Context, m Complete) Ack {
	if m.RecipientID != s.Local.NodeID {
		return Ack{OK: false, Error: ErrWrongPeer}
	}
	rec, err := s.Trust.Load(ctx)
	if err != nil {
		return Ack{OK: false, Error: ErrState}
	}
	if rec == nil || rec.PairingID != m.PairingID || rec.PeerNodeID != m.SenderID {
		return Ack{OK: false, Error: ErrWrongPeer}
	}
	key, err := s.Keys.Read(ctx)
	if err != nil || key == "" {
		return Ack{OK: false, Error: ErrState}
	}
	hash := mustHash(rec.TranscriptFP)
	if !VerifyComplete([]byte(key), m.PairingID, hash, m.SenderID, m.RecipientID, m.MAC) {
		return Ack{OK: false, Error: ErrBadMAC}
	}
	if rec.State != StateTrusted {
		if err := s.Trust.Promote(ctx, m.PairingID); err != nil {
			return Ack{OK: false, Error: ErrState}
		}
	}
	s.Window.Close()
	return Ack{OK: true, MAC: SignComplete([]byte(key), m.PairingID, hash, s.Local.NodeID, m.SenderID)}
}

// Create opens the pairing window. A fresh node does NOT expose the pairing interface: until this action all
// pairing commands are rejected.
func (s *Service) Create(ctx context.Context) (time.Time, error) {
	if err := s.mustBeUnpaired(ctx); err != nil {
		return time.Time{}, err
	}
	return s.Window.Open(s.ttl()), nil
}

// Join is the requesting side: hello, reveal, show the code. It then waits for human approval ON THE OTHER
// side: the decision belongs to whoever opened the window.
func (s *Service) Join(ctx context.Context, addr string) (string, error) {
	if err := s.mustBeUnpaired(ctx); err != nil {
		return "", err
	}
	addr = withPort(addr, s.Local.Port)

	var ack HelloAck
	hello := Hello{Cmd: CmdHello, NodeID: s.Local.NodeID, Hostname: s.Local.Hostname,
		Endpoint: fmt.Sprintf(":%d", s.Local.Port)}
	if err := s.Transport.Send(ctx, addr, hello, &ack); err != nil {
		return "", err
	}
	if !ack.OK {
		return "", fmt.Errorf("%s", orDefault(ack.Error, ErrState))
	}
	if ack.NodeID == "" || ack.NodeID == s.Local.NodeID {
		return "", fmt.Errorf("%s", ErrWrongPeer)
	}

	sess, err := s.newSession(RoleInitiator, ack.PairingID, ack.NodeID, ack.Hostname, addr)
	if err != nil {
		return "", err
	}
	sess.PeerCommitment = ack.Commitment
	sess.Transcript = Transcript{PairingID: ack.PairingID, InitiatorID: s.Local.NodeID, ResponderID: ack.NodeID}
	// The window opens HERE: on the initiator it is opened not by a button but by the "join pair" action
	// itself, which is the permission to accept the incoming commit.
	s.Window.Open(s.ttl())
	if err := s.Window.Begin(sess, s.ttl()); err != nil {
		return "", err
	}

	var rack RequestAck
	req := Request{Cmd: CmdRequest, PairingID: ack.PairingID, NodeID: s.Local.NodeID,
		PubKey: hex.EncodeToString(sess.Ephemeral.Public()), Nonce: hex.EncodeToString(sess.Nonce)}
	if err := s.Transport.Send(ctx, addr, req, &rack); err != nil {
		return "", err
	}
	if !rack.OK {
		return "", fmt.Errorf("%s", orDefault(rack.Error, ErrState))
	}
	pub, err1 := hex.DecodeString(rack.PubKey)
	nonce, err2 := hex.DecodeString(rack.Nonce)
	if err1 != nil || err2 != nil {
		return "", fmt.Errorf("%s", ErrMismatch)
	}
	var code string
	err = s.Window.Update(ack.PairingID, func(sess *Session) error {
		if err := sess.Reveal(pub, nonce, RoleResponder); err != nil {
			return err
		}
		code = sess.Code
		return nil
	})
	if err != nil {
		return "", err
	}
	return code, nil
}

// Approve records that the human compared the code on the window side. Keys come into existence only here;
// before that the permanent secret is not computed at all.
func (s *Service) Approve(ctx context.Context, by string) error {
	_, _, cur := s.Window.State()
	if cur == nil {
		return fmt.Errorf("%s", ErrClosed)
	}
	if cur.Role != RoleResponder {
		// Only the window opener approves. The initiator asked to join itself, and its "yes" adds nothing to
		// the receiving side's decision.
		return fmt.Errorf("%s", ErrState)
	}
	var (
		keys Keys
		rec  TrustRecord
		peer string
	)
	err := s.Window.Update(cur.PairingID, func(sess *Session) error {
		k, err := sess.Approve()
		if err != nil {
			return err
		}
		keys, peer = k, sess.PeerNodeID
		rec = TrustRecord{State: StateCommitting, PairingID: sess.PairingID, PeerNodeID: sess.PeerNodeID,
			PeerEndpoint: sess.PeerEndpoint, KeyFP: k.PeerKeyFP, TranscriptFP: sess.TranscriptFP(),
			ApprovedBy: by}
		return nil
	})
	if err != nil {
		return err
	}
	if err := s.persist(ctx, rec, keys); err != nil {
		return err
	}

	var ack Ack
	msg := Commit{Cmd: CmdCommit, PairingID: rec.PairingID, SenderID: s.Local.NodeID, RecipientID: peer,
		KeyFP: keys.PeerKeyFP,
		MAC:   SignCommit(keys.Session, rec.PairingID, mustHash(rec.TranscriptFP), s.Local.NodeID, peer, keys.PeerKeyFP)}
	if err := s.Transport.Send(ctx, rec.PeerEndpoint, msg, &ack); err != nil {
		return err
	}
	if !ack.OK {
		return fmt.Errorf("%s", orDefault(ack.Error, ErrState))
	}
	// The counter-signature must be verified: without it "the peer installed the key" is just the network's word.
	if !VerifyCommit(keys.Session, rec.PairingID, mustHash(rec.TranscriptFP), peer, s.Local.NodeID,
		keys.PeerKeyFP, ack.MAC) {
		return fmt.Errorf("%s", ErrBadMAC)
	}
	return s.Finish(ctx)
}

// Finish brings pairing to TRUSTED and may be repeated as often as needed: the only concession to network
// loss. Called after approval and from the watch loop while the state is committing.
func (s *Service) Finish(ctx context.Context) error {
	rec, err := s.Trust.Load(ctx)
	if err != nil {
		return err
	}
	if rec == nil || rec.State == StateTrusted {
		return nil
	}
	key, err := s.Keys.Read(ctx)
	if err != nil {
		return err
	}
	if key == "" {
		return fmt.Errorf("%s: the channel key is not installed — nothing to finish", ErrState)
	}
	hash := mustHash(rec.TranscriptFP)
	msg := Complete{Cmd: CmdComplete, PairingID: rec.PairingID, SenderID: s.Local.NodeID,
		RecipientID: rec.PeerNodeID,
		MAC:         SignComplete([]byte(key), rec.PairingID, hash, s.Local.NodeID, rec.PeerNodeID)}
	var ack Ack
	if err := s.Transport.Send(ctx, rec.PeerEndpoint, msg, &ack); err != nil {
		return err
	}
	if !ack.OK {
		return fmt.Errorf("%s", orDefault(ack.Error, ErrState))
	}
	if !VerifyComplete([]byte(key), rec.PairingID, hash, rec.PeerNodeID, s.Local.NodeID, ack.MAC) {
		return fmt.Errorf("%s", ErrBadMAC)
	}
	if err := s.Trust.Promote(ctx, rec.PairingID); err != nil {
		return err
	}
	s.Window.Close()
	return nil
}

// Reject: the human did not recognize the code. The attempt is forgotten; both nodes stay exactly where they were.
func (s *Service) Reject() { s.Window.Close() }

// Reset undoes an UNFINISHED pairing: remove the key if it was installed, then the record. The order is the
// reverse of installation, otherwise a key file nobody knows about would remain.
//
// Completed trust is not removed this way: it needs an explicit dismantle (allowTrusted), because that breaks
// a working pair's link rather than cleaning up garbage.
func (s *Service) Reset(ctx context.Context, allowTrusted bool) error {
	s.Window.Close()
	rec, err := s.Trust.Load(ctx)
	if err != nil {
		return err
	}
	if rec == nil {
		return nil
	}
	if rec.State == StateTrusted && !allowTrusted {
		return fmt.Errorf("%s", ErrAlreadySet)
	}
	if err := s.Keys.Remove(ctx, rec.KeyFP); err != nil {
		return err
	}
	return s.Trust.Delete(ctx)
}

// View is the pairing state for humans, as shown by the panel and CLI.
type View struct {
	State        string    `json:"state"` // unpaired | open | pending | committing | trusted
	Code         string    `json:"code,omitempty"`
	Role         string    `json:"role,omitempty"`
	PairingID    string    `json:"pairing_id,omitempty"`
	PeerNodeID   string    `json:"peer_node_id,omitempty"`
	PeerHostname string    `json:"peer_hostname,omitempty"` // CLAIMED by the peer
	PeerAddress  string    `json:"peer_address,omitempty"`  // OBSERVED by us
	KeyFP        string    `json:"key_fp,omitempty"`
	ApprovedBy   string    `json:"approved_by,omitempty"`
	Expires      time.Time `json:"expires,omitempty"`
}

// Status reports what to show the human. Durable state wins over memory: trust survives a restart, an attempt does not.
func (s *Service) Status(ctx context.Context) (View, error) {
	rec, err := s.Trust.Load(ctx)
	if err != nil {
		return View{}, err
	}
	if rec != nil {
		return View{State: rec.State, PairingID: rec.PairingID, PeerNodeID: rec.PeerNodeID,
			PeerAddress: rec.PeerEndpoint, KeyFP: rec.KeyFP, ApprovedBy: rec.ApprovedBy}, nil
	}
	open, expires, sess := s.Window.State()
	if !open {
		return View{State: "unpaired"}, nil
	}
	v := View{State: "open", Expires: expires}
	if sess != nil {
		v.Role, v.PairingID = sess.Role, sess.PairingID
		v.PeerNodeID, v.PeerHostname, v.PeerAddress = sess.PeerNodeID, sess.PeerHostname, sess.ObservedFrom
		if v.PeerAddress == "" {
			v.PeerAddress = sess.PeerEndpoint
		}
		if sess.Step == StepAwaitingApproval {
			v.State, v.Code = "pending", sess.Code
		}
	}
	return v, nil
}

// Trusted reports whether the node has a trusted peer. The dispatcher uses it to decide which protocol to
// accept on the shared port.
func (s *Service) Trusted(ctx context.Context) (*TrustRecord, error) { return s.Trust.Load(ctx) }

// persist writes the durable part of pairing in the only allowed order: first "we trust this node, here is
// the key fingerprint", then the key itself.
func (s *Service) persist(ctx context.Context, rec TrustRecord, keys Keys) error {
	if err := s.Trust.Save(ctx, rec); err != nil {
		return err
	}
	return s.Keys.Install(ctx, keys.Hex(), keys.PeerKeyFP)
}

// mustBeUnpaired refuses pairing on a node that already trusts someone. Only an explicit dismantle returns it
// to UNPAIRED, never an unreachable peer or a lost key.
//
// An unreadable trust record is also a refusal: pairing must not start without knowing whether the node is
// paired. The error is returned as is, because "database unavailable" and "already paired" are very
// different news for the human at the terminal.
func (s *Service) mustBeUnpaired(ctx context.Context) error {
	rec, err := s.Trust.Load(ctx)
	if err != nil {
		return err
	}
	if rec != nil {
		return fmt.Errorf("%s", ErrAlreadySet)
	}
	// An installed pair secret means the same even without a trust record, as on pairs created before pairing
	// existed (key placed by hand). Without this check the node would agree to pair, hit write-once at key
	// installation, and leave a trust record for a peer it is not actually paired with.
	key, err := s.Keys.Read(ctx)
	if err != nil {
		return err
	}
	if key != "" {
		return fmt.Errorf("%s", ErrAlreadySet)
	}
	return nil
}

// codeOf maps an error to a rejection code for the peer. Our codes go as is, anything else is "not now": the
// peer cannot do anything about our broken database anyway.
func codeOf(err error) string {
	switch msg := err.Error(); msg {
	case ErrAlreadySet, ErrBusy, ErrClosed, ErrExpired, ErrMismatch, ErrBadMAC, ErrWrongPeer, ErrState:
		return msg
	}
	return ErrState
}

func (s *Service) newSession(role, pairingID, peerID, peerHost, peerEndpoint string) (*Session, error) {
	e, err := NewEphemeral()
	if err != nil {
		return nil, err
	}
	n, err := Nonce()
	if err != nil {
		return nil, err
	}
	return &Session{PairingID: pairingID, Step: StepAwaitingReveal, Role: role, PeerNodeID: peerID,
		PeerHostname: peerHost, PeerEndpoint: peerEndpoint, Ephemeral: e, Nonce: n}, nil
}

func (s *Service) ttl() time.Duration {
	if s.WindowTTL > 0 {
		return s.WindowTTL
	}
	return 10 * time.Minute
}

func reply(v any) []byte {
	line, err := json.Marshal(v)
	if err != nil {
		return []byte(`{"ok":false,"error":"` + ErrState + `"}`)
	}
	return line
}

// mustHash decodes the transcript fingerprint from the durable record. We write it ourselves and it is always
// hex; a bad value means a corrupt record, and a MAC with an empty hash will not match, i.e. refusal, not
// silent acceptance.
func mustHash(fp string) []byte {
	b, err := hex.DecodeString(fp)
	if err != nil {
		return nil
	}
	return b
}

// endpointOf is the address WE can call the peer on: observed host plus claimed port. The claimed host is not
// used: it may point at an interface not visible from here, while the observed one is where the peer came from.
func endpointOf(observed, claimed string) string {
	host, _, err := net.SplitHostPort(observed)
	if err != nil {
		host = observed
	}
	port := ""
	if claimed != "" {
		if _, p, err := net.SplitHostPort(claimed); err == nil {
			port = p
		}
	}
	if port == "" {
		port = "7901"
	}
	return net.JoinHostPort(host, port)
}

// withPort accepts the peer address either way: "192.0.2.12" or "192.0.2.12:7901".
func withPort(addr string, def int) string {
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	if strings.Contains(addr, ":") { // IPv6 without brackets
		return net.JoinHostPort(addr, fmt.Sprint(def))
	}
	return fmt.Sprintf("%s:%d", addr, def)
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
