package pairing

import (
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// Session is the in-memory state of ONE pairing in the manager.
//
// It lives only until human confirmation: a restart closes the window and the admin starts over. Nothing is
// durable on purpose: pairing takes a minute, and recovering it is harder than repeating it.
//
// Only ONE attempt runs at a time; no list of candidates or picker is needed, because the admin opens the
// window to pair one specific second node.

// Step is the stage the attempt is at.
type Step string

const (
	StepAwaitingReveal   Step = "awaiting_reveal"   // commitments received, awaiting reveal
	StepAwaitingApproval Step = "awaiting_approval" // code computed, awaiting the human
	StepCommitting       Step = "committing"        // human confirmed, installing the key
)

type Session struct {
	PairingID string
	Step      Step
	// Role is who we are in this attempt: the window opener (responder) or the requester (initiator).
	Role string

	PeerNodeID   string
	PeerHostname string // claimed by the peer; shown to the human, never used in any check
	PeerEndpoint string
	// ObservedFrom is the address the connection actually came from, shown SEPARATELY from the claimed
	// one: it is our observation, not what we were told.
	ObservedFrom string

	// PeerCommitment is the RESPONDER's commitment when we are the initiator. Empty on the responder: the
	// initiator promised nothing, it is bound by revealing first.
	PeerCommitment string
	Ephemeral      *Ephemeral
	Nonce          []byte

	Transcript Transcript
	Code       string // six digits; set after the reveal

	Expires time.Time

	// shared is the X25519 shared secret. Unexported: keys are derived from it only after human
	// confirmation (see Approve).
	shared []byte
}

// Window is the node's pairing window: closed by default, opened by an explicit human action.
type Window struct {
	mu      sync.Mutex
	open    bool
	expires time.Time
	sess    *Session
	now     func() time.Time
}

func NewWindow() *Window { return &Window{now: time.Now} }

// SetClock is for tests: pairing state is time-dependent (the window lives for minutes), and testing that by
// waiting in real time is pointless.
func (w *Window) SetClock(f func() time.Time) { w.mu.Lock(); w.now = f; w.mu.Unlock() }

// Open opens the window for ttl. Calling it again extends the window and drops any unfinished attempt: an
// admin who clicks "create pair" again expects a clean start.
func (w *Window) Open(ttl time.Duration) time.Time {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.open = true
	w.expires = w.now().Add(ttl)
	w.sess = nil
	return w.expires
}

// Close closes the window and forgets the attempt.
func (w *Window) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.open, w.sess = false, nil
}

// State returns what to show the human and what to answer the peer.
func (w *Window) State() (open bool, expires time.Time, s *Session) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.expireLocked()
	if w.sess == nil {
		return w.open, w.expires, nil
	}
	copy := *w.sess
	return w.open, w.expires, &copy
}

// expireLocked closes the window on timeout. Checked on every access rather than by a timer: a timer is one
// more goroutine and one more way to drift from reality.
func (w *Window) expireLocked() {
	if !w.open {
		return
	}
	if w.now().After(w.expires) {
		w.open, w.sess = false, nil
	}
	// An attempt stuck before confirmation lives no longer than the window.
	if w.sess != nil && w.sess.Step != StepCommitting && w.now().After(w.sess.Expires) {
		w.sess = nil
	}
}

// Begin accepts the peer's request and creates an attempt, or returns a typed rejection if the window is
// closed or busy.
func (w *Window) Begin(s *Session, ttl time.Duration) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.expireLocked()
	if !w.open {
		return fmt.Errorf("%s", ErrClosed)
	}
	if w.sess != nil {
		// Idempotent by attempt ID: a retry of the same request (lost reply) must not look like a second
		// candidate.
		if w.sess.PairingID == s.PairingID && w.sess.PeerNodeID == s.PeerNodeID {
			return nil
		}
		return fmt.Errorf("%s", ErrBusy)
	}
	s.Expires = w.now().Add(ttl)
	w.sess = s
	return nil
}

// Update applies f to the current attempt after checking it is the same one.
func (w *Window) Update(pairingID string, f func(*Session) error) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.expireLocked()
	if w.sess == nil {
		return fmt.Errorf("%s", ErrClosed)
	}
	if w.sess.PairingID != pairingID {
		return fmt.Errorf("%s", ErrWrongPeer)
	}
	return f(w.sess)
}

// Reveal is the second step: verify the peer's commitment, compute the shared secret and the code.
//
// The commitment check is what prevents code grinding: a value other than the committed one cannot be
// revealed.
func (s *Session) Reveal(peerPub, peerNonce []byte, peerRole string) error {
	// The commitment is checked where it was given: the initiator verifies the responder's key. The responder
	// got no commitment from the initiator; the initiator is bound by revealing before seeing the responder's key.
	if s.PeerCommitment != "" && !VerifyCommitment(s.PeerCommitment, peerPub, peerNonce, s.PairingID, peerRole) {
		return fmt.Errorf("%s", ErrMismatch)
	}
	shared, err := s.Ephemeral.Shared(peerPub)
	if err != nil {
		return err
	}
	if s.Role == RoleResponder {
		s.Transcript.InitiatorPub, s.Transcript.InitiatorNonce = peerPub, peerNonce
		s.Transcript.ResponderPub, s.Transcript.ResponderNonce = s.Ephemeral.Public(), s.Nonce
	} else {
		s.Transcript.ResponderPub, s.Transcript.ResponderNonce = peerPub, peerNonce
		s.Transcript.InitiatorPub, s.Transcript.InitiatorNonce = s.Ephemeral.Public(), s.Nonce
	}
	code, err := DeriveCode(shared, s.Transcript)
	if err != nil {
		return err
	}
	s.Code, s.Step = code, StepAwaitingApproval
	// Keep the shared secret in the session: keys are derived from it ONLY after human confirmation.
	s.shared = shared
	return nil
}

// AcceptCommit handles the receiving side of the commit: derive keys, VERIFY the signature, and only then
// advance the step. The reverse order would have the node consider itself pairing with someone whose
// signature it has not checked.
func (s *Session) AcceptCommit(senderID, recipientID, keyFP, mac string) (Keys, error) {
	if s.Step != StepAwaitingApproval {
		return Keys{}, fmt.Errorf("%s", ErrState)
	}
	k, err := DeriveKeys(s.shared, s.Transcript)
	if err != nil {
		return Keys{}, err
	}
	if k.PeerKeyFP != keyFP {
		return Keys{}, fmt.Errorf("%s", ErrMismatch)
	}
	if !VerifyCommit(k.Session, s.PairingID, s.Transcript.Hash(), senderID, recipientID, keyFP, mac) {
		return Keys{}, fmt.Errorf("%s", ErrBadMAC)
	}
	s.Step = StepCommitting
	return k, nil
}

// Approve records that the human compared the code. Keys come into existence only here.
func (s *Session) Approve() (Keys, error) {
	if s.Step != StepAwaitingApproval {
		return Keys{}, fmt.Errorf("%s", ErrState)
	}
	k, err := DeriveKeys(s.shared, s.Transcript)
	if err != nil {
		return Keys{}, err
	}
	s.Step = StepCommitting
	return k, nil
}

// TranscriptFP is the transcript fingerprint, stored with the trust so the completion can be signed with
// the permanent key even after a restart.
func (s *Session) TranscriptFP() string { return hex.EncodeToString(s.Transcript.Hash()) }
