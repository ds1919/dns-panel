package pairing

// Pairing messages. They share port 7901 with the regular pair protocol but are accepted only while pairing;
// the dispatcher decides that from local state, not from the packet contents.
//
// The format is deliberately flat: no field versions, extensions or optional parts. This is a one-off
// exchange between two processes of the same version; anything "for the future" would only add ways to fail.

const (
	CmdHello    = "pair_hello"    // introduce: who is asking; the reply carries the responder's commitment
	CmdRequest  = "pair_request"  // reveal keys; afterwards both sides compute the code themselves
	CmdCommit   = "pair_commit"   // after human confirmation: install the key (signed with the ephemeral key)
	CmdComplete = "pair_complete" // bring to TRUSTED (signed with the permanent key); idempotent
)

// Hello is the first step: the initiator announces itself. It carries NO commitment on purpose: the
// commitment is bound to the attempt ID, which the responder chooses, so the initiator cannot know it yet.
//
// A two-way commitment is not needed. The initiator is bound by revealing its key FIRST, without seeing the
// other; the responder is bound by the commitment it gave earlier. Neither side can pick a key to match an
// already known one, which is the only thing this mechanism protects against.
type Hello struct {
	Cmd string `json:"cmd"`
	// NodeID is the initiator's UUID. Metadata (hostname, site) is not identity and may only be shown to
	// the admin as claimed, not proven.
	NodeID string `json:"node_id"`
	// Hostname is what the node says about itself. Shown to the human next to the connection address but
	// NOT used in any check: it is trivial to forge.
	Hostname string `json:"hostname,omitempty"`
	// Endpoint is where this node listens on the peer channel. Needed for connections back after pairing,
	// before the first configuration revision exists.
	Endpoint string `json:"endpoint"`
}

// HelloAck is the responder's reply: it accepts the attempt, names itself and commits to ITS key.
type HelloAck struct {
	OK         bool   `json:"ok"`
	Error      string `json:"error,omitempty"`
	PairingID  string `json:"pairing_id"` // chosen by the responder: the window is open on its side
	NodeID     string `json:"node_id"`
	Hostname   string `json:"hostname,omitempty"`
	Endpoint   string `json:"endpoint"`
	Commitment string `json:"commitment"`
}

// Request is the second step: the initiator reveals its key before seeing the other one.
type Request struct {
	Cmd       string `json:"cmd"`
	PairingID string `json:"pairing_id"`
	NodeID    string `json:"node_id"`
	PubKey    string `json:"pubkey"` // hex, 32 bytes
	Nonce     string `json:"nonce"`  // hex, 16 bytes
}

// RequestAck is the responder's reveal; the initiator checks it against the earlier commitment. Both sides
// then independently compute the same six digits; the code itself is NEVER sent, or there would be nothing
// to compare.
type RequestAck struct {
	OK     bool   `json:"ok"`
	Error  string `json:"error,omitempty"`
	NodeID string `json:"node_id"`
	PubKey string `json:"pubkey"`
	Nonce  string `json:"nonce"`
}

// Commit is sent after human confirmation. It is signed with the EPHEMERAL key and directional: an A->B
// signature does not pass as B->A.
type Commit struct {
	Cmd         string `json:"cmd"`
	PairingID   string `json:"pairing_id"`
	SenderID    string `json:"sender_id"`
	RecipientID string `json:"recipient_id"`
	// KeyFP is the fingerprint of the derived permanent key. The key itself is not sent; the fingerprint
	// proves both sides derived THE SAME key without revealing it.
	KeyFP string `json:"key_fp"`
	MAC   string `json:"mac"`
}

// Complete brings the pair to TRUSTED. It is signed with the PERMANENT key: both sides have it by now,
// while the ephemeral key cannot be recovered after a restart.
type Complete struct {
	Cmd         string `json:"cmd"`
	PairingID   string `json:"pairing_id"`
	SenderID    string `json:"sender_id"`
	RecipientID string `json:"recipient_id"`
	MAC         string `json:"mac"`
}

// Ack is the common reply to commit/complete.
type Ack struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	MAC   string `json:"mac,omitempty"` // counter-signature of the same step
}

// Rejection codes. Distinct values rather than text: the panel uses them to decide what to show.
const (
	ErrClosed     = "pairing_closed"      // window not open: no pairing was expected here
	ErrBusy       = "pairing_busy"        // a request is already in progress; one at a time
	ErrExpired    = "pairing_expired"     // window timed out
	ErrMismatch   = "pairing_mismatch"    // reveal did not match the commitment
	ErrBadMAC     = "pairing_bad_mac"     // signature did not verify
	ErrWrongPeer  = "pairing_wrong_peer"  // message from a node we are not pairing with
	ErrAlreadySet = "pairing_already_set" // node already trusts someone: dismantle trust first
	ErrState      = "pairing_bad_state"   // command does not match the current step
)
