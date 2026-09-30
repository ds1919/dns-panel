// Package pairing establishes trust between two standalone nodes.
//
// The job is narrow and one-off: the nodes have no shared secret yet and need one. Everything else (pair
// configuration, replication, roles) happens AFTER and separately: pairing ends in trust, not in a pair.
//
// How it works:
//
//  1. the responder FIRST publishes a commitment (hash of its ephemeral key and nonce) and only then are the
//     values revealed (commit-reveal); the initiator reveals FIRST without seeing the other key, so no
//     commitment is required from it;
//  2. the revealed values yield an X25519 shared secret and a CONFIRMATION CODE: six digits the human
//     compares by eye on both nodes;
//  3. after human confirmation the same secret yields two independent keys: an ephemeral one (signs the
//     final exchange) and the permanent `peer.key`.
//
// Why commit-reveal rather than a plain key exchange: the code has only a million values. A man in the middle
// who saw one side's key could GRIND his ephemeral key for the other side until the six-digit codes match. The
// commitment fixes his choice BEFORE he sees the other key, leaving an honest 1 in 1,000,000 chance for the
// single attempt in the pairing window.
//
// `peer.key` is NEVER sent over the network, not even encrypted: both sides derive the same bytes, so there is
// nothing to intercept. The human never sees or types it either.
//
// Why a human compares the code instead of trusting the address: address and port prove nothing to anyone in
// the middle. Before pairing there is no shared secret and no PKI, so the human check is all there is; hence
// the code must depend on BOTH ephemeral keys and both UUIDs.
package pairing

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"

	"dnspanel/dns-ha/internal/identity"
)

const (
	// labelCommit: commitment, a hash of one's own ephemeral key and nonce published BEFORE the reveal.
	labelCommit = "dns-panel pairing commitment v1"
	// labelCommitMAC signs the key-installing exchange. Directional: A->B must not pass as B->A.
	labelCommitMAC = "dns-panel pair_commit v1"
	// labelCompleteMAC signs pairing COMPLETION with the PERMANENT key, not the ephemeral one: ephemeral
	// keys live only in memory and are gone after a restart, while the permanent key is durable on both sides.
	labelCompleteMAC = "dns-panel pair_complete v1"
	// labelSession: the ephemeral key that authenticates the final pairing exchange. Separate from the
	// permanent key on purpose: two keys must never be derived from one secret with the same label.
	labelSession = "dns-panel pairing session v1"
	// labelPeerKey: the permanent pair-channel secret.
	labelPeerKey = "dns-panel peer key v1"
	// labelCode: the human confirmation code.
	labelCode = "dns-panel pairing code v1"
)

// Ephemeral is one side's ephemeral key pair, kept only in memory and only for the duration of pairing.
type Ephemeral struct {
	priv *ecdh.PrivateKey
}

// NewEphemeral generates an X25519 ephemeral key.
func NewEphemeral() (*Ephemeral, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("pairing_keygen: %w", err)
	}
	return &Ephemeral{priv: priv}, nil
}

// Public returns the public part the other side sees (32 bytes).
func (e *Ephemeral) Public() []byte { return e.priv.PublicKey().Bytes() }

// Shared computes the shared secret with the other side's public key.
func (e *Ephemeral) Shared(peerPub []byte) ([]byte, error) {
	pub, err := ecdh.X25519().NewPublicKey(peerPub)
	if err != nil {
		return nil, fmt.Errorf("pairing_bad_pubkey: %w", err)
	}
	s, err := e.priv.ECDH(pub)
	if err != nil {
		return nil, fmt.Errorf("pairing_ecdh: %w", err)
	}
	return s, nil
}

// Commitment commits to an ephemeral key and nonce without revealing them. The role is hashed in so an
// initiator's commitment cannot pass as the responder's.
func Commitment(pub, nonce []byte, pairingID, role string) string {
	h := sha256.New()
	writeField(h, []byte(labelCommit))
	writeField(h, []byte(pairingID))
	writeField(h, []byte(role))
	writeField(h, pub)
	writeField(h, nonce)
	return hex.EncodeToString(h.Sum(nil))
}

// VerifyCommitment checks the revealed values against the commitment. A mismatch means the peer ground its
// key after seeing ours, and pairing must abort.
func VerifyCommitment(commitment string, pub, nonce []byte, pairingID, role string) bool {
	return hmac.Equal([]byte(Commitment(pub, nonce, pairingID, role)), []byte(commitment))
}

// Roles in the transcript and commitments.
const (
	RoleInitiator = "initiator" // the one asking to join
	RoleResponder = "responder" // the one confirming
)

func writeField(h io.Writer, b []byte) {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(b)))
	h.Write(l[:])
	h.Write(b)
}

// Transcript is what both sides must see IDENTICALLY. Everything that affects trust goes here: a parameter
// left outside could be substituted without changing the confirmation code.
//
// Field order is fixed and independent of who initiates, or honest parties would get different codes.
type Transcript struct {
	PairingID      string // shared ID of the pairing attempt
	InitiatorID    string // UUID of the requester (B)
	ResponderID    string // UUID of the decider (A)
	InitiatorPub   []byte
	ResponderPub   []byte
	InitiatorNonce []byte
	ResponderNonce []byte
}

// Hash is the transcript fingerprint. Lengths are written explicitly so concatenation is unambiguous:
// otherwise ("ab","c") and ("a","bc") would hash the same.
func (t Transcript) Hash() []byte {
	h := sha256.New()
	writeField(h, []byte(t.PairingID))
	writeField(h, []byte(t.InitiatorID))
	writeField(h, []byte(t.ResponderID))
	writeField(h, t.InitiatorPub)
	writeField(h, t.ResponderPub)
	writeField(h, t.InitiatorNonce)
	writeField(h, t.ResponderNonce)
	return h.Sum(nil)
}

// Keys are derived AFTER human confirmation.
type Keys struct {
	// Session is the ephemeral key authenticating pairing completion; not needed afterwards.
	Session []byte
	// PeerKey is the permanent pair-channel secret, identical on both sides and never sent.
	PeerKey []byte
	// PeerKeyFP lets the sides confirm they derived THE SAME key without revealing it.
	PeerKeyFP string
}

func derive(shared []byte, t Transcript, label string, n int) ([]byte, error) {
	if len(shared) == 0 {
		return nil, fmt.Errorf("pairing_no_shared_secret")
	}
	// Several values come from ONE secret, each under its own label: a shared label would make the ephemeral
	// key, the permanent secret and the confirmation code the same thing.
	buf, err := hkdf.Key(sha256.New, shared, t.Hash(), label, n)
	if err != nil {
		return nil, fmt.Errorf("pairing_hkdf: %w", err)
	}
	return buf, nil
}

// DeriveCode derives only the six human digits. Separate from the keys on purpose: before confirmation the
// permanent secret must not even be computed, so nothing can use it early.
func DeriveCode(shared []byte, t Transcript) (string, error) {
	b, err := derive(shared, t, labelCode, 4)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", binary.BigEndian.Uint32(b)%1000000), nil
}

// DeriveKeys derives the ephemeral and permanent keys. Call it ONLY after the human has compared the code.
func DeriveKeys(shared []byte, t Transcript) (Keys, error) {
	session, err := derive(shared, t, labelSession, 32)
	if err != nil {
		return Keys{}, err
	}
	peerKey, err := derive(shared, t, labelPeerKey, 32)
	if err != nil {
		return Keys{}, err
	}
	sum := sha256.Sum256(peerKey)
	return Keys{Session: session, PeerKey: peerKey, PeerKeyFP: hex.EncodeToString(sum[:])}, nil
}

// Hex is the permanent key as WRITTEN TO DISK and read by the peer channel (64 hex). Completion is signed
// with these bytes: after a restart the node only has the file, so signing raw bytes would make completion
// retries work only until the first restart.
func (k Keys) Hex() string { return hex.EncodeToString(k.PeerKey) }

// SignCommit signs the final exchange with the ephemeral key. There is no pair HMAC yet, but completion must
// still be verified: a forged or replayed commit must not pass.
//
// The signature is DIRECTIONAL (sender and recipient are included). A symmetric one would let a completion be
// reflected back to its sender, who would take its own message for the reply.
func SignCommit(sessionKey []byte, pairingID string, transcriptHash []byte, senderID, recipientID, peerKeyFP string) string {
	m := hmac.New(sha256.New, sessionKey)
	writeField(m, []byte(labelCommitMAC))
	writeField(m, []byte(pairingID))
	writeField(m, transcriptHash)
	writeField(m, []byte(senderID))
	writeField(m, []byte(recipientID))
	writeField(m, []byte(peerKeyFP))
	return hex.EncodeToString(m.Sum(nil))
}

// VerifyCommit compares in constant time.
func VerifyCommit(sessionKey []byte, pairingID string, transcriptHash []byte, senderID, recipientID, peerKeyFP, mac string) bool {
	want := SignCommit(sessionKey, pairingID, transcriptHash, senderID, recipientID, peerKeyFP)
	return hmac.Equal([]byte(want), []byte(mac))
}

// SignComplete signs pairing completion with the PERMANENT key.
//
// Separate from SignCommit on purpose: by completion both sides have installed the same peer.key, and it
// proves each did so. This is how pairing survives a restart: the ephemeral key cannot be recovered, the
// permanent one is on disk.
func SignComplete(peerKey []byte, pairingID string, transcriptHash []byte, senderID, recipientID string) string {
	m := hmac.New(sha256.New, peerKey)
	writeField(m, []byte(labelCompleteMAC))
	writeField(m, []byte(pairingID))
	writeField(m, transcriptHash)
	writeField(m, []byte(senderID))
	writeField(m, []byte(recipientID))
	return hex.EncodeToString(m.Sum(nil))
}

// VerifyComplete compares in constant time.
func VerifyComplete(peerKey []byte, pairingID string, transcriptHash []byte, senderID, recipientID, mac string) bool {
	want := SignComplete(peerKey, pairingID, transcriptHash, senderID, recipientID)
	return hmac.Equal([]byte(want), []byte(mac))
}

// NewPairingID generates the pairing attempt ID. The RESPONDER generates it (the side where the human opened
// the window and will confirm); the initiator receives it and only checks the format.
func NewPairingID() (string, error) { return identity.NewUUID() }

// Nonce returns 16 random bytes for the transcript: two pairings of the same nodes must not yield the same
// keys or code.
func Nonce() ([]byte, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("pairing_nonce: %w", err)
	}
	return b, nil
}
