// Package identity defines node identity rules.
//
// A node's identity is a random UUID. It is never set by a human or derived from hostname, site or address:
// it backs everything that decides role (peer message signing, safety, fencing, handoff, the operation log),
// and names change — the site baked into "ams-pdns1" outlived the site itself.
//
// Three distinct things, each stored in exactly one place:
//
//	node_id                    UUID, immutable     → local dns_ha DB (ha_identity table)
//	hostname                   observed from the OS → not stored
//	name/location/description  metadata           → pair configuration (revision + ha_nodes)
//
// Storage lives in store: the local non-replicated DB is the local control-plane's home, and a separate
// identity file would be a second place saying the same thing.
package identity

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// NewUUID returns a random UUID v4 from crypto/rand: a predictable identity is no identity.
func NewUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("identity_random: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32], nil
}

// ValidUUID strictly checks the canonical lowercase form. Identities also come from the peer, and accepting
// near-UUIDs would let one node appear to the pair as two under different spellings.
func ValidUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, r := range s {
		switch i {
		case 8, 13, 18, 23:
			if r != '-' {
				return false
			}
		default:
			if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
				return false
			}
		}
	}
	return true
}

// Short returns the short UUID form for logs and operation IDs, where distinctness matters more than
// readability; human-facing messages should use the node name instead.
func Short(nodeID string) string {
	if len(nodeID) >= 8 {
		return nodeID[:8]
	}
	return nodeID
}
