// Package pinning makes the agent trust the server by certificate FINGERPRINT, not by name.
//
// Standard TLS verification matches the certificate name to the dialled address. The service address
// moves between nodes and may change, and binding to it would mean reissuing the certificate and
// visiting every site. A pinned fingerprint is a stricter check, not a disabled one (docs/25 §1).
package pinning

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type Pin struct {
	mu       sync.Mutex
	explicit string // from the config; always wins over the stored one
	stored   string // pinned on first connection
	next     string // next one announced by the server, accepted alongside the current
	path     string
	Seen     string // fingerprint the server actually presented
}

func New(explicit, stateDir string) (*Pin, error) {
	p := &Pin{explicit: strings.ToLower(explicit), path: filepath.Join(stateDir, "server.fingerprint")}
	raw, err := os.ReadFile(p.path)
	if err == nil {
		parts := strings.Fields(string(raw))
		if len(parts) > 0 {
			p.stored = strings.ToLower(parts[0])
		}
		if len(parts) > 1 {
			p.next = strings.ToLower(parts[1])
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("state: %w", err)
	}
	return p, nil
}

// TLSConfig verifies the peer itself, because it checks something DIFFERENT from standard TLS.
func (p *Pin) TLSConfig() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true, // name deliberately not checked; see package comment
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return fmt.Errorf("server presented no certificate")
			}
			sum := sha256.Sum256(raw[0])
			got := hex.EncodeToString(sum[:])
			p.mu.Lock()
			defer p.mu.Unlock()
			p.Seen = got
			switch {
			case p.explicit != "":
				if got != p.explicit {
					return fmt.Errorf("server fingerprint %s does not match the one in the config (%s)",
						got, p.explicit)
				}
			case p.stored == "":
				// First connection: persist to disk right here, before the token leaves. Otherwise a crash
				// between handshake and welcome would leave the agent unpinned, trusting any first cert again.
				p.stored = got
				if err := p.save(); err != nil {
					p.stored = ""
					return fmt.Errorf("cannot save server fingerprint (%w) — not sending the token", err)
				}
			case got == p.stored || (p.next != "" && got == p.next):
				// Current or announced next: both are valid during rotation.
			default:
				return fmt.Errorf("server fingerprint changed: expected %s, got %s — refusing to send the token",
					p.stored, got)
			}
			return nil
		},
	}
}

// Commit is called after a COMPLETE session (token accepted). Only then do we pin and drop the spare
// fingerprint: otherwise a server presenting a new certificate and rejecting the token would burn the
// agent's fallback exactly where the rollout is incomplete (docs/25 §1).
func (p *Pin) Commit() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	switch {
	case p.explicit != "":
		p.stored, p.next = p.explicit, ""
	case p.Seen != "" && p.Seen == p.next:
		p.stored, p.next = p.next, "" // rotation done: the new one becomes current
	case p.stored == "":
		p.stored = p.Seen
	}
	return p.save()
}

// Next stores the server-announced next fingerprint beside the current one. The old one is dropped only
// after the new one works for THIS agent, so only those who no longer need the fallback lose it.
func (p *Pin) Next(fp string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.next = strings.ToLower(fp)
	return p.save()
}

func (p *Pin) save() error {
	if err := os.MkdirAll(filepath.Dir(p.path), 0o700); err != nil {
		return err
	}
	line := p.stored
	if p.next != "" {
		line += " " + p.next
	}
	tmp := p.path + ".tmp"
	if err := os.WriteFile(tmp, []byte(line+"\n"), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p.path) // atomic: half a fingerprint on disk is worse than none
}
