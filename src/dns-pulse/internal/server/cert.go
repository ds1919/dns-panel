package server

import (
	"context"
	"crypto/tls"
	"errors"

	"dnspanel/dns-pulse/internal/logs"
)

// The TLS certificate lives in dns_panel, so both nodes of a pair serve the same one (agents pin its
// fingerprint). A node's database is replaced when the pair is created, so the certificate is read again
// whenever the node becomes ACTIVE, not only at start: otherwise a node would keep serving the certificate it
// had as a standalone node and, after a switchover, agents would refuse it.

// LoadCert reads the certificate from the database (creating it on a node that has none yet).
func (s *Server) LoadCert(ctx context.Context) error {
	c, err := s.DB.CertLoadOrCreate(ctx)
	if err != nil {
		return err
	}
	pair, err := tls.X509KeyPair(c.PEM, c.KeyPEM)
	if err != nil {
		return err
	}
	s.mu.Lock()
	changed := s.certFP != c.Fingerprint
	s.certFP = c.Fingerprint
	s.cert.Store(&pair)
	s.mu.Unlock()
	if changed {
		logs.Infof("pulse-server: certificate fingerprint %s", c.Fingerprint)
	}
	return nil
}

// GetCertificate is the listener's tls.Config hook: every handshake takes the current certificate.
func (s *Server) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	if c := s.cert.Load(); c != nil {
		return c, nil
	}
	return nil, errors.New("no certificate loaded")
}
