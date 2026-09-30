package store

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// Cert is the server certificate. It belongs to the PAIR, not the node, so it lives in the replicated
// dns_panel next to the TSIG secrets: a per-node certificate would make a planned role switch look like
// server impersonation to every agent (docs/25 §1). The active node generates it; the standby is read_only.
type Cert struct {
	PEM         []byte
	KeyPEM      []byte
	Fingerprint string
}

func (d *DB) CertLoadOrCreate(ctx context.Context) (*Cert, error) {
	c, err := d.certLoad(ctx)
	if err != nil || c != nil {
		return c, err
	}
	made, err := makeCert()
	if err != nil {
		return nil, err
	}
	// INSERT IGNORE rather than check-then-insert: both nodes may start at once and exactly one must win.
	if _, err := d.sql.ExecContext(ctx, `
		INSERT IGNORE INTO pulse_server_tls (id, cert_pem, key_pem, fingerprint)
		VALUES (1, ?, ?, ?)`, string(made.PEM), string(made.KeyPEM), made.Fingerprint); err != nil {
		return nil, err
	}
	return d.certLoad(ctx)
}

func (d *DB) certLoad(ctx context.Context) (*Cert, error) {
	var c Cert
	var certPEM, keyPEM string
	err := d.sql.QueryRowContext(ctx,
		`SELECT cert_pem, key_pem, fingerprint FROM pulse_server_tls WHERE id = 1`).
		Scan(&certPEM, &keyPEM, &c.Fingerprint)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	c.PEM, c.KeyPEM = []byte(certPEM), []byte(keyPEM)
	return &c, nil
}

// Self-signed, ten years, no CA and no renewal. Agents do not check the name (the service address moves);
// they pin the fingerprint, which is stricter, not weaker (docs/25 §1).
func makeCert() (*Cert, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "dns-panel pulse-server"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(der)
	return &Cert{
		PEM:         pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:      pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		Fingerprint: hex.EncodeToString(sum[:]),
	}, nil
}

// Fingerprint returns the SHA-256 of a DER certificate, exactly what the operator pastes into the agent config.
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

func (c *Cert) String() string { return fmt.Sprintf("fingerprint %s", c.Fingerprint) }
