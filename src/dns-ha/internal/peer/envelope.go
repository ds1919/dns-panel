package peer

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// Envelope is what actually goes over the wire.
//
// KEY POINT: the signature covers the EXACT bytes of `Body`, not a re-serialized struct. In the Perl
// implementation this already cost debugging: a check like `"$m->{ts}" =~ /\d/` changed a scalar's internal
// flag, canonical JSON then encoded the number as a string, and the signature "broke" out of nowhere. Go has
// different pitfalls (field order, escaping, HTML-escaping), but the lesson is the same: sign and verify BYTES.
type Envelope struct {
	Body string `json:"body"` // serialized Request/Response as a string
	Sig  string `json:"sig"`  // hex(HMAC-SHA256(secret, []byte(Body)))
}

var secretRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// LoadSecret reads the shared pair secret and validates its format. Fail loud: a key file with garbage
// inside is worse than an explicit refusal at startup.
func LoadSecret(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("peer secret: %w", err)
	}
	s := strings.TrimSpace(string(raw))
	if !secretRe.MatchString(s) {
		return nil, fmt.Errorf("peer secret %s: 64 hex characters expected (openssl rand -hex 32)", path)
	}
	return []byte(s), nil
}

// sign returns the hex HMAC over the exact bytes of body.
func sign(secret []byte, body []byte) string {
	m := hmac.New(sha256.New, secret)
	m.Write(body)
	return hex.EncodeToString(m.Sum(nil))
}

// verify compares in constant time.
func verify(secret []byte, body []byte, sig string) bool {
	want := sign(secret, body)
	return hmac.Equal([]byte(want), []byte(sig))
}

// seal serializes a value and wraps it in a signed envelope.
func seal(secret []byte, v any) ([]byte, error) {
	body, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return json.Marshal(Envelope{Body: string(body), Sig: sign(secret, body)})
}

// open verifies the signature and parses the body, returning a typed rejection code.
func open(secret []byte, raw []byte, dst any) (string, error) {
	var env Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return ErrBadEnvelope, fmt.Errorf("envelope could not be parsed: %w", err)
	}
	if env.Body == "" || env.Sig == "" {
		return ErrBadEnvelope, fmt.Errorf("envelope has no body/sig")
	}
	if !verify(secret, []byte(env.Body), env.Sig) {
		return ErrBadSignature, fmt.Errorf("signature does not match")
	}
	if err := json.Unmarshal([]byte(env.Body), dst); err != nil {
		return ErrBadRequest, fmt.Errorf("body could not be parsed: %w", err)
	}
	return "", nil
}

// randomHex generates a nonce/message_id. 128 bits: collisions are unrealistic and the envelope stays small.
func randomHex() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
