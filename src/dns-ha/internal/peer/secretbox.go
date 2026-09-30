package peer

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// Passing secrets over the peer channel.
//
// The channel is SIGNED but not encrypted: that is enough for control commands, which cannot be forged without
// the key and whose content ("switch over", "show status") is not secret. Passwords are different and must
// not be sent in clear just because "the management network is trusted".
//
// This adds nothing to the trust model: the encryption key is derived from the same `peer.key` the sides
// established by human-confirmed pairing. A separate HKDF label keeps the encryption key distinct from the
// signing key: one secret, one purpose.
const labelSecretTransfer = "dns-panel secret transfer v1"

// SealSecret encrypts a value for the peer, returning base64 (nonce || ciphertext || tag).
//
// The secret's NAME is part of the AAD: otherwise an encrypted `repl.secret` could be substituted for
// `auth-master.key`, the message signature would still verify, and the node would write the wrong thing
// to the wrong place.
func SealSecret(peerKey []byte, name string, value []byte) (string, error) {
	gcm, err := secretCipher(peerKey)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("secret_nonce: %w", err)
	}
	out := gcm.Seal(nonce, nonce, value, []byte(name))
	return base64.StdEncoding.EncodeToString(out), nil
}

// OpenSecret decrypts a value. A bad tag, a foreign key or a different secret name yield an error, not
// garbage: AEAD checks integrity before returning a single byte.
func OpenSecret(peerKey []byte, name, sealed string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(sealed)
	if err != nil {
		return nil, fmt.Errorf("secret_bad_encoding: %w", err)
	}
	gcm, err := secretCipher(peerKey)
	if err != nil {
		return nil, err
	}
	if len(raw) < gcm.NonceSize() {
		return nil, fmt.Errorf("secret_truncated")
	}
	nonce, body := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	value, err := gcm.Open(nil, nonce, body, []byte(name))
	if err != nil {
		return nil, fmt.Errorf("secret_bad_seal: %w", err)
	}
	return value, nil
}

func secretCipher(peerKey []byte) (cipher.AEAD, error) {
	if len(peerKey) == 0 {
		return nil, fmt.Errorf("secret_no_key")
	}
	key, err := hkdf.Key(sha256.New, peerKey, nil, labelSecretTransfer, 32)
	if err != nil {
		return nil, fmt.Errorf("secret_hkdf: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("secret_cipher: %w", err)
	}
	return cipher.NewGCM(block)
}
