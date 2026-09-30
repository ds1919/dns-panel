// Agent identity: the agent generates its own key on first start and never shows it; the server stores
// only its hash. The config thus carries no per-machine secret, so one settings file fits every machine,
// and the order is natural: start the agent first, then a human approves it in the panel (docs/25 §1).

package agent

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const keyFile = "agent.key"

// agentKey reads the key from StateDirectory, creating it on first start. A corrupt file is an ERROR,
// not a reason to mint a new key: a silent new identity would appear as a second enrolment request.
func agentKey(stateDir string) (string, error) {
	path := filepath.Join(stateDir, keyFile)
	raw, err := os.ReadFile(path)
	if err == nil {
		k := strings.ToLower(strings.TrimSpace(string(raw)))
		if !validKey(k) {
			return "", fmt.Errorf("%s: agent key is not 64 hex characters; delete the file to enrol anew", path)
		}
		return k, nil
	}
	if !os.IsNotExist(err) {
		return "", fmt.Errorf("state: %w", err)
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	k := hex.EncodeToString(buf)
	if err := os.WriteFile(path, []byte(k+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("state: %w", err)
	}
	return k, nil
}

func validKey(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// enrollCode is what the panel shows in the pending list: the first eight hex digits of the key hash,
// used to tell simultaneous requests apart. The key cannot be recovered from it.
func enrollCode(key string) string {
	sum := sha256.Sum256([]byte(key))
	h := strings.ToUpper(hex.EncodeToString(sum[:]))
	return h[0:4] + "-" + h[4:8]
}
