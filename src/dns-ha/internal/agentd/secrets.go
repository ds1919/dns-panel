package agentd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Pair secrets on disk.
//
// Three files must match on both nodes (§14.6); the root agent writes them because the manager runs as
// dns-ha and cannot write etc/secrets.
//
// Unlike peer.key these are not write-once: on pairing the receiver's auth-master.key is replaced with the
// donor's, or TOTP secrets in the copied DB (encrypted with the donor key) would be unusable after the first
// switchover. No backup of the old value is kept: without the old DB it is useless, just an extra secret on disk.

// secretPath maps an allowed secret name to its path. An allowlist, never a path from the request: that
// would let a network-facing process write any file as root.
func (a *Agent) secretPath(name string) (string, bool) {
	dir := filepath.Dir(a.peerKeyPath())
	switch name {
	case "auth-master.key":
		return filepath.Join(dir, "auth-master.key"), true
	case "repl.secret":
		return filepath.Join(dir, "repl.secret"), true
	case "ha_monitor.secret":
		return filepath.Join(dir, "ha_monitor.secret"), true
	}
	return "", false
}

// secretAccess: auth-master.key is read by the panel web process (root:www-data 0640); replication secrets
// only by the agent (root:root 0600).
func (a *Agent) secretAccess(name string) (os.FileMode, string) {
	if name == "auth-master.key" {
		return 0o640, a.PanelSecretGroup
	}
	return 0o600, ""
}

// readSecret returns an allowlisted secret's value.
//
// The files stay root-owned, but the manager needs the value to hand it to the peer during pairing. A missing
// file is an empty value, not an error: normal for a standalone node, and the caller then generates one.
func (a *Agent) readSecret(name string) Response {
	path, ok := a.secretPath(name)
	if !ok {
		return errResp("bad_request", "unknown secret: "+name)
	}
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return Response{OK: true, Noop: true, Status: map[string]any{"present": false}}
	}
	if err != nil {
		return errResp("secret_unreadable", err.Error())
	}
	return Response{OK: true, Status: map[string]any{"present": true, "value": strings.TrimRight(string(raw), "\n")}}
}

// installSecret writes one allowlisted secret; idempotent by content, so a retried call is a noop.
func (a *Agent) installSecret(name, value string) Response {
	path, ok := a.secretPath(name)
	if !ok {
		return errResp("bad_request", "unknown secret: "+name)
	}
	value = strings.TrimRight(value, "\n")
	if value == "" {
		return errResp("bad_request", "empty value for the secret "+name)
	}
	if cur, err := os.ReadFile(path); err == nil {
		if strings.TrimRight(string(cur), "\n") == value {
			return Response{OK: true, Noop: true, Message: name + " is already installed"}
		}
	} else if !os.IsNotExist(err) {
		return errResp("secret_unreadable", err.Error())
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return errResp("secret_write_failed", err.Error())
	}
	mode, group := a.secretAccess(name)
	tmp := path + ".new"
	// Create as 0600 and widen afterwards, so the group never sees a partially written file.
	if err := os.WriteFile(tmp, []byte(value+"\n"), 0o600); err != nil {
		return errResp("secret_write_failed", err.Error())
	}
	if err := chgrpTo(tmp, group); err != nil {
		os.Remove(tmp)
		return errResp("secret_write_failed", err.Error())
	}
	if err := os.Chmod(tmp, mode); err != nil {
		os.Remove(tmp)
		return errResp("secret_write_failed", err.Error())
	}
	// Atomic rename: readers see the old or the new file, never half of one.
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return errResp("secret_write_failed", err.Error())
	}
	return Response{OK: true, Message: fmt.Sprintf("%s installed", name)}
}
