package agentd

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Installing the pair secret is all the agent does for pairing: it safely places one file the manager
// (non-root) can read but not write, with no knowledge of trust, peer UUID or the database.
//
// These commands bypass the mutation contract (operation_id + cluster_epoch): the epoch belongs to the pair,
// which does not exist yet during pairing. They are protected instead by write-once and fingerprint-exact removal.

var keyRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// installPeerKey writes the pair secret, write-once: overwriting would break a working channel with the peer
// (key rotation is a separate, coordinated operation). A repeat with the same fingerprint succeeds, so a lost
// response does not leave the key installed but unacknowledged.
func (a *Agent) installPeerKey(key, fp string) Response {
	if !keyRe.MatchString(key) {
		return errResp("bad_request", "the key must be 64 hex characters")
	}
	if fingerprint(key) != fp {
		// Sender and receiver compute fingerprints differently: key comparison would be meaningless.
		return errResp("bad_request", "the fingerprint does not match the key")
	}
	path := a.peerKeyPath()
	if cur, err := os.ReadFile(path); err == nil {
		if fingerprint(strings.TrimSpace(string(cur))) == fp {
			return Response{OK: true, Noop: true, Message: "the key is already installed"}
		}
		return errResp("already_set", "the pair secret is already installed and differs: an explicit reset is required first")
	} else if !os.IsNotExist(err) {
		return errResp("key_unreadable", err.Error())
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return errResp("key_write_failed", err.Error())
	}
	// O_EXCL: the check above is about meaning; the race between two installs is closed by file creation.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return errResp("already_set", "the pair secret is already installed")
		}
		return errResp("key_write_failed", err.Error())
	}
	if _, err := f.WriteString(key + "\n"); err != nil {
		f.Close()
		os.Remove(path)
		return errResp("key_write_failed", err.Error())
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(path)
		return errResp("key_write_failed", err.Error())
	}
	f.Close()
	// Chown after writing: the file is root 0600 until then, so nobody could read it in between.
	if err := chownTo(path, a.PeerKeyOwner); err != nil {
		os.Remove(path)
		return errResp("key_write_failed", err.Error())
	}
	return Response{OK: true, Message: "the pair secret is installed"}
}

// removePeerKey removes the pair secret to reset an interrupted pairing where only one side got the key;
// otherwise a retry would derive a different key and hit write-once forever. The fingerprint is required so
// one command cannot break a working pair. A missing file is success.
func (a *Agent) removePeerKey(fp string) Response {
	if fp == "" {
		return errResp("bad_request", "removing the key without the expected fingerprint")
	}
	path := a.peerKeyPath()
	cur, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return Response{OK: true, Noop: true, Message: "there is no pair secret"}
	}
	if err != nil {
		return errResp("key_unreadable", err.Error())
	}
	if fingerprint(strings.TrimSpace(string(cur))) != fp {
		// A different key: not our interrupted exchange, never touch it.
		return errResp("fingerprint_mismatch", "a different pair secret is installed — removal refused")
	}
	if err := os.Remove(path); err != nil {
		return errResp("key_write_failed", err.Error())
	}
	return Response{OK: true, Message: "the pair secret was removed"}
}

func (a *Agent) peerKeyPath() string {
	if a.PeerKeyPath != "" {
		return a.PeerKeyPath
	}
	return "/opt/dns-panel/etc/secrets/peer.key"
}

// fingerprint must match the manager's: sha256 of the hex-decoded key bytes.
func fingerprint(key string) string {
	raw, err := hex.DecodeString(strings.TrimSpace(key))
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// chgrpTo gives the file to the group that must read it (the panel for auth-master.key). The owner stays
// root: a secret that its reader can rewrite is no longer a secret.
func chgrpTo(path, group string) error {
	if group == "" {
		return nil
	}
	g, err := user.LookupGroup(group)
	if err != nil {
		return err
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return err
	}
	return os.Chown(path, -1, gid)
}

// chownTo gives the file to the manager's user; an empty name leaves ownership as is (tests, foreign trees).
func chownTo(path, owner string) error {
	if owner == "" {
		return nil
	}
	u, err := user.Lookup(owner)
	if err != nil {
		return err
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return err
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return err
	}
	return os.Chown(path, uid, gid)
}
