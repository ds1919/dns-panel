package agentd

import (
	"fmt"
	"os"
	"path/filepath"
)

// HA-role fail-safe: a reboot by itself neither makes the node writable nor starts replication threads.
//
// The file lives in the product tree and is ATTACHED via a symlink in mariadb.conf.d, not copied: the content
// belongs to the product and is upgraded with it, while the system directory keeps one obvious link that is
// easy to remove on dismantle.
//
// No MariaDB restart: the file only affects the NEXT start, and the agent sets the current read_only from the
// proven role. Restarting the database under live DNS for a setting needed after reboot is a bad trade.

// EnableFailsafe attaches ha-failsafe.cnf. Idempotent: a correct symlink is success with no action.
func (n *Node) EnableFailsafe() (Response, error) {
	src, dst := n.Cfg.Failsafe.Source, n.Cfg.Failsafe.Link
	if src == "" || dst == "" {
		return errResp("bad_request", "the agent config has no ha-failsafe paths"), nil
	}
	if _, err := os.Stat(src); err != nil {
		// A dangling symlink would give a MariaDB that fails to start after the next reboot.
		return errResp("failsafe_missing", err.Error()), nil
	}
	if cur, err := os.Readlink(dst); err == nil {
		if cur == src {
			return Response{OK: true, Noop: true, Message: "fail-safe is already in place"}, nil
		}
		return errResp("failsafe_conflict", fmt.Sprintf("%s points to %s", dst, cur)), nil
	} else if _, err := os.Lstat(dst); err == nil {
		// A regular file here was written by a human and must not be overwritten.
		return errResp("failsafe_conflict", dst+" exists and is not our symlink"), nil
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return errResp("failsafe_failed", err.Error()), nil
	}
	if err := os.Symlink(src, dst); err != nil {
		return errResp("failsafe_failed", err.Error()), nil
	}
	return Response{OK: true, Message: "fail-safe is in place: " + dst}, nil
}

// DisableFailsafe removes the symlink on pair dismantle. A foreign file at the same path is left alone: we
// remove OURS, not whatever we find.
func (n *Node) DisableFailsafe() (Response, error) {
	src, dst := n.Cfg.Failsafe.Source, n.Cfg.Failsafe.Link
	if dst == "" {
		return errResp("bad_request", "the agent config has no ha-failsafe path"), nil
	}
	cur, err := os.Readlink(dst)
	if os.IsNotExist(err) {
		return Response{OK: true, Noop: true, Message: "fail-safe is not in place"}, nil
	}
	if err != nil {
		return errResp("failsafe_conflict", dst+" exists and is not our symlink"), nil
	}
	if cur != src {
		return errResp("failsafe_conflict", fmt.Sprintf("%s points to %s", dst, cur)), nil
	}
	if err := os.Remove(dst); err != nil {
		return errResp("failsafe_failed", err.Error()), nil
	}
	return Response{OK: true, Message: "fail-safe removed"}, nil
}
