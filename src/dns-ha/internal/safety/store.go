package safety

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"dnspanel/dns-ha/internal/config"
)

// Store is the only writer of the safety file.
//
// Several paths write it (committed_config, max_seen_epoch, handoff, emergency authority, fencing, PONR);
// read-modify-write from different places would let the last writer clobber the first. Writes are
// serialized, state is re-read before each change, and the result is validated.
//
// A mutex only covers goroutines; the manager, one-off commands and migration tools are separate processes,
// so writers also take flock on a separate lock file. Separate because safety.json is replaced via rename
// and a lock on it would stay on the old inode.
//
// Writes are durable: temp → fsync(file) → rename → fsync(dir). Failure at any step means not committed.
type Store struct {
	mu       sync.Mutex
	path     string
	lockPath string
}

// NewStore keeps the lock in /run: it belongs to the current boot, while state must survive reboots.
// A lock file surviving a reboot is a source of false "someone is writing".
func NewStore(path string) *Store {
	return &Store{path: path, lockPath: filepath.Join(config.RunDir, "safety.lock")}
}

// NewStoreAt sets state and lock paths explicitly (tests, one-off commands).
func NewStoreAt(path, lockPath string) *Store { return &Store{path: path, lockPath: lockPath} }

// LockPath is the inter-process lock file.
func (s *Store) LockPath() string { return s.lockPath }

// lock takes an exclusive lock for the change. Blocking on purpose: concurrent safety edits are rare and
// short, and "couldn't lock → skip the write" would lose a proof.
func (s *Store) lock() (func(), error) {
	f, err := os.OpenFile(s.LockPath(), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("safety_lock_open: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, fmt.Errorf("safety_lock: %w", err)
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}

func (s *Store) Path() string { return s.path }

// Read returns the current state without the write lock: reading is safe and must not hinder observation.
func (s *Store) Read() Status { return Read(s.path) }

// Update applies a change atomically. mutate gets a copy of the current state; changes are written only
// if the result validates. If mutate returns an error the file is not touched.
func (s *Store) Update(mutate func(*State) error) (State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, err := s.lock()
	if err != nil {
		return State{}, err
	}
	defer unlock()

	// Re-read under the lock: a copy taken before it may be stale.
	cur := Read(s.path)
	var st State
	switch {
	case cur.Valid && cur.State != nil:
		st = *cur.State
	case cur.Present:
		// Present but invalid: never overwrite silently. A blind "repair" of a durable safety authority
		// could erase a proof someone already relies on.
		return State{}, fmt.Errorf("safety_store_invalid: %s", cur.Error)
	}

	if err := mutate(&st); err != nil {
		return State{}, err
	}
	if err := validate(&st); err != nil {
		return State{}, fmt.Errorf("write refused: %w", err)
	}
	if err := s.writeAtomic(&st); err != nil {
		return State{}, err
	}
	return st, nil
}

func (s *Store) writeAtomic(st *State) error {
	raw, err := json.Marshal(st)
	if err != nil {
		return fmt.Errorf("safety_marshal: %w", err)
	}
	dir := filepath.Dir(s.path)
	tmp := s.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("safety_open: %w", err)
	}
	if _, err := f.Write(raw); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("safety_write: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("safety_fsync: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("safety_close: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("safety_rename: %w", err)
	}
	// Directory fsync is not best-effort: without it the rename may not survive a sudden reboot, and a proof
	// we consider committed would vanish.
	return syncDir(dir)
}

// ResetPair makes the node no longer half of a pair (dismantle).
//
// Erases everything describing the pair: epoch, authority, committed revision, handoff, emergency mark,
// fence. Node identity stays — it belongs to the machine. Without this no new pair could be built: it starts
// at epoch 1, and a node durably remembering epoch 9 would refuse ("this node has already seen epoch 9").
func (s *Store) ResetPair() error {
	// The file is removed, not rewritten empty: a missing max_seen_epoch fails validation (0 must not be
	// substituted), and a missing file is the normal single-node state, exactly as before the first pair.
	// Identity is not lost: it lives in ha_identity in local dns_ha; this was a copy.
	// Removal is as durable a safety change as a write, so it uses the same mutex, flock and directory fsync.
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, err := s.lock()
	if err != nil {
		return err
	}
	defer unlock()

	if err := os.Remove(s.path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return syncDir(filepath.Dir(s.path))
}

// syncDir makes a file's appearance or removal in dir durable.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("safety_dir_open: %w", err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("safety_dir_fsync: %w", err)
	}
	return nil
}
