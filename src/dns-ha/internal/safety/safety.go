// Package safety is the durable safety store (DOCS/23-ha-manager.md §4.3).
//
// This is the only home of the proofs that allow role changes: max_seen_epoch, the accepted handoff
// certificate, emergency authority, PONR marks. They are deliberately not in MariaDB: the store must be
// readable when the DB is down, read-only, or itself the object of an operation.
//
// Hence invariant §4.4.1: losing dns_ha entirely is a nuisance, never a reason to forget epoch/fence/authority
// and promote. Symmetrically: SAFETY lost means promote is forbidden — there is no proof.
package safety

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// State is the safety store content.
type State struct {
	NodeID string `json:"node_id"`
	// MaxSeenEpoch is the monotonic role generation counter. A pointer to tell 0 from missing: a defaulted 0
	// would mean "never saw an epoch" and disable epoch protection.
	MaxSeenEpoch *int64     `json:"max_seen_epoch"`
	Authority    *Authority `json:"authority,omitempty"`
	// CommittedConfig is durable proof that a config revision was committed by both sides. Kept here, not in
	// dns_ha: that DB is local, writable and not a safety authority, so its EFFECTIVE row proves nothing
	// by itself (§7.3, §4.4.1).
	CommittedConfig *CommittedConfig `json:"committed_config,omitempty"`
	// Handoff is the durable trace of handing the role over in the given epoch. Written before the receiver
	// gets the right; this is the point of no return: afterwards this node may not become ACTIVE on its own,
	// even if the switchover aborts. Otherwise an aborted handoff would leave two equally "honest" candidates.
	Handoff   *Handoff         `json:"handoff,omitempty"`
	Emergency *json.RawMessage `json:"emergency,omitempty"`
	Fenced    string           `json:"fenced_node,omitempty"`
	// Extra holds fields this binary does not know. Others write the file too (Perl tools, future
	// versions), and it is durable and authoritative: silently dropping an unknown field on rewrite is
	// exactly how a proof vanishes. Unknown fields are preserved and written back.
	Extra map[string]json.RawMessage `json:"-"`
}

// knownFields are the top-level keys this version owns; everything else goes to Extra.
var knownFields = map[string]bool{
	"node_id": true, "max_seen_epoch": true, "authority": true, "committed_config": true,
	"handoff": true, "emergency": true, "fenced_node": true,
}

// stateAlias keeps Marshal/Unmarshal below from recursing.
type stateAlias State

func (s *State) UnmarshalJSON(b []byte) error {
	var a stateAlias
	if err := json.Unmarshal(b, &a); err != nil {
		return err
	}
	var all map[string]json.RawMessage
	if err := json.Unmarshal(b, &all); err != nil {
		return err
	}
	for k := range all {
		if knownFields[k] {
			delete(all, k)
		}
	}
	*s = State(a)
	if len(all) > 0 {
		s.Extra = all
	}
	return nil
}

func (s State) MarshalJSON() ([]byte, error) {
	raw, err := json.Marshal(stateAlias(s))
	if err != nil {
		return nil, err
	}
	if len(s.Extra) == 0 {
		return raw, nil
	}
	var out map[string]json.RawMessage
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	for k, v := range s.Extra {
		if !knownFields[k] { // known fields are ours: a foreign copy must not override them
			out[k] = v
		}
	}
	return json.Marshal(out)
}

// Kinds of proof of the right to be ACTIVE (§3.2).
const (
	AuthorityHandoff   = "handoff"   // planned: certificate from the previous ACTIVE after a proven demote
	AuthorityEmergency = "emergency" // emergency: typed operator fencing ack
	// AuthorityBootstrap is issued at pair creation, when no second opinion exists yet. It allows staying
	// ACTIVE and restoring services, but not becoming ACTIVE again after losing physical state — that needs
	// a fresh peer confirmation.
	AuthorityBootstrap = "bootstrap"
)

// Handoff records a handed-over role.
type Handoff struct {
	OperationID string `json:"operation_id"`
	Epoch       int64  `json:"epoch"` // the new epoch in which the role was handed over
	To          string `json:"to"`
	From        string `json:"from"`
	ConfigHash  string `json:"config_hash"` // the config both sides agreed on
	IssuedAt    string `json:"issued_at"`
}

// Authority is a proof, always bound to a specific epoch and role.
type Authority struct {
	Type     string `json:"type"`
	Epoch    *int64 `json:"epoch"`
	Role     string `json:"role"` // active | standby
	IssuedAt string `json:"issued_at,omitempty"`
	Source   string `json:"source,omitempty"`
}

// CommittedConfig is proof of a committed config revision.
type CommittedConfig struct {
	Revision      int64  `json:"revision"`
	PayloadHash   string `json:"payload_hash"`
	Epoch         int64  `json:"epoch"` // epoch in which the revision was committed
	CommittedBy   string `json:"committed_by"`
	CertificateID string `json:"certificate_id,omitempty"`
	CommittedAt   string `json:"committed_at,omitempty"`
}

// Results of checking a new config proof.
const (
	ConfigProofAccept     = "accept"     // newer revision
	ConfigProofIdempotent = "idempotent" // same revision and hash: a repeat
	ConfigProofStale      = "stale"      // older than the stored revision
	ConfigProofConflict   = "conflict"   // same revision, different hash: incompatible proofs
	ConfigProofInvalid    = "invalid"    // internally inconsistent
)

// CheckConfigProof reports whether cand can be accepted. Its epoch need not equal max_seen_epoch: a config
// committed in epoch 9 stays valid after moving to 10. But it cannot come from the future.
func (s *State) CheckConfigProof(cand CommittedConfig) (string, string) {
	if cand.Revision <= 0 || cand.PayloadHash == "" || cand.CommittedBy == "" {
		return ConfigProofInvalid, "proof without a revision, hash or author"
	}
	if s.MaxSeenEpoch != nil && cand.Epoch > *s.MaxSeenEpoch {
		return ConfigProofInvalid, "proof issued in a future epoch"
	}
	cur := s.CommittedConfig
	if cur == nil {
		return ConfigProofAccept, ""
	}
	switch {
	case cand.Revision < cur.Revision:
		return ConfigProofStale, "a newer revision is already committed"
	case cand.Revision == cur.Revision && cand.PayloadHash != cur.PayloadHash:
		return ConfigProofConflict, "the same revision with different content — the proofs are incompatible"
	case cand.Revision == cur.Revision:
		return ConfigProofIdempotent, ""
	}
	return ConfigProofAccept, ""
}

// Authority states for the planner.
const (
	AuthValidCurrent = "valid_current" // issued for the current epoch and this role
	AuthStale        = "stale"         // issued for a past epoch: no longer a right
	AuthAbsent       = "absent"        // no proof (does NOT mean allowed)
	AuthUnknown      = "unknown"       // store not read
	AuthForeignRole  = "foreign_role"  // issued for another role
)

// ActiveAuthority is the state of the right to be ACTIVE (not of the current role). Being read-only is
// safe by itself, so STANDBY needs no proof; the right is needed to become ACTIVE and to stay ACTIVE while
// restoring the publication.
//
// It must not depend on actual service state: a legitimate ACTIVE may briefly lose PowerDNS, and if the proof
// then "stopped fitting" the manager would demote itself instead of recovering — exactly when the right is needed.
//
// Missing proof is never permission.
func (s Status) ActiveAuthority() (state, typ, detail, source string, epoch *int64) {
	if !s.Valid || s.State == nil {
		return AuthUnknown, "", "the safety store was not read", "", nil
	}
	a := s.State.Authority
	if a == nil || a.Type == "" {
		return AuthAbsent, "", "there is no proof of the right to be ACTIVE", "", nil
	}
	if a.Epoch == nil {
		return AuthAbsent, a.Type, "proof without an epoch is refused", a.Source, nil
	}
	if a.Role != "active" {
		// "Proof to be STANDBY" does not exist as a concept: such a field means a corrupted store.
		return AuthForeignRole, a.Type, "the proof was issued for the role " + a.Role, a.Source, a.Epoch
	}
	if s.State.MaxSeenEpoch != nil && *a.Epoch != *s.State.MaxSeenEpoch {
		return AuthStale, a.Type, "the proof was issued for a different epoch than the current one", a.Source, a.Epoch
	}
	return AuthValidCurrent, a.Type, "", a.Source, a.Epoch
}

// Status is the result of observing the store.
type Status struct {
	Present bool   `json:"present"`
	Valid   bool   `json:"valid"`
	Error   string `json:"error,omitempty"`
	State   *State `json:"state,omitempty"`
}

var ErrNotFound = errors.New("the safety store was not found")

// Read reads and validates the store. Missing and corrupt are different: the former is normal on an
// uninitialized node, the latter forbids any role change.
func Read(path string) Status {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Status{Present: false, Valid: false, Error: ErrNotFound.Error()}
	}
	if err != nil {
		return Status{Present: true, Valid: false, Error: fmt.Sprintf("safety_unreadable: %v", err)}
	}
	var st State
	if err := json.Unmarshal(raw, &st); err != nil {
		return Status{Present: true, Valid: false, Error: fmt.Sprintf("safety_corrupt: %v", err)}
	}
	if err := validate(&st); err != nil {
		return Status{Present: true, Valid: false, Error: err.Error()}
	}
	return Status{Present: true, Valid: true, State: &st}
}

// validate is fail-closed: a doubtful store is not valid.
func validate(st *State) error {
	if st.NodeID == "" {
		return fmt.Errorf("safety_invalid: no node_id")
	}
	if st.MaxSeenEpoch == nil {
		return fmt.Errorf("safety_invalid: no max_seen_epoch (0 must not be substituted — that would remove the epoch protection)")
	}
	if *st.MaxSeenEpoch < 0 {
		return fmt.Errorf("safety_invalid: negative max_seen_epoch")
	}
	if c := st.CommittedConfig; c != nil {
		if c.Revision <= 0 || c.PayloadHash == "" || c.CommittedBy == "" {
			return fmt.Errorf("safety_invalid: committed_config without a revision, hash or author")
		}
		// A proof "from the future" is impossible: that epoch has not happened. It only arises from
		// corruption or manual edits, and accepting it would legitimize everything built on it
		// (including restoring the config commit at startup).
		if c.Epoch < 0 || c.Epoch > *st.MaxSeenEpoch {
			return fmt.Errorf("safety_invalid: committed_config issued in epoch %d while max_seen_epoch=%d",
				c.Epoch, *st.MaxSeenEpoch)
		}
	}
	if h := st.Handoff; h != nil {
		if h.Epoch <= 0 || h.To == "" || h.From == "" {
			return fmt.Errorf("safety_invalid: handoff without an epoch or parties")
		}
		if h.Epoch > *st.MaxSeenEpoch {
			// A role cannot be handed over in an epoch the node has not seen: the epoch is accepted before
			// the handoff, otherwise after a restart it would not remember in which epoch it gave the role away.
			return fmt.Errorf("safety_invalid: handoff in epoch %d while max_seen_epoch=%d", h.Epoch, *st.MaxSeenEpoch)
		}
	}
	if a := st.Authority; a != nil {
		switch a.Type {
		case AuthorityHandoff, AuthorityEmergency, AuthorityBootstrap:
		default:
			return fmt.Errorf("safety_invalid: unknown authority type %q", a.Type)
		}
		if a.Epoch == nil {
			return fmt.Errorf("safety_invalid: authority without an epoch")
		}
		// A stale right may be stored (it honestly becomes `stale` for the planner); a future one may not:
		// max_seen_epoch is monotonic.
		if *a.Epoch < 0 || *a.Epoch > *st.MaxSeenEpoch {
			return fmt.Errorf("safety_invalid: authority issued in epoch %d while max_seen_epoch=%d",
				*a.Epoch, *st.MaxSeenEpoch)
		}
		// Rights are issued only for ACTIVE.
		if a.Role != "active" {
			return fmt.Errorf("safety_invalid: authority issued for the role %q; only active is allowed", a.Role)
		}
	}
	return nil
}

// BelongsTo reports whether the store belongs to this node. A foreign store describes someone else's
// proofs and must not be accepted.
func (s Status) BelongsTo(nodeID string) bool {
	return s.Valid && s.State != nil && s.State.NodeID == nodeID
}
