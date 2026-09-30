package store

// Configuration revision transition rules: PURE functions, no SQL.
//
// Kept separate on purpose: this is the substance of the §7 protocol and must be testable exhaustively,
// without a database or network. The SQL (config.go) stays thin and only applies decisions already made.
//
// Common principle: the same revision with the same content is a RETRY (idempotent); the same revision with
// different content is a CONFLICT (incompatible decisions, fix by hand); a revision older than the effective
// one is STALE. Silently "catching up" is never allowed.

// Rejection codes. They go to the peer and to the panel audit, so they are stable and typed.
const (
	CodeRevisionStale    = "config_revision_stale"                     // proposed revision is not newer than the effective one
	CodeRevisionConflict = "config_revision_conflict"                  // same revision, different content
	CodeNotStaged        = "config_not_staged"                         // nothing to commit: no staged revision
	CodePayloadMissing   = "config_payload_missing"                    // staged revision has no canonical content
	CodeRevisionInvalid  = "config_revision_invalid"                   // meaningless request (zero revision, empty hash)
	CodeTransportChange  = "config_transport_change_requires_rotation" // the pair channel itself changes (§7.4)
)

// Actions a rule may prescribe.
const (
	ActStage      = "stage"      // write a new staged revision (replacing the previous staged one)
	ActCommit     = "commit"     // make the staged revision effective
	ActIdempotent = "idempotent" // exactly this is already done; nothing to change
	ActReject     = "reject"
)

// RevisionView is the little the rules need to know about a revision.
type RevisionView struct {
	Revision    int64
	PayloadHash string
	HasBlob     bool
}

// ConfigState is a snapshot of the node's configuration state.
type ConfigState struct {
	Effective *RevisionView // latest committed (highest number)
	Staged    *RevisionView // staged but not committed
}

// Decision is a rule's result.
type Decision struct {
	Action string
	Code   string
	Reason string
}

func reject(code, reason string) Decision {
	return Decision{Action: ActReject, Code: code, Reason: reason}
}

// StageDecision decides whether staging revision rev with content hash is acceptable.
func StageDecision(st ConfigState, rev int64, hash string) Decision {
	if rev <= 0 || hash == "" {
		return reject(CodeRevisionInvalid, "revision without a number or a content hash")
	}
	if e := st.Effective; e != nil {
		switch {
		case rev < e.Revision:
			return reject(CodeRevisionStale, "a newer revision is in effect")
		case rev == e.Revision && hash != e.PayloadHash:
			// An already committed revision must not be restaged with different content: its fingerprint may
			// already have been confirmed as effective by someone.
			return reject(CodeRevisionConflict, "this revision is already committed with different content")
		case rev == e.Revision:
			return Decision{Action: ActIdempotent, Reason: "the revision is already in effect"}
		}
	}
	if s := st.Staged; s != nil {
		switch {
		case rev < s.Revision:
			return reject(CodeRevisionStale, "a newer revision is already staged")
		case rev == s.Revision && hash != s.PayloadHash:
			return reject(CodeRevisionConflict, "this revision is already staged with different content")
		case rev == s.Revision && s.HasBlob:
			return Decision{Action: ActIdempotent, Reason: "the revision is already staged"}
			// rev == s.Revision without a blob: overwrite; the staging was incomplete and must not be committed.
		}
	}
	return Decision{Action: ActStage}
}

// CommitDecision decides whether revision rev with content hash may be committed.
//
// Commit NEVER invents content: it commits exactly what was staged, and only if its fingerprint matches the
// one the sides agreed on.
func CommitDecision(st ConfigState, rev int64, hash string) Decision {
	if rev <= 0 || hash == "" {
		return reject(CodeRevisionInvalid, "revision without a number or a content hash")
	}
	if e := st.Effective; e != nil {
		switch {
		case rev < e.Revision:
			return reject(CodeRevisionStale, "a newer revision is in effect")
		case rev == e.Revision && hash != e.PayloadHash:
			return reject(CodeRevisionConflict, "this revision is already committed with different content")
		case rev == e.Revision:
			// The normal recovery path after a crash between writing the proof and the SQL update: the retry hits
			// an already committed revision and must look like success, not an error.
			return Decision{Action: ActIdempotent, Reason: "the revision is already committed"}
		}
	}
	s := st.Staged
	switch {
	case s == nil || s.Revision != rev:
		return reject(CodeNotStaged, "this revision is not staged")
	case s.PayloadHash != hash:
		return reject(CodeRevisionConflict, "different content is staged")
	case !s.HasBlob:
		return reject(CodePayloadMissing, "the staged revision has no canonical content")
	}
	return Decision{Action: ActCommit}
}
