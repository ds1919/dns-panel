package configsync

import (
	"dnspanel/dns-ha/internal/peer"
)

// GateInput is what is known about US when a command arrives. The snapshot comes from the same watch loop as
// everything else: the gate does not observe the world itself, or decisions would rest on two different pictures.
type GateInput struct {
	SafetyValid  bool
	MaxSeenEpoch *int64
	FencedNode   string
	SelfNodeID   string
	// IAmActive means WE consider ourselves the current ACTIVE. Then configuration commands from the peer
	// must be refused: only ACTIVE may initiate a change (§7.3), so either the peer is not who it claims or we
	// both think we are active, and that is no time to write anything.
	IAmActive bool
}

// NewGate returns the mutation permission check as a peer.MutationGate.
//
// The gate is where the request's `epoch` field gets its safety meaning. A check skipped here is not
// compensated anywhere below: the ledger ensures "exactly once", not "allowed at all".
func NewGate(get func() GateInput) peer.MutationGate {
	return func(req *peer.Request) (bool, string) {
		in := get()
		switch {
		case !in.SafetyValid:
			// Without a healthy safety store we know neither our epoch nor fencing, so we cannot prove that
			// changing state is safe. Refuse rather than "probably fine".
			return false, peer.ErrNotAllowedNow
		case in.MaxSeenEpoch == nil:
			return false, peer.ErrNotAllowedNow
		case in.FencedNode == in.SelfNodeID:
			return false, peer.ErrNotAllowedNow // we are fenced: nobody may change our state now
		case peer.RequiresSameEpoch(req.Cmd) && req.Epoch != *in.MaxSeenEpoch:
			return false, peer.ErrEpoch
		case req.Epoch < *in.MaxSeenEpoch:
			// A command from a PAST epoch never runs: its sender does not know about a transition that already
			// happened. The exact epoch requirement (equal to ours or exactly the next) is checked by the command
			// handler, since it differs per command.
			return false, peer.ErrEpoch
		case in.IAmActive && !peer.AcceptsFromActive(req.Cmd):
			// Configuration is sent to us by the ACTIVE, and we cannot be active ourselves: otherwise either the
			// peer is not who it claims, or both think they are active, and that is no time to write.
			return false, peer.ErrNotAllowedNow
		}
		return true, ""
	}
}
