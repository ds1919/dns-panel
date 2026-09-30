package pairsetup

import (
	"context"
	"encoding/json"
	"fmt"

	"dnspanel/dns-ha/internal/peer"

	"dnspanel/dns-ha/internal/store"
)

// Handler is the RECEIVER side: it does what the donor says and decides nothing itself.
//
// The only thing it really checks is its own state: init commands are accepted only while the node has no
// effective revision; once a pair exists each is refused. Who may send them was checked earlier, elsewhere:
// the peer channel accepts messages from exactly one node, the one we are paired with, and only correctly signed.
type Handler struct {
	Node Node
}

// Init errors. Typed, because the donor uses them to decide what to show the human.
const (
	ErrPaired    = "init_already_paired"  // HA already configured: nothing to rebuild, and not allowed
	ErrNoTrust   = "init_not_paired_yet"  // node is not paired: the command did not come from the expected sender
	ErrBadWire   = "init_bad_request"     // message could not be parsed
	ErrUnknown   = "init_unknown_command" // command not recognized
	ErrExecution = "init_failed"          // step failed; details in the message
)

// Handle runs one step and returns the value for the reply to the peer.
func (h *Handler) Handle(ctx context.Context, cmd string, payload []byte) (any, error) {
	trust, err := h.Node.Trust(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ErrExecution, err)
	}
	if trust.PeerNodeID == "" {
		return nil, fmt.Errorf("%s", ErrNoTrust)
	}
	// init_seed CREATES the revision, so it has its own state check: a retry with the same content succeeds,
	// with different content it is refused (SeedRevision does that). Other steps are not allowed at all on a
	// paired node.
	//
	// Exceptions are the commands that CHANGE NOTHING: device, recap, check. Their whole point is to ask the node
	// about its state, and forbidding them "because a revision exists" would mean closing our eyes exactly when we
	// most need to look. Half a built pair is exactly a node with a revision, and completion must both ask it
	// (recap) and check its resources (check).
	if cmd != CmdSeed && cmd != CmdDevice && cmd != CmdRecap && cmd != CmdCheck {
		paired, err := h.Node.HasHAConfig(ctx)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", ErrExecution, err)
		}
		if paired {
			return nil, fmt.Errorf("%s", ErrPaired)
		}
	}

	switch cmd {
	case CmdRecap:
		// What the receiver already has. Needed for one case: the donor failed to write ITS half, and the retry
		// must see that the receiver is already built rather than start from scratch or fail on "pair already
		// exists".
		return h.recap(ctx)
	case CmdPrepare:
		var m Prepare
		if err := json.Unmarshal(payload, &m); err != nil {
			return nil, fmt.Errorf("%s", ErrBadWire)
		}
		return h.prepare(ctx, trust, m)
	case CmdReseed:
		var m Reseed
		if err := json.Unmarshal(payload, &m); err != nil {
			return nil, fmt.Errorf("%s", ErrBadWire)
		}
		return h.reseed(ctx, trust, m)
	case CmdFinish:
		var m Finish
		if err := json.Unmarshal(payload, &m); err != nil {
			return nil, fmt.Errorf("%s", ErrBadWire)
		}
		if err := h.install(ctx, trust, m.Secrets, SecretAuth); err != nil {
			return nil, err
		}
		return Ack{OK: true}, nil
	case CmdDevice:
		var m Device
		if err := json.Unmarshal(payload, &m); err != nil {
			return nil, fmt.Errorf("%s", ErrBadWire)
		}
		// Anycast: the interface is known in advance and not looked up. The address lives on loopback on both
		// nodes and never moves, and a route lookup for a real anycast address would end in device_unresolved:
		// such a /32 belongs to no interface subnet.
		if m.Provider == store.ProviderAnycast {
			return DeviceAck{NodeID: h.Node.NodeID(), Device: store.AnycastDevice}, nil
		}
		// An HONEST answer either way: if we could not determine it, say so. An empty answer would look like
		// "no interface", which is different.
		dev, err := h.Node.DeviceFor(ctx, m.ServiceAddress)
		if err != nil {
			return DeviceAck{NodeID: h.Node.NodeID(), Error: err.Error()}, nil
		}
		return DeviceAck{NodeID: h.Node.NodeID(), Device: dev}, nil
	case CmdCheck:
		var m Check
		if err := json.Unmarshal(payload, &m); err != nil {
			return nil, fmt.Errorf("%s", ErrBadWire)
		}
		// An HONEST answer either way: if we could not check, say so. An empty answer would look like "no
		// conflicts", which is different, and the caller must be able to tell them apart.
		c, err := h.Node.CheckPublication(ctx, m.Provider, m.ServiceAddress, m.ProbePort)
		if err != nil {
			return CheckAck{NodeID: h.Node.NodeID(), Error: err.Error()}, nil
		}
		return CheckAck{NodeID: h.Node.NodeID(), ProbePort: c.ProbePort, Address: c.Address}, nil
	case CmdSeed:
		var m Seed
		if err := json.Unmarshal(payload, &m); err != nil {
			return nil, fmt.Errorf("%s", ErrBadWire)
		}
		return h.seed(ctx, m)
	}
	return nil, fmt.Errorf("%s", ErrUnknown)
}

// recap returns the receiver's state: whether it has a revision and which. Read-only.
func (h *Handler) recap(ctx context.Context) (any, error) {
	rev, hash, blob, err := h.Node.Revision(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ErrExecution, err)
	}
	return RecapAck{NodeID: h.Node.NodeID(), Revision: rev, PayloadHash: hash, Payload: blob}, nil
}

// prepare sets up replication secrets and donor access. Receiver data is still untouched and nothing permanent
// in its settings changes: if something goes wrong later, it remains a working standalone node, including
// after a reboot.
func (h *Handler) prepare(ctx context.Context, trust Trust, m Prepare) (any, error) {
	if err := h.install(ctx, trust, m.Secrets, SecretRepl, SecretMonitor); err != nil {
		return nil, err
	}
	if err := h.Node.EnsureGrants(ctx, trust.PeerHost); err != nil {
		return nil, fmt.Errorf("%s: replication access for the donor: %w", ErrExecution, err)
	}
	// Determine our own interface for the service address: on the donor it may be named differently.
	dev := ""
	if m.Provider == store.ProviderAnycast {
		dev = store.AnycastDevice
	} else if m.ServiceAddress != "" {
		var err error
		if dev, err = h.Node.DeviceFor(ctx, m.ServiceAddress); err != nil {
			return nil, fmt.Errorf("%s: interface for %s: %w", ErrExecution, m.ServiceAddress, err)
		}
	}
	// The donor does not know its own address: addresses live in the revision, which does not exist yet. But
	// we see where it talks to us from, and the revision gets that observed value, not a claimed one.
	return PrepareAck{NodeID: h.Node.NodeID(), SeenDonorHost: trust.PeerHost, Hostname: h.Node.Hostname(),
		PublicationDevice: dev}, nil
}

// reseed rebuilds this node from the donor. The source comes from OUR pairing record: an address from the
// message would be a second source of truth about where to copy the database from.
func (h *Handler) reseed(ctx context.Context, trust Trust, m Reseed) (any, error) {
	if m.OperationID == "" {
		return nil, fmt.Errorf("%s: reseed without an operation id", ErrBadWire)
	}
	if m.Epoch <= 0 {
		return nil, fmt.Errorf("%s: reseed without an epoch", ErrBadWire)
	}
	if err := h.Node.Reseed(ctx, trust.PeerHost, m.OperationID, m.Epoch); err != nil {
		return nil, fmt.Errorf("%s: %w", ErrExecution, err)
	}
	return Ack{OK: true}, nil
}

// seed sets fail-safe, revision 1 and epoch 1. Check that the pair includes us: a configuration without our
// UUID does not describe us and must not be written.
func (h *Handler) seed(ctx context.Context, m Seed) (any, error) {
	p, err := Payload(m.Payload)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ErrBadWire, err)
	}
	me, active := h.Node.NodeID(), m.Active
	var haveMe, haveActive bool
	for _, n := range p.Nodes {
		haveMe = haveMe || n.NodeID == me
		haveActive = haveActive || n.NodeID == active
	}
	if !haveMe {
		return nil, fmt.Errorf("%s: the pair configuration does not contain node %s", ErrBadWire, me)
	}
	if !haveActive {
		return nil, fmt.Errorf("%s: node %s is named active but is not part of the pair", ErrBadWire, active)
	}
	if active == me {
		// The receiver made active? That is the driving side's error and must be refused: the right to be
		// ACTIVE is the one thing a node cannot grant itself.
		return nil, fmt.Errorf("%s: the receiver cannot be named active when the pair is created", ErrBadWire)
	}
	// Fail-safe goes here, not earlier: it changes MariaDB behavior AFTER a reboot, and a node that did not
	// become part of the pair must not wake up read_only one day with no pair at all. The reseed does not need
	// it either: ReseedReplica puts the node read_only for its duration.
	if err := h.Node.EnableFailsafe(ctx); err != nil {
		return nil, fmt.Errorf("%s: fail-safe: %w", ErrExecution, err)
	}
	if err := h.Node.SeedRevision(ctx, p, m.Epoch, active); err != nil {
		return nil, fmt.Errorf("%s: %w", ErrExecution, err)
	}
	return Ack{OK: true}, nil
}

// install decrypts and stores the named secrets. Names are checked against the expected list: the peer must
// not be able to send "one more" secret we did not agree on.
func (h *Handler) install(ctx context.Context, trust Trust, sealed map[string]string, want ...string) error {
	for _, name := range want {
		s, ok := sealed[name]
		if !ok {
			return fmt.Errorf("%s: secret %s was not sent", ErrBadWire, name)
		}
		value, err := peer.OpenSecret(trust.PeerKey, name, s)
		if err != nil {
			return fmt.Errorf("%s: secret %s: %w", ErrBadWire, name, err)
		}
		if err := h.Node.InstallSecret(ctx, name, string(value)); err != nil {
			return fmt.Errorf("%s: secret %s: %w", ErrExecution, name, err)
		}
	}
	return nil
}
