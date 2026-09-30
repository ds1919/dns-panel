// Package pairsetup turns two paired nodes into an HA pair.
//
// Pairing (internal/pairing) ends in trust: a shared channel secret and knowing who the peer is. There is no
// pair yet: each node has its own data, its own secrets and no roles. The rest happens here: the DONOR chosen by
// the human keeps its data, the receiver is rebuilt from it, and only after proven replication do revision 1,
// epoch 1 and roles appear.
//
// The DONOR drives the sequence. All destructive actions happen on the receiver, but the command comes from
// whoever keeps their data: "create a pair" and "keep my data" are one action of one person, not two decisions
// on different servers.
//
// No new primitives here. Reseed is the existing ReseedReplica, grants, secrets and fail-safe are agent
// commands, the revision is a plain SeedRevision. The package's only job is to run them in the right order and
// stop if anything does not match.
package pairsetup

import "encoding/json"

// Initialization commands. They share port 7901 and are accepted ONLY while the node has no effective
// revision: once a pair exists each of them is refused. That is the line between "being assembled" and
// "operating".
const (
	CmdPrepare = "init_prepare" // replication secrets, grants, fail-safe
	CmdReseed  = "init_reseed"  // receiver is rebuilt from the donor
	CmdFinish  = "init_finish"  // TOTP encryption key, AFTER a successful reseed
	CmdSeed    = "init_seed"    // revision 1 and epoch 1
	// CmdDevice asks "which interface reaches this address". Read-only: the human must SEE where the
	// system will bring up the service address before anything is created.
	CmdDevice = "init_device"
	// CmdRecap asks "what do you already have". Needed by a retry: half the pair may already be built, and
	// starting from scratch is wrong, while failing on "pair already exists" is worse.
	CmdRecap = "init_recap"
	// CmdCheck asks "are the probe port and service address free on you". Read-only, and asked BEFORE any
	// destructive step: a busy port or foreign address is a predictable refusal, and learning about it after
	// reseeding someone's database is unacceptable.
	CmdCheck = "init_check"
)

// Conflicts is what prevents a node from publishing. Empty strings mean nothing.
type Conflicts struct {
	ProbePort string
	Address   string
}

// Empty reports that there are no conflicts.
func (c Conflicts) Empty() bool { return c.ProbePort == "" && c.Address == "" }

// Check is what to check on a node before pair creation.
type Check struct {
	Provider       string `json:"provider,omitempty"`
	ServiceAddress string `json:"service_address,omitempty"`
	ProbePort      int    `json:"probe_port,omitempty"`
}

// CheckAck is what the node reported about itself. Empty strings mean nothing is in the way.
type CheckAck struct {
	NodeID    string `json:"node_id"`
	ProbePort string `json:"probe_port,omitempty"`
	Address   string `json:"address,omitempty"`
	Error     string `json:"error,omitempty"`
}

// Conflict returns one line for the human, or empty.
func (a CheckAck) Conflict() string {
	switch {
	case a.ProbePort != "" && a.Address != "":
		return a.ProbePort + "; " + a.Address
	case a.ProbePort != "":
		return a.ProbePort
	}
	return a.Address
}

// RecapAck is the receiver's state as seen by a retry.
type RecapAck struct {
	NodeID      string          `json:"node_id"`
	Revision    int64           `json:"revision"`
	PayloadHash string          `json:"payload_hash,omitempty"`
	Payload     json.RawMessage `json:"payload,omitempty"`
}

// Device/DeviceAck are the interface question and its answer.
type Device struct {
	ServiceAddress string `json:"service_address"`
	Provider       string `json:"provider,omitempty"`
}

type DeviceAck struct {
	NodeID string `json:"node_id"`
	Device string `json:"device,omitempty"`
	Error  string `json:"error,omitempty"`
}

// Prepare is what the receiver must get before the reseed.
//
// No addresses on purpose. Each side takes the peer address from ITS OWN pairing record, where it already is,
// taken from the observed connection. Sending it in the message would create a second source of truth about
// who is where, and one day they would diverge.
type Prepare struct {
	// Secrets maps name -> value encrypted with the channel key (see peer.SealSecret). Passwords do not
	// travel in clear over a signed but unencrypted channel.
	Secrets map[string]string `json:"secrets"`
	// ServiceAddress is the pair address. The receiver needs it for one thing only: to find WHICH OF ITS
	// interfaces reaches it. NIC names on the two machines need not match.
	ServiceAddress string `json:"service_address,omitempty"`
	// Provider is the publication method, needed for the same reason: for anycast no interface is looked up
	// at all (the address lives on loopback and never moves), and a route lookup for a real anycast address
	// would fail since such a /32 belongs to no interface subnet.
	Provider string `json:"provider,omitempty"`
}

// PrepareAck is the receiver's reply. SeenDonorHost is the donor's address AS THE RECEIVER SEES IT: the donor
// does not know its own address (addresses live in the revision, which does not exist yet), yet the revision needs it.
type PrepareAck struct {
	NodeID        string `json:"node_id"`
	SeenDonorHost string `json:"seen_donor_host"`
	Hostname      string `json:"hostname,omitempty"`
	// PublicationDevice is the interface on which the RECEIVER will bring up the service address, determined
	// by itself: asking a human for another machine's NIC name is a way to find the mistake at role switch.
	PublicationDevice string `json:"publication_device,omitempty"`
}

// Reseed orders the receiver to rebuild from the donor. The receiver takes the source from its pairing record.
//
// OperationID and Epoch are needed by the agent mutation contract: reseed is a normal mutation, and a retry
// with the same operation_id must not run it twice.
type Reseed struct {
	OperationID string `json:"operation_id"`
	Epoch       int64  `json:"epoch"`
}

// Finish carries the donor's TOTP encryption key. A separate step AFTER the reseed: it is not needed before,
// and installed earlier it breaks the still-running standalone receiver (its own database, a foreign key).
type Finish struct {
	Secrets map[string]string `json:"secrets"`
}

// Seed carries revision 1 and epoch 1. Content travels as CANONICAL BYTES: the sides converge not by agreeing
// but by having the same bytes and hence the same fingerprint.
type Seed struct {
	Payload json.RawMessage `json:"payload"`
	Epoch   int64           `json:"epoch"`
	Active  string          `json:"active"` // who becomes ACTIVE at creation (the donor)
}

// Ack is the common positive reply for steps with nothing to return.
type Ack struct {
	OK   bool   `json:"ok"`
	Noop bool   `json:"noop,omitempty"`
	Note string `json:"note,omitempty"`
}
