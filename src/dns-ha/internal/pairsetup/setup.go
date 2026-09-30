package pairsetup

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"

	"dnspanel/dns-ha/internal/peer"
	"dnspanel/dns-ha/internal/store"
)

// Names of the secrets the pair agrees on. Exactly three: two for replication in both directions and one for
// decrypting TOTP in the transferred database. The node's other secrets (own DB access, PowerDNS API key) are
// local and need not match; see §14.6.
const (
	SecretRepl    = "repl.secret"
	SecretMonitor = "ha_monitor.secret"
	SecretAuth    = "auth-master.key"
)

// FirstEpoch is the epoch a pair starts at. One, not zero: the epoch is monotonic, and "seen none yet" must
// differ from "seen the first".
const FirstEpoch = 1

// Trust is what the node knows about the peer after pairing.
type Trust struct {
	PeerNodeID string
	PeerHost   string // peer address WITHOUT port: usable as is for both GRANT and CHANGE MASTER
	PeerKey    []byte // channel secret; it also encrypts the transferred secrets
}

// Node is the node's local actions. Everything touching the world is behind this interface, so the step
// sequence (the substance of this package) is testable without MariaDB, root or network.
type Node interface {
	NodeID() string
	Hostname() string
	Trust(ctx context.Context) (Trust, error)
	// HasHAConfig reports whether there is an effective revision, i.e. whether HA is on. Until then the node
	// is "being assembled"; once there is one, HA is configured and init commands must be refused.
	//
	// This is NOT "is the node paired": trust is asked separately via Trust() and survives HA dismantling.
	// The two questions are asked in turn here: first "is HA not yet configured?", then "is there a peer?".
	HasHAConfig(ctx context.Context) (bool, error)
	// Revision returns the node's effective revision: number, fingerprint and canonical bytes (0 and empty if
	// none). A retry uses it to learn that half the work is done and completes the other half with THE SAME
	// content, not a recomputed one.
	Revision(ctx context.Context) (int64, string, []byte, error)

	Secret(ctx context.Context, name string) (string, error) // empty if the secret is absent
	InstallSecret(ctx context.Context, name, value string) error
	EnsureGrants(ctx context.Context, host string) error
	EnableFailsafe(ctx context.Context) error
	Reseed(ctx context.Context, primary, operationID string, epoch int64) error
	// DeviceFor returns which interface THIS node uses to reach the service address. Asked of the node itself:
	// NIC names on the two machines need not match, and expecting a human to know the other machine's
	// interface name is a sure way to discover the mistake at role switch.
	DeviceFor(ctx context.Context, address string) (string, error)
	// CheckPublication reports whether the probe port and service address are free on THIS node. Read-only.
	// Empty strings mean nothing is in the way; an error means "could not check", which is NOT the same.
	CheckPublication(ctx context.Context, provider, address string, probePort int) (Conflicts, error)
	SeedRevision(ctx context.Context, payload store.ConfigPayload, epoch int64, active string) error
}

// Peer calls the peer over the pair channel.
type Peer interface {
	Call(ctx context.Context, cmd string, payload any, out any) error
}

// Plan holds the human's decisions: everything that cannot be derived from node state.
type Plan struct {
	// Provider is how the service address is published: floating_ip, anycast or marker (an external
	// provider manages the address).
	Provider string
	Address  string // CIDR, e.g. 192.0.2.10/32
	// ProbePort is the readiness probe port (anycast). floating_ip has none: there the address is the publication.
	ProbePort int
	// PeerListenPort is the pair channel port, the same one pairing used.
	PeerListenPort int
	// SelfHost is THIS node's address if the human wants to set it explicitly. Usually empty: the donor
	// learns its address from the receiver, which sees where the connection came from.
	SelfHost string
	// RequestedBy is who creates the pair; recorded in the revision as the author.
	RequestedBy string
	// OperationID identifies this attempt. A retry with the same value does not reseed a second time.
	OperationID string
}

// checkResources checks that the probe port and service address are free on BOTH nodes.
//
// Both sides are asked because a conflict on either is equally fatal: a pair whose STANDBY cannot open the
// probe finds out only at role switch, the worst possible moment. The node name goes into the message: "port
// busy" without saying where sends the human searching blindly across two machines.
func (s *Setup) checkResources(ctx context.Context, plan Plan, trust Trust) error {
	mine, err := s.Node.CheckPublication(ctx, plan.Provider, plan.Address, plan.ProbePort)
	if err != nil {
		return fmt.Errorf("checking publication resources on this node: %w", err)
	}
	if !mine.Empty() {
		return fmt.Errorf("cannot configure %s on this node: %s", plan.Provider, conflictText(mine))
	}
	var ack CheckAck
	if err := s.Peer.Call(ctx, CmdCheck,
		Check{Provider: plan.Provider, ServiceAddress: plan.Address, ProbePort: plan.ProbePort}, &ack); err != nil {
		return fmt.Errorf("checking publication resources on the other node: %w", err)
	}
	// "Could not check" is not "no conflicts". Proceeding on that would treat the unknown as confirmation,
	// exactly what we eliminated everywhere else.
	if ack.Error != "" {
		return fmt.Errorf("the other node could not check its publication resources: %s", ack.Error)
	}
	if c := ack.Conflict(); c != "" {
		return fmt.Errorf("cannot configure %s on %s: %s", plan.Provider, peerName(trust, ack), c)
	}
	return nil
}

func conflictText(c Conflicts) string {
	switch {
	case c.ProbePort != "" && c.Address != "":
		return c.ProbePort + "; " + c.Address
	case c.ProbePort != "":
		return c.ProbePort
	}
	return c.Address
}

// peerName is how to name the peer in a message: the ID it reported itself, falling back to the node we are
// paired with.
func peerName(trust Trust, ack CheckAck) string {
	if ack.NodeID != "" {
		return ack.NodeID
	}
	if trust.PeerNodeID != "" {
		return trust.PeerNodeID
	}
	return "the other node"
}

// publicationDevice returns the interface on which THIS node will bring up the service address.
//
// Ours we look up locally; the peer named its own in the prepare reply: the pair shares the address, but each
// node has its own interfaces, and NIC names on two machines need not match.
func (s *Setup) publicationDevice(ctx context.Context, plan Plan, ack PrepareAck) (string, error) {
	switch {
	case plan.Provider == store.ProviderAnycast:
		// Anycast: no interface lookup. The address never moves and lives on loopback on both nodes; asking
		// for a route to it is pointless (a raised address routes via lo, an unraised one has no route), and a
		// choice here would only be a chance to get it wrong.
		return store.AnycastDevice, nil
	case plan.Address != "":
		dev, err := s.Node.DeviceFor(ctx, plan.Address)
		if err != nil {
			return "", fmt.Errorf("interface for %s on this node: %w", plan.Address, err)
		}
		if ack.PublicationDevice == "" {
			return "", fmt.Errorf("the receiver could not determine the interface for %s", plan.Address)
		}
		return dev, nil
	}
	return "", nil
}

// preflight runs the checks that need neither peer nor database: provider, address, probe port.
//
// It also NORMALIZES the address (adds the host prefix for anycast), hence the pointer receiver: the rest of
// the sequence works with the canonical string, and that is what goes into the revision. Otherwise the address
// would have to be canonicalized everywhere it is compared, including completing a half-built pair, where a
// mismatch would read as "the human entered a different address".
func (p *Plan) preflight() error {
	switch p.Provider {
	case store.ProviderAnycast:
		addr, err := store.NormalizeAnycastAddress(p.Address)
		if err != nil {
			return err
		}
		p.Address = addr
		// The probe is the only way anycast signals readiness, since the address is up on both nodes; without
		// it the pair looks reachable via both nodes at once.
		//
		// The lower bound of 1024 is not a matter of taste. The privileged agent checks the port is free, while
		// the manager opens the probe as user `dns-ha`: below 1024 the agent would honestly say "free" and the
		// manager would then fail to open it, making the check harmful by confirming the impossible.
		if p.ProbePort < store.MinProbePort || p.ProbePort > 65535 {
			return fmt.Errorf("config_payload_invalid: anycast needs a probe port in %d..65535 (got %d)",
				store.MinProbePort, p.ProbePort)
		}
	case store.ProviderFloatingIP:
		if p.Address == "" {
			return fmt.Errorf("config_payload_invalid: floating_ip without a service address")
		}
		if _, _, err := net.ParseCIDR(strings.TrimSpace(p.Address)); err != nil {
			return fmt.Errorf("config_payload_invalid: service address %q: %v", p.Address, err)
		}
		p.Address = strings.TrimSpace(p.Address)
	case store.ProviderMarker, "":
		// An external provider manages the address: nothing to check.
	default:
		return fmt.Errorf("config_payload_invalid: unknown publication provider %q", p.Provider)
	}
	return nil
}

// Devices is where each node will bring up the service address. Asked BEFORE pair creation: the human must see
// what the system found rather than learn it at the first role switch.
type Devices struct {
	Local     string `json:"local,omitempty"`
	LocalErr  string `json:"local_error,omitempty"`
	Peer      string `json:"peer,omitempty"`
	PeerErr   string `json:"peer_error,omitempty"`
	PeerNode  string `json:"peer_node_id,omitempty"`
	LocalNode string `json:"local_node_id,omitempty"`
}

// ResolveDevices returns both sides' interfaces for the given address.
func (s *Setup) ResolveDevices(ctx context.Context, address, provider string) Devices {
	out := Devices{LocalNode: s.Node.NodeID()}
	if address == "" {
		return out
	}
	// Anycast: the interface is neither chosen nor looked up; it is always loopback on both nodes.
	if provider == store.ProviderAnycast {
		out.Local, out.Peer = store.AnycastDevice, store.AnycastDevice
		return out
	}
	if dev, err := s.Node.DeviceFor(ctx, address); err != nil {
		out.LocalErr = err.Error()
	} else {
		out.Local = dev
	}
	var ack DeviceAck
	if err := s.Peer.Call(ctx, CmdDevice, Device{ServiceAddress: address, Provider: provider}, &ack); err != nil {
		out.PeerErr = err.Error()
	} else {
		out.Peer, out.PeerErr, out.PeerNode = ack.Device, ack.Error, ack.NodeID
	}
	return out
}

// Report is the outcome, returned to the human and the journal.
type Report struct {
	Donor       string `json:"donor"`
	Receiver    string `json:"receiver"`
	Epoch       int64  `json:"epoch"`
	Revision    int64  `json:"revision"`
	PayloadHash string `json:"payload_hash"`
	DonorHost   string `json:"donor_host"`
	PeerHost    string `json:"peer_host"`
}

// Setup is the DONOR side: the one whose data survives.
type Setup struct {
	Node Node
	Peer Peer
	// Progress, if set, is told each step as it starts (n of StepCount), so the panel can say what the minutes
	// of a pair creation are spent on.
	Progress func(n int, label string)
}

// StepCount is the number of steps Create reports.
const StepCount = 8

func (s *Setup) step(n int, label string) {
	if s.Progress != nil {
		s.Progress(n, label)
	}
}

// Create runs the whole sequence. The order is the substance: nothing irreversible happens before a proven
// reseed, and roles and the epoch come last.
func (s *Setup) Create(ctx context.Context, plan Plan) (Report, error) {
	if plan.OperationID == "" {
		return Report{}, fmt.Errorf("pair creation without an operation id: a repeat would be a second reseed")
	}
	// EVERYTHING checkable without mutations is checked HERE, before the first irreversible step.
	//
	// This is not pedantry. Provider, address and probe port used to be checked first when building the payload,
	// which happens AFTER the receiver is reseeded. So a typo in the address ("10.0.0.53" without a prefix) first
	// spent minutes rebuilding someone's database, and only then did the human read "invalid CIDR address".
	// Destroying data and then refusing over a string format is the worst thing possible here.
	if err := plan.preflight(); err != nil {
		return Report{}, err
	}
	// "HA is not yet configured HERE" is checked BEFORE completing a half-built pair, not after.
	//
	// The order matters: completion itself writes (fail-safe and revision), and doing that without proving the
	// node is free means mutating before checking. The panel will not show the button over a working pair, but the
	// backend must forbid it: we deliberately made "no revisions" fail-closed, and relying on UI discipline here
	// would bypass our own protection.
	if err := s.mustHaveNoHAConfig(ctx); err != nil {
		return Report{}, err
	}
	trust, err := s.Node.Trust(ctx)
	if err != nil {
		return Report{}, err
	}
	if trust.PeerNodeID == "" {
		return Report{}, fmt.Errorf("this node is not paired with anyone — pairing comes first")
	}

	s.step(1, "Checking the service address and probe port on both nodes")
	// 0. RESOURCES on both nodes: probe port and service address. Before EVERYTHING, including completion.
	//
	// This order cost a bug. The check was first placed after finishHalfBuilt, reasoning that completion does not
	// change publication and need not be blocked by our own address. Wrong: completion returns from Create
	// immediately, so on that path resources would NEVER be checked. The pair would complete, and a busy port would
	// surface only later as a closed probe, exactly what we wanted to avoid.
	//
	// Our own address does not block completion: a host prefix up on loopback is precisely the state anycast aims
	// for and is not a conflict.
	if err := s.checkResources(ctx, plan, trust); err != nil {
		return Report{}, err
	}

	// Half the pair may have been built last time: the receiver got its revision, the donor did not write its own.
	// Then a retry does not start over (the receiver would answer "pair already exists") but completes the
	// remaining half with the same content, otherwise the sides would describe the pair differently.
	if done, err := s.finishHalfBuilt(ctx, plan); err != nil || done.Revision != 0 {
		return done, err
	}

	s.step(2, "Preparing replication secrets")
	// 1. Replication secrets. The donor is the working node, so its values become shared; if absent (fresh
	//    install) it generates them and stores them locally.
	repl, err := s.ownSecret(ctx, SecretRepl, randomPassword)
	if err != nil {
		return Report{}, err
	}
	monitor, err := s.ownSecret(ctx, SecretMonitor, randomPassword)
	if err != nil {
		return Report{}, err
	}
	sealed, err := sealAll(trust.PeerKey, map[string]string{SecretRepl: repl, SecretMonitor: monitor})
	if err != nil {
		return Report{}, err
	}

	s.step(3, "Giving the other node access to this one")
	// 2. Receiver: secrets and grants for the donor. Its data is still untouched and nothing permanent in its
	//    settings changes.
	var ack PrepareAck
	if err := s.Peer.Call(ctx, CmdPrepare,
		Prepare{Secrets: sealed, ServiceAddress: plan.Address, Provider: plan.Provider}, &ack); err != nil {
		return Report{}, fmt.Errorf("preparing the receiver: %w", err)
	}
	if ack.NodeID != trust.PeerNodeID {
		return Report{}, fmt.Errorf("node %s confirmed the preparation, but we are paired with %s", ack.NodeID, trust.PeerNodeID)
	}
	donorHost := plan.SelfHost
	if donorHost == "" {
		donorHost = ack.SeenDonorHost
	}
	if donorHost == "" {
		return Report{}, fmt.Errorf("the receiver did not report the address it sees the donor at")
	}

	s.step(4, "Giving this node access to the other one")
	// 3. Donor: access for the receiver. Grants are created BEFORE replication starts: afterwards account DDL
	//    goes into the binlog, and the same command on the receiver causes divergence.
	//
	//    Fail-safe is NOT set here: it changes MariaDB behavior after a reboot and there is no pair yet. A node
	//    whose pair creation failed must not wake up read_only one day with no pair.
	if err := s.Node.EnsureGrants(ctx, trust.PeerHost); err != nil {
		return Report{}, fmt.Errorf("replication access for the receiver: %w", err)
	}

	s.step(5, "Building the pair configuration")
	// 4. The pair configuration is BUILT AND VALIDATED BEFORE the reseed.
	//
	// Everything it needs is known by now: the human's decisions, our interface and what the receiver reported in
	// the prepare reply. Prepare is harmless and the receiver's data is intact, so HERE is the last moment the pair
	// description can be rejected for free.
	//
	// The payload used to be built after the reseed, and any defect in it (address format, interface not found)
	// surfaced after someone's database was already rebuilt. The refusal cost the human the receiver's data and
	// several minutes, when it could have been refused at once.
	donorDevice, err := s.publicationDevice(ctx, plan, ack)
	if err != nil {
		return Report{}, err
	}
	payload, err := s.payload(plan, trust, donorHost, donorDevice, ack)
	if err != nil {
		return Report{}, err
	}
	canonical, err := payload.Canonical()
	if err != nil {
		return Report{}, err
	}
	hash, err := payload.Hash()
	if err != nil {
		return Report{}, err
	}

	s.step(6, "Copying the database to the other node")
	// 5. Reseed. The only irreversible step for the receiver, and the only one proving replication really
	//    works: ReseedReplica ends by checking IO/SQL threads and position.
	if err := s.Peer.Call(ctx, CmdReseed,
		Reseed{OperationID: plan.OperationID, Epoch: FirstEpoch}, &Ack{}); err != nil {
		return Report{}, fmt.Errorf("rebuilding the receiver: %w", err)
	}

	s.step(7, "Sharing the sign-in encryption key")
	// 6. TOTP encryption key, only now: the receiver now deliberately holds the donor's data.
	auth, err := s.ownSecret(ctx, SecretAuth, randomMasterKey)
	if err != nil {
		return Report{}, err
	}
	sealedAuth, err := sealAll(trust.PeerKey, map[string]string{SecretAuth: auth})
	if err != nil {
		return Report{}, err
	}
	if err := s.Peer.Call(ctx, CmdFinish, Finish{Secrets: sealedAuth}, &Ack{}); err != nil {
		return Report{}, fmt.Errorf("TOTP encryption key: %w", err)
	}

	s.step(8, "Writing the pair configuration on both nodes")
	// 7. Revision. The same canonical bytes on both sides is what agreement means; they were built above, before
	// the reseed.
	//
	// Receiver first: it becomes STANDBY and is harmless without the donor. The reverse order, if interrupted,
	// would leave a working ACTIVE with a pair the other node does not know about.
	//
	// A retry is safe: with THE SAME revision the receiver's step is idempotent (SeedRevision checks the
	// fingerprint); with a different one it refuses, rightly: two different descriptions of one pair must not be
	// reconciled.
	if err := s.Peer.Call(ctx, CmdSeed,
		Seed{Payload: canonical, Epoch: FirstEpoch, Active: s.Node.NodeID()}, &Ack{}); err != nil {
		return Report{}, fmt.Errorf("revision 1 on the receiver: %w", err)
	}
	// Donor fail-safe goes together with its revision, for the same reason: while there is no pair, a working
	// standalone node gets no permanent HA setting.
	if err := s.Node.EnableFailsafe(ctx); err != nil {
		return Report{}, fmt.Errorf("fail-safe on the donor: %w", err)
	}
	if err := s.Node.SeedRevision(ctx, payload, FirstEpoch, s.Node.NodeID()); err != nil {
		return Report{}, fmt.Errorf("revision 1 on the donor: %w", err)
	}

	return Report{Donor: s.Node.NodeID(), Receiver: trust.PeerNodeID, Epoch: FirstEpoch, Revision: 1,
		PayloadHash: hash, DonorHost: donorHost, PeerHost: trust.PeerHost}, nil
}

// finishHalfBuilt completes a pair of which only half was built.
//
// It happens: the receiver got its revision and became STANDBY, but the donor did not write its own, and
// pressing the button again would hit "pair already exists" on the receiver. Complete with EXACTLY the content
// the receiver already has: recomputing it risks two different descriptions of one pair.
//
// An empty report means "nothing to complete"; the normal path follows.
func (s *Setup) finishHalfBuilt(ctx context.Context, plan Plan) (Report, error) {
	trust, err := s.Node.Trust(ctx)
	if err != nil || trust.PeerNodeID == "" {
		return Report{}, err
	}
	var recap RecapAck
	if err := s.Peer.Call(ctx, CmdRecap, struct{}{}, &recap); err != nil {
		return Report{}, nil // peer did not answer: let the normal path report it clearly
	}
	if recap.Revision == 0 || len(recap.Payload) == 0 {
		return Report{}, nil
	}
	p, err := Payload(recap.Payload)
	if err != nil {
		return Report{}, fmt.Errorf("the receiver already has revision %d, but its payload is unreadable: %w",
			recap.Revision, err)
	}
	hash, err := p.Hash()
	if err != nil {
		return Report{}, err
	}
	if recap.PayloadHash != "" && recap.PayloadHash != hash {
		return Report{}, fmt.Errorf("the receiver's revision %d does not match its own fingerprint", recap.Revision)
	}
	var haveMe bool
	for _, n := range p.Nodes {
		haveMe = haveMe || n.NodeID == s.Node.NodeID()
	}
	if !haveMe {
		return Report{}, fmt.Errorf("the receiver already has revision %d describing a pair without this node "+
			"— undo pairing and start over", recap.Revision)
	}
	// The publication settings the human chose NOW must match the recorded ones in full, not just the address.
	//
	// Completion finishes the OLD configuration already on the receiver; rebuilding it is not possible without the
	// sides getting different descriptions of one pair. So a mismatch with the form must be refused, not silently
	// "finish what was there". Comparing only the address was not enough: the human could switch the provider from
	// anycast to floating_ip or fix the probe port, see one thing on screen and get another, and only find out when
	// a role switch behaved unexpectedly.
	if err := halfBuiltMatches(p, plan, recap.Revision); err != nil {
		return Report{}, err
	}
	if err := s.Node.EnableFailsafe(ctx); err != nil {
		return Report{}, fmt.Errorf("fail-safe on the donor: %w", err)
	}
	if err := s.Node.SeedRevision(ctx, p, FirstEpoch, s.Node.NodeID()); err != nil {
		return Report{}, fmt.Errorf("revision 1 on the donor: %w", err)
	}
	donorHost := ""
	for _, n := range p.Nodes {
		if n.NodeID == s.Node.NodeID() {
			donorHost = n.PeerListenHost
		}
	}
	return Report{Donor: s.Node.NodeID(), Receiver: trust.PeerNodeID, Epoch: FirstEpoch, Revision: 1,
		PayloadHash: hash, DonorHost: donorHost, PeerHost: trust.PeerHost}, nil
}

// halfBuiltMatches checks that the publication recorded on the receiver matches what the human chose now.
//
// Only the USER's decisions are checked: provider, address and, for anycast, the probe port. Everything else
// in the revision the nodes derived themselves (interfaces, channel addresses, secrets); a mismatch there would
// be our own bug, not a different intent.
//
// Empty form fields are not compared: a retry without parameters means "finish what was started".
func halfBuiltMatches(p store.ConfigPayload, plan Plan, rev int64) error {
	have, want := "", plan.Provider
	if pub := p.Publication; pub != nil {
		have = pub.Provider
	}
	if want != "" && have != want {
		return fmt.Errorf("the receiver already has a half-built %s configuration (revision %d), but %s was "+
			"requested — repeat with the same settings, or undo the incomplete configuration", have, rev, want)
	}
	if addr, _ := p.PublicationTarget(); plan.Address != "" && addr != plan.Address {
		return fmt.Errorf("the receiver already has a half-built configuration for %s (revision %d) — "+
			"repeat with the same service address, or undo the incomplete configuration", addr, rev)
	}
	// The probe port is part of the anycast setup, not a detail: it is how the pair signals readiness, since
	// the address is up on both nodes at once.
	if have == store.ProviderAnycast && plan.ProbePort > 0 {
		if port := p.ProbePort(); port != plan.ProbePort {
			return fmt.Errorf("the receiver already has a half-built anycast configuration with probe port %d "+
				"(revision %d), but %d was requested — repeat with the same settings, or undo the incomplete "+
				"configuration", port, rev, plan.ProbePort)
		}
	}
	return nil
}

// payload builds the pair configuration from the human's decisions and the addresses the nodes learned about each other.
func (s *Setup) payload(plan Plan, trust Trust, donorHost, donorDevice string, ack PrepareAck) (store.ConfigPayload, error) {
	port := plan.PeerListenPort
	if port == 0 {
		port = 7901
	}
	provider := plan.Provider
	if provider == "" {
		provider = "marker" // someone outside manages the address: a valid pair, not an unfinished one
	}
	params := ""
	if plan.Address != "" {
		params = "address=" + plan.Address
	}
	// Anycast is published by an open probe, not by the address, so its port is as much part of the pair
	// configuration as the address: identical on both nodes and must survive a role switch.
	if provider == store.ProviderAnycast && plan.ProbePort > 0 {
		params += ",probe_port=" + strconv.Itoa(plan.ProbePort)
	}
	donor := store.ConfigNode{NodeID: s.Node.NodeID(), Hostname: s.Node.Hostname(), Enabled: 1,
		PeerListenHost: donorHost, PeerListenPort: port, ReplicationHost: donorHost,
		PublicationDevice: donorDevice}
	receiverDevice := ack.PublicationDevice
	if provider == store.ProviderAnycast {
		receiverDevice = store.AnycastDevice
	}
	receiver := store.ConfigNode{NodeID: trust.PeerNodeID, Hostname: ack.Hostname, Enabled: 1,
		PeerListenHost: trust.PeerHost, PeerListenPort: port, ReplicationHost: trust.PeerHost,
		PublicationDevice: receiverDevice}
	p := store.ConfigPayload{
		Version: store.PayloadVersion,
		Nodes:   []store.ConfigNode{donor, receiver},
		Replication: &store.ConfigReplication{User: "repl", Port: 3306,
			SecretRef: "/opt/dns-panel/etc/secrets/" + SecretRepl},
		Publication: &store.ConfigPublication{Provider: provider, Params: params},
	}
	if err := p.Validate(); err != nil {
		return store.ConfigPayload{}, err
	}
	return p, nil
}

// ownSecret returns our value of a secret, generating and storing it if absent. The DONOR generates it: it is
// the working node, and its values become shared by the pair.
func (s *Setup) ownSecret(ctx context.Context, name string, gen func() (string, error)) (string, error) {
	v, err := s.Node.Secret(ctx, name)
	if err != nil {
		return "", fmt.Errorf("secret %s: %w", name, err)
	}
	if v != "" {
		return v, nil
	}
	if v, err = gen(); err != nil {
		return "", err
	}
	if err := s.Node.InstallSecret(ctx, name, v); err != nil {
		return "", fmt.Errorf("secret %s: %w", name, err)
	}
	return v, nil
}

// mustHaveNoHAConfig checks that HA is NOT yet configured on this node. It does not ask about trust at all: the
// similarly named check in pairing means something else ("not paired with anyone"), and using one word for two
// states already confused us: the panel showed the initial pairing screen for a dismantled pair.
func (s *Setup) mustHaveNoHAConfig(ctx context.Context) error {
	configured, err := s.Node.HasHAConfig(ctx)
	if err != nil {
		return err
	}
	if configured {
		return fmt.Errorf("HA is already configured: this node has an effective revision")
	}
	return nil
}

func sealAll(key []byte, values map[string]string) (map[string]string, error) {
	out := make(map[string]string, len(values))
	for name, v := range values {
		sealed, err := peer.SealSecret(key, name, []byte(v))
		if err != nil {
			return nil, fmt.Errorf("secret %s: %w", name, err)
		}
		out[name] = sealed
	}
	return out, nil
}

// randomPassword generates the replication account password. Printable and quote-free: it goes into an SQL
// string, a file and a human's eyes during troubleshooting.
func randomPassword() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// randomMasterKey generates the TOTP encryption key: EXACTLY 32 bytes in base64, as the panel requires.
func randomMasterKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// HostOf returns the peer address without the port. It is stored as host:port, but in GRANT and CHANGE MASTER a
// port means something else: 'repl'@'192.0.2.12:7901' is an account nobody will ever connect as.
func HostOf(endpoint string) (string, error) {
	if endpoint == "" {
		return "", fmt.Errorf("empty peer address")
	}
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		if ip := net.ParseIP(endpoint); ip != nil {
			return ip.String(), nil // an address without a port is also valid
		}
		return "", fmt.Errorf("peer address %q: %w", endpoint, err)
	}
	return host, nil
}

// Payload parses a revision's canonical bytes (receiver side).
func Payload(raw json.RawMessage) (store.ConfigPayload, error) {
	var p store.ConfigPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return p, fmt.Errorf("revision payload: %w", err)
	}
	return p, p.Validate()
}
