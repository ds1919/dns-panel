package observe

import (
	"time"

	"dnspanel/dns-ha/internal/safety"
	"dnspanel/dns-ha/internal/store"
)

// MaxPeerObservationAge is how old a peer snapshot may be to count as proof: a few observation cycles.
const MaxPeerObservationAge = 30 * time.Second

// Observation is the single input for everything downstream: health, the planner, peer status.
//
// It holds raw evidence, not conclusions: ha_healthy=false is a final classification and must never drive
// role changes. The planner sees the same facts a human sees in the report: who is ACTIVE by control state,
// the physical MariaDB/PowerDNS state, what the peer says, whether the right to be ACTIVE is proven.
//
// Each source carries its own error: "couldn't look" and "looked and it's bad" differ, and fail-closed
// depends on keeping them apart.
type Observation struct {
	NodeID      string
	At          time.Time
	Local       LocalState
	Peer        PeerState
	Config      ConfigState
	Safety      SafetyState
	Replication ReplicationState
	Prereqs     []Prerequisite
	PrereqError string
}

// LocalState is what this node physically is.
type LocalState struct {
	AgentOK    bool
	AgentError string

	// Physical state, observed via the privileged agent.
	ReadOnly       *int   // @@global.read_only
	NotifierOn     *int   // PowerDNS is actually primary
	SecondaryOn    *int   // PowerDNS pulls secondary zones itself; pairs with NotifierOn; nil means an older agent
	PDNSVersion    string // running PowerDNS version, for display only
	RouteAnnounced *int   // publication confirmed
	// AnycastAddressUp: the anycast address is up on loopback. Anycast only; for other providers the
	// publication is the address.
	AnycastAddressUp *int
	// What this node actually holds on the interface (observed, not configured).
	PublicationAddress string
	PublicationDevice  string
	// PublicationDeviceOK: the publication interface exists on this node. Checked before the point of no
	// return in a handoff: an address with nowhere to go must be refused up front, not discovered after the
	// source has already dropped it.
	PublicationDeviceOK bool

	// CurrentOperationID is this node's running operation (local dns_ha journal). Role and epoch are not here:
	// they live in the safety file, and a second source of the same truth would drift.
	CurrentOperationID string
	AgentMaxEpoch      *int64 // the privileged agent's durable max_epoch
	// IPDevice/IPCIDR are the interface and prefix of the node's own (peer-channel) address. Observed: the
	// node knows its own mask, and inventing one would one day show a network it doesn't have. Empty means
	// unknown, not "no interface".
	IPDevice string
	IPCIDR   string
	// ServiceAddressOK: DNS actually answers on the published address (TCP 53 accepts).
	//
	// "PowerDNS is alive" and "PowerDNS listens on our service address" diverged silently: address on loopback,
	// role ACTIVE, readiness probe open, yet `dig @10.0.0.53` got connection refused because the address was
	// missing from local-address. The probe promises the world a working DNS behind it; this check backs that.
	ServiceAddressOK bool
	// ServiceAddressError says why it does not answer; empty if not checked.
	ServiceAddressError string
	// StaleAnycastUp: the previous anycast address is still up on loopback. Without this observation the
	// cleanup command would be sent every cycle, since the previous revision stays in the table.
	StaleAnycastUp bool

	// Preflight is the agent's local node check (see PreflightView).
	Preflight PreflightView
}

// IsActive reports whether the node should be ACTIVE. There is no shared replicated "who is active" row
// any more: it was a Perl-era leftover living in the DB it could itself break.
//
// Two facts void the right, both stronger than our own proof:
//   - the node is fenced (by its own state or per the peer) — it was declared unsafe and does not get a vote;
//   - the peer proved a newer epoch — the role has moved and our proof belongs to a gone epoch.
//
// Without this, a node returning after the peer's emergency promotion would call itself ACTIVE on a stale
// right: the planner has its own rules against that, but status and operations would read a lie.
func (o Observation) IsActive() bool {
	if o.Safety.Authority.State != safety.AuthValidCurrent {
		return false
	}
	if o.Safety.FencedNode == o.NodeID || (o.Peer.Reachable && o.Peer.FencedNode == o.NodeID) {
		return false
	}
	if o.Safety.MaxSeenEpoch != nil && o.Peer.MaxSeenEpoch != nil && *o.Peer.MaxSeenEpoch > *o.Safety.MaxSeenEpoch {
		return false
	}
	return true
}

// HANotConfigured reports that HA is not configured on this node.
//
// This is not "unpaired": pairing and HA are separate levels. After dismantle the node still trusts its peer
// (pairing.Service keeps `trusted`) but there is no pair. Product states:
//
//	Standalone → (Pair) → Paired · HA not configured → (Configure HA) → Paired · HA active
//
// Dismantle returns to the middle of this chain. "No trusted peer" lives in pairing.mustBeUnpaired.
// Such a node has no roles and no epochs: both exist only inside a pair.
//
// This is the single definition for the whole loop: planner, plan builder and convergence must agree, or
// a node would end up both without HA and required to prove pair rights — locked forever.
func (o Observation) HANotConfigured() bool { return o.Config.NotSeeded }

// PhysicallyActive reports that the node actually accepts writes and is published.
func (l LocalState) PhysicallyActive() bool {
	return l.ReadOnly != nil && *l.ReadOnly == 0 &&
		l.NotifierOn != nil && *l.NotifierOn == 1 &&
		l.RouteAnnounced != nil && *l.RouteAnnounced == 1
}

// PeerState is what the peer reported about itself over the authenticated channel.
type PeerState struct {
	Reachable bool
	Error     string // typed reason for unavailability/refusal

	NodeID string
	// Hostname is the peer's current OS hostname. Observed: hostnames change independently of us, and a
	// snapshot taken at pair creation goes stale silently.
	Hostname string
	// ProbeOpenPort is the probe port actually open on the peer; 0 means none.
	ProbeOpenPort int
	// IPDevice/IPCIDR are the interface and prefix of the peer's own address. Only the peer knows them: NIC
	// names differ between machines and a mask cannot be derived from an address. Empty means not reported.
	IPDevice           string
	IPCIDR             string
	Role               string
	ServiceReady       bool
	HAHealthy          bool
	ReadOnly           *int
	NotifierOn         *int
	RouteAnnounced     *int
	PDNSVersion        string
	CurrentOperationID string
	FencedNode         string
	// MaxSeenEpoch is the epoch from the peer's safety file — the only epoch concept in the pair.
	MaxSeenEpoch   *int64
	ConfigRevision *int64
	ConfigHash     string
	ObservedAt     int64 // when the peer took its snapshot (not when we received it)
	// Stale: the peer is alive on the network and signs correctly, but its observation loop is not updating.
	// Such state is no proof, except for a newer epoch: that epoch existed regardless of snapshot age.
	Stale bool
}

// PhysicallyStandby reports that the peer provably neither accepts writes nor publishes.
// All three fields must be explicitly present: missing ≠ off (a bug the Perl loop paid for with
// `source_status_incomplete`).
func (p PeerState) PhysicallyStandby() bool {
	return p.Reachable &&
		p.ReadOnly != nil && *p.ReadOnly == 1 &&
		p.NotifierOn != nil && *p.NotifierOn == 0 &&
		p.RouteAnnounced != nil && *p.RouteAnnounced == 0
}

// ConfigState is the pair's effective configuration from local dns_ha.
type ConfigState struct {
	Loaded bool
	Error  string
	// NotSeeded: there are no revisions at all (store.ErrConfigNotSeeded). A separate fact because
	// Revision == nil looks the same for "no pair" and "revision unreadable", which are opposites.
	// See Observation.HANotConfigured.
	NotSeeded   bool
	Revision    *int64
	PayloadHash string
	SelfListen  string // host:port of our peer listener
	PeerNodeID  string
	PeerListen  string
	// PeerHost is the peer address without port. For STANDBY it is the expected replication source:
	// "IO=Yes, SQL=Yes" from a foreign host is not health. (The HA channel and replication share one address
	// for now; once ha_replication is populated, take the source from there.)
	PeerHost       string
	StoreReachable bool
	SchemaValid    bool
	StoreError     string
	// Payload is the canonical content of the effective revision (the only source of working values).
	Payload store.ConfigPayload
	// PreviousAnycastAddress is the previous revision's anycast address, for cleanup: anycast addresses stay
	// on loopback, so a new revision adds a second one. Empty if there is none or it is unchanged.
	PreviousAnycastAddress string
	// ProjectionDrift: normalized tables diverged from the revision content. Working values are unaffected
	// (the manager uses the content), but the panel and SQL show wrong data.
	ProjectionDrift string
}

// AgreesWithPeer reports that both sides' configs match (revision and hash). The role must not go to a
// node with an uncertain config (§7.3).
func (c ConfigState) AgreesWithPeer(p PeerState) bool {
	if !c.Loaded || c.Revision == nil || p.ConfigRevision == nil {
		return false
	}
	return *c.Revision == *p.ConfigRevision && c.PayloadHash != "" && c.PayloadHash == p.ConfigHash
}

// SafetyState holds proofs from the durable safety store.
type SafetyState struct {
	Present      bool
	Valid        bool
	Error        string
	MaxSeenEpoch *int64
	// FencedNode is the authoritative fence (§4.4.1: safety store, not the replicated DB).
	FencedNode string
	Authority  AuthorityView
}

// ExpectedReplicationSource is the MariaDB address this node must replicate from.
//
// The single answer for planner (is replication healthy), health (right source) and plan builder (rejoin
// target): different answers would mean "all fine" is judged about one source and the connection made to
// another. The source follows the role — the current ACTIVE, i.e. the peer. The address comes from the
// effective revision; legacy revisions without replication_host fall back to the peer's HA-channel address.
func (o Observation) ExpectedReplicationSource() (string, bool) {
	peerID := o.Config.PeerNodeID
	if peerID == "" {
		peerID = o.Peer.NodeID
	}
	if peerID != "" {
		if h, ok := o.Config.Payload.ReplicationSourceOf(peerID); ok {
			return h, true
		}
	}
	if o.Config.PeerHost != "" {
		return o.Config.PeerHost, true
	}
	return "", false
}

// PreflightView is what `dns-ha-agent preflight` said. A negative verdict ("ok=0, replica_error") and
// being unable to ask ("agent unavailable") differ and must not share one flag.
type PreflightView struct {
	Observed   bool
	OK         bool
	Code       string // refusal reason in the executor's words
	Message    string
	ReplicaIO  string
	ReplicaSQL string
	Error      string // could not ask (typed agent client reason)
}

// AuthorityView is the state of the right to be ACTIVE (STANDBY needs none: read-only is safe by itself).
// Absence is never permission (§3.2).
type AuthorityView struct {
	State string // valid_current | stale | absent | unknown | foreign_role
	Type  string // handoff | emergency | bootstrap
	Epoch *int64
	// Source is who issued the proof, to tell a repeat of the same certificate from a different decision
	// in the same epoch: the epoch alone is not enough.
	Source string
	Detail string
}

// ReplicationState is this node's actual replication (SHOW REPLICA STATUS).
type ReplicationState struct {
	// GTIDBinlogPos is what this node wrote itself: the position a switchover target must catch up to.
	//
	// GTIDBinlogPosKnown separates "read, empty" from "could not read". Empty means nothing to hand over (no
	// transactions in the binlog, as right after a reseed); unread means we don't know what we hand over,
	// so no switchover.
	GTIDBinlogPos      string
	GTIDBinlogPosKnown bool
	Observed           bool   // whether we could look at all
	Error              string // e.g. missing SLAVE MONITOR privilege
	Configured         bool   // a status row exists = CHANGE MASTER was run
	IORunning          string // Yes | No | Connecting
	SQLRunning         string
	MasterHost         string
	SecondsBehind      *int64
	LastIOError        string
	LastSQLError       string
	GtidIOPos          string
	GtidSlavePos       string
}

// Healthy reports that the replica is provably connected to the expected source.
// 'Connecting' is not success: the thread runs but is not connected (a real Perl-loop bug).
func (r ReplicationState) Healthy(expectedMaster string) bool {
	return r.Observed && r.Configured &&
		r.IORunning == "Yes" && r.SQLRunning == "Yes" &&
		expectedMaster != "" && r.MasterHost == expectedMaster
}
