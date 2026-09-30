package observe

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"time"

	"dnspanel/dns-ha/internal/agent"
	"dnspanel/dns-ha/internal/config"
	"dnspanel/dns-ha/internal/peer"
	"dnspanel/dns-ha/internal/safety"
	"dnspanel/dns-ha/internal/store"
)

// Collect takes a full read-only snapshot of the node and the pair.
//
// Always-available sources first (agent, local DB, safety store), then the peer. No source cancels the
// others: an unreachable peer does not stop self-observation, an unavailable DB does not stop reading
// the safety store. Deadline and cancellation come from the caller: observation serves a waiting operation,
// and a private Background would keep peer and DB calls running after the operation gave up.
func Collect(ctx context.Context, cfg config.Config, client *peer.ClientConfig) Observation {
	obs := Observation{NodeID: cfg.Node, At: time.Now()}

	// 1. Local HA DB: reachability, schema and effective pair config. Read before the agent because the
	// config holds the service address the agent is asked about; otherwise it would answer about the
	// address from the node's local file.
	ss := store.Observe(ctx, cfg.Database.Socket, cfg.Database.Database, config.AgentTimeout)
	obs.Config.StoreReachable, obs.Config.SchemaValid, obs.Config.StoreError = ss.Reachable, ss.SchemaValid, ss.Error
	if ec, err := store.LoadEffectiveConfig(ctx, cfg.Database.Socket, cfg.Database.Database, config.AgentTimeout); err != nil {
		obs.Config.Error = err.Error()
		obs.Config.NotSeeded = errors.Is(err, store.ErrConfigNotSeeded)
	} else {
		rev := ec.Revision
		obs.Config.Loaded, obs.Config.Revision, obs.Config.PayloadHash = true, &rev, ec.PayloadHash
		obs.Config.ProjectionDrift = ec.ProjectionDrift
		obs.Config.Payload = ec.Payload
		if self, ok := ec.Self(cfg.Node); ok {
			obs.Config.SelfListen = listenAddr(self)
		}
		if other, ok := ec.Peer(cfg.Node); ok {
			obs.Config.PeerNodeID, obs.Config.PeerListen = other.NodeID, listenAddr(other)
			obs.Config.PeerHost = other.PeerListenHost
		}
	}

	// 2. Node physical and control state, via the privileged agent.
	ag := agent.Client{Socket: config.AgentSocket, Timeout: config.AgentTimeout}
	pubAddr, pubDev, pubProvider := obs.Config.Payload.PublicationOf(obs.NodeID)
	if st, err := ag.Status(ctx, pubAddr, pubDev, pubProvider); err != nil {
		obs.Local.AgentError = err.Error()
	} else {
		obs.Local.AgentOK = st.OK
		obs.Local.AgentError = st.Error
		obs.Local.AgentMaxEpoch = st.MaxEpoch
		obs.Local.ReadOnly = intPtr(st.ReadOnly)
		obs.Local.NotifierOn = intPtr(st.NotifierOn)
		obs.Local.PDNSVersion = st.PDNSVersion
		obs.Local.SecondaryOn = intPtr(st.SecondaryOn)
		obs.Local.RouteAnnounced = intPtr(st.RouteAnnounced)
		obs.Local.PublicationAddress, obs.Local.PublicationDevice = st.PublicationAddress, st.PublicationDevice
		obs.Local.AnycastAddressUp = intPtr(st.AnycastAddressUp)
		// A successful status with an interface set proves the interface exists: on a missing device the
		// agent refuses rather than reporting "not published".
		obs.Local.PublicationDeviceOK = st.OK && pubDev != ""
	}

	// Does the published address accept connections? Anycast only: the address is always on loopback of
	// both nodes, so the local check applies everywhere. A floating_ip lives only on its current owner,
	// and the same check would call a healthy STANDBY broken.
	if pubAddr != "" && pubProvider == store.ProviderAnycast {
		obs.Local.ServiceAddressOK, obs.Local.ServiceAddressError = serviceAddressReachable(ctx, pubAddr)
	}

	// Previous anycast addresses still on loopback after a service address change. All former addresses
	// are checked, not just the last: one not cleaned up in time would drop out of view with the next
	// revision and stay forever. One per cycle — the step is idempotent.
	if obs.Config.Revision != nil {
		k := agent.PeerKeys{Client: agent.Client{Socket: config.AgentSocket, Timeout: config.AgentTimeout}}
		for _, prev := range store.FormerAnycastAddresses(ctx, cfg.Database.Socket, cfg.Database.Database,
			*obs.Config.Revision, config.AgentTimeout) {
			if k.AddressPresent(ctx, prev, store.AnycastDevice) {
				obs.Config.PreviousAnycastAddress, obs.Local.StaleAnycastUp = prev, true
				break
			}
		}
	}

	// Our own address: which interface and mask. The agent knows interfaces. Optional: with no pair yet
	// there is no channel address.
	if h := hostOnly(obs.Config.SelfListen); h != "" {
		keys := agent.PeerKeys{Client: agent.Client{Socket: config.AgentSocket, Timeout: config.AgentTimeout}}
		if dev, cidr, err := keys.ResolveInterface(ctx, h); err == nil {
			obs.Local.IPDevice, obs.Local.IPCIDR = dev, cidr
		}
	}

	// Preflight confirms the root execution path works (MariaDB reachable, read_only readable, replication
	// thread not in an explicit error). Not a source of truth — the manager observes topology, epoch, grants
	// and fencing itself in more detail. The planner does not read preflight.
	if pf, err := ag.Preflight(ctx); err != nil {
		obs.Local.Preflight.Error = err.Error()
	} else {
		obs.Local.Preflight = PreflightView{Observed: true, OK: pf.OK, Code: pf.Code, Message: pf.Message,
			ReplicaIO: pf.ReplicaIO, ReplicaSQL: pf.ReplicaSQL}
	}

	// This node's running operation, from its own journal.
	obs.Local.CurrentOperationID = store.CurrentOperationID(ctx, cfg.Database.Socket, cfg.Database.Database, config.AgentTimeout)

	// 3. Safety store: the proofs that grant a role.
	sf := safety.Read(config.SafetyPath)
	// Another node's store proves nothing here: it is invalidated on sf itself, so the authority below
	// (derived from sf) cannot come out valid from a foreign proof.
	if sf.Valid && !sf.BelongsTo(cfg.Node) {
		sf.Valid, sf.Error = false, "safety_foreign: the store belongs to another node"
	}
	obs.Safety.Present, obs.Safety.Valid, obs.Safety.Error = sf.Present, sf.Valid, sf.Error
	if obs.Safety.Valid && sf.State != nil {
		obs.Safety.MaxSeenEpoch = sf.State.MaxSeenEpoch
		obs.Safety.FencedNode = sf.State.Fenced
	}
	// The right to be ACTIVE does not depend on actual service state: a legitimate ACTIVE may briefly lose
	// PowerDNS, and the proof must stay valid so it restores the publication instead of demoting itself.
	state, typ, detail, source, epoch := sf.ActiveAuthority()
	obs.Safety.Authority = AuthorityView{State: state, Type: typ, Epoch: epoch, Source: source, Detail: detail}

	// 4. This node's actual replication.
	obs.Replication = ObserveReplication(ctx, cfg.Database.Socket, config.AgentTimeout)

	// 5. Persisted MariaDB configuration (prerequisites).
	if opts, err := MyPrintDefaults(ctx, config.MyPrintDefaults, config.AgentTimeout); err != nil {
		obs.PrereqError = err.Error()
	} else {
		obs.Prereqs = CheckPrerequisites(opts, ss.SchemaPresent)
	}

	// 6. The peer, last: its answer cancels nothing, it completes the pair picture.
	if client != nil {
		c := *client
		if obs.Safety.MaxSeenEpoch != nil {
			c.Epoch = *obs.Safety.MaxSeenEpoch
		}
		r, _ := peer.Call(ctx, c, peer.CmdStatus, nil)
		obs.Peer.Reachable = r.OK
		if !r.OK {
			obs.Peer.Error = r.Code
		} else if r.Response != nil {
			var ps peer.StatusPayload
			if err := peer.DecodeResponsePayload(r.Response, &ps); err != nil {
				obs.Peer.Reachable, obs.Peer.Error = false, "peer_bad_payload"
			} else {
				obs.Peer = PeerState{
					Reachable: true, NodeID: ps.NodeID, Hostname: ps.Hostname, Role: ps.Role,
					IPDevice: ps.IPDevice, IPCIDR: ps.IPCIDR, ProbeOpenPort: ps.ProbeOpenPort,
					ServiceReady: ps.ServiceReady, HAHealthy: ps.HAHealthy,
					ReadOnly: ps.ReadOnly, NotifierOn: ps.NotifierOn, RouteAnnounced: ps.RouteAnnounced,
					PDNSVersion:        ps.PDNSVersion,
					CurrentOperationID: ps.CurrentOperationID,
					FencedNode:         ps.FencedNode, MaxSeenEpoch: ps.MaxSeenEpoch,
					ConfigRevision: ps.ConfigRevision, ConfigHash: ps.ConfigHash, ObservedAt: ps.ObservedAt,
				}
				// The peer must be the node recorded in the pair config: the signature proves key ownership,
				// not that we are talking to the expected node.
				if obs.Config.PeerNodeID != "" && ps.NodeID != obs.Config.PeerNodeID {
					obs.Peer.Reachable = false
					obs.Peer.Error = "peer_unexpected_node_id"
				}
			}
		}
	}
	return obs
}

// ToPeerStatus builds what we send the peer, from the same snapshot: the peer sees exactly what we see.
func (o Observation) ToPeerStatus(role string, serviceReady, haHealthy bool) peer.StatusPayload {
	host, _ := os.Hostname()
	return peer.StatusPayload{
		NodeID: o.NodeID, Hostname: host, Role: role, ServiceReady: serviceReady, HAHealthy: haHealthy,
		IPDevice: o.Local.IPDevice, IPCIDR: o.Local.IPCIDR,
		MaxSeenEpoch:   o.Safety.MaxSeenEpoch,
		ConfigRevision: o.Config.Revision, ConfigHash: o.Config.PayloadHash,
		ObservedAt: o.At.Unix(),
		ReadOnly:   o.Local.ReadOnly, NotifierOn: o.Local.NotifierOn, RouteAnnounced: o.Local.RouteAnnounced,
		PDNSVersion:        o.Local.PDNSVersion,
		CurrentOperationID: o.Local.CurrentOperationID,
		// Authoritative fencing from the safety store, not the old replicated control plane.
		FencedNode: o.Safety.FencedNode,
	}
}

// ToPeerHello is the hello response.
func (o Observation) ToPeerHello() peer.HelloPayload {
	return peer.HelloPayload{
		NodeID: o.NodeID, ProtocolVersion: peer.Version,
		Capabilities: []string{peer.CmdHello, peer.CmdStatus},
		MaxSeenEpoch: o.Safety.MaxSeenEpoch,
	}
}

func listenAddr(n store.NodeConfig) string {
	if n.PeerListenHost == "" || n.PeerListenPort == 0 {
		return ""
	}
	return n.PeerListenHost + ":" + itoa(n.PeerListenPort)
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}

// intPtr narrows the agent's int64 to the int used for 0/1 flags. nil stays nil: unobserved must not become 0.
func intPtr(v *int64) *int {
	if v == nil {
		return nil
	}
	i := int(*v)
	return &i
}

// hostOnly strips the port: config stores the peer listener as host:port, interfaces are looked up by address.
func hostOnly(hostPort string) string {
	if hostPort == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(hostPort); err == nil {
		return h
	}
	return hostPort
}

// serviceAddressReachable reports whether DNS accepts a TCP connection on the published address.
//
// A plain local TCP connect to 53: no privileges, stays on the node, instant. It checks exactly what once
// broke: the /32 on loopback, role ACTIVE, probe open, yet `dig` got connection refused because PowerDNS
// listened only on its local-address list.
//
// No DNS query on purpose. PowerDNS opens the socket at startup; the DB may have zero zones and the node
// may still take traffic. The probe answers "which node serves the service address", not "is the data
// healthy" — readiness tied to user zones would take down a perfectly healthy node.
func serviceAddressReachable(ctx context.Context, addr string) (bool, string) {
	host := addr
	if i := strings.IndexByte(host, '/'); i >= 0 {
		host = host[:i]
	}
	if host == "" {
		return false, ""
	}
	// The probe keeps its own limit (it runs in the observation loop), but operation cancellation also stops it.
	pctx, cancel := context.WithTimeout(ctx, serviceProbeTimeout)
	defer cancel()
	var d net.Dialer
	c, err := d.DialContext(pctx, "tcp", net.JoinHostPort(host, "53"))
	if err != nil {
		return false, err.Error()
	}
	_ = c.Close()
	return true, ""
}

// serviceProbeTimeout: the connection goes to our own address, so it answers instantly or not at all.
// A second is enough, and more is risky inside the observation loop.
const serviceProbeTimeout = time.Second
