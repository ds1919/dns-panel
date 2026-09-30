// dns-ha-manager is the HA pair manager daemon (DOCS/23-ha-manager.md).
//
// It observes the node (agent, MariaDB persisted config, local dns_ha, safety store), talks to the peer over the
// signed peer protocol, plans, and executes operations and convergence.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"dnspanel/dns-ha/internal/agent"
	"dnspanel/dns-ha/internal/config"
	"dnspanel/dns-ha/internal/configsync"
	"dnspanel/dns-ha/internal/dispatch"
	"dnspanel/dns-ha/internal/execute"
	"dnspanel/dns-ha/internal/health"
	"dnspanel/dns-ha/internal/observe"
	"dnspanel/dns-ha/internal/ops"
	"dnspanel/dns-ha/internal/pairing"
	"dnspanel/dns-ha/internal/peer"
	"dnspanel/dns-ha/internal/planner"
	"dnspanel/dns-ha/internal/probe"
	"dnspanel/dns-ha/internal/safety"
	"dnspanel/dns-ha/internal/sdnotify"
	"dnspanel/dns-ha/internal/shadow"
	"dnspanel/dns-ha/internal/statusapi"
	"dnspanel/dns-ha/internal/store"
)

// Set by the linker (see Makefile). No build time on purpose: it breaks reproducibility; revision provides
// identity.
var (
	version  = "dev"
	revision = "unknown"
)

// report is what is exposed: the state classification (health) plus the planner's DECISION.
type report struct {
	health.Verdict
	Decision planner.Decision `json:"decision"`
	// WouldExecute is the exact plan of primitive actions matching the decision. A visible plan is a way to
	// discuss behavior before it happens, not after.
	WouldExecute shadow.MutationPlan `json:"would_execute"`
	// Execution is the result of calling the executor; mutations_attempted counts the mutations it actually
	// attempted.
	Execution executionReport `json:"execution"`
	// Pair is the PAIR summary for the panel. A projection of the same observation: the UI needs a compact
	// answer to "what is going on with both nodes", not a list of checks to parse.
	Pair pairView `json:"pair"`
	// Probe is the readiness probe state (anycast only). Absent for other providers: there publication is the
	// address itself and there is no probe.
	Probe *probeReport `json:"probe,omitempty"`
}

type nodeView struct {
	// NodeID is the UUID the node is identified by wherever the role's fate is decided.
	NodeID string `json:"node_id"`
	// Name/Hostname/Location are human metadata from the pair config. The panel shows them instead of the
	// UUID; with no name set it falls back to hostname or the ID itself.
	Name     string `json:"name,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	// IPDevice/IPCIDR: where the node's own address is up. The panel shows it as `eth0: 192.0.2.11/24`;
	// a node observes this for itself and receives it from the peer.
	IPDevice string `json:"ip_device,omitempty"`
	IPCIDR   string `json:"ip_cidr,omitempty"`
	// ProbeOpenPort is the probe port ACTUALLY open on this node (0 = none). The panel compares it with the
	// configured port: until they match, "OPEN" would refer to a different port.
	ProbeOpenPort int    `json:"probe_open_port"`
	Location      string `json:"location,omitempty"`
	// Description says what the node is for. Pair config metadata: no effect on HA logic, but it is what the
	// human reads in the panel.
	Description    string `json:"description,omitempty"`
	Role           string `json:"role"`
	Epoch          *int64 `json:"epoch"`
	ServiceReady   bool   `json:"service_ready"`
	HAHealthy      bool   `json:"ha_healthy,omitempty"`
	ReadOnly       *int   `json:"read_only"`
	NotifierOn     *int   `json:"notifier_on"`
	RouteAnnounced *int   `json:"route_announced"`
	PDNSVersion    string `json:"pdns_version,omitempty"`
	Reachable      bool   `json:"reachable"`
	// Only the node ITSELF reports its publication address: the peer protocol does not carry it, and
	// presenting another node's address as observed would be untrue. The address is shared by the pair, so one suffices.
	PublicationAddress string `json:"publication_address,omitempty"`
	PublicationDevice  string `json:"publication_device,omitempty"`
	Stale              bool   `json:"stale,omitempty"`
	Error              string `json:"error,omitempty"`
}

type pairView struct {
	Self nodeView `json:"self"`
	Peer nodeView `json:"peer"`
	// Publication is HOW the service is published: the provider from the effective revision. Switchover
	// mechanics do not depend on it (role, epoch, drain, reseed are the same); only the publication primitive differs.
	Publication     string `json:"publication"`
	PublicationArgs string `json:"publication_params,omitempty"`
	ConfigRevision  *int64 `json:"config_revision"`
	// HAConfigured is TRI-STATE: whether HA is on for this node.
	//
	//	true   effective revision read: HA is on
	//	false  NO revisions at all (store.ErrConfigNotSeeded): HA is provably off
	//	null   could not determine: state unknown
	//
	// The third value is mandatory and is why this is a pointer. A two-state field folded "no HA" and "could not
	// read" into the same `false`, yet they are opposites: the former permits writes, the latter must forbid them.
	// The cost is concrete: a WORKING pair's `dns_ha` becomes unreadable for a minute, the manager says "HA off",
	// and the panel enables writes on a node that may be STANDBY at that moment. The stack below already tells
	// these apart (store.ErrConfigNotSeeded, observe.Observation.HANotConfigured); losing that at the outer
	// boundary would waste all of that work.
	//
	// The field does NOT answer "are the nodes paired": different facts, different owners. Trust is known to
	// `pair_status` (pairing.Service), its only source of truth. This field used to be `paired` and answered
	// both questions, which made the panel show the initial pairing screen to fully paired nodes after HA
	// dismantling.
	HAConfigured   *bool  `json:"ha_configured"`
	ConfigHash     string `json:"config_hash,omitempty"`
	FencedNode     string `json:"fenced_node,omitempty"`
	Authority      string `json:"authority,omitempty"`
	AuthorityState string `json:"authority_state,omitempty"`
	Replication    struct {
		Observed  bool   `json:"observed"`
		IO        string `json:"io,omitempty"`
		SQL       string `json:"sql,omitempty"`
		Source    string `json:"source,omitempty"`
		BehindSec *int64 `json:"behind_seconds,omitempty"`
		Error     string `json:"error,omitempty"`
	} `json:"replication"`
}

// pairOf builds the pair summary from one observation.
func pairOf(o observe.Observation, v health.Verdict) pairView {
	var p pairView
	p.Self = nodeView{NodeID: o.NodeID, Role: v.Role, Epoch: o.Safety.MaxSeenEpoch,
		ServiceReady: v.ServiceReady, HAHealthy: v.HAHealthy, ReadOnly: o.Local.ReadOnly,
		NotifierOn: o.Local.NotifierOn, RouteAnnounced: o.Local.RouteAnnounced, Reachable: true,
		PDNSVersion:        o.Local.PDNSVersion,
		PublicationAddress: o.Local.PublicationAddress, PublicationDevice: o.Local.PublicationDevice,
		IPDevice: o.Local.IPDevice, IPCIDR: o.Local.IPCIDR}
	p.Peer = nodeView{NodeID: o.Peer.NodeID, Role: o.Peer.Role, Epoch: o.Peer.MaxSeenEpoch,
		ServiceReady: o.Peer.ServiceReady, HAHealthy: o.Peer.HAHealthy, ReadOnly: o.Peer.ReadOnly,
		NotifierOn: o.Peer.NotifierOn, RouteAnnounced: o.Peer.RouteAnnounced,
		PDNSVersion: o.Peer.PDNSVersion,
		IPDevice:    o.Peer.IPDevice, IPCIDR: o.Peer.IPCIDR, ProbeOpenPort: o.Peer.ProbeOpenPort,
		Reachable: o.Peer.Reachable, Stale: o.Peer.Stale, Error: o.Peer.Error}
	if p.Peer.NodeID == "" {
		p.Peer.NodeID = o.Config.PeerNodeID
	}
	// Each node has its own publication interface, recorded in the pair config. Ours is already set above
	// from observation; the peer's comes from the revision, no need to ask over the network.
	for _, n := range o.Config.Payload.Nodes {
		if n.NodeID == p.Peer.NodeID && n.PublicationDevice != "" {
			p.Peer.PublicationDevice = n.PublicationDevice
		}
		if n.NodeID == p.Self.NodeID && p.Self.PublicationDevice == "" {
			p.Self.PublicationDevice = n.PublicationDevice
		}
	}
	// Metadata comes from the pair config: it is shared by both sides, no need to ask the peer.
	for _, n := range o.Config.Payload.Nodes {
		v := &p.Self
		if n.NodeID == p.Peer.NodeID {
			v = &p.Peer
		} else if n.NodeID != p.Self.NodeID {
			continue
		}
		v.Name, v.Hostname, v.Location, v.Description = n.Name, n.Hostname, n.Location, n.Description
	}
	// Our hostname is OBSERVED, not what was written into the config at pair creation. The OS name changes
	// independently of us, and showing a year-old snapshot as "Hostname" would confidently misname the node.
	// The peer's name arrives in its own status for the same reason.
	if h, err := os.Hostname(); err == nil && h != "" {
		p.Self.Hostname = h
	}
	if o.Peer.Hostname != "" {
		p.Peer.Hostname = o.Peer.Hostname
	}
	p.ConfigRevision, p.ConfigHash = o.Config.Revision, o.Config.PayloadHash
	// Three cases are distinguished EXPLICITLY, and "default" means unknown: unreadable database, corrupt
	// revision content, failed validation. None of them is "HA off".
	switch {
	case o.HANotConfigured():
		p.HAConfigured = boolPtr(false)
	case o.Config.Loaded && o.Config.Revision != nil:
		p.HAConfigured = boolPtr(true)
	default:
		p.HAConfigured = nil
	}
	p.FencedNode = o.Safety.FencedNode
	p.Authority, p.AuthorityState = o.Safety.Authority.Type, o.Safety.Authority.State
	if pub := o.Config.Payload.Publication; pub != nil {
		p.Publication, p.PublicationArgs = pub.Provider, pub.Params
	}
	p.Replication.Observed = o.Replication.Observed
	p.Replication.IO, p.Replication.SQL = o.Replication.IORunning, o.Replication.SQLRunning
	p.Replication.Source, p.Replication.Error = o.Replication.MasterHost, o.Replication.Error
	p.Replication.BehindSec = o.Replication.SecondsBehind
	return p
}

// boolPtr returns a pointer to v. Needed exactly where "no value" is itself an answer.
func boolPtr(v bool) *bool { return &v }

type executionReport struct {
	Attempted int64           `json:"mutations_attempted"`
	Outcome   execute.Outcome `json:"outcome"`
	Operation string          `json:"operation,omitempty"`
}

// snapshot is the latest report, served both on the local socket and to the peer over the peer protocol.
//
// It also holds the raw observation: the mutation gate must decide on THE SAME picture of the world as health
// and the planner. If it observed by itself, decisions would rest on two different snapshots.
type snapshot struct {
	mu  sync.RWMutex
	v   report
	st  peer.StatusPayload
	he  peer.HelloPayload
	obs observe.Observation
}

func (s *snapshot) set(v report, st peer.StatusPayload, he peer.HelloPayload, obs observe.Observation) {
	s.mu.Lock()
	s.v, s.st, s.he, s.obs = v, st, he, obs
	s.mu.Unlock()
}

func (s *snapshot) get() (report, peer.StatusPayload, peer.HelloPayload) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.v, s.st, s.he
}

// observation returns the cycle's latest observation. Peer command handlers take the world picture FROM HERE
// instead of collecting it anew: a fresh collection while handling the peer's request would mean a call back to
// the very peer waiting on us, and decisions must use the same picture health and the planner see.
// The context is unused: this is a READY observation from the last round, nothing goes outside. The parameter
// exists to fit the common state-wait signature (ops.Observe), and so nobody suspects one of the observers of
// quietly going to the network with no deadline.
func (s *snapshot) observation(context.Context) observe.Observation {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.obs
}

// gateInput derives mutation permissions from the latest observation.
func (s *snapshot) gateInput(selfNodeID string) configsync.GateInput {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return configsync.GateInput{
		SafetyValid:  s.obs.Safety.Valid,
		MaxSeenEpoch: s.obs.Safety.MaxSeenEpoch,
		FencedNode:   s.obs.Safety.FencedNode,
		SelfNodeID:   selfNodeID,
		IAmActive:    s.v.Role == "active",
	}
}

func main() {
	cfgPath := flag.String("config", "/opt/dns-panel/etc/ha.toml", "path to the bootstrap config")
	once := flag.Bool("once", false, "observe once, print JSON and exit")
	noSocket := flag.Bool("no-socket", false, "do not open the local status socket (for manual runs)")
	noPeer := flag.Bool("no-peer", false, "do not open the peer listener (for manual runs next to the service)")
	showVersion := flag.Bool("version", false, "version and revision")
	switchover := flag.Bool("switchover", false, "create a planned role switchover (on the node giving the role away)")
	to := flag.String("to", "", "whom to hand the role to (the other node by default)")
	emergency := flag.Bool("emergency", false, "emergency promotion: this node becomes ACTIVE (-ack and -operator are required)")
	ack := flag.String("ack", "", "operator acknowledgement: old_active_database_stopped | old_active_host_down | operator_isolated")
	operator := flag.String("operator", "", "who made the decision")
	acceptRelayLoss := flag.Bool("accept-relay-loss", false,
		"continue even if the relay log drain cannot be proven (DATA LOSS); with -resume it consents for an already created operation")
	reseed := flag.Bool("reseed", false, "reseed this node from the current ACTIVE")
	resume := flag.Bool("resume", false, "put an interrupted operation (-id) back to work")
	operation := flag.Bool("operation", false, "show the current (or -id) operation and its steps")
	opID := flag.String("id", "", "operation id for -operation")
	pair := flag.String("pair", "", "node pairing: status|create|join|approve|reject|reset")
	address := flag.String("address", "", "address: of the other node for -pair join (host[:port]), the service address for -pair build (CIDR)")
	force := flag.Bool("force", false, "with -pair reset: drop trust that is ALREADY established (breaking up the pair)")
	provider := flag.String("provider", "", "with -pair build: publication provider (floating_ip|anycast|marker)")
	probePort := flag.Int("probe-port", 0, "with -pair build -provider anycast: TCP readiness probe port")
	flag.Parse()

	if *showVersion {
		fmt.Printf("dns-ha-manager %s (revision %s, protocol v%d, read-only)\n", version, revision, peer.Version)
		return
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "dns-ha-manager:", err)
		os.Exit(2)
	}

	// Pairing sends commands to the RUNNING daemon: the attempt lives in its memory. Identity is not needed
	// here and deliberately not requested: a node whose database did not come up must at least say so clearly,
	// not crash before parsing the command.
	if *pair != "" {
		// `-pair build` creates the pair and runs on the DONOR: all destructive actions happen on the
		// receiver, but the one whose data survives decides. The service address comes from the same -address.
		os.Exit(pairCLI(*pair, *address, orEnv(*operator), *force,
			statusapi.Request{Provider: *provider, ProbePort: *probePort, ID: *opID}))
	}

	// Node identity comes from the LOCAL dns_ha and is created on first start. It is not in the config on purpose:
	// a one-letter TOML edit would make the node a stranger to its own pair. The database may not be up yet
	// (reboot, recovery); then the manager honestly waits for it rather than inventing an identity.
	nodeID, err := ensureIdentity(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "dns-ha-manager: node identity:", err)
		os.Exit(2)
	}
	cfg.Node = nodeID

	if *switchover {
		os.Exit(createSwitchover(cfg, *to, os.Getenv("SUDO_USER")))
	}
	if *emergency {
		os.Exit(createEmergency(cfg, *ack, orEnv(*operator), *acceptRelayLoss))
	}
	if *reseed {
		os.Exit(createReseed(cfg, orEnv(*operator)))
	}
	if *resume {
		os.Exit(resumeOperation(cfg, *opID, *acceptRelayLoss, orEnv(*operator)))
	}
	if *operation {
		os.Exit(showOperation(cfg, *opID))
	}

	snap := &snapshot{}
	if *once {
		// One-shot state dump: no deadline of its own; the observation sources bound it.
		v, _, _, _ := observeOnce(context.Background(), cfg, nil)
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(v)
		return
	}

	// Take the FIRST snapshot BEFORE opening the port. Otherwise the peer could get a correctly signed but empty
	// status (node_id="", role="", max_seen_epoch=null), and the decision layer would see a "valid" intermediate
	// state that never existed.
	{
		v0, st0, he0, obs0 := observeOnce(context.Background(), cfg, nil)
		snap.set(v0, st0, he0, obs0)
	}

	// The peer channel and operation journal come up AS SOON AS possible, not only at startup.
	//
	// The case this is for: the manager starts while local MariaDB is still down (node reboot, crash recovery). A
	// single attempt at startup would leave the node without a peer channel and journal forever, exactly when they
	// matter most.
	// Pairing and the port 7901 dispatcher ALWAYS come up, before everything else: a standalone node must be able
	// to join a pair, which means answering pairing commands with neither a revision nor a secret.
	pairSvc := newPairingService(cfg, cfg.Node)
	pairSvcRef = pairSvc
	peers := &peerRef{}
	var (
		srv       *peer.Server
		client    *peer.ClientConfig
		opsStore  *ops.Store
		lastPeerE string
		lastOpsE  string
		lastPairE string
		// peerFromTrust: the channel is up from the pairing record, not the pair config. Such a server can only
		// read (no registry, gate or executor), which is exactly what is needed between "we trust each other"
		// and "the pair exists": without it already paired nodes could not see each other at all.
		peerFromTrust bool
	)
	port := &dispatch.Dispatcher{
		Pairing: pairSvc,
		Peer: func() dispatch.PeerHandler {
			// Explicit nil, not srv: an interface holding a nil pointer is not nil, and the dispatcher would
			// hand the conversation to a nonexistent server.
			if srv == nil {
				return nil
			}
			return srv
		},
		Timeout:    config.PeerTimeout,
		MaxMessage: config.PeerMaxMessage,
	}
	if !*noPeer {
		// Before pair creation the node does not know its own address: it is in a revision that does not exist
		// yet. Listen on all interfaces and move to the specific address once the revision appears.
		if err := port.Bind(fmt.Sprintf(":%d", pairPort)); err != nil {
			fmt.Fprintln(os.Stderr, "dns-ha-manager: the pairing port is not open:", err)
			os.Exit(2)
		}
		defer port.Close()
	}
	recovered := false
	ensure := func() {
		// An interrupted config commit is completed BEFORE anything reads the effective revision, but only when
		// the database is available: with MariaDB down that is not an error, just "too early".
		if !recovered {
			if recoverConfigCommit(cfg) {
				recovered = true
			}
		}
		if (srv == nil || peerFromTrust) && !*noPeer {
			if s, c, addr, err := startPeer(cfg, snap); err != nil {
				// No pair config yet. If pairing is done, bring up a read-only channel from the trust record: the
				// peer address and shared secret are there, and nothing more is needed.
				if srv == nil {
					if s, c, e := startPeerFromTrust(cfg, snap); e == nil {
						srv, client, peerFromTrust, lastPeerE = s, c, true, ""
						peers.set(c)
						fmt.Fprintf(os.Stderr, "dns-ha-manager: trusted channel to %s (read-only)\n", c.PeerNodeID)
					}
				}
				if msg := err.Error(); msg != lastPeerE {
					lastPeerE = msg
					fmt.Fprintln(os.Stderr, "dns-ha-manager: the peer contour is not up:", msg)
				}
			} else if err := port.Bind(addr); err != nil {
				if msg := err.Error(); msg != lastPeerE {
					lastPeerE = msg
					fmt.Fprintln(os.Stderr, "dns-ha-manager: the address from the revision is not taken:", msg)
				}
			} else {
				srv, client, peerFromTrust, lastPeerE = s, c, false, ""
				peers.set(c)
				fmt.Fprintf(os.Stderr, "dns-ha-manager: peer listen %s, other node %s\n", port.Addr(), client.Address)
			}
		}
		// An unfinished pairing is completed here too: a lost reply must not leave the node in committing
		// forever, and a separate daemon for one retried message is not worth it.
		if err := pairSvc.Finish(context.Background()); err != nil {
			if msg := err.Error(); msg != lastPairE {
				lastPairE = msg
				fmt.Fprintln(os.Stderr, "dns-ha-manager: pairing did not finish:", msg)
			}
		} else {
			lastPairE = ""
		}
		if opsStore == nil {
			if st, err := openOps(cfg); err != nil {
				if msg := err.Error(); msg != lastOpsE {
					lastOpsE = msg
					fmt.Fprintln(os.Stderr, "dns-ha-manager: the operation journal is unavailable:", msg)
				}
			} else {
				opsStore, lastOpsE = st, ""
				fmt.Fprintln(os.Stderr, "dns-ha-manager: the operation journal is available")
			}
		}
	}
	ensure()
	defer func() {
		if srv != nil {
			srv.Close()
		}
	}()

	var api *statusapi.Server
	if !*noSocket {
		// Handlers create INTENTS with the same functions as the CLI: the panel and the operator share one
		// path, and there is no HA logic in the panel.
		api, err = statusapi.New(config.StatusSocket, statusapi.Handlers{
			Config: func() (any, error) { return getConfig(cfg, snap) },
			ConfigApply: func(r statusapi.Request) (any, error) {
				return applyConfig(cfg, snap, r.Payload, r.RequestedBy)
			},
			Operations: func(limit int) (any, error) { return listOperations(cfg, limit) },
			Operation:  func(id string) (any, error) { return getOperation(cfg, id, peers) },
			Switchover: func(r statusapi.Request) (any, error) {
				return intentSwitchover(cfg, r.Target, r.RequestedBy)
			},
			Emergency: func(r statusapi.Request) (any, error) {
				return intentEmergency(cfg, r.Ack, r.RequestedBy, r.AcceptRelayLoss)
			},
			Reseed:    func(r statusapi.Request) (any, error) { return intentReseed(cfg, r.RequestedBy) },
			Dismantle: func(r statusapi.Request) (any, error) { return intentDismantle(cfg, r.RequestedBy) },
			Resume: func(r statusapi.Request) (any, error) {
				return intentResume(cfg, r.ID, r.AcceptRelayLoss, r.RequestedBy)
			},
			Pair: func(r statusapi.Request) (any, error) { return handlePair(cfg, pairSvc, peers, r) },
			PublicationApply: func(r statusapi.Request) (any, error) {
				return applyPublication(cfg, snap, peers, r)
			},
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, "dns-ha-manager: status socket:", err)
			os.Exit(2)
		}
		// Publish the first snapshot BEFORE the socket starts answering. It has already been taken (see above),
		// and withholding it would answer the panel "state not taken" for one observation cycle although it was.
		// The panel would show "State unknown" for a perfectly healthy pair just because the manager had started.
		if v0, _, _ := snap.get(); v0.NodeID != "" {
			api.Publish(v0)
		}
		defer api.Close()
		go api.Serve()
	}
	// Ready: schema and identity are up and the status socket answers. systemd (Type=notify) learns it as an
	// event, not by timing: systemctl start/restart returns exactly then, and whoever waits for the manager
	// (installer, panel) need not guess.
	if err := sdnotify.Notify("READY=1"); err != nil {
		fmt.Fprintln(os.Stderr, "dns-ha-manager: sd_notify:", err)
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	// The executor. It has no separate off switch: the final program has no "can manage but deliberately never
	// does" mode; doing nothing means NOOP/HOLD, and the planner decides that.
	exec := &execute.Executor{Mutator: agent.Mutator{
		Client: agent.Client{Socket: config.AgentSocket, Timeout: config.AgentTimeout}}}

	// Readiness probe for the router (anycast). It lives in the manager process on purpose: if the manager
	// dies the socket closes with it and the route is withdrawn by itself, without the panel.
	readiness := probe.New()
	defer readiness.Close()

	ticker := time.NewTicker(config.ObserveInterval)
	defer ticker.Stop()

	writable := false
	for {
		ensure() // anything that did not come up earlier comes up here, without a daemon restart
		// Observation, plan and execution share one boundary with a peer-commanded dismantle (cycleMu).
		cycleMu.Lock()
		// Cycle order: first learn whether an operation is running, then decide readiness and the probe, then
		// execute THAT operation. Otherwise an operation created between observation and execution would start
		// with the probe still open: the router would consider the node ready while it is handing over the
		// role. An operation that appears later starts next cycle, which is enough.
		cur, curErr := currentOperation(context.Background(), opsStore)
		// An observation round is bounded by its interval: the next round must not wait on the previous one.
		obsCtx, obsCancel := context.WithTimeout(context.Background(), config.ObserveInterval)
		v, _, he, obs := observeOnce(obsCtx, cfg, client)
		obsCancel()
		if cur != nil {
			// A node mid-operation takes no traffic: the probe closes BEFORE its first step.
			v.ServiceReady = false
			v.Reason = "HA operation in progress: " + cur.ID
		} else if curErr != nil {
			// Could not tell whether an operation is running: assume it is. The opposite assumption would open
			// the probe blindly, and the router would send traffic to a node we know nothing about.
			v.ServiceReady = false
			v.Reason = "operation journal is unavailable: " + curErr.Error()
		}
		applyProbe(readiness, obs, &v)
		st := obs.ToPeerStatus(v.Role, v.ServiceReady, v.HAHealthy)
		// Observe the probe AFTER applyProbe: the peer gets the port actually open here, not the one in the
		// revision. Otherwise the peer would know about our card exactly what it already knows from the config,
		// i.e. nothing.
		if v.Probe != nil {
			st.ProbeOpenPort = v.Probe.OpenPort
		}
		// A running operation takes precedence over convergence: while the pair switches over, the intermediate
		// state is the operation's plan, not a divergence to "fix".
		v.Execution = executionReport{Attempted: exec.Attempted()}
		switch {
		case curErr != nil:
			v.Execution.Outcome = execute.Outcome{Status: execute.OutcomeBlocked, Reason: curErr.Error()}
		case opsStore != nil:
			v.Execution.Outcome = runOperationsAndConverge(context.Background(), cfg, opsStore, exec, snap, &v, obs, client, cur)
		}
		cycleMu.Unlock()
		snap.set(v, st, he, obs)
		if api != nil {
			api.Publish(v)
		} else {
			line, _ := json.Marshal(v)
			fmt.Println(string(line))
		}
		// The panel's write gate follows exactly this: ACTIVE with no operation running. The sync worker is told
		// of every change at once, after the status is published: on opening it catches up, on closing (a
		// switchover starts) it stops acting as ACTIVE.
		now := v.Role == "active" && cur == nil && curErr == nil
		if now != writable {
			wakeSyncWorker()
		}
		writable = now
		select {
		case <-stop:
			return
		case <-ticker.C:
		}
	}
}

// peerEndpoints returns our and the peer's addresses from the EFFECTIVE revision plus the shared secret. The
// only source of this data: no TOML, no hardcoding.
func peerEndpoints(cfg config.Config) (self, other store.NodeConfig, secret []byte, err error) {
	ec, err := store.LoadEffectiveConfig(context.Background(), cfg.Database.Socket, cfg.Database.Database, config.AgentTimeout)
	if err != nil {
		return self, other, nil, err
	}
	var ok bool
	if self, ok = ec.Self(cfg.Node); !ok {
		return self, other, nil, fmt.Errorf("revision %d has no row for node %q", ec.Revision, cfg.Node)
	}
	if other, ok = ec.Peer(cfg.Node); !ok {
		return self, other, nil, fmt.Errorf("revision %d has no row for the peer", ec.Revision)
	}
	secret, err = peer.LoadSecret(config.PeerKeyPath)
	return self, other, secret, err
}

// peerClientOnly returns a peer client without starting our own listener (for one-shot commands: the port is
// held by the running service and must not be taken from it).
func peerClientOnly(cfg config.Config) (*peer.ClientConfig, error) {
	_, other, secret, err := peerEndpoints(cfg)
	if err != nil {
		return nil, err
	}
	return newPeerClient(cfg, other, secret), nil
}

func newPeerClient(cfg config.Config, other store.NodeConfig, secret []byte) *peer.ClientConfig {
	return &peer.ClientConfig{
		NodeID: cfg.Node, PeerNodeID: other.NodeID,
		Address:    fmt.Sprintf("%s:%d", other.PeerListenHost, other.PeerListenPort),
		Secret:     secret,
		Window:     config.PeerWindow,
		Timeout:    config.PeerTimeout,
		MaxMessage: config.PeerMaxMessage,
	}
}

// orEnv returns the operator name: explicit beats implied, but the sudo user is better than a decision with
// no author.
func orEnv(v string) string {
	if v != "" {
		return v
	}
	return os.Getenv("SUDO_USER")
}

// startPeer builds the peer server for OUR address from the EFFECTIVE revision and prepares the peer client.
func startPeer(cfg config.Config, snap *snapshot) (*peer.Server, *peer.ClientConfig, string, error) {
	self, other, secret, err := peerEndpoints(cfg)
	if err != nil {
		return nil, nil, "", err
	}
	// Mutating commands are accepted ONLY with the full set: durable registry, gate and executor. Missing any
	// of them is a typed server-side refusal, not a silently skipped check. The registry deadline fits the
	// LONGEST mutating command: waiting for the target to apply a position takes up to a minute, and the
	// five-second observation deadline would cut it off mid-work.
	ledger, err := store.NewLedger(cfg.Database.Socket, cfg.Database.Database, 2*time.Minute)
	if err != nil {
		return nil, nil, "", fmt.Errorf("durable request ledger: %w", err)
	}
	sf := safety.NewStore(config.SafetyPath)
	cfgRecv := &configsync.Receiver{NodeID: cfg.Node, DBName: cfg.Database.Database, Safety: sf}
	opsRecv := &ops.Receiver{NodeID: cfg.Node, DBName: cfg.Database.Database, Safety: sf,
		Observe: snap.observation,
		// Dismantle on ACTIVE's command is one command: the node becomes standalone and removes its pair
		// records. It goes through the same mutation registry as a switchover, so a retry after a break does
		// not run it twice.
		Release: releasePairLocally(cfg)}
	// Server WITHOUT its own listener: the dispatcher holds the port, since pairing commands arrive on it too,
	// and two listeners cannot share one address.
	listenAddr := fmt.Sprintf("%s:%d", self.PeerListenHost, self.PeerListenPort)
	srv, err := peer.New(peer.ServerConfig{
		NodeID: cfg.Node, PeerNodeID: other.NodeID,
		Listen:      listenAddr,
		Secret:      secret,
		Window:      config.PeerWindow,
		ReadTimeout: config.PeerTimeout,
		MaxMessage:  config.PeerMaxMessage,
		StatusSource: func() (peer.StatusPayload, peer.HelloPayload) {
			_, st, he := snap.get()
			return st, he
		},
		InventorySource: localInventory,
		JournalSource:   localJournal(cfg),
		InitHandler:     initHandler(cfg),
		InitTimeout:     agent.ReseedTimeout + 2*time.Minute,
		Ledger:          ledger,
		Gate:            configsync.NewGate(func() configsync.GateInput { return snap.gateInput(cfg.Node) }),
		// One entry point, two areas: configuration and operations. Both go through the durable registry and
		// the gate, so "whom the command is for" is the only thing decided here.
		Executor: func(ctx context.Context, tx *sql.Tx, req *peer.Request) (peer.LedgerResult, error) {
			switch req.Cmd {
			case peer.CmdConfigStage, peer.CmdConfigCommit:
				return cfgRecv.Execute(ctx, tx, req)
			}
			return opsRecv.Execute(ctx, tx, req)
		},
	})
	if err != nil {
		return nil, nil, "", err
	}
	client, err := peerClientOnly(cfg)
	if err != nil {
		return nil, nil, "", err
	}
	return srv, client, listenAddr, nil
}

// replayOnlyLedger is the registry for the trust-only channel: it answers retries but never executes.
//
// Execute is unreachable here (this server has no executor), and it refuses explicitly just in case: a
// registry without an executor must not start a new mutation.
func replayOnlyLedger(cfg config.Config) peer.RequestLedger {
	l, err := store.NewLedger(cfg.Database.Socket, cfg.Database.Database, 10*time.Second)
	if err != nil {
		return nil
	}
	return replayLedger{l: l}
}

type replayLedger struct{ l *store.Ledger }

func (r replayLedger) Done(ctx context.Context, e peer.LedgerEntry) (peer.LedgerResult, bool, error) {
	return r.l.Done(ctx, e)
}
func (r replayLedger) Execute(context.Context, peer.LedgerEntry,
	func(context.Context, *sql.Tx) (peer.LedgerResult, error)) (peer.LedgerResult, bool, error) {
	return peer.LedgerResult{}, false, fmt.Errorf("this channel does not execute mutations")
}

// startPeerFromTrust brings up the channel between paired nodes BEFORE the pair is created.
//
// It differs from startPeer in exactly two ways: the peer address comes from the pairing record (there is no
// revision yet), and the server is built WITHOUT registry, gate and executor, so any mutating command gets a
// typed refusal. This is not a shortcut: at this stage there is no pair and nothing to change, and an "almost
// working" mutating path without an epoch check would be worse than none.
func startPeerFromTrust(cfg config.Config, snap *snapshot) (*peer.Server, *peer.ClientConfig, error) {
	ctx, cancel := context.WithTimeout(context.Background(), config.AgentTimeout)
	defer cancel()
	rec, err := dbTrust{cfg: cfg}.Load(ctx)
	if err != nil {
		return nil, nil, err
	}
	if rec == nil {
		return nil, nil, fmt.Errorf("this node is not paired with anyone")
	}
	if rec.State != pairing.StateTrusted {
		// An unfinished pairing is no reason to open the pair channel: the keys may not match, and an "almost
		// trusted" peer means nothing here. Completion runs on its own path (pairing.Finish).
		return nil, nil, fmt.Errorf("pairing is not finished: %s", rec.State)
	}
	secret, err := peer.LoadSecret(config.PeerKeyPath)
	if err != nil {
		return nil, nil, err
	}
	srv, err := peer.New(peer.ServerConfig{
		NodeID: cfg.Node, PeerNodeID: rec.PeerNodeID,
		Secret:      secret,
		Window:      config.PeerWindow,
		ReadTimeout: config.PeerTimeout,
		MaxMessage:  config.PeerMaxMessage,
		StatusSource: func() (peer.StatusPayload, peer.HelloPayload) {
			_, st, he := snap.get()
			return st, he
		},
		InventorySource: localInventory,
		JournalSource:   localJournal(cfg),
		InitHandler:     initHandler(cfg),
		InitTimeout:     agent.ReseedTimeout + 2*time.Minute,
		// The registry is here ONLY to answer retries of an already executed mutation. There is no gate or
		// executor and never will be: there is no pair, nothing to execute, and any new mutation must be refused.
		// But the stored result must be returned: a node that just dismantled its pair brings up exactly this
		// channel, and a retry of a command whose reply was lost before the daemon restart would otherwise get "no
		// registry" while a DONE record exists. That retry is why registry records survive dismantling.
		Ledger: replayOnlyLedger(cfg),
	})
	if err != nil {
		return nil, nil, err
	}
	other := store.NodeConfig{NodeID: rec.PeerNodeID}
	other.PeerListenHost, other.PeerListenPort, err = splitHostPort(rec.PeerEndpoint)
	if err != nil {
		return nil, nil, err
	}
	return srv, newPeerClient(cfg, other, secret), nil
}

func splitHostPort(addr string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, fmt.Errorf("peer address %q: %w", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, fmt.Errorf("peer address %q: %w", addr, err)
	}
	return host, port, nil
}

// localInventory returns THIS node's transferable database inventory. Asked from the agent: the manager has
// and must have no access to `pdns` and `dns_panel`.
func localInventory() (json.RawMessage, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return agent.Client{Socket: config.AgentSocket, Timeout: 30 * time.Second}.Inventory(ctx)
}

// applyProbe brings the readiness probe in line with the node's state.
//
// The port is open EXACTLY when the node is ready to serve traffic: not "it is ACTIVE" but the full set of
// proofs health computes (writable, PowerDNS primary, right to be active, no operation running). During a
// planned switchover this closes the probe before the role handoff, as soon as the node stops being ready.
func applyProbe(p *probe.Listener, obs observe.Observation, v *report) {
	provider := obs.Config.Payload.PublicationProvider()
	if provider != store.ProviderAnycast {
		p.Close()
		return
	}
	port := obs.Config.Payload.ProbePort()
	v.Probe = &probeReport{Port: port, Provider: provider}
	want := v.Verdict.ServiceReady
	if err := p.Set(want, port); err != nil {
		v.Probe.Error = err.Error()
	}
	v.Probe.Open = p.Open()
	v.Probe.OpenPort = p.Port()
	// The observed port also goes into OUR node's card: the panel compares it with the configured port and,
	// until they match, does not say "OPEN" for a port that is not open yet.
	v.Pair.Self.ProbeOpenPort = v.Probe.OpenPort

	// Readiness TOWARDS THE OUTSIDE is an open port, not our opinion of ourselves.
	//
	// The probe may fail to open (port taken by another process, permissions, anything). Internally the node is
	// fine: the database writes, PowerDNS is primary, the right is proven. But the router sees a closed port and
	// sends no traffic, so the node is NOT ready, and saying otherwise to the panel or the peer is wrong.
	// Otherwise a planned switchover to such a target would succeed while no route to the new ACTIVE appears.
	if want && !p.Open() {
		detail := v.Probe.Error
		if detail == "" {
			detail = fmt.Sprintf("TCP port %d is not open", port)
		}
		v.Verdict.ServiceReady = false
		v.Verdict.Service = append(v.Verdict.Service,
			health.Check{Name: "readiness_probe", State: health.Fail, Detail: detail})
		v.Verdict.Reason = "readiness probe is not open: " + detail
	}
}

// probeReport is the probe state for the panel. Deliberately NOT called "route announced": the panel does not
// know whether the router announced the route, and claiming so would present someone else's decision as ours.
type probeReport struct {
	Provider string `json:"provider"`
	// Port is the CONFIGURED port: which one should be open.
	Port int `json:"port"`
	// OpenPort is the port ACTUALLY open; zero means none.
	//
	// A separate field because the two diverge exactly when a human is looking: right after a port change
	// the revision already carries the new one while the old one is still listening. While the panel took
	// the port from config and "open" from observation, it showed "TCP 17901 · OPEN" with 17900 open.
	OpenPort int    `json:"open_port"`
	Open     bool   `json:"open"`
	Error    string `json:"error,omitempty"`
}

func observeOnce(ctx context.Context, cfg config.Config, client *peer.ClientConfig) (report, peer.StatusPayload, peer.HelloPayload, observe.Observation) {
	// ONE snapshot: health, planner and peer status are computed from the same raw evidence. The planner
	// works with the Observation directly, NOT with the health verdict: a coarse classification must not
	// drive role selection.
	obs := observe.Collect(ctx, cfg, client)
	v := health.Evaluate(obs)
	d := planner.Plan(obs)
	r := report{Verdict: v, Decision: d, WouldExecute: shadow.Build(d, obs), Pair: pairOf(obs, v)}
	return r, obs.ToPeerStatus(v.Role, v.ServiceReady, v.HAHealthy), obs.ToPeerHello(), obs
}

// syncWakeSocket is the panel's dns-sync-worker wake socket, the same on every install.
const syncWakeSocket = "/run/dns-panel/sync/wake.sock"

// wakeSyncWorker pokes the panel's sync worker: the write gate changed. Only a hint — without it the worker
// notices on its next schedule read — so a missing worker is not an error and nothing is retried.
func wakeSyncWorker() {
	c, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: syncWakeSocket, Net: "unixgram"})
	if err != nil {
		return
	}
	c.SetWriteDeadline(time.Now().Add(time.Second))
	c.Write([]byte("wake"))
	c.Close()
}
