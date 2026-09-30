package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"dnspanel/dns-ha/internal/agent"
	"dnspanel/dns-ha/internal/config"
	"dnspanel/dns-ha/internal/identity"
	"dnspanel/dns-ha/internal/pairing"
	"dnspanel/dns-ha/internal/pairsetup"
	"dnspanel/dns-ha/internal/peer"
	"dnspanel/dns-ha/internal/safety"
	"dnspanel/dns-ha/internal/statusapi"
	"dnspanel/dns-ha/internal/store"
)

// Manager side of pair creation: wiring the internal/pairsetup sequence to the real node.
//
// The sequence and its order live there and are tested without the world. Here are only the connections: node
// actions go through the privileged agent, revision and epoch are written to the local dns_ha and the safety
// file, and the peer is called over the pair channel.

// pairNode is the local node for pairsetup.
type pairNode struct {
	cfg    config.Config
	nodeID string
	host   string
}

func newPairNode(cfg config.Config) pairNode {
	host, _ := os.Hostname()
	return pairNode{cfg: cfg, nodeID: cfg.Node, host: host}
}

func (n pairNode) NodeID() string   { return n.nodeID }
func (n pairNode) Hostname() string { return n.host }

func (n pairNode) keys() agent.PeerKeys {
	// Deadline sized for the longest of these commands: a reseed takes up to ten minutes, and cutting it off
	// mid-work would produce an unknown state where it is actually well defined.
	return agent.PeerKeys{Client: agent.Client{Socket: config.AgentSocket, Timeout: config.AgentTimeout}}
}

// Trust returns whom we are paired with. The peer address is reduced to host WITHOUT port: in GRANT and CHANGE
// MASTER a port means something different than in a connection address.
func (n pairNode) Trust(ctx context.Context) (pairsetup.Trust, error) {
	rec, err := dbTrust{cfg: n.cfg}.Load(ctx)
	if err != nil || rec == nil {
		return pairsetup.Trust{}, err
	}
	if rec.State != pairing.StateTrusted {
		// Pairing is not finished: the sides may not yet hold the same key, and the peer may not know we trust
		// it. A pair built on that is built on a non-agreement; finish pairing first (it retries by itself) or
		// reset.
		return pairsetup.Trust{}, fmt.Errorf("pairing is not finished (%s): it is too early to create the pair", rec.State)
	}
	host, err := pairsetup.HostOf(rec.PeerEndpoint)
	if err != nil {
		return pairsetup.Trust{}, err
	}
	key, err := peer.LoadSecret(config.PeerKeyPath)
	if err != nil {
		return pairsetup.Trust{}, err
	}
	return pairsetup.Trust{PeerNodeID: rec.PeerNodeID, PeerHost: host, PeerKey: key}, nil
}

// HasHAConfig reports whether there is an effective revision, i.e. whether HA is on. It is what separates "being assembled" from "operating".
func (n pairNode) HasHAConfig(ctx context.Context) (bool, error) {
	_, err := store.LoadEffectiveConfig(ctx, n.cfg.Database.Socket, n.cfg.Database.Database, config.AgentTimeout)
	if err == nil {
		return true, nil
	}
	// No revision is the normal state of a standalone node, not a failure. Anything else (database down,
	// corrupt content) must be an error: such a node must not be considered free.
	if isNotSeeded(err) {
		return false, nil
	}
	return false, err
}

// Revision returns the node's full effective revision: number, fingerprint and canonical bytes. A pair
// creation retry needs it to complete the second half with THE SAME content.
func (n pairNode) Revision(ctx context.Context) (int64, string, []byte, error) {
	ec, err := store.LoadEffectiveConfig(ctx, n.cfg.Database.Socket, n.cfg.Database.Database, config.AgentTimeout)
	if err != nil {
		if isNotSeeded(err) {
			return 0, "", nil, nil
		}
		return 0, "", nil, err
	}
	blob, err := ec.Payload.Canonical()
	if err != nil {
		return 0, "", nil, err
	}
	return ec.Revision, ec.PayloadHash, blob, nil
}

// isNotSeeded distinguishes "no revisions AT ALL" from "could not read".
//
// The comparison is TYPED, not by message substring: store.ErrConfigNotSeeded exists precisely to avoid that.
// The cost of a mistake is concrete here: this answer decides whether the node is free for HA setup, and
// treating a node whose config merely could not be read as free would allow Configure HA over an existing pair.
//
// `store_schema_absent` used to be equated with it too, declaring a missing database "HA not configured". That
// code comes from store.Observe and never from LoadEffectiveConfig, so the branch was dead, but a single
// accidental wording in someone else's error text would have brought it to life.
func isNotSeeded(err error) bool {
	return errors.Is(err, store.ErrConfigNotSeeded)
}

// Secret returns our own secret's value. The AGENT reads it: the files are root:root and out of the manager's
// reach by design. The manager needs the value because it is the one talking to the peer.
func (n pairNode) Secret(ctx context.Context, name string) (string, error) {
	return n.keys().ReadSecret(ctx, name)
}

func (n pairNode) InstallSecret(ctx context.Context, name, value string) error {
	_, err := n.keys().InstallSecret(ctx, name, value)
	return err
}

// CheckPublication reports whether the probe port and service address are free on this node. The privileged
// agent checks: interfaces and trying to open a port are its business, not ours.
func (n pairNode) CheckPublication(ctx context.Context, provider, address string, probePort int) (pairsetup.Conflicts, error) {
	// Only THIS node's effective revision knows "which address here is ours"; the agent does not read config.
	// Empty (no revision yet) means we own no address, and any host prefix on loopback is foreign.
	own := ""
	if ec, err := store.LoadEffectiveConfig(ctx, n.cfg.Database.Socket, n.cfg.Database.Database,
		config.AgentTimeout); err == nil {
		own, _ = ec.Payload.PublicationTarget()
	}
	c, err := n.keys().CheckPublication(ctx, provider, address, probePort, own)
	if err != nil {
		return pairsetup.Conflicts{}, err
	}
	return pairsetup.Conflicts{ProbePort: c.ProbePort, Address: c.Address}, nil
}

// DeviceFor returns the interface through which THIS node reaches the service address. The agent is asked:
// the node knows its routes, not the human or the panel.
func (n pairNode) DeviceFor(ctx context.Context, address string) (string, error) {
	return n.keys().ResolveDevice(ctx, address)
}

func (n pairNode) EnsureGrants(ctx context.Context, host string) error {
	_, err := n.keys().EnsurePairGrants(ctx, host)
	return err
}

func (n pairNode) EnableFailsafe(ctx context.Context) error {
	_, err := n.keys().EnableFailsafe(ctx)
	return err
}

// Reseed uses the existing agent primitive. No separate "data copy" is written for pair creation:
// ReseedReplica does exactly that and ends with proof that replication works.
func (n pairNode) Reseed(ctx context.Context, primary, operationID string, epoch int64) error {
	m := agent.Mutator{Client: agent.Client{Socket: config.AgentSocket, Timeout: agent.ReseedTimeout}}
	res, err := m.ReseedReplica(ctx, agent.Op{OperationID: operationID, ClusterEpoch: epoch}, primary)
	if err != nil {
		return err
	}
	if !res.OK {
		return fmt.Errorf("%s: %s", res.Error, res.Message)
	}
	return nil
}

// SeedRevision writes revision 1, the epoch and the right to be ACTIVE. Pair creation from the panel and from the
// terminal must bring the node to exactly the same state.
func (n pairNode) SeedRevision(ctx context.Context, p store.ConfigPayload, epoch int64, active string) error {
	dsn, err := store.WriteDSN(n.cfg.Database.Socket)
	if err != nil {
		return err
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return fmt.Errorf("store_open: %w", err)
	}
	defer db.Close()
	if err := store.ApplySchema(ctx, db, n.cfg.Database.Database); err != nil {
		return err
	}
	// The previous pair's peer-request registry is cleared HERE, at a safe point: there is no pair yet and no
	// peer mutation is running. It must not be touched during dismantling (peer commands run inside a
	// transaction on this very table), hence the cleanup moved here.
	if err := store.ClearPeerLedger(ctx, dsn, n.cfg.Database.Database, 15*time.Second); err != nil {
		return fmt.Errorf("peer request ledger: %w", err)
	}
	if err := store.SeedRevision(ctx, db, n.cfg.Database.Database, 1, p, n.nodeID); err != nil {
		return err
	}
	hash, err := p.Hash()
	if err != nil {
		return err
	}
	return seedSafety(n.nodeID, epoch, hash, active == n.nodeID)
}

// seedSafety writes the epoch and the right to be ACTIVE into the durable safety store.
func seedSafety(nodeID string, epoch int64, hash string, iAmActive bool) error {
	sf := safety.NewStore(config.SafetyPath)
	cur := sf.Read()
	if cur.Present && cur.Valid && cur.State.MaxSeenEpoch != nil && *cur.State.MaxSeenEpoch > epoch {
		// Never lower the epoch: the node would agree to execute a command from the past.
		return fmt.Errorf("this node has already seen epoch %d; the pair starts at %d", *cur.State.MaxSeenEpoch, epoch)
	}
	if cur.Present && !cur.Valid {
		return fmt.Errorf("safety file is unusable (%s): pair creation refused", cur.Error)
	}
	_, err := sf.Update(func(s *safety.State) error {
		s.NodeID = nodeID
		if s.MaxSeenEpoch == nil || *s.MaxSeenEpoch < epoch {
			e := epoch
			s.MaxSeenEpoch = &e
		}
		s.Fenced = ""
		if iAmActive {
			e := epoch
			s.Authority = &safety.Authority{Type: safety.AuthorityBootstrap, Epoch: &e, Role: "active",
				IssuedAt: time.Now().UTC().Format(time.RFC3339), Source: "pair_create"}
		} else {
			// STANDBY has NO right to be active and must not: read-only is safe by itself, and a "proof of
			// being STANDBY" could one day permit a promote.
			s.Authority = nil
		}
		s.CommittedConfig = &safety.CommittedConfig{Revision: 1, PayloadHash: hash, Epoch: epoch,
			CommittedBy: nodeID, CommittedAt: time.Now().UTC().Format(time.RFC3339)}
		return nil
	})
	return err
}

// pairPeer is the peer over the pair channel. The deadline is per command: a reseed takes minutes, and the
// five-second observation deadline would cut it off mid-work.
type pairPeer struct{ client *peer.ClientConfig }

func (p pairPeer) Call(ctx context.Context, cmd string, payload any, out any) error {
	if p.client == nil {
		return fmt.Errorf("the channel to the peer is not up")
	}
	cfg := *p.client
	// The five-second observation deadline does not suit pair creation steps. On init_seed the receiver
	// deploys the schema, writes the revision and the safety file, which takes LONGER than five seconds on a
	// fresh database, and the donor declared failure exactly when the receiver was succeeding: the pair was
	// half-built while the human saw "failed". Found in live build logs: the receiver's revision and the
	// donor's failure were exactly one timeout apart.
	switch cmd {
	case pairsetup.CmdReseed:
		cfg.Timeout = agent.ReseedTimeout + time.Minute
	case pairsetup.CmdPrepare, pairsetup.CmdFinish, pairsetup.CmdSeed, pairsetup.CmdRecap, pairsetup.CmdDevice,
		pairsetup.CmdCheck:
		cfg.Timeout = 2 * time.Minute
	}
	res, err := peer.Call(ctx, cfg, cmd, payload)
	if err != nil {
		return err
	}
	if !res.OK {
		return fmt.Errorf("%s", res.Code)
	}
	if out == nil || res.Response == nil || len(res.Response.Payload) == 0 {
		return nil
	}
	return json.Unmarshal(res.Response.Payload, out)
}

// initHandler is the receiver side: pair creation steps arriving from the donor.
func initHandler(cfg config.Config) func(cmd string, payload []byte) (any, error) {
	h := &pairsetup.Handler{Node: newPairNode(cfg)}
	return func(cmd string, payload []byte) (any, error) {
		ctx, cancel := context.WithTimeout(context.Background(), agent.ReseedTimeout+time.Minute)
		defer cancel()
		return h.Handle(ctx, cmd, payload)
	}
}

// pairDevices reports where each node will bring up the service address. Read-only: shown to the human before
// pair creation so that "interface" stops being a question for them.
func pairDevices(cfg config.Config, peers *peerRef, address, provider string) (any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s := &pairsetup.Setup{Node: newPairNode(cfg), Peer: pairPeer{client: peers.get()},
		Progress: func(n int, label string) {
			buildProgress.Store(&buildStep{Step: n, Total: pairsetup.StepCount, Label: label})
		}}
	defer buildProgress.Store(nil)
	return s.ResolveDevices(ctx, address, provider), nil
}

// createPair is the "create pair" command from the panel or terminal. It runs on the DONOR: all destructive
// actions happen on the receiver, but the one whose data survives decides.
// buildProgress is the step a running pair creation is on, shown by pair_status so the panel can say what
// the minutes are spent on. Nil while nothing is being built.
var buildProgress atomic.Pointer[buildStep]

type buildStep struct {
	Step  int    `json:"step"`
	Total int    `json:"total"`
	Label string `json:"label"`
}

func createPair(cfg config.Config, peers *peerRef, r statusapi.Request) (any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), statusapi.DeadlineFor("pair_build")-time.Minute)
	defer cancel()

	opID, err := identity.NewUUID()
	if err != nil {
		return nil, err
	}
	if r.ID != "" {
		// Retry of an interrupted attempt: same ID, same reseed, not a second one.
		opID = r.ID
	}
	s := &pairsetup.Setup{Node: newPairNode(cfg), Peer: pairPeer{client: peers.get()}}
	rep, err := s.Create(ctx, pairsetup.Plan{
		Provider: r.Provider, Address: r.Address, ProbePort: r.ProbePort,
		PeerListenPort: pairPort, RequestedBy: r.RequestedBy, OperationID: opID,
	})
	if err != nil {
		return nil, err
	}
	return rep, nil
}
