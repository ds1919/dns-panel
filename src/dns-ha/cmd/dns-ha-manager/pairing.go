package main

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"dnspanel/dns-ha/internal/agent"
	"dnspanel/dns-ha/internal/config"
	"dnspanel/dns-ha/internal/pairing"
	"dnspanel/dns-ha/internal/peer"
	"dnspanel/dns-ha/internal/statusapi"
	"dnspanel/dns-ha/internal/store"
)

// Manager side of pairing: wiring the service ports to the real world.
//
// The order of actions lives in internal/pairing and is tested without any world. Here are just three
// connections: durable trust record -> local dns_ha, key file -> privileged agent, network -> TCP.

// newPairingService builds the pairing service. It ALWAYS exists, even on a standalone node without a
// database: the window is closed and every command gets a typed refusal, but the node must answer, not stay silent.
func newPairingService(cfg config.Config, nodeID string) *pairing.Service {
	host, _ := os.Hostname()
	return &pairing.Service{
		Local:     pairing.Local{NodeID: nodeID, Hostname: host, Port: pairPort},
		Trust:     dbTrust{cfg: cfg},
		Keys:      agentKeys{},
		Transport: pairing.TCP{Timeout: config.PeerTimeout, MaxMessage: config.PeerMaxMessage},
		Window:    pairing.NewWindow(),
	}
}

// pairPort is the peer-channel port before a pair configuration exists. The node does not know its own
// address yet (addresses live in the revision, and there is none), so it listens on all interfaces; once the
// pair is created the dispatcher moves to the specific address from the revision.
const pairPort = 7901

type dbTrust struct{ cfg config.Config }

func (t dbTrust) open() (*sql.DB, error) {
	dsn, err := store.WriteDSN(t.cfg.Database.Socket)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	return db, nil
}

func (t dbTrust) Load(ctx context.Context) (*pairing.TrustRecord, error) {
	db, err := t.open()
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rec, err := store.LoadTrustedPeer(ctx, db, t.cfg.Database.Database)
	if err != nil || rec == nil {
		return nil, err
	}
	return &pairing.TrustRecord{State: rec.State, PairingID: rec.PairingID, PeerNodeID: rec.PeerNodeID,
		PeerEndpoint: rec.PeerEndpoint, KeyFP: rec.KeyFP, TranscriptFP: rec.TranscriptFP,
		ApprovedBy: rec.ApprovedBy}, nil
}

func (t dbTrust) Save(ctx context.Context, r pairing.TrustRecord) error {
	db, err := t.open()
	if err != nil {
		return err
	}
	defer db.Close()
	return store.SaveTrustedPeer(ctx, db, t.cfg.Database.Database, store.TrustedPeer{
		State: r.State, PairingID: r.PairingID, PeerNodeID: r.PeerNodeID, PeerEndpoint: r.PeerEndpoint,
		KeyFP: r.KeyFP, TranscriptFP: r.TranscriptFP, ApprovedBy: r.ApprovedBy})
}

func (t dbTrust) Promote(ctx context.Context, pairingID string) error {
	db, err := t.open()
	if err != nil {
		return err
	}
	defer db.Close()
	return store.PromoteTrustedPeer(ctx, db, t.cfg.Database.Database, pairingID)
}

func (t dbTrust) Delete(ctx context.Context) error {
	db, err := t.open()
	if err != nil {
		return err
	}
	defer db.Close()
	return store.DeleteTrustedPeer(ctx, db, t.cfg.Database.Database)
}

// agentKeys: the root agent installs and removes the pair secret, while the manager reads it itself: it may
// not write to etc/secrets, but must read it to sign both the peer channel and pairing completion.
type agentKeys struct{}

func (agentKeys) client() agent.PeerKeys {
	return agent.PeerKeys{Client: agent.Client{Socket: config.AgentSocket, Timeout: config.AgentTimeout}}
}

func (k agentKeys) Install(ctx context.Context, keyHex, fp string) error {
	_, err := k.client().Install(ctx, keyHex, fp)
	return err
}

func (k agentKeys) Remove(ctx context.Context, fp string) error {
	_, err := k.client().Remove(ctx, fp)
	return err
}

// Read returns an EMPTY string with no error when the key is missing: a standalone node without a pair
// secret is normal, not a failure. Anything else (no permission, garbage inside) must be an error: such a node
// must not be silently treated as free to pair.
func (agentKeys) Read(ctx context.Context) (string, error) {
	if _, err := os.Stat(config.PeerKeyPath); os.IsNotExist(err) {
		return "", nil
	}
	secret, err := peer.LoadSecret(config.PeerKeyPath)
	if err != nil {
		return "", err
	}
	return string(secret), nil
}

// peerRef holds the current peer client. It is set and replaced in the watch loop and read by control-socket
// handlers from another goroutine: a bare field would be a race that shows up once a month.
type peerRef struct {
	mu sync.RWMutex
	c  *peer.ClientConfig
}

func (r *peerRef) set(c *peer.ClientConfig) { r.mu.Lock(); r.c = c; r.mu.Unlock() }
func (r *peerRef) get() *peer.ClientConfig  { r.mu.RLock(); defer r.mu.RUnlock(); return r.c }

// pairInventory reports what is on BOTH nodes. The human picks whose data survives and must see both sides at
// once rather than go to the second server for the other half.
//
// An unreachable side is an ERROR in its half of the reply, not an empty inventory: empty would mean "no data",
// and the human would agree to wipe what they never saw.
func pairInventory(local func() (json.RawMessage, error), client *peer.ClientConfig) map[string]any {
	out := map[string]any{}
	if inv, err := local(); err != nil {
		out["local"] = map[string]any{"error": err.Error()}
	} else {
		out["local"] = inv
	}
	if client == nil {
		out["peer"] = map[string]any{"error": "the other node is unreachable: the channel to it is not up"}
		return out
	}
	// Informational only; nobody to cancel it.
	res, err := peer.Call(context.Background(), *client, peer.CmdInventory, nil)
	switch {
	case err != nil:
		out["peer"] = map[string]any{"error": err.Error()}
	case !res.OK:
		out["peer"] = map[string]any{"error": res.Code}
	default:
		out["peer"] = json.RawMessage(res.Response.Payload)
		out["peer_node_id"] = res.Response.SenderNodeID
	}
	return out
}

// handlePair runs pairing commands from the panel and CLI. All of them go to the RUNNING manager: the attempt
// lives in its memory, and a separate process would not see it.
func handlePair(cfg config.Config, svc *pairing.Service, peers *peerRef, req statusapi.Request) (any, error) {
	res, err := handlePairStep(cfg, svc, peers, req)
	if err != nil {
		// Log the reason too, not only return it. The reply lives until the dialog closes, while a failed pair
		// creation is investigated later, and the one useful line must not be lost by then. We got stuck on this once.
		fmt.Fprintf(os.Stderr, "dns-ha-manager: %s: %v\n", req.Cmd, err)
	}
	return res, err
}

func handlePairStep(cfg config.Config, svc *pairing.Service, peers *peerRef, req statusapi.Request) (any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	switch req.Cmd {
	case "pair_status":
		v, err := svc.Status(ctx)
		if err != nil {
			return nil, err
		}
		return struct {
			pairing.View
			Build *buildStep `json:"build,omitempty"`
		}{v, buildProgress.Load()}, nil
	case "pair_inventory":
		return pairInventory(localInventory, peers.get()), nil
	case "pair_devices":
		return pairDevices(cfg, peers, req.Address, req.Provider)
	case "pair_build":
		// Pair creation is driven by the DONOR, the node whose data survives. Here that is always us: the human
		// issued the command on this node to keep its data.
		return createPair(cfg, peers, req)
	case "pair_create":
		expires, err := svc.Create(ctx)
		if err != nil {
			return nil, err
		}
		return map[string]any{"expires": expires}, nil
	case "pair_join":
		if req.Address == "" {
			return nil, fmt.Errorf("pair_join without the peer address")
		}
		code, err := svc.Join(ctx, req.Address)
		if err != nil {
			return nil, err
		}
		return map[string]any{"code": code}, nil
	case "pair_approve":
		if err := svc.Approve(ctx, req.RequestedBy); err != nil {
			return nil, err
		}
		return svc.Status(ctx)
	case "pair_reject":
		svc.Reject()
		return svc.Status(ctx)
	case "pair_reset":
		if err := svc.Reset(ctx, req.Force); err != nil {
			return nil, err
		}
		return svc.Status(ctx)
	}
	return nil, fmt.Errorf("unknown pairing command: %s", req.Cmd)
}

// pairCLI runs the same actions from a terminal, via the control socket for the same reason: the attempt state
// lives in the running daemon.
func pairCLI(action, address, by string, force bool, plan statusapi.Request) int {
	req := plan
	req.Address, req.RequestedBy, req.Force = address, by, force
	switch action {
	case "status", "inventory", "devices", "create", "join", "approve", "reject", "reset", "build":
		req.Cmd = "pair_" + action
	default:
		fmt.Fprintln(os.Stderr,
			"dns-ha-manager: -pair accepts status|inventory|devices|create|join|approve|reject|reset|build")
		return 2
	}
	raw, err := askManager(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, "dns-ha-manager:", err)
		return 1
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		fmt.Fprintln(os.Stderr, "dns-ha-manager: the response could not be parsed:", err)
		return 1
	}
	pretty, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(pretty))
	if ok, _ := out["ok"].(bool); !ok {
		return 1
	}
	return 0
}

// askManager sends one request to the control socket. No dedicated client on purpose: the socket answers with
// one JSON line, so sending a line and reading a line is all that is needed.
func askManager(req statusapi.Request) ([]byte, error) {
	conn, err := net.DialTimeout("unix", config.StatusSocket, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("HA manager is unavailable (%s): %w", config.StatusSocket, err)
	}
	defer conn.Close()
	// Wait EXACTLY as long as the command is allowed on the other side: a client that gives up before the executor
	// leaves the human with no answer while the operation runs ("still going or broken?").
	_ = conn.SetDeadline(time.Now().Add(statusapi.DeadlineFor(req.Cmd) + 10*time.Second))
	line, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(append(line, '\n')); err != nil {
		return nil, err
	}
	raw, err := bufio.NewReader(io.LimitReader(conn, 256*1024)).ReadBytes('\n')
	if err != nil && len(raw) == 0 {
		return nil, err
	}
	return raw, nil
}
