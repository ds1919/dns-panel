package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"dnspanel/dns-ha/internal/agent"
	"dnspanel/dns-ha/internal/config"
	"dnspanel/dns-ha/internal/pairsetup"
	"dnspanel/dns-ha/internal/peer"
	"dnspanel/dns-ha/internal/statusapi"
	"dnspanel/dns-ha/internal/store"
)

// Changing the PUBLICATION parameters of a working pair: service address and probe port.
//
// For the human it is one action, "Save" on two fields. Internally they differ, but that is not their concern:
//   - port: a normal revision; nodes reopen the probe on the new port through convergence;
//   - address: the same revision plus cleanup. For anycast the address lives on loopback PERMANENTLY and is not
//     removed by withdrawing publication, so the old /32 would stay next to the new one. Each node's convergence
//     removes it on its own (see shadow: drop_stale_address), using the previous revision from the same table.
//     No separate operation is needed: the step is idempotent and failure is harmless (both addresses are up,
//     the service works, and the next cycle retries).
//
// Resources on both sides are checked BEFORE the revision: a busy port or foreign address must be refused up
// front, not discovered after the configuration has spread to the nodes.
func applyPublication(cfg config.Config, snap *snapshot, peers *peerRef, r statusapi.Request) (any, error) {
	if ok, why := configEditable(snap); !ok {
		return nil, fmt.Errorf("config_not_editable: %s", why)
	}
	obs := snap.observation(context.Background())
	cur := obs.Config.Payload
	pub := cur.Publication
	if pub == nil {
		return nil, fmt.Errorf("config_payload_invalid: this pair has no publication to change")
	}

	address := strings.TrimSpace(r.Address)
	if address == "" {
		address, _ = cur.PublicationTarget()
	}
	probe := r.ProbePort
	if probe == 0 {
		probe = cur.ProbePort()
	}
	if pub.Provider == store.ProviderAnycast {
		norm, err := store.NormalizeAnycastAddress(address)
		if err != nil {
			return nil, err
		}
		address = norm
		if probe < store.MinProbePort || probe > 65535 {
			return nil, fmt.Errorf("config_payload_invalid: probe port must be in %d..65535 (got %d)",
				store.MinProbePort, probe)
		}
	}

	oldAddr, _ := cur.PublicationTarget()
	if address == oldAddr && probe == cur.ProbePort() {
		return map[string]any{"changed": false, "address": address, "probe_port": probe}, nil
	}

	// Resources on BOTH nodes and before the revision. Anyone could have taken the port, the address could
	// already sit on another interface; finding out after the config has spread is too late.
	if err := checkPublicationResources(cfg, peers, pub.Provider, address, probe, oldAddr, cur.ProbePort()); err != nil {
		return nil, err
	}

	next := cur
	next.Publication = &store.ConfigPublication{Provider: pub.Provider, Params: pubParams(pub.Provider, address, probe)}
	if err := next.Validate(); err != nil {
		return nil, err
	}
	blob, err := next.Canonical()
	if err != nil {
		return nil, err
	}
	res, err := applyConfig(cfg, snap, blob, r.RequestedBy)
	if err != nil {
		return nil, err
	}
	return map[string]any{"changed": true, "address": address, "probe_port": probe,
		"previous_address": oldAddr, "revision": res}, nil
}

// pubParams renders publication parameters as a revision string. The port is written only for anycast: other
// providers have no probe, and an empty value in the revision would imply a setting that does not exist.
func pubParams(provider, address string, probe int) string {
	params := "address=" + address
	if provider == store.ProviderAnycast && probe > 0 {
		params += ",probe_port=" + strconv.Itoa(probe)
	}
	return params
}

// checkPublicationResources checks that the NEW address and port are free on both nodes.
//
// Only what CHANGES is checked, otherwise the check answers the wrong question and rejects itself:
//   - same address: it is supposed to be up, it is our own effective configuration;
//   - same port: OUR OWN manager on ACTIVE is listening on it right now, and opening it again returns "address
//     already in use", so changing just the address with the port unchanged would always fail on our own probe.
func checkPublicationResources(cfg config.Config, peers *peerRef, provider, address string, probe int,
	oldAddr string, oldProbe int) error {

	if address == oldAddr {
		address = ""
	}
	if probe == oldProbe {
		probe = 0
	}
	if address == "" && probe == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	keys := agent.PeerKeys{Client: agent.Client{Socket: config.AgentSocket, Timeout: config.AgentTimeout}}
	mine, err := keys.CheckPublication(ctx, provider, address, probe, oldAddr)
	if err != nil {
		return fmt.Errorf("checking publication resources on this node: %w", err)
	}
	if !mine.Empty() {
		return fmt.Errorf("cannot apply publication on this node: %s", mine.String())
	}
	client := peers.get()
	if client == nil {
		return fmt.Errorf("no channel to the other node — both nodes must confirm the new address and port")
	}
	c := *client
	c.Timeout = 30 * time.Second
	var ack pairsetup.CheckAck
	res, err := peer.Call(context.Background(), c, peer.CmdInitCheck,
		pairsetup.Check{Provider: provider, ServiceAddress: address, ProbePort: probe})
	if err != nil {
		return fmt.Errorf("checking publication resources on the other node: %w", err)
	}
	if !res.OK {
		return fmt.Errorf("checking publication resources on the other node: %s", res.Code)
	}
	if res.Response != nil && len(res.Response.Payload) > 0 {
		if err := peer.DecodeResponsePayload(res.Response, &ack); err != nil {
			return fmt.Errorf("the other node answered with an unreadable payload: %w", err)
		}
	}
	if ack.Error != "" {
		return fmt.Errorf("the other node could not check its publication resources: %s", ack.Error)
	}
	if c := ack.Conflict(); c != "" {
		return fmt.Errorf("cannot apply publication on the other node: %s", c)
	}
	return nil
}
