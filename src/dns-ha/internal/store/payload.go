package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
)

// ConfigPayload is the TYPED content of a pair configuration revision and the ONLY source of the manager's
// working configuration.
//
// It is exactly the object whose canonical form is hashed into `payload_hash`. The point of payload_hash is
// that it is identical on both nodes: they compare one fingerprint of an agreed decision, not rows in their own
// tables (§7.3). So the payload describes the whole PAIR, not "my node".
//
// The normalized tables (`ha_nodes`, `ha_settings`, `ha_replication`, `ha_publication`) are a PROJECTION of it
// for UI and SQL, not the source of truth. Otherwise one stray UPDATE in the projection would let the nodes
// show the same `payload_hash` while running different configurations, turning revisions into decoration.
//
// Field order matters: Go's JSON encoder writes fields in declaration order, and the canonical form needs
// alphabetical keys, so the output matches Perl's `JSON->new->canonical` byte for byte.
type ConfigPayload struct {
	Nodes       []ConfigNode       `json:"nodes"`
	Publication *ConfigPublication `json:"publication"`
	Replication *ConfigReplication `json:"replication"`
	Settings    map[string]string  `json:"settings"`
	Version     int                `json:"version"`
}

// PayloadVersion is the content format version. The fingerprint covers the WHOLE HA config: otherwise the
// sides could have different timeouts, publication or replication parameters under one payload_hash, i.e.
// an "agreed" configuration that actually differs.
const PayloadVersion = 1

type ConfigNode struct {
	// AdminIP is a pointer because the canonical form must distinguish "no field" from "empty string":
	// a legacy blob with `"admin_ip":null` would otherwise re-encode as `""` and stop matching itself.
	AdminIP *string `json:"admin_ip"`
	// Description/Location/Name/Hostname are the node's human metadata. They live HERE, in the pair config,
	// not next to the identity: a human edits them in the panel, and a second place would mean divergence.
	// HA logic ignores them entirely; it only knows NodeID.
	Description string `json:"description,omitempty"`
	Enabled     int    `json:"enabled"`
	Hostname    string `json:"hostname,omitempty"`
	Location    string `json:"location,omitempty"`
	Name        string `json:"name,omitempty"`
	// NodeID is the node UUID, the only field peer, safety and the operation journal identify it by.
	NodeID string `json:"node_id"`
	// PeerListenHost/Port: where the node OF THIS ROW listens on the peer channel.
	PeerListenHost string `json:"peer_listen_host"`
	PeerListenPort int    `json:"peer_listen_port"`
	// PublicationDevice is the interface on which THIS node brings up the service address.
	//
	// A NODE property, not a pair one: the two machines' interfaces are often named differently (eth0 vs
	// ens18), and one device per pair would leave the address nowhere to go after a role switch. Empty means
	// the device from publication params (pairs created before this split look like that).
	PublicationDevice string `json:"publication_device,omitempty"`
	// ReplicationHost is THIS node's MariaDB address as a replication SOURCE. A node property, not a pair
	// one: the source follows the role, and after an A<->B switchover replication runs the other way, so a
	// single `replication.host` would be right only until the first switchover. Separate from admin_ip and
	// peer_listen_host on purpose: admin, HA and SQL endpoints need not coincide.
	ReplicationHost string `json:"replication_host,omitempty"`
}

// ConfigReplication holds pair-wide replication parameters. There is no ADDRESS: it comes from the row of
// the node that is provably ACTIVE right now (see ConfigNode.ReplicationHost). No secret either, only a
// file reference (§4.5); otherwise it would end up in the payload, its fingerprint and peer messages.
type ConfigReplication struct {
	Port      int    `json:"port"`
	SecretRef string `json:"secret_ref"`
	User      string `json:"user"`
}

// ReplicationSourceOf returns where STANDBY must connect when activeNodeID is ACTIVE.
func (p ConfigPayload) ReplicationSourceOf(activeNodeID string) (string, bool) {
	for _, n := range p.Nodes {
		if n.NodeID == activeNodeID && n.ReplicationHost != "" {
			return n.ReplicationHost, true
		}
	}
	return "", false
}

type ConfigPublication struct {
	Params   string `json:"params"`
	Provider string `json:"provider"`
}

// PublicationTargetOf returns the pair address and the interface of a SPECIFIC node. The address is shared
// (one per pair, it moves), the interface is per node: NIC names on two machines need not match.
func (p ConfigPayload) PublicationTargetOf(nodeID string) (address, device string) {
	address, device = p.PublicationTarget()
	// Anycast: the address sits permanently on loopback on BOTH nodes and nothing moves between them, so
	// the interface is the same everywhere and there is nothing to ask the human.
	if p.PublicationProvider() == ProviderAnycast {
		return address, AnycastDevice
	}
	for _, n := range p.Nodes {
		if n.NodeID == nodeID && n.PublicationDevice != "" {
			return address, n.PublicationDevice
		}
	}
	return address, device
}

// PublicationOf returns the full publication target for a node: what to bring up, where, and by which provider.
//
// The provider travels with the address on purpose: without it the executor cannot tell floating_ip from
// anycast, and the difference is exactly whether the address is REMOVED when the role leaves. Getting it wrong
// either leaves two nodes with one moving address or removes an anycast address from loopback, where it is
// never removed.
func (p ConfigPayload) PublicationOf(nodeID string) (address, device, provider string) {
	address, device = p.PublicationTargetOf(nodeID)
	return address, device, p.PublicationProvider()
}

// PublicationProvider returns how the service address is published; empty if the revision has no publication.
func (p ConfigPayload) PublicationProvider() string {
	if p.Publication == nil {
		return ""
	}
	return p.Publication.Provider
}

// ProbePort is the Anycast TCP probe port: an external checker (balancer, health checker, IP SLA) only looks at
// whether it is open. Zero means no probe.
func (p ConfigPayload) ProbePort() int {
	if p.Publication == nil {
		return 0
	}
	for _, kv := range strings.Split(p.Publication.Params, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(kv), "=")
		if !ok || strings.TrimSpace(k) != "probe_port" {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return 0
		}
		return n
	}
	return 0
}

// PublicationTarget returns the service address and interface from the publication params.
//
// The format is deliberately flat (`address=192.0.2.10/32,device=eth0`): provider params are a string in the
// revision content, and giving them a structured object would change the payload format for one provider.
// Empty means the node manages the address itself (local agent config), which is fine: an external publication
// provider (BGP daemon, load balancer) may have no address here at all.
func (p ConfigPayload) PublicationTarget() (address, device string) {
	if p.Publication == nil {
		return "", ""
	}
	for _, kv := range strings.Split(p.Publication.Params, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(kv), "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "address":
			address = strings.TrimSpace(v)
		case "device":
			device = strings.TrimSpace(v)
		}
	}
	return address, device
}

// Service address publication providers.
//
// floating_ip: one /32 physically moves between nodes; the agent brings it up on ACTIVE and removes it on the
// former one, and gratuitous ARP wakes up segment neighbours.
//
// anycast: the same /32 sits PERMANENTLY on loopback of both nodes and nothing moves. A node is published not by
// the address but by the probe port being open: the external checker sees only "port up / down" and decides
// itself where to announce the route. The panel does not manage routing or pretend to know about it: it owns
// the address on lo and an unambiguous readiness signal.
const (
	ProviderMarker     = "marker"
	ProviderFloatingIP = "floating_ip"
	ProviderAnycast    = "anycast"
	ProviderExternal   = "external_health"

	// AnycastDevice is the anycast address interface. Not a setting: an address that never moves lives on
	// loopback, and a choice here would only be a chance to get it wrong.
	AnycastDevice = "lo"
)

var publicationProviders = map[string]bool{
	ProviderMarker: true, ProviderFloatingIP: true, ProviderAnycast: true, ProviderExternal: true,
}

// Canonical returns the bytes payload_hash is computed over. The only allowed way to serialize a payload:
// any deviation here becomes a spurious "configuration conflict".
func (p ConfigPayload) Canonical() ([]byte, error) {
	nodes := append([]ConfigNode(nil), p.Nodes...)
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].NodeID < nodes[j].NodeID })

	if p.Version != PayloadVersion {
		return nil, fmt.Errorf("config_payload_version: unknown format version %d", p.Version)
	}
	c := p
	c.Nodes = nodes
	var v any = c

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	// HTML escaping is off: it would turn `<`/`&` into < etc. and diverge from the Perl canonical form.
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, fmt.Errorf("config_payload_marshal: %w", err)
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil // Encode appends \n, which is not part of the fingerprint
}

// Hash is the SHA-256 of the canonical form.
func (p ConfigPayload) Hash() (string, error) {
	raw, err := p.Canonical()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// Validate checks revision content requirements. Checked BEFORE write and BEFORE commit: a revision in which a
// node can neither start a listener nor be found is useless and dangerous.
func (p ConfigPayload) Validate() error {
	if p.Version != PayloadVersion {
		return fmt.Errorf("config_payload_invalid: unknown format version %d", p.Version)
	}
	if len(p.Nodes) != 2 {
		return fmt.Errorf("config_payload_invalid: a pair must have exactly two nodes, got %d", len(p.Nodes))
	}
	seen := map[string]bool{}
	for _, n := range p.Nodes {
		switch {
		case n.NodeID == "":
			return fmt.Errorf("config_payload_invalid: empty node_id")
		case seen[n.NodeID]:
			return fmt.Errorf("config_payload_invalid: node_id %q is repeated", n.NodeID)
		case n.PeerListenHost == "":
			return fmt.Errorf("config_payload_invalid: %s has no peer_listen_host", n.NodeID)
		case n.PeerListenPort <= 0 || n.PeerListenPort > 65535:
			return fmt.Errorf("config_payload_invalid: %s has an invalid peer_listen_port %d", n.NodeID, n.PeerListenPort)
		}
		seen[n.NodeID] = true
	}
	for k, v := range p.Settings {
		if k == "" || v == "" {
			return fmt.Errorf("config_payload_invalid: empty setting %q", k)
		}
	}
	if r := p.Replication; r != nil {
		if r.User == "" {
			return fmt.Errorf("config_payload_invalid: replication without a user")
		}
		if r.Port <= 0 || r.Port > 65535 {
			return fmt.Errorf("config_payload_invalid: invalid replication port %d", r.Port)
		}
		// With replication configured, every node must be usable as a SOURCE: after a role switch the current
		// replica becomes the source.
		for _, n := range p.Nodes {
			if n.ReplicationHost == "" {
				return fmt.Errorf("config_payload_invalid: %s has no replication_host", n.NodeID)
			}
		}
	}
	if pub := p.Publication; pub != nil {
		if !publicationProviders[pub.Provider] {
			return fmt.Errorf("config_payload_invalid: unknown publication provider %q", pub.Provider)
		}
		// Anycast without an address or a probe is meaningless: there is nowhere to bring the address up and
		// nothing for the router to watch, so from outside the pair looks reachable via both nodes at once.
		if pub.Provider == ProviderAnycast {
			addr, _ := p.PublicationTarget()
			if addr == "" {
				return fmt.Errorf("config_payload_invalid: anycast without a publication address")
			}
			// STRICT, no normalization: this checks an already STORED revision, the very canonical bytes whose
			// identity on both sides defines agreement. Adding a prefix here would accept both "10.0.0.5" and
			// "10.0.0.5/32" with different fingerprints, so two nodes would think they describe one pair with
			// different descriptions. Canonicalizing the address is the INPUT's job (pairsetup.Plan.preflight).
			if err := validateAnycastAddress(addr); err != nil {
				return err
			}
			if port := p.ProbePort(); port < MinProbePort || port > 65535 {
				return fmt.Errorf("config_payload_invalid: anycast needs a probe_port in %d..65535 (got %d)",
					MinProbePort, port)
			}
		}
	}
	return nil
}

// MinProbePort is the lower bound for the probe port.
//
// Privileged ports are excluded on purpose: the manager opens the probe as user `dns-ha`, while the root agent
// checks the port is free. Below 1024 they would disagree (agent "free", manager "denied"), and the resource
// check would confirm something that cannot be done.
const MinProbePort = 1024

// NormalizeAnycastAddress canonicalizes and validates an anycast address.
//
// The prefix is ADDED if omitted: `10.0.0.53` -> `10.0.0.53/32`. Requiring "/32" by hand is ritual: an
// anycast address has no other prefix by definition, it lives on loopback as a single host. Refusing here told
// the human nothing but "guess the format".
//
// A host prefix is the ONLY one allowed. Anycast with `/24` is not "wide anycast" but someone else's network on
// loopback: the node would start answering for addresses it does not own.
//
// Normalization lives HERE, not in the panel: the panel adds the prefix for convenience, but the source of
// truth must be whoever writes the revision, or it would have to be repeated in the CLI, the API and every
// future interface, and one day one of them would diverge.
func NormalizeAnycastAddress(addr string) (string, error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", fmt.Errorf("config_payload_invalid: anycast without a publication address")
	}
	// No prefix: add the host one. The only leniency, and it is purely about input convenience.
	if !strings.Contains(addr, "/") {
		ip := net.ParseIP(addr)
		if ip == nil {
			return "", fmt.Errorf("config_payload_invalid: anycast address %q is not an IP address", addr)
		}
		if ip.To4() != nil {
			addr = ip.String() + "/32"
		} else {
			addr = ip.String() + "/128"
		}
	}
	if err := validateAnycastAddress(addr); err != nil {
		return "", err
	}
	return addr, nil
}

// validateAnycastAddress checks an already canonical address: host prefix, nothing to add.
//
// A host prefix is the ONLY one allowed. Anycast with `/24` is not "wide anycast" but someone else's network on
// loopback: the node would start answering for addresses it does not own.
func validateAnycastAddress(addr string) error {
	_, netw, err := net.ParseCIDR(addr)
	if err != nil {
		return fmt.Errorf("config_payload_invalid: anycast address %q: %v", addr, err)
	}
	if ones, bits := netw.Mask.Size(); ones != bits {
		return fmt.Errorf("config_payload_invalid: anycast address %q must be a single host, got /%d "+
			"(expected /%d)", addr, ones, bits)
	}
	return nil
}

// Transport returns the parameters defining the pair's COMMUNICATION CHANNEL itself (§7.4). They change via a
// separate rotation procedure, not a normal revision: applied asymmetrically they break the channel, after
// which the divergence cannot be fixed automatically since the sides have no way to agree.
func (p ConfigPayload) Transport() map[string]string {
	t := make(map[string]string, len(p.Nodes))
	for _, n := range p.Nodes {
		t[n.NodeID] = fmt.Sprintf("%s:%d", n.PeerListenHost, n.PeerListenPort)
	}
	return t
}

// TransportChanged reports whether the new revision's channel differs from the effective one.
func TransportChanged(cur, next ConfigPayload) bool {
	a, b := cur.Transport(), next.Transport()
	if len(a) != len(b) {
		return true
	}
	for id, addr := range a {
		if b[id] != addr {
			return true
		}
	}
	return false
}

// ParseConfigPayload parses a stored blob and PROVES it is exactly the bytes payload_hash was computed over.
//
// The order of checks matters:
//  1. SHA-256 OF THE RAW BYTES is compared to the expected fingerprint; otherwise we would check the digested
//     result, not the blob (rehashing a parsed struct would accept bytes with different whitespace or key order);
//  2. decoding must read ONE object and hit end of data, otherwise "valid JSON + trailing junk" would pass;
//  3. the canonical form of the parsed value must equal the original bytes, otherwise the blob is not canonical
//     and must not be sent to the peer as revision content.
func ParseConfigPayload(blob []byte, wantHash string) (ConfigPayload, error) {
	var p ConfigPayload
	if len(blob) == 0 {
		return p, fmt.Errorf("config_payload_missing: the revision has no stored content")
	}
	if wantHash != "" {
		sum := sha256.Sum256(blob)
		if got := hex.EncodeToString(sum[:]); got != wantHash {
			return ConfigPayload{}, fmt.Errorf("config_payload_hash_mismatch: stored %s, bytes hash to %s", wantHash, got)
		}
	}
	dec := json.NewDecoder(bytes.NewReader(blob))
	dec.DisallowUnknownFields() // unknown field = foreign schema; its meaning must not be guessed
	if err := dec.Decode(&p); err != nil {
		return ConfigPayload{}, fmt.Errorf("config_payload_parse: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return ConfigPayload{}, fmt.Errorf("config_payload_trailing: extra data after the content")
	}
	canon, err := p.Canonical()
	if err != nil {
		return ConfigPayload{}, err
	}
	if !bytes.Equal(blob, canon) {
		return ConfigPayload{}, fmt.Errorf("config_payload_not_canonical: the stored bytes differ from the canonical form")
	}
	return p, nil
}
