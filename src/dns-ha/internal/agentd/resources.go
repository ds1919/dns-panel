package agentd

import (
	"fmt"
	"net"
	"strings"
)

// Checks the resources publication will need (probe port, service address) before anything is changed.
//
// Both belong to the host and may be taken by something unrelated; finding out after a reseed is too late.
// This does not replace the runtime guard (a probe that fails to open keeps the node not ready): preflight
// catches the predictable error before destructive steps, runtime catches the rest.

// PublicationConflicts lists what prevents publishing on this node; empty means nothing.
type PublicationConflicts struct {
	ProbePort string `json:"probe_port,omitempty"`
	Address   string `json:"address,omitempty"`
}

// CheckPublication reports whether the probe port and service address are free.
//
// A conflict is a successful observation (`ok` with details), distinct from "could not check".
func (n *Node) CheckPublication(provider, address string, probePort int) (Response, error) {
	return n.CheckPublicationOwned(provider, address, probePort, "")
}

// CheckPublicationOwned is CheckPublication where own is the node's legitimate anycast address from its
// current revision; empty means any host prefix found belongs to someone else.
func (n *Node) CheckPublicationOwned(provider, address string, probePort int, own string) (Response, error) {
	var c PublicationConflicts
	if probePort > 0 {
		if err := probePortFree(probePort); err != nil {
			c.ProbePort = fmt.Sprintf("TCP port %d is already in use (%v)", probePort, err)
		}
	}
	// Only anycast: a floating_ip is expected to be up on its current owner.
	if provider == "anycast" && address != "" {
		if msg, err := anycastAddressConflict(address, own); err != nil {
			return errResp("device_unresolved", err.Error()), nil
		} else if msg != "" {
			c.Address = msg
		}
	}
	return Response{OK: true, Status: map[string]any{"conflicts": c}}, nil
}

// probePortFree opens the port exactly as the probe will, so per-interface use and permission denials show up.
func probePortFree(port int) error {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return err
	}
	return ln.Close()
}

// anycastAddressConflict checks whether the anycast address is already used by something else.
//
// All interfaces are checked: the same address on eth0 belongs to the real network, and Linux would silently
// allow adding it again on lo. A host prefix on loopback is fine only if it is ours (own); a /32 merely present
// on lo may be someone else's, and adopting it would later get it removed by address-change cleanup.
func anycastAddressConflict(address, own string) (string, error) {
	raw := address
	if i := strings.IndexByte(raw, '/'); i >= 0 {
		raw = raw[:i]
	}
	ip := net.ParseIP(raw)
	if ip == nil {
		return "", fmt.Errorf("unusable address %q", address)
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, ifi := range ifaces {
		// "Could not look" is not "no conflict": do not swallow the error.
		addrs, err := ifi.Addrs()
		if err != nil {
			return "", fmt.Errorf("interface %s: %w", ifi.Name, err)
		}
		for _, a := range addrs {
			in, ok := a.(*net.IPNet)
			if !ok || !in.IP.Equal(ip) {
				continue
			}
			ones, bits := in.Mask.Size()
			if msg := addressVerdict(raw, own, ifi.Name, ones, bits, ifi.Flags&net.FlagLoopback != 0); msg != "" {
				return msg, nil
			}
		}
	}
	return "", nil
}

// sameHost compares two addresses ignoring any prefix length.
func sameHost(a, b string) bool {
	strip := func(s string) string {
		if i := strings.IndexByte(s, '/'); i >= 0 {
			s = s[:i]
		}
		return s
	}
	ipA, ipB := net.ParseIP(strip(a)), net.ParseIP(strip(b))
	return ipA != nil && ipB != nil && ipA.Equal(ipB)
}

// addressVerdict is the conflict rule without any network access, so it is testable without root.
//
//	not loopback              → conflict: belongs to the real network
//	loopback, not /32 (/128)  → conflict: a regular interface address, not anycast
//	loopback, host, ours      → no conflict: it is supposed to be up
//	loopback, host, not ours  → conflict: presence on lo does not make it ours
func addressVerdict(addr, own, device string, ones, bits int, loopback bool) string {
	if !loopback {
		return fmt.Sprintf("%s is already configured on %s as %s/%d", addr, device, addr, ones)
	}
	if ones != bits {
		return fmt.Sprintf("%s is already configured on %s as %s/%d", addr, device, addr, ones)
	}
	if own != "" && sameHost(own, addr) {
		return ""
	}
	return fmt.Sprintf("%s is already configured on %s and does not belong to this pair", addr, device)
}
