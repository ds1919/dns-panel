package agentd

import (
	"fmt"
	"net"
	"strings"
)

// The node finds its own interface for the service address rather than asking a human: NIC names on the two
// machines need not match (eth0 vs ens18), and a wrong answer would only surface at switchover.
//
// Routing does NOT work for this: on a node already holding the address, `ip route get` answers `dev lo`
// because the address is local (seen on a live ACTIVE). So we inspect the interfaces themselves.

// ResolveDevice finds where the service address lives (or will live). Accepts both CIDR and a bare address.
func (n *Node) ResolveDevice(address string) (Response, error) {
	raw := address
	if i := strings.IndexByte(raw, '/'); i >= 0 {
		raw = raw[:i]
	}
	ip := net.ParseIP(raw)
	if ip == nil {
		return errResp("bad_request", fmt.Sprintf("unusable address %q", address)), nil
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return errResp("device_unresolved", err.Error()), nil
	}

	// 1. The address is already up on some interface. Checked first: it covers the current ACTIVE holding
	//    the VIP and anycast, where the address sits on loopback on purpose and belongs to no subnet.
	for _, ifi := range ifaces {
		addrs, _ := ifi.Addrs()
		for _, a := range addrs {
			if in, ok := a.(*net.IPNet); ok && in.IP.Equal(ip) {
				// Return the prefix too: the panel shows `eth0: 192.0.2.11/24`, and the mask here is an
				// OBSERVATION, not a guess from the network class.
				ones, _ := in.Mask.Size()
				return Response{OK: true, Status: map[string]any{"device": ifi.Name,
					"cidr": fmt.Sprintf("%s/%d", in.IP, ones), "reason": "address is up here"}}, nil
			}
		}
	}
	// 2. The address belongs to an interface's subnet — it will be raised there. Loopback is skipped: a
	//    127.0.0.0/8 address is never a service address, and lo is already covered by case 1.
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifi.Addrs()
		for _, a := range addrs {
			if in, ok := a.(*net.IPNet); ok && in.Contains(ip) {
				return Response{OK: true, Status: map[string]any{"device": ifi.Name, "reason": "address belongs to this subnet"}}, nil
			}
		}
	}
	return errResp("device_unresolved",
		fmt.Sprintf("no interface holds %s or belongs to its subnet", raw)), nil
}
