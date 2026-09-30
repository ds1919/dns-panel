package agentd

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"syscall"
	"time"
)

// Publication of the pair's service address (`publication.address`), which lives on the proven ACTIVE node.
//
// The truth is the address on the interface, not the marker file. The marker is used only when something
// else brings the address up (BGP daemon, external balancer) and then records just the node's intent.
//
// Failing to add the address just leaves the node unpublished; failing to remove it must be reported, since
// two owners of one address is exactly the failure HA exists to prevent.

func (n *Node) AnnouncePanel(address, device, provider string) (Response, error) {
	return n.setPublication(true, address, device, provider)
}
func (n *Node) WithdrawPanel(address, device, provider string) (Response, error) {
	return n.setPublication(false, address, device, provider)
}

// setPublication announces or withdraws the service address.
//
// Anycast keeps the same address permanently on loopback of both nodes: removing it would drop traffic the
// router may still send for a moment. Publication there is switched by the probe (held by the manager, see
// internal/probe), so anycast only keeps the address up and maintains the marker as route_announced.
func (n *Node) setPublication(want bool, address, device, provider string) (Response, error) {
	// The replicated revision wins over the local file so both nodes publish the same address; the local
	// config is a fallback when the revision has none.
	addr, dev := n.Cfg.Publication.Address, n.Cfg.Publication.Device
	if address != "" && device != "" {
		if _, _, err := net.ParseCIDR(address); err != nil {
			return failResp(fail("publication_address_invalid", err.Error())), nil
		}
		if _, err := net.InterfaceByName(device); err != nil {
			return failResp(fail("publication_device_unknown", err.Error())), nil
		}
		addr, dev = address, device
	}
	if addr == "" {
		return n.setPublicationMarker(want)
	}
	if provider == providerAnycast {
		return n.setAnycastPublication(want, addr, dev)
	}

	have, err := n.addrPresent(addr, dev)
	if err != nil {
		return failResp(fail("publication_state_unknown", err.Error())), nil
	}
	if have == want {
		// The marker follows the fact, not the other way round.
		n.syncMarker(n.markerRoute(), want)
		return Response{OK: true, Noop: true, Status: n.pubStatus(want, "", addr, dev)}, nil
	}

	action := "del"
	if want {
		action = "add"
	}
	out, runErr := n.run("ip", "addr", action, addr, "dev", dev)

	// Re-observe instead of trusting `ip`'s exit code: "File exists" / "Cannot assign requested address"
	// mean the desired state already holds.
	got, err := n.addrPresent(addr, dev)
	if err != nil {
		return failResp(fail("publication_state_unknown", err.Error())), nil
	}
	if got != want {
		code := "withdraw_failed"
		if want {
			code = "announce_failed"
		}
		return failResp(fail(code, fmt.Sprintf("ip addr %s %s dev %s: %s (%v)",
			action, addr, dev, strings.TrimSpace(out), runErr))), nil
	}

	// Tell the segment now rather than after ARP cache expiry. A failed announcement does not undo the
	// publication; it only slows convergence.
	garp := ""
	if want {
		if err := announceARP(addr, dev); err != nil {
			garp = err.Error()
		}
	}
	n.syncMarker(n.markerRoute(), want)
	return Response{OK: true, Status: n.pubStatus(want, garp, addr, dev)}, nil
}

// providerAnycast mirrors store.ProviderAnycast; duplicated because the root agent does not import manager packages.
const providerAnycast = "anycast"

// setAnycastPublication always keeps the address up; only the intent to publish changes.
func (n *Node) setAnycastPublication(want bool, addr, dev string) (Response, error) {
	have, err := n.addrPresent(addr, dev)
	if err != nil {
		return failResp(fail("publication_state_unknown", err.Error())), nil
	}
	if !have {
		// With anycast the loopback address is permanent node config, not a role signal.
		if _, runErr := n.run("ip", "addr", "add", addr, "dev", dev); runErr != nil {
			if got, gerr := n.addrPresent(addr, dev); gerr != nil || !got {
				return failResp(fail("announce_failed",
					fmt.Sprintf("ip addr add %s dev %s: %v", addr, dev, runErr))), nil
			}
		}
	}
	mark := n.markerRoute()
	noop := fileExists(mark) == want && have
	n.syncMarker(mark, want)
	st := n.pubStatus(want, "", addr, dev)
	st["publication_provider"] = providerAnycast
	st["anycast_address_up"] = boolInt(true)
	return Response{OK: true, Noop: noop, Status: st}, nil
}

// setPublicationMarker handles the no-address mode where an external provider publishes.
func (n *Node) setPublicationMarker(want bool) (Response, error) {
	mark := n.markerRoute()
	if fileExists(mark) == want {
		return Response{OK: true, Noop: true, Status: map[string]any{"route_announced": boolInt(want)}}, nil
	}
	if want {
		if err := n.setMarker(mark); err != nil {
			return failResp(fail("mark_write_failed", err.Error())), nil
		}
	} else if err := n.clearMarker(mark); err != nil {
		return failResp(fail("mark_unlink_failed", err.Error())), nil
	}
	return Response{OK: true, Status: map[string]any{"route_announced": boolInt(want)}}, nil
}

func (n *Node) pubStatus(want bool, garpErr string, addr, dev string) map[string]any {
	st := map[string]any{
		"route_announced":     boolInt(want),
		"publication_address": addr,
		"publication_device":  dev,
	}
	if garpErr != "" {
		st["garp_error"] = garpErr
	}
	return st
}

func (n *Node) syncMarker(mark string, want bool) {
	if want {
		n.setMarker(mark)
		return
	}
	n.clearMarker(mark)
}

func (n *Node) addrPresent(addr, dev string) (bool, error) {
	out, err := n.run("ip", "-o", "addr", "show", "dev", dev)
	if err != nil {
		return false, fmt.Errorf("ip addr show %s: %s", dev, strings.TrimSpace(out))
	}
	return AddrPresent(out, addr), nil
}

// AddrPresent parses `ip -o addr show` with an exact match including prefix length: 192.0.2.10/32 and
// 192.0.2.10/24 are different entries.
func AddrPresent(out, addr string) bool {
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		for i := 0; i+1 < len(f); i++ {
			if (f[i] == "inet" || f[i] == "inet6") && f[i+1] == addr {
				return true
			}
		}
	}
	return false
}

// announceARP sends three gratuitous ARP announcements (RFC 5227) for the address on our MAC.
//
// Built in rather than `arping -U`: iputils-arping may be missing, and the announcement would then silently
// not happen, leaving the panel unreachable for minutes after a "successful" switchover.
func announceARP(addr, dev string) error {
	ip, _, err := net.ParseCIDR(addr)
	if err != nil {
		return fmt.Errorf("publication address %q: %v", addr, err)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return nil // IPv6 uses Neighbor Advertisement, not ARP
	}
	ifi, err := net.InterfaceByName(dev)
	if err != nil {
		return err
	}
	frame, err := BuildARPAnnounce(ifi.HardwareAddr, ip4)
	if err != nil {
		return err
	}
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ARP)))
	if err != nil {
		return fmt.Errorf("raw ARP socket: %v", err)
	}
	defer syscall.Close(fd)
	sa := &syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_ARP),
		Ifindex:  ifi.Index,
		Halen:    6,
		Addr:     [8]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	}
	for i := 0; i < 3; i++ {
		if err := syscall.Sendto(fd, frame, 0, sa); err != nil {
			return fmt.Errorf("sending ARP: %v", err)
		}
		if i < 2 {
			time.Sleep(200 * time.Millisecond)
		}
	}
	return nil
}

// BuildARPAnnounce builds an ARP announcement: a broadcast request whose sender and target IP are both the
// published address, which updates neighbours' caches without needing a reply.
func BuildARPAnnounce(mac net.HardwareAddr, ip net.IP) ([]byte, error) {
	ip4 := ip.To4()
	if len(mac) != 6 || ip4 == nil {
		return nil, fmt.Errorf("ARP announcement: a 6-byte MAC and IPv4 are required (mac=%v ip=%v)", mac, ip)
	}
	f := make([]byte, 0, 42)
	f = append(f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff) // ethernet dst: broadcast
	f = append(f, mac...)                             // ethernet src
	f = append(f, 0x08, 0x06)                         // ethertype ARP
	f = append(f, 0x00, 0x01)                         // hardware type: ethernet
	f = append(f, 0x08, 0x00)                         // protocol type: IPv4
	f = append(f, 0x06, 0x04)                         // address lengths
	f = append(f, 0x00, 0x01)                         // operation: request
	f = append(f, mac...)                             // sender MAC
	f = append(f, ip4...)                             // sender IP = published address
	f = append(f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00) // target MAC: unknown
	f = append(f, ip4...)                             // target IP = same (makes it gratuitous)
	return f, nil
}

func htons(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return binary.LittleEndian.Uint16(b[:])
}

// DropAddress removes a specific address from the interface.
//
// Used when the pair's anycast address changes: withdrawal never removes an anycast address, so the old one
// would otherwise stay next to the new one. Idempotent; the result is decided by re-observation.
func (n *Node) DropAddress(addr, dev string) (Response, error) {
	if addr == "" || dev == "" {
		return errResp("bad_request", "drop_address needs an address and a device"), nil
	}
	have, err := n.addrPresent(addr, dev)
	if err != nil {
		return failResp(fail("publication_state_unknown", err.Error())), nil
	}
	if !have {
		return Response{OK: true, Noop: true, Status: map[string]any{"address": addr, "device": dev}}, nil
	}
	out, runErr := n.run("ip", "addr", "del", addr, "dev", dev)
	got, gerr := n.addrPresent(addr, dev)
	if gerr != nil {
		return failResp(fail("publication_state_unknown", gerr.Error())), nil
	}
	if got {
		return failResp(fail("drop_address_failed",
			fmt.Sprintf("ip addr del %s dev %s: %s (%v)", addr, dev, strings.TrimSpace(out), runErr))), nil
	}
	return Response{OK: true, Status: map[string]any{"address": addr, "device": dev}}, nil
}

// AddressPresent reports whether a specific address (e.g. the previous anycast address) is on the interface.
// Read-only; a separate command because it is rarely needed and not part of every status poll.
func (n *Node) AddressPresent(addr, dev string) (Response, error) {
	if addr == "" || dev == "" {
		return errResp("bad_request", "address_present needs an address and a device"), nil
	}
	have, err := n.addrPresent(addr, dev)
	if err != nil {
		return failResp(fail("publication_state_unknown", err.Error())), nil
	}
	return Response{OK: true, Status: map[string]any{"present": boolInt(have)}}, nil
}
