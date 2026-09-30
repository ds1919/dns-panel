// Package probe implements exactly two probe kinds, ICMP echo and TCP connect: we check ADDRESS
// reachability, not application health.
//
// The target is always an ADDRESS, never a name: names resolve through the very DNS this system switches,
// so a name-based check would start probing another host after the first switch and confirm itself.
package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// ICMPAvailable reports whether ICMP can be sent here. Asked ONCE at startup and reported to the server:
// missing privileges must not look like a failing host, so the agent simply takes no such tasks (docs/25 §1).
func ICMPAvailable() bool {
	for _, n := range []struct{ net, addr string }{
		{"udp4", "0.0.0.0"},     // unprivileged ping: needs net.ipv4.ping_group_range
		{"ip4:icmp", "0.0.0.0"}, // raw socket: needs CAP_NET_RAW
	} {
		c, err := icmp.ListenPacket(n.net, n.addr)
		if err == nil {
			c.Close()
			return true
		}
	}
	return false
}

// ErrCannotMeasure means NO probe happened (no socket, no privileges, unparsable address). "Nothing to
// check with" is unknown, while "no reply" is an outage; the two must never be confused (docs/25 §1).
var ErrCannotMeasure = errors.New("probe not performed")

// One runs a single probe and returns nil if the target replied in time.
func One(ctx context.Context, kind, ip string, port uint32, timeout time.Duration) error {
	switch kind {
	case "tcp":
		return tcpOne(ctx, ip, port, timeout)
	case "icmp":
		return icmpOne(ctx, ip, timeout)
	}
	return fmt.Errorf("unknown probe kind %q", kind)
}

func tcpOne(ctx context.Context, ip string, port uint32, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, fmt.Sprint(port)))
	if err != nil {
		return err
	}
	return c.Close()
}

func icmpOne(ctx context.Context, ip string, timeout time.Duration) error {
	addr := net.ParseIP(ip)
	if addr == nil {
		return fmt.Errorf("%w: %q is not an address", ErrCannotMeasure, ip)
	}
	network, listen, proto, typ := "udp4", "0.0.0.0", 1, icmp.Type(ipv4.ICMPTypeEcho)
	if addr.To4() == nil {
		network, listen, proto, typ = "udp6", "::", 58, icmp.Type(ipv6.ICMPTypeEchoRequest)
	}
	// On a ping socket the KERNEL sets the echo ID (it substitutes the local port) and routes replies back
	// by it, so the ID must not be compared with what we wrote: it never matches. That once made every
	// probe silently time out on hosts with ping_group_range open.
	unpriv := true
	conn, err := icmp.ListenPacket(network, listen)
	if err != nil {
		// Fallback: a raw socket needs CAP_NET_RAW but no sysctl change. There the ID is ours and is what
		// tells our reply apart, since the socket sees all ICMP on the host.
		unpriv = false
		raw := "ip4:icmp"
		if addr.To4() == nil {
			raw = "ip6:ipv6-icmp"
		}
		conn, err = icmp.ListenPacket(raw, listen)
		if err != nil {
			return fmt.Errorf("%w: icmp socket: %v", ErrCannotMeasure, err)
		}
	}
	defer conn.Close()

	body := &icmp.Echo{ID: os.Getpid() & 0xffff, Seq: int(time.Now().UnixNano() & 0xffff),
		Data: []byte("dns-panel-pulse")}
	wire, err := (&icmp.Message{Type: typ, Code: 0, Body: body}).Marshal(nil)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return err
	}
	// A ping socket takes a UDP address, a raw one an IP address; the wrong kind fails the write, and every
	// probe then looked like a host that does not answer.
	dst := net.Addr(&net.UDPAddr{IP: addr})
	if !unpriv {
		dst = &net.IPAddr{IP: addr}
	}
	if _, err := conn.WriteTo(wire, dst); err != nil {
		return err
	}
	buf := make([]byte, 1500)
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			return err
		}
		msg, err := icmp.ParseMessage(proto, buf[:n])
		if err != nil {
			continue
		}
		if echo, ok := msg.Body.(*icmp.Echo); ok && echo.Seq == body.Seq && (unpriv || echo.ID == body.ID) {
			return nil
		}
		// Someone else's reply: keep waiting for ours until the deadline.
	}
}

// RoutableTo reports whether there is a route and source address from here to THIS address. Asked before
// a probe; "no" means "cannot measure", not "host down": otherwise an agent without a route to that
// network would paint it red without ever reaching it (docs/25 §7).
//
// This is route selection, not traffic: a UDP "connect" sends nothing, it only makes the kernel pick a
// source address. Whatever it picks (loopback for a loopback target) is a real path.
func RoutableTo(ip string) bool {
	addr := net.ParseIP(ip)
	if addr == nil {
		return false
	}
	network := "udp4"
	if addr.To4() == nil {
		network = "udp6"
	}
	c, err := net.Dial(network, net.JoinHostPort(ip, "9")) // 9 = discard; the port is irrelevant, we only ask for a route
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// Routable reports whether there is a REAL outbound path for this address family, not whether the kernel
// has IPv6 or ::1 exists; otherwise an agent without a route would paint every AAAA red (docs/25 §7).
//
// This is only the overall capability that decides whether the agent gets AAAA tasks at all. The path to
// a specific target is checked separately before the probe: a route to a local network may exist without
// internet access, and vice versa.
func Routable(family string) bool {
	network, probes := "udp4", []string{"8.8.8.8:53", "192.168.0.1:53", "10.0.0.1:53"}
	if family == "ipv6" {
		network, probes = "udp6", []string{"[2001:4860:4860::8888]:53", "[fd00::1]:53", "[fc00::1]:53"}
	}
	for _, p := range probes {
		c, err := net.Dial(network, p)
		if err != nil {
			continue
		}
		local, _ := c.LocalAddr().(*net.UDPAddr)
		c.Close()
		if local == nil {
			continue
		}
		// Loopback and link-local sources do not count as an outbound path.
		if local.IP.IsGlobalUnicast() && !local.IP.IsLoopback() && !local.IP.IsLinkLocalUnicast() {
			return true
		}
	}
	return false
}
