package configsync

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"dnspanel/dns-ha/internal/store"
)

// Replication address checks BEFORE a revision is created.
//
// Changing `replication_host` is not cosmetic: STANDBY will then connect to the new address, and a typo in it
// breaks replication until a human notices the wrong digit. One TCP connection is a cheap check that prevents
// the most annoying mistake: a nonexistent address accepted as pair configuration and shipped to both nodes.
//
// Only what can be checked honestly is checked: MariaDB answers at the address. Whether it is THAT node's
// MariaDB cannot be seen from here without its credentials; that kind of misconfiguration is beyond the typo
// this exists for.

// ReplicationCheck describes what did not match and why.
type ReplicationCheck struct {
	NodeID  string
	Address string
	Reason  string
}

func (c ReplicationCheck) Error() string {
	return fmt.Sprintf("replication_host_unreachable: node %s, address %s: %s", c.NodeID, c.Address, c.Reason)
}

// CheckReplicationHosts checks the addresses THAT CHANGE. Unchanged ones are skipped: the pair may run with a
// peer that is currently unreachable (rebooting), and blocking a node rename for that would demand pair health
// where only the description changes.
func CheckReplicationHosts(ctx context.Context, cur, next store.ConfigPayload, port int, timeout time.Duration) error {
	old := map[string]string{}
	for _, n := range cur.Nodes {
		old[n.NodeID] = n.ReplicationHost
	}
	if port <= 0 {
		port = 3306
	}
	if next.Replication != nil && next.Replication.Port > 0 {
		port = next.Replication.Port
	}
	for _, n := range next.Nodes {
		host := n.ReplicationHost
		if host == "" || host == old[n.NodeID] {
			continue
		}
		if reason := probeMariaDB(ctx, net.JoinHostPort(host, strconv.Itoa(port)), timeout); reason != "" {
			return ReplicationCheck{NodeID: n.NodeID, Address: host, Reason: reason}
		}
	}
	return nil
}

// probeMariaDB reports whether MariaDB answers at addr; an empty string means it does.
//
// It looks at the server greeting, which comes FIRST, before any authentication, and starts with protocol
// version 10. "Port open" is not enough: anything could listen on 3306, and mistyping an address within your
// own network is common.
func probeMariaDB(ctx context.Context, addr string, timeout time.Duration) string {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return "cannot connect (" + err.Error() + ")"
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(timeout))

	r := bufio.NewReader(conn)
	head := make([]byte, 5) // 3 bytes packet length, sequence number, protocol version
	if _, err := readFull(r, head); err != nil {
		return "no greeting from the server (" + err.Error() + ")"
	}
	if head[4] != 10 {
		return "the service answering at this address is not MariaDB"
	}
	return ""
}

func readFull(r *bufio.Reader, buf []byte) (int, error) {
	n := 0
	for n < len(buf) {
		m, err := r.Read(buf[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}
