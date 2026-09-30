// Package probe is the readiness signal for the router.
//
// In anycast mode the service /32 sits on loopback of BOTH nodes and nothing moves between machines. A node
// is published by having the probe port OPEN: an external checker (tcp-connect) or balancer sees only
// "reachable / not" and decides where to announce the route.
//
//  1. No protocol. The probe reads and writes nothing; a successful TCP handshake is the whole answer.
//  2. Fail-closed by construction. The manager holds the listener in-process: if it dies the socket closes
//     and the route is withdrawn without the panel. That is why the probe lives here, not in the agent.
//  3. Readiness, not role. The port opens because the node is READY to serve (writable, PowerDNS primary,
//     right to be active proven, no operation running), as computed by health.Verdict.ServiceReady.
package probe

import (
	"fmt"
	"net"
	"sync"
)

// Listener is the probe port, opened and closed by readiness; repeated calls with the same wish are no-ops.
type Listener struct {
	mu   sync.Mutex
	ln   net.Listener
	port int
	done chan struct{}
}

// New returns a closed probe.
func New() *Listener { return &Listener{} }

// Set brings the probe to the desired state. A changed port closes the old one and opens the new one:
// staying on a probe_port the revision no longer has would signal the router on stale config.
func (l *Listener) Set(open bool, port int) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if !open || port <= 0 || port > 65535 {
		l.closeLocked()
		if open && (port <= 0 || port > 65535) {
			return fmt.Errorf("probe_port_invalid: %d", port)
		}
		return nil
	}
	if l.ln != nil && l.port == port {
		return nil
	}
	l.closeLocked()

	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return fmt.Errorf("probe_listen_failed: %w", err)
	}
	l.ln, l.port = ln, port
	done := make(chan struct{})
	l.done = done
	// Accept and close immediately: the checker needs only the handshake.
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				select {
				case <-done:
					return // closed by us
				default:
					return // listener died; the next convergence cycle reopens it
				}
			}
			c.Close()
		}
	}()
	return nil
}

// Close closes the probe for good (manager shutdown).
func (l *Listener) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closeLocked()
}

// Port returns the port being listened on, 0 if closed.
func (l *Listener) Port() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.ln == nil {
		return 0
	}
	return l.port
}

// Open reports whether the probe is listening now.
func (l *Listener) Open() bool { return l.Port() != 0 }

func (l *Listener) closeLocked() {
	if l.ln == nil {
		return
	}
	close(l.done)
	l.ln.Close()
	l.ln, l.done, l.port = nil, nil, 0
}
