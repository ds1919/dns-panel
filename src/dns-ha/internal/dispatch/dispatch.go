// Package dispatch serves two conversations on one port 7901: pairing and the regular pair protocol.
//
// One port on purpose: the node moves UNPAIRED → TRUSTED → PAIRED without a restart, and a second listener on
// the same address would not bind. Pairing is flat JSON with a cmd field, the pair protocol a signed envelope.
// What is allowed lives in the handlers (trust state and windows for pairing; signature, epoch and gate for
// the pair); the dispatcher only keeps them apart so an HA command cannot slip through unsigned.
package dispatch

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"dnspanel/dns-ha/internal/pairing"
)

// PeerHandler serves the protocol of an established pair; the dispatcher does not parse it.
type PeerHandler interface {
	ServeLine(conn net.Conn, line []byte)
}

type Dispatcher struct {
	// Pairing is always present: a fresh node must be able to join a pair.
	Pairing *pairing.Service
	// Peer exists only once the pair is configured (nothing to sign or verify before). A func because the
	// server starts later, when MariaDB and the revision become available.
	Peer func() PeerHandler

	Timeout    time.Duration
	MaxMessage int64

	mu   sync.Mutex
	ln   net.Listener
	addr string
}

// Bind listens on addr; calling it with a DIFFERENT address moves the listener. This happens once per node
// lifetime, when the pair config appears and "listen on all" becomes the node's own address.
func (d *Dispatcher) Bind(addr string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.ln != nil && d.addr == addr {
		return nil
	}
	// Close the old listener FIRST: moving from "all" to a specific address on the same port would otherwise
	// fail against our own socket, which is exactly the case this method exists for.
	old, oldAddr := d.ln, d.addr
	if old != nil {
		_ = old.Close()
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		d.ln, d.addr = nil, ""
		if old != nil {
			// Falling back to the old address matters more than the error: without 7901 the node cannot
			// answer its peer at all.
			if back, e := net.Listen("tcp", oldAddr); e == nil {
				d.ln, d.addr = back, oldAddr
				go d.serve(back)
			}
		}
		return err
	}
	d.ln, d.addr = ln, addr
	// Each loop serves its OWN listener, so the one closed on a move ends by itself.
	go d.serve(ln)
	return nil
}

func (d *Dispatcher) Addr() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.ln == nil {
		return ""
	}
	return d.ln.Addr().String()
}

func (d *Dispatcher) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.ln == nil {
		return nil
	}
	err := d.ln.Close()
	d.ln, d.addr = nil, ""
	return err
}

func (d *Dispatcher) serve(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go d.handle(conn)
	}
}

func (d *Dispatcher) handle(conn net.Conn) {
	defer conn.Close()
	timeout := d.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	max := d.MaxMessage
	if max <= 0 {
		max = 64 * 1024
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Limit while reading, or a sender could fill memory before the size check.
	line, err := bufio.NewReader(io.LimitReader(conn, max+1)).ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return
	}
	if isPairing(line) {
		out := d.Pairing.Handle(context.Background(), line, conn.RemoteAddr().String())
		_, _ = conn.Write(append(out, '\n'))
		return
	}
	// Without a pair there is no server and no secret to sign even a refusal, so stay silent.
	if d.Peer == nil {
		return
	}
	srv := d.Peer()
	if srv == nil {
		return
	}
	srv.ServeLine(conn, line)
}

// isPairing recognises pairing by the flat cmd field; the signed pair envelope (body/sig) never has it.
func isPairing(line []byte) bool {
	var head struct {
		Cmd string `json:"cmd"`
	}
	if err := json.Unmarshal(line, &head); err != nil {
		return false
	}
	return strings.HasPrefix(head.Cmd, "pair_")
}
