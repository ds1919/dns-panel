package pairing

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"time"
)

// Transport is how pairing reaches the peer. It is an interface so the whole exchange can be tested without a
// network: the substance of pairing is its states and checks, not sockets.
type Transport interface {
	Send(ctx context.Context, addr string, req any, resp any) error
}

// TCP is a plain connection to the peer's port 7901: one JSON line each way.
//
// There is no TLS or signing here, and there cannot be: pairing is what derives the shared secret, so before
// it there is nothing to sign with. Authenticity comes from the human comparing the code (see crypto.go).
type TCP struct {
	Timeout    time.Duration
	MaxMessage int64
}

func (t TCP) Send(ctx context.Context, addr string, req any, resp any) error {
	timeout := t.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("pairing_unreachable: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	line, err := json.Marshal(req)
	if err != nil {
		return err
	}
	if _, err := conn.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("pairing_io: %w", err)
	}
	max := t.MaxMessage
	if max <= 0 {
		max = 64 * 1024
	}
	raw, err := bufio.NewReader(io.LimitReader(conn, max)).ReadBytes('\n')
	if err != nil && len(raw) == 0 {
		return fmt.Errorf("pairing_io: %w", err)
	}
	if err := json.Unmarshal(raw, resp); err != nil {
		return fmt.Errorf("pairing_bad_response: %w", err)
	}
	return nil
}
