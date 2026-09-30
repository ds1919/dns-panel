// Package hagate asks dns-ha-manager, the same authority the panel uses, whether this node may write.
// There must be no second HA model here (docs/22, docs/25 §2).
//
//   - ask AT WRITE TIME, not at startup: the role changes under a running process;
//   - "don't know" is a REFUSAL: treating it as "no HA" would open writes on a node that may be STANDBY.
package hagate

import (
	"context"
	"encoding/json"
	"net"
	"sync"
	"time"
)

type Gate struct {
	Socket  string
	Enabled bool          // whether this node has HA at all; from the config, as in the panel
	Timeout time.Duration // limit for a manager call
	TTL     time.Duration // how long a previous verdict is trusted

	mu     sync.Mutex
	cached bool
	until  time.Time
}

// CanObserve reports whether THIS node may observe: accept agents and record their states.
//
// This is NOT permission to change DNS (docs/25 §2): during a planned HA operation zone writes are
// frozen, but results must still be accepted.
func (g *Gate) CanObserve(ctx context.Context) bool {
	if g == nil || !g.Enabled {
		return true // no HA: the node serves itself
	}
	g.mu.Lock()
	if time.Now().Before(g.until) {
		v := g.cached
		g.mu.Unlock()
		return v
	}
	g.mu.Unlock()

	v := g.ask(ctx)
	g.mu.Lock()
	g.cached, g.until = v, time.Now().Add(g.TTL)
	g.mu.Unlock()
	return v
}

type status struct {
	Role string `json:"role"`
	Pair struct {
		HAConfigured *bool `json:"ha_configured"`
	} `json:"pair"`
}

func (g *Gate) ask(ctx context.Context) bool {
	d := net.Dialer{Timeout: g.Timeout}
	conn, err := d.DialContext(ctx, "unix", g.Socket)
	if err != nil {
		return false // manager unreachable: unknown, so no writes
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(g.Timeout))
	if _, err := conn.Write([]byte(`{"cmd":"status"}` + "\n")); err != nil {
		return false
	}
	var st status
	if err := json.NewDecoder(conn).Decode(&st); err != nil {
		return false
	}
	if st.Pair.HAConfigured == nil {
		return false // "don't know" is a refusal
	}
	if !*st.Pair.HAConfigured {
		return true // HA installed but not enabled: roles do not exist
	}
	// A running operation is deliberately ignored: it freezes zone writes, not observations.
	return st.Role == "active"
}
