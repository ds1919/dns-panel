package agentd

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"time"
)

// Server is the agent's unix socket: one request line, one response line.
//
// Only group `dns-ha` can connect, since commanding the root executor means changing the node's role.
// The agent never listens on the network.
type Server struct {
	Agent  *Agent
	Socket string
	Group  string // socket owner group

	ln net.Listener
}

const (
	maxRequest = 64 * 1024
	// CallTimeout caps serving one request; the outer bound of the chain executor < client < socket.
	CallTimeout = 15 * time.Minute
)

func (s *Server) Listen() error {
	dir := filepath.Dir(s.Socket)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	os.Remove(s.Socket) // stale socket from a previous run
	ln, err := net.Listen("unix", s.Socket)
	if err != nil {
		return err
	}
	s.ln = ln
	if err := os.Chmod(s.Socket, 0o660); err != nil {
		return err
	}
	if s.Group != "" {
		g, err := user.LookupGroup(s.Group)
		if err != nil {
			return fmt.Errorf("group %q: %w", s.Group, err)
		}
		gid, _ := strconv.Atoi(g.Gid)
		if err := os.Chown(s.Socket, 0, gid); err != nil {
			return fmt.Errorf("socket owner: %w", err)
		}
		if err := os.Chown(dir, 0, gid); err != nil {
			return fmt.Errorf("socket directory owner: %w", err)
		}
	}
	return nil
}

func (s *Server) Serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *Server) Close() error {
	if s.ln == nil {
		return nil
	}
	err := s.ln.Close()
	os.Remove(s.Socket)
	return err
}

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(CallTimeout))
	// The same deadline bounds the work itself, not only the socket, and is passed down the chain.
	ctx, cancel := context.WithTimeout(context.Background(), CallTimeout)
	defer cancel()

	line, err := bufio.NewReader(io.LimitReader(conn, maxRequest+1)).ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return
	}
	if len(line) > maxRequest {
		writeJSON(conn, errResp("bad_request", "the request is too large"))
		return
	}
	var req Request
	if err := json.Unmarshal(line, &req); err != nil {
		writeJSON(conn, errResp("bad_request", "the request could not be parsed"))
		return
	}
	writeJSON(conn, s.Agent.HandleContext(ctx, req))
}

func writeJSON(w io.Writer, v any) {
	raw, err := json.Marshal(v)
	if err != nil {
		return
	}
	w.Write(append(raw, '\n'))
}
