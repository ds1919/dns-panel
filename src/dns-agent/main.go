// dns-agent is the privileged local broker between the web panel (www-data) and PowerDNS.
//
// The panel has no access to the PowerDNS control socket. It sends fixed commands here over a unix socket,
// and the agent (running as pdns) runs pdns_control or dig with validated arguments. No shell, ever.
//
// Protocol: one JSON line per request, one JSON line in response (see handle.go for the commands).
//
//	dns-agent [-config /opt/dns-panel/etc/dns-agent.toml]
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

var revision = "dev"

const maxRequest = 64 << 10

// Config is this process's own file, not the panel's: a daemon running as pdns has no business reading the
// panel's DB passwords.
type Config struct {
	Socket, SocketGroup string
	Timeout             time.Duration // one request, including waiting for its turn at pdns_control
	MaxConcurrent       int
	PdnsControl, Dig    string
	VerifyResolver      string
}

func main() {
	path := flag.String("config", defaultConfig(), "config file")
	flag.Parse()
	log.SetFlags(0)
	cfg, err := loadConfig(*path)
	if err != nil {
		log.Fatalf("dns-agent: agent config: %v", err)
	}
	ln, err := listen(cfg)
	if err != nil {
		log.Fatalf("dns-agent: socket %s: %v", cfg.Socket, err)
	}

	var stopping atomic.Bool
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-stop; stopping.Store(true); ln.Close() }()

	log.Printf("dns-agent %s: listening on %s (timeout=%s, max_concurrent=%d, pdns_control=%s)",
		revision, cfg.Socket, cfg.Timeout, cfg.MaxConcurrent, cfg.PdnsControl)
	sdNotify("READY=1")

	// Bounded: past the limit connections wait in the listen backlog instead of each spawning a dig.
	slots := make(chan struct{}, cfg.MaxConcurrent)
	for {
		slots <- struct{}{}
		conn, err := ln.Accept()
		if err != nil {
			if stopping.Load() {
				break
			}
			// Exit non-zero so Restart=on-failure brings the agent back.
			log.Fatalf("dns-agent: accept: %v", err)
		}
		go func() { serve(conn, cfg); <-slots }()
	}
	log.Print("dns-agent: stopped")
}

// listen opens the socket. Its directory is setgid www-data (tmpfiles), so the socket gets the panel's
// group without the agent being a member of it: membership would let pdns read the panel's secrets.
func listen(cfg Config) (*net.UnixListener, error) {
	if st, err := os.Lstat(cfg.Socket); err == nil && st.Mode()&os.ModeSocket != 0 {
		os.Remove(cfg.Socket) // stale socket from a killed run; anything else there makes bind fail loudly
	}
	old := syscall.Umask(0o117)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: cfg.Socket, Net: "unix"})
	syscall.Umask(old)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*net.UnixListener, error) { ln.Close(); return nil, err }
	if err := os.Chmod(cfg.Socket, 0o660); err != nil {
		return fail(err)
	}
	g, err := user.LookupGroup(cfg.SocketGroup)
	if err != nil {
		return fail(err)
	}
	var st syscall.Stat_t
	if err := syscall.Stat(cfg.Socket, &st); err != nil {
		return fail(err)
	}
	if strconv.FormatUint(uint64(st.Gid), 10) != g.Gid {
		return fail(fmt.Errorf("socket group is gid %d, not %s: the directory must be setgid %s (etc/tmpfiles/dns-panel.conf)",
			st.Gid, cfg.SocketGroup, cfg.SocketGroup))
	}
	return ln, nil
}

func serve(conn net.Conn, cfg Config) {
	defer conn.Close()
	// A client that connects and never finishes its line must not hold a slot forever.
	conn.SetReadDeadline(time.Now().Add(cfg.Timeout))
	// Our requests are a few hundred bytes; the cap only keeps a runaway client from growing memory.
	line, err := bufio.NewReader(io.LimitReader(conn, maxRequest)).ReadBytes('\n')
	if len(line) == 0 && err != nil {
		return
	}
	var req any
	var resp map[string]any
	dec := json.NewDecoder(strings.NewReader(string(line)))
	dec.UseNumber()
	if len(line) == maxRequest && line[len(line)-1] != '\n' {
		resp = fail("request too large")
	} else if err := dec.Decode(&req); err != nil {
		resp = fail("invalid JSON")
	} else {
		resp = handle(req, cfg)
	}
	out, _ := json.Marshal(resp)
	conn.SetWriteDeadline(time.Now().Add(cfg.Timeout))
	conn.Write(append(out, '\n'))
}

func defaultConfig() string {
	exe, err := os.Executable()
	if err == nil {
		exe, err = filepath.EvalSymlinks(exe)
	}
	if err != nil {
		return "/opt/dns-panel/etc/dns-agent.toml"
	}
	return filepath.Join(filepath.Dir(exe), "..", "etc", "dns-agent.toml")
}

// loadConfig reads flat key = value lines. Anything it doesn't know is an error: a typo must not silently
// fall back to a default.
func loadConfig(path string) (Config, error) {
	c := Config{SocketGroup: "www-data", Timeout: 5 * time.Second, MaxConcurrent: 16,
		PdnsControl: "/usr/bin/pdns_control", Dig: "/usr/bin/dig", VerifyResolver: "127.0.0.1"}
	raw, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	for no, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		at := fmt.Sprintf("%s:%d", path, no+1)
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return c, fmt.Errorf("%s: expected key = value", at)
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if i := strings.IndexByte(v, '#'); i > 0 && (v[i-1] == ' ' || v[i-1] == '\t') {
			v = strings.TrimSpace(v[:i])
		}
		v = strings.Trim(v, `"`)
		switch k {
		case "socket":
			c.Socket = v
		case "socket_group":
			c.SocketGroup = v
		case "timeout", "max_concurrent":
			n, err := strconv.Atoi(v)
			if err != nil || n <= 0 {
				return c, fmt.Errorf("%s: %s must be a positive integer", at, k)
			}
			if k == "timeout" {
				c.Timeout = time.Duration(n) * time.Second
			} else {
				c.MaxConcurrent = n
			}
		case "pdns_control":
			c.PdnsControl = v
		case "dig":
			c.Dig = v
		case "verify_resolver":
			c.VerifyResolver = v
		default:
			return c, fmt.Errorf("%s: unknown key %q", at, k)
		}
	}
	if c.Socket == "" {
		return c, fmt.Errorf("socket is not set in %s", path)
	}
	return c, nil
}

// sdNotify tells systemd (Type=notify) the socket is open. NOTIFY_SOCKET is dropped so pdns_control and dig
// don't inherit it.
func sdNotify(state string) {
	addr := os.Getenv("NOTIFY_SOCKET")
	if addr == "" {
		return
	}
	os.Unsetenv("NOTIFY_SOCKET")
	if addr[0] == '@' {
		addr = "\x00" + addr[1:]
	}
	c, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: addr, Net: "unixgram"})
	if err != nil {
		log.Printf("dns-agent: sd_notify: %v", err)
		return
	}
	c.Write([]byte(state))
	c.Close()
}
