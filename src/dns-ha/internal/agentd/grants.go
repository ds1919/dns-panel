package agentd

import (
	"fmt"
	"net"
	"regexp"
)

// Replication accounts for the pair.
//
// Created locally on EACH node and strictly BEFORE replication starts: once the replica is connected, any
// CREATE USER/GRANT on the source goes into the binlog, and repeating it on the receiver means divergence
// and broken strict GTID. After pair creation only ACTIVE manages accounts.
//
// Grants are needed in BOTH directions (source A today, B tomorrow), so each node creates access FOR ITS PEER.
//
// Passwords are not in the request: the agent reads them from its own files placed earlier by
// install_secret. A secret passed a second way is a second place for it to diverge.

// hostRe is an acceptable MariaDB host pattern: name, address or `%` pattern. It goes into DDL, so it is
// checked against a character allowlist — there is no way to escape a host name in GRANT.
var hostRe = regexp.MustCompile(`^[0-9a-zA-Z.:_%-]+$`)

// replicationHost normalises the host for MariaDB and REJECTS a network endpoint.
//
// The trap is real: `peer_endpoint` like 192.0.2.12:7901 passes any sane character allowlist and yields
// 'repl'@'192.0.2.12:7901' — an account nobody will ever connect as, while everything looks successful. A
// port means nothing in a MariaDB host name, so a string with a port is a caller ERROR, not something to guess.
func replicationHost(host string) (string, error) {
	if host == "" {
		return "", fmt.Errorf("empty host")
	}
	// A bare address (including IPv6 with colons) is the common and only unambiguous case.
	if ip := net.ParseIP(host); ip != nil {
		return ip.String(), nil
	}
	// Parses as host:port, so we were given an endpoint: reject explicitly.
	if h, p, err := net.SplitHostPort(host); err == nil && p != "" {
		return "", fmt.Errorf("a host without a port is expected, got the connection address %q (the host here is %q)", host, h)
	}
	if !hostRe.MatchString(host) {
		return "", fmt.Errorf("unusable host pattern %q", host)
	}
	return host, nil
}

// EnsurePairGrants creates local access for the peer. Idempotent: a repeat resets password and grants without
// breaking anything, which is what a retried interrupted pair creation needs.
func (n *Node) EnsurePairGrants(host string) (Response, error) {
	host, err := replicationHost(host)
	if err != nil {
		return errResp("bad_request", err.Error()), nil
	}
	replPass, err := n.Cfg.replicationSecret()
	if err != nil {
		return failResp(err), nil
	}
	dumpPass, err := n.Cfg.dumpSecret()
	if err != nil {
		return failResp(err), nil
	}
	if replPass == "" || dumpPass == "" {
		return errResp("secret_missing", "the replication passwords are not set yet"), nil
	}
	db, err := n.db()
	if err != nil {
		return failResp(err), nil
	}

	accounts := []struct {
		user, pass, grant string
	}{
		// repl is replication only: dumps do NOT use it (that is ha_monitor's job).
		{n.Cfg.Replication.User, replPass, "REPLICATION SLAVE"},
		// ha_monitor does reseed and monitoring. SLAVE MONITOR is required: MariaDB 10.5+ needs it for
		// SHOW REPLICA STATUS, otherwise preflight fails with "no replica status" for no reason.
		{n.Cfg.Replication.DumpUser, dumpPass, "REPLICATION CLIENT, REPLICATION SLAVE, SLAVE MONITOR, SELECT"},
	}
	for _, a := range accounts {
		if a.user == "" {
			return errResp("bad_request", "the agent config has no replication user"), nil
		}
		acct := fmt.Sprintf("%s@%s", quote(a.user), quote(host))
		if _, err := db.ExecContext(n.ctx(), "CREATE USER IF NOT EXISTS "+acct+" IDENTIFIED BY "+quote(a.pass)); err != nil {
			return failResp(fail("grant_failed", err.Error())), nil
		}
		// ALTER after CREATE IF NOT EXISTS: the user may exist with an old password (nodes installed
		// independently), so "already exists" means "wrong password", not "all good".
		if _, err := db.ExecContext(n.ctx(), "ALTER USER "+acct+" IDENTIFIED BY "+quote(a.pass)); err != nil {
			return failResp(fail("grant_failed", err.Error())), nil
		}
		if _, err := db.ExecContext(n.ctx(), "GRANT "+a.grant+" ON *.* TO "+acct); err != nil {
			return failResp(fail("grant_failed", err.Error())), nil
		}
	}
	return Response{OK: true, Message: "access for the peer " + host + " is configured"}, nil
}
