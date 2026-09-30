package config

import "time"

// Platform constants: where the product lives on the node. These are NOT settings: paths are the same on all
// nodes and set by installation, while operational intervals arrive from `dns_ha` as configuration revisions (§7).
//
// Keeping them in TOML would again give two diverging files on two nodes and "why is the timeout different on
// the second node?". A value that truly must change on a live system belongs in CONFIG in the database (shared by
// the pair and revisioned), not in a local line.
//
// Everything product-related lives in ONE tree, `/opt/dns-panel`. Files used to be spread over five system
// directories, and finding out what was installed meant searching the filesystem.
const (
	// Root is the product's single home: bin/ etc/ var/ www/. The repository tree mirrors it one to one.
	Root = "/opt/dns-panel"
	// RunDir holds HA sockets and locks. It is shared by the manager and the agent (root:dns-ha), and it is
	// a privilege boundary, not a per-process split: next to it, /run/dns-panel/pdns holds the panel agent's
	// socket, which has no business in HA IPC. Created by tmpfiles.d and gone on reboot: lock files surviving a
	// reboot would read as "someone is writing" with nobody there.
	RunDir = "/run/dns-panel/ha"

	// AgentSocket is the privileged dns-ha-agent's unix socket.
	AgentSocket = RunDir + "/agent.sock"
	// StatusSocket is the manager's local control socket (the panel and CLI query state).
	StatusSocket = RunDir + "/manager.sock"
	// SafetyPath is the durable safety store: max_seen_epoch, handoff certificate, fencing (§4.3).
	// It lives OUTSIDE MariaDB on purpose: it must be readable when the database is down, read-only or itself the subject of an operation.
	SafetyPath = Root + "/var/safety.json"
	// MyPrintDefaults is the only reliable way to see MariaDB's persisted configuration (§12.3).
	MyPrintDefaults = "my_print_defaults"

	// AgentTimeout bounds one call to the local agent (status/preflight are short commands).
	AgentTimeout = 5 * time.Second
	// ObserveInterval is the watch loop period until the value arrives from CONFIG.
	ObserveInterval = 3 * time.Second
)

// Peer channel: manager<->manager.
const (
	PeerKeyPath    = Root + "/etc/secrets/peer.key"
	PeerWindow     = 30 * time.Second // allowed clock skew
	PeerTimeout    = 5 * time.Second
	PeerMaxMessage = 64 * 1024
)
