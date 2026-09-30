// Package store accesses the local, NON-replicated `dns_ha` database (DOCS/23-ha-manager.md §4).
//
// Note what `dns_ha` does NOT hold: any safety authority (§4.4.1). It holds CONFIG (revisions), STATE
// (observed) and the operations view for the panel. Losing it cannot make the node forget epoch/fence/authority,
// which live in the on-disk safety store, so `dns_ha` can be recreated from scratch.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os/user"
	"sort"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

// SchemaVersion is the schema version THIS binary supports. A mismatch means the schema must be migrated, and
// the manager must say so plainly instead of silently working with someone else's columns.
const SchemaVersion = 1

// ExpectedTables is the `dns_ha` schema per §4.4. Order does not matter; compared as a set.
var ExpectedTables = []string{
	"ha_schema",
	"ha_identity",
	"ha_trusted_peer",
	"ha_peer_requests",
	"ha_config_revision",
	"ha_nodes",
	"ha_settings",
	"ha_replication",
	"ha_publication",
	"ha_operations",
	"ha_operation_steps",
	"ha_state",
}

// Status is the result of observing the store.
type Status struct {
	Reachable     bool     `json:"reachable"`      // MariaDB server answers
	SchemaPresent bool     `json:"schema_present"` // database dns_ha exists
	SchemaValid   bool     `json:"schema_valid"`   // all expected tables present AND schema version matches
	SchemaVersion int      `json:"schema_version,omitempty"`
	MissingTables []string `json:"missing_tables,omitempty"`
	Error         string   `json:"error,omitempty"`
}

// DSN builds the connection string for the LOCAL MariaDB over a unix socket.
// The user is ALWAYS the process's OS user: with `IDENTIFIED VIA unix_socket` MariaDB maps the account by it,
// so no password is needed or stored. There is deliberately no user-name setting: mapping an OS user to a
// different SQL account only creates a mismatch that breaks under the service and looks fine when run by root.
// No database is selected: schema presence must be checkable before the database exists.
//
// The read deadline is a PARAMETER, not a constant, and not fine-tuning: observation and writes need different
// ones. The watch loop hits the database every three seconds and must give up fast (a hung poll is worse than
// not knowing), while a transaction WRITING pair configuration must wait for the answer.
//
// One five-second deadline for everything cost a live incident: `Configure HA` spent minutes reseeding the
// receiver, reached the revision write on the donor and hit `read unix ...: i/o timeout` on the transaction,
// because polling and freshly started replication were hitting the same tables. The driver marked the
// connection bad, `config_seed: invalid connection` surfaced, and the human got a failure after minutes of
// work. It looked like a network drop but was our own deadline.
func DSN(socket string) (string, error) { return dsn(socket, ObserveDeadline) }

// WriteDSN is the same connection for MUTATIONS: revision seeding, schema, operation journal.
func WriteDSN(socket string) (string, error) { return dsn(socket, WriteDeadline) }

// Local MariaDB deadlines. Not performance tuning but the split between two modes of work: see DSN.
const (
	// ObserveDeadline is for observation reads. Short on purpose: the loop runs every three seconds, and
	// getting stuck in it is worse than honestly saying "not read".
	ObserveDeadline = 5 * time.Second
	// WriteDeadline is for writes, as long as a node mutation is allowed: a transaction may wait for a lock,
	// and cutting it by our own deadline would invent a failure where there was none.
	WriteDeadline = 30 * time.Second
)

func dsn(socket string, deadline time.Duration) (string, error) {
	if socket == "" {
		return "", fmt.Errorf("store: empty socket path")
	}
	u, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("store: could not determine the OS user: %w", err)
	}
	return fmt.Sprintf("%s@unix(%s)/?parseTime=true&timeout=5s&readTimeout=%s&writeTimeout=%s",
		u.Username, socket, deadline, deadline), nil
}

// MissingTables returns expected tables absent from actual. A pure function, testable without a database.
func MissingTables(actual []string) []string {
	have := make(map[string]bool, len(actual))
	for _, t := range actual {
		have[strings.ToLower(t)] = true
	}
	var missing []string
	for _, t := range ExpectedTables {
		if !have[t] {
			missing = append(missing, t)
		}
	}
	sort.Strings(missing)
	return missing
}

// Observe connects to the local MariaDB and inspects the schema state. SELECT only.
func Observe(ctx context.Context, socket, dbName string, timeout time.Duration) Status {
	dsn, err := DSN(socket)
	if err != nil {
		return Status{Error: err.Error()}
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return Status{Error: fmt.Sprintf("store_open: %v", err)}
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	c, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := db.PingContext(c); err != nil {
		return Status{Error: fmt.Sprintf("store_unreachable: %v", err)}
	}
	st := Status{Reachable: true}

	var found string
	err = db.QueryRowContext(c, "SELECT schema_name FROM information_schema.schemata WHERE schema_name = ?", dbName).Scan(&found)
	if err == sql.ErrNoRows {
		st.Error = fmt.Sprintf("store_schema_absent: database %q does not exist", dbName)
		return st
	}
	if err != nil {
		st.Error = fmt.Sprintf("store_query: %v", err)
		return st
	}
	st.SchemaPresent = true

	rows, err := db.QueryContext(c, "SELECT table_name FROM information_schema.tables WHERE table_schema = ?", dbName)
	if err != nil {
		st.Error = fmt.Sprintf("store_query: %v", err)
		return st
	}
	defer rows.Close()
	var actual []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			st.Error = fmt.Sprintf("store_scan: %v", err)
			return st
		}
		actual = append(actual, t)
	}
	if err := rows.Err(); err != nil {
		st.Error = fmt.Sprintf("store_rows: %v", err)
		return st
	}
	st.MissingTables = MissingTables(actual)
	if len(st.MissingTables) > 0 {
		st.Error = "store_schema_incomplete: missing tables " + strings.Join(st.MissingTables, ", ")
		return st
	}
	if err := db.QueryRowContext(c, "SELECT MAX(schema_version) FROM "+dbName+".ha_schema").Scan(&st.SchemaVersion); err != nil {
		st.Error = fmt.Sprintf("store_schema_version: %v", err)
		return st
	}
	if st.SchemaVersion != SchemaVersion {
		st.Error = fmt.Sprintf("store_schema_version_mismatch: database has %d, this binary supports %d", st.SchemaVersion, SchemaVersion)
		return st
	}
	st.SchemaValid = true
	return st
}

// NodeConfig is a node of the effective revision: identity, addresses and human metadata.
type NodeConfig struct {
	NodeID string // UUID; all HA logic hinges on it
	// Name/Hostname/Location/Description are for humans. The panel shows them instead of the UUID; no
	// check or role decision looks at them.
	Name           string
	Hostname       string
	Location       string
	Description    string
	AdminIP        string
	PeerListenHost string
	PeerListenPort int
	Enabled        bool
}

// EffectiveConfig is the effective pair configuration. It comes ONLY from the revision's canonical content
// (`payload_blob`, verified against its `payload_hash`): no hardcoding, TOML or normalized tables. The tables
// are a UI projection; a mismatch shows up as ProjectionDrift, but the manager is driven by the content it
// vouches for to the peer by fingerprint.
type EffectiveConfig struct {
	Revision    int64
	PayloadHash string
	Payload     ConfigPayload
	Nodes       []NodeConfig
	// ProjectionDrift is non-empty when the normalized tables diverge from the content. Work continues
	// (values come from the content), but the panel and SQL are showing something untrue.
	ProjectionDrift string
}

// Self and Peer return this node's and the peer's rows. peer_listen_* is unambiguous: it is where the node of
// THAT row listens. Our row tells us where to listen, the peer's row where to connect.
func (c EffectiveConfig) Self(nodeID string) (NodeConfig, bool) { return c.find(nodeID, true) }
func (c EffectiveConfig) Peer(nodeID string) (NodeConfig, bool) { return c.find(nodeID, false) }

func (c EffectiveConfig) find(nodeID string, self bool) (NodeConfig, bool) {
	for _, n := range c.Nodes {
		if (n.NodeID == nodeID) == self {
			return n, true
		}
	}
	return NodeConfig{}, false
}

// ErrConfigNotSeeded means there are NO configuration revisions at all: HA is not configured.
//
// A distinct typed error rather than text: it is a FACT, not a read failure, and every caller deciding on it
// must tell the two apart. "Could not read the revision" is unknown and decides nothing; "no revisions" is
// proven absence of a pair, the normal state after dismantling. Substring matching would one day lose that
// difference, silently and exactly where a mistake costs the most.
var ErrConfigNotSeeded = errors.New("config_not_seeded: there is no EFFECTIVE revision")

// LoadEffectiveConfig reads the latest EFFECTIVE revision. SELECT only.
//
// Missing or corrupt canonical content is a REFUSAL, not a reason to "rebuild the config from tables":
// otherwise the node would run on data whose fingerprint it never promised the peer. The fix is recreating
// the pair (§14.6), not guesswork at runtime.
func LoadEffectiveConfig(ctx context.Context, socket, dbName string, timeout time.Duration) (EffectiveConfig, error) {
	var cfg EffectiveConfig
	dsn, err := DSN(socket)
	if err != nil {
		return cfg, err
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return cfg, fmt.Errorf("store_open: %w", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	c, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var blob []byte
	err = db.QueryRowContext(c, "SELECT revision, payload_hash, payload_blob FROM "+dbName+
		".ha_config_revision WHERE status='EFFECTIVE' ORDER BY revision DESC LIMIT 1").Scan(&cfg.Revision, &cfg.PayloadHash, &blob)
	if err == sql.ErrNoRows {
		return cfg, ErrConfigNotSeeded
	}
	if err != nil {
		return cfg, fmt.Errorf("store_query: %w", err)
	}
	payload, err := ParseConfigPayload(blob, cfg.PayloadHash)
	if err != nil {
		return cfg, fmt.Errorf("revision %d: %w", cfg.Revision, err)
	}
	if err := payload.Validate(); err != nil {
		return cfg, fmt.Errorf("revision %d: %w", cfg.Revision, err)
	}
	cfg.Payload = payload
	for _, n := range payload.Nodes {
		nc := NodeConfig{NodeID: n.NodeID, Name: n.Name, Hostname: n.Hostname, Location: n.Location,
			Description: n.Description, PeerListenHost: n.PeerListenHost,
			PeerListenPort: n.PeerListenPort, Enabled: n.Enabled != 0}
		if n.AdminIP != nil {
			nc.AdminIP = *n.AdminIP
		}
		cfg.Nodes = append(cfg.Nodes, nc)
	}

	// The projection is read ONLY to report drift; it does not affect working values.
	cfg.ProjectionDrift = projectionDrift(c, db, dbName, cfg.Revision, payload)

	return cfg, nil
}

// projectionDrift compares normalized node rows with the canonical content. Returns an empty string when the
// projection is correct and a description of the mismatch otherwise.
func projectionDrift(ctx context.Context, db *sql.DB, dbName string, rev int64, p ConfigPayload) string {
	rows, err := db.QueryContext(ctx, "SELECT node_id, COALESCE(peer_listen_host,''), COALESCE(peer_listen_port,0), "+
		"enabled, COALESCE(name,''), COALESCE(hostname,''), COALESCE(location,''), COALESCE(description,'') "+
		"FROM "+dbName+".ha_nodes WHERE revision = ?", rev)
	if err != nil {
		return fmt.Sprintf("the projection was not read: %v", err)
	}
	defer rows.Close()
	got := map[string]string{}
	for rows.Next() {
		var id, host, name, hostname, location, descr string
		var port, enabled int
		if err := rows.Scan(&id, &host, &port, &enabled, &name, &hostname, &location, &descr); err != nil {
			return fmt.Sprintf("the projection was not read: %v", err)
		}
		got[id] = fmt.Sprintf("%s:%d/%d|%s|%s|%s|%s", host, port, enabled, name, hostname, location, descr)
	}
	if err := rows.Err(); err != nil {
		return fmt.Sprintf("the projection was not read: %v", err)
	}
	want := map[string]string{}
	for _, n := range p.Nodes {
		want[n.NodeID] = fmt.Sprintf("%s:%d/%d|%s|%s|%s|%s", n.PeerListenHost, n.PeerListenPort, n.Enabled,
			n.Name, n.Hostname, n.Location, n.Description)
	}
	var diff []string
	for id, w := range want {
		if g, ok := got[id]; !ok {
			diff = append(diff, id+": the row is missing")
		} else if g != w {
			diff = append(diff, fmt.Sprintf("%s: %s in the table, %s in the content", id, g, w))
		}
	}
	for id := range got {
		if _, ok := want[id]; !ok {
			diff = append(diff, id+": unexpected extra row")
		}
	}
	sort.Strings(diff)
	return strings.Join(diff, "; ")
}

// PreviousAnycastAddress returns the anycast address of the revision PRECEDING the effective one.
//
// Cleanup needs it: an anycast address lives on loopback permanently and is not removed by withdrawing
// publication, so a new revision just adds a second /32 next to the old one. Only whoever remembers the old
// address can remove it, and the revision table remembers it.
//
// Empty without error is a normal answer: no previous revision (pair just created) or it had no address.
// A read error also yields "nothing to clean": cleanup is not important enough to make convergence declare
// the state unknown, and skipping it breaks nothing since both addresses are up and served.
func PreviousAnycastAddress(ctx context.Context, socket, dbName string, current int64, timeout time.Duration) string {
	addrs := FormerAnycastAddresses(ctx, socket, dbName, current, timeout)
	if len(addrs) == 0 {
		return ""
	}
	return addrs[0]
}

// FormerAnycastAddresses returns ALL anycast addresses from past revisions other than the effective one.
//
// Looking only at the immediately previous revision is not enough, and this is not theoretical:
//
//	rev1  A     rev2  B (A not yet removed)     rev3  B, only the port changed
//
// At rev3 the previous revision has the same B, "nothing to clean", and A stays on loopback FOREVER, because
// the next revision pushed it out of sight. The node would keep answering on an address that has been absent
// from the pair config twice over.
//
// A read error yields an empty list: cleanup is not important enough to make convergence declare the state
// unknown, and skipping it breaks nothing since the addresses are up and served.
func FormerAnycastAddresses(ctx context.Context, socket, dbName string, current int64, timeout time.Duration) []string {
	if current <= 1 {
		return nil
	}
	dsn, err := DSN(socket)
	if err != nil {
		return nil
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	c, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// The effective address is excluded: it belongs on loopback.
	var curAddr string
	if ec, err := revisionPayload(c, db, dbName, current); err == nil {
		curAddr, _ = ec.PublicationTarget()
	}

	// Only revisions that were EFFECTIVE: a REJECTED one, or a STAGED one never committed, never had its address
	// brought up, so it is not "past". No practical harm (we only remove what is really on loopback), but what
	// we look for is the trace of previous operation.
	rows, err := db.QueryContext(c, "SELECT payload_hash, payload_blob FROM "+dbName+
		".ha_config_revision WHERE revision < ? AND status='EFFECTIVE' ORDER BY revision DESC", current)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	seen := map[string]bool{}
	for rows.Next() {
		var blob []byte
		var hash string
		if err := rows.Scan(&hash, &blob); err != nil {
			return out
		}
		p, err := ParseConfigPayload(blob, hash)
		if err != nil || p.Publication == nil || p.Publication.Provider != ProviderAnycast {
			continue
		}
		addr, _ := p.PublicationTarget()
		if addr == "" || addr == curAddr || seen[addr] {
			continue
		}
		seen[addr] = true
		out = append(out, addr)
	}
	return out
}

// revisionPayload returns the canonical content of a SPECIFIC revision.
func revisionPayload(ctx context.Context, db *sql.DB, dbName string, rev int64) (ConfigPayload, error) {
	var blob []byte
	var hash string
	if err := db.QueryRowContext(ctx, "SELECT payload_hash, payload_blob FROM "+dbName+
		".ha_config_revision WHERE revision=?", rev).Scan(&hash, &blob); err != nil {
		return ConfigPayload{}, err
	}
	return ParseConfigPayload(blob, hash)
}
