// Package peer is the manager<->manager protocol between the two nodes of a pair (DOCS/23-ha-manager.md §6),
// on port 7901.
//
// This is v1 of our own protocol, not compatibility with the Perl implementation. Perl serves as an oracle of
// BEHAVIOR (which decision is made in a given state), not as a wire format to inherit; otherwise we would
// rebuild the old architecture inside the new one.
package peer

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// Version is the protocol version. Checked explicitly: pair nodes are upgraded at different times, and
// "let's try to make sense of it" is not acceptable here.
const Version = 1

// Read-only commands.
const (
	CmdHello  = "hello"  // negotiation: version, identity, capabilities, max_seen_epoch
	CmdStatus = "status" // observed node state
	// CmdInventory: what the peer has in the transferable databases. Needed exactly at pair creation: the
	// human picks whose data survives and must see both sides, not just their own (§14.6).
	CmdInventory = "inventory"
	// CmdOperationJournal: the operation journal on the node that EXECUTED it. Local dns_ha is not
	// replicated, so switchover steps exist only on the source: after the service address moves, another node
	// serves the panel, and without this request the human would see an empty console.
	CmdOperationJournal = "operation_journal"
)

// INITIALIZATION (pair creation) commands. Kept apart from pair mutations on purpose: mutations have an epoch,
// a durable registry and a gate, while here there is no pair yet (no epoch, revision or roles). Their
// protection is different: they are accepted only while the node has no effective revision, and each has its
// own idempotency (secrets by content, reseed by the agent's operation_id, revision by fingerprint).
const (
	CmdInitPrepare = "init_prepare"
	CmdInitReseed  = "init_reseed"
	CmdInitFinish  = "init_finish"
	CmdInitSeed    = "init_seed"
	CmdInitDevice  = "init_device"
	CmdInitRecap   = "init_recap"
	CmdInitCheck   = "init_check"
)

// InitCommands is the same list, for membership checks.
var InitCommands = map[string]bool{
	CmdInitPrepare: true, CmdInitReseed: true, CmdInitFinish: true, CmdInitSeed: true,
	CmdInitDevice: true, CmdInitRecap: true, CmdInitCheck: true,
}

// IsInit reports whether cmd belongs to pair creation.
func IsInit(cmd string) bool { return InitCommands[cmd] }

var allowedCommands = map[string]bool{
	CmdHello: true, CmdStatus: true, CmdInventory: true, CmdOperationJournal: true,
	CmdInitPrepare: true, CmdInitReseed: true, CmdInitFinish: true, CmdInitSeed: true, CmdInitDevice: true,
	CmdInitRecap: true, CmdInitCheck: true,
	CmdConfigStage: true, CmdConfigCommit: true,
	CmdPrepareSwitchover: true, CmdAwaitGTID: true, CmdHandoffCertificate: true,
	CmdClearFencing: true,
	CmdReleasePair:  true,
}

// Configuration revision protocol commands (§7.2). There is no separate "ack" message: the acknowledgement is
// the signed RESPONSE bound to the request's message_id and nonce. A reverse request for the ack would double
// the protocol surface for something the transport already guarantees.
const (
	CmdConfigStage  = "config_stage"  // store the revision as staged (full payload)
	CmdConfigCommit = "config_commit" // make the staged revision effective

	// Planned switchover commands. The source drives it; the target answers three questions: ready to take
	// the role, applied all source data, accepts the right to be active.
	CmdPrepareSwitchover  = "prepare_switchover"
	CmdAwaitGTID          = "await_gtid"
	CmdHandoffCertificate = "handoff_certificate"

	// CmdReleasePair: dismantle on the peer side: it stops replication, drops fail-safe, becomes writable,
	// removes the service address and its pair records. ONE command on purpose: a separate "forget the pair" would
	// ask to delete the channel and confirm the deletion over that same channel. Trust between machines is left
	// alone: that has its own action.
	CmdReleasePair = "release_pair"

	// CmdClearFencing lifts fencing from a repaired node. It is lifted by WHOEVER SET IT: a node declared
	// unsafe cannot decide by itself that it is fine again.
	CmdClearFencing = "clear_fencing"
)

// MutatingCommands change state. They require durable deduplication (ledger), an epoch check and a
// permitting gate.
var MutatingCommands = map[string]bool{
	CmdConfigStage:  true,
	CmdConfigCommit: true,
	// prepare_switchover changes nothing itself but goes through the same path: it reserves the running
	// operation on the target, and a retry must not create a second one.
	CmdPrepareSwitchover:  true,
	CmdAwaitGTID:          true,
	CmdHandoffCertificate: true,
	CmdClearFencing:       true,
	// Dismantling changes the peer's state no less than a switchover (stops replication, drops fail-safe,
	// makes the node writable, wipes pair records), so it must use the same path: durable dedup, epoch, gate.
	// Without this the client rejected it before sending ("a persistent message_id only makes sense for
	// mutations"), and dismantle failed at the first step towards the peer.
	CmdReleasePair: true,
}

// IsMutating reports whether cmd changes the recipient's state.
func IsMutating(cmd string) bool { return MutatingCommands[cmd] }

// RequestHash is a stable fingerprint of a command's MEANING: what, in which epoch, to whom, with what payload.
// Network attributes (ts/nonce) are NOT included, or an honest retry would look like a different action.
func RequestHash(cmd string, epoch int64, recipient, payloadHash string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%d|%s|%s", cmd, epoch, recipient, payloadHash)))
	return hex.EncodeToString(sum[:])
}

// Typed rejections, so the reason is machine-distinguishable rather than log text.
const (
	ErrBadEnvelope   = "peer_bad_envelope"
	ErrBadSignature  = "peer_bad_signature"
	ErrBadRequest    = "peer_bad_request"
	ErrVersion       = "peer_protocol_version"
	ErrIdentity      = "peer_identity_rejected"
	ErrRecipient     = "peer_wrong_recipient"
	ErrTimestamp     = "peer_bad_timestamp"
	ErrReplay        = "peer_replay"
	ErrCommand       = "peer_command_not_allowed"
	ErrPayloadHash   = "peer_payload_hash_mismatch"
	ErrTooLarge      = "peer_message_too_large"
	ErrIDConflict    = "peer_message_id_conflict"  // same message_id, DIFFERENT command content
	ErrEpoch         = "peer_epoch_mismatch"       // sender's epoch does not match ours
	ErrNotAllowedNow = "peer_mutation_not_allowed" // state not calm: fencing/operation/wrong ACTIVE
	ErrLedger        = "peer_ledger_unavailable"   // durable dedup unavailable -> mutation not executed
	// ErrNoGate: the node was built without a mutation permission check. A distinct code rather than
	// "unknown error": it is a build/init defect and must be visible as such.
	ErrNoGate         = "peer_mutation_gate_unavailable"
	ErrResponseIdent  = "peer_response_identity"
	ErrResponseBind   = "peer_response_binding"
	ErrResponseStale  = "peer_response_stale"
	ErrResponseBadSig = "peer_response_bad_signature"
	ErrInventory      = "peer_inventory_unavailable" // inventory not taken: an empty one must not be shown
	ErrJournal        = "peer_journal_unavailable"   // peer's operation journal not read
	ErrNoInit         = "peer_init_unavailable"      // node cannot create pairs (init path not wired)
	ErrUnreachable    = "peer_unreachable"
	ErrTimeout        = "peer_timeout"
)

// Request is the request body. It is signed as the EXACT serialized bytes (see envelope.go).
//
// The split of identifiers matters for mutations:
//   - message_id identifies the LOGICAL action and is KEPT across attempts: a retry with the same id must
//     return the same result, not run the operation twice;
//   - nonce, ts identify one NETWORK attempt and are fresh each time, otherwise a retry after a break and a
//     pause would hit a stale ts and become impossible;
//   - request_hash is a stable fingerprint of the command's MEANING (cmd+epoch+recipient+payload); it tells
//     an honest retry from content swapped under the same message_id.
type Request struct {
	ProtocolVersion int             `json:"protocol_version"`
	MessageID       string          `json:"message_id"` // logical action; survives retries
	SenderNodeID    string          `json:"sender_node_id"`
	RecipientNodeID string          `json:"recipient_node_id"` // guards against delivery to the wrong node
	Epoch           int64           `json:"epoch"`             // sender's max_seen_epoch (monotonicity backstop)
	TS              int64           `json:"ts"`
	Nonce           string          `json:"nonce"`
	Cmd             string          `json:"cmd"`
	Payload         json.RawMessage `json:"payload,omitempty"`
	PayloadHash     string          `json:"payload_hash"`           // separate from the signature: proves both sides mean the same thing
	RequestHash     string          `json:"request_hash,omitempty"` // fingerprint of the command's meaning (required for mutations)
}

// Response is the response body. It is bound to the request, or an old signed response could be replayed
// (exactly the bug found in the Perl implementation: replaying `status` with the source still read_only led
// to a promote).
type Response struct {
	ProtocolVersion  int             `json:"protocol_version"`
	SenderNodeID     string          `json:"sender_node_id"`
	RecipientNodeID  string          `json:"recipient_node_id"`
	RequestMessageID string          `json:"request_message_id"`
	RequestNonce     string          `json:"request_nonce"`
	TS               int64           `json:"ts"`
	Nonce            string          `json:"nonce"`
	OK               bool            `json:"ok"`
	Error            string          `json:"error,omitempty"`
	Payload          json.RawMessage `json:"payload,omitempty"`
	PayloadHash      string          `json:"payload_hash"`
}

// HelloPayload is the reply to `hello`.
type HelloPayload struct {
	NodeID          string   `json:"node_id"`
	ProtocolVersion int      `json:"protocol_version"`
	Capabilities    []string `json:"capabilities"`
	MaxSeenEpoch    *int64   `json:"max_seen_epoch"` // nil = safety store unavailable/invalid (not zero!)
}

// StatusPayload is the reply to `status`: the node's observed state as seen by ITS manager.
type StatusPayload struct {
	NodeID string `json:"node_id"`
	// Hostname is the node's name in the OPERATING SYSTEM right now. An observation, not a setting: a
	// snapshot taken at pair creation goes stale silently, and the panel shows this field to the human.
	Hostname string `json:"hostname,omitempty"`
	IPDevice string `json:"ip_device,omitempty"`
	IPCIDR   string `json:"ip_cidr,omitempty"`
	// ProbeOpenPort is the probe port ACTUALLY open on the peer; zero means none. A node knows its own
	// probe; the peer's is known only from here, otherwise the panel would just guess for the second card.
	ProbeOpenPort int    `json:"probe_open_port,omitempty"`
	Role          string `json:"role"`
	ServiceReady  bool   `json:"service_ready"`
	HAHealthy     bool   `json:"ha_healthy"`
	MaxSeenEpoch  *int64 `json:"max_seen_epoch"`
	// CurrentOperationID/FencedNode: without them the planner would not see a running operation and could
	// not tell "peer merely behind on epoch" from "I was explicitly marked as needing a reseed".
	CurrentOperationID string `json:"current_operation_id,omitempty"`
	FencedNode         string `json:"fenced_node,omitempty"`
	ConfigRevision     *int64 `json:"config_revision"`
	ConfigHash         string `json:"config_hash"`
	ObservedAt         int64  `json:"observed_at"` // when the snapshot was taken (is the watch loop alive?)
	ReadOnly           *int   `json:"read_only"`
	NotifierOn         *int   `json:"notifier_on"`
	RouteAnnounced     *int   `json:"route_announced"`
	PDNSVersion        string `json:"pdns_version,omitempty"` // display only; absent from an older peer
}

// ConfigStagePayload is the `config_stage` body. The content travels IN FULL and in the exact bytes whose
// fingerprint is declared: the recipient must be able to prove the very same revision, not a similar one.
type ConfigStagePayload struct {
	Revision    int64  `json:"revision"`
	PayloadHash string `json:"payload_hash"`
	PayloadBlob []byte `json:"payload_blob"`
}

// ConfigCommitPayload is the `config_commit` body. No content on purpose: only what is already staged and
// proven gets committed, not whatever arrived with the command.
type ConfigCommitPayload struct {
	Revision    int64  `json:"revision"`
	PayloadHash string `json:"payload_hash"`
}

// SwitchoverPreparePayload asks "are you ready to take the role in epoch N".
type SwitchoverPreparePayload struct {
	OperationID string `json:"operation_id"`
	Epoch       int64  `json:"epoch"`
	ConfigHash  string `json:"config_hash"`
}

// AwaitGTIDPayload asks "apply everything up to this position and confirm".
type AwaitGTIDPayload struct {
	OperationID    string `json:"operation_id"`
	Position       string `json:"position"`
	TimeoutSeconds int    `json:"timeout_seconds"`
}

// DismantlePayload is a dismantle step on the peer.
type DismantlePayload struct {
	OperationID string `json:"operation_id"`
	// Address/Device: the pair's service address as the REVISION has it. The peer removes exactly that:
	// its local config may lag, and the address to disappear is the one the pair published.
	Address string `json:"address,omitempty"`
	Device  string `json:"device,omitempty"`
}

// HandoffPayload is the role handoff certificate.
type HandoffPayload struct {
	OperationID string `json:"operation_id"`
	Epoch       int64  `json:"epoch"`
	From        string `json:"from"`
	ConfigHash  string `json:"config_hash"`
	// RequestedBy is WHO asked for the switchover. Only the initiator knows: the receiver has no record of
	// it and used to fill in the source node, so history said "requested by EQ DNS" although that node only
	// executed it and a human asked.
	RequestedBy string `json:"requested_by,omitempty"`
}

// ClearFencingPayload asks to lift fencing after a proven reseed.
type ClearFencingPayload struct {
	OperationID string `json:"operation_id"`
	Node        string `json:"node"`
	Epoch       int64  `json:"epoch"`
}

// OpAck is the target's reply to switchover commands. Fields are distinct on purpose: "not ready", "not
// applied" and "not accepted" are different states and must not be merged into one boolean.
type OpAck struct {
	NodeID   string `json:"node_id"`
	Ready    bool   `json:"ready,omitempty"`
	Applied  bool   `json:"applied,omitempty"`
	Accepted bool   `json:"accepted,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

// ConfigAck is the reply to both config commands: what the recipient actually ended up with.
type ConfigAck struct {
	NodeID      string `json:"node_id"`
	Revision    int64  `json:"revision"`
	PayloadHash string `json:"payload_hash"`
	Result      string `json:"result"` // staged | committed | idempotent
}

// PayloadHash is the SHA-256 of the canonical payload. An empty payload hashes the empty string: the field is
// mandatory so "no hash" cannot be confused with "hash matched".
func PayloadHash(raw json.RawMessage) string {
	if len(raw) == 0 {
		sum := sha256.Sum256(nil)
		return hex.EncodeToString(sum[:])
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// marshalPayload serializes the payload and hashes the same bytes.
func marshalPayload(v any) (json.RawMessage, string, error) {
	if v == nil {
		return nil, PayloadHash(nil), nil
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, "", fmt.Errorf("payload: %w", err)
	}
	return raw, PayloadHash(raw), nil
}

// RequiresSameEpoch reports whether cmd runs ONLY in the epoch the recipient sees.
//
// True for configuration: it describes the sides' agreement HERE AND NOW and has no reason to come from another
// epoch. Switchover commands are the opposite: they carry the NEW epoch they exist for, so the general "not
// from the past" rule suffices.
func RequiresSameEpoch(cmd string) bool {
	return cmd == CmdConfigStage || cmd == CmdConfigCommit
}

// AcceptsFromActive reports whether cmd may be accepted even when the recipient considers ITSELF active.
//
// For almost all commands the answer is no: configuration and role handoff are initiated by the current
// ACTIVE, and accepting them while believing ourselves active would record someone else's decisions with two
// active nodes.
//
// The single exception goes the OTHER WAY: lifting fencing is requested by the repaired node and decided by
// the current ACTIVE, the one who set it. Requiring "recipient not active" would make lifting impossible.
func AcceptsFromActive(cmd string) bool { return cmd == CmdClearFencing }

// OperationJournalPayload names the journal being requested.
type OperationJournalPayload struct {
	OperationID string `json:"operation_id"`
}
