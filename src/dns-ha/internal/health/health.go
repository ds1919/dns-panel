// Package health classifies one observe.Observation into two independent verdicts (DOCS/23-ha-manager.md §12):
//
//	service_ready — may this node receive traffic (read by the anycast/LB probe);
//	ha_healthy    — is the HA machinery correctly armed (read by the panel and alerts).
//
// They must not be mixed: failing the probe over redundancy problems (peer down, config drift, epoch
// mismatch) would pull a working DNS node out of traffic.
//
// Health is a classification, not a source of truth: the planner works on the Observation directly and must
// never choose a role based on the coarse ha_healthy summary.
package health

import (
	"fmt"
	"strings"

	"dnspanel/dns-ha/internal/observe"
	"dnspanel/dns-ha/internal/safety"
	"dnspanel/dns-ha/internal/store"
)

// State is a three-valued check result. Unknown ("could not observe") is deliberately distinct from Fail
// ("observed and bad"); fail-closed behaviour relies on that distinction.
type State string

const (
	OK      State = "ok"
	Fail    State = "fail"
	Unknown State = "unknown"
)

type Check struct {
	Name   string `json:"name"`
	State  State  `json:"state"`
	Detail string `json:"detail,omitempty"`
}

type Verdict struct {
	NodeID       string  `json:"node_id"`
	Role         string  `json:"role"` // active | standby | unknown — the observed role, not the desired one
	ServiceReady bool    `json:"service_ready"`
	HAHealthy    bool    `json:"ha_healthy"`
	Reason       string  `json:"reason,omitempty"`
	Service      []Check `json:"service_checks"`
	HA           []Check `json:"ha_checks"`
}

// Evaluate is a pure function from an observation to a verdict.
func Evaluate(o observe.Observation) Verdict {
	v := Verdict{NodeID: o.NodeID, Role: role(o)}

	// service_ready: only evidence about this node's own role.
	agent := Check{Name: "agent", State: OK}
	if !o.Local.AgentOK {
		agent = Check{Name: "agent", State: Fail, Detail: orDefault(o.Local.AgentError, "agent does not answer")}
	}
	v.Service = append(v.Service, agent)

	writable := Check{Name: "writable", State: Unknown, Detail: "read_only not observed"}
	if o.Local.ReadOnly != nil {
		if *o.Local.ReadOnly == 0 {
			writable = Check{Name: "writable", State: OK}
		} else {
			writable = Check{Name: "writable", State: Fail, Detail: "MariaDB read_only=1 (node refuses writes)"}
		}
	}
	v.Service = append(v.Service, writable)
	v.Service = append(v.Service, flagCheck("pdns_primary", o.Local.NotifierOn, "PowerDNS is not in the primary role"))
	v.Service = append(v.Service, secondaryServiceCheck(o, v.Role))
	v.Service = append(v.Service, flagCheck("published", o.Local.RouteAnnounced, "publication is not confirmed"))
	v.Service = append(v.Service, serviceAddressCheck(o))

	// A node in the middle of a switchover is not ready for traffic.
	frozen := Check{Name: "not_frozen", State: OK}
	if o.Local.CurrentOperationID != "" {
		frozen = Check{Name: "not_frozen", State: Fail, Detail: "HA operation in progress: " + o.Local.CurrentOperationID}
	}
	v.Service = append(v.Service, frozen)

	// Right vs physics is an independent split-brain detector (§3.4): a node accepting writes without the
	// right to be ACTIVE is dangerous whatever it believes about itself.
	if o.Local.ReadOnly != nil {
		if o.IsActive() != (*o.Local.ReadOnly == 0) {
			v.Service = append(v.Service, Check{Name: "role_vs_physics", State: Fail,
				Detail: fmt.Sprintf("right to be ACTIVE: %s, read_only=%d — right and physics disagree",
					o.Safety.Authority.State, *o.Local.ReadOnly)})
		} else {
			v.Service = append(v.Service, Check{Name: "role_vs_physics", State: OK})
		}
	} else {
		v.Service = append(v.Service, Check{Name: "role_vs_physics", State: Unknown,
			Detail: "physical state not observed"})
	}

	// Only ACTIVE needs proof of its right; being read-only is safe by itself.
	if v.Role != "active" {
		v.Service = append(v.Service, Check{Name: "active_authority", State: OK, Detail: "STANDBY needs no right"})
	} else {
		switch o.Safety.Authority.State {
		case safety.AuthValidCurrent:
			v.Service = append(v.Service, Check{Name: "active_authority", State: OK, Detail: "type " + o.Safety.Authority.Type})
		case safety.AuthUnknown, "":
			v.Service = append(v.Service, Check{Name: "active_authority", State: Unknown,
				Detail: orDefault(o.Safety.Authority.Detail, "proof not read")})
		default:
			v.Service = append(v.Service, Check{Name: "active_authority", State: Fail,
				Detail: o.Safety.Authority.State + ": " + orDefault(o.Safety.Authority.Detail, "right to be ACTIVE not proven")})
		}
	}

	if v.Role == "standby" {
		// Not taking traffic is the correct STANDBY state, not a failure.
		v.ServiceReady = false
		v.Reason = "node is STANDBY — it does not take traffic"
	} else {
		v.ServiceReady = allOK(v.Service)
		if !v.ServiceReady {
			v.Reason = firstProblem(v.Service)
		}
	}

	// ha_healthy: is the HA machinery armed.
	v.HA = append(v.HA, prereqCheck(o))
	v.HA = append(v.HA, storeCheck(o))
	v.HA = append(v.HA, safetyCheck(o))
	v.HA = append(v.HA, peerCheck(o))
	v.HA = append(v.HA, epochCheck(o))
	v.HA = append(v.HA, safetyEpochConsistencyCheck(o))
	v.HA = append(v.HA, peerFreshnessCheck(o))
	v.HA = append(v.HA, configAgreementCheck(o), configProjectionCheck(o), preflightCheck(o))
	v.HA = append(v.HA, replicationCheck(o))
	v.HA = append(v.HA, fencedCheck(o))
	v.HA = append(v.HA, staleAnycastCheck(o))
	v.HA = append(v.HA, pdnsRoleCheck(o, v.Role))
	v.HA = append(v.HA, agent)

	v.HAHealthy = allOK(v.HA)
	return v
}

// role derives the node role from its right to be ACTIVE. An unread safety store yields "unknown", not
// "standby": a safe-looking default would hide that the node does not know its own state.
func role(o observe.Observation) string {
	if o.Safety.Authority.State == safety.AuthUnknown {
		return "unknown"
	}
	if o.IsActive() {
		return "active"
	}
	return "standby"
}

func prereqCheck(o observe.Observation) Check {
	if len(o.Prereqs) == 0 {
		return Check{Name: "mysql_prerequisites", State: Unknown,
			Detail: orDefault(o.PrereqError, "persisted config not read")}
	}
	var drift []string
	for _, p := range o.Prereqs {
		if !p.OK {
			got := p.GotString()
			if got == "" {
				got = "unset"
			}
			drift = append(drift, fmt.Sprintf("%s: want %s, got %s", p.Option, p.Want, got))
		}
	}
	if len(drift) > 0 {
		return Check{Name: "mysql_prerequisites", State: Fail, Detail: "mysql_prerequisite_drift: " + join(drift)}
	}
	return Check{Name: "mysql_prerequisites", State: OK}
}

func storeCheck(o observe.Observation) Check {
	switch {
	case !o.Config.StoreReachable:
		return Check{Name: "store", State: Fail, Detail: orDefault(o.Config.StoreError, "local database unavailable")}
	case !o.Config.SchemaValid:
		return Check{Name: "store", State: Fail, Detail: orDefault(o.Config.StoreError, "dns_ha schema incomplete")}
	case !o.Config.Loaded:
		return Check{Name: "store", State: Fail, Detail: orDefault(o.Config.Error, "pair configuration not read")}
	}
	return Check{Name: "store", State: OK}
}

func safetyCheck(o observe.Observation) Check {
	switch {
	case !o.Safety.Present:
		return Check{Name: "safety_store", State: Fail, Detail: orDefault(o.Safety.Error, "safety store missing")}
	case !o.Safety.Valid:
		return Check{Name: "safety_store", State: Fail, Detail: orDefault(o.Safety.Error, "safety store invalid")}
	}
	return Check{Name: "safety_store", State: OK}
}

func peerCheck(o observe.Observation) Check {
	if !o.Peer.Reachable {
		if o.Peer.Error == "" && o.Config.PeerListen == "" {
			return Check{Name: "peer_reachable", State: Unknown, Detail: "peer contour not started"}
		}
		return Check{Name: "peer_reachable", State: Fail,
			Detail: orDefault(o.Peer.Error, "peer unreachable — no redundancy")}
	}
	detail := "peer " + o.Peer.NodeID
	if o.Peer.Role != "" {
		detail += " (" + o.Peer.Role + ")"
	}
	return Check{Name: "peer_reachable", State: OK, Detail: detail}
}

// epochCheck is separate from peer_reachable: the peer can be reachable and correctly signed while its
// state is unusable for decisions, and folding that into "unreachable" would lose the cause.
func epochCheck(o observe.Observation) Check {
	local, remote := o.Safety.MaxSeenEpoch, o.Peer.MaxSeenEpoch
	switch {
	case !o.Peer.Reachable:
		return Check{Name: "peer_epoch", State: Unknown, Detail: "peer state not received"}
	case local == nil || remote == nil:
		return Check{Name: "peer_epoch", State: Unknown, Detail: "epoch unknown on one side"}
	case *remote < *local:
		return Check{Name: "peer_epoch", State: Fail, Detail: fmt.Sprintf(
			"stale_peer_epoch: peer at %d, we are at %d — its state is not a basis for decisions", *remote, *local)}
	case *remote > *local:
		return Check{Name: "peer_epoch", State: Fail, Detail: fmt.Sprintf(
			"local_epoch_behind: peer at %d, we are at %d — HOLD until the new epoch is processed", *remote, *local)}
	}
	return Check{Name: "peer_epoch", State: OK}
}

// safetyEpochConsistencyCheck compares the two durable epoch copies: the manager's safety store and the
// agent's max_epoch. If only the agent's advanced, both nodes would agree on a stale epoch and
// peer_epoch=ok would prove nothing.
func safetyEpochConsistencyCheck(o observe.Observation) Check {
	local, agent := o.Safety.MaxSeenEpoch, o.Local.AgentMaxEpoch
	if local == nil || agent == nil {
		return Check{Name: "safety_epoch_consistency", State: Unknown, Detail: "one of the epochs is unknown"}
	}
	if *agent > *local {
		return Check{Name: "safety_epoch_consistency", State: Fail, Detail: fmt.Sprintf(
			"safety_stale_against_agent: agent saw %d, safety store %d — this state cannot back decisions",
			*agent, *local)}
	}
	return Check{Name: "safety_epoch_consistency", State: OK}
}

// peerFreshnessCheck catches a live peer serving a frozen snapshot (e.g. a stuck observation loop): the
// response is signed with the current time, so without this check stale state would look like fresh proof.
func peerFreshnessCheck(o observe.Observation) Check {
	if !o.Peer.Reachable {
		return Check{Name: "peer_observation_fresh", State: Unknown, Detail: "peer state not received"}
	}
	if o.Peer.ObservedAt == 0 {
		return Check{Name: "peer_observation_fresh", State: Unknown, Detail: "peer did not report snapshot time"}
	}
	age := o.At.Unix() - o.Peer.ObservedAt
	if age < 0 {
		age = -age
	}
	if age > int64(observe.MaxPeerObservationAge.Seconds()) {
		return Check{Name: "peer_observation_fresh", State: Fail, Detail: fmt.Sprintf(
			"peer_state_stale: the peer snapshot is %ds old — not usable as proof", age)}
	}
	return Check{Name: "peer_observation_fresh", State: OK}
}

// configAgreementCheck detects config revision mismatch (§7.3): the role must not be handed to a node
// running a different revision.
func configAgreementCheck(o observe.Observation) Check {
	if !o.Peer.Reachable {
		return Check{Name: "config_agreement", State: Unknown, Detail: "peer configuration not received"}
	}
	if o.Config.Revision == nil || o.Peer.ConfigRevision == nil {
		return Check{Name: "config_agreement", State: Unknown, Detail: "revision unknown on one side"}
	}
	if !o.Config.AgreesWithPeer(o.Peer) {
		return Check{Name: "config_agreement", State: Fail, Detail: fmt.Sprintf(
			"config_commit_unsynced: our revision %d, peer revision %d", *o.Config.Revision, *o.Peer.ConfigRevision)}
	}
	return Check{Name: "config_agreement", State: OK}
}

// preflightCheck reports whether the node's privileged (root) execution path works. It belongs to
// ha_healthy, not service_ready: serving is judged by role, physics and rights, and failing the traffic
// probe over a broken control path would pull a node that answers fine.
func preflightCheck(o observe.Observation) Check {
	p := o.Local.Preflight
	switch {
	case !p.Observed:
		return Check{Name: "agent_preflight", State: Unknown, Detail: orDefault(p.Error, "preflight did not run")}
	case !p.OK:
		return Check{Name: "agent_preflight", State: Fail, Detail: strings.TrimSpace(p.Code + " " + p.Message)}
	}
	return Check{Name: "agent_preflight", State: OK}
}

// configProjectionCheck reports whether the normalized tables match the revision's canonical content.
// It does not affect role choice (the manager uses the fingerprinted content), but drift means the panel
// and SQL show a configuration nobody runs.
func configProjectionCheck(o observe.Observation) Check {
	if !o.Config.Loaded {
		return Check{Name: "config_projection", State: Unknown, Detail: "configuration not read"}
	}
	if o.Config.ProjectionDrift != "" {
		return Check{Name: "config_projection", State: Fail,
			Detail: "config_projection_drift: " + o.Config.ProjectionDrift}
	}
	return Check{Name: "config_projection", State: OK}
}

// replicationCheck reports data replication state: no replica is normal on ACTIVE, a failure on STANDBY.
func replicationCheck(o observe.Observation) Check {
	if !o.Replication.Observed {
		return Check{Name: "replication", State: Unknown,
			Detail: orDefault(o.Replication.Error, "replication status not observed")}
	}
	if o.IsActive() {
		// Running replica threads on ACTIVE would mean circular replication (what skip-slave-start prevents).
		if o.Replication.Configured && (o.Replication.IORunning == "Yes" || o.Replication.SQLRunning == "Yes") {
			return Check{Name: "replication", State: Fail, Detail: fmt.Sprintf(
				"an ACTIVE node must not replicate: IO=%s SQL=%s from %s",
				o.Replication.IORunning, o.Replication.SQLRunning, o.Replication.MasterHost)}
		}
		return Check{Name: "replication", State: OK, Detail: "ACTIVE — threads stopped"}
	}
	if !o.Replication.Configured {
		return Check{Name: "replication", State: Fail, Detail: "STANDBY without configured replication"}
	}
	// IO=Yes SQL=Yes from an unexpected source host is not healthy.
	if src, ok := o.ExpectedReplicationSource(); ok && o.Replication.MasterHost != "" && o.Replication.MasterHost != src {
		return Check{Name: "replication", State: Fail, Detail: fmt.Sprintf(
			"replicating from %s, expected %s", o.Replication.MasterHost, src)}
	}
	if o.Replication.IORunning != "Yes" || o.Replication.SQLRunning != "Yes" {
		d := fmt.Sprintf("IO=%s SQL=%s", o.Replication.IORunning, o.Replication.SQLRunning)
		if o.Replication.LastIOError != "" {
			d += "; " + trim(o.Replication.LastIOError, 120)
		}
		if o.Replication.LastSQLError != "" {
			d += "; " + trim(o.Replication.LastSQLError, 120)
		}
		return Check{Name: "replication", State: Fail, Detail: d}
	}
	d := "from " + o.Replication.MasterHost
	if o.Replication.SecondsBehind != nil {
		d += fmt.Sprintf(", %ds behind", *o.Replication.SecondsBehind)
	}
	return Check{Name: "replication", State: OK, Detail: d}
}

// fencedCheck makes a RESEED_REQUIRED node explicitly visible; it is not mere lag. The authoritative fencing
// source is the safety store (§4.4.1), not the replicated database.
func fencedCheck(o observe.Observation) Check {
	fenced := o.Safety.FencedNode
	if fenced == "" && o.Peer.Reachable {
		fenced = o.Peer.FencedNode
	}
	if fenced == "" {
		return Check{Name: "fenced_node", State: OK}
	}
	if fenced == o.NodeID {
		return Check{Name: "fenced_node", State: Fail, Detail: "THIS node is marked RESEED_REQUIRED"}
	}
	return Check{Name: "fenced_node", State: Fail, Detail: "node " + fenced + " is marked RESEED_REQUIRED"}
}

// secondaryServiceCheck is the secondary half of the PowerDNS role for service_ready. On ACTIVE, secondary=0
// is an incomplete role that convergence fixes by restarting PowerDNS, so the node is not ready: the manager
// closes the probe before converging and the restart happens without traffic. Older agents do not report the
// field; then readiness is unaffected, or deploying the manager first would pull ACTIVE out of traffic.
func secondaryServiceCheck(o observe.Observation, role string) Check {
	if role == "standby" && !o.HANotConfigured() {
		return Check{Name: "pdns_secondary", State: OK, Detail: "not required on STANDBY"}
	}
	if o.Local.SecondaryOn == nil {
		return Check{Name: "pdns_secondary", State: OK, Detail: "not reported by this agent version"}
	}
	if *o.Local.SecondaryOn == 1 {
		return Check{Name: "pdns_secondary", State: OK}
	}
	return Check{Name: "pdns_secondary", State: Fail,
		Detail: "PowerDNS does not pull secondary zones itself (secondary=no) — the role is being completed"}
}

// pdnsRoleCheck checks that the PowerDNS (primary, secondary) mode pair matches the node state: yes/yes on
// ACTIVE and on a node without HA configured, no/no on STANDBY (both modes write to the database, which is a
// read-only replica there). A node without HA has no ACTIVE right and looks like "standby", so it is matched
// first. A mixed pair is an unfinished transition that convergence completes.
func pdnsRoleCheck(o observe.Observation, role string) Check {
	p, s := o.Local.NotifierOn, o.Local.SecondaryOn
	if p == nil || s == nil {
		return Check{Name: "pdns_role", State: Unknown, Detail: "the PowerDNS mode pair is not reported"}
	}
	want, state := -1, ""
	switch {
	case o.HANotConfigured():
		want, state = 1, "a node without HA"
	case role == "active":
		want, state = 1, "ACTIVE"
	case role == "standby":
		want, state = 0, "STANDBY"
	default:
		return Check{Name: "pdns_role", State: Unknown, Detail: "the node role is not known"}
	}
	if *p == want && *s == want {
		return Check{Name: "pdns_role", State: OK}
	}
	return Check{Name: "pdns_role", State: Fail,
		Detail: fmt.Sprintf("PowerDNS primary=%s secondary=%s, but this is %s", yesNo(*p), yesNo(*s), state)}
}

func yesNo(v int) string {
	if v == 1 {
		return "yes"
	}
	return "no"
}

func flagCheck(name string, v *int, failDetail string) Check {
	if v == nil {
		return Check{Name: name, State: Unknown}
	}
	if *v == 1 {
		return Check{Name: name, State: OK}
	}
	return Check{Name: name, State: Fail, Detail: failDetail}
}

// allOK treats Unknown as failure: "could not check" is not "fine".
func allOK(checks []Check) bool {
	for _, c := range checks {
		if c.State != OK {
			return false
		}
	}
	return true
}

func firstProblem(checks []Check) string {
	for _, c := range checks {
		if c.State != OK {
			if c.Detail != "" {
				return c.Name + ": " + c.Detail
			}
			return c.Name + ": " + string(c.State)
		}
	}
	return ""
}

func join(items []string) string {
	out := ""
	for i, s := range items {
		if i > 0 {
			out += "; "
		}
		out += s
	}
	return out
}

func trim(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// staleAnycastCheck reports an anycast address from the previous configuration still on loopback.
// An address change succeeds before convergence removes the old /32, possibly after retries; until then
// the node also answers on an address the pair no longer has. The next cycle retries the cleanup; this
// check only makes a failed cleanup visible.
func staleAnycastCheck(o observe.Observation) Check {
	if !o.Local.StaleAnycastUp || o.Config.PreviousAnycastAddress == "" {
		return Check{Name: "anycast_address", State: OK}
	}
	return Check{Name: "anycast_address", State: Fail,
		Detail: "stale anycast address " + o.Config.PreviousAnycastAddress + " is still present on loopback"}
}

// serviceAddressCheck verifies that DNS accepts connections on the published address. It is a service
// check because the readiness probe promises a working DNS behind the address: in one real case the /32
// was on loopback and everything else was green, but PowerDNS listened only on explicit addresses and
// refused connections.
//
// Anycast only: there the address is on loopback of both nodes, so the local check applies on either side;
// a floating_ip lives only on its current owner and the check would fail a healthy STANDBY.
//
// Only the TCP connect is checked, not a DNS query: readiness must not depend on zone data.
func serviceAddressCheck(o observe.Observation) Check {
	addr, _, provider := o.Config.Payload.PublicationOf(o.NodeID)
	if provider != store.ProviderAnycast || addr == "" {
		return Check{Name: "service_address", State: OK}
	}
	if o.Local.ServiceAddressOK {
		return Check{Name: "service_address", State: OK}
	}
	// Word the detail as exactly what was checked, so nobody goes looking at zones, SOA or UDP.
	detail := "no DNS TCP/53 listener on " + addr
	if o.Local.ServiceAddressError != "" {
		detail += ": " + o.Local.ServiceAddressError
	}
	return Check{Name: "service_address", State: Fail, Detail: detail}
}
