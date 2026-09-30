// Package planner is the HA brain: a pure function from observation to desired role and action.
//
// Plan() only decides; execution is a separate layer that can be enabled piece by piece.
//
// It works on the raw observe.Observation, not the health verdict: ha_healthy is a coarse classification
// and must never drive role changes (§12).
//
// Rule order: first whatever moves the node to safety, only then whatever grants it the right to act.
// Any uncertainty is a refusal (fail-closed).
package planner

import (
	"fmt"

	"dnspanel/dns-ha/internal/observe"
	"dnspanel/dns-ha/internal/safety"
)

type Role string

const (
	RoleActive  Role = "active"
	RoleStandby Role = "standby"
	RoleUnknown Role = "unknown"
)

type Action string

const (
	ActionNoop          Action = "noop"           // state matches the desired one
	ActionRestoreActive Action = "restore_active" // legitimate ACTIVE, but some services are down
	ActionPromote       Action = "promote"        // become ACTIVE (requires proof)
	ActionDemoteSafe    Action = "demote_safe"    // go to the safe state immediately
	ActionRejoin        Action = "rejoin"         // STANDBY: attach replication to the confirmed ACTIVE
	// ActionQuietStandby is a STANDBY left with the notifier on. Not a demotion (the role is fine), just
	// removing what a replica must not have.
	ActionQuietStandby Action = "quiet_standby"
	ActionHold         Action = "hold" // change nothing: not enough evidence
)

// AuthorityRequirement is what must prove an action. Not a bool: the proofs differ, and "migrated" is never "handoff".
type AuthorityRequirement string

const (
	AuthNone                 AuthorityRequirement = "none"                     // safe actions need no proof
	AuthCurrentActive        AuthorityRequirement = "current_active_authority" // stay ACTIVE
	AuthPeerConfirmation     AuthorityRequirement = "peer_confirmation"        // resume the role after losing physical state
	AuthHandoffCertificate   AuthorityRequirement = "handoff_certificate"      // planned switchover
	AuthEmergencyOperatorAck AuthorityRequirement = "emergency_operator_ack"   // emergency promotion
)

// Decision is what the planner decided and why.
type Decision struct {
	DesiredRole       Role                 `json:"desired_role"`
	Action            Action               `json:"action"`
	Reason            string               `json:"reason"`
	AuthorityRequired AuthorityRequirement `json:"authority_required"`
	Detail            string               `json:"detail,omitempty"`
}

// Typed reasons: machine-comparable.
const (
	ReasonFencedSelf         = "fenced_self"
	ReasonPeerNewerEpoch     = "peer_newer_epoch"
	ReasonNoActiveAuthority  = "no_active_authority"
	ReasonHandoffCertificate = "handoff_certificate"
	ReasonStandbyWritable    = "standby_physically_writable"
	ReasonConfirmedActive    = "confirmed_active"
	ReasonServicesDegraded   = "active_services_degraded"
	ReasonNeedConfirmation   = "needs_peer_confirmation"
	ReasonPeerUnconfirmed    = "peer_unconfirmed"
	ReasonReplicationBroken  = "replication_broken"
	ReasonSteadyActive       = "steady_active"
	ReasonSteadyStandby      = "steady_standby"
	ReasonRoleUnknown        = "role_unknown"
	ReasonAgentUnavailable   = "agent_unavailable"
	// ReasonHANotConfigured is not a failure: the node serves on its own. It is the normal end state of
	// dismantling a pair.
	ReasonHANotConfigured = "ha_not_configured"
)

// Plan is the single decision point.
func Plan(o observe.Observation) Decision {
	// (0) Without the agent we know neither physical nor control state: decide and touch nothing.
	if !o.Local.AgentOK || o.Local.ReadOnly == nil {
		return Decision{RoleUnknown, ActionHold, ReasonAgentUnavailable, AuthNone,
			"the physical state of the node is not observed"}
	}
	// (0.1) No HA config means HA is not configured.
	//
	// Pairing and HA are separate levels: nodes may know each other with no pair, which is where dismantling
	// ends. Such a node needs no right to be ACTIVE — there are no roles — and applying pair rules would demand
	// proof of something that does not exist (it used to demote itself forever, so dismantle never finished).
	//
	// A proven absence of a pair differs from an unreadable revision; the latter is still unknown and decides
	// nothing. Observation.HANotConfigured holds that distinction for the whole loop.
	if o.HANotConfigured() {
		if *o.Local.ReadOnly != 0 || (o.Local.NotifierOn != nil && *o.Local.NotifierOn == 0) || isZero(o.Local.SecondaryOn) {
			return Decision{RoleActive, ActionRestoreActive, ReasonHANotConfigured, AuthNone,
				"HA is not configured on this node — it serves on its own"}
		}
		return Decision{RoleActive, ActionNoop, ReasonHANotConfigured, AuthNone,
			"HA is not configured on this node — it serves on its own"}
	}
	writable := *o.Local.ReadOnly == 0
	published := isSet(o.Local.NotifierOn) && isSet(o.Local.RouteAnnounced)
	// Role comes from the right to be ACTIVE, not from a shared DB row: such a row lived in the replicated
	// DB and so became unavailable exactly when it was needed most.
	authValid := o.Safety.Authority.State == safety.AuthValidCurrent
	activeByControl := authValid

	// (1) We are fenced. Unconditional: the operator issued proof of isolation; no local reasoning overrides it.
	if o.Safety.FencedNode == o.NodeID || (o.Peer.Reachable && o.Peer.FencedNode == o.NodeID) {
		if writable || published {
			return Decision{RoleStandby, ActionDemoteSafe, ReasonFencedSelf, AuthNone,
				"node is marked RESEED_REQUIRED — go to the safe state immediately"}
		}
		return Decision{RoleStandby, ActionHold, ReasonFencedSelf, AuthNone,
			"node is marked RESEED_REQUIRED — waiting for a reseed"}
	}

	// (2) The peer proved a newer epoch. Counts even from a stale snapshot: if that epoch ever existed, the
	//     role has moved and staying ACTIVE is dangerous.
	if peerEpochNewer(o) {
		if writable || published {
			return Decision{RoleStandby, ActionDemoteSafe, ReasonPeerNewerEpoch, AuthNone,
				fmt.Sprintf("the other node is at epoch %s, this one at %s", str(o.Peer.MaxSeenEpoch), str(o.Safety.MaxSeenEpoch))}
		}
		return Decision{RoleStandby, ActionHold, ReasonPeerNewerEpoch, AuthNone,
			"waiting until the newer epoch is processed"}
	}

	// (3) Physically dangerous without a valid right to be ACTIVE. An expired proof lands here too:
	//     a previous epoch's right is no right.
	if (writable || published) && !authValid {
		return Decision{RoleStandby, ActionDemoteSafe, ReasonNoActiveAuthority, AuthNone,
			"the node accepts writes or is published, but the right to be ACTIVE is not proven (" + o.Safety.Authority.State + ")"}
	}

	// (4) Control state says STANDBY but the node is physically active, whatever the peer says.
	if !activeByControl && (writable || published) {
		return Decision{RoleStandby, ActionDemoteSafe, ReasonStandbyWritable, AuthNone,
			"control state says STANDBY, but physically the node is writable or published"}
	}

	if activeByControl {
		// (5) Running ACTIVE with a valid right. Peer unavailability does not change the role (§8.3).
		// PowerDNS role is a pair: the zone source also pulls secondary zones from their primary. A disabled
		// secondary half is not a role change but a service to restore (6).
		if writable && published && authValid && !isZero(o.Local.SecondaryOn) {
			return Decision{RoleActive, ActionNoop, ReasonSteadyActive, AuthCurrentActive, ""}
		}
		// (6) Still ACTIVE (DB writable) but some services are down: restore them. The right suffices;
		//     the role does not change.
		if writable && authValid {
			return Decision{RoleActive, ActionRestoreActive, ReasonServicesDegraded, AuthCurrentActive,
				"MariaDB is writable, but PowerDNS or the publication is not confirmed"}
		}
		// (7) Physical state lost (typically a MariaDB restart → read_only=1). This is "become ACTIVE", not
		//     "stay ACTIVE": the pair may have moved via emergency meanwhile, so BOTH proofs are needed —
		//     a valid right AND a fresh peer confirmation. The peer cannot grant a right we lack; without
		//     the right we wait.
		// A handoff certificate permits promotion only while its own operation runs. Demanding peer
		// confirmation then would deadlock: the peer is driving the switchover and confirms nothing.
		//
		// After the operation the certificate remains a right to stay ACTIVE, not a permission to become
		// ACTIVE again. Otherwise a node that lost physical state would promote on an old certificate
		// without learning that the peer took over via emergency — exactly the two-ACTIVEs scenario.
		if authValid && o.Safety.Authority.Type == safety.AuthorityHandoff && o.Local.CurrentOperationID != "" {
			return Decision{RoleActive, ActionPromote, ReasonHandoffCertificate, AuthHandoffCertificate,
				"a handoff certificate for the current epoch was received"}
		}
		if authValid && peerConfirmsUsActive(o) {
			return Decision{RoleActive, ActionPromote, ReasonNeedConfirmation, AuthPeerConfirmation,
				"the other node confirms this node is ACTIVE and stands physically STANDBY"}
		}
		if !authValid {
			return Decision{RoleStandby, ActionHold, ReasonNoActiveAuthority, AuthCurrentActive,
				"becoming ACTIVE without a valid right is refused (" + o.Safety.Authority.State + ")"}
		}
		return Decision{RoleStandby, ActionHold, ReasonPeerUnconfirmed, AuthPeerConfirmation,
			"becoming ACTIVE without a fresh confirmation from the other node is refused"}
	}

	// (8) STANDBY: the only active step is restoring replication, and only to a proven ACTIVE.
	src, haveSrc := o.ExpectedReplicationSource()
	if haveSrc && o.Replication.Observed && !o.Replication.Healthy(src) {
		if peerConfirmedActive(o) {
			return Decision{RoleStandby, ActionRejoin, ReasonReplicationBroken, AuthNone,
				"replication is not healthy and the ACTIVE is confirmed — attaching to " + src}
		}
		return Decision{RoleStandby, ActionHold, ReasonPeerUnconfirmed, AuthNone,
			"replication is not healthy, but the ACTIVE is not confirmed — not attaching blindly"}
	}

	// (9) Steady STANDBY.
	if activeUnknown(o) {
		return Decision{RoleUnknown, ActionHold, ReasonRoleUnknown, AuthNone, "control state was not read"}
	}
	// (9a) A replica must not have the notifier on. After sending NOTIFY, PowerDNS writes notified_serial
	// into the domains table, and a STANDBY DB is read-only: a guaranteed write error on the first
	// replicated zone change. A node that became STANDBY via reseed at pair build used to keep it on
	// (seen live: notifier_on=1 on both sides).
	if isSet(o.Local.NotifierOn) {
		return Decision{RoleStandby, ActionQuietStandby, ReasonSteadyStandby, AuthNone,
			"a replica must not send NOTIFY: it writes notified_serial into a read-only database"}
	}
	// (9b) Same for the secondary half: secondary mode pulls zones and writes AXFR into the read-only
	// replica DB. A mixed pair appears e.g. from secondary=yes in a shared config.
	if isSet(o.Local.SecondaryOn) {
		return Decision{RoleStandby, ActionQuietStandby, ReasonSteadyStandby, AuthNone,
			"a replica must not pull zones itself: secondary mode writes transfers into a read-only database"}
	}
	return Decision{RoleStandby, ActionNoop, ReasonSteadyStandby, AuthNone, ""}
}

// peerEpochNewer reports a peer epoch above ours. Freshness is not required: a newer epoch ever
// existing is reason enough not to consider ourselves ACTIVE.
func peerEpochNewer(o observe.Observation) bool {
	if !o.Peer.Reachable || o.Peer.MaxSeenEpoch == nil || o.Safety.MaxSeenEpoch == nil {
		return false
	}
	return *o.Peer.MaxSeenEpoch > *o.Safety.MaxSeenEpoch
}

// peerConfirmsUsActive: the peer's fresh snapshot confirms we are ACTIVE, it is physically standby,
// epochs and config match, nobody is fenced, no operations run. All together, none alone.
func peerConfirmsUsActive(o observe.Observation) bool {
	if !peerEvidenceUsable(o) {
		return false
	}
	// The peer must be physically standby: three fields explicitly, missing ≠ off.
	return o.Peer.PhysicallyStandby() && o.Peer.Role == "standby"
}

// peerConfirmedActive: the peer's fresh snapshot confirms the peer is ACTIVE (for rejoin).
func peerConfirmedActive(o observe.Observation) bool {
	if !peerEvidenceUsable(o) {
		return false
	}
	if _, ok := o.ExpectedReplicationSource(); !ok {
		return false // nowhere to attach
	}
	return o.Peer.Role == "active" && isZero(o.Peer.ReadOnly) && isSet(o.Peer.NotifierOn)
}

// peerEvidenceUsable holds the common conditions for the peer's state to count as proof.
// A stale snapshot is no proof: things may have changed since.
func peerEvidenceUsable(o observe.Observation) bool {
	if !o.Peer.Reachable || o.Peer.Stale {
		return false
	}
	if o.Peer.FencedNode != "" {
		return false // someone in the pair is fenced: not a steady state
	}
	if o.Peer.CurrentOperationID != "" {
		return false // an operation is running
	}
	if o.Safety.MaxSeenEpoch == nil || o.Peer.MaxSeenEpoch == nil || *o.Peer.MaxSeenEpoch != *o.Safety.MaxSeenEpoch {
		return false // epochs must match
	}
	return o.Config.AgreesWithPeer(o.Peer) // configs must match (§7.3)
}

// activeUnknown: the right to be ACTIVE is not observed at all (safety file unread). Not "we are STANDBY"
// but "we don't know who we are": only waiting is allowed.
func activeUnknown(o observe.Observation) bool { return o.Safety.Authority.State == safety.AuthUnknown }

func isSet(v *int) bool  { return v != nil && *v == 1 }
func isZero(v *int) bool { return v != nil && *v == 0 }

func str(v *int64) string {
	if v == nil {
		return "?"
	}
	return fmt.Sprintf("%d", *v)
}
