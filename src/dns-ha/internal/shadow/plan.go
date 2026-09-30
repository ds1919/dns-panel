// Package shadow turns a planner decision into an exact plan of agent primitives.
//
// It is a pure function `(Decision, Observation) → MutationPlan`: no sockets, DB, time or randomness.
// The point is to make "what we would do" visible before we have the right to do it: the plan can be
// printed in status and inspected step by step without touching anything.
//
// Deliberately absent: operation_id, retries, timeouts, per-step error handling — those belong to the executor.
package shadow

import (
	"dnspanel/dns-ha/internal/observe"
	"dnspanel/dns-ha/internal/planner"
	"dnspanel/dns-ha/internal/store"
)

// Agent primitives. Names must match exactly what dns-ha-agent executes: the plan must run as is.
const (
	CmdPromote         = "promote"
	CmdDemote          = "demote"
	CmdEnableNotifier  = "enable_notifier"
	CmdDisableNotifier = "disable_notifier"
	// CmdDropAddress removes a specific address from an interface. Only used to clean up a previous anycast
	// address: anycast addresses live on loopback permanently and are not removed with the publication.
	CmdDropAddress   = "drop_address"
	CmdAnnouncePanel = "announce_panel"
	CmdWithdrawPanel = "withdraw_panel"
	CmdRejoinReplica = "rejoin_replica"
)

// Step is one primitive action. Primary is set only where the agent expects it (rejoin_replica).
type Step struct {
	Command string `json:"command"`
	Primary string `json:"primary,omitempty"`
	// PubAddress/PubDevice are the service address from the active revision. They travel in the step rather
	// than coming from the agent's local file: the pair address lives in replicated config, and two sources
	// would eventually bring up different addresses on the nodes.
	PubAddress string `json:"pub_address,omitempty"`
	PubDevice  string `json:"pub_device,omitempty"`
	// PubProvider is floating_ip or anycast. It decides whether withdrawing removes the address: anycast keeps
	// it on loopback and withdraws by closing the probe.
	PubProvider string `json:"pub_provider,omitempty"`
	Why         string `json:"why,omitempty"` // for humans, not for execution
}

// MutationPlan is what would be done. Rollback is set only for actions whose failure leaves the node
// in a dangerous intermediate state.
type MutationPlan struct {
	Action   planner.Action `json:"action"`
	Steps    []Step         `json:"steps"`
	Rollback []Step         `json:"rollback,omitempty"`
	// StopOnError is a property of the action, not an executor setting. Protective steps all run
	// independently: the node must stop being dangerous by any means, and a failed disable_notifier is no
	// reason to keep the publication. Promoting steps stop at the first failure and roll back: a
	// half-promoted node must not continue.
	StopOnError bool `json:"stop_on_error"`
	// Blocked means an action was chosen but no plan could be built. Empty steps with Blocked set is a
	// lack of data, not "nothing to do".
	Blocked string `json:"blocked,omitempty"`
}

// Empty reports whether the plan has nothing to do.
func (p MutationPlan) Empty() bool { return len(p.Steps) == 0 }

// Build turns a decision into a plan.
func Build(d planner.Decision, o observe.Observation) MutationPlan {
	p := buildSteps(d, o)
	// Fill the publication address once for all publication steps: missing it in one branch would make the
	// node take the address from the revision in one place and from its local file in another.
	addr, dev, provider := o.Config.Payload.PublicationOf(o.NodeID)
	if addr != "" {
		fill := func(steps []Step) {
			for i := range steps {
				if steps[i].Command == CmdAnnouncePanel || steps[i].Command == CmdWithdrawPanel {
					steps[i].PubAddress, steps[i].PubDevice = addr, dev
					steps[i].PubProvider = provider
				}
			}
		}
		fill(p.Steps)
		fill(p.Rollback)
	}
	return p
}

// anycastAddressMissing reports anycast mode with the address absent from loopback.
//
// Based on the agent's observation (anycast_address_up), not the marker: the marker is intent to publish,
// the address itself is role-independent. Unobserved state (agent silent) is no reason to act blindly.
func anycastAddressMissing(o observe.Observation) bool {
	if o.Config.Payload.PublicationProvider() != store.ProviderAnycast {
		return false
	}
	addr, _ := o.Config.Payload.PublicationTarget()
	if addr == "" {
		return false
	}
	return o.Local.AnycastAddressUp != nil && *o.Local.AnycastAddressUp == 0
}

// staleAnycastAddress returns a previous-revision anycast address still up on loopback, or "".
func staleAnycastAddress(o observe.Observation) string {
	if o.Config.Payload.Publication == nil || o.Config.Payload.Publication.Provider != store.ProviderAnycast {
		return ""
	}
	prev := o.Config.PreviousAnycastAddress
	if prev == "" {
		return ""
	}
	if cur, _ := o.Config.Payload.PublicationTarget(); cur == prev {
		return ""
	}
	// Whether it is up right now comes from the agent's observation.
	if !o.Local.StaleAnycastUp {
		return ""
	}
	return prev
}

func buildSteps(d planner.Decision, o observe.Observation) MutationPlan {
	p := MutationPlan{Action: d.Action}
	switch d.Action {
	case planner.ActionNoop, planner.ActionHold:
		// Steady state means zero actions: commands go out only when observation proves divergence.
		//
		// Exception: the anycast /32 on loopback. It is not a role marker — both nodes hold it permanently.
		// Once lost (reboot, manual edit) nothing would restore it, since a calm STANDBY stays in noop for
		// months. withdraw_panel restores it: for anycast it brings up the address without publishing.
		if anycastAddressMissing(o) {
			p.Steps = append(p.Steps, Step{Command: CmdWithdrawPanel,
				Why: "the anycast address is not up on loopback"})
		}
		// Second exception of the same kind: the old anycast address after a service address change.
		// It stays on loopback next to the new /32, so the node keeps answering on an address the pair no
		// longer has. Each node cleans up itself from the previous revision in its own table: the step is
		// idempotent, failure is harmless (both addresses up), and the next cycle retries.
		if stale := staleAnycastAddress(o); stale != "" {
			p.Steps = append(p.Steps, Step{Command: CmdDropAddress, PubAddress: stale,
				PubDevice: store.AnycastDevice, PubProvider: store.ProviderAnycast,
				Why: "the previous anycast address is still up on loopback"})
		}
		return p

	case planner.ActionQuietStandby:
		// Exactly one step; this is not demote_safe. Role, replication and publication are fine —
		// only NOTIFY, which a replica must not send, is removed.
		p.Steps = []Step{{Command: CmdDisableNotifier, Why: "a replica must not send NOTIFY"}}
		return p

	case planner.ActionDemoteSafe:
		// All three steps always, even if observation says some are already off: it may be stale, and a
		// redundant disable_notifier costs nothing next to a leftover publication.
		p.Steps = []Step{
			{Command: CmdDisableNotifier, Why: "stop being the source of zones"},
			{Command: CmdWithdrawPanel, Why: "withdraw the publication"},
			{Command: CmdDemote, Why: "return the node to read-only"},
		}
		return p

	case planner.ActionRestoreActive:
		// Already the legitimate ACTIVE: restore only what is missing. No promote here — "stay ACTIVE" and
		// "become ACTIVE" need different proofs (§8.3). A node without HA config must accept writes: there
		// are no roles, and read-only is just a trace of a dismantled pair.
		if o.HANotConfigured() && o.Local.ReadOnly != nil && *o.Local.ReadOnly != 0 {
			p.Steps = append(p.Steps, Step{Command: CmdPromote, Why: "HA is not configured — the node must accept writes"})
		}
		// PowerDNS role is set as a pair (primary+secondary) by one command; check the secondary half only
		// if the agent reports it — older agents lack the field and the command would be a no-op.
		if isOff(o.Local.NotifierOn) || (o.Local.SecondaryOn != nil && *o.Local.SecondaryOn == 0) {
			p.Steps = append(p.Steps, Step{Command: CmdEnableNotifier, Why: "PowerDNS is not in the primary role"})
		}
		// Publish only when a pair exists: a node without HA config has no pair service address.
		if isOff(o.Local.RouteAnnounced) && !o.HANotConfigured() {
			p.Steps = append(p.Steps, Step{Command: CmdAnnouncePanel, Why: "the publication is not confirmed"})
		}
		return p

	case planner.ActionPromote:
		p.StopOnError = true
		p.Steps = []Step{
			{Command: CmdPromote, Why: "become the write source"},
			{Command: CmdEnableNotifier, Why: "put PowerDNS into the primary role"},
			{Command: CmdAnnouncePanel, Why: "announce the node"},
		}
		// Roll back in reverse, toward safety: an aborted promotion leaves the node writable and possibly
		// announced — exactly the split-brain state.
		p.Rollback = []Step{
			{Command: CmdWithdrawPanel, Why: "withdraw the announcement"},
			{Command: CmdDisableNotifier, Why: "stop serving zones"},
			{Command: CmdDemote, Why: "return to read-only"},
		}
		return p

	case planner.ActionRejoin:
		// Rejoin only a proven ACTIVE, using the address from that node's config. Guessing "probably the
		// peer" would mean replicating from the wrong source.
		host, ok := replicationSource(o)
		if !ok {
			p.Blocked = "the replication address of the confirmed ACTIVE is unknown"
			return p
		}
		p.StopOnError = true
		p.Steps = []Step{{Command: CmdRejoinReplica, Primary: host, Why: "attach replication to the confirmed ACTIVE"}}
		return p
	}
	p.Blocked = "unknown action " + string(d.Action)
	return p
}

// replicationSource is where to attach replication. Shared with planner and health
// (observe.ExpectedReplicationSource) so the decision and the connection agree on the source.
func replicationSource(o observe.Observation) (string, bool) {
	if o.Peer.NodeID == "" || !o.Peer.Reachable {
		return "", false // ACTIVE not confirmed: no plan
	}
	return o.ExpectedReplicationSource()
}

func isOff(v *int) bool { return v == nil || *v == 0 }
