package agentd

import (
	"fmt"
)

// Pair DISMANTLE primitives: the node stops being half of a pair and becomes a standalone server again.
//
// Dismantling is a planned operation, not post-crash cleanup, so nothing here is destructive to data: zones,
// records, users and settings stay on both nodes exactly as they were. Only what makes two servers ONE pair
// is removed: replication, the shared service address and the fail-safe that keeps STANDBY read-only.

// StopReplication detaches the node from its source PERMANENTLY rather than pausing it.
//
// `STOP SLAVE` alone would keep the source configured: the node would silently resume replication on the
// next start and keep receiving foreign changes as a standalone server. So the link is removed entirely
// (`RESET SLAVE ALL`) and the result is verified.
func (n *Node) StopReplication() (Response, error) {
	db, err := n.db()
	if err != nil {
		return failResp(err), nil
	}
	// replicaStatus()'s second value means "SHOW succeeded"; whether replication exists is st.Present.
	// Confusing them turns a successful SHOW with no row (proven absence) into "the source survived" — exactly
	// what happened on a live pair: RESET SLAVE ALL worked, yet the step reported empty IO=/SQL= fields.
	st, ok := n.replicaStatus()
	if !ok {
		return failResp(fail("replication_state_unknown",
			"SHOW REPLICA STATUS failed — the replication state is unknown")), nil
	}
	if !st.Present {
		// Already standalone. Idempotency matters: dismantling resumes after interruption.
		return Response{OK: true, Noop: true, Status: map[string]any{"replication": "none"}}, nil
	}
	db.ExecContext(n.ctx(), "STOP SLAVE")
	if _, err := db.ExecContext(n.ctx(), "RESET SLAVE ALL"); err != nil {
		return failResp(fail("reset_slave_failed", err.Error())), nil
	}
	after, ok := n.replicaStatus()
	if !ok {
		return failResp(fail("replication_state_unknown",
			"SHOW REPLICA STATUS failed after RESET SLAVE ALL — the result is unknown")), nil
	}
	if after.Present {
		return failResp(fail("replication_still_configured",
			fmt.Sprintf("the source survived RESET SLAVE ALL: host=%s IO=%s SQL=%s",
				after.MasterHost, after.IORunning, after.SQLRunning))), nil
	}
	return Response{OK: true, Status: map[string]any{"replication": "none"}}, nil
}

// ReleasePublication removes the pair's service address ENTIRELY, regardless of provider.
//
// That is the difference from withdraw_panel. In normal operation an anycast address is never removed — it
// lives on loopback of both nodes, and removing it would refuse traffic the router still sends. On dismantle
// it is the opposite: the shared address no longer exists, and leaving it on loopback would leave two
// independent servers answering on the same address.
func (n *Node) ReleasePublication(address, device string) (Response, error) {
	addr, dev := n.Cfg.Publication.Address, n.Cfg.Publication.Device
	if address != "" && device != "" {
		addr, dev = address, device
	}
	mark := n.markerRoute()
	if addr == "" {
		// The address is managed externally — only drop our own intent to publish.
		if err := n.clearMarker(mark); err != nil {
			return failResp(fail("mark_unlink_failed", err.Error())), nil
		}
		return Response{OK: true, Status: map[string]any{"route_announced": 0}}, nil
	}
	have, err := n.addrPresent(addr, dev)
	if err != nil {
		return failResp(fail("publication_state_unknown", err.Error())), nil
	}
	if have {
		n.run("ip", "addr", "del", addr, "dev", dev)
		got, err := n.addrPresent(addr, dev)
		if err != nil {
			return failResp(fail("publication_state_unknown", err.Error())), nil
		}
		if got {
			return failResp(fail("release_failed",
				fmt.Sprintf("the address %s is still on %s", addr, dev))), nil
		}
	}
	if err := n.clearMarker(mark); err != nil {
		return failResp(fail("mark_unlink_failed", err.Error())), nil
	}
	return Response{OK: true, Noop: !have, Status: map[string]any{
		"route_announced": 0, "publication_address": addr, "publication_device": dev,
	}}, nil
}
