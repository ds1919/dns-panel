package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// PeerKeys manages pair secrets and replication access through the privileged agent.
//
// It is separate from Mutator because the contract differs: mutations need operation_id and cluster_epoch
// of an existing pair, while pairing and pair creation happen BEFORE the pair exists, when there is no epoch
// to give. Each command carries its own guard instead: peer.key is written once and removed only by exact
// fingerprint, secrets are idempotent by content and only under known names, grants only for a vetted host.
type PeerKeys struct {
	Client Client
}

const peerKeyTimeout = 10 * time.Second

// Install stores the pair secret. A retry with the same fingerprint succeeds: pairing must be idempotent.
func (p PeerKeys) Install(ctx context.Context, keyHex, fp string) (CommandResult, error) {
	if keyHex == "" || fp == "" {
		return CommandResult{}, &Error{Code: CodeBadRequest, Err: fmt.Errorf("install_peer_key without a key or fingerprint")}
	}
	return p.send(ctx, map[string]any{"cmd": "install_peer_key", "peer_key": keyHex, "key_fp": fp})
}

// Remove deletes the pair secret, but ONLY the one with the given fingerprint. It resets an interrupted
// pairing where the key landed on one side only and a retry would derive a different key.
func (p PeerKeys) Remove(ctx context.Context, fp string) (CommandResult, error) {
	if fp == "" {
		return CommandResult{}, &Error{Code: CodeBadRequest, Err: fmt.Errorf("remove_peer_key without the expected fingerprint")}
	}
	return p.send(ctx, map[string]any{"cmd": "remove_peer_key", "key_fp": fp})
}

// ReadSecret returns a pair secret; "" means it does not exist yet (normal on a standalone node, telling the
// caller to generate one). The files are root:root, so only the agent serves them, from a closed name list.
func (p PeerKeys) ReadSecret(ctx context.Context, name string) (string, error) {
	if name == "" {
		return "", &Error{Code: CodeBadRequest, Err: fmt.Errorf("read_secret without a name")}
	}
	var raw struct {
		OK      *FlexBool `json:"ok"`
		Error   string    `json:"error,omitempty"`
		Message string    `json:"message,omitempty"`
		Status  struct {
			Present bool   `json:"present"`
			Value   string `json:"value"`
		} `json:"status"`
	}
	c := p.Client
	if c.Timeout < peerKeyTimeout {
		c.Timeout = peerKeyTimeout
	}
	if err := c.send(ctx, map[string]any{"cmd": "read_secret", "secret": name}, &raw); err != nil {
		return "", err
	}
	if raw.OK == nil {
		return "", &Error{Code: CodeMalformed, Err: fmt.Errorf("the response has no ok field")}
	}
	if !raw.OK.Bool() {
		return "", &Error{Code: CodeCommand, Err: fmt.Errorf("%s: %s", raw.Error, raw.Message)}
	}
	if !raw.Status.Present {
		return "", nil
	}
	return raw.Status.Value, nil
}

// ResolveDevice returns the interface THIS node would put the service address on. The node is asked, not
// the operator: NIC names need not match across the pair.
func (p PeerKeys) ResolveDevice(ctx context.Context, address string) (string, error) {
	if address == "" {
		return "", &Error{Code: CodeBadRequest, Err: fmt.Errorf("resolve_publication_device without an address")}
	}
	var raw struct {
		OK      *FlexBool `json:"ok"`
		Error   string    `json:"error,omitempty"`
		Message string    `json:"message,omitempty"`
		Status  struct {
			Device string `json:"device"`
			CIDR   string `json:"cidr"`
		} `json:"status"`
	}
	c := p.Client
	if c.Timeout < peerKeyTimeout {
		c.Timeout = peerKeyTimeout
	}
	if err := c.send(ctx, map[string]any{"cmd": "resolve_publication_device", "value": address}, &raw); err != nil {
		return "", err
	}
	if raw.OK == nil || !raw.OK.Bool() {
		return "", &Error{Code: CodeCommand, Err: fmt.Errorf("%s: %s", raw.Error, raw.Message)}
	}
	return raw.Status.Device, nil
}

// ResolveInterface returns the interface AND prefix for address, so the panel can show `eth0: 192.0.2.11/24`
// with an observed mask. An empty result without error means the address is not up on this node (e.g. the
// service address on the node not holding it), which is normal.
func (p PeerKeys) ResolveInterface(ctx context.Context, address string) (device, cidr string, err error) {
	var raw struct {
		OK     *FlexBool `json:"ok"`
		Status struct {
			Device string `json:"device"`
			CIDR   string `json:"cidr"`
		} `json:"status"`
	}
	if address == "" {
		return "", "", nil
	}
	c := p.Client
	if c.Timeout < peerKeyTimeout {
		c.Timeout = peerKeyTimeout
	}
	if err := c.send(ctx, map[string]any{"cmd": "resolve_publication_device", "value": address}, &raw); err != nil {
		return "", "", err
	}
	if raw.OK == nil || !raw.OK.Bool() {
		return "", "", nil // nothing to show, but not an error
	}
	return raw.Status.Device, raw.Status.CIDR, nil
}

// InstallSecret stores an agreed pair secret (name from the agent's allowlist). Unlike peer.key it REPLACES:
// the receiver's auth-master.key must become the donor's, or TOTP in the copied database cannot be decrypted.
func (p PeerKeys) InstallSecret(ctx context.Context, name, value string) (CommandResult, error) {
	if name == "" || value == "" {
		return CommandResult{}, &Error{Code: CodeBadRequest, Err: fmt.Errorf("install_secret without a name or value")}
	}
	return p.send(ctx, map[string]any{"cmd": "install_secret", "secret": name, "value": value})
}

// EnsurePairGrants creates LOCAL replication access for the peer. Passwords are not sent: the agent reads
// its own files, since a second delivery path is a second place for the secret to diverge.
func (p PeerKeys) EnsurePairGrants(ctx context.Context, host string) (CommandResult, error) {
	if host == "" {
		return CommandResult{}, &Error{Code: CodeBadRequest, Err: fmt.Errorf("ensure_pair_grants without the peer host")}
	}
	return p.send(ctx, map[string]any{"cmd": "ensure_pair_grants", "host": host})
}

// EnableFailsafe turns on the HA-role fail-safe (DisableFailsafe turns it off). No MariaDB restart: the file
// affects the next start, and the agent sets the current read_only from the proven role.
func (p PeerKeys) EnableFailsafe(ctx context.Context) (CommandResult, error) {
	return p.send(ctx, map[string]any{"cmd": "enable_failsafe"})
}

func (p PeerKeys) DisableFailsafe(ctx context.Context) (CommandResult, error) {
	return p.send(ctx, map[string]any{"cmd": "disable_failsafe"})
}

// ResetPairState makes the node forget the pair epoch, on teardown: a new pair starts at epoch 1, and an
// agent durably remembering epoch 9 would reject all its mutations as stale.
func (p PeerKeys) ResetPairState(ctx context.Context) (CommandResult, error) {
	return p.send(ctx, map[string]any{"cmd": "reset_pair_state"})
}

func (p PeerKeys) send(ctx context.Context, req map[string]any) (CommandResult, error) {
	var raw struct {
		OK      *FlexBool `json:"ok"`
		Noop    *FlexBool `json:"noop"`
		Error   string    `json:"error,omitempty"`
		Message string    `json:"message,omitempty"`
	}
	c := p.Client
	if c.Timeout < peerKeyTimeout {
		c.Timeout = peerKeyTimeout
	}
	if err := c.send(ctx, req, &raw); err != nil {
		return CommandResult{}, err
	}
	if raw.OK == nil {
		return CommandResult{}, &Error{Code: CodeMalformed, Err: fmt.Errorf("the response has no ok field")}
	}
	res := CommandResult{OK: raw.OK.Bool(), Noop: raw.Noop.Bool(), Error: raw.Error, Message: raw.Message,
		Status: json.RawMessage(nil)}
	if !res.OK {
		if res.Error == "" {
			res.Error = CodeCommand
		}
		return res, &Error{Code: CodeCommand, Err: fmt.Errorf("%s: %s", res.Error, res.Message)}
	}
	return res, nil
}

// PublicationConflicts lists what blocks publication (probe port or address in use); empty means nothing.
type PublicationConflicts struct {
	ProbePort string `json:"probe_port,omitempty"`
	Address   string `json:"address,omitempty"`
}

// Empty reports whether there are no conflicts.
func (c PublicationConflicts) Empty() bool { return c.ProbePort == "" && c.Address == "" }

// String renders the conflicts as one human-readable line.
func (c PublicationConflicts) String() string {
	switch {
	case c.ProbePort != "" && c.Address != "":
		return c.ProbePort + "; " + c.Address
	case c.ProbePort != "":
		return c.ProbePort
	}
	return c.Address
}

// CheckPublication asks the node whether publication resources are free. Read-only.
//
// It runs before pair creation and any destructive step, so a busy port or foreign address refuses up front
// rather than after the receiver's database has been rebuilt.
func (p PeerKeys) CheckPublication(ctx context.Context, provider, address string, probePort int, own string) (PublicationConflicts, error) {
	var raw struct {
		OK      *FlexBool `json:"ok"`
		Error   string    `json:"error,omitempty"`
		Message string    `json:"message,omitempty"`
		Status  struct {
			Conflicts PublicationConflicts `json:"conflicts"`
		} `json:"status"`
	}
	c := p.Client
	if c.Timeout < peerKeyTimeout {
		c.Timeout = peerKeyTimeout
	}
	req := map[string]any{"cmd": "check_publication",
		"publication_provider": provider, "publication_address": address}
	if probePort > 0 {
		req["probe_port"] = probePort
	}
	if own != "" {
		req["own_address"] = own
	}
	if err := c.send(ctx, req, &raw); err != nil {
		return PublicationConflicts{}, err
	}
	if raw.OK == nil || !raw.OK.Bool() {
		return PublicationConflicts{}, &Error{Code: CodeCommand, Err: fmt.Errorf("%s: %s", raw.Error, raw.Message)}
	}
	return raw.Status.Conflicts, nil
}

// AddressPresent reports whether an address is up on an interface. Read-only.
//
// Errors and "not up" both return false on purpose: the only consumer is cleanup of a previous anycast
// address, and skipping it is safer than looping on a failed query; service keeps working and the next
// cycle retries.
func (p PeerKeys) AddressPresent(ctx context.Context, addr, dev string) bool {
	if addr == "" || dev == "" {
		return false
	}
	var raw struct {
		OK     *FlexBool `json:"ok"`
		Status struct {
			Present *FlexInt `json:"present"`
		} `json:"status"`
	}
	c := p.Client
	if c.Timeout < peerKeyTimeout {
		c.Timeout = peerKeyTimeout
	}
	req := map[string]any{"cmd": "address_present", "publication_address": addr, "publication_device": dev}
	if err := c.send(ctx, req, &raw); err != nil {
		return false
	}
	if raw.OK == nil || !raw.OK.Bool() || raw.Status.Present == nil {
		return false
	}
	v := raw.Status.Present.Int64()
	return v != nil && *v == 1
}

// DropAddress removes a specific address. It has no epoch by design: it cleans up a PAST configuration
// rather than acting on a role.
func (p PeerKeys) DropAddress(ctx context.Context, addr, dev string) (CommandResult, error) {
	if addr == "" || dev == "" {
		return CommandResult{}, &Error{Code: CodeBadRequest, Err: fmt.Errorf("drop_address without an address")}
	}
	return p.send(ctx, map[string]any{"cmd": "drop_address",
		"publication_address": addr, "publication_device": dev})
}
