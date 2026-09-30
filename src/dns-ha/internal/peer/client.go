package peer

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"time"
)

// ClientConfig holds the parameters for calling the peer. The address comes from the EFFECTIVE `dns_ha` revision.
type ClientConfig struct {
	NodeID     string // own node_id (signed as sender)
	PeerNodeID string // who the reply MUST come from
	Address    string // peer's host:port (its peer_listen_*)
	Secret     []byte
	Window     time.Duration
	Timeout    time.Duration
	MaxMessage int64
	Epoch      int64 // own max_seen_epoch, so the peer sees our epoch (monotonicity backstop)
	// MessageID identifies the LOGICAL action. For mutations the caller sets it and KEEPS it across
	// attempts: only then is a retry after a lost reply recognized as the same request. Empty for read-only
	// commands, where each request stands alone.
	MessageID string
}

// Result is the outcome of a call. A transport error and a typed peer rejection are different things, so the
// rejection code is returned separately from error.
type Result struct {
	OK       bool
	Code     string // typed reason when OK=false
	Response *Response
}

// Call performs ONE request and fully verifies the reply.
//
// A broken connection does NOT mean a state change (§6.1): the caller simply asks again later, so there are no
// retries here; the watch loop decides on retries, not the transport.
// The context is required: talking to the peer is the only place observation goes to the network, and there is
// no point waiting after the operation is cancelled. The earlier of cfg.Timeout and the context deadline wins,
// and cancellation breaks an ALREADY OPEN connection, otherwise "stopped waiting" would just abandon the call.
func Call(ctx context.Context, cfg ClientConfig, cmd string, payload any) (Result, error) {
	if !allowedCommands[cmd] {
		return Result{Code: ErrCommand}, fmt.Errorf("command %q is not allowed", cmd)
	}
	raw, hash, err := marshalPayload(payload)
	if err != nil {
		return Result{Code: ErrBadRequest}, err
	}
	messageID := cfg.MessageID
	if messageID == "" {
		if messageID, err = randomHex(); err != nil {
			return Result{Code: ErrBadRequest}, err
		}
	} else if !IsMutating(cmd) {
		return Result{Code: ErrBadRequest}, fmt.Errorf("a persistent message_id is only meaningful for mutations")
	}
	if IsMutating(cmd) && cfg.MessageID == "" {
		return Result{Code: ErrBadRequest}, fmt.Errorf("mutation without a persistent message_id: a retry would be a new action")
	}
	nonce, err := randomHex()
	if err != nil {
		return Result{Code: ErrBadRequest}, err
	}
	req := Request{
		ProtocolVersion: Version,
		MessageID:       messageID,
		SenderNodeID:    cfg.NodeID,
		RecipientNodeID: cfg.PeerNodeID,
		Epoch:           cfg.Epoch,
		TS:              time.Now().Unix(),
		Nonce:           nonce,
		Cmd:             cmd,
		Payload:         raw,
		PayloadHash:     hash,
	}
	if IsMutating(cmd) {
		// Fingerprint of MEANING: it binds message_id to the content, so a payload swapped under the same ID
		// is seen by the recipient as a conflict, not an honest retry.
		req.RequestHash = RequestHash(cmd, cfg.Epoch, cfg.PeerNodeID, hash)
	}
	body, err := seal(cfg.Secret, req)
	if err != nil {
		return Result{Code: ErrBadRequest}, err
	}

	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil { // cancelled before dialing: don't dial
		return Result{Code: ErrTimeout}, err
	}
	dialer := net.Dialer{Timeout: cfg.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", cfg.Address)
	if err != nil {
		return Result{Code: ErrUnreachable}, err
	}
	defer conn.Close()
	// Cancellation closes the connection, so the read returns at once instead of waiting out its deadline.
	stopWatch := context.AfterFunc(ctx, func() { conn.Close() })
	defer stopWatch()
	deadline := time.Now().Add(cfg.Timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl // caller's deadline is earlier than ours: use it
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return Result{Code: ErrTimeout}, err
	}
	if _, err := conn.Write(append(body, '\n')); err != nil {
		return Result{Code: ErrUnreachable}, err
	}

	lr := io.LimitReader(conn, cfg.MaxMessage+1)
	line, err := bufio.NewReader(lr).ReadBytes('\n')
	if err != nil && len(line) == 0 {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return Result{Code: ErrTimeout}, err
		}
		return Result{Code: ErrUnreachable}, err
	}
	if int64(len(line)) > cfg.MaxMessage {
		return Result{Code: ErrTooLarge}, fmt.Errorf("response is larger than %d bytes", cfg.MaxMessage)
	}

	var resp Response
	if code, err := open(cfg.Secret, line, &resp); code != "" {
		if code == ErrBadSignature {
			code = ErrResponseBadSig
		}
		return Result{Code: code}, err
	}
	if code := validateResponse(&cfg, &req, &resp); code != "" {
		return Result{Code: code, Response: &resp}, fmt.Errorf("response rejected: %s", code)
	}
	if !resp.OK {
		return Result{Code: resp.Error, Response: &resp}, nil // peer replied with a typed rejection
	}
	return Result{OK: true, Response: &resp}, nil
}

// validateResponse: without these checks a signed reply can be replayed; that is how, in the Perl
// implementation, an old `status` (source still read_only) led to a promote with the source alive.
func validateResponse(cfg *ClientConfig, req *Request, resp *Response) string {
	if resp.ProtocolVersion != Version {
		return ErrVersion
	}
	if resp.SenderNodeID != cfg.PeerNodeID {
		return ErrResponseIdent
	}
	if resp.RecipientNodeID != "" && resp.RecipientNodeID != cfg.NodeID {
		return ErrResponseIdent
	}
	// The reply must be bound to OUR request specifically.
	if resp.RequestNonce != req.Nonce || resp.RequestMessageID != req.MessageID {
		return ErrResponseBind
	}
	drift := time.Now().Unix() - resp.TS
	if drift < 0 {
		drift = -drift
	}
	if time.Duration(drift)*time.Second > cfg.Window {
		return ErrResponseStale
	}
	if PayloadHash(resp.Payload) != resp.PayloadHash {
		return ErrPayloadHash
	}
	return ""
}
