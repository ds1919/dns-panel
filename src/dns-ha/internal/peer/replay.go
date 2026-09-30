package peer

import (
	"sync"
	"time"
)

// verdict is what the server decides about an incoming message before executing it.
type verdict int

const (
	verdictFresh      verdict = iota // new message: execute
	verdictRetransmit                // same message_id and nonce: retransmission, return the PREVIOUS reply
	verdictReplay                    // nonce seen with a different message_id: replay of someone else's message
)

// replayCache tells apart two fundamentally different cases:
//   - retransmission: the network blinked and the sender resent THE SAME message. This is NORMAL (§6.1: "a
//     repeated message_id creates no new action"), and the right response is the same result, not a second run;
//   - replay: someone reuses an intercepted nonce in another message. That is an attack and is rejected.
type replayCache struct {
	mu    sync.Mutex
	ttl   time.Duration
	max   int
	byMsg map[string]*cacheEntry // sender|message_id -> reply
	nonce map[string]nonceEntry  // sender|nonce -> when seen and with which message_id
	now   func() time.Time
}

type cacheEntry struct {
	response []byte
	seen     time.Time
}

type nonceEntry struct {
	messageID string
	seen      time.Time
}

func newReplayCache(ttl time.Duration, max int) *replayCache {
	return &replayCache{ttl: ttl, max: max, byMsg: map[string]*cacheEntry{}, nonce: map[string]nonceEntry{}, now: time.Now}
}

func key(sender, id string) string { return sender + "|" + id }

// check decides a message's fate; for a retransmission it returns the stored reply.
func (c *replayCache) check(sender, messageID, nonce string) (verdict, []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.evictLocked()

	mk, nk := key(sender, messageID), key(sender, nonce)
	if ent, ok := c.byMsg[mk]; ok {
		if n, ok2 := c.nonce[nk]; ok2 && n.messageID == messageID {
			return verdictRetransmit, ent.response // same message_id AND nonce: honest retry
		}
		// Same message_id, different nonce: the message was rewritten and cannot be trusted.
		return verdictReplay, nil
	}
	if n, ok := c.nonce[nk]; ok && n.messageID != messageID {
		return verdictReplay, nil
	}
	return verdictFresh, nil
}

// claimMutationNonce is anti-replay for mutating commands: checks and records the nonce in ONE operation.
//
// Separate "check" and "remember" are unusable here: the mutex is released between them, and two concurrent
// messages with one nonce would both see it free.
//
// For mutations retry semantics are the reverse of read-only: the same message_id with a NEW nonce is a normal
// retry of the logical action, not a replay. So message_id takes no part in the verdict: authoritative action
// dedup lives in the durable registry (ha_peer_requests), and the cache only enforces one-time nonces.
func (c *replayCache) claimMutationNonce(sender, messageID, nonce string) verdict {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.evictLocked()

	nk := key(sender, nonce)
	if n, ok := c.nonce[nk]; ok && n.messageID != messageID {
		return verdictReplay // same nonce in a DIFFERENT message: replay attempt
	}
	c.nonce[nk] = nonceEntry{messageID: messageID, seen: c.now()}
	return verdictFresh
}

// remember records an executed message and its reply.
func (c *replayCache) remember(sender, messageID, nonce string, response []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	c.byMsg[key(sender, messageID)] = &cacheEntry{response: response, seen: now}
	c.nonce[key(sender, nonce)] = nonceEntry{messageID: messageID, seen: now}
	c.evictLocked()
}

// evictLocked drops expired entries and bounds the cache: this is network-facing, and "remember everything
// forever" would be a slow memory leak under someone else's control.
func (c *replayCache) evictLocked() {
	now := c.now()
	for k, v := range c.byMsg {
		if now.Sub(v.seen) > c.ttl {
			delete(c.byMsg, k)
		}
	}
	for k, v := range c.nonce {
		if now.Sub(v.seen) > c.ttl {
			delete(c.nonce, k)
		}
	}
	// Emergency reset on overflow: better to lose retransmit protection (it degrades to re-running a
	// read-only command) than to let memory grow until the node fails.
	if len(c.byMsg) > c.max {
		c.byMsg = map[string]*cacheEntry{}
	}
	if len(c.nonce) > c.max {
		c.nonce = map[string]nonceEntry{}
	}
}
