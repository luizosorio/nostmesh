package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/luizosorio/nostmesh/internal/domain"
	"github.com/luizosorio/nostmesh/internal/nostr"
	"github.com/luizosorio/nostmesh/internal/orchestrator"
	"github.com/luizosorio/nostmesh/internal/protocol"
)

// controlPlane carries the driver's payloads over Nostr.
//
// It is the only place that knows both halves: the driver produces and consumes
// protocol payloads and knows nothing of relays or encryption, and the relay set
// carries bytes and knows nothing of sessions.
type controlPlane struct {
	set      *nostr.RelaySet
	codec    *nostr.Codec
	signer   *nostr.Signer
	key      nostr.ConversationKey
	clock    func() time.Time
	sessions string

	self domain.NostrPublicKey
	peer domain.NostrPublicKey

	// inbound carries what the relay subscription delivered, already opened.
	inbound <-chan nostr.Received

	mu        sync.Mutex
	rejected  int
	reasons   []string
	published []publication
}

// publication records how one outgoing message fared across the relay set.
type publication struct {
	kind     protocol.MessageType
	accepted int
	failures int
}

// newControlPlane wires a relay set to one peer conversation.
func newControlPlane(ctx context.Context, set *nostr.RelaySet, identity domain.NodeIdentity,
	peer domain.NostrPublicKey, sessionID string, clock func() time.Time,
) (*controlPlane, error) {
	signer, err := nostr.NewSigner(identity.PrivateKey())
	if err != nil {
		return nil, fmt.Errorf("building signer: %w", err)
	}

	// The conversation key is derived once. It never leaves this struct, and
	// the private key it derives from is not retained.
	privateHex, err := nostr.PrivateKeyHex(identity.PrivateKey())
	if err != nil {
		return nil, err
	}

	key, err := nostr.DeriveConversationKey(privateHex, peer.String())
	if err != nil {
		return nil, fmt.Errorf("deriving conversation key: %w", err)
	}

	plane := &controlPlane{
		set:      set,
		codec:    nostr.NewCodec(clock),
		signer:   signer,
		key:      key,
		clock:    clock,
		sessions: sessionID,
		self:     identity.PublicKey(),
		peer:     peer,
	}

	plane.inbound = set.Client().Subscribe(ctx, 64, nostr.EnvelopeKey)
	return plane, nil
}

// Publish seals a payload and publishes it as a signed Nostr event.
func (c *controlPlane) Publish(ctx context.Context, kind protocol.MessageType,
	seq uint64, payload protocol.Payload,
) error {
	messageID := make([]byte, 16)
	if _, err := rand.Read(messageID); err != nil {
		return fmt.Errorf("generating message id: %w", err)
	}

	c.mu.Lock()
	session := c.sessions
	c.mu.Unlock()

	if session == "" {
		// Publishing before the conversation has a session would name none, and
		// the peer discards a message that belongs to no conversation.
		return fmt.Errorf("cannot publish %s: this conversation has no session yet", kind)
	}

	now := c.clock()
	envelope := protocol.Envelope{
		Version:   protocol.Version,
		Namespace: protocol.Namespace,
		Type:      kind,
		MessageID: hex.EncodeToString(messageID),
		SessionID: session,
		Seq:       seq,
		CreatedAt: now.Unix(),
		ExpiresAt: now.Add(envelopeLifetime).Unix(),
		Sender:    c.self.String(),
		Recipient: c.peer.String(),
	}

	sealed, err := c.codec.Seal(envelope, payload, c.key)
	if err != nil {
		return fmt.Errorf("sealing %s: %w", kind, err)
	}

	// The whole envelope is the event content, not the ciphertext alone: the
	// cleartext routing fields are what the receiver recomputes into the
	// context hash, so a body published on its own cannot be opened.
	content, err := json.Marshal(sealed)
	if err != nil {
		return fmt.Errorf("encoding envelope: %w", err)
	}

	// The messages that open a conversation are keyed by recipient, so a new
	// attempt replaces the previous one on the relay instead of joining it.
	//
	// Both directions need it. A responder must find one live request per peer,
	// and an initiator must find one live offer — an initiator handed an offer
	// from a session it abandoned discards it as belonging to another
	// conversation, and waits out its timeout while the answer to its actual
	// request sits behind the stale one. That is the same failure the request
	// tag fixed, seen from the other end.
	//
	// Everything after the opening exchange is keyed by position instead: within
	// a session each message is distinct and nothing should replace anything.
	positionTag := nostr.ReplaceableTag(sealed.SessionID, string(sealed.Type), sealed.Seq)
	if opensAConversation(kind) {
		positionTag = nostr.OpeningTag(c.peer, string(sealed.Type))
	}

	tags := [][]string{
		nostr.RecipientTag(c.peer),
		positionTag,
	}

	_, raw, err := nostr.BuildEvent(c.signer, protocol.ExperimentalKind, tags, string(content), now)
	if err != nil {
		return fmt.Errorf("building event: %w", err)
	}

	entry := nostr.Entry{
		ID:        sealed.MessageID,
		Event:     raw,
		ExpiresAt: now.Add(envelopeLifetime),
	}

	// Through the outbox: a publication no relay accepted is retried rather
	// than lost, which is what lets a node work through a relay outage.
	result, err := c.set.Client().PublishWithOutbox(ctx, entry)
	if err != nil {
		return fmt.Errorf("publishing %s: %w", kind, err)
	}

	// Which relays accepted is recorded rather than discarded. A publication
	// that satisfies the acceptance threshold while most relays refused is a
	// working session running on far less redundancy than configured, and
	// nothing else would ever report that.
	c.recordPublication(kind, result)
	return nil
}

// opensAConversation reports whether a message type begins an exchange rather
// than continuing one.
//
// A request opens it and an offer answers that opening. Both are superseded
// wholesale by a later attempt, so the relay should keep only the newest of
// each per peer. Everything else belongs to a session already under way.
func opensAConversation(kind protocol.MessageType) bool {
	return kind == protocol.TypeSessionRequest || kind == protocol.TypeSessionOffer
}

// recordPublication remembers how a publication fared.
func (c *controlPlane) recordPublication(kind protocol.MessageType, result nostr.PublishResult) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.published = append(c.published, publication{
		kind:     kind,
		accepted: len(result.AcceptedBy),
		failures: len(result.Failures),
	})
}

// Publications reports what this conversation published and how it fared.
func (c *controlPlane) Publications() []string {
	c.mu.Lock()
	defer c.mu.Unlock()

	lines := make([]string, 0, len(c.published))
	for _, p := range c.published {
		lines = append(lines, fmt.Sprintf("%s: %d accepted, %d refused", p.kind, p.accepted, p.failures))
	}
	return lines
}

// Next returns the peer's next control message.
//
// Everything arriving here is untrusted until it has been verified twice: the
// event's signature proves who wrote it, and opening the payload proves it was
// sealed for this conversation. A message failing either is discarded, since a
// relay carrying other people's traffic is ordinary — but the reason is kept, so
// a wait that ends empty can say what it saw instead of only that it waited.
func (c *controlPlane) Next(ctx context.Context) (orchestrator.Delivery, error) {
	for {
		select {
		case <-ctx.Done():
			// The reasons messages were discarded are the whole diagnosis when
			// a wait times out: "no offer arrived" says nothing, while "4
			// messages arrived and every one failed to decrypt" names the
			// problem.
			return orchestrator.Delivery{}, c.explainTimeout(ctx.Err())

		case received, open := <-c.inbound:
			if !open {
				return orchestrator.Delivery{}, errors.New("control plane closed")
			}

			delivery, err := c.open(received)
			if err != nil {
				// A rejected message is not fatal — relays carry other
				// people's traffic, and a message for another session or
				// another node is ordinary. But discarding silently is how a
				// misconfigured node waits out its whole timeout with nothing
				// to show for it, so the reason is recorded and reported if
				// the wait ends empty.
				c.recordRejection(err)
				continue
			}
			return delivery, nil
		}
	}
}

// open verifies and decrypts one delivered event.
func (c *controlPlane) open(received nostr.Received) (orchestrator.Delivery, error) {
	event, err := nostr.ParseEvent(received.Event.Raw)
	if err != nil {
		return orchestrator.Delivery{}, err
	}

	// The signature is checked before anything else is believed about the
	// event. A relay can deliver whatever it likes; only this establishes
	// authorship.
	if err := nostr.VerifyEvent(event); err != nil {
		return orchestrator.Delivery{}, err
	}

	// An event signed by someone other than the peer is not part of this
	// conversation, whatever it claims inside.
	if event.PublicKey != c.peer.String() {
		return orchestrator.Delivery{}, errors.New("event is not from the expected peer")
	}

	var envelope protocol.Envelope
	if err := json.Unmarshal([]byte(event.Content), &envelope); err != nil {
		return orchestrator.Delivery{}, err
	}

	// Version, namespace, size, expiry and recipient, all checked before the
	// payload is decrypted: validation is cheapest-first so a malformed message
	// cannot make this node spend cryptography on it.
	if err := protocol.ValidateEnvelope(envelope, c.self.String(), c.clock()); err != nil {
		return orchestrator.Delivery{}, err
	}

	// The envelope's claimed sender must match the key that actually signed
	// the event. Without this the cleartext fields could name anyone, and the
	// signature would still verify against its true author.
	if envelope.Sender != event.PublicKey {
		return orchestrator.Delivery{}, errors.New("envelope sender does not match the signing key")
	}

	// A relay stores events and replays them to a new subscription, so a
	// message from a previous session with this same peer arrives looking
	// perfectly valid — correctly signed, correctly addressed, not yet expired.
	//
	// Acting on one is worse than ignoring it: an offer from an earlier session
	// carries a different offer hash, and accepting it produces a mismatch the
	// far side reports as tampering. The session id is what tells them apart.
	if err := c.matchesSession(envelope); err != nil {
		return orchestrator.Delivery{}, err
	}

	payload, err := c.codec.Open(envelope, c.key)
	if err != nil {
		return orchestrator.Delivery{}, err
	}

	if err := protocol.ValidatePayload(payload, envelope, c.clock()); err != nil {
		return orchestrator.Delivery{}, err
	}

	return orchestrator.Delivery{
		Kind:      envelope.Type,
		Seq:       envelope.Seq,
		Payload:   payload,
		SessionID: envelope.SessionID,
		CreatedAt: envelope.CreatedTime(),
	}, nil
}

// BindSession names the session this conversation belongs to.
//
// An empty id is refused. "Not yet bound" is this plane's initial state, not a
// request a caller makes: accepting one would publish messages naming no
// session, which the peer discards as belonging to a different conversation.
func (c *controlPlane) BindSession(sessionID string) error {
	if sessionID == "" {
		return errors.New("a session identifier is required; an unbound plane is its initial state, not a request")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.sessions = sessionID
	return nil
}

// matchesSession keeps a bound conversation to its single session.
//
// While unbound the message is accepted and its session reported upward: a
// responder sees several requests before choosing one, and adopting here would
// bind the conversation to whichever the relay replayed first, before the driver
// had seen the alternatives. Choosing is the driver's decision, and this plane
// has none of the information it needs to make it.
//
// Once bound, a message from any other session is refused — which is what stops
// a relay's replay of an older session from being answered as though current.
func (c *controlPlane) matchesSession(envelope protocol.Envelope) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.sessions == "" {
		return nil
	}
	if envelope.SessionID != c.sessions {
		return fmt.Errorf("message belongs to session %s, this conversation is %s",
			abbreviateID(envelope.SessionID), abbreviateID(c.sessions))
	}
	return nil
}

// abbreviateID shortens an identifier for a message.
func abbreviateID(id string) string {
	const shown = 8
	if len(id) <= shown {
		return id
	}
	return id[:shown]
}

// recordRejection remembers why a delivered message was not usable.
func (c *controlPlane) recordRejection(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.rejected++

	// Only the first few are kept. A relay carrying unrelated traffic would
	// otherwise grow this without bound, and the first reasons are the
	// informative ones.
	if len(c.reasons) < maxRecordedRejections {
		c.reasons = append(c.reasons, err.Error())
	}
}

// explainTimeout turns an empty wait into a diagnosis.
func (c *controlPlane) explainTimeout(cause error) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Deliveries this node discarded for want of a reader are reported first:
	// they mean the relay did its job and the loss is local, which is a
	// different problem from a peer that never published.
	if dropped := c.set.Dropped(); dropped > 0 {
		return fmt.Errorf("%w (%d delivery(ies) were discarded because this node was not reading; %d message(s) arrived and none were usable)",
			cause, dropped, c.rejected)
	}

	// A relay that closed the subscription said it would send nothing more.
	// Without reporting it, the wait simply ends with no explanation.
	if closed, reason := c.set.ClosedSubscriptions(); closed > 0 {
		if reason == "" {
			reason = "no reason given"
		}
		return fmt.Errorf("%w (a relay closed the subscription %d time(s): %s)", cause, closed, reason)
	}

	if c.rejected == 0 {
		return fmt.Errorf("%w (no messages arrived from the peer)", cause)
	}
	return fmt.Errorf("%w (%d message(s) arrived and none were usable: %s)",
		cause, c.rejected, strings.Join(c.reasons, "; "))
}

const (
	// envelopeLifetime bounds how long a control message stays valid.
	envelopeLifetime = 5 * time.Minute

	// maxRecordedRejections bounds the diagnostic detail kept for a timeout.
	maxRecordedRejections = 5
)
