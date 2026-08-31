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

	mu               sync.Mutex
	rejected         int
	reasons          []string
	published        []publication
	sessionCreatedAt time.Time
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

	now := c.clock()
	envelope := protocol.Envelope{
		Version:   protocol.Version,
		Namespace: protocol.Namespace,
		Type:      kind,
		MessageID: hex.EncodeToString(messageID),
		SessionID: c.Session(),
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

	// The message that opens a conversation is keyed by recipient, so a new
	// attempt replaces the previous one on the relay instead of joining it. A
	// responder must find one live request per peer, not a backlog of every
	// session its counterpart ever abandoned.
	positionTag := nostr.ReplaceableTag(sealed.SessionID, string(sealed.Type), sealed.Seq)
	if kind == protocol.TypeSessionRequest {
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
func (c *controlPlane) Next(ctx context.Context) (protocol.MessageType, uint64, protocol.Payload, error) {
	for {
		select {
		case <-ctx.Done():
			// The reasons messages were discarded are the whole diagnosis when
			// a wait times out: "no offer arrived" says nothing, while "4
			// messages arrived and every one failed to decrypt" names the
			// problem.
			return "", 0, protocol.Payload{}, c.explainTimeout(ctx.Err())

		case received, open := <-c.inbound:
			if !open {
				return "", 0, protocol.Payload{}, errors.New("control plane closed")
			}

			kind, seq, payload, err := c.open(received)
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
			return kind, seq, payload, nil
		}
	}
}

// open verifies and decrypts one delivered event.
func (c *controlPlane) open(received nostr.Received) (protocol.MessageType, uint64, protocol.Payload, error) {
	event, err := nostr.ParseEvent(received.Event.Raw)
	if err != nil {
		return "", 0, protocol.Payload{}, err
	}

	// The signature is checked before anything else is believed about the
	// event. A relay can deliver whatever it likes; only this establishes
	// authorship.
	if err := nostr.VerifyEvent(event); err != nil {
		return "", 0, protocol.Payload{}, err
	}

	// An event signed by someone other than the peer is not part of this
	// conversation, whatever it claims inside.
	if event.PublicKey != c.peer.String() {
		return "", 0, protocol.Payload{}, errors.New("event is not from the expected peer")
	}

	var envelope protocol.Envelope
	if err := json.Unmarshal([]byte(event.Content), &envelope); err != nil {
		return "", 0, protocol.Payload{}, err
	}

	// Version, namespace, size, expiry and recipient, all checked before the
	// payload is decrypted: validation is cheapest-first so a malformed message
	// cannot make this node spend cryptography on it.
	if err := protocol.ValidateEnvelope(envelope, c.self.String(), c.clock()); err != nil {
		return "", 0, protocol.Payload{}, err
	}

	// The envelope's claimed sender must match the key that actually signed
	// the event. Without this the cleartext fields could name anyone, and the
	// signature would still verify against its true author.
	if envelope.Sender != event.PublicKey {
		return "", 0, protocol.Payload{}, errors.New("envelope sender does not match the signing key")
	}

	// A relay stores events and replays them to a new subscription, so a
	// message from a previous session with this same peer arrives looking
	// perfectly valid — correctly signed, correctly addressed, not yet expired.
	//
	// Acting on one is worse than ignoring it: an offer from an earlier session
	// carries a different offer hash, and accepting it produces a mismatch the
	// far side reports as tampering. The session id is what tells them apart.
	if err := c.matchesSession(envelope); err != nil {
		return "", 0, protocol.Payload{}, err
	}

	payload, err := c.codec.Open(envelope, c.key)
	if err != nil {
		return "", 0, protocol.Payload{}, err
	}

	if err := protocol.ValidatePayload(payload, envelope, c.clock()); err != nil {
		return "", 0, protocol.Payload{}, err
	}

	return envelope.Type, envelope.Seq, payload, nil
}

// BindSession names the session this conversation belongs to.
//
// An empty id makes the conversation adopt the first session it sees, which is
// what a responder needs: it learns the session from the request it answers.
func (c *controlPlane) BindSession(sessionID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.sessions = sessionID
	if sessionID == "" {
		c.sessionCreatedAt = time.Time{}
	}
	return nil
}

// Session reports the session this conversation settled on.
func (c *controlPlane) Session() string {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.sessions
}

// SessionCreatedAt reports when the message that named this session was
// published, as its sender stamped it.
func (c *controlPlane) SessionCreatedAt() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.sessionCreatedAt
}

// matchesSession keeps a conversation to a single session.
//
// The initiator knows its session id from the start. The responder learns it
// from the request that opens the session, so it adopts the first one it
// accepts and refuses every other afterwards — which is what stops a relay's
// replay of an older session from being answered as though it were current.
func (c *controlPlane) matchesSession(envelope protocol.Envelope) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.sessions == "" {
		c.sessions = envelope.SessionID
		c.sessionCreatedAt = envelope.CreatedTime()
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
