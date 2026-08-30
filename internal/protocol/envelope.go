// Package protocol defines the NostMesh control protocol.
//
// It is transport-neutral: envelopes, validation and message types are defined
// over bytes, and nothing here knows about Nostr, relays or WebSockets. The
// transport adapter lives in internal/nostr.
//
// The protocol is experimental. It claims no NIP number and uses a namespaced
// experimental kind range until interoperability work says otherwise.
package protocol

import (
	"errors"
	"fmt"
	"time"
)

// Version is the protocol version this build speaks.
//
// A receiver rejects an envelope carrying a version it does not implement.
// Version negotiation happens through capabilities, not by attempting to parse
// an unknown shape.
const Version = 1

// Namespace scopes every message this implementation produces.
//
// It is explicit so that an experimental protocol cannot be mistaken for a
// standardized one, and so that a future namespace change is a visible break
// rather than a silent reinterpretation.
const Namespace = "org.nostmesh.experimental"

// ExperimentalKind is the Nostr event kind used during development.
//
// The 30000-39999 range is parameterized-replaceable per NIP-01. A final kind
// requires interoperability review and is deliberately not claimed here.
const ExperimentalKind = 31111

// Size limits, checked before anything expensive happens.
//
// Validation order is cheapest-first: an oversized frame is refused before it is
// parsed, and a malformed envelope before its payload is decrypted. That keeps
// an attacker from spending our CPU with garbage.
const (
	// MaxEnvelopeSize bounds the outer event.
	MaxEnvelopeSize = 64 * 1024

	// MaxPayloadSize bounds the encrypted payload.
	MaxPayloadSize = 32 * 1024

	// MaxJSONDepth bounds nesting, so a deeply nested document cannot exhaust
	// the stack during parsing.
	MaxJSONDepth = 16

	// MaxCriticalExtensions bounds the critical list.
	MaxCriticalExtensions = 8
)

// Validity bounds. Timestamps come from a peer and are therefore untrusted:
// they are only ever used to decide whether a message falls inside a window,
// never to order messages, which is what sequence numbers are for.
const (
	// MaxClockSkew tolerates disagreement between hosts.
	MaxClockSkew = 5 * time.Minute

	// MaxValidity bounds how far ahead a message may claim to be valid.
	MaxValidity = 10 * time.Minute
)

// MessageType names a control message.
type MessageType string

const (
	// TypeSessionRequest asks a peer to open a session.
	TypeSessionRequest MessageType = "session.request"

	// TypeSessionOffer conditionally accepts and commits parameters.
	TypeSessionOffer MessageType = "session.offer"

	// TypeSessionAccept accepts the hash of an offer.
	TypeSessionAccept MessageType = "session.accept"

	// TypeCandidateUpdate adds or removes connectivity candidates.
	TypeCandidateUpdate MessageType = "candidate.update"

	// TypeSessionReady reports local confirmation of the tunnel.
	//
	// It is informative. A session becomes established when this node verifies
	// the tunnel itself, never because a peer said it was ready.
	TypeSessionReady MessageType = "session.ready"

	// TypeSessionKeepalive refreshes control-plane liveness.
	TypeSessionKeepalive MessageType = "session.keepalive"

	// TypeSessionClose ends a session with a reason.
	TypeSessionClose MessageType = "session.close"

	// TypeSessionError reports a sanitized error with a stable code.
	TypeSessionError MessageType = "session.error"
)

// knownTypes is the closed set this version accepts.
var knownTypes = map[MessageType]bool{
	TypeSessionRequest:   true,
	TypeSessionOffer:     true,
	TypeSessionAccept:    true,
	TypeCandidateUpdate:  true,
	TypeSessionReady:     true,
	TypeSessionKeepalive: true,
	TypeSessionClose:     true,
	TypeSessionError:     true,
}

// IsKnown reports whether this version understands the type.
func (t MessageType) IsKnown() bool { return knownTypes[t] }

// String returns the wire form.
func (t MessageType) String() string { return string(t) }

var (
	// ErrUnsupportedVersion reports a version this build does not implement.
	ErrUnsupportedVersion = errors.New("unsupported protocol version")

	// ErrUnknownNamespace reports a namespace from another protocol.
	ErrUnknownNamespace = errors.New("unknown namespace")

	// ErrUnknownType reports a message type this version does not handle.
	ErrUnknownType = errors.New("unknown message type")

	// ErrCriticalExtension reports a critical extension this build cannot
	// honour. Ignoring it would mean processing a message whose meaning has
	// been changed in a way the sender considered essential.
	ErrCriticalExtension = errors.New("unsupported critical extension")

	// ErrTooLarge reports a frame or payload beyond its limit.
	ErrTooLarge = errors.New("message exceeds size limit")

	// ErrExpired reports a message outside its validity window.
	ErrExpired = errors.New("message has expired")

	// ErrNotYetValid reports a message claiming to start in the future beyond
	// tolerated clock skew.
	ErrNotYetValid = errors.New("message is not yet valid")

	// ErrWrongRecipient reports a message addressed elsewhere.
	ErrWrongRecipient = errors.New("message is addressed to another node")

	// ErrMalformed reports a structurally invalid envelope.
	ErrMalformed = errors.New("malformed envelope")
)

// Envelope is the outer, unencrypted structure of a control message.
//
// It carries only what routing and validation need. Everything sensitive —
// candidates, overlay addresses, WireGuard public keys, negotiated parameters —
// lives in the encrypted Body, because the outer fields are visible to every
// relay that handles the event.
type Envelope struct {
	// Version is the protocol version.
	Version int `json:"v"`

	// Namespace scopes the message.
	Namespace string `json:"namespace"`

	// Type names the message.
	Type MessageType `json:"type"`

	// MessageID is a random 128-bit identifier, used for deduplication.
	MessageID string `json:"message_id"`

	// SessionID is a random 256-bit session identifier.
	SessionID string `json:"session_id"`

	// Seq orders messages within a session. Ordering comes from this, never
	// from comparing timestamps across hosts.
	Seq uint64 `json:"seq"`

	// CreatedAt is when the sender produced the message.
	CreatedAt int64 `json:"created_at"`

	// ExpiresAt is when the message stops being valid.
	ExpiresAt int64 `json:"expires_at"`

	// Sender is the originating Nostr public key, hex-encoded.
	Sender string `json:"sender"`

	// Recipient is the intended Nostr public key, hex-encoded.
	Recipient string `json:"recipient"`

	// ReplyTo references a prior message, when the type calls for it.
	ReplyTo string `json:"reply_to,omitempty"`

	// Body is the encrypted payload.
	Body string `json:"body"`

	// Critical lists extensions the sender considers essential. A receiver that
	// does not understand one must reject the message rather than process it
	// with the extension ignored.
	Critical []string `json:"critical,omitempty"`
}

// AssociatedData returns the bytes authenticated alongside the encrypted body.
//
// Binding these fields cryptographically is what stops an attacker from taking
// a valid payload and re-addressing it: changing the recipient, the session, the
// sequence number or the validity window invalidates the authentication tag,
// even though those fields travel in the clear.
//
// The encoding is explicit and length-prefixed so that no combination of field
// values can produce the same byte string as a different combination.
func (e Envelope) AssociatedData() []byte {
	fields := []string{
		fmt.Sprintf("v=%d", e.Version),
		"ns=" + e.Namespace,
		"type=" + string(e.Type),
		"msg=" + e.MessageID,
		"session=" + e.SessionID,
		fmt.Sprintf("seq=%d", e.Seq),
		fmt.Sprintf("created=%d", e.CreatedAt),
		fmt.Sprintf("expires=%d", e.ExpiresAt),
		"from=" + e.Sender,
		"to=" + e.Recipient,
	}
	for _, extension := range e.Critical {
		fields = append(fields, "critical="+extension)
	}

	var buf []byte
	for _, field := range fields {
		// A field longer than the prefix can express would make the encoding
		// ambiguous, defeating the whole point. Validation bounds every field
		// well below this, so reaching it means something upstream is wrong:
		// truncate deterministically rather than silently wrap.
		length := len(field)
		if length > maxFieldLength {
			length = maxFieldLength
			field = field[:maxFieldLength]
		}

		buf = append(buf, byte(length>>8), byte(length&0xFF))
		buf = append(buf, field...)
	}
	return buf
}

// maxFieldLength is what a two-byte prefix can express.
const maxFieldLength = 0xFFFF

// CreatedTime returns the creation timestamp.
func (e Envelope) CreatedTime() time.Time { return time.Unix(e.CreatedAt, 0).UTC() }

// ExpiryTime returns the expiry timestamp.
func (e Envelope) ExpiryTime() time.Time { return time.Unix(e.ExpiresAt, 0).UTC() }
