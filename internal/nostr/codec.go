// Package nostr adapts the NostMesh control protocol to Nostr transport.
//
// It owns the cryptographic dependencies — NIP-44 for directed encryption,
// secp256k1 for signatures — so that internal/protocol stays transport-neutral
// and testable without them. Per NM-10 only the nip44 subpackage is imported;
// the go-nostr root, with its WebSocket client and JSON libraries, is not.
package nostr

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/nbd-wtf/go-nostr/nip44"

	"github.com/luizosorio/nostmesh/internal/protocol"
)

var (
	// ErrDecryption reports a payload that failed to decrypt or authenticate.
	//
	// The cause is deliberately not distinguished. Telling a sender whether the
	// key was wrong or the tag failed hands them an oracle.
	ErrDecryption = errors.New("payload could not be decrypted")

	// ErrConversationKey reports a failure deriving the shared key.
	ErrConversationKey = errors.New("conversation key derivation failed")
)

// ConversationKey is the symmetric key shared by two identities.
//
// NIP-44 derives it from the two long-term keys, which means it is stable for
// a given pair and offers no forward secrecy. NM-10 records that consequence
// and the mitigations: short validity windows, minimal metadata, and ephemeral
// tunnel keys that are never derived from it.
type ConversationKey [32]byte

// DeriveConversationKey computes the shared key for a peer.
//
// The private key is passed as hex because that is what the NIP-44
// implementation expects. It is not logged, stored or returned.
func DeriveConversationKey(privateKeyHex, peerPublicKeyHex string) (ConversationKey, error) {
	var key ConversationKey

	derived, err := nip44.GenerateConversationKey(peerPublicKeyHex, privateKeyHex)
	if err != nil {
		return key, fmt.Errorf("%w: %w", ErrConversationKey, err)
	}

	copy(key[:], derived[:])
	return key, nil
}

// String returns a redaction marker. A conversation key decrypts every message
// between two identities, so it is as sensitive as the identity key itself.
func (k ConversationKey) String() string { return "[REDACTED]" }

// GoString returns a redaction marker, so %#v cannot reveal the key.
func (k ConversationKey) GoString() string { return "[REDACTED]" }

// MarshalJSON refuses to serialize the key.
func (k ConversationKey) MarshalJSON() ([]byte, error) {
	return nil, errors.New("conversation key must never be serialized")
}

// Codec encrypts and decrypts protocol payloads.
type Codec struct {
	clock func() time.Time
}

// NewCodec builds a codec. A nil clock uses the system clock.
func NewCodec(clock func() time.Time) *Codec {
	if clock == nil {
		clock = time.Now
	}
	return &Codec{clock: clock}
}

// Seal encrypts a payload into an envelope.
//
// The envelope's cleartext fields are authenticated as associated data, so a
// relay or an attacker cannot re-address the result: changing the recipient,
// session, sequence or validity window invalidates the tag.
func (c *Codec) Seal(envelope protocol.Envelope, payload protocol.Payload, key ConversationKey) (protocol.Envelope, error) {
	if err := payload.MatchesEnvelope(envelope.Type); err != nil {
		return protocol.Envelope{}, err
	}

	plaintext, err := json.Marshal(payload)
	if err != nil {
		return protocol.Envelope{}, fmt.Errorf("encoding payload: %w", err)
	}
	if len(plaintext) > protocol.MaxPayloadSize {
		return protocol.Envelope{}, fmt.Errorf("%w: payload is %d bytes, limit is %d",
			protocol.ErrTooLarge, len(plaintext), protocol.MaxPayloadSize)
	}

	// NIP-44 does not take associated data, so the binding is established by
	// hashing the envelope's fields into the plaintext. A receiver recomputes
	// the hash from the envelope it actually received: if any field was
	// altered in transit, the hashes differ and the message is refused.
	bound := boundPlaintext{
		Context: contextHash(envelope),
		Payload: plaintext,
	}
	sealed, err := json.Marshal(bound)
	if err != nil {
		return protocol.Envelope{}, fmt.Errorf("binding payload: %w", err)
	}

	ciphertext, err := nip44.Encrypt(string(sealed), key)
	if err != nil {
		return protocol.Envelope{}, fmt.Errorf("encrypting payload: %w", err)
	}

	envelope.Body = ciphertext
	return envelope, nil
}

// Open decrypts and validates an envelope's payload.
//
// The envelope must already have passed ValidateEnvelope: this performs the
// expensive step, and doing it before the cheap checks would invert the
// validation order the protocol specifies.
func (c *Codec) Open(envelope protocol.Envelope, key ConversationKey) (protocol.Payload, error) {
	plaintext, err := nip44.Decrypt(envelope.Body, key)
	if err != nil {
		// The specific failure is not surfaced: distinguishing a wrong key
		// from a failed tag would let a sender probe for either.
		return protocol.Payload{}, ErrDecryption
	}

	var bound boundPlaintext
	if err := json.Unmarshal([]byte(plaintext), &bound); err != nil {
		return protocol.Payload{}, fmt.Errorf("%w: %w", protocol.ErrMalformed, err)
	}

	// Recompute the context from the envelope as received. A mismatch means a
	// cleartext field was altered after the payload was sealed.
	if bound.Context != contextHash(envelope) {
		return protocol.Payload{}, fmt.Errorf("%w: envelope context does not match the sealed payload",
			protocol.ErrMalformed)
	}

	payload, err := protocol.DecodePayload(bound.Payload)
	if err != nil {
		return protocol.Payload{}, err
	}

	if err := protocol.ValidatePayload(payload, envelope, c.clock()); err != nil {
		return protocol.Payload{}, err
	}

	return payload, nil
}

// boundPlaintext ties a payload to the envelope that carries it.
type boundPlaintext struct {
	// Context is the hash of the envelope's authenticated fields.
	Context string `json:"ctx"`

	// Payload is the encoded message.
	Payload json.RawMessage `json:"payload"`
}

// contextHash digests the envelope's associated data.
func contextHash(envelope protocol.Envelope) string {
	sum := sha256.Sum256(envelope.AssociatedData())
	return hex.EncodeToString(sum[:])
}

// OfferHash computes the hash an accept must reference.
//
// It covers the offer's terms exactly. Changing any term produces a different
// hash, so an acceptance cannot be replayed against modified terms.
func OfferHash(offer protocol.SessionOffer) (string, error) {
	encoded, err := json.Marshal(offer)
	if err != nil {
		return "", fmt.Errorf("encoding offer: %w", err)
	}

	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}
