package session

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/luizosorio/nostmesh/internal/domain"
	"github.com/luizosorio/nostmesh/internal/protocol"
)

// Capabilities this build declares.
func localCapabilities() protocol.Capabilities {
	return protocol.Capabilities{
		ProtocolVersions: []int{protocol.Version},
		Transports:       []string{"wireguard/udp"},
		CandidateTypes:   []string{"host", "static"},
	}
}

// BuildRequest produces the opening message.
//
// Only the tunnel *public* key goes in, bound to the session and given an
// expiry. The private half stays in the handshake.
func (h *Handshake) BuildRequest(nonce domain.Nonce, keyLifetime time.Duration, now time.Time) (protocol.Payload, error) {
	if err := h.checkAlive(now); err != nil {
		return protocol.Payload{}, err
	}
	if h.role != RoleInitiator {
		return protocol.Payload{}, fmt.Errorf("%w: only an initiator sends a request", ErrUnexpectedMessage)
	}
	if h.state != StateIdle {
		return protocol.Payload{}, fmt.Errorf("%w: cannot request in state %s", ErrUnexpectedMessage, h.state)
	}

	payload := protocol.Payload{Request: &protocol.SessionRequest{
		Capabilities: localCapabilities(),
		TunnelKey: protocol.TunnelKey{
			PublicKey: h.localTunnelPublic.String(),
			Nonce:     nonce.String(),
			ExpiresAt: now.Add(keyLifetime).Unix(),
		},
	}}

	h.state = StateRequestSent
	h.updatedAt = now
	return payload, nil
}

// ReceiveRequest handles an incoming request.
//
// Authorization happens here, before anything is committed. Deny-by-default:
// a peer absent from local policy is refused, and no state changes.
func (h *Handshake) ReceiveRequest(request protocol.SessionRequest, seq uint64,
	authorizer Authorizer, now time.Time,
) error {
	if err := h.checkAlive(now); err != nil {
		return err
	}
	if h.role != RoleResponder {
		return fmt.Errorf("%w: only a responder receives a request", ErrUnexpectedMessage)
	}
	if h.state != StateIdle {
		return fmt.Errorf("%w: cannot accept a request in state %s", ErrUnexpectedMessage, h.state)
	}

	// Policy first. Everything after this point commits state, and a peer we
	// will refuse anyway must not be able to make us do that work.
	if authorizer != nil {
		if err := authorizer.Authorize(h.peerKey); err != nil {
			return fmt.Errorf("%w: %w", ErrUnauthorized, err)
		}
	}

	if err := h.recordSeq(seq, request); err != nil {
		return err
	}
	if err := h.bindPeerTunnelKey(request.TunnelKey, now); err != nil {
		return err
	}

	h.state = StateRequestReceived
	h.updatedAt = now
	return nil
}

// BuildOffer produces the responder's commitment to parameters.
func (h *Handshake) BuildOffer(nonce domain.Nonce, keyLifetime time.Duration, now time.Time) (protocol.Payload, string, error) {
	if err := h.checkAlive(now); err != nil {
		return protocol.Payload{}, "", err
	}
	if h.role != RoleResponder {
		return protocol.Payload{}, "", fmt.Errorf("%w: only a responder sends an offer", ErrUnexpectedMessage)
	}
	if h.state != StateRequestReceived {
		return protocol.Payload{}, "", fmt.Errorf("%w: cannot offer in state %s", ErrUnexpectedMessage, h.state)
	}

	offer := protocol.SessionOffer{
		Capabilities: localCapabilities(),
		TunnelKey: protocol.TunnelKey{
			PublicKey: h.localTunnelPublic.String(),
			Nonce:     nonce.String(),
			ExpiresAt: now.Add(keyLifetime).Unix(),
		},
		AgreedVersion:    protocol.Version,
		AgreedTransports: []string{"wireguard/udp"},
	}

	hash, err := HashOffer(offer)
	if err != nil {
		return protocol.Payload{}, "", err
	}

	h.offerHash = hash
	h.state = StateOfferSent
	h.updatedAt = now

	return protocol.Payload{Offer: &offer}, hash, nil
}

// ReceiveOffer handles the responder's offer.
func (h *Handshake) ReceiveOffer(offer protocol.SessionOffer, seq uint64, now time.Time) error {
	if err := h.checkAlive(now); err != nil {
		return err
	}
	if h.role != RoleInitiator {
		return fmt.Errorf("%w: only an initiator receives an offer", ErrUnexpectedMessage)
	}
	if h.state != StateRequestSent {
		return fmt.Errorf("%w: cannot accept an offer in state %s", ErrUnexpectedMessage, h.state)
	}

	if err := h.recordSeq(seq, offer); err != nil {
		return err
	}
	if err := h.bindPeerTunnelKey(offer.TunnelKey, now); err != nil {
		return err
	}

	hash, err := HashOffer(offer)
	if err != nil {
		return err
	}

	h.offerHash = hash
	h.state = StateOfferReceived
	h.updatedAt = now
	return nil
}

// BuildAccept produces the initiator's acceptance.
//
// It carries the offer's hash rather than restating the terms, so accepting
// modified terms is impossible: a different offer hashes differently.
func (h *Handshake) BuildAccept(now time.Time) (protocol.Payload, error) {
	if err := h.checkAlive(now); err != nil {
		return protocol.Payload{}, err
	}
	if h.role != RoleInitiator {
		return protocol.Payload{}, fmt.Errorf("%w: only an initiator accepts", ErrUnexpectedMessage)
	}
	if h.state != StateOfferReceived {
		return protocol.Payload{}, fmt.Errorf("%w: cannot accept in state %s", ErrUnexpectedMessage, h.state)
	}

	payload := protocol.Payload{Accept: &protocol.SessionAccept{OfferHash: h.offerHash}}

	h.state = StateConnecting
	h.updatedAt = now
	return payload, nil
}

// ReceiveAccept handles the initiator's acceptance.
func (h *Handshake) ReceiveAccept(accept protocol.SessionAccept, seq uint64, now time.Time) error {
	if err := h.checkAlive(now); err != nil {
		return err
	}
	if h.role != RoleResponder {
		return fmt.Errorf("%w: only a responder receives an acceptance", ErrUnexpectedMessage)
	}
	if h.state != StateOfferSent {
		return fmt.Errorf("%w: cannot process an acceptance in state %s", ErrUnexpectedMessage, h.state)
	}
	if err := h.recordSeq(seq, accept); err != nil {
		return err
	}

	// The acceptance must reference exactly what was offered. A different hash
	// means the peer is accepting terms this node never proposed.
	if accept.OfferHash != h.offerHash {
		return fmt.Errorf("%w: accepted %s, offered %s",
			ErrOfferMismatch, abbreviate(accept.OfferHash), abbreviate(h.offerHash))
	}

	h.state = StateConnecting
	h.updatedAt = now
	return nil
}

// ConfirmEstablished records that this node verified the tunnel locally.
//
// Only local verification establishes a session. A peer's session.ready is
// informative: it says the peer believes its side works, which is not evidence
// about this host.
func (h *Handshake) ConfirmEstablished(now time.Time) error {
	if err := h.checkAlive(now); err != nil {
		return err
	}
	if h.state != StateConnecting {
		return fmt.Errorf("%w: cannot establish from state %s", ErrUnexpectedMessage, h.state)
	}

	h.state = StateEstablished
	h.updatedAt = now
	return nil
}

// ReceiveReady notes that the peer reported its side ready.
//
// It changes no state. Recording it separately from establishment is the point:
// conflating the two would let a peer declare this node's tunnel working.
func (h *Handshake) ReceiveReady(seq uint64, now time.Time) error {
	if err := h.checkAlive(now); err != nil {
		return err
	}
	if h.state != StateConnecting && h.state != StateEstablished {
		return fmt.Errorf("%w: ready in state %s", ErrUnexpectedMessage, h.state)
	}
	return h.recordSeq(seq, "ready")
}

// bindPeerTunnelKey validates and stores the peer's tunnel key.
//
// Substitution is the attack this prevents. Once a key is bound, a later
// message carrying a different one is refused: an attacker who intercepts the
// handshake cannot swap in their own key and take over the tunnel.
func (h *Handshake) bindPeerTunnelKey(key protocol.TunnelKey, now time.Time) error {
	parsed, err := domain.ParseWireGuardPublicKey(key.PublicKey)
	if err != nil {
		return fmt.Errorf("peer tunnel key: %w", err)
	}
	if parsed.IsZero() {
		return fmt.Errorf("peer tunnel key is all zeros")
	}
	if key.IsExpired(now) {
		return fmt.Errorf("%w: peer tunnel key expired at %s",
			protocol.ErrExpired, key.ExpiryTime().Format(time.RFC3339))
	}

	if h.peerTunnel != nil && h.peerTunnel.PublicKey != key.PublicKey {
		return fmt.Errorf("%w: was %s, now %s",
			ErrKeySubstituted, abbreviate(h.peerTunnel.PublicKey), abbreviate(key.PublicKey))
	}

	// The tunnel key must differ from this node's own. Sharing one would mean
	// both ends hold the same private key, which is not a tunnel.
	if parsed == h.localTunnelPublic {
		return fmt.Errorf("%w: peer offered this node's own tunnel key", ErrKeySubstituted)
	}

	h.peerTunnel = &key
	return nil
}

// recordSeq enforces monotonic, non-conflicting sequence numbers.
//
// An identical repeat is idempotent, because relays deliver duplicates by
// design. Different content at the same sequence is a conflict: one of the two
// messages is not what it claims, and the session's ordering is no longer
// trustworthy.
func (h *Handshake) recordSeq(seq uint64, content any) error {
	digest, err := contentDigest(content)
	if err != nil {
		return err
	}

	if previous, seen := h.seenSeq[seq]; seen {
		if previous == digest {
			// A duplicate delivery. Expected, and harmless.
			return nil
		}
		return fmt.Errorf("%w: sequence %d carries different content than before", ErrSequenceConflict, seq)
	}

	h.seenSeq[seq] = digest
	return nil
}

// checkAlive refuses to act on a terminal or expired handshake.
//
// Every transition calls this first. A finished or expired handshake accepts
// nothing regardless of the message, and saying so precisely beats reporting
// "unexpected message" — a caller distinguishing the two acts differently:
// a timeout is worth retrying with a new session, an unexpected message is not.
func (h *Handshake) checkAlive(now time.Time) error {
	if h.state.IsTerminal() {
		return fmt.Errorf("%w: %s", ErrTerminal, h.state)
	}
	if h.IsExpired(now) {
		return fmt.Errorf("%w: deadline was %s", ErrTimeout, h.deadline.Format(time.RFC3339))
	}
	return nil
}

// HashOffer computes the digest an acceptance must reference.
func HashOffer(offer protocol.SessionOffer) (string, error) {
	encoded, err := json.Marshal(offer)
	if err != nil {
		return "", fmt.Errorf("encoding offer: %w", err)
	}

	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

func contentDigest(content any) (string, error) {
	encoded, err := json.Marshal(content)
	if err != nil {
		return "", fmt.Errorf("digesting message content: %w", err)
	}

	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

// abbreviate shortens a value for an error message.
func abbreviate(value string) string {
	if len(value) <= 8 {
		return value
	}
	return value[:8]
}
