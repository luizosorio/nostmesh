package protocol

import (
	"errors"
	"fmt"
	"time"
)

// Payload is the decrypted content of an envelope.
//
// Exactly one field is set, matching the envelope's Type. Everything sensitive
// lives here rather than in the envelope, because the envelope is readable by
// every relay that handles the event.
type Payload struct {
	Request   *SessionRequest   `json:"request,omitempty"`
	Offer     *SessionOffer     `json:"offer,omitempty"`
	Accept    *SessionAccept    `json:"accept,omitempty"`
	Candidate *CandidateUpdate  `json:"candidate,omitempty"`
	Ready     *SessionReady     `json:"ready,omitempty"`
	Keepalive *SessionKeepalive `json:"keepalive,omitempty"`
	Close     *SessionClose     `json:"close,omitempty"`
	Error     *SessionError     `json:"error,omitempty"`
}

// Capabilities declares what a node supports.
//
// Negotiation is explicit rather than inferred from behaviour: a peer states
// what it can do, both sides commit to the intersection, and the commitment is
// hashed into the offer so neither side can later claim different terms.
type Capabilities struct {
	// ProtocolVersions lists the versions the sender implements.
	ProtocolVersions []int `json:"protocol_versions"`

	// Transports names the data-plane transports supported. MVP 1 has only
	// WireGuard over UDP; the field exists so a future transport is a
	// negotiation rather than a version break.
	Transports []string `json:"transports"`

	// CandidateTypes names the connectivity candidate kinds understood.
	CandidateTypes []string `json:"candidate_types"`

	// Extensions names optional features. An extension absent from this list
	// must not be assumed available.
	Extensions []string `json:"extensions,omitempty"`
}

// TunnelKey is a WireGuard public key bound to its authorizing context.
//
// The binding is the entire point. A WireGuard public key on its own is 32
// bytes that say nothing about who vouched for it, for which session, or for
// how long. Per NM-06 and ADR-003, only the public key ever appears here; the
// private key never leaves the node that generated it.
type TunnelKey struct {
	// PublicKey is the WireGuard public key, base64-encoded.
	PublicKey string `json:"public_key"`

	// Nonce is a single-use value making replay detectable.
	Nonce string `json:"nonce"`

	// ExpiresAt bounds how long this key may be used.
	ExpiresAt int64 `json:"expires_at"`
}

// SessionRequest opens a session.
type SessionRequest struct {
	// Capabilities declares what the initiator supports.
	Capabilities Capabilities `json:"capabilities"`

	// TunnelKey is the initiator's ephemeral WireGuard public key.
	TunnelKey TunnelKey `json:"tunnel_key"`

	// OverlayAddress is the address the initiator proposes for itself, in CIDR
	// notation.
	//
	// It is a proposal. The recipient derives what it actually installs from
	// local policy, per NM-04.
	OverlayAddress string `json:"overlay_address,omitempty"`
}

// SessionOffer conditionally accepts a request and commits parameters.
type SessionOffer struct {
	// Capabilities is the responder's declaration.
	Capabilities Capabilities `json:"capabilities"`

	// TunnelKey is the responder's independent ephemeral key. It is generated
	// separately and never derived from the initiator's.
	TunnelKey TunnelKey `json:"tunnel_key"`

	// OverlayAddress is the responder's proposed address.
	OverlayAddress string `json:"overlay_address,omitempty"`

	// AgreedVersion is the protocol version both sides will use.
	AgreedVersion int `json:"agreed_version"`

	// AgreedTransports is the negotiated intersection.
	AgreedTransports []string `json:"agreed_transports"`
}

// SessionAccept accepts the exact terms of an offer.
//
// It carries the offer's hash rather than restating the terms. Any change to
// the offer produces a different hash, so a substituted or modified offer
// cannot be accepted by replaying an earlier acceptance.
type SessionAccept struct {
	// OfferHash is the SHA-256 of the canonical offer encoding, hex-encoded.
	OfferHash string `json:"offer_hash"`
}

// CandidateType names how a candidate was obtained.
type CandidateType string

const (
	// CandidateHost is a local interface address.
	CandidateHost CandidateType = "host"

	// CandidateServerReflexive is an address observed by a STUN server.
	//
	// It is a claim by a third party, and stays unverified until an
	// authenticated connectivity check reaches the exact address and port.
	CandidateServerReflexive CandidateType = "srflx"

	// CandidateRelay is an allocation on a data relay.
	CandidateRelay CandidateType = "relay"

	// CandidateStatic is a manually configured endpoint.
	CandidateStatic CandidateType = "static"
)

var knownCandidateTypes = map[CandidateType]bool{
	CandidateHost:            true,
	CandidateServerReflexive: true,
	CandidateRelay:           true,
	CandidateStatic:          true,
}

// IsKnown reports whether this version understands the candidate type.
func (c CandidateType) IsKnown() bool { return knownCandidateTypes[c] }

// Candidate is one possible path to a peer.
type Candidate struct {
	// ID identifies the candidate within the session.
	ID string `json:"id"`

	// Type names how it was obtained.
	Type CandidateType `json:"type"`

	// Transport is the protocol, currently always "udp".
	Transport string `json:"transport"`

	// Address is the candidate address as host:port.
	Address string `json:"address"`

	// Priority orders candidates; lower is preferred.
	Priority uint32 `json:"priority"`

	// RelatedAddress is the base address a reflexive candidate derives from.
	RelatedAddress string `json:"related_address,omitempty"`

	// ExpiresAt bounds the candidate's usefulness.
	ExpiresAt int64 `json:"expires_at"`
}

// CandidateUpdate adds or removes candidates.
type CandidateUpdate struct {
	// Added lists new candidates.
	Added []Candidate `json:"added,omitempty"`

	// Removed lists candidate IDs no longer valid.
	Removed []string `json:"removed,omitempty"`

	// Final marks the end of gathering, so the peer can stop waiting.
	Final bool `json:"final,omitempty"`
}

// SessionReady reports that the sender confirmed the tunnel locally.
//
// It is informative only. The receiver establishes its own session when its own
// verification succeeds; a peer's word is not evidence about this host.
type SessionReady struct {
	// SelectedCandidate names the path the sender nominated.
	SelectedCandidate string `json:"selected_candidate,omitempty"`
}

// SessionKeepalive refreshes control-plane liveness.
type SessionKeepalive struct {
	// Sequence echoes the sender's view of progress.
	Sequence uint64 `json:"sequence"`
}

// CloseReason is a stable code explaining a close.
type CloseReason string

const (
	// CloseNormal is an orderly shutdown.
	CloseNormal CloseReason = "normal"

	// CloseTimeout means the peer stopped responding.
	CloseTimeout CloseReason = "timeout"

	// ClosePolicy means local policy withdrew authorization.
	ClosePolicy CloseReason = "policy"

	// CloseSuperseded means a newer session replaced this one.
	CloseSuperseded CloseReason = "superseded"

	// CloseError means an unrecoverable error occurred.
	CloseError CloseReason = "error"
)

// SessionClose ends a session.
type SessionClose struct {
	// Reason is a stable code. Free-form text is deliberately absent: it would
	// invite leaking internal state to a peer.
	Reason CloseReason `json:"reason"`
}

// ErrorCode is a stable, enumerable error identifier.
//
// Codes are coarse on purpose. A precise error tells an attacker which of their
// guesses was closer, so the wire carries a category while the detail stays in
// local logs.
type ErrorCode string

const (
	// ErrorUnsupportedVersion means the version is not implemented.
	ErrorUnsupportedVersion ErrorCode = "unsupported_version"

	// ErrorUnauthorized means local policy refused.
	ErrorUnauthorized ErrorCode = "unauthorized"

	// ErrorMalformed means the message could not be parsed or validated.
	ErrorMalformed ErrorCode = "malformed"

	// ErrorExpired means the message fell outside its validity window.
	ErrorExpired ErrorCode = "expired"

	// ErrorReplay means the message was already seen.
	ErrorReplay ErrorCode = "replay"

	// ErrorUnsupportedCapability means no common capability set exists.
	ErrorUnsupportedCapability ErrorCode = "unsupported_capability"

	// ErrorInternal means the sender failed for a reason it will not disclose.
	ErrorInternal ErrorCode = "internal"
)

// SessionError reports a sanitized failure.
type SessionError struct {
	// Code is the stable category.
	Code ErrorCode `json:"code"`
}

var (
	// ErrEmptyPayload reports a payload with no message set.
	ErrEmptyPayload = errors.New("payload carries no message")

	// ErrMultiplePayloads reports a payload with more than one message set.
	ErrMultiplePayloads = errors.New("payload carries more than one message")

	// ErrTypeMismatch reports a payload that does not match the envelope type.
	ErrTypeMismatch = errors.New("payload does not match the envelope type")
)

// TypeOf returns the message type the payload carries.
func (p Payload) TypeOf() (MessageType, error) {
	var (
		found MessageType
		count int
	)

	set := []struct {
		present bool
		kind    MessageType
	}{
		{p.Request != nil, TypeSessionRequest},
		{p.Offer != nil, TypeSessionOffer},
		{p.Accept != nil, TypeSessionAccept},
		{p.Candidate != nil, TypeCandidateUpdate},
		{p.Ready != nil, TypeSessionReady},
		{p.Keepalive != nil, TypeSessionKeepalive},
		{p.Close != nil, TypeSessionClose},
		{p.Error != nil, TypeSessionError},
	}

	for _, entry := range set {
		if entry.present {
			found = entry.kind
			count++
		}
	}

	switch count {
	case 0:
		return "", ErrEmptyPayload
	case 1:
		return found, nil
	default:
		return "", ErrMultiplePayloads
	}
}

// MatchesEnvelope checks the payload against the envelope's declared type.
//
// The type appears in the clear so relays can route, and inside the encrypted
// payload so it is authenticated. A mismatch means one of the two was tampered
// with, and the message is refused.
func (p Payload) MatchesEnvelope(declared MessageType) error {
	actual, err := p.TypeOf()
	if err != nil {
		return err
	}
	if actual != declared {
		return fmt.Errorf("%w: envelope says %s, payload carries %s", ErrTypeMismatch, declared, actual)
	}
	return nil
}

// ExpiryTime returns the tunnel key's expiry.
func (t TunnelKey) ExpiryTime() time.Time { return time.Unix(t.ExpiresAt, 0).UTC() }

// IsExpired reports whether the tunnel key has expired.
func (t TunnelKey) IsExpired(now time.Time) bool { return !now.Before(t.ExpiryTime()) }
