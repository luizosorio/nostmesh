// Package session drives the control-plane handshake.
//
// It is pure: it decides what message to send next and what a received message
// means, but it neither publishes nor configures anything. Effects belong to
// the orchestrator, which is what lets every transition be tested without a
// relay or a kernel.
package session

import (
	"errors"
	"fmt"
	"time"

	"github.com/luizosorio/nostmesh/internal/domain"
	"github.com/luizosorio/nostmesh/internal/protocol"
)

// Role is which side of the handshake a node is on.
type Role uint8

const (
	// RoleInitiator opened the session.
	RoleInitiator Role = iota

	// RoleResponder was asked to open one.
	RoleResponder
)

// String returns the role name.
func (r Role) String() string {
	if r == RoleInitiator {
		return "initiator"
	}
	return "responder"
}

// State is where a handshake stands.
//
// The protocol's states, distinct from the tunnel lifecycle in internal/domain:
// this machine ends where that one begins.
type State uint8

const (
	// StateIdle is before anything was sent or received.
	StateIdle State = iota

	// StateRequestSent means the initiator is waiting for an offer.
	StateRequestSent

	// StateRequestReceived means the responder is deciding.
	StateRequestReceived

	// StateOfferSent means the responder is waiting for an acceptance.
	StateOfferSent

	// StateOfferReceived means the initiator is deciding.
	StateOfferReceived

	// StateConnecting means both sides agreed and are establishing the tunnel.
	StateConnecting

	// StateEstablished means this node verified the tunnel locally.
	//
	// It is never entered because a peer said it was ready. A peer's word is
	// evidence about the peer, not about this host.
	StateEstablished

	// StateClosed is terminal.
	StateClosed

	// StateFailed is terminal and carries a reason.
	StateFailed
)

var stateNames = map[State]string{
	StateIdle:            "IDLE",
	StateRequestSent:     "REQUEST_SENT",
	StateRequestReceived: "REQUEST_RECEIVED",
	StateOfferSent:       "OFFER_SENT",
	StateOfferReceived:   "OFFER_RECEIVED",
	StateConnecting:      "CONNECTING",
	StateEstablished:     "ESTABLISHED",
	StateClosed:          "CLOSED",
	StateFailed:          "FAILED",
}

// String returns the state name.
func (s State) String() string {
	if name, ok := stateNames[s]; ok {
		return name
	}
	return fmt.Sprintf("State(%d)", uint8(s))
}

// IsTerminal reports whether the state can never transition again.
func (s State) IsTerminal() bool { return s == StateClosed || s == StateFailed }

var (
	// ErrUnexpectedMessage reports a message the current state does not accept.
	// The handshake is left untouched.
	ErrUnexpectedMessage = errors.New("unexpected message for the current state")

	// ErrTerminal reports an attempt to act on a finished handshake.
	ErrTerminal = errors.New("handshake is in a terminal state")

	// ErrUnauthorized reports an identity local policy does not allow.
	ErrUnauthorized = errors.New("peer is not authorized")

	// ErrSequenceConflict reports a message claiming a used sequence number
	// with different content.
	ErrSequenceConflict = errors.New("sequence number conflict")

	// ErrOfferMismatch reports an acceptance referencing different terms than
	// were offered.
	ErrOfferMismatch = errors.New("acceptance does not match the offer")

	// ErrKeySubstituted reports a tunnel key that changed mid-handshake.
	ErrKeySubstituted = errors.New("tunnel key was substituted")

	// ErrTimeout reports a handshake that made no progress in time.
	ErrTimeout = errors.New("handshake timed out")
)

// Authorizer decides whether a peer may open a session.
//
// Deny-by-default: an identity absent from local policy is refused. A valid
// signature proves who is asking, not that they may.
type Authorizer interface {
	// Authorize reports whether the peer is allowed.
	Authorize(peer domain.NostrPublicKey) error
}

// Handshake tracks one session negotiation.
type Handshake struct {
	role      Role
	sessionID domain.SessionID
	localKey  domain.NostrPublicKey
	peerKey   domain.NostrPublicKey

	state State

	// localTunnel is this node's ephemeral key pair. The private half never
	// leaves this struct, and never leaves the process.
	localTunnelPublic  domain.WireGuardPublicKey
	localTunnelPrivate domain.WireGuardPrivateKey

	// peerTunnel is the peer's public key, once bound and validated.
	peerTunnel *protocol.TunnelKey

	// offerHash pins the terms both sides committed to.
	offerHash string

	// nextSeq is the sequence number this node will send next.
	nextSeq uint64

	// seenSeq records what the peer has sent, so a repeat with different
	// content is detectable.
	seenSeq map[uint64]string

	createdAt time.Time
	updatedAt time.Time
	deadline  time.Time

	failure string
}

// Options configures a Handshake.
type Options struct {
	Role      Role
	SessionID domain.SessionID
	LocalKey  domain.NostrPublicKey
	PeerKey   domain.NostrPublicKey

	// TunnelPublic and TunnelPrivate are this session's ephemeral WireGuard
	// key pair. Each session generates its own; a key never carries across.
	TunnelPublic  domain.WireGuardPublicKey
	TunnelPrivate domain.WireGuardPrivateKey

	// Timeout bounds the whole handshake. Without it a peer that goes silent
	// leaves a session pending forever.
	Timeout time.Duration

	Now time.Time
}

const defaultTimeout = 60 * time.Second

// New builds a Handshake in StateIdle.
func New(opts Options) (*Handshake, error) {
	switch {
	case opts.SessionID.IsZero():
		return nil, errors.New("handshake requires a session id")
	case opts.LocalKey.IsZero():
		return nil, errors.New("handshake requires a local identity")
	case opts.PeerKey.IsZero():
		return nil, errors.New("handshake requires a peer identity")
	case opts.LocalKey == opts.PeerKey:
		return nil, errors.New("handshake requires two distinct identities")
	case opts.TunnelPublic.IsZero():
		return nil, errors.New("handshake requires a tunnel key")
	}

	if opts.Timeout <= 0 {
		opts.Timeout = defaultTimeout
	}
	if opts.Now.IsZero() {
		return nil, errors.New("handshake requires a clock reading")
	}

	return &Handshake{
		role:               opts.Role,
		sessionID:          opts.SessionID,
		localKey:           opts.LocalKey,
		peerKey:            opts.PeerKey,
		localTunnelPublic:  opts.TunnelPublic,
		localTunnelPrivate: opts.TunnelPrivate,
		state:              StateIdle,
		seenSeq:            make(map[uint64]string),
		createdAt:          opts.Now,
		updatedAt:          opts.Now,
		deadline:           opts.Now.Add(opts.Timeout),
	}, nil
}

// State returns the current state.
func (h *Handshake) State() State { return h.state }

// Role returns which side this is.
func (h *Handshake) Role() Role { return h.role }

// SessionID returns the session identifier.
func (h *Handshake) SessionID() domain.SessionID { return h.sessionID }

// PeerKey returns the remote identity.
func (h *Handshake) PeerKey() domain.NostrPublicKey { return h.peerKey }

// PeerTunnelKey returns the peer's tunnel key, or nil if not yet bound.
func (h *Handshake) PeerTunnelKey() *protocol.TunnelKey { return h.peerTunnel }

// LocalTunnelPrivate returns this node's tunnel private key.
//
// The caller is the WireGuard adapter, which needs it to configure the kernel.
// It goes nowhere else: not into an event, a log, the journal, or a diagnostic.
func (h *Handshake) LocalTunnelPrivate() domain.WireGuardPrivateKey { return h.localTunnelPrivate }

// LocalTunnelPublic returns this node's tunnel public key.
func (h *Handshake) LocalTunnelPublic() domain.WireGuardPublicKey { return h.localTunnelPublic }

// OfferHash returns the committed terms, once agreed.
func (h *Handshake) OfferHash() string { return h.offerHash }

// NextSeq returns and consumes the next outbound sequence number.
func (h *Handshake) NextSeq() uint64 {
	seq := h.nextSeq
	h.nextSeq++
	return seq
}

// FailureReason returns why the handshake failed, or an empty string.
func (h *Handshake) FailureReason() string { return h.failure }

// IsExpired reports whether the handshake ran out of time.
func (h *Handshake) IsExpired(now time.Time) bool { return !now.Before(h.deadline) }

// String renders the handshake for logs, without secret material.
func (h *Handshake) String() string {
	return fmt.Sprintf("Handshake{session: %s, role: %s, peer: %s, state: %s}",
		h.sessionID.Short(), h.role, h.peerKey.Short(), h.state)
}

// Fail moves the handshake to StateFailed.
func (h *Handshake) Fail(reason string, now time.Time) {
	h.state = StateFailed
	h.failure = reason
	h.updatedAt = now
}

// Close moves the handshake to StateClosed.
func (h *Handshake) Close(now time.Time) {
	h.state = StateClosed
	h.updatedAt = now
}
