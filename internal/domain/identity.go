package domain

import (
	"errors"
	"fmt"
	"time"
)

var (
	// ErrIdentityIncomplete reports an identity missing required material.
	ErrIdentityIncomplete = errors.New("identity is incomplete")

	// ErrKeyReuse reports the same secret material appearing in both the Nostr
	// and WireGuard roles. Per ADR-003 this must never happen.
	ErrKeyReuse = errors.New("nostr and wireguard keys must not share material")
)

// NodeIdentity is this node's durable identity on the control plane.
//
// It holds the private key, so it never leaves the process that owns it.
type NodeIdentity struct {
	public  NostrPublicKey
	private NostrPrivateKey
	created time.Time
}

// NewNodeIdentity pairs a public key with its private key.
func NewNodeIdentity(public NostrPublicKey, private NostrPrivateKey, created time.Time) (NodeIdentity, error) {
	if public.IsZero() {
		return NodeIdentity{}, fmt.Errorf("%w: missing public key", ErrIdentityIncomplete)
	}
	if private.IsDestroyed() {
		return NodeIdentity{}, fmt.Errorf("%w: private key destroyed", ErrIdentityIncomplete)
	}
	if created.IsZero() {
		return NodeIdentity{}, fmt.Errorf("%w: missing creation time", ErrIdentityIncomplete)
	}
	return NodeIdentity{public: public, private: private, created: created}, nil
}

// PublicKey returns the identity's public key.
func (n NodeIdentity) PublicKey() NostrPublicKey { return n.public }

// PrivateKey returns the identity's private key. Callers must not log, store or
// transmit it.
func (n NodeIdentity) PrivateKey() NostrPrivateKey { return n.private }

// CreatedAt returns when the identity was generated.
func (n NodeIdentity) CreatedAt() time.Time { return n.created }

// String renders the identity without its secret.
func (n NodeIdentity) String() string {
	return fmt.Sprintf("NodeIdentity{pubkey: %s}", n.public.Short())
}

// PeerIdentity is a remote participant this node may interact with.
//
// It carries only public material: a peer is known by its Nostr public key, and
// nothing about it is secret.
type PeerIdentity struct {
	public NostrPublicKey
	alias  string
}

// NewPeerIdentity builds a peer identity. The alias is a local label with no
// authority; it never participates in an authorization decision.
func NewPeerIdentity(public NostrPublicKey, alias string) (PeerIdentity, error) {
	if public.IsZero() {
		return PeerIdentity{}, fmt.Errorf("%w: missing public key", ErrIdentityIncomplete)
	}
	return PeerIdentity{public: public, alias: alias}, nil
}

// PublicKey returns the peer's public key.
func (p PeerIdentity) PublicKey() NostrPublicKey { return p.public }

// Alias returns the local label for this peer.
func (p PeerIdentity) Alias() string { return p.alias }

// String renders the peer for logs.
func (p PeerIdentity) String() string {
	if p.alias != "" {
		return fmt.Sprintf("PeerIdentity{%s, pubkey: %s}", p.alias, p.public.Short())
	}
	return fmt.Sprintf("PeerIdentity{pubkey: %s}", p.public.Short())
}

// TunnelKeyBinding ties an ephemeral WireGuard public key to the session and
// the identities that authorized it.
//
// This is the structure ADR-003 requires. Without the binding, a WireGuard
// public key is just 32 bytes: it says nothing about who vouched for it, for
// which session, or for how long. Validating the binding is what stops a key
// from being replayed into a different session or attributed to a different
// peer.
type TunnelKeyBinding struct {
	sessionID SessionID
	sender    NostrPublicKey
	recipient NostrPublicKey
	publicKey WireGuardPublicKey
	createdAt time.Time
	expiresAt time.Time
	nonce     Nonce
	sequence  uint64
}

// TunnelKeyBindingParams carries the values needed to build a binding. Every
// field is required; the constructor rejects an incomplete binding rather than
// letting a partially specified authorization exist.
type TunnelKeyBindingParams struct {
	SessionID SessionID
	Sender    NostrPublicKey
	Recipient NostrPublicKey
	PublicKey WireGuardPublicKey
	CreatedAt time.Time
	ExpiresAt time.Time
	Nonce     Nonce
	Sequence  uint64
}

// NewTunnelKeyBinding validates and builds a binding.
func NewTunnelKeyBinding(p TunnelKeyBindingParams) (TunnelKeyBinding, error) {
	switch {
	case p.SessionID.IsZero():
		return TunnelKeyBinding{}, errors.New("binding requires a session id")
	case p.Sender.IsZero():
		return TunnelKeyBinding{}, errors.New("binding requires a sender")
	case p.Recipient.IsZero():
		return TunnelKeyBinding{}, errors.New("binding requires a recipient")
	case p.PublicKey.IsZero():
		return TunnelKeyBinding{}, errors.New("binding requires a wireguard public key")
	case p.Nonce.IsZero():
		return TunnelKeyBinding{}, errors.New("binding requires a nonce")
	case p.CreatedAt.IsZero():
		return TunnelKeyBinding{}, errors.New("binding requires a creation time")
	case p.ExpiresAt.IsZero():
		return TunnelKeyBinding{}, errors.New("binding requires an expiry")
	case !p.ExpiresAt.After(p.CreatedAt):
		return TunnelKeyBinding{}, fmt.Errorf("binding expires at %s, before or at its creation %s", p.ExpiresAt, p.CreatedAt)
	case p.Sender == p.Recipient:
		return TunnelKeyBinding{}, errors.New("binding sender and recipient must differ")
	}

	return TunnelKeyBinding{
		sessionID: p.SessionID,
		sender:    p.Sender,
		recipient: p.Recipient,
		publicKey: p.PublicKey,
		createdAt: p.CreatedAt,
		expiresAt: p.ExpiresAt,
		nonce:     p.Nonce,
		sequence:  p.Sequence,
	}, nil
}

// SessionID returns the session this binding authorizes.
func (b TunnelKeyBinding) SessionID() SessionID { return b.sessionID }

// Sender returns the identity that authorized the key.
func (b TunnelKeyBinding) Sender() NostrPublicKey { return b.sender }

// Recipient returns the identity the binding is addressed to.
func (b TunnelKeyBinding) Recipient() NostrPublicKey { return b.recipient }

// PublicKey returns the bound WireGuard public key.
func (b TunnelKeyBinding) PublicKey() WireGuardPublicKey { return b.publicKey }

// ExpiresAt returns when the binding stops being valid.
func (b TunnelKeyBinding) ExpiresAt() time.Time { return b.expiresAt }

// Sequence returns the binding's monotonic sequence number.
func (b TunnelKeyBinding) Sequence() uint64 { return b.sequence }

// IsExpired reports whether the binding has expired at the given time.
func (b TunnelKeyBinding) IsExpired(now time.Time) bool {
	return !now.Before(b.expiresAt)
}

// ValidateFor checks the binding against the local context before it can have
// any effect.
//
// A valid signature proves who made the proposal; it does not prove the
// proposal applies here. This check is what turns an authenticated message into
// an authorized one: the binding must name this session, be addressed to this
// node, come from the expected peer, and still be within its validity window.
func (b TunnelKeyBinding) ValidateFor(session SessionID, localNode, expectedPeer NostrPublicKey, now time.Time) error {
	switch {
	case b.sessionID != session:
		return fmt.Errorf("binding is for session %s, not %s", b.sessionID.Short(), session.Short())
	case b.recipient != localNode:
		return fmt.Errorf("binding is addressed to %s, not to this node", b.recipient.Short())
	case b.sender != expectedPeer:
		return fmt.Errorf("binding is from %s, not from the expected peer %s", b.sender.Short(), expectedPeer.Short())
	case b.IsExpired(now):
		return fmt.Errorf("binding expired at %s", b.expiresAt.Format(time.RFC3339))
	}
	return nil
}

// String renders the binding for logs, without secret material. The WireGuard
// public key is not secret, but it is abbreviated to keep log lines readable.
func (b TunnelKeyBinding) String() string {
	return fmt.Sprintf("TunnelKeyBinding{session: %s, from: %s, to: %s, wg: %s, seq: %d}",
		b.sessionID.Short(), b.sender.Short(), b.recipient.Short(), b.publicKey.Short(), b.sequence)
}
