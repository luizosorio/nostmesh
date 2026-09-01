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
