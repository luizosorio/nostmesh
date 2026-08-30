// Package identity defines how NostMesh obtains and uses key material.
//
// The interfaces here are ports: the domain states what it needs, and adapters
// supply it. A production deployment can put the Nostr private key in an
// external signer that never hands it over, while development uses a protected
// file — without the domain knowing the difference.
package identity

import (
	"github.com/luizosorio/nostmesh/internal/domain"
)

// Signer produces signatures with the node's durable Nostr identity.
//
// The interface deliberately does not expose the private key. A hardware token
// or remote signer can implement it by signing without ever revealing key
// material, which is the whole point of keeping this a port.
type Signer interface {
	// PublicKey returns the identity this signer speaks for.
	PublicKey() domain.NostrPublicKey

	// Sign signs the given digest.
	Sign(digest []byte) ([]byte, error)
}

// TunnelKeyGenerator produces ephemeral WireGuard key pairs.
//
// Each session gets an independent pair. The private key is returned to the
// caller because the local WireGuard adapter needs it to configure the
// interface — and it goes nowhere else.
type TunnelKeyGenerator interface {
	// Generate returns a new key pair.
	Generate() (domain.WireGuardPublicKey, domain.WireGuardPrivateKey, error)
}

// Keystore persists and retrieves the node's identity.
//
// Implementations are responsible for protecting the material at rest. The
// development implementation in this package writes a file and is explicitly
// not a production backend.
type Keystore interface {
	// Load reads the stored identity.
	Load() (domain.NodeIdentity, error)

	// Store writes an identity, refusing to overwrite an existing one.
	Store(identity domain.NodeIdentity) error

	// Exists reports whether an identity is already stored.
	Exists() (bool, error)
}
