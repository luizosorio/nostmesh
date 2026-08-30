package identity

import (
	"crypto/sha256"
	"errors"

	"github.com/luizosorio/nostmesh/internal/domain"
)

// ErrNoSigner reports that no Nostr signing backend is configured.
var ErrNoSigner = errors.New("no nostr signing backend is configured")

// DeriveNostrPublicKey computes the public key for a Nostr private key.
//
// Nostr public keys are x-only secp256k1 points, and deriving one requires a
// secp256k1 implementation. That belongs to the signing adapter introduced in
// M1.1, alongside event signing and NIP-44 encryption — the same library will
// serve all three, and adopting one now would fix that choice before the
// protocol work that should inform it.
//
// Until then this returns a deterministic development placeholder: a SHA-256
// digest of the private key, domain-separated so it can never be mistaken for a
// real secp256k1 point. It exercises the keystore end to end, and it is not a
// valid Nostr identity.
//
// Every caller in MVP 0 is local-only: nothing generated here reaches a relay,
// a peer, or an authorization decision. M1.1 replaces this with real derivation
// and must invalidate any identity created by it.
func DeriveNostrPublicKey(private domain.NostrPrivateKey) (domain.NostrPublicKey, error) {
	var public domain.NostrPublicKey

	raw, err := private.Bytes()
	if err != nil {
		return public, err
	}
	defer zero(raw)

	digest := sha256.Sum256(append([]byte("nostmesh-dev-placeholder-v1|"), raw...))
	copy(public[:], digest[:])

	if public.IsZero() {
		return domain.NostrPublicKey{}, errors.New("derived placeholder key is zero")
	}
	return public, nil
}
