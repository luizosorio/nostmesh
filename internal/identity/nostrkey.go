package identity

import (
	"errors"

	"github.com/luizosorio/nostmesh/internal/domain"
)

// ErrNoSigner reports that no Nostr signing backend is configured.
var ErrNoSigner = errors.New("no nostr signing backend is configured")

// ErrPlaceholderIdentity reports an identity created before real key
// derivation existed.
//
// The development placeholder produced a SHA-256 digest rather than a
// secp256k1 point. Such an identity cannot sign, cannot be addressed by a peer,
// and must not be treated as valid — silently accepting one would produce a
// node that appears configured and can never communicate.
var ErrPlaceholderIdentity = errors.New("identity was created by the development placeholder and must be regenerated")

// DeriveNostrPublicKey computes the public key for a Nostr private key.
//
// Derivation lives in internal/nostr, which owns the secp256k1 dependency. This
// indirection keeps the identity package free of it, so the keystore stays
// testable without cryptography.
//
// The function value is injected by the caller that has both packages in scope.
// It is a variable rather than a direct import because internal/identity must
// not depend on the transport package (NM-10).
var DeriveNostrPublicKey func(domain.NostrPrivateKey) (domain.NostrPublicKey, error)

// deriveOrFail returns the configured derivation, or an error explaining what
// is missing rather than producing a key that cannot sign.
func deriveOrFail(private domain.NostrPrivateKey) (domain.NostrPublicKey, error) {
	if DeriveNostrPublicKey == nil {
		return domain.NostrPublicKey{}, ErrNoSigner
	}
	return DeriveNostrPublicKey(private)
}

// VerifyStoredIdentity checks that a stored identity's public key matches what
// its private key actually derives.
//
// A mismatch means the identity predates real derivation: the stored public key
// is a placeholder digest with no corresponding curve point. Detecting that here
// turns a confusing runtime failure — events signed but never accepted — into a
// clear instruction to regenerate.
func VerifyStoredIdentity(identity domain.NodeIdentity) error {
	derived, err := deriveOrFail(identity.PrivateKey())
	if err != nil {
		return err
	}

	if derived != identity.PublicKey() {
		return ErrPlaceholderIdentity
	}
	return nil
}
