package nostr

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"

	"github.com/luizosorio/nostmesh/internal/domain"
)

var (
	// ErrInvalidSignature reports a signature that does not verify.
	ErrInvalidSignature = errors.New("signature does not verify")

	// ErrInvalidKey reports key material that is not a valid secp256k1 value.
	ErrInvalidKey = errors.New("invalid secp256k1 key")
)

// Signer produces Schnorr signatures with a Nostr identity.
//
// It supersedes the development placeholder recorded in NM-07: public keys are
// now real secp256k1 x-only points, so an identity created before this exists
// cannot sign and must be regenerated.
type Signer struct {
	private *btcec.PrivateKey
	public  domain.NostrPublicKey
}

// NewSigner builds a signer from a Nostr private key.
func NewSigner(private domain.NostrPrivateKey) (*Signer, error) {
	raw, err := private.Bytes()
	if err != nil {
		return nil, fmt.Errorf("reading identity key: %w", err)
	}
	defer zero(raw)

	key, publicKey := btcec.PrivKeyFromBytes(raw)
	if key == nil {
		return nil, ErrInvalidKey
	}

	// Nostr uses x-only public keys: the 32-byte x coordinate, with the y
	// parity discarded. Two different private keys can therefore produce the
	// same public key, which is why the protocol authenticates by signature
	// rather than by key equality alone.
	var public domain.NostrPublicKey
	copy(public[:], schnorr.SerializePubKey(publicKey))

	return &Signer{private: key, public: public}, nil
}

// PublicKey returns the identity this signer speaks for.
func (s *Signer) PublicKey() domain.NostrPublicKey { return s.public }

// Sign signs a digest.
//
// The caller supplies the digest rather than the message, because what gets
// signed in Nostr is a specific canonical serialization: signing anything else
// would produce a signature no other implementation accepts.
func (s *Signer) Sign(digest []byte) ([]byte, error) {
	if len(digest) != sha256.Size {
		return nil, fmt.Errorf("digest must be %d bytes, got %d", sha256.Size, len(digest))
	}

	signature, err := schnorr.Sign(s.private, digest)
	if err != nil {
		return nil, fmt.Errorf("signing: %w", err)
	}
	return signature.Serialize(), nil
}

// Verify checks a signature against a public key and digest.
//
// This is where an event's authorship is established. Everything downstream —
// policy, session state, network effects — depends on it, so it happens before
// any of them and its failure is terminal for the message.
func Verify(publicKey domain.NostrPublicKey, digest, signature []byte) error {
	if len(digest) != sha256.Size {
		return fmt.Errorf("digest must be %d bytes, got %d", sha256.Size, len(digest))
	}

	parsedKey, err := schnorr.ParsePubKey(publicKey[:])
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidKey, err)
	}

	parsedSignature, err := schnorr.ParseSignature(signature)
	if err != nil {
		// A malformed signature and a wrong one are reported identically:
		// distinguishing them tells an attacker which half to work on.
		return ErrInvalidSignature
	}

	if !parsedSignature.Verify(digest, parsedKey) {
		return ErrInvalidSignature
	}
	return nil
}

// DerivePublicKey computes the x-only public key for a Nostr private key.
//
// This replaces the placeholder from NM-07. Identities created by that
// placeholder derive a SHA-256 digest rather than a curve point, so they are
// not valid Nostr identities and must be regenerated.
func DerivePublicKey(private domain.NostrPrivateKey) (domain.NostrPublicKey, error) {
	signer, err := NewSigner(private)
	if err != nil {
		return domain.NostrPublicKey{}, err
	}
	return signer.PublicKey(), nil
}

// PrivateKeyHex renders a private key for the NIP-44 implementation, which
// takes hex.
//
// This is a secret escape, sanctioned only for cryptographic use. The result
// must not be logged, stored or transmitted.
func PrivateKeyHex(private domain.NostrPrivateKey) (string, error) {
	raw, err := private.Bytes()
	if err != nil {
		return "", err
	}
	defer zero(raw)

	return hex.EncodeToString(raw), nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
