package identity

import (
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"

	"github.com/luizosorio/nostmesh/internal/domain"
)

// KeyGenerator produces Nostr and WireGuard key material.
//
// Its randomness source is injectable so that tests can supply a failing or
// degenerate reader, but production always uses crypto/rand.
type KeyGenerator struct {
	random io.Reader
}

// NewKeyGenerator returns a generator reading from crypto/rand.
func NewKeyGenerator() *KeyGenerator {
	return &KeyGenerator{random: rand.Reader}
}

// NewKeyGeneratorWithSource returns a generator reading from the given source.
// It exists for tests that need to simulate entropy failure.
func NewKeyGeneratorWithSource(random io.Reader) *KeyGenerator {
	return &KeyGenerator{random: random}
}

// GenerateNostrKey produces a durable identity key pair.
//
// The private key is a 32-byte secp256k1 scalar; the public key derivation is
// deferred to the signing adapter, which owns the curve implementation. For the
// development keystore the public key is supplied alongside.
func (g *KeyGenerator) GenerateNostrKey() (domain.NostrPrivateKey, error) {
	raw := make([]byte, domain.NostrKeySize)
	if _, err := io.ReadFull(g.random, raw); err != nil {
		return domain.NostrPrivateKey{}, fmt.Errorf("%w: generating nostr key: %w", domain.ErrInsufficientEntropy, err)
	}

	key, err := domain.NewNostrPrivateKey(raw)
	zero(raw)
	if err != nil {
		return domain.NostrPrivateKey{}, fmt.Errorf("generating nostr key: %w", err)
	}
	return key, nil
}

// Generate produces an ephemeral WireGuard key pair.
//
// It satisfies TunnelKeyGenerator. Each call yields an independent pair: a
// session never reuses another session's tunnel key.
func (g *KeyGenerator) Generate() (domain.WireGuardPublicKey, domain.WireGuardPrivateKey, error) {
	var (
		empty   domain.WireGuardPublicKey
		noKey   domain.WireGuardPrivateKey
		rawPriv = make([]byte, domain.WireGuardKeySize)
	)

	if _, err := io.ReadFull(g.random, rawPriv); err != nil {
		return empty, noKey, fmt.Errorf("%w: generating wireguard key: %w", domain.ErrInsufficientEntropy, err)
	}

	private, err := domain.NewWireGuardPrivateKey(rawPriv)
	zero(rawPriv)
	if err != nil {
		return empty, noKey, fmt.Errorf("generating wireguard key: %w", err)
	}

	public, err := derivePublicKey(private)
	if err != nil {
		return empty, noKey, err
	}
	return public, private, nil
}

// derivePublicKey computes the Curve25519 public key for a private key.
func derivePublicKey(private domain.WireGuardPrivateKey) (domain.WireGuardPublicKey, error) {
	var public domain.WireGuardPublicKey

	raw, err := private.Bytes()
	if err != nil {
		return public, fmt.Errorf("deriving wireguard public key: %w", err)
	}
	defer zero(raw)

	derived, err := curve25519.X25519(raw, curve25519.Basepoint)
	if err != nil {
		return public, fmt.Errorf("deriving wireguard public key: %w", err)
	}

	copy(public[:], derived)
	return public, nil
}

// DerivePublicKey exposes public key derivation for callers holding a private
// key, such as the keystore when reloading a stored identity.
func DerivePublicKey(private domain.WireGuardPrivateKey) (domain.WireGuardPublicKey, error) {
	return derivePublicKey(private)
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
