// Package domain holds the pure types and state machines of NostMesh.
//
// Nothing here touches the operating system, the network or the clock. Time
// arrives through an injected Clock, randomness through an injected source, and
// effects are expressed as decisions for an adapter to carry out.
package domain

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
)

// Key sizes. Nostr uses secp256k1 x-only public keys; WireGuard uses
// Curve25519. Both are 32 bytes, which is exactly why they are given distinct
// types: the compiler, not the reader, has to be the one that keeps them apart.
const (
	NostrKeySize     = 32
	WireGuardKeySize = 32
)

var (
	// ErrKeySize reports a key of the wrong length.
	ErrKeySize = errors.New("wrong key size")

	// ErrKeyEncoding reports a key that is not valid in its expected encoding.
	ErrKeyEncoding = errors.New("invalid key encoding")

	// ErrZeroKey reports an all-zero key. It is never a legitimate value and
	// usually means uninitialized memory reached a place it should not have.
	ErrZeroKey = errors.New("key is all zeros")
)

// NostrPublicKey identifies a participant on the control plane.
//
// It is durable: it authorizes sessions and outlives any single tunnel. It is
// public by nature and appears in event envelopes.
type NostrPublicKey [NostrKeySize]byte

// WireGuardPublicKey identifies a peer on the data plane.
//
// It is ephemeral, scoped to one session, and travels only inside encrypted,
// directed signaling — bound to the session that authorized it.
type WireGuardPublicKey [WireGuardKeySize]byte

// The two public key types are deliberately distinct. A Nostr key must never be
// usable where a WireGuard key is expected, and the type system is what makes
// that a compile error rather than a code review comment.

// ParseNostrPublicKey decodes a hex-encoded Nostr public key.
func ParseNostrPublicKey(encoded string) (NostrPublicKey, error) {
	var key NostrPublicKey

	raw, err := hex.DecodeString(encoded)
	if err != nil {
		return key, fmt.Errorf("%w: nostr public key must be hex", ErrKeyEncoding)
	}
	if len(raw) != NostrKeySize {
		return key, fmt.Errorf("%w: nostr public key must be %d bytes, got %d", ErrKeySize, NostrKeySize, len(raw))
	}

	copy(key[:], raw)
	if key.isZero() {
		return NostrPublicKey{}, ErrZeroKey
	}
	return key, nil
}

// ParseWireGuardPublicKey decodes a base64-encoded WireGuard public key.
func ParseWireGuardPublicKey(encoded string) (WireGuardPublicKey, error) {
	var key WireGuardPublicKey

	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return key, fmt.Errorf("%w: wireguard public key must be base64", ErrKeyEncoding)
	}
	if len(raw) != WireGuardKeySize {
		return key, fmt.Errorf("%w: wireguard public key must be %d bytes, got %d", ErrKeySize, WireGuardKeySize, len(raw))
	}

	copy(key[:], raw)
	if key.isZero() {
		return WireGuardPublicKey{}, ErrZeroKey
	}
	return key, nil
}

// String returns the hex encoding used by Nostr.
func (k NostrPublicKey) String() string { return hex.EncodeToString(k[:]) }

// String returns the base64 encoding used by WireGuard.
func (k WireGuardPublicKey) String() string { return base64.StdEncoding.EncodeToString(k[:]) }

// Short returns an abbreviated form for logs and diagnostics, where a full key
// adds noise without adding meaning.
func (k NostrPublicKey) Short() string { return k.String()[:8] }

// Short returns an abbreviated form for logs and diagnostics.
func (k WireGuardPublicKey) Short() string { return k.String()[:8] }

func (k NostrPublicKey) isZero() bool     { return k == NostrPublicKey{} }
func (k WireGuardPublicKey) isZero() bool { return k == WireGuardPublicKey{} }

// IsZero reports whether the key is unset.
func (k NostrPublicKey) IsZero() bool { return k.isZero() }

// IsZero reports whether the key is unset.
func (k WireGuardPublicKey) IsZero() bool { return k.isZero() }
