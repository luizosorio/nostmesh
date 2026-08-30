package domain

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
)

// ErrSecretConsumed reports use of a secret that has already been destroyed.
var ErrSecretConsumed = errors.New("secret has been destroyed")

// NostrPrivateKey is the durable identity secret.
//
// It never appears in an event, a log line, or a diagnostic bundle. The String,
// GoString and MarshalJSON methods below make that structural: the value cannot
// be printed or serialized by accident, because every path that would normally
// reveal it returns a redaction marker instead.
type NostrPrivateKey struct {
	key       [NostrKeySize]byte
	destroyed bool
}

// WireGuardPrivateKey is the ephemeral tunnel secret.
//
// Per ADR-003 and NM-04 this value never leaves the node that generated it: not
// in a Nostr event, not in the network journal, not in a log, not in a
// diagnostic export. It is the single most sensitive value in the system.
type WireGuardPrivateKey struct {
	key       [WireGuardKeySize]byte
	destroyed bool
}

const redacted = "[REDACTED]"

// String returns a redaction marker, never the key.
//
// This is what makes accidental disclosure structurally hard: fmt verbs, log
// formatters and error messages all route through String, so a secret that
// reaches one of them prints as [REDACTED] rather than as key material.
func (k NostrPrivateKey) String() string { return redacted }

// GoString returns a redaction marker, so %#v cannot reveal the key either.
func (k NostrPrivateKey) GoString() string { return redacted }

// MarshalJSON refuses to serialize the key.
//
// Returning an error rather than a redacted string means a struct carrying a
// secret fails to encode instead of silently shipping a placeholder that looks
// like data.
func (k NostrPrivateKey) MarshalJSON() ([]byte, error) {
	return nil, errors.New("nostr private key must never be serialized")
}

// LogValue is what structured logging sees.
//
// slog consults this before any other representation, so a secret passed as a
// log attribute renders as the marker rather than falling through to
// MarshalJSON and leaving an error string in the log.
func (k NostrPrivateKey) LogValue() slog.Value { return slog.StringValue(redacted) }

// String returns a redaction marker, never the key.
func (k WireGuardPrivateKey) String() string { return redacted }

// GoString returns a redaction marker, so %#v cannot reveal the key either.
func (k WireGuardPrivateKey) GoString() string { return redacted }

// MarshalJSON refuses to serialize the key.
func (k WireGuardPrivateKey) MarshalJSON() ([]byte, error) {
	return nil, errors.New("wireguard private key must never be serialized")
}

// LogValue is what structured logging sees. See NostrPrivateKey.LogValue.
func (k WireGuardPrivateKey) LogValue() slog.Value { return slog.StringValue(redacted) }

// NewNostrPrivateKey builds a key from raw bytes.
func NewNostrPrivateKey(raw []byte) (NostrPrivateKey, error) {
	var k NostrPrivateKey
	if len(raw) != NostrKeySize {
		return k, fmt.Errorf("%w: nostr private key must be %d bytes, got %d", ErrKeySize, NostrKeySize, len(raw))
	}
	copy(k.key[:], raw)
	if isZeroBytes(k.key[:]) {
		return NostrPrivateKey{}, ErrZeroKey
	}
	return k, nil
}

// NewWireGuardPrivateKey builds a key from raw bytes, applying the Curve25519
// clamping WireGuard expects.
func NewWireGuardPrivateKey(raw []byte) (WireGuardPrivateKey, error) {
	var k WireGuardPrivateKey
	if len(raw) != WireGuardKeySize {
		return k, fmt.Errorf("%w: wireguard private key must be %d bytes, got %d", ErrKeySize, WireGuardKeySize, len(raw))
	}
	if isZeroBytes(raw) {
		return WireGuardPrivateKey{}, ErrZeroKey
	}
	copy(k.key[:], raw)

	// Curve25519 clamping, as specified by WireGuard.
	k.key[0] &= 248
	k.key[31] &= 127
	k.key[31] |= 64

	return k, nil
}

// Bytes exposes the raw key to a caller that genuinely needs it, such as a
// signer or a key-derivation step.
//
// Every call site is a place where a secret escapes the type's protection, so
// callers must not log, store or transmit the result. The returned slice is a
// copy; mutating it does not affect the key.
func (k NostrPrivateKey) Bytes() ([]byte, error) {
	if k.destroyed {
		return nil, ErrSecretConsumed
	}
	out := make([]byte, NostrKeySize)
	copy(out, k.key[:])
	return out, nil
}

// Bytes exposes the raw key to a caller that genuinely needs it.
//
// The same warning as NostrPrivateKey.Bytes applies, with more force: this
// value must never reach an event, a log or the network journal.
func (k WireGuardPrivateKey) Bytes() ([]byte, error) {
	if k.destroyed {
		return nil, ErrSecretConsumed
	}
	out := make([]byte, WireGuardKeySize)
	copy(out, k.key[:])
	return out, nil
}

// Destroy zeroes the key material.
//
// Go's garbage collector may have copied the value elsewhere, so this is a
// reduction in exposure window, not a guarantee of erasure. It still matters:
// an ephemeral session key that is destroyed on close is not sitting in memory
// for the lifetime of the process.
func (k *NostrPrivateKey) Destroy() {
	zeroBytes(k.key[:])
	k.destroyed = true
}

// Destroy zeroes the key material. See NostrPrivateKey.Destroy for the limits
// of this guarantee.
func (k *WireGuardPrivateKey) Destroy() {
	zeroBytes(k.key[:])
	k.destroyed = true
}

// IsDestroyed reports whether the secret has been zeroed.
func (k NostrPrivateKey) IsDestroyed() bool { return k.destroyed }

// IsDestroyed reports whether the secret has been zeroed.
func (k WireGuardPrivateKey) IsDestroyed() bool { return k.destroyed }

// Equal compares two keys in constant time.
func (k NostrPrivateKey) Equal(other NostrPrivateKey) bool {
	return subtle.ConstantTimeCompare(k.key[:], other.key[:]) == 1
}

// Equal compares two keys in constant time.
func (k WireGuardPrivateKey) Equal(other WireGuardPrivateKey) bool {
	return subtle.ConstantTimeCompare(k.key[:], other.key[:]) == 1
}

// HexForKeystore encodes the key for the development keystore only.
//
// This is the one sanctioned path out of the type, and it exists because the
// development keystore has to persist the key to disk. Production backends sign
// without ever handing the key to the caller. Nothing else may call this.
func (k NostrPrivateKey) HexForKeystore() (string, error) {
	if k.destroyed {
		return "", ErrSecretConsumed
	}
	return hex.EncodeToString(k.key[:]), nil
}

// Base64ForKeystore encodes the key for the development keystore only. The same
// restriction as HexForKeystore applies.
func (k WireGuardPrivateKey) Base64ForKeystore() (string, error) {
	if k.destroyed {
		return "", ErrSecretConsumed
	}
	return base64.StdEncoding.EncodeToString(k.key[:]), nil
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func isZeroBytes(b []byte) bool {
	var acc byte
	for _, v := range b {
		acc |= v
	}
	return acc == 0
}
