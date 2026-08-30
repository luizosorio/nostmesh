package domain

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"
)

// Identifier sizes. Both are large enough that an attacker cannot guess or
// enumerate them: a session id must be unpredictable so that a third party who
// observes signaling metadata cannot forge references to a session, and a nonce
// must be unique so that replaying a message is detectable.
const (
	SessionIDSize = 32
	NonceSize     = 16
)

// ErrInsufficientEntropy reports that the randomness source failed.
//
// This is treated as fatal rather than retried: a node that cannot generate
// unpredictable identifiers must not produce sessions at all.
var ErrInsufficientEntropy = errors.New("insufficient entropy")

// SessionID uniquely identifies a session.
type SessionID [SessionIDSize]byte

// Nonce is a single-use value that makes replay detectable.
type Nonce [NonceSize]byte

// NewSessionID reads a session id from the given randomness source.
func NewSessionID(random io.Reader) (SessionID, error) {
	var id SessionID
	if _, err := io.ReadFull(random, id[:]); err != nil {
		return SessionID{}, fmt.Errorf("%w: reading session id: %w", ErrInsufficientEntropy, err)
	}
	if id.IsZero() {
		return SessionID{}, fmt.Errorf("%w: session id is all zeros", ErrInsufficientEntropy)
	}
	return id, nil
}

// NewNonce reads a nonce from the given randomness source.
func NewNonce(random io.Reader) (Nonce, error) {
	var n Nonce
	if _, err := io.ReadFull(random, n[:]); err != nil {
		return Nonce{}, fmt.Errorf("%w: reading nonce: %w", ErrInsufficientEntropy, err)
	}
	if n.IsZero() {
		return Nonce{}, fmt.Errorf("%w: nonce is all zeros", ErrInsufficientEntropy)
	}
	return n, nil
}

// ParseSessionID decodes a hex-encoded session id.
func ParseSessionID(encoded string) (SessionID, error) {
	var id SessionID

	raw, err := hex.DecodeString(encoded)
	if err != nil {
		return id, fmt.Errorf("%w: session id must be hex", ErrKeyEncoding)
	}
	if len(raw) != SessionIDSize {
		return id, fmt.Errorf("%w: session id must be %d bytes, got %d", ErrKeySize, SessionIDSize, len(raw))
	}

	copy(id[:], raw)
	if id.IsZero() {
		return SessionID{}, errors.New("session id is all zeros")
	}
	return id, nil
}

// String returns the hex encoding.
func (s SessionID) String() string { return hex.EncodeToString(s[:]) }

// Short returns an abbreviated form for logs.
func (s SessionID) Short() string { return s.String()[:8] }

// IsZero reports whether the id is unset.
func (s SessionID) IsZero() bool { return s == SessionID{} }

// String returns the hex encoding.
func (n Nonce) String() string { return hex.EncodeToString(n[:]) }

// IsZero reports whether the nonce is unset.
func (n Nonce) IsZero() bool { return n == Nonce{} }

// Clock supplies the current time.
//
// The domain never calls time.Now directly. Expiry, validity windows and
// timeouts are all decided against this interface, which is what makes them
// testable without sleeping and what keeps a wrong system clock from being
// indistinguishable from a bug.
type Clock interface {
	Now() time.Time
}

// SystemClock reads the host clock.
//
// Remote timestamps are only ever used to evaluate a validity window; ordering
// within a session comes from sequence numbers, not from comparing clocks
// across hosts.
type SystemClock struct{}

// Now returns the current system time.
func (SystemClock) Now() time.Time { return time.Now() }
