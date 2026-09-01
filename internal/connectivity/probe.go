package connectivity

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"time"
)

// Probe sizes. The challenge is large enough that guessing one is infeasible,
// and the whole message is small enough that a probe cannot be used to amplify:
// a response is never larger than the challenge that prompted it.
const (
	// NonceSize is the challenge length.
	NonceSize = 16

	// TagSize is the authentication tag length.
	TagSize = 32

	// ProbeSize is the total wire size of a challenge or response.
	ProbeSize = 1 + NonceSize + 8 + TagSize
)

// Message types on the probe wire.
const (
	probeChallenge byte = 1
	probeResponse  byte = 2
)

var (
	// ErrProbeMalformed reports a probe that could not be parsed.
	ErrProbeMalformed = errors.New("probe is malformed")

	// ErrProbeUnauthenticated reports a probe whose tag does not verify.
	//
	// This is the check that makes a lying observer harmless: a response can
	// only be produced by something holding the session key, so an address the
	// observer invented cannot answer.
	ErrProbeUnauthenticated = errors.New("probe is not authenticated")

	// ErrProbeMismatch reports a response that does not match its challenge.
	ErrProbeMismatch = errors.New("response does not match the challenge")
)

// SessionKey authenticates probes within one session.
//
// It is derived from material only the two session participants hold, so a
// third party cannot produce a valid response no matter what address it claims.
// Deriving it per session also means a probe captured from one session is
// useless in another.
type SessionKey [32]byte

// String returns a redaction marker: this key authenticates probes, so it is
// secret.
func (k SessionKey) String() string { return "[REDACTED]" }

// GoString returns a redaction marker.
func (k SessionKey) GoString() string { return "[REDACTED]" }

// MarshalJSON refuses to serialize the key.
func (k SessionKey) MarshalJSON() ([]byte, error) {
	return nil, errors.New("session key must never be serialized")
}

// DeriveSessionKey computes the probe key for a session.
//
// Both sides derive the same value from the session id and the two tunnel
// public keys, sorted so that each side computes an identical input regardless
// of which one is the initiator.
func DeriveSessionKey(sessionID string, localTunnelKey, peerTunnelKey string) SessionKey {
	first, second := localTunnelKey, peerTunnelKey
	if first > second {
		first, second = second, first
	}

	digest := sha256.New()
	digest.Write([]byte("nostmesh-probe-v1"))
	digest.Write([]byte(sessionID))
	digest.Write([]byte(first))
	digest.Write([]byte(second))

	var key SessionKey
	copy(key[:], digest.Sum(nil))
	return key
}

// Challenge is a probe sent to test a candidate.
type Challenge struct {
	// Nonce is what the responder must echo. It is random per probe, so a
	// response captured earlier cannot be replayed.
	Nonce [NonceSize]byte

	// SentAt is when the challenge left, used to measure round-trip time.
	SentAt time.Time
}

// NewChallenge builds a challenge with fresh randomness.
func NewChallenge(now time.Time) (Challenge, error) {
	var challenge Challenge

	if _, err := rand.Read(challenge.Nonce[:]); err != nil {
		return Challenge{}, fmt.Errorf("generating probe nonce: %w", err)
	}
	challenge.SentAt = now
	return challenge, nil
}

// EncodeChallenge serializes a challenge.
//
// No address is authenticated, and that omission is deliberate. The two ends of
// a path do not agree on any single address: the sender knows where it aimed,
// the receiver knows where the datagram came from, and behind NAT those are
// different values. A tag over either one cannot be recomputed by the other
// side, so a challenge bound to an address is a challenge that is silently
// dropped the moment a NAT is in the path.
//
// What the tag still proves is what matters: only a holder of the session key
// could have produced this, and the nonce makes each one fresh. Binding a probe
// to a path is the response's job, where both ends do share a value — see
// EncodeResponse.
func EncodeChallenge(challenge Challenge, key SessionKey) []byte {
	buf := make([]byte, 0, ProbeSize)
	buf = append(buf, probeChallenge)
	buf = append(buf, challenge.Nonce[:]...)
	buf = binary.BigEndian.AppendUint64(buf, uint64(challenge.SentAt.UnixNano()))

	tag := authenticateUnbound(key, probeChallenge, challenge.Nonce[:], buf[NonceSize+1:])
	return append(buf, tag...)
}

// EncodeResponse serializes a response to a challenge.
//
// The response carries the same nonce and is authenticated with the address the
// responder observed the challenge arriving from. That address is the one value
// both ends share: it is what the challenger sees as its own mapped address for
// this path, and what the responder sees as the source.
//
// This is where the anti-relay property lives. A response is only valid for the
// path it was made on, so one captured while verifying candidate X cannot be
// replayed to promote candidate Y. Promotion is what an attacker would want to
// influence, and promotion depends on this tag.
func EncodeResponse(nonce [NonceSize]byte, receivedAt time.Time, source netip.AddrPort, key SessionKey) []byte {
	buf := make([]byte, 0, ProbeSize)
	buf = append(buf, probeResponse)
	buf = append(buf, nonce[:]...)
	buf = binary.BigEndian.AppendUint64(buf, uint64(receivedAt.UnixNano()))

	tag := authenticate(key, probeResponse, nonce[:], buf[NonceSize+1:], source)
	return append(buf, tag...)
}

// DecodedProbe is a parsed probe.
type DecodedProbe struct {
	// IsResponse distinguishes a response from a challenge.
	IsResponse bool

	// Nonce is the challenge value.
	Nonce [NonceSize]byte

	// Timestamp is when the sender produced it.
	Timestamp time.Time
}

// DecodeProbe parses and authenticates a probe.
//
// The peer address is the address the packet came from, or is going to, and it
// is part of what is authenticated. A probe that arrives from an address other
// than the one it was addressed to fails here.
func DecodeChallenge(raw []byte, key SessionKey) (DecodedProbe, error) {
	parsed, err := parseProbe(raw)
	if err != nil {
		return DecodedProbe{}, err
	}
	if parsed.kind != probeChallenge {
		return DecodedProbe{}, fmt.Errorf("%w: probe is a response, not a challenge", ErrProbeMismatch)
	}

	expected := authenticateUnbound(key, parsed.kind, parsed.nonce[:], parsed.body)
	if subtle.ConstantTimeCompare(parsed.tag, expected) != 1 {
		// A wrong key and a tampered probe report the same thing.
		// Distinguishing them would tell an attacker which to work on.
		return DecodedProbe{}, ErrProbeUnauthenticated
	}
	return parsed.decoded(), nil
}

// DecodeResponse parses and authenticates a response to a challenge.
//
// The caller supplies the address it probed, which is what the tag must cover.
// A response is only usable for the candidate it was sent to: one captured
// while verifying a different path will not authenticate here, and that is what
// keeps a promotion tied to the path it was earned on.
func DecodeResponse(raw []byte, probed netip.AddrPort, key SessionKey) (DecodedProbe, error) {
	parsed, err := parseProbe(raw)
	if err != nil {
		return DecodedProbe{}, err
	}
	if parsed.kind != probeResponse {
		return DecodedProbe{}, fmt.Errorf("%w: probe is a challenge, not a response", ErrProbeMismatch)
	}

	expected := authenticate(key, parsed.kind, parsed.nonce[:], parsed.body, probed)
	if subtle.ConstantTimeCompare(parsed.tag, expected) != 1 {
		return DecodedProbe{}, ErrProbeUnauthenticated
	}
	return parsed.decoded(), nil
}

// ProbeKind reports whether a datagram is a challenge or a response.
//
// It reads the type byte without authenticating anything, so the caller can
// route to the right verifier. The byte is covered by the tag, so a probe that
// lies about its kind fails to authenticate as either.
func ProbeKind(raw []byte) (isResponse bool, err error) {
	parsed, err := parseProbe(raw)
	if err != nil {
		return false, err
	}
	return parsed.kind == probeResponse, nil
}

// parsedProbe is a probe split into its parts, before authentication.
type parsedProbe struct {
	kind  byte
	nonce [NonceSize]byte
	body  []byte
	tag   []byte
}

// decoded builds the caller-facing form. Only call it after the tag verifies.
func (p parsedProbe) decoded() DecodedProbe {
	nanos := binary.BigEndian.Uint64(p.body)
	return DecodedProbe{
		IsResponse: p.kind == probeResponse,
		Nonce:      p.nonce,
		//nolint:gosec // the timestamp is authenticated by the caller, so its range is not attacker-controlled
		Timestamp: time.Unix(0, int64(nanos)),
	}
}

// parseProbe splits a datagram without authenticating it.
func parseProbe(raw []byte) (parsedProbe, error) {
	if len(raw) != ProbeSize {
		return parsedProbe{}, fmt.Errorf("%w: %d bytes, expected %d", ErrProbeMalformed, len(raw), ProbeSize)
	}

	kind := raw[0]
	if kind != probeChallenge && kind != probeResponse {
		return parsedProbe{}, fmt.Errorf("%w: unknown probe type %d", ErrProbeMalformed, kind)
	}

	var nonce [NonceSize]byte
	copy(nonce[:], raw[1:1+NonceSize])

	return parsedProbe{
		kind:  kind,
		nonce: nonce,
		body:  raw[1+NonceSize : 1+NonceSize+8],
		tag:   raw[1+NonceSize+8:],
	}, nil
}

// VerifyResponse checks that a response answers a specific challenge.
//
// Matching the nonce in constant time matters less here than elsewhere, but
// doing it consistently costs nothing and removes a category of reasoning about
// when it matters.
func VerifyResponse(challenge Challenge, response DecodedProbe) error {
	if !response.IsResponse {
		return fmt.Errorf("%w: probe is a challenge, not a response", ErrProbeMismatch)
	}
	if subtle.ConstantTimeCompare(challenge.Nonce[:], response.Nonce[:]) != 1 {
		return fmt.Errorf("%w: nonce does not match", ErrProbeMismatch)
	}
	return nil
}

// authenticateUnbound computes the tag over a probe's contents alone.
//
// The kind byte is covered, which is what stops a challenge from being read as
// a response or the reverse — the probe protocol authenticates session
// membership, not direction, so the two forms must not be interchangeable.
func authenticateUnbound(key SessionKey, kind byte, nonce, body []byte) []byte {
	mac := hmac.New(sha256.New, key[:])
	mac.Write([]byte{kind})
	mac.Write(nonce)
	mac.Write(body)

	return mac.Sum(nil)
}

// authenticate computes the tag over a probe's contents and its address.
func authenticate(key SessionKey, kind byte, nonce, body []byte, addr netip.AddrPort) []byte {
	mac := hmac.New(sha256.New, key[:])
	mac.Write([]byte{kind})
	mac.Write(nonce)
	mac.Write(body)

	// The address is included so a probe is only valid for the path it was
	// made for.
	address := addr.Addr().Unmap().As16()
	mac.Write(address[:])

	// Big-endian, matching how a port appears on the wire, so both sides
	// authenticate the same bytes.
	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, addr.Port())
	mac.Write(port)

	return mac.Sum(nil)
}
