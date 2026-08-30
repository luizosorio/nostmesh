package connectivity

import (
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func testNow() time.Time {
	return time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
}

func testKey() SessionKey {
	return DeriveSessionKey("session-1", "keyAAA", "keyBBB")
}

func testTarget() netip.AddrPort {
	return netip.MustParseAddrPort("198.51.100.10:51820")
}

// Both sides must derive the same key regardless of which is the initiator,
// or one side's probes would never authenticate to the other.
func TestSessionKeyIsSymmetric(t *testing.T) {
	first := DeriveSessionKey("session-1", "keyAAA", "keyBBB")
	second := DeriveSessionKey("session-1", "keyBBB", "keyAAA")

	if first != second {
		t.Error("the two sides derived different keys")
	}
}

// A probe from one session must be useless in another, so capturing one buys
// nothing beyond that session.
func TestSessionKeysDifferPerSession(t *testing.T) {
	first := DeriveSessionKey("session-1", "keyAAA", "keyBBB")
	second := DeriveSessionKey("session-2", "keyAAA", "keyBBB")

	if first == second {
		t.Error("two sessions derived the same probe key")
	}
}

func TestChallengeResponseRoundTrip(t *testing.T) {
	key := testKey()
	target := testTarget()

	challenge, err := NewChallenge(testNow())
	if err != nil {
		t.Fatalf("building challenge: %v", err)
	}

	// The responder receives the challenge from the challenger's address.
	encoded := EncodeChallenge(challenge, target, key)

	decoded, err := DecodeProbe(encoded, target, key)
	if err != nil {
		t.Fatalf("decoding challenge: %v", err)
	}
	if decoded.IsResponse {
		t.Error("a challenge decoded as a response")
	}

	response := EncodeResponse(decoded.Nonce, testNow(), target, key)

	decodedResponse, err := DecodeProbe(response, target, key)
	if err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if err := VerifyResponse(challenge, decodedResponse); err != nil {
		t.Errorf("the response must answer its challenge: %v", err)
	}
}

// This is the property that makes a lying observer harmless. An observer can
// report any address it likes; without the session key it cannot produce a
// response from there, so the candidate never becomes valid.
func TestForgedResponseWithoutTheKeyFails(t *testing.T) {
	key := testKey()
	target := testTarget()

	challenge, err := NewChallenge(testNow())
	if err != nil {
		t.Fatalf("building challenge: %v", err)
	}

	// An attacker who saw the challenge knows the nonce, but not the key.
	attackerKey := DeriveSessionKey("session-1", "attacker", "guess")
	forged := EncodeResponse(challenge.Nonce, testNow(), target, attackerKey)

	if _, err := DecodeProbe(forged, target, key); !errors.Is(err, ErrProbeUnauthenticated) {
		t.Errorf("expected ErrProbeUnauthenticated, got: %v", err)
	}
}

// A probe is bound to the address it was made for, so one captured on the way
// to one address cannot be replayed toward another.
func TestProbeIsBoundToItsAddress(t *testing.T) {
	key := testKey()

	challenge, err := NewChallenge(testNow())
	if err != nil {
		t.Fatalf("building challenge: %v", err)
	}

	encoded := EncodeChallenge(challenge, testTarget(), key)
	elsewhere := netip.MustParseAddrPort("203.0.113.5:51820")

	if _, err := DecodeProbe(encoded, elsewhere, key); !errors.Is(err, ErrProbeUnauthenticated) {
		t.Errorf("a probe replayed to another address must fail, got: %v", err)
	}
}

// The port is part of the binding: two mappings of the same host are distinct
// paths, and a probe for one must not validate the other.
func TestProbeIsBoundToItsPort(t *testing.T) {
	key := testKey()

	challenge, err := NewChallenge(testNow())
	if err != nil {
		t.Fatalf("building challenge: %v", err)
	}

	encoded := EncodeChallenge(challenge, testTarget(), key)
	otherPort := netip.MustParseAddrPort("198.51.100.10:51821")

	if _, err := DecodeProbe(encoded, otherPort, key); !errors.Is(err, ErrProbeUnauthenticated) {
		t.Errorf("a probe replayed to another port must fail, got: %v", err)
	}
}

// A response to a different challenge must not validate this one, or an
// attacker could answer with something they captured earlier.
func TestResponseToAnotherChallengeIsRefused(t *testing.T) {
	key := testKey()
	target := testTarget()

	first, err := NewChallenge(testNow())
	if err != nil {
		t.Fatalf("building challenge: %v", err)
	}
	second, err := NewChallenge(testNow())
	if err != nil {
		t.Fatalf("building challenge: %v", err)
	}
	if first.Nonce == second.Nonce {
		t.Fatal("two challenges produced the same nonce")
	}

	response := EncodeResponse(second.Nonce, testNow(), target, key)

	decoded, err := DecodeProbe(response, target, key)
	if err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if err := VerifyResponse(first, decoded); !errors.Is(err, ErrProbeMismatch) {
		t.Errorf("expected ErrProbeMismatch, got: %v", err)
	}
}

// A challenge presented where a response is expected must be refused: they are
// different messages and confusing them would let one stand in for the other.
func TestChallengeIsNotAResponse(t *testing.T) {
	key := testKey()
	target := testTarget()

	challenge, err := NewChallenge(testNow())
	if err != nil {
		t.Fatalf("building challenge: %v", err)
	}

	encoded := EncodeChallenge(challenge, target, key)
	decoded, err := DecodeProbe(encoded, target, key)
	if err != nil {
		t.Fatalf("decoding: %v", err)
	}

	if err := VerifyResponse(challenge, decoded); !errors.Is(err, ErrProbeMismatch) {
		t.Errorf("expected ErrProbeMismatch, got: %v", err)
	}
}

func TestMalformedProbesAreRefused(t *testing.T) {
	key := testKey()
	target := testTarget()

	tests := []struct {
		name string
		raw  []byte
	}{
		{"empty", nil},
		{"too short", make([]byte, ProbeSize-1)},
		{"too long", make([]byte, ProbeSize+1)},
		{"unknown type", append([]byte{99}, make([]byte, ProbeSize-1)...)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := DecodeProbe(tt.raw, target, key); err == nil {
				t.Error("a malformed probe must be refused")
			}
		})
	}
}

// A probe cannot amplify: the response is never larger than the challenge, so
// an attacker spoofing a source address gains no leverage.
func TestProbeDoesNotAmplify(t *testing.T) {
	key := testKey()
	target := testTarget()

	challenge, err := NewChallenge(testNow())
	if err != nil {
		t.Fatalf("building challenge: %v", err)
	}

	encoded := EncodeChallenge(challenge, target, key)
	response := EncodeResponse(challenge.Nonce, testNow(), target, key)

	if len(response) > len(encoded) {
		t.Errorf("response is %d bytes against a %d-byte challenge; this amplifies",
			len(response), len(encoded))
	}
}

// Nonces must not repeat, or a captured response could answer a later
// challenge.
func TestChallengeNoncesAreUnique(t *testing.T) {
	seen := make(map[[NonceSize]byte]bool)

	for range 1000 {
		challenge, err := NewChallenge(testNow())
		if err != nil {
			t.Fatalf("building challenge: %v", err)
		}
		if seen[challenge.Nonce] {
			t.Fatal("a nonce repeated")
		}
		seen[challenge.Nonce] = true
	}
}

// The probe key authenticates every check in a session, so it must not be
// printable.
func TestSessionKeyNeverPrints(t *testing.T) {
	key := testKey()

	for _, rendered := range []string{key.String(), key.GoString()} {
		if !strings.Contains(rendered, "REDACTED") {
			t.Errorf("expected a redaction marker, got: %s", rendered)
		}
	}
	if _, err := json.Marshal(key); err == nil {
		t.Error("marshaling a session key must fail")
	}
}

// Every authentication failure reports identically, whatever went wrong.
func TestAuthenticationFailuresAreIndistinguishable(t *testing.T) {
	key := testKey()
	target := testTarget()

	challenge, err := NewChallenge(testNow())
	if err != nil {
		t.Fatalf("building challenge: %v", err)
	}
	encoded := EncodeChallenge(challenge, target, key)

	wrongKey := DeriveSessionKey("other", "a", "b")
	_, wrongKeyErr := DecodeProbe(encoded, target, wrongKey)

	tampered := make([]byte, len(encoded))
	copy(tampered, encoded)
	tampered[5] ^= 0xFF
	_, tamperedErr := DecodeProbe(tampered, target, key)

	_, wrongAddrErr := DecodeProbe(encoded, netip.MustParseAddrPort("203.0.113.1:1"), key)

	if wrongKeyErr == nil || tamperedErr == nil || wrongAddrErr == nil {
		t.Fatal("all three must fail")
	}
	if wrongKeyErr.Error() != tamperedErr.Error() || tamperedErr.Error() != wrongAddrErr.Error() {
		t.Errorf("errors differ and leak which check failed:\n  key:  %v\n  tag:  %v\n  addr: %v",
			wrongKeyErr, tamperedErr, wrongAddrErr)
	}
}
