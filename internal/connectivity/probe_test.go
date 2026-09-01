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

	encoded := EncodeChallenge(challenge, key)

	decoded, err := DecodeChallenge(encoded, key)
	if err != nil {
		t.Fatalf("decoding challenge: %v", err)
	}
	if decoded.IsResponse {
		t.Error("a challenge decoded as a response")
	}

	response := EncodeResponse(decoded.Nonce, testNow(), target, key)

	decodedResponse, err := DecodeResponse(response, key)
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

	if _, err := DecodeResponse(forged, key); !errors.Is(err, ErrProbeUnauthenticated) {
		t.Errorf("expected ErrProbeUnauthenticated, got: %v", err)
	}
}

// The address a response states is authenticated, so a peer cannot claim to
// have been reached somewhere it was not.
//
// This address is how a node learns its own mapped address for a path without
// trusting a third party. If it could be rewritten in flight, an on-path
// attacker would choose what a node believes about itself.
func TestTheStatedAddressIsAuthenticated(t *testing.T) {
	key := testKey()
	observed := testTarget()

	response := EncodeResponse(testNonce(), testNow(), observed, key)

	decoded, err := DecodeResponse(response, key)
	if err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if decoded.Observed != observed {
		t.Errorf("stated address is %s, expected %s", decoded.Observed, observed)
	}

	// Rewriting the address must invalidate the tag.
	tampered := make([]byte, len(response))
	copy(tampered, response)
	tampered[1+NonceSize+8] ^= 0xFF

	if _, err := DecodeResponse(tampered, key); !errors.Is(err, ErrProbeUnauthenticated) {
		t.Errorf("a rewritten address must be caught, got: %v", err)
	}
}

// A challenge carries no address, and must authenticate whatever path it took.
//
// The two ends of a path do not share an address: the sender knows where it
// aimed, the receiver knows where the datagram came from, and behind NAT those
// differ. A challenge bound to either one is silently dropped by the other side.
//
// Measured between two real hosts, one behind NAT: both sides probed, neither
// answered, and nothing reported an error. The test that should have caught it
// used one variable for both addresses, so it passed by construction.
func TestChallengeSurvivesAddressTranslation(t *testing.T) {
	key := testKey()

	challenge, err := NewChallenge(testNow())
	if err != nil {
		t.Fatalf("building challenge: %v", err)
	}

	// The sender aims at the peer's public address.
	encoded := EncodeChallenge(challenge, key)

	// The receiver sees it arrive from the sender's NAT-mapped address, which
	// is a different value entirely.
	if _, err := DecodeChallenge(encoded, key); err != nil {
		t.Fatalf("a challenge must authenticate regardless of the path it took: %v", err)
	}
}

// The port is part of the stated address: two mappings of the same host are
// distinct paths, and a response about one must not be read as being about the
// other.
func TestTheStatedPortIsAuthenticated(t *testing.T) {
	key := testKey()

	response := EncodeResponse(testNonce(), testNow(), testTarget(), key)

	// The port sits at the end of the observed address.
	tampered := make([]byte, len(response))
	copy(tampered, response)
	tampered[1+NonceSize+8+16] ^= 0xFF

	if _, err := DecodeResponse(tampered, key); !errors.Is(err, ErrProbeUnauthenticated) {
		t.Errorf("a rewritten port must be caught, got: %v", err)
	}
}

// testNonce is a fixed nonce for tests that only need one.
func testNonce() [NonceSize]byte {
	var nonce [NonceSize]byte
	for i := range nonce {
		nonce[i] = byte(i + 1)
	}
	return nonce
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

	decoded, err := DecodeResponse(response, key)
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

	challenge, err := NewChallenge(testNow())
	if err != nil {
		t.Fatalf("building challenge: %v", err)
	}

	encoded := EncodeChallenge(challenge, key)

	// A challenge must not authenticate as a response: the kind byte is covered
	// by the tag, so the two forms are not interchangeable even under the same
	// key.
	if _, err := DecodeResponse(encoded, key); !errors.Is(err, ErrProbeMismatch) {
		t.Errorf("a challenge decoded as a response, got: %v", err)
	}

	decoded, err := DecodeChallenge(encoded, key)
	if err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if err := VerifyResponse(challenge, decoded); !errors.Is(err, ErrProbeMismatch) {
		t.Errorf("expected ErrProbeMismatch, got: %v", err)
	}
}

func TestMalformedProbesAreRefused(t *testing.T) {
	key := testKey()

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
			if _, err := DecodeResponse(tt.raw, key); err == nil {
				t.Error("a malformed probe must be refused")
			}
			if _, err := DecodeChallenge(tt.raw, key); err == nil {
				t.Error("a malformed probe must be refused as a challenge too")
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

	encoded := EncodeChallenge(challenge, key)
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

	// A response, because that is the form carrying an address: the three
	// failures compared here are wrong key, tampered bytes, and wrong address.
	encoded := EncodeResponse(testNonce(), testNow(), target, key)

	wrongKey := DeriveSessionKey("other", "a", "b")
	_, wrongKeyErr := DecodeResponse(encoded, wrongKey)

	tampered := make([]byte, len(encoded))
	copy(tampered, encoded)
	tampered[5] ^= 0xFF
	_, tamperedErr := DecodeResponse(tampered, key)

	tamperedAddress := make([]byte, len(encoded))
	copy(tamperedAddress, encoded)
	tamperedAddress[1+NonceSize+8] ^= 0xFF
	_, wrongAddrErr := DecodeResponse(tamperedAddress, key)

	if wrongKeyErr == nil || tamperedErr == nil || wrongAddrErr == nil {
		t.Fatal("all three must fail")
	}
	if wrongKeyErr.Error() != tamperedErr.Error() || tamperedErr.Error() != wrongAddrErr.Error() {
		t.Errorf("errors differ and leak which check failed:\n  key:  %v\n  tag:  %v\n  addr: %v",
			wrongKeyErr, tamperedErr, wrongAddrErr)
	}
}
