package nostr

import (
	"errors"
	"strings"
	"testing"
)

// The specification's own vectors.
//
// These are from BIP-173, and they are the point of testing this at all: an
// encoder tested only against its own decoder agrees with itself and with
// nobody else. A key a user pastes here was produced by another
// implementation, so agreement with the specification is the property that
// matters.
var bip173Valid = []string{
	"A12UEL5L",
	"a12uel5l",
	"an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
	"abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
	"11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
	"split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
	"?1ezyfcl",
}

func TestKnownBech32StringsDecode(t *testing.T) {
	for _, encoded := range bip173Valid {
		t.Run(truncateForName(encoded), func(t *testing.T) {
			hrp, payload, err := decodeBech32(encoded)
			if err != nil {
				t.Fatalf("a valid string was rejected: %v", err)
			}

			// Re-encoding must reproduce the input, lowercased. Bech32 is
			// case-insensitive but not case-preserving.
			reencoded, err := encodeBech32(hrp, payload)
			if err != nil {
				t.Fatalf("re-encoding: %v", err)
			}
			if reencoded != strings.ToLower(encoded) {
				t.Errorf("re-encoded to %q, want %q", reencoded, strings.ToLower(encoded))
			}
		})
	}
}

// Invalid strings from BIP-173, each with the reason it is invalid.
//
// Rejecting these is what makes the encoding worth having: a corrupted key must
// fail rather than decode to a different key.
func TestKnownInvalidBech32StringsAreRefused(t *testing.T) {
	tests := []struct {
		name    string
		encoded string
	}{
		{"hrp character out of range", "\x201nwldj5"},
		{"no separator", "pzry9x0s0muk"},
		{"empty hrp", "1pzry9x0s0muk"},
		{"invalid data character", "x1b4n0q5v"},
		{"too short checksum", "li1dgmt3"},
		{"checksum calculated with uppercase form of hrp", "A1G7SGD8"},
		{"empty hrp with checksum", "10a06t8"},
		{"empty hrp only", "1qzzfhee"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, err := decodeBech32(tt.encoded); err == nil {
				t.Errorf("an invalid string was accepted: %q", tt.encoded)
			}
		})
	}
}

// A single altered character must be caught.
//
// This is the property a user relies on without knowing it: a key mistyped by
// one character is refused, rather than silently becoming a different, valid
// key belonging to nobody.
func TestASingleAlteredCharacterFailsTheChecksum(t *testing.T) {
	original, err := encodeBech32("nsec", testKeyBytes(t, 7))
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}

	for i := len(original) - 1; i >= 0; i-- {
		altered := alterOneCharacter(original, i)
		if altered == "" {
			continue
		}

		if _, _, decodeErr := decodeBech32(altered); decodeErr == nil {
			t.Fatalf("altering position %d produced another valid string: %q", i, altered)
		}
	}
}

// The prefix is covered by the checksum, so a payload relabelled as another
// kind of key does not decode.
//
// Without this a private key could be presented as a public one, or the
// reverse, and the only thing standing between a user and pasting the wrong one
// somewhere public is the label.
func TestTheePrefixIsCoveredByTheChecksum(t *testing.T) {
	payload := testKeyBytes(t, 11)

	asSecret, err := encodeBech32("nsec", payload)
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}

	// Relabel: same data and checksum characters, different prefix.
	relabelled := "npub" + strings.TrimPrefix(asSecret, "nsec")

	if _, _, err := decodeBech32(relabelled); !errors.Is(err, ErrBech32Checksum) {
		t.Errorf("a relabelled key decoded; expected a checksum failure, got: %v", err)
	}
}

func TestBech32RoundTripsAKey(t *testing.T) {
	payload := testKeyBytes(t, 3)

	encoded, err := encodeBech32("nsec", payload)
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}
	if !strings.HasPrefix(encoded, "nsec1") {
		t.Errorf("encoded as %q, expected the prefix and separator", encoded)
	}

	hrp, decoded, err := decodeBech32(encoded)
	if err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if hrp != "nsec" {
		t.Errorf("prefix is %q, want nsec", hrp)
	}
	if string(decoded) != string(payload) {
		t.Error("the payload did not survive the round trip")
	}
}

// Mixed case is refused rather than normalised, because BIP-173 makes it
// invalid: a checksum computed over one case does not cover the other.
func TestMixedCaseIsRefused(t *testing.T) {
	encoded, err := encodeBech32("nsec", testKeyBytes(t, 5))
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}

	mixed := strings.ToUpper(encoded[:6]) + encoded[6:]
	if _, _, err := decodeBech32(mixed); !errors.Is(err, ErrBech32Invalid) {
		t.Errorf("mixed case was accepted, got: %v", err)
	}
}

// An oversized input is refused before it is parsed, so a misdirected file
// cannot be buffered as though it were a key.
func TestAnOversizedStringIsRefused(t *testing.T) {
	oversized := "nsec1" + strings.Repeat("q", bech32MaxLength)

	if _, _, err := decodeBech32(oversized); !errors.Is(err, ErrBech32Invalid) {
		t.Errorf("an oversized string was parsed, got: %v", err)
	}
}

// testKeyBytes builds 32 bytes from a seed.
//
// Derived rather than written down: a secret scanner cannot tell a public key
// from a private one, so the project's rule is that test key material is
// computed, never a literal.
func testKeyBytes(t *testing.T, seed byte) []byte {
	t.Helper()

	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = seed + byte(i)
	}
	return raw
}

// alterOneCharacter returns the string with position i changed to a different
// character from the alphabet, or "" if the position is not payload.
func alterOneCharacter(encoded string, i int) string {
	separator := strings.LastIndexByte(encoded, '1')
	if i <= separator {
		return ""
	}

	replacement := byte('q')
	if encoded[i] == replacement {
		replacement = 'p'
	}
	return encoded[:i] + string(replacement) + encoded[i+1:]
}

// truncateForName keeps subtest names readable.
func truncateForName(s string) string {
	if len(s) <= 24 {
		return s
	}
	return s[:24]
}
