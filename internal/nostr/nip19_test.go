package nostr

import (
	"errors"
	"strings"
	"testing"

	"github.com/luizosorio/nostmesh/internal/domain"
)

// A key survives the round trip through the form a client exports.
func TestAPrivateKeyRoundTripsThroughBech32(t *testing.T) {
	original := testPrivateKeyFromSeed(t, 3)

	encoded, err := encodeBech32(privateKeyPrefix, testKeyBytes(t, 3))
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}

	decoded, err := DecodePrivateKey(encoded)
	if err != nil {
		t.Fatalf("decoding: %v", err)
	}

	if !sameKey(t, decoded, original) {
		t.Error("the key did not survive the round trip")
	}
}

// The same key in hexadecimal decodes to the same key.
//
// Both forms exist in the wild: clients show bech32, while configuration files
// and debugging output carry hex. Accepting only one would send a user to a
// conversion website with their private key in the clipboard.
func TestTheHexadecimalFormDecodesToTheSameKey(t *testing.T) {
	fromBech32, err := encodeBech32(privateKeyPrefix, testKeyBytes(t, 9))
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}

	viaBech32, err := DecodePrivateKey(fromBech32)
	if err != nil {
		t.Fatalf("decoding bech32: %v", err)
	}
	viaHex, err := DecodePrivateKey(hexEncode(testKeyBytes(t, 9)))
	if err != nil {
		t.Fatalf("decoding hex: %v", err)
	}

	if !sameKey(t, viaBech32, viaHex) {
		t.Error("the two encodings of one key decoded differently")
	}
}

// A public key offered as a private one is refused, and says so.
//
// The likeliest mistake a person makes here, and the one where a generic parse
// error would leave them wondering whether they had just leaked something.
func TestAPublicKeyIsRefusedWithItsOwnReason(t *testing.T) {
	public, err := EncodePublicKey(testPublicKeyFromSeed(t, 5))
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}

	_, err = DecodePrivateKey(public)
	if !errors.Is(err, ErrPublicKeySupplied) {
		t.Errorf("expected ErrPublicKeySupplied, got: %v", err)
	}
}

// An encrypted key is named rather than dismissed as malformed.
//
// It is a legitimate export format, so the useful answer is what to do about
// it, not that it could not be parsed.
func TestAnEncryptedKeyIsNamedRatherThanCalledMalformed(t *testing.T) {
	encrypted, err := encodeBech32(encryptedKeyPrefix, testKeyBytes(t, 13))
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}

	_, err = DecodePrivateKey(encrypted)
	if !errors.Is(err, ErrEncryptedKeyUnsupported) {
		t.Errorf("expected ErrEncryptedKeyUnsupported, got: %v", err)
	}
}

// Input that is neither encoding is refused rather than coerced.
func TestUnrecognizedInputIsRefused(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"whitespace", "   \n"},
		{"a sentence", "this is not a key"},
		{"hex of the wrong length", strings.Repeat("ab", 16)},
		{"not hexadecimal", strings.Repeat("zz", 32)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := DecodePrivateKey(tt.input); err == nil {
				t.Errorf("accepted %q as a key", tt.input)
			}
		})
	}
}

// Surrounding whitespace is tolerated: a pasted key routinely carries a
// trailing newline, and refusing that would be a puzzle rather than a warning.
func TestSurroundingWhitespaceIsTolerated(t *testing.T) {
	encoded, err := encodeBech32(privateKeyPrefix, testKeyBytes(t, 17))
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}

	if _, err := DecodePrivateKey("  " + encoded + "\n"); err != nil {
		t.Errorf("a pasted key with surrounding whitespace was refused: %v", err)
	}
}

// A failure must not quote the key it failed on.
//
// An error string reaches logs and terminals that a key never should. This is
// the one place a private key is handled in text, so it is the one place that
// mistake is available to make.
func TestAFailureNeverQuotesTheKey(t *testing.T) {
	corrupted := hexEncode(testKeyBytes(t, 21))
	corrupted = corrupted[:len(corrupted)-1] + "zz"

	_, err := DecodePrivateKey(corrupted)
	if err == nil {
		t.Fatal("a corrupted key was accepted")
	}

	// Any run of the key's own characters appearing in the message would mean
	// the input was echoed back.
	for _, fragment := range []string{corrupted[:16], corrupted[16:32]} {
		if strings.Contains(err.Error(), fragment) {
			t.Errorf("the error quotes the input: %v", err)
		}
	}
}

// The public encoding is what other clients show, so a user can compare.
func TestAPublicKeyEncodesWithItsOwnPrefix(t *testing.T) {
	encoded, err := EncodePublicKey(testPublicKeyFromSeed(t, 7))
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}

	if !strings.HasPrefix(encoded, publicKeyPrefix+"1") {
		t.Errorf("encoded as %q, expected the public-key prefix", encoded)
	}

	hrp, payload, err := decodeBech32(encoded)
	if err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if hrp != publicKeyPrefix {
		t.Errorf("prefix is %q, want %q", hrp, publicKeyPrefix)
	}
	if len(payload) != domain.NostrKeySize {
		t.Errorf("payload is %d bytes, want %d", len(payload), domain.NostrKeySize)
	}
}

// testPrivateKeyFromSeed builds a private key from a seed.
func testPrivateKeyFromSeed(t *testing.T, seed byte) domain.NostrPrivateKey {
	t.Helper()

	key, err := domain.NewNostrPrivateKey(testKeyBytes(t, seed))
	if err != nil {
		t.Fatalf("building key: %v", err)
	}
	return key
}

// testPublicKeyFromSeed builds a public key from a seed.
func testPublicKeyFromSeed(t *testing.T, seed byte) domain.NostrPublicKey {
	t.Helper()

	var key domain.NostrPublicKey
	copy(key[:], testKeyBytes(t, seed))
	return key
}

// sameKey compares two private keys without rendering either.
func sameKey(t *testing.T, a, b domain.NostrPrivateKey) bool {
	t.Helper()

	first, err := a.HexForKeystore()
	if err != nil {
		t.Fatalf("comparing: %v", err)
	}
	second, err := b.HexForKeystore()
	if err != nil {
		t.Fatalf("comparing: %v", err)
	}
	return first == second
}

// hexEncode renders bytes as lowercase hexadecimal.
func hexEncode(raw []byte) string {
	const digits = "0123456789abcdef"

	var builder strings.Builder
	for _, b := range raw {
		builder.WriteByte(digits[b>>4])
		builder.WriteByte(digits[b&0x0f])
	}
	return builder.String()
}

// A number at or above the curve's group order is refused, not reduced.
//
// The signing library reduces such a value modulo the group order rather than
// rejecting it, so it silently becomes a different, valid key. Importing one
// would give a node an identity nobody chose, discovered only when peers failed
// to recognise it. The group order itself reduces to zero and yields an
// all-zero public key.
func TestAScalarOutsideTheGroupOrderIsRefused(t *testing.T) {
	tests := []struct {
		name string
		key  string
	}{
		{"every byte set", strings.Repeat("ff", domain.NostrKeySize)},
		{"the group order", "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"},
		{"one above the order", "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := DecodePrivateKey(tt.key); !errors.Is(err, ErrKeyOutOfRange) {
				t.Errorf("expected ErrKeyOutOfRange, got: %v", err)
			}
		})
	}
}

// The largest valid scalar is still accepted: the bound is exclusive, and
// refusing a legitimate key would be its own defect.
func TestTheLargestValidScalarIsAccepted(t *testing.T) {
	const nMinusOne = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140"

	if _, err := DecodePrivateKey(nMinusOne); err != nil {
		t.Errorf("the largest valid private key was refused: %v", err)
	}
}
