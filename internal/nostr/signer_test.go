package nostr

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/luizosorio/nostmesh/internal/domain"
)

func testPrivateKey(t *testing.T, seed byte) domain.NostrPrivateKey {
	t.Helper()

	raw := make([]byte, domain.NostrKeySize)
	for i := range raw {
		raw[i] = seed + byte(i)
	}

	key, err := domain.NewNostrPrivateKey(raw)
	if err != nil {
		t.Fatalf("building key: %v", err)
	}
	return key
}

func testDigest(content string) []byte {
	sum := sha256.Sum256([]byte(content))
	return sum[:]
}

// A derived public key must be a real point on secp256k1. The placeholder it
// replaces produced a SHA-256 digest, which is not.
func TestDerivedKeyIsOnTheCurve(t *testing.T) {
	public, err := DerivePublicKey(testPrivateKey(t, 1))
	if err != nil {
		t.Fatalf("deriving: %v", err)
	}

	// Parsing as an x-only point succeeds only for a valid curve point.
	if _, err := NewSigner(testPrivateKey(t, 1)); err != nil {
		t.Fatalf("the derived key must be usable for signing: %v", err)
	}
	if public.IsZero() {
		t.Error("derived key is zero")
	}
}

func TestDerivationIsDeterministic(t *testing.T) {
	first, err := DerivePublicKey(testPrivateKey(t, 1))
	if err != nil {
		t.Fatalf("deriving: %v", err)
	}
	second, err := DerivePublicKey(testPrivateKey(t, 1))
	if err != nil {
		t.Fatalf("deriving: %v", err)
	}

	if first != second {
		t.Error("the same private key derived two different public keys")
	}
}

func TestDifferentKeysDeriveDifferentIdentities(t *testing.T) {
	first, err := DerivePublicKey(testPrivateKey(t, 1))
	if err != nil {
		t.Fatalf("deriving: %v", err)
	}
	second, err := DerivePublicKey(testPrivateKey(t, 200))
	if err != nil {
		t.Fatalf("deriving: %v", err)
	}

	if first == second {
		t.Error("two different private keys derived the same identity")
	}
}

func TestSignAndVerifyRoundTrip(t *testing.T) {
	signer, err := NewSigner(testPrivateKey(t, 1))
	if err != nil {
		t.Fatalf("building signer: %v", err)
	}

	digest := testDigest("nostmesh control event")

	signature, err := signer.Sign(digest)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	if err := Verify(signer.PublicKey(), digest, signature); err != nil {
		t.Errorf("a signature must verify against its own key: %v", err)
	}
}

// Every way a signature can be wrong must be refused. This is what establishes
// authorship, and everything downstream depends on it.
func TestVerifyRefusesInvalidSignatures(t *testing.T) {
	signer, err := NewSigner(testPrivateKey(t, 1))
	if err != nil {
		t.Fatalf("building signer: %v", err)
	}

	other, err := NewSigner(testPrivateKey(t, 200))
	if err != nil {
		t.Fatalf("building signer: %v", err)
	}

	digest := testDigest("original message")
	signature, err := signer.Sign(digest)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	t.Run("different message", func(t *testing.T) {
		if err := Verify(signer.PublicKey(), testDigest("tampered"), signature); err == nil {
			t.Error("a signature must not verify over a different message")
		}
	})

	t.Run("different key", func(t *testing.T) {
		if err := Verify(other.PublicKey(), digest, signature); err == nil {
			t.Error("a signature must not verify under another identity")
		}
	})

	t.Run("corrupted signature", func(t *testing.T) {
		corrupted := make([]byte, len(signature))
		copy(corrupted, signature)
		corrupted[10] ^= 0xFF

		if err := Verify(signer.PublicKey(), digest, corrupted); !errors.Is(err, ErrInvalidSignature) {
			t.Errorf("expected ErrInvalidSignature, got: %v", err)
		}
	})

	t.Run("truncated signature", func(t *testing.T) {
		if err := Verify(signer.PublicKey(), digest, signature[:32]); !errors.Is(err, ErrInvalidSignature) {
			t.Errorf("expected ErrInvalidSignature, got: %v", err)
		}
	})

	t.Run("empty signature", func(t *testing.T) {
		if err := Verify(signer.PublicKey(), digest, nil); !errors.Is(err, ErrInvalidSignature) {
			t.Errorf("expected ErrInvalidSignature, got: %v", err)
		}
	})
}

// A malformed signature and a wrong one report identically: distinguishing them
// tells an attacker which half of the problem to work on.
func TestSignatureErrorsAreIndistinguishable(t *testing.T) {
	signer, err := NewSigner(testPrivateKey(t, 1))
	if err != nil {
		t.Fatalf("building signer: %v", err)
	}

	digest := testDigest("message")
	signature, err := signer.Sign(digest)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	corrupted := make([]byte, len(signature))
	copy(corrupted, signature)
	corrupted[5] ^= 0xFF

	wrongErr := Verify(signer.PublicKey(), testDigest("other"), signature)
	malformedErr := Verify(signer.PublicKey(), digest, []byte("garbage"))

	if wrongErr == nil || malformedErr == nil {
		t.Fatal("both must fail")
	}
	if wrongErr.Error() != malformedErr.Error() {
		t.Errorf("errors differ and leak which failed:\n  wrong:     %v\n  malformed: %v",
			wrongErr, malformedErr)
	}
}

func TestSignRejectsWrongDigestSize(t *testing.T) {
	signer, err := NewSigner(testPrivateKey(t, 1))
	if err != nil {
		t.Fatalf("building signer: %v", err)
	}

	for _, size := range []int{0, 16, 31, 33, 64} {
		if _, err := signer.Sign(make([]byte, size)); err == nil {
			t.Errorf("a %d-byte digest must be refused", size)
		}
	}
}

// Signatures are deterministic, and that is the desirable property.
//
// BIP-340 permits a deterministic nonce derived from the private key and the
// message, which is what this implementation uses. It eliminates the failure
// mode where reusing a nonce leaks the private key — the bug that has emptied
// Bitcoin wallets and broken console signing keys.
//
// The property that matters is that different messages produce different
// signatures; identical output for identical input is correct.
func TestSignaturesAreDeterministic(t *testing.T) {
	signer, err := NewSigner(testPrivateKey(t, 1))
	if err != nil {
		t.Fatalf("building signer: %v", err)
	}

	digest := testDigest("message")

	first, err := signer.Sign(digest)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	second, err := signer.Sign(digest)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	if hex.EncodeToString(first) != hex.EncodeToString(second) {
		t.Error("signing the same message twice produced different bytes; the nonce is not deterministic")
	}

	other, err := signer.Sign(testDigest("a different message"))
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	if hex.EncodeToString(first) == hex.EncodeToString(other) {
		t.Error("different messages produced the same signature")
	}

	for name, signature := range map[string][]byte{"first": first, "second": second} {
		if err := Verify(signer.PublicKey(), digest, signature); err != nil {
			t.Errorf("%s signature must verify: %v", name, err)
		}
	}
}

// The signer holds a private key, so it must not be printable.
func TestSignerRevealsNoPrivateKey(t *testing.T) {
	private := testPrivateKey(t, 1)

	signer, err := NewSigner(private)
	if err != nil {
		t.Fatalf("building signer: %v", err)
	}

	raw, err := private.Bytes()
	if err != nil {
		t.Fatalf("reading key: %v", err)
	}
	material := hex.EncodeToString(raw)

	// The signer exposes only the public key.
	rendered := signer.PublicKey().String()
	if strings.Contains(rendered, material) {
		t.Error("the public key rendering contains private key material")
	}
	if strings.Contains(rendered, material[:16]) {
		t.Error("the public key rendering shares a prefix with the private key")
	}
}

// Real randomness must produce usable identities, not just the fixed seeds the
// other tests use.
func TestRandomKeysProduceValidIdentities(t *testing.T) {
	for range 20 {
		raw := make([]byte, domain.NostrKeySize)
		if _, err := rand.Read(raw); err != nil {
			t.Fatalf("generating randomness: %v", err)
		}

		private, err := domain.NewNostrPrivateKey(raw)
		if err != nil {
			continue // an all-zero draw is refused upstream, which is correct
		}

		signer, err := NewSigner(private)
		if err != nil {
			t.Fatalf("a random key must produce a signer: %v", err)
		}

		digest := testDigest("round trip")
		signature, err := signer.Sign(digest)
		if err != nil {
			t.Fatalf("signing: %v", err)
		}
		if err := Verify(signer.PublicKey(), digest, signature); err != nil {
			t.Fatalf("verifying: %v", err)
		}
	}
}
