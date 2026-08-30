package identity

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/luizosorio/nostmesh/internal/domain"
)

// failingReader simulates an exhausted or broken randomness source.
type failingReader struct{ afterBytes int }

func (r *failingReader) Read(p []byte) (int, error) {
	if r.afterBytes <= 0 {
		return 0, errors.New("entropy source failed")
	}
	n := min(len(p), r.afterBytes)
	for i := range p[:n] {
		p[i] = 1
	}
	r.afterBytes -= n
	return n, nil
}

// zeroReader always yields zeros, which must never produce a usable key.
type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

// ADR-003: Nostr and WireGuard keys must never share secret material. This is
// the test that would catch a refactor accidentally deriving one from the
// other.
func TestNostrAndWireGuardKeysAreIndependent(t *testing.T) {
	generator := NewKeyGenerator()

	nostr, err := generator.GenerateNostrKey()
	if err != nil {
		t.Fatalf("generating nostr key: %v", err)
	}
	_, wg, err := generator.Generate()
	if err != nil {
		t.Fatalf("generating wireguard key: %v", err)
	}

	nostrRaw, err := nostr.Bytes()
	if err != nil {
		t.Fatalf("reading nostr key: %v", err)
	}
	wgRaw, err := wg.Bytes()
	if err != nil {
		t.Fatalf("reading wireguard key: %v", err)
	}

	if bytes.Equal(nostrRaw, wgRaw) {
		t.Fatal("nostr and wireguard keys must not share material")
	}
}

// Every session gets an independent tunnel key. Reuse across sessions would let
// an old session's key open a new one.
func TestEachTunnelKeyIsDistinct(t *testing.T) {
	generator := NewKeyGenerator()
	seen := make(map[string]bool)

	for i := 0; i < 50; i++ {
		public, private, err := generator.Generate()
		if err != nil {
			t.Fatalf("generating key %d: %v", i, err)
		}

		raw, err := private.Bytes()
		if err != nil {
			t.Fatalf("reading key %d: %v", i, err)
		}

		if seen[string(raw)] {
			t.Fatalf("private key repeated after %d generations", i)
		}
		seen[string(raw)] = true

		if public.IsZero() {
			t.Fatal("derived public key must not be zero")
		}
	}
}

// The public key must actually correspond to the private key, or WireGuard
// would fail to handshake with no useful diagnostic.
func TestDerivedPublicKeyMatchesPrivateKey(t *testing.T) {
	generator := NewKeyGenerator()

	public, private, err := generator.Generate()
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	derived, err := DerivePublicKey(private)
	if err != nil {
		t.Fatalf("deriving public key: %v", err)
	}
	if derived != public {
		t.Error("derived public key does not match the one returned at generation")
	}
}

// A node that cannot produce unpredictable keys must fail loudly rather than
// emit a weak one.
func TestEntropyFailureIsFatal(t *testing.T) {
	tests := []struct {
		name   string
		source io.Reader
	}{
		{"source fails immediately", &failingReader{afterBytes: 0}},
		{"source truncates mid-key", &failingReader{afterBytes: 10}},
		{"source yields zeros", zeroReader{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			generator := NewKeyGeneratorWithSource(tt.source)

			if _, err := generator.GenerateNostrKey(); err == nil {
				t.Error("generating a nostr key must fail")
			}
			if _, _, err := generator.Generate(); err == nil {
				t.Error("generating a wireguard key must fail")
			}
		})
	}
}

func TestEntropyFailureReportsInsufficientEntropy(t *testing.T) {
	generator := NewKeyGeneratorWithSource(&failingReader{afterBytes: 0})

	_, err := generator.GenerateNostrKey()
	if !errors.Is(err, domain.ErrInsufficientEntropy) {
		t.Errorf("expected ErrInsufficientEntropy, got: %v", err)
	}
}
