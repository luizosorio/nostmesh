package domain

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func testNostrPrivate(t *testing.T) NostrPrivateKey {
	t.Helper()

	raw := make([]byte, NostrKeySize)
	for i := range raw {
		raw[i] = byte(i + 1)
	}
	key, err := NewNostrPrivateKey(raw)
	if err != nil {
		t.Fatalf("building test key: %v", err)
	}
	return key
}

func testWireGuardPrivate(t *testing.T) WireGuardPrivateKey {
	t.Helper()

	raw := make([]byte, WireGuardKeySize)
	for i := range raw {
		raw[i] = byte(i + 100)
	}
	key, err := NewWireGuardPrivateKey(raw)
	if err != nil {
		t.Fatalf("building test key: %v", err)
	}
	return key
}

// The central invariant of the project: a private key must not be printable.
// Every formatting verb, and the logger, must yield a redaction marker.
func TestPrivateKeysNeverPrint(t *testing.T) {
	nostr := testNostrPrivate(t)
	wg := testWireGuardPrivate(t)

	nostrRaw, err := nostr.Bytes()
	if err != nil {
		t.Fatalf("reading key bytes: %v", err)
	}
	wgRaw, err := wg.Bytes()
	if err != nil {
		t.Fatalf("reading key bytes: %v", err)
	}

	// Any rendering that contains a run of the actual key bytes has leaked.
	leaked := func(rendered string) bool {
		return strings.Contains(rendered, fmt.Sprintf("%x", nostrRaw[:8])) ||
			strings.Contains(rendered, fmt.Sprintf("%x", wgRaw[:8]))
	}

	renderings := []struct {
		name     string
		rendered string
	}{
		{"nostr %v", fmt.Sprintf("%v", nostr)},
		{"nostr String()", nostr.String()},
		{"nostr %+v", fmt.Sprintf("%+v", nostr)},
		{"nostr %#v", fmt.Sprintf("%#v", nostr)},
		{"nostr %q", fmt.Sprintf("%q", nostr)},
		{"wireguard %v", fmt.Sprintf("%v", wg)},
		{"wireguard String()", wg.String()},
		{"wireguard %+v", fmt.Sprintf("%+v", wg)},
		{"wireguard %#v", fmt.Sprintf("%#v", wg)},
		{"wireguard %q", fmt.Sprintf("%q", wg)},
	}

	for _, r := range renderings {
		t.Run(r.name, func(t *testing.T) {
			if leaked(r.rendered) {
				t.Fatalf("key material appeared in output: %s", r.rendered)
			}
			if !strings.Contains(r.rendered, "REDACTED") {
				t.Errorf("expected a redaction marker, got: %s", r.rendered)
			}
		})
	}
}

// Structured logging is the most likely accidental disclosure path, so it is
// checked against the real logger rather than assumed to follow from String.
func TestPrivateKeysDoNotLeakThroughSlog(t *testing.T) {
	key := testWireGuardPrivate(t)
	raw, err := key.Bytes()
	if err != nil {
		t.Fatalf("reading key bytes: %v", err)
	}

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	logger.Info("session configured", "tunnel_key", key)

	output := buf.String()
	if strings.Contains(output, fmt.Sprintf("%x", raw[:8])) {
		t.Fatalf("key material reached the log: %s", output)
	}
	if !strings.Contains(output, "REDACTED") {
		t.Errorf("expected a redaction marker in the log, got: %s", output)
	}
}

// Serialization fails outright rather than emitting a placeholder, so a struct
// carrying a secret cannot be shipped somewhere while looking well-formed.
func TestPrivateKeysRefuseSerialization(t *testing.T) {
	t.Run("nostr", func(t *testing.T) {
		if _, err := json.Marshal(testNostrPrivate(t)); err == nil {
			t.Fatal("marshaling a nostr private key must fail")
		}
	})

	t.Run("wireguard", func(t *testing.T) {
		if _, err := json.Marshal(testWireGuardPrivate(t)); err == nil {
			t.Fatal("marshaling a wireguard private key must fail")
		}
	})

	t.Run("nested in a struct", func(t *testing.T) {
		payload := struct {
			Session string              `json:"session"`
			Key     WireGuardPrivateKey `json:"key"`
		}{Session: "abc", Key: testWireGuardPrivate(t)}

		if _, err := json.Marshal(payload); err == nil {
			t.Fatal("marshaling a struct containing a private key must fail")
		}
	})
}

func TestDestroyZeroesKey(t *testing.T) {
	key := testWireGuardPrivate(t)

	before, err := key.Bytes()
	if err != nil {
		t.Fatalf("reading key bytes: %v", err)
	}
	if isZeroBytes(before) {
		t.Fatal("test key must not start zeroed")
	}

	key.Destroy()

	if !key.IsDestroyed() {
		t.Error("key must report itself destroyed")
	}
	if _, err := key.Bytes(); err == nil {
		t.Error("reading a destroyed key must fail")
	}
	if _, err := key.Base64ForKeystore(); err == nil {
		t.Error("encoding a destroyed key must fail")
	}
}

// Bytes returns a copy: a caller mutating the result must not corrupt the key.
func TestBytesReturnsCopy(t *testing.T) {
	key := testWireGuardPrivate(t)

	first, err := key.Bytes()
	if err != nil {
		t.Fatalf("reading key bytes: %v", err)
	}
	for i := range first {
		first[i] = 0xFF
	}

	second, err := key.Bytes()
	if err != nil {
		t.Fatalf("reading key bytes: %v", err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("mutating the returned slice corrupted the key")
	}
}

func TestRejectsZeroKeys(t *testing.T) {
	zeros := make([]byte, WireGuardKeySize)

	if _, err := NewNostrPrivateKey(zeros); err == nil {
		t.Error("an all-zero nostr key must be rejected")
	}
	if _, err := NewWireGuardPrivateKey(zeros); err == nil {
		t.Error("an all-zero wireguard key must be rejected")
	}
}

func TestRejectsWrongKeySize(t *testing.T) {
	short := make([]byte, 16)
	for i := range short {
		short[i] = 1
	}

	if _, err := NewNostrPrivateKey(short); err == nil {
		t.Error("a short nostr key must be rejected")
	}
	if _, err := NewWireGuardPrivateKey(short); err == nil {
		t.Error("a short wireguard key must be rejected")
	}
}

// WireGuard requires Curve25519 clamping; without it a key is not a valid
// scalar and the resulting public key would be wrong.
func TestWireGuardKeyIsClamped(t *testing.T) {
	raw := make([]byte, WireGuardKeySize)
	for i := range raw {
		raw[i] = 0xFF
	}

	key, err := NewWireGuardPrivateKey(raw)
	if err != nil {
		t.Fatalf("building key: %v", err)
	}

	clamped, err := key.Bytes()
	if err != nil {
		t.Fatalf("reading key bytes: %v", err)
	}

	if clamped[0]&7 != 0 {
		t.Errorf("low three bits of byte 0 must be cleared, got %08b", clamped[0])
	}
	if clamped[31]&128 != 0 {
		t.Errorf("high bit of byte 31 must be cleared, got %08b", clamped[31])
	}
	if clamped[31]&64 == 0 {
		t.Errorf("bit 6 of byte 31 must be set, got %08b", clamped[31])
	}
}
