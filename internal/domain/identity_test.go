package domain

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func nostrKey(t *testing.T, seed byte) NostrPublicKey {
	t.Helper()

	var key NostrPublicKey
	for i := range key {
		key[i] = seed + byte(i)
	}
	if key.IsZero() {
		t.Fatal("test key must not be zero")
	}
	return key
}

// testTime is the fixed clock reading these tests judge against.
func testTime() time.Time {
	return time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
}

func TestIdentityStringsCarryNoSecret(t *testing.T) {
	private := testNostrPrivate(t)
	identity, err := NewNodeIdentity(nostrKey(t, 1), private, testTime())
	if err != nil {
		t.Fatalf("building identity: %v", err)
	}

	raw, err := private.Bytes()
	if err != nil {
		t.Fatalf("reading key bytes: %v", err)
	}

	rendered := identity.String()
	if strings.Contains(rendered, hex.EncodeToString(raw[:8])) {
		t.Errorf("identity rendering must not contain key material: %s", rendered)
	}
	if strings.Contains(rendered, string(raw)) {
		t.Errorf("identity rendering must not contain raw key bytes: %s", rendered)
	}
}

func TestParseKeysRejectBadInput(t *testing.T) {
	t.Run("nostr", func(t *testing.T) {
		for _, input := range []string{"", "zz", strings.Repeat("0", 64), strings.Repeat("ab", 16)} {
			if _, err := ParseNostrPublicKey(input); err == nil {
				t.Errorf("input %q must be rejected", input)
			}
		}
	})

	t.Run("wireguard", func(t *testing.T) {
		for _, input := range []string{"", "not base64!", "c2hvcnQ="} {
			if _, err := ParseWireGuardPublicKey(input); err == nil {
				t.Errorf("input %q must be rejected", input)
			}
		}
	})
}
