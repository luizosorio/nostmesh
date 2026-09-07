package main

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/luizosorio/nostmesh/internal/domain"
	"github.com/luizosorio/nostmesh/internal/wireguard"
)

func slotTestKey(t *testing.T, seed string) domain.NostrPublicKey {
	t.Helper()

	digest := sha256.Sum256([]byte(seed))
	key, err := domain.ParseNostrPublicKey(hex.EncodeToString(digest[:]))
	if err != nil {
		t.Fatalf("building key: %v", err)
	}
	return key
}

// A peer's slot is the same on every run.
//
// This is what NM-15 needs. A peer verified a NAT mapping for one port, and
// coming back on a different one describes a mapping nothing verified — the
// failure that looks like a NAT problem while every candidate is marked valid.
func TestASlotIsStableAcrossRuns(t *testing.T) {
	peer := slotTestKey(t, "a peer")

	first, err := slotFor(peer, 51820)
	if err != nil {
		t.Fatalf("deriving: %v", err)
	}

	for range 16 {
		again, err := slotFor(peer, 51820)
		if err != nil {
			t.Fatalf("deriving again: %v", err)
		}
		if again != first {
			t.Fatalf("the same peer got %+v then %+v; a restart would break its verified mapping", first, again)
		}
	}
}

// Adding or removing a peer does not move anybody else.
//
// A counted allocation would shift every port when the peer list changed,
// invalidating every NAT mapping the other peers had verified — a change to one
// peer breaking every other is the opposite of independent sessions.
func TestASlotDoesNotDependOnTheOtherPeers(t *testing.T) {
	alice, bob := slotTestKey(t, "alice"), slotTestKey(t, "bob")

	alone, err := assignSlots([]domain.NostrPublicKey{alice}, 51820)
	if err != nil {
		t.Fatalf("assigning: %v", err)
	}
	together, err := assignSlots([]domain.NostrPublicKey{bob, alice}, 51820)
	if err != nil {
		t.Fatalf("assigning: %v", err)
	}

	if alone[alice] != together[alice] {
		t.Errorf("alice moved from %+v to %+v when bob joined", alone[alice], together[alice])
	}
}

// Two peers get different interfaces and different ports.
//
// Sharing either is what makes multi-peer fail today: the second session to
// establish rewrites the first's kernel state, and the second to end deletes it.
func TestTwoPeersGetDistinctSlots(t *testing.T) {
	slots, err := assignSlots([]domain.NostrPublicKey{
		slotTestKey(t, "alice"), slotTestKey(t, "bob"), slotTestKey(t, "carol"),
	}, 51820)
	if err != nil {
		t.Fatalf("assigning: %v", err)
	}

	names := make(map[string]bool)
	ports := make(map[int]bool)
	for peer, slot := range slots {
		if names[slot.Interface] {
			t.Errorf("%s reuses interface %s", peer.Short(), slot.Interface)
		}
		if ports[slot.Port] {
			t.Errorf("%s reuses port %d", peer.Short(), slot.Port)
		}
		names[slot.Interface] = true
		ports[slot.Port] = true
	}
}

// The interface name is one this project owns and Linux accepts.
func TestASlotNameIsOwnedAndFits(t *testing.T) {
	for _, seed := range []string{"alice", "bob", "carol", "dave", "erin"} {
		slot, err := slotFor(slotTestKey(t, seed), 51820)
		if err != nil {
			t.Fatalf("deriving: %v", err)
		}

		if !wireguard.OwnsInterface(slot.Interface) {
			t.Errorf("%s is not an interface this project owns", slot.Interface)
		}
		if len(slot.Interface) > interfaceNameLimit {
			t.Errorf("%s is %d bytes; Linux refuses anything over %d",
				slot.Interface, len(slot.Interface), interfaceNameLimit)
		}
	}
}

// The name carries the same abbreviation the logs use.
//
// An operator reading `nm-a1b2c3d4` has to be able to find that peer in a log
// line, and the logs abbreviate to eight characters.
func TestASlotNameMatchesTheLoggedAbbreviation(t *testing.T) {
	peer := slotTestKey(t, "alice")

	slot, err := slotFor(peer, 51820)
	if err != nil {
		t.Fatalf("deriving: %v", err)
	}

	if !strings.HasSuffix(slot.Interface, peer.Short()) {
		t.Errorf("interface %s does not carry the peer's abbreviation %s", slot.Interface, peer.Short())
	}
}

// A colliding pair is refused with both peers named.
//
// Eight hex characters is plenty against accident and nothing against a peer
// that chose its key to collide, so this is checked rather than assumed.
func TestACollidingPairIsRefused(t *testing.T) {
	peer := slotTestKey(t, "alice")

	// The same peer twice is the shape a collision takes, and the only one a
	// test can produce without searching for a hash prefix.
	if _, err := assignSlots([]domain.NostrPublicKey{peer, peer}, 51820); err == nil {
		t.Error("two peers deriving one slot were accepted")
	}
}

// Port zero keeps meaning "let the kernel choose".
//
// It is what a client that only dials out wants, and every peer gets its own
// socket, so nothing collides.
func TestPortZeroLetsTheKernelChoose(t *testing.T) {
	slots, err := assignSlots([]domain.NostrPublicKey{
		slotTestKey(t, "alice"), slotTestKey(t, "bob"),
	}, 0)
	if err != nil {
		t.Fatalf("assigning: %v", err)
	}

	for peer, slot := range slots {
		if slot.Port != 0 {
			t.Errorf("%s got port %d when the operator asked the kernel to choose", peer.Short(), slot.Port)
		}
	}
}

// A base port with no room for the span is refused.
//
// Deriving past 65535 would wrap or fail at bind, and either failure appears far
// from the configuration that caused it.
func TestABasePortWithNoRoomIsRefused(t *testing.T) {
	if _, err := slotFor(slotTestKey(t, "alice"), 65535); err == nil {
		t.Error("a base port leaving no room for the span was accepted")
	}
}

// Ports stay inside the declared span.
//
// A node must not quietly claim more of the host's port space than it said it
// would.
func TestPortsStayInsideTheSpan(t *testing.T) {
	const base = 51820

	for _, seed := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
		slot, err := slotFor(slotTestKey(t, seed), base)
		if err != nil {
			t.Fatalf("deriving: %v", err)
		}

		if slot.Port < base || slot.Port >= base+slotPortSpan {
			t.Errorf("%s got port %d, outside [%d, %d)", seed, slot.Port, base, base+slotPortSpan)
		}
	}
}
