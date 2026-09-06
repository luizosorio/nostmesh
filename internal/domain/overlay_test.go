package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"strings"
	"testing"
)

// testSalt builds a salt from a visible seed.
//
// Derived rather than written as a literal: a secret scanner cannot tell a salt
// from any other 32 bytes, so the project's rule is that test values come from
// seeds nobody has to classify.
func testSalt(t *testing.T, seed string) NetworkSalt {
	t.Helper()

	digest := sha256.Sum256([]byte(seed))
	salt, err := NewNetworkSalt(digest[:])
	if err != nil {
		t.Fatalf("building salt: %v", err)
	}
	return salt
}

func testNetworkID(t *testing.T, seed string) NetworkID {
	t.Helper()

	digest := sha256.Sum256([]byte(seed))
	id, err := NewNetworkID(digest[:])
	if err != nil {
		t.Fatalf("building network id: %v", err)
	}
	return id
}

func testPublicKey(t *testing.T, seed string) NostrPublicKey {
	t.Helper()

	digest := sha256.Sum256([]byte(seed))
	key, err := ParseNostrPublicKey(hex.EncodeToString(digest[:]))
	if err != nil {
		t.Fatalf("building public key: %v", err)
	}
	return key
}

// The same inputs produce the same address, every time and everywhere.
//
// This is the property the whole scheme rests on: two members who never speak
// must compute the same address for a third. A change to the output here is a
// compatibility break, and this test is what says so.
func TestDerivationIsDeterministic(t *testing.T) {
	salt := testSalt(t, "nostmesh test network salt")
	subnet := testNetworkID(t, "nostmesh test network").Subnet(0)
	key := testPublicKey(t, "member one")

	first, err := DeriveOverlayAddress(salt, subnet, key, 0)
	if err != nil {
		t.Fatalf("deriving: %v", err)
	}

	for range 16 {
		again, err := DeriveOverlayAddress(salt, subnet, key, 0)
		if err != nil {
			t.Fatalf("deriving again: %v", err)
		}
		if again != first {
			t.Fatalf("the same inputs produced %s and then %s", first, again)
		}
	}
}

// The golden vector, so a change to the derivation cannot pass unnoticed.
//
// Written out rather than computed, because a test that recomputes what it
// checks agrees with any implementation — including a broken one. If this fails
// after a deliberate change, the diff is the compatibility break.
//
// The values were taken from the implementation and then checked by hand against
// what the scheme requires: all three share the network prefix and subnet, the
// two members differ throughout the interface id rather than in a few bits, and
// the two counters for one member land nowhere near each other. A golden vector
// nobody inspected only records whatever the code did on the day it was written.
func TestTheDerivationMatchesItsGoldenVector(t *testing.T) {
	salt := testSalt(t, "nostmesh test network salt")
	subnet := testNetworkID(t, "nostmesh test network").Subnet(0)

	for _, testCase := range []struct {
		seed    string
		counter uint32
		want    string
	}{
		{"member one", 0, "fd3e:42a7:56e1:0:bdf:defd:f1a2:7b0c"},
		{"member one", 1, "fd3e:42a7:56e1:0:4:9b5d:9303:fc5e"},
		{"member two", 0, "fd3e:42a7:56e1:0:e9ea:c454:57e6:d28b"},
	} {
		t.Run(testCase.seed, func(t *testing.T) {
			got, err := DeriveOverlayAddress(salt, subnet, testPublicKey(t, testCase.seed), testCase.counter)
			if err != nil {
				t.Fatalf("deriving: %v", err)
			}
			if got.String() != testCase.want {
				t.Errorf("derived %s, want %s\nif this change was deliberate, it is a compatibility break", got, testCase.want)
			}
		})
	}
}

// A derived address lands inside the subnet it was derived for.
func TestADerivedAddressIsInsideItsSubnet(t *testing.T) {
	salt := testSalt(t, "nostmesh test network salt")
	network := testNetworkID(t, "nostmesh test network")

	for _, subnetID := range []uint16{0, 1, 0xffff} {
		subnet := network.Subnet(subnetID)

		address, err := DeriveOverlayAddress(salt, subnet, testPublicKey(t, "member one"), 0)
		if err != nil {
			t.Fatalf("deriving: %v", err)
		}
		if !subnet.Contains(address) {
			t.Errorf("%s is outside its subnet %s", address, subnet)
		}
	}
}

// A network's prefix is a locally assigned ULA.
//
// RFC 4193 leaves fc00::/8 undefined, so fd00::/8 is the only half anyone may
// use. An address outside it would be squatting on space that belongs elsewhere.
func TestANetworkPrefixIsALocallyAssignedULA(t *testing.T) {
	prefix := testNetworkID(t, "nostmesh test network").NetworkPrefix()

	if prefix.Bits() != NetworkPrefixBits {
		t.Errorf("network prefix is /%d, want /%d", prefix.Bits(), NetworkPrefixBits)
	}
	if first := prefix.Addr().As16()[0]; first != ulaMarker {
		t.Errorf("network prefix starts %#x, want %#x (fd00::/8)", first, ulaMarker)
	}
	if !prefix.Addr().IsPrivate() {
		t.Errorf("%s is not a private address, so it would be routed on the internet", prefix)
	}
}

// Incrementing the counter moves the address somewhere unrelated.
//
// This is what makes renumbering safe. Adding one to the address would walk into
// whatever neighbour occupies the next slot — likely the very member that
// collided. Re-deriving makes a second collision as unlikely as the first.
func TestTheCounterMovesTheAddressUnpredictably(t *testing.T) {
	salt := testSalt(t, "nostmesh test network salt")
	subnet := testNetworkID(t, "nostmesh test network").Subnet(0)
	key := testPublicKey(t, "member one")

	first, err := DeriveOverlayAddress(salt, subnet, key, 0)
	if err != nil {
		t.Fatalf("deriving: %v", err)
	}
	second, err := DeriveOverlayAddress(salt, subnet, key, 1)
	if err != nil {
		t.Fatalf("deriving: %v", err)
	}

	if first == second {
		t.Fatal("incrementing the counter did not move the address, so renumbering cannot resolve a collision")
	}

	// Adjacent addresses would mean the counter is being added to the result
	// rather than fed into the derivation.
	firstBytes, secondBytes := first.As16(), second.As16()
	adjacent := true
	for i := range 15 {
		if firstBytes[i] != secondBytes[i] {
			adjacent = false
			break
		}
	}
	if adjacent {
		t.Errorf("%s and %s differ only in the last byte; the counter is being added to the address rather than derived with", first, second)
	}
}

// The same identity in two networks gets unrelated addresses.
//
// This is the privacy claim NM-21 makes, and it is worth a test rather than a
// paragraph: one identity is expected to join more than one network, and if the
// addresses matched, joining twice would publish the link between them.
func TestOneIdentityGetsUnrelatedAddressesInTwoNetworks(t *testing.T) {
	key := testPublicKey(t, "member one")

	first, err := DeriveOverlayAddress(
		testSalt(t, "first network salt"),
		testNetworkID(t, "first network").Subnet(0), key, 0)
	if err != nil {
		t.Fatalf("deriving: %v", err)
	}
	second, err := DeriveOverlayAddress(
		testSalt(t, "second network salt"),
		testNetworkID(t, "second network").Subnet(0), key, 0)
	if err != nil {
		t.Fatalf("deriving: %v", err)
	}

	firstBytes, secondBytes := first.As16(), second.As16()
	if [8]byte(firstBytes[8:]) == [8]byte(secondBytes[8:]) {
		t.Error("the same identity got the same interface id in two networks, so the two memberships are linkable by address")
	}
}

// Two networks occupy different prefixes.
func TestTwoNetworksGetDifferentPrefixes(t *testing.T) {
	first := testNetworkID(t, "first network").NetworkPrefix()
	second := testNetworkID(t, "second network").NetworkPrefix()

	if first == second {
		t.Errorf("two networks share the prefix %s, so their traffic is indistinguishable", first)
	}
}

// The salt is what the derivation depends on, not just the key.
//
// If it were not, every network using the same identity would produce the same
// address and the salt would be decoration.
func TestTheSaltChangesTheAddress(t *testing.T) {
	subnet := testNetworkID(t, "nostmesh test network").Subnet(0)
	key := testPublicKey(t, "member one")

	first, err := DeriveOverlayAddress(testSalt(t, "one salt"), subnet, key, 0)
	if err != nil {
		t.Fatalf("deriving: %v", err)
	}
	second, err := DeriveOverlayAddress(testSalt(t, "another salt"), subnet, key, 0)
	if err != nil {
		t.Fatalf("deriving: %v", err)
	}

	if first == second {
		t.Error("changing the salt did not change the address, so the salt is not protecting anything")
	}
}

// A prefix that is not an overlay subnet is refused.
func TestANonOverlayPrefixIsRefused(t *testing.T) {
	salt := testSalt(t, "nostmesh test network salt")
	key := testPublicKey(t, "member one")

	for _, prefix := range []netip.Prefix{
		netip.MustParsePrefix("fd00::/48"),      // a network, not a subnet
		netip.MustParsePrefix("fd00::/128"),     // a single address
		netip.MustParsePrefix("192.168.1.0/24"), // IPv4
	} {
		if _, err := DeriveOverlayAddress(salt, prefix, key, 0); err == nil {
			t.Errorf("%s was accepted as an overlay subnet", prefix)
		}
	}
}

// A salt or network id of the wrong length is refused rather than padded.
func TestWrongSizedInputsAreRefused(t *testing.T) {
	for _, size := range []int{0, 16, 31, 33, 64} {
		if _, err := NewNetworkSalt(make([]byte, size)); err == nil {
			t.Errorf("a %d-byte salt was accepted", size)
		}
		if _, err := NewNetworkID(make([]byte, size)); err == nil {
			t.Errorf("a %d-byte network id was accepted", size)
		}
	}
}

// The derivation never returns the subnet-router anycast address.
//
// RFC 4291 reserves the all-zero interface id. A member handed it would be
// answering for the subnet rather than for itself.
func TestTheAnycastAddressIsNeverDerived(t *testing.T) {
	salt := testSalt(t, "nostmesh test network salt")
	subnet := testNetworkID(t, "nostmesh test network").Subnet(0)

	for i := range 256 {
		key := testPublicKey(t, "member "+string(rune('a'+i%26))+string(rune('a'+i/26)))

		address, err := DeriveOverlayAddress(salt, subnet, key, 0)
		if err != nil {
			t.Fatalf("deriving: %v", err)
		}
		if address == subnet.Addr() {
			t.Fatalf("%s is the subnet-router anycast address", address)
		}
	}
}

// No secret material reaches the derivation's inputs.
//
// NM-21 requires that the derivation take only public values, so that an address
// is reproducible by anyone who should reproduce it. The public key is the only
// per-member input; a private key has no path in.
func TestTheDerivationTakesOnlyPublicInputs(t *testing.T) {
	// Deriving with only a public key and a salt has to be sufficient: if the
	// signature required anything else, this would not compile.
	salt := testSalt(t, "nostmesh test network salt")
	subnet := testNetworkID(t, "nostmesh test network").Subnet(0)

	if _, err := DeriveOverlayAddress(salt, subnet, testPublicKey(t, "member one"), 0); err != nil {
		t.Fatalf("deriving from public inputs alone failed: %v", err)
	}

	// And the address must not contain the key it was derived from, which would
	// make the hash decorative.
	key := testPublicKey(t, "member one")
	address, err := DeriveOverlayAddress(salt, subnet, key, 0)
	if err != nil {
		t.Fatalf("deriving: %v", err)
	}
	if strings.Contains(hex.EncodeToString(address.AsSlice()), hex.EncodeToString(key[:8])) {
		t.Error("the address contains bytes of the public key verbatim")
	}
}
