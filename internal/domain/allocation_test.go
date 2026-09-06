package domain

import (
	"errors"
	"net/netip"
	"testing"
)

func manifestWith(t *testing.T, seeds ...string) Manifest {
	t.Helper()

	members := make([]Member, 0, len(seeds))
	for _, seed := range seeds {
		members = append(members, Member{PublicKey: testPublicKey(t, seed), Alias: seed})
	}

	return Manifest{
		NetworkID: testNetworkID(t, "nostmesh test network"),
		Version:   1,
		Members:   members,
	}
}

// Every member gets an address, and no two get the same one.
func TestAllocationGivesEveryMemberADistinctAddress(t *testing.T) {
	salt := testSalt(t, "nostmesh test network salt")
	manifest := manifestWith(t, "one", "two", "three", "four", "five")

	allocation, err := Allocate(manifest, salt, 0)
	if err != nil {
		t.Fatalf("allocating: %v", err)
	}

	if len(allocation.Assignments) != len(manifest.Members) {
		t.Fatalf("allocated %d addresses for %d members",
			len(allocation.Assignments), len(manifest.Members))
	}

	seen := make(map[netip.Addr]NostrPublicKey)
	for _, assignment := range allocation.Assignments {
		if holder, clash := seen[assignment.Address]; clash {
			t.Errorf("%s and %s both got %s",
				holder.Short(), assignment.Member.Short(), assignment.Address)
		}
		seen[assignment.Address] = assignment.Member

		if !allocation.Subnet.Contains(assignment.Address) {
			t.Errorf("%s is outside the subnet %s", assignment.Address, allocation.Subnet)
		}
	}
}

// The manifest's member order does not change the table.
//
// Two nodes handed the same network written differently must produce identical
// allocations. If order mattered, a collision would be resolved in favour of
// whoever happened to be listed first, and the two ends would disagree about
// which of them had to move.
func TestAllocationDoesNotDependOnManifestOrder(t *testing.T) {
	salt := testSalt(t, "nostmesh test network salt")

	forwards := manifestWith(t, "one", "two", "three", "four")
	backwards := manifestWith(t, "four", "three", "two", "one")

	first, err := Allocate(forwards, salt, 0)
	if err != nil {
		t.Fatalf("allocating: %v", err)
	}
	second, err := Allocate(backwards, salt, 0)
	if err != nil {
		t.Fatalf("allocating: %v", err)
	}

	if len(first.Assignments) != len(second.Assignments) {
		t.Fatalf("different lengths: %d and %d", len(first.Assignments), len(second.Assignments))
	}
	for i := range first.Assignments {
		if first.Assignments[i] != second.Assignments[i] {
			t.Errorf("entry %d differs: %+v and %+v", i, first.Assignments[i], second.Assignments[i])
		}
	}
}

// Allocation is deterministic across runs.
func TestAllocationIsDeterministic(t *testing.T) {
	salt := testSalt(t, "nostmesh test network salt")
	manifest := manifestWith(t, "one", "two", "three")

	first, err := Allocate(manifest, salt, 0)
	if err != nil {
		t.Fatalf("allocating: %v", err)
	}

	for range 8 {
		again, err := Allocate(manifest, salt, 0)
		if err != nil {
			t.Fatalf("allocating again: %v", err)
		}
		for i := range first.Assignments {
			if first.Assignments[i] != again.Assignments[i] {
				t.Fatalf("entry %d changed between runs", i)
			}
		}
	}
}

// Nobody is renumbered when nothing collides.
//
// A counter above zero means a member lost a collision, and in a 64-bit space
// that should never happen by chance. This is what makes Renumbered() worth
// looking at: anything in it is a signal, not noise.
func TestNobodyIsRenumberedWithoutACollision(t *testing.T) {
	salt := testSalt(t, "nostmesh test network salt")
	manifest := manifestWith(t, "one", "two", "three", "four", "five", "six")

	allocation, err := Allocate(manifest, salt, 0)
	if err != nil {
		t.Fatalf("allocating: %v", err)
	}

	if renumbered := allocation.Renumbered(); len(renumbered) != 0 {
		t.Errorf("%d members were renumbered with nothing to collide with: %+v",
			len(renumbered), renumbered)
	}
}

// A collision renumbers the loser rather than overwriting the winner.
//
// A real 64-bit collision cannot be produced — the first is expected after some
// five billion members — so this exercises the resolution path directly, by
// pre-claiming the address a member is about to derive. That is exactly the
// state allocateOne sees on the second of two colliding members.
func TestACollisionRenumbersTheLoser(t *testing.T) {
	salt := testSalt(t, "nostmesh test network salt")
	subnet := testNetworkID(t, "nostmesh test network").Subnet(0)
	member := Member{PublicKey: testPublicKey(t, "one")}

	first, err := DeriveOverlayAddress(salt, subnet, member.PublicKey, 0)
	if err != nil {
		t.Fatalf("deriving: %v", err)
	}

	// Somebody already holds what this member would derive.
	incumbent := testPublicKey(t, "the incumbent")
	taken := map[netip.Addr]NostrPublicKey{first: incumbent}

	assignment, err := allocateOne(member, salt, subnet, taken)
	if err != nil {
		t.Fatalf("allocating into a collision: %v", err)
	}

	if assignment.Address == first {
		t.Fatal("the loser was given the address the incumbent already held")
	}
	if assignment.Counter == 0 {
		t.Error("the loser was not renumbered, so the collision went unrecorded")
	}

	// And the address it moved to is the one both ends compute, not an
	// arbitrary next slot.
	expected, err := DeriveOverlayAddress(salt, subnet, member.PublicKey, assignment.Counter)
	if err != nil {
		t.Fatalf("deriving: %v", err)
	}
	if assignment.Address != expected {
		t.Errorf("renumbered to %s, but counter %d derives %s — the two ends would disagree",
			assignment.Address, assignment.Counter, expected)
	}
}

// Renumbering is bounded rather than infinite.
//
// A member that collides on every counter must fail loudly. The alternative is a
// loop, or worse, installing an address somebody else holds.
func TestExhaustedRenumberingFails(t *testing.T) {
	salt := testSalt(t, "nostmesh test network salt")
	subnet := testNetworkID(t, "nostmesh test network").Subnet(0)
	member := Member{PublicKey: testPublicKey(t, "one")}

	// Every address this member could derive is already taken.
	taken := make(map[netip.Addr]NostrPublicKey)
	for counter := uint32(0); counter <= maxDerivationCounter; counter++ {
		address, err := DeriveOverlayAddress(salt, subnet, member.PublicKey, counter)
		if err != nil {
			t.Fatalf("deriving: %v", err)
		}
		taken[address] = testPublicKey(t, "the incumbent")
	}

	_, err := allocateOne(member, salt, subnet, taken)
	if !errors.Is(err, ErrAddressConflict) {
		t.Errorf("expected a conflict, got: %v", err)
	}
}

// A conflict is never resolved by silently handing over an occupied address.
//
// This is the acceptance criterion NM-21 states outright, and the failure it
// guards against is the worst kind: traffic reaching the wrong node through a
// tunnel that looks entirely healthy.
func TestAConflictNeverYieldsAnOccupiedAddress(t *testing.T) {
	salt := testSalt(t, "nostmesh test network salt")
	subnet := testNetworkID(t, "nostmesh test network").Subnet(0)
	member := Member{PublicKey: testPublicKey(t, "one")}

	// Claim the first several addresses this member would derive, so the search
	// has to walk past them.
	taken := make(map[netip.Addr]NostrPublicKey)
	for counter := uint32(0); counter < 5; counter++ {
		address, err := DeriveOverlayAddress(salt, subnet, member.PublicKey, counter)
		if err != nil {
			t.Fatalf("deriving: %v", err)
		}
		taken[address] = testPublicKey(t, "the incumbent")
	}

	assignment, err := allocateOne(member, salt, subnet, taken)
	if err != nil {
		t.Fatalf("allocating: %v", err)
	}

	if holder, clash := taken[assignment.Address]; clash {
		t.Errorf("allocated %s, which %s already holds", assignment.Address, holder.Short())
	}
	if assignment.Counter != 5 {
		t.Errorf("counter = %d, want 5; the search skipped or repeated an attempt", assignment.Counter)
	}
}

// An explicitly assigned IPv4 address is carried through.
func TestAnAssignedIPv4AddressIsCarried(t *testing.T) {
	salt := testSalt(t, "nostmesh test network salt")

	manifest := manifestWith(t, "one", "two")
	manifest.Members[0].IPv4 = "10.20.30.40/32"

	allocation, err := Allocate(manifest, salt, 0)
	if err != nil {
		t.Fatalf("allocating: %v", err)
	}

	assignment, err := allocation.For(manifest.Members[0].PublicKey)
	if err != nil {
		t.Fatalf("looking up: %v", err)
	}
	if assignment.IPv4.String() != "10.20.30.40/32" {
		t.Errorf("ipv4 = %s, want 10.20.30.40/32", assignment.IPv4)
	}
}

// Two members assigned the same IPv4 address is reported, not resolved.
//
// This is an operator's mistake rather than a hash collision, and there is no
// rule that could pick a winner without overriding what they wrote.
func TestDuplicateIPv4AssignmentsAreReported(t *testing.T) {
	manifest := manifestWith(t, "one", "two")
	manifest.Members[0].IPv4 = "10.20.30.40/32"
	manifest.Members[1].IPv4 = "10.20.30.40/32"

	if err := CheckIPv4Conflicts(manifest); !errors.Is(err, ErrAddressConflict) {
		t.Errorf("expected a conflict, got: %v", err)
	}
}

// Distinct IPv4 assignments pass.
func TestDistinctIPv4AssignmentsAreAccepted(t *testing.T) {
	manifest := manifestWith(t, "one", "two")
	manifest.Members[0].IPv4 = "10.20.30.40/32"
	manifest.Members[1].IPv4 = "10.20.30.41/32"

	if err := CheckIPv4Conflicts(manifest); err != nil {
		t.Errorf("distinct assignments were refused: %v", err)
	}
}

// An unparseable or non-IPv4 assignment is refused rather than ignored.
func TestABadIPv4AssignmentIsRefused(t *testing.T) {
	salt := testSalt(t, "nostmesh test network salt")

	for _, bad := range []string{"not-an-address", "10.20.30.40", "fd00::1/128", "10.0.0.0/8/8"} {
		manifest := manifestWith(t, "one")
		manifest.Members[0].IPv4 = bad

		if _, err := Allocate(manifest, salt, 0); !errors.Is(err, ErrManifestMalformed) {
			t.Errorf("%q was accepted as an ipv4 assignment: %v", bad, err)
		}
	}
}

// A member absent from the manifest has no assignment.
func TestAStrangerHasNoAssignment(t *testing.T) {
	salt := testSalt(t, "nostmesh test network salt")

	allocation, err := Allocate(manifestWith(t, "one", "two"), salt, 0)
	if err != nil {
		t.Fatalf("allocating: %v", err)
	}

	if _, err := allocation.For(testPublicKey(t, "a stranger")); !errors.Is(err, ErrNotAMember) {
		t.Errorf("expected a not-a-member error, got: %v", err)
	}
}

// A malformed manifest is refused before anything is allocated.
func TestAllocatingAMalformedManifestFails(t *testing.T) {
	salt := testSalt(t, "nostmesh test network salt")

	manifest := manifestWith(t, "one")
	manifest.Version = 0

	if _, err := Allocate(manifest, salt, 0); !errors.Is(err, ErrManifestMalformed) {
		t.Errorf("expected a malformed refusal, got: %v", err)
	}
}

// Two networks allocate the same members to unrelated addresses.
//
// The privacy claim again, this time at the level of a whole table: joining two
// networks with one identity must not produce a matching row in both.
func TestTwoNetworksAllocateUnrelatedAddresses(t *testing.T) {
	manifest := manifestWith(t, "one", "two", "three")

	first, err := Allocate(manifest, testSalt(t, "first salt"), 0)
	if err != nil {
		t.Fatalf("allocating: %v", err)
	}
	second, err := Allocate(manifest, testSalt(t, "second salt"), 0)
	if err != nil {
		t.Fatalf("allocating: %v", err)
	}

	for i := range first.Assignments {
		if first.Assignments[i].Address == second.Assignments[i].Address {
			t.Errorf("%s got the same address in both networks", first.Assignments[i].Member.Short())
		}
	}
}
