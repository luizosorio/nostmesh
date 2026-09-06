package domain

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// Address allocation across a network, per NM-21.
//
// Every member derives every address, so allocation is a computation rather than
// a negotiation: two members who never speak arrive at the same table. What this
// adds over the derivation itself is collision handling — detecting when two
// identities land on one address, and renumbering deterministically so that both
// ends agree on where the loser moves without exchanging a message.

var (
	// ErrAddressConflict reports two identities deriving the same address with
	// no resolution available.
	//
	// It exists so a conflict can never be mistaken for success. An address
	// installed while this is unresolved would route somebody else's traffic,
	// and the tunnel carrying it would look perfectly healthy.
	ErrAddressConflict = errors.New("two members derived the same overlay address")

	// ErrNotAMember reports an identity absent from the manifest being
	// allocated.
	ErrNotAMember = errors.New("identity is not in the manifest")
)

// Assignment is one member's place in the network.
type Assignment struct {
	// Member is the identity this address belongs to.
	Member NostrPublicKey

	// Address is the derived overlay address.
	Address netip.Addr

	// Counter is how many times the derivation had to be repeated before this
	// address was free. Zero for almost every member; a non-zero value means
	// this member lost a collision and was renumbered.
	Counter uint32

	// IPv4 is the explicitly assigned compatibility address, if the manifest
	// gave one. Empty otherwise, which is the ordinary case.
	IPv4 netip.Prefix
}

// Allocation is the whole network's address table.
type Allocation struct {
	// Subnet is the prefix every address in this table falls inside.
	Subnet netip.Prefix

	// Assignments is one entry per member, ordered by identity so that two
	// nodes produce byte-identical tables.
	Assignments []Assignment
}

// For returns one member's assignment.
func (a Allocation) For(member NostrPublicKey) (Assignment, error) {
	for _, assignment := range a.Assignments {
		if assignment.Member == member {
			return assignment, nil
		}
	}
	return Assignment{}, fmt.Errorf("%w: %s", ErrNotAMember, member.Short())
}

// Renumbered reports the members whose address is not their first choice.
//
// A member here lost a collision. In a 64-bit space that is vanishingly
// unlikely, so a non-empty result is worth an operator's attention: it is far
// more likely to mean two members share an identity than that a hash collided.
func (a Allocation) Renumbered() []Assignment {
	var renumbered []Assignment
	for _, assignment := range a.Assignments {
		if assignment.Counter > 0 {
			renumbered = append(renumbered, assignment)
		}
	}
	return renumbered
}

// Allocate computes the address table for a manifest.
//
// Members are processed in identity order rather than manifest order, so that
// two nodes given the same manifest written differently produce the same table.
// Without that, a collision would be resolved in favour of whichever member
// happened to be listed first, and the two ends would disagree about which of
// them had to move.
//
// A collision advances the loser's counter and re-derives. The winner is the
// member whose identity sorts first — an arbitrary rule, but one both ends
// compute identically, which is the only property that matters.
func Allocate(manifest Manifest, salt NetworkSalt, subnetIndex int) (Allocation, error) {
	if err := manifest.Validate(); err != nil {
		return Allocation{}, err
	}

	subnet := manifest.NetworkID.Subnet(manifest.Subnet(subnetIndex))

	members := slices.Clone(manifest.Members)
	slices.SortFunc(members, func(a, b Member) int {
		return strings.Compare(a.PublicKey.String(), b.PublicKey.String())
	})

	allocation := Allocation{
		Subnet:      subnet,
		Assignments: make([]Assignment, 0, len(members)),
	}
	taken := make(map[netip.Addr]NostrPublicKey, len(members))

	for _, member := range members {
		assignment, err := allocateOne(member, salt, subnet, taken)
		if err != nil {
			return Allocation{}, err
		}

		taken[assignment.Address] = member.PublicKey
		allocation.Assignments = append(allocation.Assignments, assignment)
	}

	return allocation, nil
}

// allocateOne finds a free address for one member.
func allocateOne(member Member, salt NetworkSalt, subnet netip.Prefix,
	taken map[netip.Addr]NostrPublicKey,
) (Assignment, error) {
	ipv4, err := parseAssignedIPv4(member)
	if err != nil {
		return Assignment{}, err
	}

	for counter := uint32(0); counter <= maxDerivationCounter; counter++ {
		address, err := DeriveOverlayAddress(salt, subnet, member.PublicKey, counter)
		if err != nil {
			return Assignment{}, err
		}

		if holder, clash := taken[address]; clash {
			// Somebody already has it. The counter advances and the derivation
			// runs again, landing somewhere unrelated rather than at the next
			// address along — which would very likely be another member's.
			_ = holder
			continue
		}

		return Assignment{
			Member:  member.PublicKey,
			Address: address,
			Counter: counter,
			IPv4:    ipv4,
		}, nil
	}

	// Reached only if a member collided with every counter the bound allows,
	// which cannot happen by chance in a 64-bit space. Failing here is the point:
	// the alternative is installing an address somebody else holds.
	return Assignment{}, fmt.Errorf("%w: %s could not be placed after %d attempts",
		ErrAddressConflict, member.PublicKey.Short(), maxDerivationCounter)
}

// parseAssignedIPv4 reads a member's explicit IPv4 assignment.
//
// Assigned rather than derived: NM-21 measured that twenty nodes in a /24 collide
// more often than not, so this is an operator's allocation and is checked as
// input rather than trusted.
func parseAssignedIPv4(member Member) (netip.Prefix, error) {
	if member.IPv4 == "" {
		return netip.Prefix{}, nil
	}

	prefix, err := netip.ParsePrefix(member.IPv4)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%w: %s has an unparseable ipv4 assignment",
			ErrManifestMalformed, member.PublicKey.Short())
	}
	if !prefix.Addr().Is4() {
		return netip.Prefix{}, fmt.Errorf("%w: %s has a non-IPv4 address in its ipv4 assignment",
			ErrManifestMalformed, member.PublicKey.Short())
	}
	return prefix, nil
}

// CheckIPv4Conflicts reports members sharing an explicitly assigned address.
//
// Separate from Allocate because these are an operator's mistake rather than a
// hash collision: two members handed the same address in the manifest. It is
// reported rather than resolved, because there is no rule that could pick a
// winner without overriding what the operator wrote.
func CheckIPv4Conflicts(manifest Manifest) error {
	holders := make(map[netip.Addr]NostrPublicKey, len(manifest.Members))

	members := slices.Clone(manifest.Members)
	slices.SortFunc(members, func(a, b Member) int {
		return strings.Compare(a.PublicKey.String(), b.PublicKey.String())
	})

	for _, member := range members {
		prefix, err := parseAssignedIPv4(member)
		if err != nil {
			return err
		}
		if !prefix.IsValid() {
			continue
		}

		if holder, clash := holders[prefix.Addr()]; clash {
			return fmt.Errorf("%w: %s and %s are both assigned %s",
				ErrAddressConflict, holder.Short(), member.PublicKey.Short(), prefix.Addr())
		}
		holders[prefix.Addr()] = member.PublicKey
	}

	return nil
}
