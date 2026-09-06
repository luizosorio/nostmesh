package domain

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

// Overlay addressing, per NM-21.
//
// An address is derived rather than assigned, so that a network needs no central
// allocator: every member computes the same address for every other member from
// inputs they all hold. The derivation is a pure function of the network's salt,
// the member's public key and a counter — no clock, no randomness, nothing that
// could make two nodes disagree.

// NetworkSaltSize is the length of a network's salt.
//
// Thirty-two bytes because the salt is the whole privacy boundary: it is what
// stops somebody holding the manifest's public parts from mapping addresses back
// to identities. A short salt would be searchable.
const NetworkSaltSize = 32

// NetworkIDSize is the length of a network identifier.
const NetworkIDSize = 32

// Sizes of the parts of a ULA address, in bits, per RFC 4193.
const (
	// ulaPrefixBits is the fd00::/8 prefix that marks a locally assigned ULA.
	ulaPrefixBits = 8

	// globalIDBits is the 40-bit Global ID identifying the network.
	globalIDBits = 40

	// subnetIDBits is the 16-bit Subnet ID the manifest may carve.
	subnetIDBits = 16

	// interfaceIDBits is the 64-bit host part, which is what is derived.
	interfaceIDBits = 64

	// NetworkPrefixBits is the length of a network's prefix: the ULA marker plus
	// the Global ID.
	NetworkPrefixBits = ulaPrefixBits + globalIDBits

	// SubnetPrefixBits is the length of a subnet's prefix.
	SubnetPrefixBits = NetworkPrefixBits + subnetIDBits
)

// ulaMarker is the first byte of a locally assigned ULA: fc00::/7 with the L bit
// set, which is fd00::/8. RFC 4193 leaves fc00::/8 undefined, so fd is the only
// half anyone may use.
const ulaMarker = 0xfd

// maxDerivationCounter bounds how far renumbering will search.
//
// The counter exists for collisions, and in a 64-bit space a collision is a
// correctness formality rather than an expectation — the first is expected after
// roughly 5.4 billion members. A bound this size will never be reached by
// chance; it is here so that a caller which somehow keeps colliding fails
// loudly instead of looping.
const maxDerivationCounter = 1024

var (
	// ErrSaltSize reports a salt of the wrong length.
	ErrSaltSize = errors.New("network salt has the wrong length")

	// ErrNetworkIDSize reports a network id of the wrong length.
	ErrNetworkIDSize = errors.New("network id has the wrong length")

	// ErrCounterExhausted reports a derivation that could not find a free
	// address within the bound.
	ErrCounterExhausted = errors.New("address derivation exhausted its counter")

	// ErrNotAnOverlayPrefix reports a prefix that is not a ULA network prefix.
	ErrNotAnOverlayPrefix = errors.New("prefix is not a ULA overlay network")
)

// NetworkSalt is a network's secret, shared by its members.
//
// It never appears in the manifest event and never leaves the members: an
// observer holding every published event still cannot derive a single address
// without it. That is the property that keeps the overlay's addresses from being
// a public map of who is on the network.
type NetworkSalt [NetworkSaltSize]byte

// NetworkID names a network.
//
// Unlike the salt this is not secret. It is what makes two networks derive
// unrelated addresses for the same identity, and it is public because a member
// has to be able to say which network they mean.
type NetworkID [NetworkIDSize]byte

// NetworkPrefix returns the /48 a network occupies.
//
// The Global ID comes from the network id rather than from the salt, because the
// prefix is public: it is on every packet, and deriving it from the secret would
// leak forty bits of that secret to anyone watching.
func (n NetworkID) NetworkPrefix() netip.Prefix {
	digest := sha256.Sum256(append([]byte("nostmesh/overlay/global-id/v1"), n[:]...))

	var address [16]byte
	address[0] = ulaMarker
	copy(address[1:6], digest[:5]) // 40 bits of Global ID

	return netip.PrefixFrom(netip.AddrFrom16(address), NetworkPrefixBits)
}

// Subnet returns one subnet of a network.
//
// The manifest carves these; nothing is derived here. A network that uses a
// single subnet passes zero and gets the first.
func (n NetworkID) Subnet(id uint16) netip.Prefix {
	address := n.NetworkPrefix().Addr().As16()
	binary.BigEndian.PutUint16(address[6:8], id)

	return netip.PrefixFrom(netip.AddrFrom16(address), SubnetPrefixBits)
}

// DeriveOverlayAddress computes a member's address within a subnet.
//
// The counter is what makes renumbering deterministic: on a collision every
// member increments it and re-derives, arriving at the same next address without
// exchanging a message. Passing zero gives the address a member holds unless
// something collided.
//
// Only the public key enters the derivation. An address is therefore reproducible
// by anyone who should be able to reproduce it, and reveals nothing the public
// key did not already reveal.
func DeriveOverlayAddress(salt NetworkSalt, subnet netip.Prefix, key NostrPublicKey, counter uint32) (netip.Addr, error) {
	if subnet.Bits() != SubnetPrefixBits {
		return netip.Addr{}, fmt.Errorf("%w: want a /%d, got /%d",
			ErrNotAnOverlayPrefix, SubnetPrefixBits, subnet.Bits())
	}
	if !subnet.Addr().Is6() {
		return netip.Addr{}, fmt.Errorf("%w: overlay addresses are IPv6", ErrNotAnOverlayPrefix)
	}

	// The counter is part of the derivation input rather than added to the
	// result. Incrementing an address would walk into a neighbour's; deriving
	// again lands somewhere unrelated, which is what makes a second collision as
	// unlikely as the first.
	info := make([]byte, 0, len("nostmesh/overlay/interface-id/v1")+NostrKeySize+4)
	info = append(info, "nostmesh/overlay/interface-id/v1"...)
	info = append(info, key[:]...)
	info = binary.BigEndian.AppendUint32(info, counter)

	// HKDF with the salt as the salt and the network's own label as the secret:
	// the key is public, so it is the salt that has to carry the entropy.
	interfaceID, err := hkdf.Key(sha256.New, salt[:], nil, string(info), interfaceIDBits/8)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("deriving interface id: %w", err)
	}

	address := subnet.Addr().As16()
	copy(address[8:], interfaceID)

	derived := netip.AddrFrom16(address)

	// The all-zero interface id is the subnet-router anycast address, which
	// RFC 4291 reserves. Rather than special-casing it at every caller, the
	// derivation skips it by advancing the counter — which is the same mechanism
	// a collision uses, so it needs no separate path.
	if derived == subnet.Addr() {
		if counter >= maxDerivationCounter {
			return netip.Addr{}, ErrCounterExhausted
		}
		return DeriveOverlayAddress(salt, subnet, key, counter+1)
	}

	return derived, nil
}

// NewNetworkSalt builds a salt from raw bytes.
func NewNetworkSalt(raw []byte) (NetworkSalt, error) {
	var salt NetworkSalt
	if len(raw) != NetworkSaltSize {
		return salt, fmt.Errorf("%w: want %d bytes, got %d", ErrSaltSize, NetworkSaltSize, len(raw))
	}
	copy(salt[:], raw)
	return salt, nil
}

// NewNetworkID builds a network id from raw bytes.
func NewNetworkID(raw []byte) (NetworkID, error) {
	var id NetworkID
	if len(raw) != NetworkIDSize {
		return id, fmt.Errorf("%w: want %d bytes, got %d", ErrNetworkIDSize, NetworkIDSize, len(raw))
	}
	copy(id[:], raw)
	return id, nil
}
