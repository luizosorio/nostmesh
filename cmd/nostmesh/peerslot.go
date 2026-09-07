package main

import (
	"encoding/binary"
	"fmt"

	"github.com/luizosorio/nostmesh/internal/domain"
	"github.com/luizosorio/nostmesh/internal/wireguard"
)

// A peer's slot: the interface it gets and the port it binds.
//
// Both are derived from the peer's identity rather than allocated, for the same
// reason addresses are (NM-21): a value computed from stable inputs survives a
// restart unchanged, where an allocated one has to be remembered and can be
// lost. NM-15 cares about this specifically — a peer verified a NAT mapping for
// one port, and coming back on a different one describes a mapping nothing
// verified.
//
// One interface and one port per peer rather than one shared pair, per the
// reading of NM-15 that its invariant is per session: observation, probing and
// the data plane of *one* session must share a port, because a NAT maps per
// source port. Two sessions sharing one is not something it asks for, and the
// probe key is already derived per session.

// slotPortSpan is how many ports a node may allocate to peers.
//
// Bounded so that a node cannot quietly claim an unlimited range of the host's
// port space. It comfortably exceeds the concurrent sessions the policy allows.
const slotPortSpan = 256

// interfaceNameLimit is what Linux allows for an interface name.
//
// Fifteen bytes plus a terminator. A name over it is refused by the kernel at
// creation time, which would surface as an unexplained failure well after the
// point where the name was chosen.
const interfaceNameLimit = 15

// slotKeyDigits is how much of the peer's identity names its slot.
//
// Eight hex characters, matching the abbreviation used in logs so an operator
// reading `nm-a1b2c3d4` can find the same peer in a log line. Collision within a
// node's own peer list is checked rather than assumed: 32 bits is plenty against
// accident and nothing against a peer that chose its key to collide.
const slotKeyDigits = 8

// peerSlot is one peer's interface and port.
type peerSlot struct {
	Interface string
	Port      int
}

// slotFor computes a peer's slot.
//
// The base port is the operator's `listen_port`. Zero keeps its existing
// meaning — let the kernel choose — which is what a client that dials out wants
// and which the transport already reads back.
func slotFor(peer domain.NostrPublicKey, basePort int) (peerSlot, error) {
	name := wireguard.InterfacePrefix + "-" + peer.String()[:slotKeyDigits]
	if len(name) > interfaceNameLimit {
		return peerSlot{}, fmt.Errorf("interface name %q exceeds the %d-byte limit", name, interfaceNameLimit)
	}

	if basePort == 0 {
		// The kernel picks, and the transport reads the choice back. Every peer
		// gets its own socket either way, so nothing collides.
		return peerSlot{Interface: name, Port: 0}, nil
	}

	// Derived from the identity rather than counted, so that adding or removing
	// a peer does not shift everyone else's port — which would invalidate every
	// NAT mapping the other peers had verified.
	offset := binary.BigEndian.Uint32(peer[:4]) % slotPortSpan
	port := basePort + int(offset)

	if port > 65535 {
		return peerSlot{}, fmt.Errorf(
			"listen_port %d leaves no room for a %d-port span; use a base below %d",
			basePort, slotPortSpan, 65536-slotPortSpan)
	}

	return peerSlot{Interface: name, Port: port}, nil
}

// assignSlots computes slots for a set of peers, refusing any collision.
//
// Two peers on one port or one interface would fail at bind or clobber each
// other's kernel state, and either failure appears far from its cause. Refusing
// here names both peers while the reason is still visible.
func assignSlots(peers []domain.NostrPublicKey, basePort int) (map[domain.NostrPublicKey]peerSlot, error) {
	slots := make(map[domain.NostrPublicKey]peerSlot, len(peers))
	byName := make(map[string]domain.NostrPublicKey, len(peers))
	byPort := make(map[int]domain.NostrPublicKey, len(peers))

	for _, peer := range peers {
		slot, err := slotFor(peer, basePort)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", peer.Short(), err)
		}

		if holder, clash := byName[slot.Interface]; clash {
			return nil, fmt.Errorf("%s and %s both derive interface %s",
				holder.Short(), peer.Short(), slot.Interface)
		}
		// Port zero means the kernel chooses one per socket, so it cannot clash.
		if holder, clash := byPort[slot.Port]; clash && slot.Port != 0 {
			return nil, fmt.Errorf("%s and %s both derive port %d",
				holder.Short(), peer.Short(), slot.Port)
		}

		byName[slot.Interface] = peer
		byPort[slot.Port] = peer
		slots[peer] = slot
	}

	return slots, nil
}
