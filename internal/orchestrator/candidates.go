package orchestrator

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/luizosorio/nostmesh/internal/connectivity"
	"github.com/luizosorio/nostmesh/internal/protocol"
)

// Candidate conversion lives here rather than in either package it bridges.
//
// protocol must stay transport-neutral — it describes messages over bytes and
// knows nothing of probing — and connectivity must stay unaware of the wire
// format, or the checking logic would be coupled to how candidates travel. The
// orchestrator is what already knows both.

// candidateKinds maps wire types to the checker's kinds.
//
// A wire type with no mapping is refused rather than defaulted. Guessing would
// let an unknown type inherit the priority and treatment of a known one, and a
// relay candidate silently treated as a host candidate is a routing decision
// made by accident.
var candidateKinds = map[protocol.CandidateType]connectivity.Kind{
	protocol.CandidateHost:            connectivity.KindHost,
	protocol.CandidateServerReflexive: connectivity.KindServerReflexive,
	protocol.CandidateStatic:          connectivity.KindStatic,
}

// wireKinds is the reverse mapping, for candidates this node publishes.
var wireKinds = map[connectivity.Kind]protocol.CandidateType{
	connectivity.KindHost:            protocol.CandidateHost,
	connectivity.KindServerReflexive: protocol.CandidateServerReflexive,
	connectivity.KindPeerReflexive:   protocol.CandidateServerReflexive,
	connectivity.KindStatic:          protocol.CandidateStatic,
	connectivity.KindPortMapped:      protocol.CandidateServerReflexive,
}

// toConnectivity converts a candidate received from a peer.
//
// Everything here arrives from the network and is therefore untrusted. The
// address is parsed rather than assumed well-formed, the kind must be one this
// node understands, and the result enters the engine as UNVERIFIED — a peer
// cannot assert that its own candidate works.
func toConnectivity(wire protocol.Candidate, source string) (connectivity.Candidate, error) {
	kind, known := candidateKinds[wire.Type]
	if !known {
		return connectivity.Candidate{}, fmt.Errorf("unsupported candidate type %q", wire.Type)
	}

	// Only UDP exists today. Accepting an unknown transport would mean probing
	// an address with a protocol the checker does not speak.
	if wire.Transport != "" && wire.Transport != "udp" {
		return connectivity.Candidate{}, fmt.Errorf("unsupported transport %q", wire.Transport)
	}

	address, err := netip.ParseAddrPort(wire.Address)
	if err != nil {
		return connectivity.Candidate{}, fmt.Errorf("unparseable candidate address %q: %w", wire.Address, err)
	}

	candidate := connectivity.Candidate{
		ID:       wire.ID,
		Kind:     kind,
		Address:  address,
		Priority: wire.Priority,
		Source:   source,
	}

	if wire.RelatedAddress != "" {
		related, err := netip.ParseAddrPort(wire.RelatedAddress)
		if err != nil {
			return connectivity.Candidate{}, fmt.Errorf("unparseable related address %q: %w", wire.RelatedAddress, err)
		}
		candidate.Related = related
	}

	return candidate, nil
}

// toWire converts a locally gathered candidate for publication.
func toWire(candidate connectivity.Candidate, expiresAt time.Time) (protocol.Candidate, error) {
	kind, known := wireKinds[candidate.Kind]
	if !known {
		return protocol.Candidate{}, fmt.Errorf("candidate kind %q has no wire representation", candidate.Kind)
	}

	wire := protocol.Candidate{
		ID:        candidate.ID,
		Type:      kind,
		Transport: "udp",
		Address:   candidate.Address.String(),
		Priority:  candidate.Priority,
		ExpiresAt: expiresAt.Unix(),
	}

	if candidate.Related.IsValid() {
		wire.RelatedAddress = candidate.Related.String()
	}
	return wire, nil
}

// toWireAll converts every candidate that has a wire representation.
//
// A candidate that cannot be represented is skipped rather than failing the
// batch: it is one path among several, and losing it costs a possible route
// while failing the publication would cost every route.
func toWireAll(candidates []connectivity.Candidate, expiresAt time.Time) []protocol.Candidate {
	wire := make([]protocol.Candidate, 0, len(candidates))
	for _, candidate := range candidates {
		converted, err := toWire(candidate, expiresAt)
		if err != nil {
			continue
		}
		wire = append(wire, converted)
	}
	return wire
}
