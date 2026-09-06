package orchestrator

import (
	"context"
	"errors"
	"net/netip"

	"github.com/luizosorio/nostmesh/internal/connectivity"
	"github.com/luizosorio/nostmesh/internal/observability"
	"github.com/luizosorio/nostmesh/internal/wireguard"
)

// classifyDriverFailure maps a session failure to a reason code.
//
// The error itself is still logged alongside: unlike a refusal, these originate
// in this node's own work — a socket that would not bind, a kernel that refused
// a peer, a wait that ended — so the message is ours to read rather than
// something a peer composed. The code is what makes them countable.
//
// Matching is on sentinels rather than on message text, so a reworded error does
// not silently start reporting the wrong cause.
func classifyDriverFailure(err error) string {
	switch {
	case err == nil:
		return ""

	case errors.Is(err, ErrUnauthorized):
		return observability.ReasonUnauthorized
	case errors.Is(err, ErrNoRequest):
		return observability.ReasonTimeout
	case errors.Is(err, ErrSessionDropped):
		return observability.ReasonHandshakeStale
	case errors.Is(err, ErrRoamingRejected):
		return observability.ReasonRoamRejected

	case errors.Is(err, connectivity.ErrNoValidPath):
		return observability.ReasonNoPath
	case errors.Is(err, connectivity.ErrObserverUnreachable), errors.Is(err, connectivity.ErrObserverResponse):
		return observability.ReasonObserverUnreachable
	case errors.Is(err, connectivity.ErrUnverified):
		return observability.ReasonProbeUnauthenticated

	// Cancellation before timeout: a caller that went away is a different
	// outcome from a peer that never answered, and conflating them would make a
	// clean shutdown look like a connectivity problem.
	case errors.Is(err, context.Canceled):
		return observability.ReasonCancelled
	case errors.Is(err, context.DeadlineExceeded):
		return observability.ReasonTimeout
	}

	return observability.ReasonInternal
}

// changed reports whether an observation differs from the one before it.
//
// The hold loop polls for the life of a session, so this is what keeps a working
// tunnel from writing a line every few seconds forever. Counters moving, the
// handshake refreshing or the endpoint moving are the things worth a record; a
// tunnel sitting idle is not news.
func changed(previous, current wireguard.PeerState) bool {
	if previous.PublicKey != current.PublicKey {
		return true
	}
	if previous.ReceiveBytes != current.ReceiveBytes || previous.TransmitBytes != current.TransmitBytes {
		return true
	}
	if !previous.LastHandshake.Equal(current.LastHandshake) {
		return true
	}
	return !sameEndpoint(previous.Endpoint, current.Endpoint)
}

// sameEndpoint compares two optional endpoints.
func sameEndpoint(a, b *netip.AddrPort) bool {
	switch {
	case a == nil && b == nil:
		return true
	case a == nil || b == nil:
		return false
	}
	return *a == *b
}
