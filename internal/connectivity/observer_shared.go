package connectivity

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/pion/stun/v3"
)

var (
	// ErrObserverUnreachable reports a STUN server that did not answer.
	ErrObserverUnreachable = errors.New("observer did not answer")

	// ErrObserverResponse reports an answer that could not be used.
	ErrObserverResponse = errors.New("observer returned an unusable response")
)

// defaultSTUNTimeout bounds one query.
const defaultSTUNTimeout = 3 * time.Second

// SharedObserver queries STUN servers over the session's own socket.
//
// STUNObserver opens its own socket for each query, which leaves a gap: between
// closing it and binding the session port, another process can take the port,
// and the address just observed then describes a mapping this node no longer
// holds. Borrowing the transport's socket removes the gap entirely — the port
// is held continuously from gathering through verification to handover.
//
// It reads responses from the transport's demultiplexer rather than from the
// socket directly, because the probe reader is already reading that socket and
// two readers would race for each datagram.
type SharedObserver struct {
	transport *UDPTransport
	timeout   time.Duration
}

// NewSharedObserver builds an observer over an existing transport.
func NewSharedObserver(transport *UDPTransport, timeout time.Duration) (*SharedObserver, error) {
	if transport == nil {
		return nil, errors.New("shared observer requires a transport")
	}
	if timeout <= 0 {
		timeout = defaultSTUNTimeout
	}
	return &SharedObserver{transport: transport, timeout: timeout}, nil
}

// Observe asks one server what address it sees.
//
// The localPort argument is accepted for the Observer interface and must match
// the port the transport already holds: this observer cannot query from any
// other port, and silently observing the wrong one would produce a candidate
// describing a NAT mapping that nothing will use.
func (o *SharedObserver) Observe(ctx context.Context, server string, localPort int) (netip.AddrPort, error) {
	if server == "" {
		return netip.AddrPort{}, errors.New("observer address is empty")
	}
	if localPort > 0 && uint16(localPort) != o.transport.LocalPort() { //nolint:gosec // compared, not converted for use
		return netip.AddrPort{}, fmt.Errorf(
			"shared observer holds port %d and cannot observe port %d",
			o.transport.LocalPort(), localPort)
	}

	remote, err := net.ResolveUDPAddr("udp", server)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("%w: resolving %s: %w", ErrObserverUnreachable, server, err)
	}

	target, ok := netip.AddrFromSlice(remote.IP)
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("%w: %s: unparseable server address", ErrObserverUnreachable, server)
	}
	//nolint:gosec // a resolved UDP port is a uint16
	targetAddr := netip.AddrPortFrom(target.Unmap(), uint16(remote.Port))

	// Drain answers left over from an earlier query. A late response carries a
	// different transaction id and would be refused, but discarding it here
	// keeps it from consuming this query's timeout budget.
	o.drain()

	request := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	if err := o.transport.Send(ctx, targetAddr, request.Raw); err != nil {
		return netip.AddrPort{}, fmt.Errorf("%w: %s: %w", ErrObserverUnreachable, server, err)
	}

	return o.awaitResponse(ctx, request, server)
}

// awaitResponse waits for the answer to one query.
func (o *SharedObserver) awaitResponse(ctx context.Context, request *stun.Message, server string) (netip.AddrPort, error) {
	// A duration, never an absolute instant from an injected clock: a context
	// deadline is compared against the system clock, so a test clock set in the
	// future would produce an already-expired context and a query that never
	// waits.
	waitCtx, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()

	for {
		select {
		case <-waitCtx.Done():
			return netip.AddrPort{}, fmt.Errorf("%w: %s: %w", ErrObserverUnreachable, server, waitCtx.Err())

		default:
		}

		payload, _, err := o.transport.ReceiveSTUN(waitCtx)
		if err != nil {
			return netip.AddrPort{}, fmt.Errorf("%w: %s: %w", ErrObserverUnreachable, server, err)
		}

		observed, parseErr := parseSTUNResponse(payload, request.TransactionID, server)
		if parseErr != nil {
			// A response that does not match this query is discarded and the
			// wait continues: refusing outright would let anything that can
			// reach this socket cancel a legitimate observation.
			continue
		}
		return observed, nil
	}
}

// drain discards STUN responses queued from an earlier query.
func (o *SharedObserver) drain() {
	for {
		select {
		case <-o.transport.stun:
		default:
			return
		}
	}
}

// parseSTUNResponse validates a STUN answer and extracts the observed address.
//
// It is shared by every observer, whether it owns its socket or borrows one:
// the checks here are what make a stranger's answer safe to use at all, and an
// observer that skipped them would let a hostile server inject an address into
// this node's candidate set.
func parseSTUNResponse(raw []byte, transaction [stun.TransactionIDSize]byte, server string) (netip.AddrPort, error) {
	var response stun.Message
	response.Raw = raw
	if err := response.Decode(); err != nil {
		return netip.AddrPort{}, fmt.Errorf("%w: %s: %w", ErrObserverResponse, server, err)
	}

	// The transaction id ties the answer to this request. Without checking it,
	// anything that can reach this socket could inject an address.
	if response.TransactionID != transaction {
		return netip.AddrPort{}, fmt.Errorf("%w: %s: transaction id does not match", ErrObserverResponse, server)
	}

	var mapped stun.XORMappedAddress
	if err := mapped.GetFrom(&response); err != nil {
		return netip.AddrPort{}, fmt.Errorf("%w: %s: %w", ErrObserverResponse, server, err)
	}

	addr, ok := netip.AddrFromSlice(mapped.IP)
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("%w: %s: unparseable address", ErrObserverResponse, server)
	}

	//nolint:gosec // a STUN port is a uint16 on the wire
	observed := netip.AddrPortFrom(addr.Unmap(), uint16(mapped.Port))

	// An observer reporting an unusable address is broken or hostile; either
	// way the answer is refused here rather than becoming a candidate.
	if err := ValidateAddress(observed); err != nil {
		return netip.AddrPort{}, fmt.Errorf("%w: %s: %w", ErrObserverResponse, server, err)
	}

	return observed, nil
}
