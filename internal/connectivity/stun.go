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

// STUNObserver queries STUN servers for this node's observed address.
//
// What it returns is what a stranger says it saw. That is useful — a node
// behind NAT has no other way to learn its mapped address — and it is not
// evidence: the result becomes an UNVERIFIED candidate like any other.
type STUNObserver struct {
	timeout time.Duration

	// maxResponseSize bounds what is read from a socket. A server that floods
	// must not be able to spend this node's memory.
	maxResponseSize int
}

// STUNObserverOptions configures a STUNObserver.
type STUNObserverOptions struct {
	// Timeout bounds one query.
	Timeout time.Duration
}

const (
	defaultSTUNTimeout = 3 * time.Second

	// A STUN response is small. Anything larger is not one.
	maxSTUNResponse = 1500
)

// NewSTUNObserver builds an observer.
func NewSTUNObserver(opts STUNObserverOptions) *STUNObserver {
	if opts.Timeout <= 0 {
		opts.Timeout = defaultSTUNTimeout
	}
	return &STUNObserver{
		timeout:         opts.Timeout,
		maxResponseSize: maxSTUNResponse,
	}
}

// Observe asks one server what address it sees.
//
// The query goes out from the same local port WireGuard will use. That matters:
// a NAT maps per source port, so an address observed from a different port
// tells this node nothing about the port it actually needs.
func (o *STUNObserver) Observe(ctx context.Context, server string, localPort int) (netip.AddrPort, error) {
	if server == "" {
		return netip.AddrPort{}, errors.New("observer address is empty")
	}

	conn, err := o.dial(ctx, server, localPort)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("%w: %s: %w", ErrObserverUnreachable, server, err)
	}
	defer func() { _ = conn.Close() }()

	deadline := time.Now().Add(o.timeout)
	if fromContext, ok := ctx.Deadline(); ok && fromContext.Before(deadline) {
		deadline = fromContext
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return netip.AddrPort{}, fmt.Errorf("setting deadline: %w", err)
	}

	request := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	if _, err := conn.Write(request.Raw); err != nil {
		return netip.AddrPort{}, fmt.Errorf("%w: %s: %w", ErrObserverUnreachable, server, err)
	}

	return o.readResponse(conn, request, server)
}

// dial opens a UDP socket bound to the local port WireGuard uses.
func (o *STUNObserver) dial(ctx context.Context, server string, localPort int) (*net.UDPConn, error) {
	remote, err := net.ResolveUDPAddr("udp", server)
	if err != nil {
		return nil, fmt.Errorf("resolving %s: %w", server, err)
	}

	var local *net.UDPAddr
	if localPort > 0 {
		local = &net.UDPAddr{Port: localPort}
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	conn, err := net.DialUDP("udp", local, remote)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// readResponse reads and validates the server's answer.
func (o *STUNObserver) readResponse(conn *net.UDPConn, request *stun.Message, server string) (netip.AddrPort, error) {
	buf := make([]byte, o.maxResponseSize)

	read, err := conn.Read(buf)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("%w: %s: %w", ErrObserverUnreachable, server, err)
	}

	return parseSTUNResponse(buf[:read], request.TransactionID, server)
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
