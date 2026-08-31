package connectivity

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"
)

var (
	// ErrTransportClosed reports use of a transport that has been handed over.
	ErrTransportClosed = errors.New("transport is closed")

	// ErrDatagramTooLarge reports an outgoing payload that will not fit.
	ErrDatagramTooLarge = errors.New("datagram is too large")
)

const (
	// maxDatagram bounds what is read from the socket. Probes are 57 bytes and
	// STUN responses a few hundred; anything approaching this is neither, and
	// the bound keeps a flood from spending this node's memory.
	maxDatagram = 1500

	// receivePollInterval bounds how long a blocked read waits before checking
	// whether its context was cancelled.
	receivePollInterval = 200 * time.Millisecond
)

// UDPTransport is the real probe transport, and the owner of the local port.
//
// Its central job is not sending bytes — it is holding one specific UDP port so
// that everything a peer learns about this node refers to the same port. A NAT
// maps per source port, so an address observed from one port says nothing about
// another. Gathering, STUN observation and connectivity checks therefore all
// run through this socket, and WireGuard afterwards binds the same port number.
//
// The socket is unconnected: one socket serves every candidate address, which
// is required because a connected socket would discard datagrams from all but
// one peer, and a peer's usable address is not known in advance.
type UDPTransport struct {
	conn *net.UDPConn
	port uint16

	mu     sync.Mutex
	closed bool

	// stun receives datagrams that are STUN responses rather than probes, so a
	// shared observer can read them without racing the probe reader for the
	// socket.
	stun chan stunDatagram
}

// stunDatagram is a STUN response handed to the observer.
type stunDatagram struct {
	payload []byte
	source  netip.AddrPort
}

// NewUDPTransport binds a UDP socket for the session.
//
// A port of zero lets the kernel choose, and the chosen number is then read
// back. Reading it back is what makes the handover work: the port must be known
// before WireGuard is configured, and asking the kernel to choose twice would
// produce two different ports and an endpoint the peer verified against
// neither.
func NewUDPTransport(port uint16) (*UDPTransport, error) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: int(port)})
	if err != nil {
		return nil, fmt.Errorf("binding udp port %d: %w", port, err)
	}

	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		_ = conn.Close()
		return nil, errors.New("bound socket has no usable local address")
	}

	//nolint:gosec // a bound UDP port is a uint16
	bound := uint16(local.Port)
	if bound == 0 {
		_ = conn.Close()
		return nil, errors.New("kernel reported port 0 for a bound socket")
	}

	return &UDPTransport{
		conn: conn,
		port: bound,
		stun: make(chan stunDatagram, 4),
	}, nil
}

// LocalPort returns the port this transport holds.
//
// This is the authoritative port for the whole session: candidates are gathered
// for it, the peer verifies it, and WireGuard is configured with it.
func (t *UDPTransport) LocalPort() uint16 { return t.port }

// Send transmits a probe.
func (t *UDPTransport) Send(ctx context.Context, target netip.AddrPort, payload []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(payload) > maxDatagram {
		return fmt.Errorf("%w: %d bytes, limit %d", ErrDatagramTooLarge, len(payload), maxDatagram)
	}

	t.mu.Lock()
	closed := t.closed
	t.mu.Unlock()
	if closed {
		return ErrTransportClosed
	}

	if _, err := t.conn.WriteToUDPAddrPort(payload, target); err != nil {
		return fmt.Errorf("sending to %s: %w", target, err)
	}
	return nil
}

// Receive returns the next probe to arrive.
//
// STUN responses arriving on the same socket are diverted to the observer
// rather than returned here. Sharing the socket is what keeps the observed
// address and the probed address referring to the same NAT mapping; the cost is
// that this reader must sort the two apart.
func (t *UDPTransport) Receive(ctx context.Context) ([]byte, netip.AddrPort, error) {
	buf := make([]byte, maxDatagram)

	for {
		if err := ctx.Err(); err != nil {
			return nil, netip.AddrPort{}, err
		}

		t.mu.Lock()
		closed := t.closed
		t.mu.Unlock()
		if closed {
			return nil, netip.AddrPort{}, ErrTransportClosed
		}

		// A short deadline rather than a blocking read: the socket must notice
		// a cancelled context without waiting for a datagram that may never
		// arrive.
		deadline := time.Now().Add(receivePollInterval)
		if fromContext, ok := ctx.Deadline(); ok && fromContext.Before(deadline) {
			deadline = fromContext
		}
		if err := t.conn.SetReadDeadline(deadline); err != nil {
			return nil, netip.AddrPort{}, fmt.Errorf("setting read deadline: %w", err)
		}

		read, source, err := t.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil, netip.AddrPort{}, ErrTransportClosed
			}
			var timeout net.Error
			if errors.As(err, &timeout) && timeout.Timeout() {
				continue
			}
			return nil, netip.AddrPort{}, fmt.Errorf("receiving: %w", err)
		}

		payload := make([]byte, read)
		copy(payload, buf[:read])

		// A v4-mapped v6 address is unmapped so the source compares equal to the
		// candidate address that was probed: the probe tag authenticates the
		// address, and two spellings of one address would not match.
		normalized := netip.AddrPortFrom(source.Addr().Unmap(), source.Port())

		if isSTUNMessage(payload) {
			t.dispatchSTUN(payload, normalized)
			continue
		}

		return payload, normalized, nil
	}
}

// dispatchSTUN hands a STUN response to a waiting observer.
//
// A response nobody is waiting for is dropped rather than queued: it is either
// late or unsolicited, and holding it would only let it answer a later query it
// does not belong to.
func (t *UDPTransport) dispatchSTUN(payload []byte, source netip.AddrPort) {
	select {
	case t.stun <- stunDatagram{payload: payload, source: source}:
	default:
	}
}

// Close releases the port.
//
// This is the handover: WireGuard cannot share this socket, because wgctrl has
// no way to accept a file descriptor. The port is therefore freed here and
// rebound by the kernel module. The NAT mapping survives the gap, since a
// mapping expires on inactivity rather than when a local socket closes.
func (t *UDPTransport) Close() error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil
	}
	t.closed = true
	t.mu.Unlock()

	if err := t.conn.Close(); err != nil {
		return fmt.Errorf("closing transport: %w", err)
	}
	return nil
}

// isSTUNMessage reports whether a datagram is STUN.
//
// STUN puts a fixed magic cookie at a fixed offset precisely so it can be
// demultiplexed from other traffic on a shared socket. Probes are distinguished
// by exclusion, and are additionally authenticated, so a datagram that fakes
// the cookie can at worst be discarded as an unmatched STUN response.
func isSTUNMessage(payload []byte) bool {
	// RFC 5389: the cookie is the four bytes at offset 4, fixed at 0x2112A442.
	const (
		cookieOffset = 4
		cookieSize   = 4
	)

	if len(payload) < cookieOffset+cookieSize {
		return false
	}
	return payload[cookieOffset] == 0x21 &&
		payload[cookieOffset+1] == 0x12 &&
		payload[cookieOffset+2] == 0xA4 &&
		payload[cookieOffset+3] == 0x42
}
