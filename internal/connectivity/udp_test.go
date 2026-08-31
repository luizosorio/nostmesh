package connectivity

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/pion/stun/v3"
)

func newTestTransport(t *testing.T) *UDPTransport {
	t.Helper()

	transport, err := NewUDPTransport(0)
	if err != nil {
		t.Fatalf("binding transport: %v", err)
	}
	t.Cleanup(func() { _ = transport.Close() })
	return transport
}

func localAddr(t *testing.T, transport *UDPTransport) netip.AddrPort {
	t.Helper()
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), transport.LocalPort())
}

// Binding port zero must report the port the kernel actually chose. Everything
// downstream depends on this: the candidates offered to the peer, the address
// the peer verifies, and the port WireGuard later binds are all this number. A
// transport that reported zero would have the session advertise a port nothing
// is listening on.
func TestBindingPortZeroReportsTheChosenPort(t *testing.T) {
	transport := newTestTransport(t)

	if transport.LocalPort() == 0 {
		t.Fatal("transport must report the port the kernel chose, not zero")
	}

	local, ok := transport.conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatal("socket has no UDP address")
	}
	if int(transport.LocalPort()) != local.Port {
		t.Errorf("reported port %d, socket is bound to %d", transport.LocalPort(), local.Port)
	}
}

// An explicit port must be honoured, or a session configured with a fixed port
// would verify one port and configure another.
func TestBindingAnExplicitPortHonoursIt(t *testing.T) {
	chooser := newTestTransport(t)
	port := chooser.LocalPort()
	if err := chooser.Close(); err != nil {
		t.Fatalf("releasing port: %v", err)
	}

	transport, err := NewUDPTransport(port)
	if err != nil {
		t.Skipf("port %d was taken between release and rebind: %v", port, err)
	}
	defer func() { _ = transport.Close() }()

	if transport.LocalPort() != port {
		t.Errorf("bound port %d, asked for %d", transport.LocalPort(), port)
	}
}

func TestProbeRoundTrip(t *testing.T) {
	alice := newTestTransport(t)
	bob := newTestTransport(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	payload := []byte("probe payload")
	if err := alice.Send(ctx, localAddr(t, bob), payload); err != nil {
		t.Fatalf("sending: %v", err)
	}

	received, source, err := bob.Receive(ctx)
	if err != nil {
		t.Fatalf("receiving: %v", err)
	}
	if string(received) != string(payload) {
		t.Errorf("received %q, sent %q", received, payload)
	}
	if source.Port() != alice.LocalPort() {
		t.Errorf("source port %d, sender is on %d", source.Port(), alice.LocalPort())
	}
}

// A cancelled context must return promptly rather than blocking on a datagram
// that may never arrive. A session that could not abandon a wait would hang
// instead of failing.
func TestReceiveHonoursContextCancellation(t *testing.T) {
	transport := newTestTransport(t)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	started := time.Now()
	_, _, err := transport.Receive(ctx)
	elapsed := time.Since(started)

	if err == nil {
		t.Fatal("receive must fail when the context expires")
	}
	if elapsed > 2*time.Second {
		t.Errorf("receive took %s to notice cancellation", elapsed)
	}
}

func TestSendRejectsOversizedDatagram(t *testing.T) {
	transport := newTestTransport(t)
	target := localAddr(t, transport)

	err := transport.Send(context.Background(), target, make([]byte, maxDatagram+1))
	if !errors.Is(err, ErrDatagramTooLarge) {
		t.Errorf("expected ErrDatagramTooLarge, got %v", err)
	}
}

// After the handover the transport must refuse use rather than fail obscurely.
func TestClosedTransportRefusesUse(t *testing.T) {
	transport, err := NewUDPTransport(0)
	if err != nil {
		t.Fatalf("binding: %v", err)
	}
	target := localAddr(t, transport)

	if err := transport.Close(); err != nil {
		t.Fatalf("closing: %v", err)
	}

	if err := transport.Send(context.Background(), target, []byte("x")); !errors.Is(err, ErrTransportClosed) {
		t.Errorf("send after close: expected ErrTransportClosed, got %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, _, err := transport.Receive(ctx); !errors.Is(err, ErrTransportClosed) {
		t.Errorf("receive after close: expected ErrTransportClosed, got %v", err)
	}

	// Closing twice must be safe: the handover path may unwind more than once.
	if err := transport.Close(); err != nil {
		t.Errorf("second close must be a no-op, got %v", err)
	}
}

// The socket carries both probes and STUN responses. Sorting them apart is what
// lets one port serve both, and a probe misrouted to the observer would be a
// verification that silently never completes.
func TestSTUNAndProbeShareTheSocket(t *testing.T) {
	transport := newTestTransport(t)
	sender := newTestTransport(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	target := localAddr(t, transport)

	// A STUN-shaped datagram must reach the observer channel, not the prober.
	stunMessage := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	if err := sender.Send(ctx, target, stunMessage.Raw); err != nil {
		t.Fatalf("sending stun: %v", err)
	}

	// A probe-shaped datagram must reach the prober.
	probe := make([]byte, ProbeSize)
	probe[0] = 1
	if err := sender.Send(ctx, target, probe); err != nil {
		t.Fatalf("sending probe: %v", err)
	}

	received, _, err := transport.Receive(ctx)
	if err != nil {
		t.Fatalf("receiving probe: %v", err)
	}
	if len(received) != ProbeSize {
		t.Errorf("prober received %d bytes, expected the %d-byte probe", len(received), ProbeSize)
	}

	select {
	case datagram := <-transport.stun:
		if !isSTUNMessage(datagram.payload) {
			t.Error("observer received a datagram that is not STUN")
		}
	case <-time.After(2 * time.Second):
		t.Error("the STUN datagram never reached the observer")
	}
}

func TestSTUNDetection(t *testing.T) {
	stunMessage := stun.MustBuild(stun.TransactionID, stun.BindingRequest)

	cases := map[string]struct {
		payload []byte
		want    bool
	}{
		"real stun message": {stunMessage.Raw, true},
		"probe sized":       {make([]byte, ProbeSize), false},
		"empty":             {nil, false},
		"too short":         {[]byte{0x00, 0x01, 0x00, 0x00}, false},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := isSTUNMessage(tc.payload); got != tc.want {
				t.Errorf("isSTUNMessage = %v, want %v", got, tc.want)
			}
		})
	}
}

// The shared observer exists to hold one port for the whole session. Asking it
// to observe a different port is a wiring mistake that would produce a
// candidate describing a mapping nothing uses, so it must be refused loudly
// rather than answered with the wrong port's address.
func TestSharedObserverRefusesAForeignPort(t *testing.T) {
	transport := newTestTransport(t)

	observer, err := NewSharedObserver(transport, time.Second)
	if err != nil {
		t.Fatalf("building observer: %v", err)
	}

	foreign := int(transport.LocalPort()) + 1
	if _, err := observer.Observe(context.Background(), "stun.example:3478", foreign); err == nil {
		t.Error("observing a port the transport does not hold must fail")
	}
}

// A STUN server that never answers must time out rather than hang.
func TestSharedObserverTimesOut(t *testing.T) {
	transport := newTestTransport(t)
	silent := newTestTransport(t)

	observer, err := NewSharedObserver(transport, 300*time.Millisecond)
	if err != nil {
		t.Fatalf("building observer: %v", err)
	}

	server := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(silent.LocalPort())))

	started := time.Now()
	_, err = observer.Observe(context.Background(), server, int(transport.LocalPort()))
	elapsed := time.Since(started)

	if !errors.Is(err, ErrObserverUnreachable) {
		t.Errorf("expected ErrObserverUnreachable, got %v", err)
	}
	if elapsed > 3*time.Second {
		t.Errorf("observation took %s to time out", elapsed)
	}
}

// The observer must reject an answer whose transaction id does not match, since
// otherwise anything able to reach this socket could inject an address into the
// candidate set.
func TestSharedObserverRejectsForeignTransaction(t *testing.T) {
	request := stun.MustBuild(stun.TransactionID, stun.BindingRequest)

	// An answer to a different transaction, carrying a plausible address.
	other := stun.MustBuild(stun.TransactionID, stun.BindingSuccess,
		&stun.XORMappedAddress{IP: net.ParseIP("203.0.113.5"), Port: 4242})

	if _, err := parseSTUNResponse(other.Raw, request.TransactionID, "stun.example"); !errors.Is(err, ErrObserverResponse) {
		t.Errorf("expected ErrObserverResponse for a foreign transaction, got %v", err)
	}
}

// An observer reporting an unusable address is broken or hostile. Accepting it
// would put a loopback or multicast address into the candidate set, which the
// checker would then try to probe.
func TestSharedObserverRejectsUnusableAddress(t *testing.T) {
	request := stun.MustBuild(stun.TransactionID, stun.BindingSuccess,
		&stun.XORMappedAddress{IP: net.ParseIP("127.0.0.1"), Port: 4242})

	if _, err := parseSTUNResponse(request.Raw, request.TransactionID, "stun.example"); !errors.Is(err, ErrObserverResponse) {
		t.Errorf("a loopback observation must be refused, got %v", err)
	}
}
