package orchestrator

import (
	"context"
	"crypto/rand"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luizosorio/nostmesh/internal/connectivity"
	"github.com/luizosorio/nostmesh/internal/domain"
	"github.com/luizosorio/nostmesh/internal/identity"
	"github.com/luizosorio/nostmesh/internal/netstate"
	"github.com/luizosorio/nostmesh/internal/policy"
	"github.com/luizosorio/nostmesh/internal/protocol"
	"github.com/luizosorio/nostmesh/internal/wireguard"
)

// stubTransport stands in for the UDP transport, recording whether the port was
// released before the interface was configured.
type stubTransport struct {
	mu     sync.Mutex
	port   uint16
	closed bool

	// received is handed to the checker; an empty channel means no probe ever
	// answers, which is how an unreachable peer behaves.
	received chan []byte
}

func newStubTransport(port uint16) *stubTransport {
	return &stubTransport{port: port, received: make(chan []byte)}
}

func (s *stubTransport) Send(ctx context.Context, _ netip.AddrPort, _ []byte) error {
	return ctx.Err()
}

func (s *stubTransport) Receive(ctx context.Context) ([]byte, netip.AddrPort, error) {
	select {
	case <-ctx.Done():
		return nil, netip.AddrPort{}, ctx.Err()
	case payload := <-s.received:
		return payload, netip.AddrPort{}, nil
	}
}

func (s *stubTransport) LocalPort() uint16 { return s.port }

func (s *stubTransport) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

func (s *stubTransport) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// stubPublisher records what the driver sent.
type stubPublisher struct {
	mu   sync.Mutex
	sent []protocol.MessageType
}

func (p *stubPublisher) Publish(_ context.Context, kind protocol.MessageType, _ uint64, _ protocol.Payload) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sent = append(p.sent, kind)
	return nil
}

func (p *stubPublisher) types() []protocol.MessageType {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]protocol.MessageType, len(p.sent))
	copy(out, p.sent)
	return out
}

// stubReceiver replays a scripted sequence of peer messages.
type stubReceiver struct {
	mu       sync.Mutex
	messages []scriptedMessage
	index    int
}

type scriptedMessage struct {
	kind    protocol.MessageType
	seq     uint64
	payload protocol.Payload
}

func (r *stubReceiver) Next(ctx context.Context) (protocol.MessageType, uint64, protocol.Payload, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.index >= len(r.messages) {
		// Nothing left: behave like a peer that went silent rather than
		// returning a message the script does not contain.
		<-ctx.Done()
		return "", 0, protocol.Payload{}, ctx.Err()
	}

	message := r.messages[r.index]
	r.index++
	return message.kind, message.seq, message.payload, nil
}

func newDriverFixture(t *testing.T, authorized bool) (*Driver, *wireguard.FakeController, *stubTransport, *stubPublisher, domain.NostrPublicKey) {
	t.Helper()

	controller := wireguard.NewFakeController()
	clock := &fixedClock{now: testFixedNow}
	journal := netstate.NewJournalStore(t.TempDir())
	netManager := netstate.NewManager(controller, journal, clock)

	manager, err := NewSessionManager(SessionManagerOptions{
		Controller: controller,
		NetState:   netManager,
		Clock:      clock,
	})
	if err != nil {
		t.Fatalf("building manager: %v", err)
	}

	peer := nostrIdentity(t, 9)

	allowlist := policy.NewAllowlist()
	if authorized {
		if err := allowlist.Add(policy.Grant{
			Peer:    peer,
			Alias:   "peer",
			Actions: []policy.Action{policy.ActionSession},
		}); err != nil {
			t.Fatalf("authorizing peer: %v", err)
		}
	}

	transport := newStubTransport(51820)
	publisher := &stubPublisher{}

	gatherer := connectivity.NewGatherer(connectivity.GathererOptions{
		Policy: connectivity.GatherPolicy{Order: []connectivity.Method{connectivity.MethodInterface}},
		Clock:  clock.Now,
	})

	driver, err := NewDriver(DriverDeps{
		Manager:    manager,
		Allowlist:  allowlist,
		NetState:   netManager,
		Controller: controller,
		Identity:   nostrIdentity(t, 1),
		Keys:       identity.NewKeyGenerator(),
		Transport:  transport,
		Publisher:  publisher,
		Receiver:   &stubReceiver{},
		Gatherer:   gatherer,
		Clock:      clock,
	}, DriverOptions{
		InterfaceName:    "nm0",
		AllowedIPs:       []netip.Prefix{netip.MustParsePrefix("100.96.0.2/32")},
		HandshakeTimeout: 300 * time.Millisecond,
		VerifyTimeout:    300 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("building driver: %v", err)
	}

	return driver, controller, transport, publisher, peer
}

// The first invariant: an unauthorized peer costs this node nothing. No socket
// is released, no interface is created, and crucially no peer is ever applied
// to the kernel.
func TestUnauthorizedPeerTouchesNothing(t *testing.T) {
	driver, controller, transport, publisher, peer := newDriverFixture(t, false)

	err := driver.Connect(context.Background(), peer, RoleInitiator)
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized, got %v", err)
	}

	for _, call := range controller.Calls {
		if strings.Contains(call, "ApplyPeer") || strings.Contains(call, "EnsureInterface") {
			t.Errorf("an unauthorized peer reached the kernel: %s", call)
		}
	}
	if transport.isClosed() {
		t.Error("the session port was released for an unauthorized peer")
	}
	if len(publisher.types()) != 0 {
		t.Errorf("an unauthorized peer was announced to relays: %v", publisher.types())
	}
}

// Authorization must happen before a session is even registered, so a refused
// peer leaves no trace to clean up.
func TestUnauthorizedPeerLeavesNoSession(t *testing.T) {
	driver, _, _, _, peer := newDriverFixture(t, false)

	_ = driver.Connect(context.Background(), peer, RoleInitiator)

	if _, known := driver.manager.Get(peer); known {
		t.Error("a refused peer left a session behind")
	}
}

// When no candidate verifies, the session fails and nothing is written to the
// kernel. A tunnel configured toward an unverified address is exactly what the
// connectivity checks exist to prevent.
func TestNoValidPathAppliesNoPeer(t *testing.T) {
	driver, controller, _, _, peer := newDriverFixture(t, true)

	// The peer offers a candidate but never answers a probe.
	driver.receiver = &stubReceiver{messages: []scriptedMessage{
		offerMessage(t),
		candidateMessage("198.51.100.10:51820"),
	}}

	err := driver.Connect(context.Background(), peer, RoleInitiator)
	if err == nil {
		t.Fatal("connecting must fail when no candidate verifies")
	}

	for _, call := range controller.Calls {
		if strings.Contains(call, "ApplyPeer") {
			t.Errorf("a peer was applied without a verified path: %s", call)
		}
	}

	state, known := driver.manager.Get(peer)
	if !known {
		t.Fatal("a failed session must remain visible")
	}
	if state.Phase != PhaseFailed {
		t.Errorf("phase = %s, want failed", state.Phase)
	}
	if state.FailureReason == "" {
		t.Error("a failed session must record why")
	}
}

// A peer offering a loopback or multicast address must not get this node to
// probe it. Refusing at the engine is what stops a peer from aiming this node's
// traffic somewhere it does not belong.
func TestPeerCannotOfferUnroutableCandidates(t *testing.T) {
	for name, address := range map[string]string{
		"loopback":    "127.0.0.1:51820",
		"unspecified": "0.0.0.0:51820",
		"multicast":   "224.0.0.1:51820",
	} {
		t.Run(name, func(t *testing.T) {
			driver, controller, _, _, peer := newDriverFixture(t, true)

			driver.receiver = &stubReceiver{messages: []scriptedMessage{
				offerMessage(t),
				candidateMessage(address),
			}}

			err := driver.Connect(context.Background(), peer, RoleInitiator)
			if !errors.Is(err, ErrNoValidPath) {
				t.Errorf("expected ErrNoValidPath for %s, got %v", address, err)
			}

			for _, call := range controller.Calls {
				if strings.Contains(call, "ApplyPeer") {
					t.Errorf("an unroutable candidate reached the kernel: %s", call)
				}
			}
		})
	}
}

// A candidate carrying a transport this node does not speak must be refused
// rather than probed with the wrong protocol.
func TestUnknownTransportIsRefused(t *testing.T) {
	wire := protocol.Candidate{
		ID:        "c1",
		Type:      protocol.CandidateHost,
		Transport: "tcp",
		Address:   "198.51.100.10:51820",
	}

	if _, err := toConnectivity(wire, "peer"); err == nil {
		t.Error("a non-UDP candidate must be refused")
	}
}

// An unknown candidate type must not inherit the treatment of a known one: a
// relay candidate silently handled as a host candidate is a routing decision
// made by accident.
func TestUnknownCandidateTypeIsRefused(t *testing.T) {
	wire := protocol.Candidate{
		ID:      "c1",
		Type:    protocol.CandidateType("something-new"),
		Address: "198.51.100.10:51820",
	}

	if _, err := toConnectivity(wire, "peer"); err == nil {
		t.Error("an unknown candidate type must be refused")
	}
}

// A candidate arriving from the wire is never trusted as verified: it enters
// the engine unverified, whatever it claims.
func TestPeerCandidatesArriveUnverified(t *testing.T) {
	wire := protocol.Candidate{
		ID:       "c1",
		Type:     protocol.CandidateHost,
		Address:  "198.51.100.10:51820",
		Priority: 10,
	}

	candidate, err := toConnectivity(wire, "peer")
	if err != nil {
		t.Fatalf("converting: %v", err)
	}
	if candidate.Status == connectivity.StatusValid {
		t.Error("a candidate from the wire must not arrive valid")
	}
}

// The driver must refuse to run without the pieces that enforce its
// invariants. An absent allowlist in particular cannot mean "allow": no list
// would mean no denials, inverting deny-by-default.
func TestDriverRequiresItsGuards(t *testing.T) {
	controller := wireguard.NewFakeController()
	journal := netstate.NewJournalStore(t.TempDir())
	clock := &fixedClock{now: time.Now()}
	netManager := netstate.NewManager(controller, journal, clock)

	manager, err := NewSessionManager(SessionManagerOptions{
		Controller: controller, NetState: netManager, Clock: clock,
	})
	if err != nil {
		t.Fatalf("building manager: %v", err)
	}

	complete := DriverDeps{
		Manager:    manager,
		Allowlist:  policy.NewAllowlist(),
		NetState:   netManager,
		Controller: controller,
		Identity:   nostrIdentity(t, 1),
		Keys:       identity.NewKeyGenerator(),
		Transport:  newStubTransport(51820),
		Publisher:  &stubPublisher{},
		Receiver:   &stubReceiver{},
		Gatherer:   connectivity.NewGatherer(connectivity.GathererOptions{Clock: clock.Now}),
	}

	cases := map[string]func(*DriverDeps){
		"no allowlist": func(d *DriverDeps) { d.Allowlist = nil },
		"no netstate":  func(d *DriverDeps) { d.NetState = nil },
		"no manager":   func(d *DriverDeps) { d.Manager = nil },
		"no transport": func(d *DriverDeps) { d.Transport = nil },
		"no identity":  func(d *DriverDeps) { d.Identity = domain.NostrPublicKey{} },
	}

	for name, break_ := range cases {
		t.Run(name, func(t *testing.T) {
			deps := complete
			break_(&deps)

			if _, err := NewDriver(deps, DriverOptions{}); err == nil {
				t.Errorf("a driver with %s must be refused", name)
			}
		})
	}
}

// AllowedIPs come from local configuration. A peer's physical endpoint must
// never appear there: that field decides what source addresses this node
// accepts through the tunnel, and letting a peer influence it would let it
// claim traffic for prefixes it was never granted.
func TestAllowedIPsNeverIncludeThePeerEndpoint(t *testing.T) {
	driver, _, _, _, _ := newDriverFixture(t, true)

	endpoint := netip.MustParseAddrPort("198.51.100.10:51820")
	for _, allowed := range driver.options.AllowedIPs {
		if allowed.Contains(endpoint.Addr()) {
			t.Errorf("AllowedIPs %s contains the peer's physical address", allowed)
		}
	}
}

// offerMessage scripts a session offer carrying a usable tunnel key.
//
// The key must carry a real expiry: an offer whose key has already expired is
// refused before candidates are ever considered, so a fixture without one would
// test the expiry check rather than what the test is named for.
func offerMessage(t *testing.T) scriptedMessage {
	t.Helper()

	public, _, err := identity.NewKeyGenerator().Generate()
	if err != nil {
		t.Fatalf("generating peer tunnel key: %v", err)
	}

	nonce, err := domain.NewNonce(rand.Reader)
	if err != nil {
		t.Fatalf("generating nonce: %v", err)
	}

	return scriptedMessage{
		kind: protocol.TypeSessionOffer,
		seq:  1,
		payload: protocol.Payload{
			Offer: &protocol.SessionOffer{
				TunnelKey: protocol.TunnelKey{
					PublicKey: public.String(),
					Nonce:     nonce.String(),
					ExpiresAt: testFixedNow.Add(time.Hour).Unix(),
				},
			},
		},
	}
}

// testFixedNow is the instant the driver fixtures' clock reports.
var testFixedNow = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

// candidateMessage scripts a candidate update from the peer.
func candidateMessage(address string) scriptedMessage {
	return scriptedMessage{
		kind: protocol.TypeCandidateUpdate,
		seq:  2,
		payload: protocol.Payload{
			Candidate: &protocol.CandidateUpdate{
				Added: []protocol.Candidate{{
					ID:      "peer-1",
					Type:    protocol.CandidateHost,
					Address: address,
				}},
				Final: true,
			},
		},
	}
}
