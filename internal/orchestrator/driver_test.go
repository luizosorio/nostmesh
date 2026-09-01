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
	mu      sync.Mutex
	sent    []sentMessage
	session string
}

// sentMessage records a publication and the session it named, which is the only
// way to tell an offer that names the answered session from one that names
// nothing.
type sentMessage struct {
	kind    protocol.MessageType
	session string
}

func (p *stubPublisher) Publish(_ context.Context, kind protocol.MessageType, _ uint64, _ protocol.Payload) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// The session is captured at publication time, exactly as the real plane
	// stamps it into the envelope. A stub that ignored it could not tell a
	// message naming no session from a correct one.
	p.sent = append(p.sent, sentMessage{kind: kind, session: p.session})
	return nil
}

// BindSession mirrors the real transport: an empty id is refused, because "not
// yet bound" is an initial state rather than something a caller asks for.
func (p *stubPublisher) BindSession(sessionID string) error {
	if sessionID == "" {
		return errors.New("a session identifier is required")
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	p.session = sessionID
	return nil
}

func (p *stubPublisher) types() []protocol.MessageType {
	p.mu.Lock()
	defer p.mu.Unlock()

	out := make([]protocol.MessageType, 0, len(p.sent))
	for _, sent := range p.sent {
		out = append(out, sent.kind)
	}
	return out
}

// sessionOf reports the session a published message named, and whether it was
// published at all.
func (p *stubPublisher) sessionOf(kind protocol.MessageType) (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, sent := range p.sent {
		if sent.kind == kind {
			return sent.session, true
		}
	}
	return "", false
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

	// session names the conversation the message belongs to, as the envelope
	// would.
	session string

	// createdAt is when the sender stamped it.
	createdAt time.Time
}

func (r *stubReceiver) Next(ctx context.Context) (Delivery, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.index >= len(r.messages) {
		// Nothing left: behave like a peer that went silent rather than
		// returning a message the script does not contain.
		<-ctx.Done()
		return Delivery{}, ctx.Err()
	}

	message := r.messages[r.index]
	r.index++

	return Delivery{
		Kind:      message.kind,
		Seq:       message.seq,
		Payload:   message.payload,
		SessionID: message.session,
		CreatedAt: message.createdAt,
	}, nil
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

// answeringTransport answers its own probes, so a candidate verifies without a
// network. It stands in for a reachable peer.
type answeringTransport struct {
	*stubTransport

	// key is supplied by the driver's own derivation, so the answer is
	// authenticated exactly as a real peer's would be. A transport that echoed
	// without authenticating would make the checker accept anything, which is
	// the one thing it must never do.
	key   func() connectivity.SessionKey
	clock func() time.Time

	mu     sync.Mutex
	target netip.AddrPort
}

func (a *answeringTransport) Send(_ context.Context, target netip.AddrPort, payload []byte) error {
	key := a.key()

	// A probe that does not authenticate is dropped silently, exactly as a real
	// peer would drop it: answering would defeat the check.
	decoded, ok := decodeChallenge(payload, key)
	if !ok || decoded.IsResponse {
		return nil
	}

	a.mu.Lock()
	a.target = target
	a.mu.Unlock()

	// Answer as the peer at that address would: the response is authenticated
	// for the source address the challenger will see.
	response := connectivity.EncodeResponse(decoded.Nonce, a.clock(), target, key)

	go func() {
		select {
		case a.received <- response:
		case <-time.After(2 * time.Second):
		}
	}()
	return nil
}

func (a *answeringTransport) Receive(ctx context.Context) ([]byte, netip.AddrPort, error) {
	select {
	case <-ctx.Done():
		return nil, netip.AddrPort{}, ctx.Err()
	case payload := <-a.received:
		a.mu.Lock()
		source := a.target
		a.mu.Unlock()
		return payload, source, nil
	}
}

// Both sides run concurrently and relays reorder, so a message legitimately
// arrives before the step that consumes it. Dropping it loses it for good, and
// both sides then wait out their timeouts for something that already came and
// went — which is exactly what happened against real relays.
func TestOutOfOrderMessagesAreNotLost(t *testing.T) {
	driver, _, _, _, _ := newDriverFixture(t, true)

	early := candidateMessage("198.51.100.10:51820")
	offer := offerMessage(t)

	// The candidate update arrives first, before anything waits for it.
	driver.receiver = &stubReceiver{messages: []scriptedMessage{early, offer}}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// The offer is consumed while the candidate update is held.
	if _, err := driver.awaitMessage(ctx, protocol.TypeSessionOffer); err != nil {
		t.Fatalf("waiting for the offer: %v", err)
	}

	// The receiver is exhausted now, so the candidate update can only come from
	// what was held.
	delivery, err := driver.awaitMessage(ctx, protocol.TypeCandidateUpdate)
	if err != nil {
		t.Fatalf("the early candidate update was lost: %v", err)
	}
	if delivery.Payload.Candidate == nil || len(delivery.Payload.Candidate.Added) != 1 {
		t.Error("the held message did not survive intact")
	}
}

// A peer flooding one message type must not grow the buffer without bound.
func TestHeldMessagesAreBounded(t *testing.T) {
	driver, _, _, _, _ := newDriverFixture(t, true)

	flood := make([]scriptedMessage, 0, maxHeldPerType*3)
	for range maxHeldPerType * 3 {
		flood = append(flood, candidateMessage("198.51.100.10:51820"))
	}
	driver.receiver = &stubReceiver{messages: flood}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Waiting for a type that never arrives drains the flood into the buffer.
	_, _ = driver.awaitMessage(ctx, protocol.TypeSessionReady)

	driver.pendingMu.Lock()
	held := len(driver.pending[protocol.TypeCandidateUpdate])
	driver.pendingMu.Unlock()

	if held > maxHeldPerType {
		t.Errorf("held %d messages, limit is %d", held, maxHeldPerType)
	}
}

// The offer a responder publishes must name the session of the request it
// answered. An offer naming nothing is discarded by the initiator as belonging
// to a different conversation, and both sides then wait out their timeouts.
//
// Observed against a real relay, where the offer carried an empty session id.
// This assertion is on the published message rather than on transport state,
// because three earlier versions asserting the latter passed against the bug:
// the stub held the same field the implementation held, so it answered from its
// own bookkeeping instead of from what was sent.
func TestTheOfferNamesTheAnsweredSession(t *testing.T) {
	driver, _, _, publisher, peer := newDriverFixture(t, true)

	request := requestMessage(t)
	driver.receiver = &stubReceiver{messages: []scriptedMessage{request}}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// Run the responder far enough to publish its offer. It will fail later
	// waiting for an accept that never comes, which is not what is under test.
	_ = driver.Connect(ctx, peer, RoleResponder)

	named, published := publisher.sessionOf(protocol.TypeSessionOffer)
	if !published {
		t.Fatal("the responder never published an offer")
	}
	if named == "" {
		t.Fatal("the offer named no session; the initiator discards it as belonging to another conversation")
	}
	if named != request.session {
		t.Errorf("the offer names session %s, the request it answered was %s", named, request.session)
	}
}

// A responder must not answer the same session twice. A relay hands back stored
// requests on every poll, so without this it answers an abandoned session
// forever and never reaches the live one behind it.
func TestResponderDoesNotAnswerASessionTwice(t *testing.T) {
	driver, _, _, _, _ := newDriverFixture(t, true)

	first := requestMessage(t)
	driver.receiver = &stubReceiver{messages: []scriptedMessage{first}}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	answered, err := driver.awaitRequest(ctx)
	if err != nil {
		t.Fatalf("awaiting the first request: %v", err)
	}

	if !driver.alreadyTried(answered.sessionID) {
		t.Error("a session that was answered must be remembered")
	}
}

// Asking whether a session was answered must not record that it was.
//
// The responder consults this on every request the relay hands it, including
// ones it goes on to reject for other reasons. If merely asking marked them, a
// session declined once could never be answered later, and the responder would
// sit idle with a live request in front of it.
//
// Measured against real relays: the responder settled on a request from a
// previous run, that attempt failed, and the session it should have answered had
// been struck off by the act of comparing the two.
func TestAskingDoesNotRecordAnAttempt(t *testing.T) {
	driver, _, _, _, _ := newDriverFixture(t, true)

	var session domain.SessionID
	for i := range session {
		session[i] = byte(i + 1)
	}

	if driver.alreadyTried(session) {
		t.Fatal("a session nothing has answered must not be reported as tried")
	}

	// Asking again must still say no: the first question cannot have been an
	// answer.
	if driver.alreadyTried(session) {
		t.Error("asking whether a session was answered recorded it as answered")
	}

	driver.recordAttempt(session)
	if !driver.alreadyTried(session) {
		t.Error("a recorded attempt must be remembered")
	}
}

// A responder answers the first request it has not already answered.
//
// This is what a continuously running listener makes possible: it is already
// subscribed when a request is published, so requests arrive in order and no
// heuristic is needed to tell a live one from a stored one.
func TestResponderAnswersTheFirstUnansweredRequest(t *testing.T) {
	driver, _, _, _, _ := newDriverFixture(t, true)

	first := requestMessage(t)
	first.session = strings.Repeat("44", 32)

	second := requestMessage(t)
	second.session = strings.Repeat("55", 32)

	driver.receiver = &stubReceiver{messages: []scriptedMessage{first, second}}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	chosen, err := driver.awaitRequest(ctx)
	if err != nil {
		t.Fatalf("awaiting a request: %v", err)
	}
	if chosen.sessionID.String() != first.session {
		t.Errorf("answered %s, expected the first %s", chosen.sessionID.String()[:8], first.session[:8])
	}
}

// A session already answered is skipped, so a relay handing the same stored
// request back on every poll does not make the responder answer it forever.
func TestResponderSkipsASessionItAlreadyAnswered(t *testing.T) {
	driver, _, _, _, _ := newDriverFixture(t, true)

	repeated := requestMessage(t)
	repeated.session = strings.Repeat("66", 32)

	fresh := requestMessage(t)
	fresh.session = strings.Repeat("77", 32)

	// The same request arrives twice, as a poll would deliver it, followed by a
	// new one.
	driver.receiver = &stubReceiver{messages: []scriptedMessage{repeated, repeated, fresh}}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if _, err := driver.awaitRequest(ctx); err != nil {
		t.Fatalf("first request: %v", err)
	}

	next, err := driver.awaitRequest(ctx)
	if err != nil {
		t.Fatalf("second request: %v", err)
	}
	if next.sessionID.String() != fresh.session {
		t.Errorf("answered %s again, expected to move on to %s",
			next.sessionID.String()[:8], fresh.session[:8])
	}
}

// An offer from a responder whose clock runs behind must still be accepted, or
// the skew tolerance would be tighter here than the protocol applies elsewhere.
func TestInitiatorAcceptsAnOfferFromASkewedResponder(t *testing.T) {
	driver, _, _, _, _ := newDriverFixture(t, true)

	skewed := offerMessage(t)
	skewed.createdAt = testFixedNow.Add(-protocol.MaxClockSkew + time.Minute)

	driver.receiver = &stubReceiver{messages: []scriptedMessage{skewed}}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if _, err := driver.awaitOffer(ctx, testFixedNow); err != nil {
		t.Errorf("an offer from a responder running behind must be accepted: %v", err)
	}
}

// A listener builds a fresh driver for each attempt, so the record of what it
// answered must be supplied from outside and survive between them.
//
// Without that, a responder binds to the same stored session on every attempt
// and refuses every live request behind it. Measured against real relays: the
// responder answered session e29cb989 from an earlier run and then refused six
// consecutive live requests, one per attempt, indefinitely.
func TestAnsweredSessionsSurviveAcrossDrivers(t *testing.T) {
	answered := NewAnsweredSessions(func() time.Time { return testFixedNow })

	stale := requestMessage(t)
	stale.session = strings.Repeat("88", 32)

	live := requestMessage(t)
	live.session = strings.Repeat("99", 32)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// First attempt: a driver answers the stored session and then fails, as one
	// answering an abandoned session does.
	first := newDriverSharing(t, answered, []scriptedMessage{stale, live})
	chosen, err := first.awaitRequest(ctx)
	if err != nil {
		t.Fatalf("first attempt: %v", err)
	}
	if chosen.sessionID.String() != stale.session {
		t.Fatalf("first attempt answered %s, expected the stored %s",
			chosen.sessionID.String()[:8], stale.session[:8])
	}

	// Second attempt: a new driver, the same record. The relay hands back both
	// requests again, and the responder must move past the one it answered.
	second := newDriverSharing(t, answered, []scriptedMessage{stale, live})
	next, err := second.awaitRequest(ctx)
	if err != nil {
		t.Fatalf("second attempt: %v", err)
	}
	if next.sessionID.String() != live.session {
		t.Errorf("second attempt answered %s again; a fresh driver forgot what the listener had answered",
			next.sessionID.String()[:8])
	}
}

// A session is forgotten once a relay would no longer serve its messages, so a
// listener left up for weeks does not grow without bound.
func TestAnsweredSessionsAreForgottenEventually(t *testing.T) {
	now := testFixedNow
	answered := NewAnsweredSessions(func() time.Time { return now })

	var session domain.SessionID
	for i := range session {
		session[i] = byte(i + 1)
	}

	answered.Add(session)
	if !answered.Contains(session) {
		t.Fatal("a session just answered must be remembered")
	}

	now = now.Add(answeredRetention + time.Minute)
	if answered.Contains(session) {
		t.Error("a session older than the retention window must be forgotten")
	}
}

// newDriverSharing builds a driver over a shared record of answered sessions.
//
// It goes through NewDriver rather than setting the field afterwards, so the
// test exercises the wiring a listener actually uses: a constructor that ignored
// the supplied record would still pass if the test reached past it.
func newDriverSharing(t *testing.T, answered *AnsweredSessions, script []scriptedMessage) *Driver {
	t.Helper()

	controller := wireguard.NewFakeController()
	clock := &fixedClock{now: testFixedNow}
	journal := netstate.NewJournalStore(t.TempDir())
	netManager := netstate.NewManager(controller, journal, clock)

	manager, err := NewSessionManager(SessionManagerOptions{
		Controller: controller, NetState: netManager, Clock: clock,
	})
	if err != nil {
		t.Fatalf("building manager: %v", err)
	}

	peer := nostrIdentity(t, 9)
	allowlist := policy.NewAllowlist()
	if err := allowlist.Add(policy.Grant{
		Peer: peer, Alias: "peer", Actions: []policy.Action{policy.ActionSession},
	}); err != nil {
		t.Fatalf("authorizing: %v", err)
	}

	driver, err := NewDriver(DriverDeps{
		Manager:    manager,
		Allowlist:  allowlist,
		NetState:   netManager,
		Controller: controller,
		Identity:   nostrIdentity(t, 1),
		Keys:       identity.NewKeyGenerator(),
		Transport:  newStubTransport(51820),
		Publisher:  &stubPublisher{},
		Receiver:   &stubReceiver{messages: script},
		Gatherer: connectivity.NewGatherer(connectivity.GathererOptions{
			Policy: connectivity.GatherPolicy{Order: []connectivity.Method{connectivity.MethodInterface}},
			Clock:  clock.Now,
		}),
		Clock:    clock,
		Answered: answered,
	}, DriverOptions{
		InterfaceName:    "nm0",
		AllowedIPs:       []netip.Prefix{netip.MustParsePrefix("100.96.0.2/32")},
		HandshakeTimeout: 300 * time.Millisecond,
		VerifyTimeout:    300 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("building driver: %v", err)
	}
	return driver
}

// Both ends must reach the same answer about who initiates, without exchanging
// a message.
//
// If both open a session, each refuses the other's as belonging to a different
// conversation and neither can break the tie. Observed between two real hosts:
// one bound to session 50e5e074, the other to b2be095e, and each rejected its
// peer's until both timed out.
func TestBothEndsAgreeOnWhoInitiates(t *testing.T) {
	lower := nostrIdentity(t, 1)
	higher := nostrIdentity(t, 200)

	if lower.String() >= higher.String() {
		t.Fatalf("fixture is not ordered as assumed: %s vs %s", lower.String()[:8], higher.String()[:8])
	}

	// Each side computes from its own point of view; the results must be
	// complementary.
	fromLower := resolveRole(lower, higher, RoleAuto)
	fromHigher := resolveRole(higher, lower, RoleAuto)

	if fromLower != RoleInitiator {
		t.Errorf("the lower key must initiate, got role %d", fromLower)
	}
	if fromHigher != RoleResponder {
		t.Errorf("the higher key must respond, got role %d", fromHigher)
	}
	if fromLower == fromHigher {
		t.Error("both ends chose the same role; neither would answer the other")
	}
}

// An explicit role is honoured, so one-shot debugging can still force a side.
func TestAnExplicitRoleIsNotOverridden(t *testing.T) {
	lower := nostrIdentity(t, 1)
	higher := nostrIdentity(t, 200)

	if resolveRole(higher, lower, RoleInitiator) != RoleInitiator {
		t.Error("an explicitly requested role must be honoured")
	}
	if resolveRole(lower, higher, RoleResponder) != RoleResponder {
		t.Error("an explicitly requested role must be honoured")
	}
}

// requestMessage scripts a session request from the peer.
func requestMessage(t *testing.T) scriptedMessage {
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
		kind:      protocol.TypeSessionRequest,
		seq:       0,
		session:   strings.Repeat("ab", 32),
		createdAt: testFixedNow,
		payload: protocol.Payload{
			Request: &protocol.SessionRequest{
				TunnelKey: protocol.TunnelKey{
					PublicKey: public.String(),
					Nonce:     nonce.String(),
					ExpiresAt: testFixedNow.Add(time.Hour).Unix(),
				},
			},
		},
	}
}

// decodeChallenge reports whether a datagram is an authentic challenge.
//
// The boolean is deliberate: an unauthenticated probe is not an error to
// propagate, it is a datagram to ignore, and the two must not be confused.
func decodeChallenge(payload []byte, key connectivity.SessionKey) (connectivity.DecodedProbe, bool) {
	decoded, err := connectivity.DecodeChallenge(payload, key)
	return decoded, err == nil
}

// The heart of this delivery: a tunnel that is fully configured and carries no
// traffic must be reported as a failure, not as success.
//
// Every check before this one passes for such a tunnel — the interface exists,
// the peer was applied, the endpoint was written. Only the data plane can say
// whether a packet actually moves.
func TestConfiguredTunnelCarryingNothingFails(t *testing.T) {
	driver, controller, _, _, peer := newDriverFixture(t, true)
	makeReachable(t, driver)

	// The controller is left with handshakes off: the peer is applied and the
	// data plane stays silent.
	err := driver.Connect(context.Background(), peer, RoleInitiator)
	if !errors.Is(err, ErrTunnelNotCarrying) {
		t.Fatalf("expected ErrTunnelNotCarrying, got %v", err)
	}

	// The peer was applied — which is exactly why configuration alone is not
	// evidence, and why this check exists.
	var applied bool
	for _, call := range controller.Calls {
		if strings.Contains(call, "ApplyPeer") {
			applied = true
		}
	}
	if !applied {
		t.Error("the test did not reach configuration, so it proves nothing about the traffic check")
	}

	state, _ := driver.manager.Get(peer)
	if state.Phase != PhaseFailed {
		t.Errorf("phase = %s, want failed", state.Phase)
	}
}

// A tunnel that was configured and carries nothing must be removed, not left.
//
// The port it holds is the session's, and the next attempt binds the same one.
// Leaving the interface turns a single failed session into a peer that can never
// reconnect: every later attempt fails with "address already in use" against a
// port its own previous attempt is still holding.
//
// Measured between two hosts: the first attempt failed the traffic check, and
// every attempt after it failed to bind.
func TestAFailedTrafficCheckRemovesWhatItApplied(t *testing.T) {
	driver, controller, _, _, peer := newDriverFixture(t, true)
	makeReachable(t, driver)

	// Handshakes stay off, so the tunnel is configured and carries nothing.
	err := driver.Connect(context.Background(), peer, RoleInitiator)
	if !errors.Is(err, ErrTunnelNotCarrying) {
		t.Fatalf("expected ErrTunnelNotCarrying, got %v", err)
	}

	if controller.HasInterface("nm0") {
		t.Error("the interface outlived the session that failed; it still holds the port the next attempt needs")
	}
}

// With the data plane carrying traffic, the same path establishes.
func TestTunnelCarryingTrafficEstablishes(t *testing.T) {
	driver, controller, transport, publisher, peer := newDriverFixture(t, true)
	makeReachable(t, driver)

	controller.HandshakeOnApply(testFixedNow)

	if err := driver.Connect(context.Background(), peer, RoleInitiator); err != nil {
		t.Fatalf("connecting: %v", err)
	}

	state, _ := driver.manager.Get(peer)
	if state.Phase != PhaseEstablished {
		t.Errorf("phase = %s, want established", state.Phase)
	}

	// The port must have been handed over before the interface was configured.
	if !transport.isClosed() {
		t.Error("the session port was never released for WireGuard")
	}

	var announced bool
	for _, kind := range publisher.types() {
		if kind == protocol.TypeSessionReady {
			announced = true
		}
	}
	if !announced {
		t.Error("an established session was not announced to the peer")
	}
}

// The endpoint written to the kernel must be the verified address, and the
// AllowedIPs must be the locally configured ones — never anything derived from
// what the peer sent.
func TestConfiguredPeerUsesVerifiedEndpointAndLocalAllowedIPs(t *testing.T) {
	driver, controller, _, _, peer := newDriverFixture(t, true)
	makeReachable(t, driver)
	controller.HandshakeOnApply(testFixedNow)

	if err := driver.Connect(context.Background(), peer, RoleInitiator); err != nil {
		t.Fatalf("connecting: %v", err)
	}

	observed, err := controller.ObserveInterface(context.Background(), "nm0")
	if err != nil {
		t.Fatalf("observing: %v", err)
	}
	if len(observed.Peers) != 1 {
		t.Fatalf("%d peers configured, want 1", len(observed.Peers))
	}

	applied := observed.Peers[0]
	if applied.Endpoint == nil || applied.Endpoint.String() != "198.51.100.10:51820" {
		t.Errorf("endpoint = %v, want the verified address", applied.Endpoint)
	}

	if len(applied.AllowedIPs) != 1 || applied.AllowedIPs[0].String() != "100.96.0.2/32" {
		t.Errorf("AllowedIPs = %v, want the locally configured prefix", applied.AllowedIPs)
	}

	// The peer's physical address must never appear in AllowedIPs: that field
	// decides what this node accepts through the tunnel.
	for _, allowed := range applied.AllowedIPs {
		if allowed.Contains(netip.MustParseAddr("198.51.100.10")) {
			t.Errorf("AllowedIPs %s contains the peer's physical address", allowed)
		}
	}
}

// reachableAddress is the candidate a scripted peer offers and answers on.
const reachableAddress = "198.51.100.10:51820"

// makeReachable scripts a peer that negotiates and answers probes.
func makeReachable(t *testing.T, driver *Driver) {
	t.Helper()

	driver.receiver = &stubReceiver{messages: []scriptedMessage{
		offerMessage(t),
		candidateMessage(reachableAddress),
	}}

	stub, ok := driver.transport.(*stubTransport)
	if !ok {
		t.Fatal("fixture transport has been replaced")
	}

	// The probe key comes from the session id and both tunnel keys, none of
	// which exist until negotiation finishes. It is therefore derived lazily,
	// from the same handshake the driver uses, so the answer authenticates the
	// way a real peer's would rather than bypassing the check.
	peer := nostrIdentity(t, 9)
	derive := func() connectivity.SessionKey {
		handshake, known := driver.manager.Handshake(peer)
		if !known {
			return connectivity.SessionKey{}
		}
		return connectivity.DeriveSessionKey(
			handshake.SessionID().String(),
			handshake.LocalTunnelPublic().String(),
			peerTunnelKeyString(handshake),
		)
	}

	driver.transport = &answeringTransport{
		stubTransport: stub,
		key:           derive,
		clock:         driver.clock.Now,
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
		kind:      protocol.TypeSessionOffer,
		seq:       1,
		createdAt: testFixedNow,
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
