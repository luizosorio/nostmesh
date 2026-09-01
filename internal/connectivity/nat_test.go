package connectivity

import (
	"context"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// natTransport models an address-dependent NAT in front of the peer.
//
// The existing fakeTransport answers at whatever address it was aimed at, which
// makes the announced address and the working address the same value. Behind a
// real NAT they are not: the mapping a peer's STUN lookup produced accepts
// traffic from the STUN server, and traffic from anywhere else takes a
// different mapping or is dropped. A fake that collapses the two cannot fail on
// that difference, so it would confirm the implementation rather than test it.
//
// This transport therefore knows only addresses and the session key. It never
// consults the engine or the candidate table: if it did, it would be asserting
// what the implementation expects instead of what a network does.
type natTransport struct {
	mu sync.Mutex

	// announced is the address the peer published, learned from its STUN
	// lookup. Traffic aimed here is dropped: the mapping exists for the
	// observer, not for us.
	announced netip.AddrPort

	// mappings holds the addresses that currently accept our traffic. A
	// mapping appears only when the peer sends through it first, which is what
	// makes the working address unreachable until the peer speaks.
	mappings map[netip.AddrPort]bool

	key     SessionKey
	sent    []netip.AddrPort
	inbound chan probeArrival
	clock   func() time.Time
}

func newNATTransport(announced netip.AddrPort, key SessionKey, clock func() time.Time) *natTransport {
	return &natTransport{
		announced: announced,
		mappings:  make(map[netip.AddrPort]bool),
		key:       key,
		inbound:   make(chan probeArrival, 64),
		clock:     clock,
	}
}

func (n *natTransport) Send(_ context.Context, target netip.AddrPort, payload []byte) error {
	n.mu.Lock()
	n.sent = append(n.sent, target)
	open := n.mappings[target]
	n.mu.Unlock()

	if !open {
		// No mapping: the NAT drops it. Sending succeeded locally, which is
		// exactly what an unreachable address looks like from here.
		return nil
	}

	decoded, err := DecodeChallenge(payload, n.key)
	if err != nil {
		// Not a challenge we can answer. A response we sent lands here too,
		// and the peer has nothing further to say about it.
		return nil //nolint:nilerr // silence is the modelled behaviour
	}

	// The peer answers through the same mapping, so the datagram comes back
	// from the address we reached it at.
	response := EncodeResponse(decoded.Nonce, n.clock(), target, n.key)

	select {
	case n.inbound <- probeArrival{payload: response, source: target}:
	default:
	}
	return nil
}

func (n *natTransport) Receive(ctx context.Context) ([]byte, netip.AddrPort, error) {
	select {
	case <-ctx.Done():
		return nil, netip.AddrPort{}, ctx.Err()
	case arrival := <-n.inbound:
		return arrival.payload, arrival.source, nil
	}
}

// injectChallenge models the peer probing us.
//
// Its outgoing packet creates the NAT mapping, which is why the address becomes
// reachable only now and only at this exact address. This is the whole reason a
// peer-reflexive candidate is worth anything: the path opened because the peer
// used it, and nothing the peer announced describes it.
func (n *natTransport) injectChallenge(t *testing.T, from netip.AddrPort) {
	t.Helper()

	challenge, err := NewChallenge(n.clock())
	if err != nil {
		t.Fatalf("building challenge: %v", err)
	}

	n.mu.Lock()
	n.mappings[from] = true
	n.mu.Unlock()

	select {
	case n.inbound <- probeArrival{payload: EncodeChallenge(challenge, n.key), source: from}:
	default:
		t.Fatal("inbound queue is full")
	}
}

// natFixture wires an engine and checker onto a NAT transport.
type natFixture struct {
	engine    *Engine
	transport *natTransport
	checker   *Checker
	clock     *advancingClock
}

func newNATFixture(t *testing.T, announced netip.AddrPort) *natFixture {
	t.Helper()

	clock := &advancingClock{now: testNow(), step: time.Millisecond}

	engine, err := NewEngine(EngineOptions{
		SessionID: "session-1",
		Limits:    DefaultLimits(),
		Clock:     clock.Now,
	})
	if err != nil {
		t.Fatalf("building engine: %v", err)
	}

	transport := newNATTransport(announced, testKey(), clock.Now)

	limits := DefaultLimits()
	limits.CheckTimeout = 20 * time.Millisecond
	limits.TotalTimeout = 2 * time.Second

	checker, err := NewChecker(CheckerOptions{
		Engine:    engine,
		Transport: transport,
		Key:       testKey(),
		Limits:    limits,
		Clock:     clock.Now,
	})
	if err != nil {
		t.Fatalf("building checker: %v", err)
	}

	return &natFixture{engine: engine, transport: transport, checker: checker, clock: clock}
}

// A peer behind an address-dependent NAT connects through the address its
// probes actually came from, not the one it announced.
//
// This is the case measured between two real hosts: the announced address never
// answered, the working address was never probed because no candidate described
// it, and the session failed with every datagram accounted for and nothing
// discarded. Learning a peer-reflexive candidate is what closes it.
func TestANatdPathVerifiesThroughAPeerReflexiveCandidate(t *testing.T) {
	announced := netip.MustParseAddrPort("203.0.113.20:40001")
	working := netip.MustParseAddrPort("203.0.113.20:40002")

	fixture := newNATFixture(t, announced)

	// All we were told is the address the peer's STUN lookup produced.
	if err := fixture.engine.AddCandidate(Candidate{
		ID:       "srflx-peer",
		Kind:     KindServerReflexive,
		Address:  announced,
		Priority: priorityFor(KindServerReflexive, announced.Addr()),
		Source:   "peer",
	}); err != nil {
		t.Fatalf("adding candidate: %v", err)
	}

	// The peer probes us, opening the mapping its own traffic uses.
	fixture.transport.injectChallenge(t, working)

	result, err := fixture.checker.Run(context.Background())
	if err != nil {
		t.Fatalf("checking: %v", err)
	}

	if result.Nominated == nil {
		t.Fatal("no candidate was nominated")
	}
	if result.Nominated.Address != working {
		t.Errorf("nominated %s, want the address the peer actually reached us from (%s)",
			result.Nominated.Address, working)
	}
	if result.Nominated.Kind != KindPeerReflexive {
		t.Errorf("nominated a %s candidate, want %s", result.Nominated.Kind, KindPeerReflexive)
	}

	endpoint, ok := fixture.engine.Endpoint()
	if !ok || endpoint != working {
		t.Errorf("endpoint is %s (ok=%v), want %s", endpoint, ok, working)
	}
}

// The address an authenticated challenge came from becomes a candidate.
//
// Without this the address is discarded, and nothing ever probes the one path
// known to carry packets.
func TestPeerReflexiveCandidateIsLearnedFromAnUnexpectedSource(t *testing.T) {
	fixture := newCheckerFixture(t)

	source := netip.MustParseAddrPort("203.0.113.20:40002")
	challenge, err := NewChallenge(testNow())
	if err != nil {
		t.Fatalf("building challenge: %v", err)
	}

	fixture.checker.handleArrival(probeArrival{
		payload: EncodeChallenge(challenge, testKey()),
		source:  source,
	})

	for _, candidate := range fixture.engine.Diagnostics() {
		if candidate.Kind == KindPeerReflexive && candidate.Address == source {
			return
		}
	}
	t.Errorf("no peer-reflexive candidate was learned for %s", source)
}

// A learned candidate is a lead, not a result.
//
// A datagram arriving from an address says the peer can reach us through it. It
// says nothing about whether we can reach the peer, which is what the
// challenge/response that follows decides.
func TestALearnedPeerReflexiveCandidateStartsUnverified(t *testing.T) {
	fixture := newCheckerFixture(t)

	source := netip.MustParseAddrPort("203.0.113.20:40002")
	challenge, err := NewChallenge(testNow())
	if err != nil {
		t.Fatalf("building challenge: %v", err)
	}

	fixture.checker.handleArrival(probeArrival{
		payload: EncodeChallenge(challenge, testKey()),
		source:  source,
	})

	learned := false
	for _, candidate := range fixture.engine.Diagnostics() {
		if candidate.Address != source {
			continue
		}
		learned = true

		if candidate.Status != StatusUnverified {
			t.Errorf("learned candidate has status %s, want %s", candidate.Status, StatusUnverified)
		}
		if candidate.Attempts != 0 {
			t.Errorf("learned candidate has %d attempts, want 0", candidate.Attempts)
		}
		if candidate.VerifiedAt != nil {
			t.Error("learned candidate is already marked verified")
		}
	}
	if !learned {
		t.Fatalf("no candidate was learned for %s", source)
	}
}

// An address already described is not learned twice.
//
// Re-adding it under another kind would spend a third-party slot to probe the
// same address a second time.
func TestLearningDoesNotDuplicateAKnownAddress(t *testing.T) {
	fixture := newCheckerFixture(t)

	source := netip.MustParseAddrPort("198.51.100.50:51820")
	if err := fixture.engine.AddCandidate(Candidate{
		ID:      "known",
		Kind:    KindHost,
		Address: source,
		Source:  "peer",
	}); err != nil {
		t.Fatalf("adding candidate: %v", err)
	}

	challenge, err := NewChallenge(testNow())
	if err != nil {
		t.Fatalf("building challenge: %v", err)
	}

	fixture.checker.handleArrival(probeArrival{
		payload: EncodeChallenge(challenge, testKey()),
		source:  source,
	})

	if count := fixture.engine.Count(); count != 1 {
		t.Errorf("%d candidates, want the one already known", count)
	}
}

// Learning costs no extra packet.
//
// Probing the learned address immediately would answer one datagram with two,
// which is the amplification the probe design exists to prevent. The next round
// of Run picks it up instead.
func TestLearningDoesNotAmplify(t *testing.T) {
	fixture := newCheckerFixture(t)

	challenge, err := NewChallenge(testNow())
	if err != nil {
		t.Fatalf("building challenge: %v", err)
	}

	fixture.checker.handleArrival(probeArrival{
		payload: EncodeChallenge(challenge, testKey()),
		source:  netip.MustParseAddrPort("203.0.113.20:40002"),
	})

	if sent := fixture.transport.sentCount(); sent != 1 {
		t.Errorf("%d packets sent, want 1: the answer and nothing else", sent)
	}
}

// An unauthenticated datagram teaches nothing.
//
// This is what keeps an off-path attacker out of the candidate table entirely:
// without the session key it cannot produce a challenge that authenticates, so
// no source address it spoofs is ever recorded.
func TestAnUnauthenticatedChallengeTeachesNothing(t *testing.T) {
	fixture := newCheckerFixture(t)

	wrongKey := DeriveSessionKey("other-session", "a", "b")
	challenge, err := NewChallenge(testNow())
	if err != nil {
		t.Fatalf("building challenge: %v", err)
	}

	arrivals := [][]byte{
		EncodeChallenge(challenge, wrongKey),
		make([]byte, ProbeSize),
		[]byte("not a probe at all"),
	}

	for _, payload := range arrivals {
		fixture.checker.handleArrival(probeArrival{
			payload: payload,
			source:  netip.MustParseAddrPort("203.0.113.20:40002"),
		})
	}

	if count := fixture.engine.Count(); count != 0 {
		t.Errorf("%d candidates learned from unauthenticated datagrams, want 0", count)
	}
}

// The third-party limit bounds learning, and hitting it does not stop the node
// answering.
//
// Both halves matter. The limit caps what an authorized but hostile peer can
// make this node probe; still answering keeps a legitimate peer able to verify
// its own candidates, so a resource guard does not become a denial of service.
func TestLearningIsBoundedByTheThirdPartyLimit(t *testing.T) {
	clock := &advancingClock{now: testNow(), step: time.Millisecond}

	limits := DefaultLimits()
	limits.MaxThirdPartyCandidates = 2
	limits.CheckTimeout = 20 * time.Millisecond
	limits.TotalTimeout = 2 * time.Second

	engine, err := NewEngine(EngineOptions{
		SessionID: "session-1",
		Limits:    limits,
		Clock:     clock.Now,
	})
	if err != nil {
		t.Fatalf("building engine: %v", err)
	}

	transport := newFakeTransport(clock.Now)
	checker, err := NewChecker(CheckerOptions{
		Engine:    engine,
		Transport: transport,
		Key:       testKey(),
		Limits:    limits,
		Clock:     clock.Now,
	})
	if err != nil {
		t.Fatalf("building checker: %v", err)
	}

	sources := []string{
		"203.0.113.20:40001",
		"203.0.113.20:40002",
		"203.0.113.20:40003",
		"203.0.113.20:40004",
	}
	for _, address := range sources {
		challenge, challengeErr := NewChallenge(clock.Now())
		if challengeErr != nil {
			t.Fatalf("building challenge: %v", challengeErr)
		}
		checker.handleArrival(probeArrival{
			payload: EncodeChallenge(challenge, testKey()),
			source:  netip.MustParseAddrPort(address),
		})
	}

	if count := engine.Count(); count > limits.MaxThirdPartyCandidates {
		t.Errorf("%d candidates learned, limit is %d", count, limits.MaxThirdPartyCandidates)
	}

	// Every challenge was answered, including the ones that taught nothing.
	if sent := transport.sentCount(); sent != len(sources) {
		t.Errorf("%d answers sent for %d challenges: reaching the limit stopped the node answering",
			sent, len(sources))
	}

	if summary := checker.traffic(); !strings.Contains(summary, "could not learn") {
		t.Errorf("the refusal is invisible in diagnostics: %s", summary)
	}
}

// Recording what was discarded must not deadlock the receiving goroutine.
//
// verifyResponse holds the state lock across the whole match and still has to
// count what it drops. When both used one mutex, the first response that failed
// to authenticate hung the goroutine forever: probing simply stopped, with no
// error and no timeout of its own. Nothing reached this path, so nothing caught
// it.
func TestDiscardingAResponseDoesNotDeadlock(t *testing.T) {
	fixture := newCheckerFixture(t)

	done := make(chan struct{})
	go func() {
		defer close(done)

		// A response-shaped datagram whose tag cannot verify.
		garbage := make([]byte, ProbeSize)
		garbage[0] = probeResponse
		fixture.checker.verifyResponse(garbage, netip.MustParseAddrPort("198.51.100.1:1234"))

		// And one that authenticates but answers no outstanding challenge.
		orphan := EncodeResponse(testNonce(), testNow(), testTarget(), testKey())
		fixture.checker.verifyResponse(orphan, testTarget())
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("verifyResponse deadlocked while counting a discarded response")
	}

	if summary := fixture.checker.traffic(); !strings.Contains(summary, "discarded") {
		t.Errorf("discarded responses are invisible: %s", summary)
	}
}

// A reply that arrives after its candidate was probed again must still verify.
//
// Run re-probes every probable candidate each round while waiting only
// CheckTimeout for a single datagram, so on a fast path a reply routinely
// arrives after the next round has already gone out. Holding one challenge per
// candidate discards those replies: measured between two hosts 0.36 ms apart,
// every response authenticated, matched no outstanding challenge, and the
// candidate never verified despite the peer answering correctly every time.
func TestAResponseToAnEarlierRoundStillVerifies(t *testing.T) {
	fixture := newCheckerFixture(t)

	target := netip.MustParseAddrPort("198.51.100.10:51820")
	if err := fixture.engine.AddCandidate(candidate("c1", KindHost, target.String(), 100)); err != nil {
		t.Fatalf("adding: %v", err)
	}

	if err := fixture.checker.sendChallenge(context.Background(),
		Candidate{ID: "c1", Address: target}); err != nil {
		t.Fatalf("sending: %v", err)
	}
	first := onlyOutstanding(t, fixture.checker)

	// The next round goes out before the answer to the first got back.
	if err := fixture.checker.sendChallenge(context.Background(),
		Candidate{ID: "c1", Address: target}); err != nil {
		t.Fatalf("resending: %v", err)
	}

	response := EncodeResponse(first.Nonce, testNow(), target, testKey())
	if _, verified := fixture.checker.handleArrival(
		probeArrival{payload: response, source: target}); !verified {
		t.Error("a reply to the previous round was discarded; re-probing dropped its nonce")
	}
}
