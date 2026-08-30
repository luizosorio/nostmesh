package connectivity

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeTransport simulates the network, including hosts that answer when they
// should not and hosts that stay silent.
type fakeTransport struct {
	mu sync.Mutex

	// responders maps an address to the key it answers with. An address absent
	// from the map is a black hole, which is what an unreachable candidate or
	// an address an observer invented looks like.
	responders map[netip.AddrPort]SessionKey

	// sent records every probe, so a test can assert how many packets a lie
	// cost.
	sent []netip.AddrPort

	inbound chan probeArrival
	clock   func() time.Time
}

func newFakeTransport(clock func() time.Time) *fakeTransport {
	return &fakeTransport{
		responders: make(map[netip.AddrPort]SessionKey),
		inbound:    make(chan probeArrival, 64),
		clock:      clock,
	}
}

func (f *fakeTransport) Send(_ context.Context, target netip.AddrPort, payload []byte) error {
	f.mu.Lock()
	f.sent = append(f.sent, target)
	key, answers := f.responders[target]
	f.mu.Unlock()

	if !answers {
		// Silence: the packet went somewhere that does not reply.
		return nil
	}

	decoded, err := DecodeProbe(payload, target, key)
	if err != nil || decoded.IsResponse {
		// A host that cannot make sense of the probe stays silent, which is
		// what an unreachable address or a wrong-key responder looks like on a
		// real network. Send succeeded; nothing comes back.
		return nil //nolint:nilerr // silence is the modelled behaviour
	}

	// The responder answers from the address that was probed.
	response := EncodeResponse(decoded.Nonce, f.clock(), target, key)

	select {
	case f.inbound <- probeArrival{payload: response, source: target}:
	default:
	}
	return nil
}

func (f *fakeTransport) Receive(ctx context.Context) ([]byte, netip.AddrPort, error) {
	select {
	case <-ctx.Done():
		return nil, netip.AddrPort{}, ctx.Err()
	case arrival := <-f.inbound:
		return arrival.payload, arrival.source, nil
	}
}

func (f *fakeTransport) sentCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.sent)
}

func (f *fakeTransport) sentTo(target netip.AddrPort) int {
	f.mu.Lock()
	defer f.mu.Unlock()

	count := 0
	for _, addr := range f.sent {
		if addr == target {
			count++
		}
	}
	return count
}

// advancingClock moves forward a fixed step per reading.
//
// A frozen clock would never let the total timeout expire, so a session with
// nothing to probe would spin until the context deadline rather than reporting
// exhaustion. Advancing keeps the tests deterministic while exercising the
// timeout the way real time would.
type advancingClock struct {
	mu   sync.Mutex
	now  time.Time
	step time.Duration
}

func (c *advancingClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.now = c.now.Add(c.step)
	return c.now
}

// checkerFixture wires an engine, a transport and a checker onto one clock.
//
// They are parts of a single flow, and giving them separate clocks makes one
// judge the other late — which is a bug that would only ever appear in tests,
// so the fixture prevents it rather than each test having to remember.
type checkerFixture struct {
	engine    *Engine
	transport *fakeTransport
	checker   *Checker
	clock     *advancingClock
}

func newCheckerFixture(t *testing.T) *checkerFixture {
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

	transport := newFakeTransport(clock.Now)

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

	return &checkerFixture{engine: engine, transport: transport, checker: checker, clock: clock}
}

// A candidate that answers correctly is promoted and becomes the endpoint.
func TestRespondingCandidateIsVerified(t *testing.T) {
	fixture := newCheckerFixture(t)
	engine, transport := fixture.engine, fixture.transport

	target := netip.MustParseAddrPort("198.51.100.10:51820")
	transport.responders[target] = testKey()

	if err := engine.AddCandidate(candidate("c1", KindHost, target.String(), 100)); err != nil {
		t.Fatalf("adding: %v", err)
	}

	checker := fixture.checker

	result, err := checker.Run(context.Background())
	if err != nil {
		t.Fatalf("running checks: %v", err)
	}
	if result.Nominated == nil {
		t.Fatal("a responding candidate must be nominated")
	}
	if result.Nominated.Address != target {
		t.Errorf("nominated %s, want %s", result.Nominated.Address, target)
	}

	endpoint, ok := engine.Endpoint()
	if !ok || endpoint != target {
		t.Errorf("endpoint = %s (%v), want %s", endpoint, ok, target)
	}
}

// The attack this whole design exists to stop: an observer reports an address
// that will not answer, and the candidate must never become usable.
func TestSilentAddressIsNeverVerified(t *testing.T) {
	fixture := newCheckerFixture(t)
	engine := fixture.engine

	// The observer's claim. Nothing at this address replies.
	invented := "203.0.113.99:51820"
	c := candidate("srflx", KindServerReflexive, invented, 500)
	c.Source = "hostile.observer.invalid"
	if err := engine.AddCandidate(c); err != nil {
		t.Fatalf("adding: %v", err)
	}

	checker := fixture.checker

	_, err := checker.Run(context.Background())
	if !errors.Is(err, ErrNoValidPath) {
		t.Fatalf("expected ErrNoValidPath, got: %v", err)
	}

	if _, ok := engine.Endpoint(); ok {
		t.Error("an unanswered candidate must never yield an endpoint")
	}
}

// A lie must stay cheap for the victim. The number of packets sent to an
// invented address is bounded by the attempt limit, not by how long the session
// runs.
func TestObserverLieCostsBoundedTraffic(t *testing.T) {
	fixture := newCheckerFixture(t)
	engine, transport := fixture.engine, fixture.transport

	victim := netip.MustParseAddrPort("203.0.113.42:51820")
	c := candidate("srflx", KindServerReflexive, victim.String(), 500)
	c.Source = "hostile.observer.invalid"
	if err := engine.AddCandidate(c); err != nil {
		t.Fatalf("adding: %v", err)
	}

	checker := fixture.checker
	_, _ = checker.Run(context.Background())

	limits := DefaultLimits()
	if sent := transport.sentTo(victim); sent > limits.MaxAttemptsPerCandidate {
		t.Errorf("sent %d probes to the victim, limit is %d",
			sent, limits.MaxAttemptsPerCandidate)
	}
	if transport.sentTo(victim) == 0 {
		t.Error("the test did not exercise the path it claims to")
	}
}

// A host that answers with the wrong key cannot validate a candidate, however
// promptly it replies.
func TestWrongKeyResponseDoesNotVerify(t *testing.T) {
	fixture := newCheckerFixture(t)
	engine, transport := fixture.engine, fixture.transport

	target := netip.MustParseAddrPort("198.51.100.10:51820")
	// Something is at this address and answers eagerly — with a key it made up.
	transport.responders[target] = DeriveSessionKey("other-session", "x", "y")

	if err := engine.AddCandidate(candidate("c1", KindHost, target.String(), 100)); err != nil {
		t.Fatalf("adding: %v", err)
	}

	checker := fixture.checker

	_, err := checker.Run(context.Background())
	if !errors.Is(err, ErrNoValidPath) {
		t.Fatalf("expected ErrNoValidPath, got: %v", err)
	}
	if _, ok := engine.Endpoint(); ok {
		t.Error("a response with the wrong key must not verify the candidate")
	}
}

// Priority ordering means the preferred path wins when several answer.
func TestPreferredPathIsNominated(t *testing.T) {
	fixture := newCheckerFixture(t)
	engine, transport := fixture.engine, fixture.transport

	host := netip.MustParseAddrPort("192.0.2.5:51820")
	reflexive := netip.MustParseAddrPort("198.51.100.10:51820")

	transport.responders[host] = testKey()
	transport.responders[reflexive] = testKey()

	if err := engine.AddCandidate(candidate("srflx", KindServerReflexive, reflexive.String(), 500)); err != nil {
		t.Fatalf("adding: %v", err)
	}
	if err := engine.AddCandidate(candidate("host", KindHost, host.String(), 100)); err != nil {
		t.Fatalf("adding: %v", err)
	}

	checker := fixture.checker

	result, err := checker.Run(context.Background())
	if err != nil {
		t.Fatalf("running checks: %v", err)
	}
	if result.Nominated.ID != "host" {
		t.Errorf("nominated %s, want the higher-priority host candidate", result.Nominated.ID)
	}
}

// With no relay fallback, failure has to end clearly and say what was tried.
func TestExhaustionExplainsWhatFailed(t *testing.T) {
	fixture := newCheckerFixture(t)
	engine := fixture.engine

	c := candidate("srflx", KindServerReflexive, "203.0.113.99:51820", 500)
	c.Source = "stun.example.invalid:3478"
	if err := engine.AddCandidate(c); err != nil {
		t.Fatalf("adding: %v", err)
	}

	checker := fixture.checker

	_, err := checker.Run(context.Background())
	if err == nil {
		t.Fatal("checking must fail")
	}

	message := err.Error()
	for _, want := range []string{"203.0.113.99", "srflx", "stun.example.invalid"} {
		if !strings.Contains(message, want) {
			t.Errorf("the failure must mention %q so an operator can act, got: %s", want, message)
		}
	}
}

// Cancelling must stop promptly rather than run to the total timeout.
func TestCancellationStopsChecking(t *testing.T) {
	fixture := newCheckerFixture(t)
	engine := fixture.engine

	if err := engine.AddCandidate(candidate("c1", KindHost, "203.0.113.99:51820", 100)); err != nil {
		t.Fatalf("adding: %v", err)
	}

	checker := fixture.checker

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	started := time.Now()
	if _, err := checker.Run(ctx); err == nil {
		t.Error("a cancelled check must fail")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Errorf("cancellation took %s; it should be prompt", elapsed)
	}
}

// A peer's challenge is answered, which is what lets the peer verify its own
// candidate. The answer is never larger than the challenge.
func TestPeerChallengeIsAnswered(t *testing.T) {
	fixture := newCheckerFixture(t)
	transport := fixture.transport

	checker := fixture.checker

	peer := netip.MustParseAddrPort("198.51.100.50:51820")
	challenge, err := NewChallenge(testNow())
	if err != nil {
		t.Fatalf("building challenge: %v", err)
	}

	// The peer's challenge is authenticated for the address it came from.
	incoming := EncodeChallenge(challenge, peer, testKey())

	_, verified := checker.handleArrival(probeArrival{payload: incoming, source: peer})
	if verified {
		t.Error("a challenge must not be treated as a verification")
	}
	if transport.sentCount() != 1 {
		t.Errorf("%d packets sent, want 1 answer to the peer", transport.sentCount())
	}
}

// Garbage must be discarded without any trace in candidate state: recording it
// would let an attacker learn something by sending noise.
func TestGarbageLeavesNoTrace(t *testing.T) {
	fixture := newCheckerFixture(t)
	engine, transport := fixture.engine, fixture.transport

	target := "198.51.100.10:51820"
	if err := engine.AddCandidate(candidate("c1", KindHost, target, 100)); err != nil {
		t.Fatalf("adding: %v", err)
	}

	checker := fixture.checker
	before := engine.Diagnostics()[0]

	for _, garbage := range [][]byte{
		nil,
		[]byte("not a probe"),
		make([]byte, ProbeSize),
	} {
		checker.handleArrival(probeArrival{
			payload: garbage,
			source:  netip.MustParseAddrPort(target),
		})
	}

	after := engine.Diagnostics()[0]
	if after.Status != before.Status || after.Attempts != before.Attempts {
		t.Error("garbage changed candidate state")
	}
	if transport.sentCount() != 0 {
		t.Errorf("%d packets sent in response to garbage; it must be ignored", transport.sentCount())
	}
}

func TestCheckerRequiresDependencies(t *testing.T) {
	engine := newCheckerFixture(t).engine

	t.Run("no engine", func(t *testing.T) {
		if _, err := NewChecker(CheckerOptions{Transport: newFakeTransport(time.Now)}); err == nil {
			t.Error("an engine is required")
		}
	})

	t.Run("no transport", func(t *testing.T) {
		if _, err := NewChecker(CheckerOptions{Engine: engine}); err == nil {
			t.Error("a transport is required")
		}
	})
}
