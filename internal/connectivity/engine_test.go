package connectivity

import (
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"
)

func newTestEngine(t *testing.T, now *time.Time) *Engine {
	t.Helper()

	engine, err := NewEngine(EngineOptions{
		SessionID: "session-1",
		Limits:    DefaultLimits(),
		Clock:     func() time.Time { return *now },
	})
	if err != nil {
		t.Fatalf("building engine: %v", err)
	}
	return engine
}

func candidate(id string, kind Kind, address string, priority uint32) Candidate {
	return Candidate{
		ID:       id,
		Kind:     kind,
		Address:  netip.MustParseAddrPort(address),
		Priority: priority,
	}
}

// Everything starts unverified, including addresses this node found itself.
// A local address existing says nothing about whether the peer can reach it.
func TestEveryCandidateStartsUnverified(t *testing.T) {
	now := testNow()
	engine := newTestEngine(t, &now)

	for _, kind := range []Kind{KindHost, KindServerReflexive, KindStatic, KindPortMapped} {
		t.Run(string(kind), func(t *testing.T) {
			c := candidate("c-"+string(kind), kind, "198.51.100.10:51820", 100)

			// An attacker would send a candidate pre-marked valid.
			c.Status = StatusValid

			if err := engine.AddCandidate(c); err != nil {
				t.Fatalf("adding: %v", err)
			}

			for _, stored := range engine.Diagnostics() {
				if stored.ID == c.ID && stored.Status != StatusUnverified {
					t.Errorf("candidate entered as %s, must be unverified", stored.Status)
				}
			}
		})
	}
}

// The central rule: nothing unverified may configure the host.
func TestUnverifiedCandidateYieldsNoEndpoint(t *testing.T) {
	now := testNow()
	engine := newTestEngine(t, &now)

	if err := engine.AddCandidate(candidate("c1", KindHost, "198.51.100.10:51820", 100)); err != nil {
		t.Fatalf("adding: %v", err)
	}

	if _, ok := engine.Endpoint(); ok {
		t.Error("an unverified candidate must not yield an endpoint")
	}
	if engine.Nominated() != nil {
		t.Error("nothing may be nominated before verification")
	}
}

func TestVerifiedCandidateYieldsEndpoint(t *testing.T) {
	now := testNow()
	engine := newTestEngine(t, &now)

	if err := engine.AddCandidate(candidate("c1", KindHost, "198.51.100.10:51820", 100)); err != nil {
		t.Fatalf("adding: %v", err)
	}
	if err := engine.RecordAttempt("c1"); err != nil {
		t.Fatalf("recording attempt: %v", err)
	}
	if err := engine.RecordSuccess("c1", 20*time.Millisecond); err != nil {
		t.Fatalf("recording success: %v", err)
	}

	endpoint, ok := engine.Endpoint()
	if !ok {
		t.Fatal("a verified candidate must yield an endpoint")
	}
	if endpoint.String() != "198.51.100.10:51820" {
		t.Errorf("endpoint = %s, want the verified address", endpoint)
	}
}

// An observer reporting a victim's address must not turn this node into a
// source of traffic aimed at that victim. Dangerous addresses are refused
// before a candidate is even recorded.
func TestDangerousAddressesAreRefused(t *testing.T) {
	now := testNow()
	engine := newTestEngine(t, &now)

	tests := []struct {
		name    string
		address string
	}{
		{"loopback", "127.0.0.1:51820"},
		{"loopback v6", "[::1]:51820"},
		{"unspecified", "0.0.0.0:51820"},
		{"unspecified v6", "[::]:51820"},
		{"multicast", "224.0.0.1:51820"},
		{"multicast v6", "[ff02::1]:51820"},
		{"link-local", "169.254.1.1:51820"},
		{"link-local v6", "[fe80::1]:51820"},
		{"zero port", "198.51.100.10:0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := candidate("c-"+tt.name, KindServerReflexive, tt.address, 100)

			err := engine.AddCandidate(c)
			if !errors.Is(err, ErrUnsafeAddress) {
				t.Errorf("expected ErrUnsafeAddress for %s, got: %v", tt.address, err)
			}
			if engine.Count() != 0 {
				t.Error("an unsafe candidate must not be recorded at all")
			}
		})
	}
}

// A stranger flooding candidates must not be able to spend this node's
// bandwidth on their behalf.
func TestThirdPartyCandidatesAreLimitedSeparately(t *testing.T) {
	now := testNow()
	engine := newTestEngine(t, &now)
	limits := DefaultLimits()

	// Fill the third-party allowance.
	for i := range limits.MaxThirdPartyCandidates {
		c := candidate(fmt.Sprintf("srflx-%d", i), KindServerReflexive,
			fmt.Sprintf("198.51.100.%d:51820", i+1), 200)
		if err := engine.AddCandidate(c); err != nil {
			t.Fatalf("adding third-party candidate %d: %v", i, err)
		}
	}

	// One more from a third party must be refused.
	extra := candidate("srflx-extra", KindServerReflexive, "198.51.100.200:51820", 200)
	if err := engine.AddCandidate(extra); !errors.Is(err, ErrTooManyCandidates) {
		t.Errorf("expected ErrTooManyCandidates, got: %v", err)
	}

	// A locally discovered candidate is still accepted: the limit applies to
	// what strangers contribute, not to the total.
	local := candidate("host-1", KindHost, "192.0.2.5:51820", 50)
	if err := engine.AddCandidate(local); err != nil {
		t.Errorf("a local candidate must still be accepted: %v", err)
	}
}

// Bounding attempts is what keeps an observer's lie cheap for the victim
// rather than amplified.
func TestAttemptsPerCandidateAreBounded(t *testing.T) {
	now := testNow()
	engine := newTestEngine(t, &now)
	limits := DefaultLimits()

	if err := engine.AddCandidate(candidate("c1", KindServerReflexive, "198.51.100.10:51820", 100)); err != nil {
		t.Fatalf("adding: %v", err)
	}

	for i := range limits.MaxAttemptsPerCandidate {
		if len(engine.Probable()) == 0 {
			t.Fatalf("candidate stopped being probable after %d attempts", i)
		}
		if err := engine.RecordAttempt("c1"); err != nil {
			t.Fatalf("recording attempt: %v", err)
		}
		if err := engine.RecordFailure("c1", "no response"); err != nil {
			t.Fatalf("recording failure: %v", err)
		}
	}

	if len(engine.Probable()) != 0 {
		t.Errorf("candidate is still probable after %d attempts", limits.MaxAttemptsPerCandidate)
	}
}

// Priority ordering exists so the preferred path is tried first: a direct
// address before one a stranger suggested.
func TestProbingFollowsPriority(t *testing.T) {
	now := testNow()
	engine := newTestEngine(t, &now)

	added := []Candidate{
		candidate("srflx", KindServerReflexive, "198.51.100.10:51820", 300),
		candidate("host", KindHost, "192.0.2.5:51820", 100),
		candidate("static", KindStatic, "203.0.113.7:51820", 200),
	}
	for _, c := range added {
		if err := engine.AddCandidate(c); err != nil {
			t.Fatalf("adding %s: %v", c.ID, err)
		}
	}

	probable := engine.Probable()
	want := []string{"host", "static", "srflx"}

	if len(probable) != len(want) {
		t.Fatalf("got %d probable candidates, want %d", len(probable), len(want))
	}
	for i, c := range probable {
		if c.ID != want[i] {
			t.Errorf("position %d is %s, want %s", i, c.ID, want[i])
		}
	}
}

// Two candidates that would behave identically are probed once: probing both
// spends packets to learn one thing.
func TestSharedFoundationIsProbedOnce(t *testing.T) {
	now := testNow()
	engine := newTestEngine(t, &now)

	base := netip.MustParseAddrPort("192.0.2.5:51820")

	first := candidate("srflx-a", KindServerReflexive, "198.51.100.10:51820", 100)
	first.Related = base
	second := candidate("srflx-b", KindServerReflexive, "198.51.100.11:51820", 110)
	second.Related = base

	for _, c := range []Candidate{first, second} {
		if err := engine.AddCandidate(c); err != nil {
			t.Fatalf("adding %s: %v", c.ID, err)
		}
	}

	if got := len(engine.Probable()); got != 1 {
		t.Errorf("%d candidates probable, want 1 for a shared foundation", got)
	}
}

// A repeated candidate is not an error, since relays duplicate. Its address
// changing under the same id is.
func TestDuplicateCandidateIsIdempotent(t *testing.T) {
	now := testNow()
	engine := newTestEngine(t, &now)

	c := candidate("c1", KindHost, "198.51.100.10:51820", 100)

	for range 3 {
		if err := engine.AddCandidate(c); err != nil {
			t.Fatalf("adding: %v", err)
		}
	}
	if engine.Count() != 1 {
		t.Errorf("%d candidates recorded, want 1", engine.Count())
	}

	moved := candidate("c1", KindHost, "203.0.113.9:51820", 100)
	if err := engine.AddCandidate(moved); err == nil {
		t.Error("the same id pointing at a different address must be refused")
	}
}

// There is no data relay yet, so a session with nothing left to try must fail
// clearly rather than loop.
func TestExhaustionIsDetected(t *testing.T) {
	now := testNow()
	engine := newTestEngine(t, &now)
	limits := DefaultLimits()

	if err := engine.AddCandidate(candidate("c1", KindHost, "198.51.100.10:51820", 100)); err != nil {
		t.Fatalf("adding: %v", err)
	}

	if engine.IsExhausted() {
		t.Fatal("a fresh candidate must not count as exhausted")
	}

	for range limits.MaxAttemptsPerCandidate {
		if err := engine.RecordAttempt("c1"); err != nil {
			t.Fatalf("recording attempt: %v", err)
		}
		if err := engine.RecordFailure("c1", "no response"); err != nil {
			t.Fatalf("recording failure: %v", err)
		}
	}

	if !engine.IsExhausted() {
		t.Error("a session with nothing probable must report exhaustion")
	}
	if _, ok := engine.Endpoint(); ok {
		t.Error("an exhausted session must not yield an endpoint")
	}
}

// Timing out must release the session rather than leave it pending.
func TestTotalTimeoutExhaustsTheSession(t *testing.T) {
	now := testNow()
	engine := newTestEngine(t, &now)

	if err := engine.AddCandidate(candidate("c1", KindHost, "198.51.100.10:51820", 100)); err != nil {
		t.Fatalf("adding: %v", err)
	}

	now = now.Add(DefaultLimits().TotalTimeout + time.Second)

	if !engine.IsExhausted() {
		t.Error("a session past its total timeout must be exhausted")
	}
}

// "Why did this not connect" is the question an operator asks, so failures
// have to be visible with their reasons.
func TestDiagnosticsExplainEveryCandidate(t *testing.T) {
	now := testNow()
	engine := newTestEngine(t, &now)

	if err := engine.AddCandidate(candidate("good", KindHost, "192.0.2.5:51820", 100)); err != nil {
		t.Fatalf("adding: %v", err)
	}
	bad := candidate("bad", KindServerReflexive, "198.51.100.10:51820", 200)
	bad.Source = "wss://observer.invalid"
	if err := engine.AddCandidate(bad); err != nil {
		t.Fatalf("adding: %v", err)
	}

	if err := engine.RecordAttempt("good"); err != nil {
		t.Fatalf("recording attempt: %v", err)
	}
	if err := engine.RecordSuccess("good", 15*time.Millisecond); err != nil {
		t.Fatalf("recording success: %v", err)
	}

	for range DefaultLimits().MaxAttemptsPerCandidate {
		if err := engine.RecordAttempt("bad"); err != nil {
			t.Fatalf("recording attempt: %v", err)
		}
	}
	if err := engine.RecordFailure("bad", "no response within timeout"); err != nil {
		t.Fatalf("recording failure: %v", err)
	}

	diagnostics := engine.Diagnostics()
	if len(diagnostics) != 2 {
		t.Fatalf("%d diagnostics, want 2", len(diagnostics))
	}

	var sawFailure bool
	for _, entry := range diagnostics {
		if entry.ID == "bad" {
			sawFailure = true
			if entry.Status != StatusFailed {
				t.Errorf("failed candidate has status %s", entry.Status)
			}
			if entry.FailureReason == "" {
				t.Error("a failed candidate must carry a reason")
			}
			if entry.Source == "" {
				t.Error("a third-party candidate must record who suggested it")
			}
		}
	}
	if !sawFailure {
		t.Error("diagnostics must include failed candidates")
	}
}

// Claims and measurements stay separate: what an observer said is recorded as
// its claim, and only the local probe decides.
func TestObserverClaimDoesNotImplyValidity(t *testing.T) {
	now := testNow()
	engine := newTestEngine(t, &now)

	// Two observers report the same address. Agreement is not evidence: a
	// symmetric NAT gives a different mapping per destination, so agreement
	// means they were reached the same way.
	for i, id := range []string{"obs-a", "obs-b"} {
		c := candidate(id, KindServerReflexive, "198.51.100.10:51820", uint32(200+i))
		c.Source = fmt.Sprintf("observer-%d", i)
		if err := engine.AddCandidate(c); err != nil {
			t.Fatalf("adding %s: %v", id, err)
		}
	}

	if _, ok := engine.Endpoint(); ok {
		t.Error("agreement between observers must not produce an endpoint")
	}
	for _, entry := range engine.Diagnostics() {
		if entry.Status.Permits() {
			t.Errorf("candidate %s is permitted without a probe", entry.ID)
		}
	}
}

func TestEngineRequiresSessionID(t *testing.T) {
	if _, err := NewEngine(EngineOptions{}); err == nil {
		t.Error("an engine without a session id must be refused")
	}
}
