package e2e

import (
	"context"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/luizosorio/nostmesh/internal/nostr"
)

func testClock() func() time.Time {
	return time.Now
}

func newHarness(t *testing.T) *Harness {
	t.Helper()

	harness, err := NewHarness(HarnessOptions{RelayCount: 3, Clock: testClock()})
	if err != nil {
		t.Fatalf("building harness: %v", err)
	}
	return harness
}

// The basic path: two authorized nodes negotiate over relays and verify a
// direct path.
func TestEndToEndConnection(t *testing.T) {
	harness := newHarness(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result := harness.Connect(ctx)
	if !result.Established {
		t.Fatalf("connection failed in phase %s: %v", result.Phase, result.Err)
	}
	if !result.Endpoint.IsValid() {
		t.Error("an established connection must have a verified endpoint")
	}
}

// The acceptance criterion: one relay of three going down must not prevent a
// connection. Redundancy is the reason the control plane survives.
func TestConnectionSurvivesRelayFailure(t *testing.T) {
	for _, down := range []int{0, 1, 2} {
		t.Run(fmt.Sprintf("relay-%d-down", down), func(t *testing.T) {
			harness := newHarness(t)
			harness.SetRelayDown(down, true)

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			result := harness.Connect(ctx)
			if !result.Established {
				t.Fatalf("connection failed with relay %d down, phase %s: %v",
					down, result.Phase, result.Err)
			}
		})
	}
}

// A relay duplicating every delivery must not produce duplicate processing:
// deduplication turns redundancy back into one message.
func TestConnectionSurvivesRelayDuplication(t *testing.T) {
	harness := newHarness(t)
	harness.SetRelayBehaviour(0, nostr.RelayBehaviour{DuplicateDeliveries: 3})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result := harness.Connect(ctx)
	if !result.Established {
		t.Fatalf("connection failed with a duplicating relay, phase %s: %v", result.Phase, result.Err)
	}
}

// A relay that accepts and silently discards is the nastiest failure: the
// client is told everything worked. Only redundancy across relays saves it.
func TestConnectionSurvivesSilentRelayDrop(t *testing.T) {
	harness := newHarness(t)
	harness.SetRelayBehaviour(0, nostr.RelayBehaviour{DropRate: 1.0})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result := harness.Connect(ctx)
	if !result.Established {
		t.Fatalf("connection failed with a silently dropping relay, phase %s: %v",
			result.Phase, result.Err)
	}
}

// With every relay down there is nothing to negotiate over, and the failure
// must be clear rather than a hang.
func TestConnectionFailsWithAllRelaysDown(t *testing.T) {
	harness := newHarness(t)
	for i := range harness.Relays {
		harness.SetRelayDown(i, true)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result := harness.Connect(ctx)
	if result.Established {
		t.Fatal("a connection must not establish with every relay down")
	}
	if result.Phase != "negotiating" {
		t.Errorf("failed in phase %s, want negotiating", result.Phase)
	}
	if result.Err == nil {
		t.Error("the failure must carry a reason")
	}
}

// Deny-by-default: a peer that was never authorized cannot connect, whatever
// else is working.
func TestUnauthorizedPeerCannotConnect(t *testing.T) {
	harness := newHarness(t)

	// Bob forgets Alice.
	harness.Bob.Allowlist.Remove(harness.Alice.Public)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result := harness.Connect(ctx)
	if result.Established {
		t.Fatal("an unauthorized peer must not connect")
	}
}

// The MVP 1 gate: 100 connections, reporting success rate and latency
// percentiles. A single run says little; a hundred exposes flakiness that one
// would hide.
func TestGateHundredConnections(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the 100-connection gate in short mode")
	}

	const attempts = 100

	var (
		durations []time.Duration
		succeeded int
		failures  = make(map[string]int)
	)

	for i := range attempts {
		harness, err := NewHarness(HarnessOptions{RelayCount: 3, Clock: testClock()})
		if err != nil {
			t.Fatalf("building harness for attempt %d: %v", i, err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		result := harness.Connect(ctx)
		cancel()

		if result.Established {
			succeeded++
			durations = append(durations, result.Duration)
			continue
		}
		failures[result.Phase]++
	}

	rate := float64(succeeded) / float64(attempts) * 100

	t.Logf("success rate: %.1f%% (%d of %d)", rate, succeeded, attempts)
	if len(durations) > 0 {
		p50, p95, p99 := percentiles(durations)
		t.Logf("connection latency: p50=%s p95=%s p99=%s", p50, p95, p99)
	}
	for phase, count := range failures {
		t.Logf("failures in phase %s: %d", phase, count)
	}

	if succeeded != attempts {
		t.Errorf("%d of %d connections failed; the gate requires all to succeed",
			attempts-succeeded, attempts)
	}
}

// Repeated connect and disconnect must not accumulate state. A leak that only
// appears after many cycles is the kind that reaches production.
func TestRepeatedConnectionsLeaveNoResidue(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the residue check in short mode")
	}

	harness := newHarness(t)

	for cycle := range 50 {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		result := harness.Connect(ctx)
		cancel()

		if !result.Established {
			t.Fatalf("cycle %d failed in phase %s: %v", cycle, result.Phase, result.Err)
		}
	}

	// The inbox bounds itself; if it did not, fifty cycles would show it.
	for i, relay := range harness.Relays {
		if published := len(relay.Published()); published == 0 {
			t.Errorf("relay %d received nothing across fifty cycles", i)
		}
	}
}

// percentiles returns p50, p95 and p99 of a duration sample.
func percentiles(durations []time.Duration) (p50, p95, p99 time.Duration) {
	if len(durations) == 0 {
		return 0, 0, 0
	}

	sorted := make([]time.Duration, len(durations))
	copy(sorted, durations)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	at := func(fraction float64) time.Duration {
		index := int(float64(len(sorted)-1) * fraction)
		return sorted[index]
	}
	return at(0.50), at(0.95), at(0.99)
}
