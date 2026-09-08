package e2e

import (
	"context"
	"sync"
	"testing"
	"time"
)

// The control plane going away and coming back.
//
// M2.5 asks for partition and reconnection, and the reason is not that relays
// fail often — it is that the control plane failing must not change what a node
// is allowed to do. A partition that widened access, or that left a node holding
// something it could no longer be told to give up, would be a security failure
// rather than an availability one.

// A total partition stops new sessions and does not widen anything.
//
// Every relay down is the worst the control plane can do short of lying. The
// property is that a node which cannot reach anyone gets nothing it did not
// already have: no session, no route, no authorization it lacked before.
func TestATotalPartitionGrantsNothing(t *testing.T) {
	harness := meshHarness(t, 2)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Every relay out of service: the nodes are up, the network between them is
	// not.
	for i := range harness.Relays {
		harness.SetRelayDown(i, true)
	}

	result := harness.Connect(ctx)
	if result.Err == nil {
		t.Fatal("a session was established with every relay down")
	}

	// The failure is the absence of a session, not a session with fewer checks.
	if result.Established {
		t.Error("a partition produced an established session")
	}
}

// A partition that lifts lets the same nodes connect.
//
// The other half: refusing during a partition is only correct if the node
// recovers afterwards. A node that stayed broken would have turned an outage
// into a permanent failure, which is worse than the outage.
func TestSessionsResumeAfterAPartitionLifts(t *testing.T) {
	harness := meshHarness(t, 2)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	for i := range harness.Relays {
		harness.SetRelayDown(i, true)
	}
	if result := harness.Connect(ctx); result.Err == nil {
		t.Fatal("a session was established during the partition, so this proves nothing")
	}

	for i := range harness.Relays {
		harness.SetRelayDown(i, false)
	}

	result := harness.Connect(ctx)
	if result.Err != nil {
		t.Fatalf("the nodes did not recover after the partition lifted: %v", result.Err)
	}
	if !result.Established {
		t.Error("the session did not establish after recovery")
	}
}

// One relay surviving is enough.
//
// A partial partition is the common case, and the reason a node is configured
// with several relays at all. If losing all but one stopped a session, the
// redundancy would be decorative.
func TestOneSurvivingRelayCarriesTheSession(t *testing.T) {
	harness := meshHarness(t, 2)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// All but the last.
	for i := 0; i < len(harness.Relays)-1; i++ {
		harness.SetRelayDown(i, true)
	}

	result := harness.Connect(ctx)
	if result.Err != nil {
		t.Fatalf("a session failed with one relay still up: %v", result.Err)
	}
	if !result.Established {
		t.Error("the session did not establish on the surviving relay")
	}
}

// Churn: nodes connecting and disconnecting while others work.
//
// The M2.5 scenario in miniature. What it guards is isolation — a pair
// establishing and tearing down repeatedly must not disturb a pair that is
// simply working, and a mesh where it did would fail unpredictably under
// ordinary use.
func TestChurnDoesNotDisturbASteadyPair(t *testing.T) {
	const rounds = 5

	harness := meshHarness(t, 4)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// The steady pair connects once and is expected to be unaffected.
	steady := harness.ConnectPair(ctx, harness.Nodes[0], harness.Nodes[1])
	if steady.Err != nil {
		t.Fatalf("the steady pair could not connect: %v", steady.Err)
	}

	// The churning pair goes up and down beside it.
	for round := range rounds {
		result := harness.ConnectPair(ctx, harness.Nodes[2], harness.Nodes[3])
		if result.Err != nil {
			t.Fatalf("churn round %d failed: %v", round, result.Err)
		}
	}

	// The steady pair connects again, which it could not do if churn had taken
	// its port, its interface or its relay subscription.
	again := harness.ConnectPair(ctx, harness.Nodes[0], harness.Nodes[1])
	if again.Err != nil {
		t.Errorf("the steady pair was disturbed by churn beside it: %v", again.Err)
	}
}

// Churn under partition: relays failing while pairs come and go.
//
// The two failure modes together, which is how they arrive in practice. Nothing
// here asserts that every session succeeds — under a partition some must not.
// What it asserts is that the mesh does not deadlock, leak, or leave a node
// unable to connect once the network returns.
func TestChurnDuringAPartitionRecovers(t *testing.T) {
	harness := meshHarness(t, 4)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	var wg sync.WaitGroup

	// Relays flapping while sessions are attempted.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for round := range 4 {
			down := round%2 == 0
			for i := range harness.Relays {
				harness.SetRelayDown(i, down)
			}
			time.Sleep(50 * time.Millisecond)
		}
		// Left up, so recovery is possible.
		for i := range harness.Relays {
			harness.SetRelayDown(i, false)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 4 {
			// Failures are expected here and deliberately not asserted: during
			// a partition a session must fail, and requiring success would be
			// requiring the partition not to work.
			_ = harness.ConnectPair(ctx, harness.Nodes[2], harness.Nodes[3])
		}
	}()

	wg.Wait()

	// Everything settled: a pair that never ran during the churn connects.
	result := harness.ConnectPair(ctx, harness.Nodes[0], harness.Nodes[1])
	if result.Err != nil {
		t.Errorf("the mesh did not recover after churn under partition: %v", result.Err)
	}
}
