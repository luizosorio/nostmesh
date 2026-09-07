package e2e

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/luizosorio/nostmesh/internal/policy"
)

// meshHarness builds a testbed with the given number of nodes.
func meshHarness(t *testing.T, nodes int) *Harness {
	t.Helper()

	harness, err := NewHarness(HarnessOptions{RelayCount: 3, Clock: testClock(), NodeCount: nodes})
	if err != nil {
		t.Fatalf("building a %d-node harness: %v", nodes, err)
	}
	return harness
}

// Several pairs establish at once, and each one succeeds.
//
// This is the M2.2 gate, and it is what the hundred-connection test does not
// cover: that one runs a hundred sessions between the same pair, one after
// another. Sessions running *at the same time* between *different* pairs is a
// different property, and it is the one the mesh needs.
func TestAMeshOfSimultaneousSessions(t *testing.T) {
	const nodes = 6

	harness := meshHarness(t, nodes)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Pairs that share no node, so every session is independent: nothing here
	// succeeds because it waited for another to finish.
	type pair struct{ from, to int }
	pairs := []pair{{0, 1}, {2, 3}, {4, 5}}

	var wg sync.WaitGroup
	results := make([]HandshakeResult, len(pairs))

	for i, p := range pairs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = harness.ConnectPair(ctx, harness.Nodes[p.from], harness.Nodes[p.to])
		}()
	}
	wg.Wait()

	for i, result := range results {
		if !result.Established {
			t.Errorf("pair %d (%s → %s) failed in phase %s: %v",
				i, harness.Nodes[pairs[i].from].Name, harness.Nodes[pairs[i].to].Name,
				result.Phase, result.Err)
		}
	}
}

// Every node can reach every other, one pair at a time.
//
// A full mesh of sessions is not required — the roadmap says so — but a pair
// that cannot connect because of who else exists would be a defect, and this is
// what would catch it.
func TestEveryPairCanConnect(t *testing.T) {
	const nodes = 4

	harness := meshHarness(t, nodes)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	for i := range nodes {
		for j := range nodes {
			if i == j {
				continue
			}

			t.Run(fmt.Sprintf("%s-to-%s", harness.Nodes[i].Name, harness.Nodes[j].Name), func(t *testing.T) {
				result := harness.ConnectPair(ctx, harness.Nodes[i], harness.Nodes[j])
				if !result.Established {
					t.Errorf("failed in phase %s: %v", result.Phase, result.Err)
				}
			})
		}
	}
}

// One pair failing does not stop the others.
//
// Independent failure is what the roadmap asks for, and what sharing a session
// table put at risk. A node that is not authorized is the cheapest way to make
// exactly one pair fail while the rest are untouched.
func TestOnePairFailingLeavesTheOthersAlone(t *testing.T) {
	harness := meshHarness(t, 4)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Node 1 stops authorizing node 0, so that pair must fail.
	harness.Nodes[1].Allowlist = policy.NewAllowlist()

	failing := harness.ConnectPair(ctx, harness.Nodes[0], harness.Nodes[1])
	if failing.Established {
		t.Fatal("a session with an unauthorized peer was established")
	}

	// The untouched pair must be unaffected.
	working := harness.ConnectPair(ctx, harness.Nodes[2], harness.Nodes[3])
	if !working.Established {
		t.Errorf("an unrelated pair failed after another pair's failure: %s: %v",
			working.Phase, working.Err)
	}
}

// A mesh run leaves no goroutines behind.
//
// The M2.2 prompt asks for this by name. It is worth measuring rather than
// assuming: every session opens relay subscriptions and a transport, and a
// supervisor that forgot one would leak a goroutine per attempt — invisible in a
// test that only asks whether the session came up.
func TestAMeshRunLeaksNoGoroutines(t *testing.T) {
	// A baseline taken after a warm-up run, so that one-time setup inside the
	// packages under test is not counted as a leak.
	warmup := meshHarness(t, 2)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	_ = warmup.Connect(ctx)

	settle(t)
	before := runtime.NumGoroutine()

	harness := meshHarness(t, 6)
	for _, p := range [][2]int{{0, 1}, {2, 3}, {4, 5}} {
		if result := harness.ConnectPair(ctx, harness.Nodes[p[0]], harness.Nodes[p[1]]); !result.Established {
			t.Fatalf("pair %v failed: %s: %v", p, result.Phase, result.Err)
		}
	}

	settle(t)
	after := runtime.NumGoroutine()

	// The allowance is one, not a handful.
	//
	// It was four, and three deliberately leaked goroutines fit inside it — the
	// guard passed while the thing it names was happening. An allowance wide
	// enough to hide a leak per session is not measuring leaks; it is measuring
	// whether the number moved a lot.
	const allowance = 1
	if after > before+allowance {
		t.Errorf("goroutines went from %d to %d across three sessions; something is not being released",
			before, after)
	}
}

// settle waits for goroutines that are shutting down to finish.
//
// Counting immediately would race a teardown that is correct but not yet
// complete, which is a flaky test rather than a leak.
func settle(t *testing.T) {
	t.Helper()

	runtime.GC()
	for range 20 {
		time.Sleep(25 * time.Millisecond)
		runtime.GC()
	}
}
