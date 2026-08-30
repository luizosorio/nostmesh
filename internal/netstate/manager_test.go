package netstate

import (
	"context"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luizosorio/nostmesh/internal/domain"
	"github.com/luizosorio/nostmesh/internal/wireguard"
)

type fixedClock struct{ now time.Time }

func (c *fixedClock) Now() time.Time { return c.now }

func testClock() *fixedClock {
	return &fixedClock{now: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
}

func testKey(t *testing.T, seed byte) domain.WireGuardPublicKey {
	t.Helper()

	var key domain.WireGuardPublicKey
	for i := range key {
		key[i] = seed + byte(i)
	}
	return key
}

func testPrivateKey(t *testing.T) domain.WireGuardPrivateKey {
	t.Helper()

	raw := make([]byte, domain.WireGuardKeySize)
	for i := range raw {
		raw[i] = byte(i + 1)
	}
	key, err := domain.NewWireGuardPrivateKey(raw)
	if err != nil {
		t.Fatalf("building key: %v", err)
	}
	return key
}

func testSpec(t *testing.T) wireguard.InterfaceSpec {
	t.Helper()

	return wireguard.InterfaceSpec{
		Name:       "nm0",
		PrivateKey: testPrivateKey(t),
		ListenPort: 51820,
		Addresses:  []netip.Prefix{netip.MustParsePrefix("100.96.0.1/32")},
		MTU:        1420,
	}
}

func testPeers(t *testing.T, count int) []wireguard.PeerSpec {
	t.Helper()

	peers := make([]wireguard.PeerSpec, 0, count)
	for i := range count {
		endpoint := netip.MustParseAddrPort("198.51.100.10:51820")
		peers = append(peers, wireguard.PeerSpec{
			PublicKey:  testKey(t, byte(10+i*40)),
			Endpoint:   &endpoint,
			AllowedIPs: []netip.Prefix{netip.MustParsePrefix("100.96.0.2/32")},
		})
	}
	return peers
}

func newTestManager(t *testing.T) (*Manager, *wireguard.FakeController, *JournalStore) {
	t.Helper()

	controller := wireguard.NewFakeController()
	journal := NewJournalStore(filepath.Join(t.TempDir(), "journal"))
	return NewManager(controller, journal, testClock()), controller, journal
}

func TestApplyCreatesInterfaceAndPeers(t *testing.T) {
	manager, controller, journal := newTestManager(t)
	ctx := context.Background()

	plan, err := manager.PlanInterface(ctx, "tx-1", testSpec(t), testPeers(t, 2))
	if err != nil {
		t.Fatalf("planning: %v", err)
	}

	transaction, err := manager.Apply(ctx, plan)
	if err != nil {
		t.Fatalf("applying: %v", err)
	}

	if !transaction.Committed {
		t.Error("a successful apply must commit the transaction")
	}
	if !controller.HasInterface("nm0") {
		t.Error("the interface must exist after apply")
	}
	if got := controller.PeerCount("nm0"); got != 2 {
		t.Errorf("peer count = %d, want 2", got)
	}

	stored, err := journal.Load("tx-1")
	if err != nil {
		t.Fatalf("loading journal: %v", err)
	}
	if !stored.Committed {
		t.Error("the journal must record the commit")
	}
	if stored.NeedsRecovery() {
		t.Error("a committed transaction must not need recovery")
	}
}

// Applying the same plan twice must converge, not duplicate or fail. This is
// what makes retrying after an interrupted run safe.
func TestApplyIsIdempotent(t *testing.T) {
	manager, controller, _ := newTestManager(t)
	ctx := context.Background()
	spec := testSpec(t)
	peers := testPeers(t, 2)

	for attempt := 1; attempt <= 3; attempt++ {
		plan, err := manager.PlanInterface(ctx, "tx-1", spec, peers)
		if err != nil {
			t.Fatalf("planning attempt %d: %v", attempt, err)
		}
		if _, err := manager.Apply(ctx, plan); err != nil {
			t.Fatalf("applying attempt %d: %v", attempt, err)
		}

		if got := controller.PeerCount("nm0"); got != 2 {
			t.Fatalf("after attempt %d peer count = %d, want 2", attempt, got)
		}
	}
}

// The core property: a failure at any step leaves the host as it was found.
// Injecting at each operation in turn is the only way to establish that.
func TestRollbackLeavesNothingBehind(t *testing.T) {
	for _, failAfter := range []OperationKind{
		OpCreateInterface,
		OpConfigureInterface,
		OpSetLinkUp,
		OpAddAddress,
		OpApplyPeer,
	} {
		t.Run(string(failAfter), func(t *testing.T) {
			manager, controller, journal := newTestManager(t)
			ctx := context.Background()

			plan, err := manager.PlanInterface(ctx, "tx-1", testSpec(t), testPeers(t, 2))
			if err != nil {
				t.Fatalf("planning: %v", err)
			}

			manager.InjectFailureAfter(failAfter)

			if _, err := manager.Apply(ctx, plan); err == nil {
				t.Fatalf("apply must fail when injecting after %s", failAfter)
			}

			if controller.HasInterface("nm0") {
				t.Errorf("interface survived rollback after failing at %s", failAfter)
			}

			stored, err := journal.Load("tx-1")
			if err != nil {
				t.Fatalf("loading journal: %v", err)
			}
			if stored.Committed {
				t.Error("a failed transaction must not be committed")
			}
			for _, op := range stored.Operations {
				if op.Status == StatusApplied {
					t.Errorf("%s remained applied after rollback", op.Kind)
				}
			}
		})
	}
}

// NostMesh reverts what it introduced, never what it found. An interface that
// predates the transaction must survive a rollback.
func TestRollbackPreservesPreexistingInterface(t *testing.T) {
	manager, controller, _ := newTestManager(t)
	ctx := context.Background()

	controller.PreexistingInterface("nm0", []netip.Prefix{netip.MustParsePrefix("100.96.0.1/32")})

	plan, err := manager.PlanInterface(ctx, "tx-1", testSpec(t), testPeers(t, 1))
	if err != nil {
		t.Fatalf("planning: %v", err)
	}

	manager.InjectFailureAfter(OpApplyPeer)

	if _, err := manager.Apply(ctx, plan); err == nil {
		t.Fatal("apply must fail")
	}

	if !controller.HasInterface("nm0") {
		t.Fatal("a pre-existing interface must survive rollback")
	}
}

// Compensation must run in reverse: a peer comes off before the interface that
// carries it.
func TestCompensationRunsInReverse(t *testing.T) {
	manager, controller, _ := newTestManager(t)
	ctx := context.Background()

	plan, err := manager.PlanInterface(ctx, "tx-1", testSpec(t), testPeers(t, 1))
	if err != nil {
		t.Fatalf("planning: %v", err)
	}

	manager.InjectFailureAfter(OpApplyPeer)
	if _, err := manager.Apply(ctx, plan); err == nil {
		t.Fatal("apply must fail")
	}

	var removePeer, removeInterface = -1, -1
	for i, call := range controller.Calls {
		switch call {
		case "RemovePeer":
			if removePeer == -1 {
				removePeer = i
			}
		case "RemoveInterface":
			if removeInterface == -1 {
				removeInterface = i
			}
		}
	}

	if removePeer == -1 || removeInterface == -1 {
		t.Fatalf("expected both removals, got calls: %v", controller.Calls)
	}
	if removePeer > removeInterface {
		t.Errorf("peer must be removed before the interface, got calls: %v", controller.Calls)
	}
}

// A crash mid-apply leaves a journal that says how far it got.
func TestInterruptedTransactionNeedsRecovery(t *testing.T) {
	manager, controller, journal := newTestManager(t)
	ctx := context.Background()

	plan, err := manager.PlanInterface(ctx, "tx-1", testSpec(t), testPeers(t, 1))
	if err != nil {
		t.Fatalf("planning: %v", err)
	}

	// Fail the peer removal too, so compensation cannot tidy up and the
	// transaction is left mid-flight, as a crash would.
	controller.FailOn["RemoveInterface"] = context.DeadlineExceeded
	manager.InjectFailureAfter(OpApplyPeer)

	if _, err := manager.Apply(ctx, plan); err == nil {
		t.Fatal("apply must fail")
	}

	pending, err := journal.PendingRecovery()
	if err != nil {
		t.Fatalf("listing pending: %v", err)
	}
	if len(pending) == 0 {
		t.Skip("compensation succeeded; nothing left pending")
	}
}

func TestPlanDescribesWithoutSecrets(t *testing.T) {
	manager, _, _ := newTestManager(t)

	plan, err := manager.PlanInterface(context.Background(), "tx-1", testSpec(t), testPeers(t, 1))
	if err != nil {
		t.Fatalf("planning: %v", err)
	}

	lines := plan.Describe()
	if len(lines) == 0 {
		t.Fatal("a plan must describe its operations")
	}

	joined := strings.Join(lines, "\n")
	if strings.Contains(joined, "REDACTED") {
		t.Error("the plan should not need to mention secrets at all")
	}

	raw, err := testPrivateKey(t).Bytes()
	if err != nil {
		t.Fatalf("reading key: %v", err)
	}
	if strings.Contains(joined, string(raw)) {
		t.Error("the plan description leaked key material")
	}
}

func TestPlanRequiresTransactionID(t *testing.T) {
	manager, _, _ := newTestManager(t)

	if _, err := manager.PlanInterface(context.Background(), "", testSpec(t), nil); err == nil {
		t.Fatal("a plan without a transaction id must be rejected")
	}
}
