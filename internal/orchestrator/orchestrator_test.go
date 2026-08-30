package orchestrator

import (
	"context"
	"encoding/base64"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/luizosorio/nostmesh/internal/config"
	"github.com/luizosorio/nostmesh/internal/domain"
	"github.com/luizosorio/nostmesh/internal/netstate"
	"github.com/luizosorio/nostmesh/internal/wireguard"
)

type fixedClock struct{ now time.Time }

func (c *fixedClock) Now() time.Time { return c.now }

// deterministicKey supplies a fixed tunnel key so tests do not depend on
// randomness.
func deterministicKey() (domain.WireGuardPublicKey, domain.WireGuardPrivateKey, error) {
	raw := make([]byte, domain.WireGuardKeySize)
	for i := range raw {
		raw[i] = byte(i + 1)
	}

	private, err := domain.NewWireGuardPrivateKey(raw)
	if err != nil {
		return domain.WireGuardPublicKey{}, domain.WireGuardPrivateKey{}, err
	}

	var public domain.WireGuardPublicKey
	for i := range public {
		public[i] = byte(i + 200)
	}
	return public, private, nil
}

// testPeerKey builds a WireGuard public key from a seed; see the note in the
// config package tests on why these are derived rather than written literally.
func testPeerKey(seed byte) string {
	raw := make([]byte, domain.WireGuardKeySize)
	for i := range raw {
		raw[i] = seed + byte(i)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func testConfig() config.Config {
	cfg := config.Default()
	cfg.Node = config.Node{
		Name:           "lab",
		StateDir:       "/var/lib/nostmesh",
		OverlayAddress: "100.96.0.1/32",
		ListenPort:     51820,
		MTU:            1420,
	}
	cfg.Peers = []config.Peer{{
		Name:           "lab-b",
		PublicKey:      testPeerKey(90),
		Endpoint:       "198.51.100.10:51820",
		OverlayAddress: "100.96.0.2/32",
		AllowedIPs:     []string{"100.96.0.2/32"},
		KeepAlive:      25 * time.Second,
	}}
	return cfg
}

func newTestOrchestrator(t *testing.T) (*Orchestrator, *wireguard.FakeController, *netstate.JournalStore) {
	t.Helper()

	controller := wireguard.NewFakeController()
	journal := netstate.NewJournalStore(filepath.Join(t.TempDir(), "journal"))

	orchestrator, err := New(Options{
		Controller:  controller,
		Journal:     journal,
		Clock:       &fixedClock{now: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)},
		GenerateKey: deterministicKey,
	})
	if err != nil {
		t.Fatalf("building orchestrator: %v", err)
	}
	return orchestrator, controller, journal
}

func TestUpConfiguresInterfaceAndPeers(t *testing.T) {
	orchestrator, controller, _ := newTestOrchestrator(t)
	ctx := context.Background()

	transaction, err := orchestrator.Up(ctx, testConfig())
	if err != nil {
		t.Fatalf("bringing tunnel up: %v", err)
	}

	if !transaction.Committed {
		t.Error("a successful Up must commit the transaction")
	}
	if !controller.HasInterface("nm0") {
		t.Error("the interface must exist after Up")
	}
	if got := controller.PeerCount("nm0"); got != 1 {
		t.Errorf("peer count = %d, want 1", got)
	}
}

// Status must distinguish what is configured from what the host carries. A peer
// in the file but not in the kernel is exactly what an operator needs to see.
func TestStatusDistinguishesDesiredFromObserved(t *testing.T) {
	orchestrator, _, _ := newTestOrchestrator(t)
	ctx := context.Background()
	cfg := testConfig()

	before, err := orchestrator.Status(ctx, cfg)
	if err != nil {
		t.Fatalf("reading status: %v", err)
	}
	if before.InterfaceUp {
		t.Error("the interface must not be reported up before Up runs")
	}
	if len(before.Configured) != 1 {
		t.Errorf("configured peers = %d, want 1", len(before.Configured))
	}
	if before.Observed != nil {
		t.Error("nothing should be observed before Up runs")
	}

	if _, err := orchestrator.Up(ctx, cfg); err != nil {
		t.Fatalf("bringing tunnel up: %v", err)
	}

	after, err := orchestrator.Status(ctx, cfg)
	if err != nil {
		t.Fatalf("reading status: %v", err)
	}
	if !after.InterfaceUp {
		t.Error("the interface must be reported up after Up")
	}
	if after.Observed == nil {
		t.Fatal("observed state must be present after Up")
	}
	if len(after.Observed.Peers) != 1 {
		t.Errorf("observed peers = %d, want 1", len(after.Observed.Peers))
	}
}

func TestDownRemovesWhatWasApplied(t *testing.T) {
	orchestrator, controller, _ := newTestOrchestrator(t)
	ctx := context.Background()

	if _, err := orchestrator.Up(ctx, testConfig()); err != nil {
		t.Fatalf("bringing tunnel up: %v", err)
	}

	result, err := orchestrator.Down(ctx)
	if err != nil {
		t.Fatalf("bringing tunnel down: %v", err)
	}

	if controller.HasInterface("nm0") {
		t.Error("the interface must be gone after Down")
	}
	if len(result.Removed) != 1 || result.Removed[0] != "nm0" {
		t.Errorf("Down must report what it removed, got %v", result.Removed)
	}
}

// Down on a host with nothing up must succeed quietly rather than error.
func TestDownWithNothingUp(t *testing.T) {
	orchestrator, _, _ := newTestOrchestrator(t)

	result, err := orchestrator.Down(context.Background())
	if err != nil {
		t.Fatalf("Down with nothing up must succeed: %v", err)
	}
	if len(result.Removed) != 0 {
		t.Errorf("nothing should be removed, got %v", result.Removed)
	}
}

// The full cycle must be repeatable without accumulating state. This is the
// property the gate's 100-cycle run checks at a larger scale.
func TestUpDownCycleLeavesNoResidue(t *testing.T) {
	orchestrator, controller, journal := newTestOrchestrator(t)
	ctx := context.Background()
	cfg := testConfig()

	for cycle := 1; cycle <= 20; cycle++ {
		if _, err := orchestrator.Up(ctx, cfg); err != nil {
			t.Fatalf("cycle %d up: %v", cycle, err)
		}
		if !controller.HasInterface("nm0") {
			t.Fatalf("cycle %d: interface missing after up", cycle)
		}

		if _, err := orchestrator.Down(ctx); err != nil {
			t.Fatalf("cycle %d down: %v", cycle, err)
		}
		if controller.HasInterface("nm0") {
			t.Fatalf("cycle %d: interface survived down", cycle)
		}
	}

	pending, err := journal.PendingRecovery()
	if err != nil {
		t.Fatalf("reading journal: %v", err)
	}
	if len(pending) != 0 {
		t.Errorf("%d transactions left needing recovery after 20 cycles", len(pending))
	}
}

// A process that dies mid-apply leaves a journal entry and possibly partial
// host state. Recover returns the host to a known baseline and resolves the
// entry.
func TestRecoverAfterInterruptedApply(t *testing.T) {
	orchestrator, controller, journal := newTestOrchestrator(t)
	ctx := context.Background()

	// Simulate a crash: a transaction recorded as applying, with the interface
	// actually present, and no compensation having run.
	transaction := netstate.NewTransaction("tx-crashed", "nm0", orchestrator.clock.Now())
	if err := transaction.Plan(netstate.Operation{
		ID:     "op-1",
		Kind:   netstate.OpCreateInterface,
		Target: "nm0",
	}, orchestrator.clock.Now()); err != nil {
		t.Fatalf("planning: %v", err)
	}
	if err := transaction.MarkApplying("op-1"); err != nil {
		t.Fatalf("marking applying: %v", err)
	}
	if err := journal.Save(transaction); err != nil {
		t.Fatalf("saving journal: %v", err)
	}
	controller.PreexistingInterface("nm0", nil)

	result, err := orchestrator.Recover(ctx)
	if err != nil {
		t.Fatalf("recovering: %v", err)
	}

	if len(result.Interrupted) != 1 {
		t.Fatalf("expected 1 interrupted transaction, got %d", len(result.Interrupted))
	}
	if controller.HasInterface("nm0") {
		t.Error("recovery must return the host to a known baseline")
	}

	pending, err := journal.PendingRecovery()
	if err != nil {
		t.Fatalf("reading journal: %v", err)
	}
	if len(pending) != 0 {
		t.Errorf("recovery must resolve the journal, %d still pending", len(pending))
	}
}

func TestRecoverWithCleanJournal(t *testing.T) {
	orchestrator, _, _ := newTestOrchestrator(t)

	result, err := orchestrator.Recover(context.Background())
	if err != nil {
		t.Fatalf("recovering a clean journal must succeed: %v", err)
	}
	if len(result.Interrupted) != 0 {
		t.Errorf("nothing should be interrupted, got %d", len(result.Interrupted))
	}
}

func TestUpWithoutPeers(t *testing.T) {
	orchestrator, _, _ := newTestOrchestrator(t)

	cfg := testConfig()
	cfg.Peers = nil

	if _, err := orchestrator.Up(context.Background(), cfg); !errors.Is(err, ErrNoPeers) {
		t.Errorf("expected ErrNoPeers, got: %v", err)
	}
}

// A plan must describe what would happen without touching anything.
func TestPlanUpAppliesNothing(t *testing.T) {
	orchestrator, controller, journal := newTestOrchestrator(t)

	plan, err := orchestrator.PlanUp(context.Background(), testConfig())
	if err != nil {
		t.Fatalf("planning: %v", err)
	}

	if len(plan.Operations) == 0 {
		t.Error("a plan must contain operations")
	}
	if controller.HasInterface("nm0") {
		t.Error("planning must not create the interface")
	}

	transactions, err := journal.List()
	if err != nil {
		t.Fatalf("listing journal: %v", err)
	}
	if len(transactions) != 0 {
		t.Errorf("planning must not write to the journal, got %d entries", len(transactions))
	}
}

// Everything applied comes from local configuration. Nothing is derived from
// what a peer claims, which is what NM-04 requires.
func TestPeerSpecsComeFromLocalConfiguration(t *testing.T) {
	orchestrator, _, _ := newTestOrchestrator(t)
	cfg := testConfig()

	plan, err := orchestrator.PlanUp(context.Background(), cfg)
	if err != nil {
		t.Fatalf("planning: %v", err)
	}

	if len(plan.Peers) != 1 {
		t.Fatalf("expected 1 peer spec, got %d", len(plan.Peers))
	}

	peer := plan.Peers[0]
	if len(peer.AllowedIPs) != 1 || peer.AllowedIPs[0].String() != "100.96.0.2/32" {
		t.Errorf("allowed IPs must come from configuration, got %v", peer.AllowedIPs)
	}
	if peer.Endpoint == nil || peer.Endpoint.String() != "198.51.100.10:51820" {
		t.Errorf("endpoint must come from configuration, got %v", peer.Endpoint)
	}
	if peer.PersistentKeepalive != 25*time.Second {
		t.Errorf("keepalive = %s, want 25s", peer.PersistentKeepalive)
	}
}

func TestNewRequiresDependencies(t *testing.T) {
	journal := netstate.NewJournalStore(t.TempDir())

	t.Run("no controller", func(t *testing.T) {
		if _, err := New(Options{Journal: journal}); err == nil {
			t.Error("a controller is required")
		}
	})

	t.Run("no journal", func(t *testing.T) {
		if _, err := New(Options{Controller: wireguard.NewFakeController()}); err == nil {
			t.Error("a journal is required")
		}
	})
}
