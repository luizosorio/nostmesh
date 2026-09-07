package orchestrator

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"

	"github.com/luizosorio/nostmesh/internal/netstate"
	"github.com/luizosorio/nostmesh/internal/wireguard"
)

// seedInterface creates an interface directly, the way a previous run would
// have left one behind.
func seedInterface(t *testing.T, controller *wireguard.FakeController, name string) {
	t.Helper()

	if _, err := controller.EnsureInterface(context.Background(), wireguard.InterfaceSpec{
		Name:       name,
		ListenPort: 51820,
		Addresses:  []netip.Prefix{netip.MustParsePrefix("fd00::1/128")},
	}); err != nil {
		t.Fatalf("seeding %s: %v", name, err)
	}
}

// Down removes every interface this project owns, not one known name.
//
// This is the defect the enumeration exists to fix. A node running several
// sessions leaves several interfaces; cleaning up one would leave the rest
// holding their listen ports, and the next run would fail to bind them forever
// with nothing on the host explaining why.
func TestDownRemovesEveryOwnedInterface(t *testing.T) {
	orchestrator, controller, _ := newTestOrchestrator(t)
	ctx := context.Background()

	for _, name := range []string{"nm0", "nm-a1b2c3d4", "nm-e5f6a7b8"} {
		seedInterface(t, controller, name)
	}

	result, err := orchestrator.Down(ctx)
	if err != nil {
		t.Fatalf("bringing down: %v", err)
	}

	for _, name := range []string{"nm0", "nm-a1b2c3d4", "nm-e5f6a7b8"} {
		if controller.HasInterface(name) {
			t.Errorf("%s survived Down, and is still holding its listen port", name)
		}
		if !slices.Contains(result.Removed, name) {
			t.Errorf("Down did not report removing %s, so a partial cleanup would look complete", name)
		}
	}
}

// An interface this project does not own is left alone.
//
// The host may carry an operator's own WireGuard interfaces, and removing one
// would be taking away something NostMesh never added.
func TestDownLeavesInterfacesItDoesNotOwn(t *testing.T) {
	orchestrator, controller, _ := newTestOrchestrator(t)
	ctx := context.Background()

	seedInterface(t, controller, "nm0")

	result, err := orchestrator.Down(ctx)
	if err != nil {
		t.Fatalf("bringing down: %v", err)
	}

	// The fake refuses to create an interface outside the prefix, which is the
	// same rule the adapter enforces — so what this asserts is that enumeration
	// never offered one up in the first place.
	for _, removed := range result.Removed {
		if !wireguard.OwnsInterface(removed) {
			t.Errorf("Down removed %s, which this project does not own", removed)
		}
	}
}

// Recover clears every owned interface, not one.
//
// An interrupted run may have created several, and the transaction that died
// says nothing about the others.
func TestRecoverClearsEveryOwnedInterface(t *testing.T) {
	orchestrator, controller, journal := newTestOrchestrator(t)
	ctx := context.Background()

	for _, name := range []string{"nm0", "nm-a1b2c3d4"} {
		seedInterface(t, controller, name)
	}

	// A transaction that died partway, which is what makes Recover act.
	crashed := netstate.NewTransaction("tx-crashed", "nm0", orchestrator.clock.Now())
	if err := crashed.Plan(netstate.Operation{
		ID:     "op-1",
		Kind:   netstate.OpCreateInterface,
		Target: "nm0",
	}, orchestrator.clock.Now()); err != nil {
		t.Fatalf("planning: %v", err)
	}
	if err := crashed.MarkApplying("op-1"); err != nil {
		t.Fatalf("marking applying: %v", err)
	}
	if err := journal.Save(crashed); err != nil {
		t.Fatalf("saving journal: %v", err)
	}

	result, err := orchestrator.Recover(ctx)
	if err != nil {
		t.Fatalf("recovering: %v", err)
	}

	if len(result.Interrupted) == 0 {
		t.Fatal("recovery saw no interrupted transaction")
	}
	for _, name := range []string{"nm0", "nm-a1b2c3d4"} {
		if controller.HasInterface(name) {
			t.Errorf("%s survived recovery, and is still holding its listen port", name)
		}
	}
}

// Enumeration is ordered, so two runs clean up identically.
//
// A partial failure must leave the same remainder every time; an order that
// varied would make a half-finished cleanup unreproducible.
func TestEnumerationIsOrdered(t *testing.T) {
	controller := wireguard.NewFakeController()

	for _, name := range []string{"nm-zz", "nm0", "nm-aa"} {
		seedInterface(t, controller, name)
	}

	first, err := controller.ListOwnedInterfaces(context.Background())
	if err != nil {
		t.Fatalf("listing: %v", err)
	}
	if !slices.IsSorted(first) {
		t.Errorf("the listing is not ordered: %v", first)
	}

	for range 8 {
		again, err := controller.ListOwnedInterfaces(context.Background())
		if err != nil {
			t.Fatalf("listing again: %v", err)
		}
		if !slices.Equal(first, again) {
			t.Fatalf("the listing changed between calls: %v then %v", first, again)
		}
	}
}

// An interface that vanishes between the listing and the removal is not an
// error.
//
// The two are separate calls, and something else cleaning up in between leaves
// exactly the state this wanted anyway.
func TestAVanishedInterfaceIsNotAnError(t *testing.T) {
	orchestrator, controller, _ := newTestOrchestrator(t)
	ctx := context.Background()

	seedInterface(t, controller, "nm0")

	// Removing it behind the orchestrator's back is the closest reproducible
	// stand-in for another process cleaning up mid-reconciliation.
	if err := controller.RemoveInterface(ctx, "nm0"); err != nil {
		t.Fatalf("preparing: %v", err)
	}

	if _, err := orchestrator.Down(ctx); err != nil {
		t.Errorf("an interface that vanished mid-reconciliation was reported as an error: %v", err)
	}
}

// A listing failure stops reconciliation rather than reporting success.
//
// Concluding there is nothing to clean because the question could not be asked
// is how residue survives a cleanup that reported no problem.
func TestAFailedListingStopsReconciliation(t *testing.T) {
	orchestrator, controller, _ := newTestOrchestrator(t)

	controller.FailOn["ListOwnedInterfaces"] = errors.New("netlink refused")

	if _, err := orchestrator.Down(context.Background()); err == nil {
		t.Error("Down reported success when it could not list what to remove")
	}
}
