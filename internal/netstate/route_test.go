package netstate

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/luizosorio/nostmesh/internal/wireguard"
)

// bringUpInterface applies an interface so routes have somewhere to point.
func bringUpInterface(t *testing.T, manager *Manager) {
	t.Helper()

	plan, err := manager.PlanInterface(context.Background(), "tx-iface", testSpec(t), testPeers(t, 1))
	if err != nil {
		t.Fatalf("planning interface: %v", err)
	}
	if _, err := manager.Apply(context.Background(), plan); err != nil {
		t.Fatalf("applying interface: %v", err)
	}
}

// An announced route is installed and journaled as its own operation.
func TestAnnouncedRoutesAreInstalled(t *testing.T) {
	manager, controller, _ := newTestManager(t)
	ctx := context.Background()
	bringUpInterface(t, manager)

	routes := []netip.Prefix{
		netip.MustParsePrefix("10.20.30.0/24"),
		netip.MustParsePrefix("10.40.0.0/16"),
	}

	plan, err := manager.PlanRoutes(ctx, "tx-routes", "nm0", routes)
	if err != nil {
		t.Fatalf("planning routes: %v", err)
	}

	transaction, err := manager.Apply(ctx, plan)
	if err != nil {
		t.Fatalf("applying routes: %v", err)
	}
	if !transaction.Committed {
		t.Error("a successful apply must commit")
	}

	installed := controller.Routes("nm0")
	if len(installed) != len(routes) {
		t.Fatalf("installed %v, want %v", installed, routes)
	}

	for _, op := range transaction.Operations {
		if op.Kind != OpAddRoute {
			t.Errorf("a route plan produced a %s operation", op.Kind)
		}
	}
}

// Withdrawing a route leaves the tunnel alone.
//
// The reason routes are their own operation (NM-25): under the old coupling the
// only way to remove one prefix was to reapply the peer, so an expiry rewrote
// live kernel state and a failure took the tunnel with it.
func TestWithdrawingARouteLeavesThePeerAlone(t *testing.T) {
	manager, controller, _ := newTestManager(t)
	ctx := context.Background()
	bringUpInterface(t, manager)

	prefix := netip.MustParsePrefix("10.20.30.0/24")
	plan, err := manager.PlanRoutes(ctx, "tx-routes", "nm0", []netip.Prefix{prefix})
	if err != nil {
		t.Fatalf("planning: %v", err)
	}
	if _, err := manager.Apply(ctx, plan); err != nil {
		t.Fatalf("applying: %v", err)
	}

	peersBefore := controller.PeerCount("nm0")

	if err := manager.RemoveRoute(ctx, "nm0", prefix); err != nil {
		t.Fatalf("withdrawing: %v", err)
	}

	if got := controller.Routes("nm0"); len(got) != 0 {
		t.Errorf("routes = %v, want none after withdrawal", got)
	}
	if got := controller.PeerCount("nm0"); got != peersBefore {
		t.Errorf("peers = %d, want %d; withdrawing a route must not touch the tunnel", got, peersBefore)
	}
	if !controller.HasInterface("nm0") {
		t.Error("withdrawing a route removed the interface")
	}
}

// Withdrawing a route that is not there succeeds.
//
// Expiry, withdrawal and close can all remove the same route, and they race.
// Failing on absence would make a second remover report an error about the
// state it wanted.
func TestWithdrawingAnAbsentRouteSucceeds(t *testing.T) {
	manager, _, _ := newTestManager(t)
	ctx := context.Background()
	bringUpInterface(t, manager)

	if err := manager.RemoveRoute(ctx, "nm0", netip.MustParsePrefix("10.99.0.0/16")); err != nil {
		t.Errorf("removing an absent route reported an error: %v", err)
	}
}

// A failed route application removes the routes it installed.
func TestFailedRouteApplyRollsBack(t *testing.T) {
	manager, controller, _ := newTestManager(t)
	ctx := context.Background()
	bringUpInterface(t, manager)

	routes := []netip.Prefix{
		netip.MustParsePrefix("10.20.30.0/24"),
		netip.MustParsePrefix("10.40.0.0/16"),
	}
	plan, err := manager.PlanRoutes(ctx, "tx-routes", "nm0", routes)
	if err != nil {
		t.Fatalf("planning: %v", err)
	}

	// The first AddRoute fails, so the transaction rolls back having applied
	// nothing of its own. What is asserted is that it leaves nothing behind and
	// does not take the interface with it.
	controller.FailNext("AddRoute", 1, errors.New("no space"))

	if _, err := manager.Apply(ctx, plan); err == nil {
		t.Fatal("a failing route application was reported as success")
	}

	if got := controller.Routes("nm0"); len(got) != 0 {
		t.Errorf("routes = %v; a rolled-back transaction must leave none", got)
	}
	if !controller.HasInterface("nm0") {
		t.Error("rolling back routes removed the interface they were added to")
	}
}

// A route that already existed survives a rollback.
//
// The journal's discipline: NostMesh reverts what it did, never what it found.
// A route an operator installed themselves must not be deleted because a later
// transaction failed.
func TestRollbackPreservesAPreexistingRoute(t *testing.T) {
	manager, controller, _ := newTestManager(t)
	ctx := context.Background()
	bringUpInterface(t, manager)

	theirs := netip.MustParsePrefix("10.20.30.0/24")
	if err := controller.AddRoute(ctx, "nm0", theirs); err != nil {
		t.Fatalf("seeding a route: %v", err)
	}

	ours := netip.MustParsePrefix("10.40.0.0/16")
	plan, err := manager.PlanRoutes(ctx, "tx-routes", "nm0", []netip.Prefix{theirs, ours})
	if err != nil {
		t.Fatalf("planning: %v", err)
	}

	// The plan must have noticed which route was already there.
	for _, op := range plan.Operations {
		if op.Target == theirs.String() && !op.Existed {
			t.Error("a route that was already present was planned as new; rollback would delete it")
		}
		if op.Target == ours.String() && op.Existed {
			t.Error("a route that was not present was planned as existing; rollback would leave it")
		}
	}

	// Fail after a route applies, so compensation has both to consider: the one
	// that was already there, journaled as Existed, and the one this
	// transaction added. Only the second may be removed.
	manager.InjectFailureAfter(OpAddRoute)
	if _, err := manager.Apply(ctx, plan); err == nil {
		t.Fatal("a failing apply was reported as success")
	}

	remaining := controller.Routes("nm0")
	if len(remaining) != 1 || remaining[0] != theirs {
		t.Errorf("routes = %v, want only the preexisting %v", remaining, theirs)
	}
}

// Routing through an interface that does not exist is refused at planning.
func TestRoutingRequiresTheInterface(t *testing.T) {
	manager, _, _ := newTestManager(t)

	_, err := manager.PlanRoutes(context.Background(), "tx", "nm0", []netip.Prefix{
		netip.MustParsePrefix("10.20.30.0/24"),
	})
	if err == nil {
		t.Fatal("routes were planned for an interface that does not exist")
	}
}

// Compensation knows how to undo a route.
//
// The undo switch ends in a default that reports "no compensation defined". An
// operation kind nobody added a case for reaches it, and the rollback fails —
// which is the worst outcome a transaction has, because the host is left partly
// changed with the journal saying so.
func TestRouteCompensationIsDefined(t *testing.T) {
	manager, controller, _ := newTestManager(t)
	ctx := context.Background()
	bringUpInterface(t, manager)

	err := manager.undo(ctx, "nm0", Operation{
		Kind:   OpAddRoute,
		Target: "10.20.30.0/24",
	})
	if err != nil {
		t.Fatalf("undoing a route: %v", err)
	}

	if !controller.Attempted("RemoveRoute") {
		t.Error("undoing a route did not ask the controller to remove one")
	}
}

// The fake refuses a route to an interface it does not have.
//
// A fake that accepted one would let every route test pass against an interface
// nothing created, which is the failure mode a fake mirroring the kernel exists
// to prevent.
func TestTheFakeRefusesARouteWithoutItsInterface(t *testing.T) {
	controller := wireguard.NewFakeController()

	err := controller.AddRoute(context.Background(), "nm0", netip.MustParsePrefix("10.0.0.0/8"))
	if !errors.Is(err, wireguard.ErrInterfaceNotFound) {
		t.Errorf("error = %v, want %v", err, wireguard.ErrInterfaceNotFound)
	}
}
