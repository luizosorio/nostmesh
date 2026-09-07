package main

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/luizosorio/nostmesh/internal/domain"
	"github.com/luizosorio/nostmesh/internal/netstate"
	"github.com/luizosorio/nostmesh/internal/policy"
	"github.com/luizosorio/nostmesh/internal/protocol"
	"github.com/luizosorio/nostmesh/internal/wireguard"
)

func routeClock() func() time.Time {
	at := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	return func() time.Time { return at }
}

// newTestRouteHandler builds a handler over a fake host with an interface up.
func newTestRouteHandler(t *testing.T, peer domain.NostrPublicKey, allowed ...string) (
	*routeHandler, *wireguard.FakeController,
) {
	t.Helper()

	list := policy.NewAllowlist()
	prefixes := make([]netip.Prefix, 0, len(allowed))
	for _, entry := range allowed {
		prefixes = append(prefixes, netip.MustParsePrefix(entry))
	}
	if err := list.Add(policy.Grant{
		Peer:       peer,
		Actions:    []policy.Action{policy.ActionSession, policy.ActionRoute},
		AllowedIPs: prefixes,
	}); err != nil {
		t.Fatalf("granting: %v", err)
	}

	controller := wireguard.NewFakeController()
	journal := netstate.NewJournalStore(t.TempDir())
	manager := netstate.NewManager(controller, journal, stubClock{at: routeClock()()})

	// The interface a route points through has to exist.
	plan, err := manager.PlanInterface(context.Background(), "tx", wireguard.InterfaceSpec{
		Name:       "nm0",
		PrivateKey: testWireGuardKey(t),
		ListenPort: 51820,
	}, nil)
	if err != nil {
		t.Fatalf("planning interface: %v", err)
	}
	if _, err := manager.Apply(context.Background(), plan); err != nil {
		t.Fatalf("applying interface: %v", err)
	}

	router := policy.NewRouter(list, domain.NewRouteTable(0), domain.LocalNetwork{})
	handler := newRouteHandler(router, manager, routeClock(), slog.New(slog.NewTextHandler(io.Discard, nil)))

	return handler, controller
}

type stubClock struct{ at time.Time }

func (c stubClock) Now() time.Time { return c.at }

func testWireGuardKey(t *testing.T) domain.WireGuardPrivateKey {
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

func announcement(prefixes ...string) protocol.RouteAnnounce {
	routes := make([]protocol.AnnouncedRoute, 0, len(prefixes))
	for _, prefix := range prefixes {
		routes = append(routes, protocol.AnnouncedRoute{Prefix: prefix, Metric: 10})
	}
	return protocol.RouteAnnounce{
		Routes:     routes,
		NetworkID:  "lab",
		Version:    1,
		ValidUntil: routeClock()().Add(10 * time.Minute).Unix(),
	}
}

// An authorized announcement reaches the kernel.
//
// The whole delivery in one assertion: a peer says it can reach a prefix, and
// the route appears on the interface.
func TestAnAnnouncementReachesTheKernel(t *testing.T) {
	peer := testNostrKey(t, 120)
	handler, controller := newTestRouteHandler(t, peer, "10.20.30.0/24")
	ctx := context.Background()

	if err := handler.Announce(ctx, peer, announcement("10.20.30.0/24")); err != nil {
		t.Fatalf("announcing: %v", err)
	}
	if err := handler.Reconcile(ctx, peer, "nm0"); err != nil {
		t.Fatalf("reconciling: %v", err)
	}

	installed := controller.Routes("nm0")
	if len(installed) != 1 || installed[0].String() != "10.20.30.0/24" {
		t.Errorf("routes = %v, want the announced prefix", installed)
	}
}

// A prefix policy refuses never reaches the kernel.
func TestARefusedAnnouncementInstallsNothing(t *testing.T) {
	peer := testNostrKey(t, 121)
	handler, controller := newTestRouteHandler(t, peer, "10.20.30.0/24")
	ctx := context.Background()

	if err := handler.Announce(ctx, peer, announcement("192.168.0.0/16")); err != nil {
		t.Fatalf("announcing: %v", err)
	}
	if err := handler.Reconcile(ctx, peer, "nm0"); err != nil {
		t.Fatalf("reconciling: %v", err)
	}

	if got := controller.Routes("nm0"); len(got) != 0 {
		t.Errorf("routes = %v; policy refused this prefix", got)
	}
}

// A withdrawal takes the route out of the kernel.
func TestAWithdrawalRemovesTheRouteFromTheKernel(t *testing.T) {
	peer := testNostrKey(t, 122)
	handler, controller := newTestRouteHandler(t, peer, "10.20.30.0/24")
	ctx := context.Background()

	if err := handler.Announce(ctx, peer, announcement("10.20.30.0/24")); err != nil {
		t.Fatalf("announcing: %v", err)
	}
	if err := handler.Reconcile(ctx, peer, "nm0"); err != nil {
		t.Fatalf("reconciling: %v", err)
	}
	if len(controller.Routes("nm0")) != 1 {
		t.Fatal("the route was not installed, so this asserts nothing")
	}

	if err := handler.Withdraw(ctx, peer, protocol.RouteWithdraw{
		Prefixes:  []string{"10.20.30.0/24"},
		NetworkID: "lab",
		Version:   2,
	}); err != nil {
		t.Fatalf("withdrawing: %v", err)
	}
	if err := handler.Reconcile(ctx, peer, "nm0"); err != nil {
		t.Fatalf("reconciling: %v", err)
	}

	if got := controller.Routes("nm0"); len(got) != 0 {
		t.Errorf("routes = %v, want none after withdrawal", got)
	}
}

// An expired announcement is removed without anyone saying so.
func TestAnExpiredAnnouncementLeavesTheKernel(t *testing.T) {
	peer := testNostrKey(t, 123)
	handler, controller := newTestRouteHandler(t, peer, "10.20.30.0/24")
	ctx := context.Background()

	if err := handler.Announce(ctx, peer, announcement("10.20.30.0/24")); err != nil {
		t.Fatalf("announcing: %v", err)
	}
	if err := handler.Reconcile(ctx, peer, "nm0"); err != nil {
		t.Fatalf("reconciling: %v", err)
	}
	if len(controller.Routes("nm0")) != 1 {
		t.Fatal("the route was not installed, so this asserts nothing")
	}

	// Past the validity the announcement carried.
	handler.clock = func() time.Time { return routeClock()().Add(time.Hour) }
	if err := handler.Reconcile(ctx, peer, "nm0"); err != nil {
		t.Fatalf("reconciling: %v", err)
	}

	if got := controller.Routes("nm0"); len(got) != 0 {
		t.Errorf("routes = %v; the announcement's validity had passed", got)
	}
}

// Reconciling twice installs nothing the second time.
//
// The hold loop calls this on every tick, so a handler that reapplied would
// rewrite kernel state and grow the journal forever.
func TestReconcilingTwiceIsQuiet(t *testing.T) {
	peer := testNostrKey(t, 124)
	handler, controller := newTestRouteHandler(t, peer, "10.20.30.0/24")
	ctx := context.Background()

	if err := handler.Announce(ctx, peer, announcement("10.20.30.0/24")); err != nil {
		t.Fatalf("announcing: %v", err)
	}
	if err := handler.Reconcile(ctx, peer, "nm0"); err != nil {
		t.Fatalf("reconciling: %v", err)
	}

	controller.ResetCalls()
	for range 5 {
		if err := handler.Reconcile(ctx, peer, "nm0"); err != nil {
			t.Fatalf("reconciling: %v", err)
		}
	}

	for _, call := range controller.RecordedCalls() {
		if call == "AddRoute" {
			t.Fatal("a settled route was reinstalled; the hold loop would rewrite it forever")
		}
	}
}

// Releasing a peer drops what it offered.
func TestReleasingAPeerDropsItsRoutes(t *testing.T) {
	peer := testNostrKey(t, 125)
	handler, _ := newTestRouteHandler(t, peer, "10.20.30.0/24")
	ctx := context.Background()

	if err := handler.Announce(ctx, peer, announcement("10.20.30.0/24")); err != nil {
		t.Fatalf("announcing: %v", err)
	}
	if err := handler.Reconcile(ctx, peer, "nm0"); err != nil {
		t.Fatalf("reconciling: %v", err)
	}

	if err := handler.Release(ctx, peer, "nm0"); err != nil {
		t.Fatalf("releasing: %v", err)
	}

	if got := handler.router.Installed(); len(got) != 0 {
		t.Errorf("the table still claims %v after the peer was released", got)
	}
}
