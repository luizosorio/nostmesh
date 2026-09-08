package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/luizosorio/nostmesh/internal/config"
	"github.com/luizosorio/nostmesh/internal/domain"
	"github.com/luizosorio/nostmesh/internal/netstate"
	"github.com/luizosorio/nostmesh/internal/orchestrator"
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

// A node offering nothing announces nothing.
//
// The default. A node that advertised whatever it happened to reach would offer
// its own LAN to strangers without its operator asking for it.
func TestANodeOffersNothingByDefault(t *testing.T) {
	handler, _ := newTestRouteHandler(t, testNostrKey(t, 130), "10.20.30.0/24")

	if announce := handler.Advertise(); announce != nil {
		t.Errorf("a node with nothing configured announced %+v", announce)
	}
}

// A configured node announces what it was told to offer.
func TestAConfiguredNodeAnnouncesItsPrefixes(t *testing.T) {
	handler, _ := newTestRouteHandler(t, testNostrKey(t, 131), "10.20.30.0/24")
	handler.Advertising([]netip.Prefix{
		netip.MustParsePrefix("10.1.0.0/24"),
		netip.MustParsePrefix("10.2.0.0/24"),
	}, 20, "lab")

	announce := handler.Advertise()
	if announce == nil {
		t.Fatal("a configured node announced nothing")
	}
	if len(announce.Routes) != 2 {
		t.Fatalf("routes = %d, want both prefixes", len(announce.Routes))
	}
	if announce.NetworkID != "lab" {
		t.Errorf("network = %q, want lab", announce.NetworkID)
	}
	if announce.Routes[0].Metric != 20 {
		t.Errorf("metric = %d, want the configured claim", announce.Routes[0].Metric)
	}
	if announce.ValidUntil <= handler.clock().Unix() {
		t.Error("the announcement is already expired when it is made")
	}
}

// The announcement passes the protocol's own validation.
//
// Built here and checked by the code a receiver would run, so a shape this node
// cannot express is caught before it reaches the wire rather than by a peer
// silently refusing it.
func TestAnAnnouncementIsValidOnTheWire(t *testing.T) {
	handler, _ := newTestRouteHandler(t, testNostrKey(t, 132), "10.20.30.0/24")
	handler.Advertising([]netip.Prefix{netip.MustParsePrefix("10.1.0.0/24")}, 10, "lab")

	announce := handler.Advertise()
	if announce == nil {
		t.Fatal("nothing was announced")
	}

	envelope := protocol.Envelope{Type: protocol.TypeRouteAnnounce}
	if err := protocol.ValidatePayload(
		protocol.Payload{RouteAnnounce: announce}, envelope, handler.clock(),
	); err != nil {
		t.Errorf("this node built an announcement a peer would refuse: %v", err)
	}
}

// The version increases, so a peer never sees a refresh as stale.
//
// It comes from the clock rather than a counter because it has to survive a
// restart: a counter starting at zero would be refused by every peer still
// holding the previous announcement.
func TestAnnouncementVersionsIncrease(t *testing.T) {
	handler, _ := newTestRouteHandler(t, testNostrKey(t, 133), "10.20.30.0/24")
	handler.Advertising([]netip.Prefix{netip.MustParsePrefix("10.1.0.0/24")}, 10, "lab")

	first := handler.Advertise()

	later := routeClock()().Add(time.Minute)
	handler.clock = func() time.Time { return later }
	second := handler.Advertise()

	if second.Version <= first.Version {
		t.Errorf("version went from %d to %d; a refresh would be refused as stale",
			first.Version, second.Version)
	}
	if second.ValidUntil <= first.ValidUntil {
		t.Error("the refreshed announcement does not extend the validity")
	}
}

// The routes a node installed are visible in what the service reports.
//
// The RIB is what this node decided; `nostmesh status` shows the kernel's own
// table. An operator can only tell the two apart by reading both, and before
// this neither reported a route at all.
func TestInstalledRoutesAreReportedToTheOperator(t *testing.T) {
	peer := testNostrKey(t, 140)
	handler, _ := newTestRouteHandler(t, peer, "10.20.30.0/24")
	ctx := context.Background()

	if err := handler.Announce(ctx, peer, announcement("10.20.30.0/24")); err != nil {
		t.Fatalf("announcing: %v", err)
	}
	if err := handler.Reconcile(ctx, peer, "nm0"); err != nil {
		t.Fatalf("reconciling: %v", err)
	}

	installed, conflicts := handler.Snapshot()
	if len(installed) != 1 {
		t.Fatalf("reported %d routes, want the one that was installed", len(installed))
	}
	if installed[0].Provider != peer {
		t.Error("the reported route does not name the peer that offered it")
	}
	if installed[0].ExpiresAt.IsZero() {
		t.Error("the reported route carries no validity; an operator cannot see when it lapses")
	}
	if len(conflicts) != 0 {
		t.Errorf("conflicts = %v, want none with a single provider", conflicts)
	}
}

// A contested destination is reported, with the winner named.
//
// Only one route per prefix is installed, and an operator wondering why a
// provider's offer is not in use needs to see that another won rather than that
// theirs vanished.
func TestAContestedDestinationIsReported(t *testing.T) {
	winner := testNostrKey(t, 141)
	loser := testNostrKey(t, 142)

	list := policy.NewAllowlist()
	for _, peer := range []domain.NostrPublicKey{winner, loser} {
		if err := list.Add(policy.Grant{
			Peer:       peer,
			Actions:    []policy.Action{policy.ActionRoute},
			AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.20.30.0/24")},
		}); err != nil {
			t.Fatalf("granting: %v", err)
		}
	}

	controller := wireguard.NewFakeController()
	journal := netstate.NewJournalStore(t.TempDir())
	manager := netstate.NewManager(controller, journal, stubClock{at: routeClock()()})
	router := policy.NewRouter(list, domain.NewRouteTable(0), domain.LocalNetwork{})
	handler := newRouteHandler(router, manager, routeClock(), slog.New(slog.NewTextHandler(io.Discard, nil)))

	ctx := context.Background()

	// The better metric wins; both are recorded.
	good := announcement("10.20.30.0/24")
	good.Routes[0].Metric = 5
	if err := handler.Announce(ctx, winner, good); err != nil {
		t.Fatalf("announcing: %v", err)
	}
	poor := announcement("10.20.30.0/24")
	poor.Routes[0].Metric = 50
	if err := handler.Announce(ctx, loser, poor); err != nil {
		t.Fatalf("announcing: %v", err)
	}

	_, conflicts := handler.Snapshot()
	if len(conflicts) != 1 {
		t.Fatalf("conflicts = %d, want the contested destination", len(conflicts))
	}
	if len(conflicts[0].Offers) != 2 {
		t.Errorf("offers = %d, want both providers visible", len(conflicts[0].Offers))
	}
}

// A node that routes nothing reports nothing.
//
// The default, and the common case. Reporting an empty section on every node
// that never announced anything is noise rather than information.
func TestANodeRoutingNothingReportsNothing(t *testing.T) {
	handler, _ := newTestRouteHandler(t, testNostrKey(t, 143), "10.20.30.0/24")

	installed, conflicts := handler.Snapshot()
	if len(installed) != 0 || len(conflicts) != 0 {
		t.Errorf("a node with no routes reported %v / %v", installed, conflicts)
	}
}

// status prints the routes the kernel holds for an interface.
//
// The FIB half of "RIB/FIB/status coherent". `nostmesh state` reports what the
// node decided; this reports what the kernel actually has, and an operator can
// only tell a route that failed to install from one that worked by reading both.
//
// renderStatus directly rather than the command: the command needs a kernel and
// skips without one, and a guard that skips in CI is not a guard.
func TestStatusPrintsTheKernelRoutes(t *testing.T) {
	var printed bytes.Buffer
	out := &output{w: &printed}

	status := orchestrator.Status{
		Interfaces: []wireguard.InterfaceState{{
			Name:       "nm-abc12345",
			MTU:        1420,
			ListenPort: 51820,
			Routes: []netip.Prefix{
				netip.MustParsePrefix("10.20.30.0/24"),
				netip.MustParsePrefix("10.40.0.0/16"),
			},
		}},
	}

	if code := renderStatus(status, config.Default(), out); code != exitOK {
		t.Fatalf("render returned %d", code)
	}

	rendered := printed.String()
	for _, want := range []string{"10.20.30.0/24", "10.40.0.0/16"} {
		if !strings.Contains(rendered, want) {
			t.Errorf("status does not report route %s:\n%s", want, rendered)
		}
	}
}

// An interface carrying no routes prints none, rather than an empty heading.
func TestStatusPrintsNoRoutesWhenThereAreNone(t *testing.T) {
	var printed bytes.Buffer
	out := &output{w: &printed}

	status := orchestrator.Status{
		Interfaces: []wireguard.InterfaceState{{Name: "nm-abc12345", MTU: 1420}},
	}

	if code := renderStatus(status, config.Default(), out); code != exitOK {
		t.Fatalf("render returned %d", code)
	}
	if strings.Contains(printed.String(), "route:") {
		t.Errorf("status mentions routes for an interface that has none:\n%s", printed.String())
	}
}

// The service reports its routes to the operator.
//
// Through service.snapshot, which is what `nostmesh state` reads — not through
// the handler directly. A test that asked the handler would pass with the
// service never wired to it, which is exactly the defect this closes: the RIB
// existed and nothing reported it.
func TestTheServiceReportsItsRoutes(t *testing.T) {
	peer := testNostrKey(t, 150)
	handler, _ := newTestRouteHandler(t, peer, "10.20.30.0/24")
	ctx := context.Background()

	if err := handler.Announce(ctx, peer, announcement("10.20.30.0/24")); err != nil {
		t.Fatalf("announcing: %v", err)
	}
	if err := handler.Reconcile(ctx, peer, "nm0"); err != nil {
		t.Fatalf("reconciling: %v", err)
	}

	cfg, path := writeServiceConfig(t, peer, false)
	svc := testService(t, cfg, path)
	svc.super.routes = handler

	state := svc.snapshot()
	if len(state.Routes) != 1 {
		t.Fatalf("state reports %d routes, want the one installed", len(state.Routes))
	}
	if state.Routes[0].Prefix != "10.20.30.0/24" {
		t.Errorf("prefix = %q, want the announced destination", state.Routes[0].Prefix)
	}
	if state.Routes[0].Provider != peer.Short() {
		t.Errorf("provider = %q, want the peer that offered it", state.Routes[0].Provider)
	}
	if state.Routes[0].Expires == "" {
		t.Error("no validity reported; an operator cannot see when the route lapses")
	}
}

// A service routing nothing reports no route section at all.
func TestTheServiceReportsNoRoutesWhenItHasNone(t *testing.T) {
	peer := testNostrKey(t, 151)
	cfg, path := writeServiceConfig(t, peer, false)
	svc := testService(t, cfg, path)

	state := svc.snapshot()
	if len(state.Routes) != 0 || len(state.Conflicts) != 0 {
		t.Errorf("a service with no routes reported %v / %v", state.Routes, state.Conflicts)
	}
}
