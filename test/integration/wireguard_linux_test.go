//go:build linux && privileged

// Package integration exercises the netlink adapter against a real kernel.
//
// These tests need CAP_NET_ADMIN and the wireguard module, so they are behind
// the "privileged" build tag and never run in the default suite. Each test
// works inside its own network namespace, so a failure cannot disturb the host
// or another test.
package integration

import (
	"context"
	"net/netip"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/vishvananda/netns"

	"github.com/luizosorio/nostmesh/internal/domain"
	"github.com/luizosorio/nostmesh/internal/wireguard"
)

// withNamespace runs fn inside a fresh network namespace.
//
// The goroutine is locked to its thread because network namespaces are a
// per-thread property in Linux: without the lock the Go runtime could move the
// goroutine to a thread still in the original namespace, and the test would
// silently configure the host instead.
func withNamespace(t testing.TB, fn func()) {
	t.Helper()

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	original, err := netns.Get()
	if err != nil {
		t.Fatalf("reading current namespace: %v", err)
	}
	defer func() { _ = original.Close() }()

	// Creating a network namespace needs CAP_SYS_ADMIN, not just NET_ADMIN.
	// Under Docker that means --privileged or --cap-add SYS_ADMIN; see
	// docs/development.md. Skip before installing the restore deferral, so a
	// namespace that was never entered is not restored.
	created, err := netns.New()
	if err != nil {
		t.Skipf("cannot create a network namespace (needs CAP_SYS_ADMIN): %v", err)
	}
	defer func() {
		if err := netns.Set(original); err != nil {
			t.Errorf("restoring namespace: %v", err)
		}
		_ = created.Close()
	}()

	fn()
}

func requirePrivileges(t testing.TB) {
	t.Helper()

	if os.Geteuid() != 0 {
		t.Skip("privileged tests need root or CAP_NET_ADMIN")
	}
}

func testPrivateKey(t testing.TB, seed byte) domain.WireGuardPrivateKey {
	t.Helper()

	raw := make([]byte, domain.WireGuardKeySize)
	for i := range raw {
		raw[i] = seed + byte(i)
	}
	key, err := domain.NewWireGuardPrivateKey(raw)
	if err != nil {
		t.Fatalf("building key: %v", err)
	}
	return key
}

func testPublicKey(t testing.TB, seed byte) domain.WireGuardPublicKey {
	t.Helper()

	var key domain.WireGuardPublicKey
	for i := range key {
		key[i] = seed + byte(i)
	}
	return key
}

func testSpec(t testing.TB, name string) wireguard.InterfaceSpec {
	t.Helper()

	return wireguard.InterfaceSpec{
		Name:       name,
		PrivateKey: testPrivateKey(t, 1),
		ListenPort: 51820,
		Addresses:  []netip.Prefix{netip.MustParsePrefix("100.96.0.1/32")},
		MTU:        1420,
	}
}

func TestCreateAndObserveInterface(t *testing.T) {
	requirePrivileges(t)

	withNamespace(t, func() {
		adapter, err := wireguard.NewLinuxAdapter()
		if err != nil {
			t.Fatalf("opening adapter: %v", err)
		}
		defer func() { _ = adapter.Close() }()

		ctx := context.Background()
		spec := testSpec(t, "nm0")

		state, err := adapter.EnsureInterface(ctx, spec)
		if err != nil {
			t.Fatalf("creating interface: %v", err)
		}

		if state.Name != "nm0" {
			t.Errorf("name = %q, want nm0", state.Name)
		}
		if state.ListenPort != spec.ListenPort {
			t.Errorf("listen port = %d, want %d", state.ListenPort, spec.ListenPort)
		}
		if state.MTU != spec.MTU {
			t.Errorf("MTU = %d, want %d", state.MTU, spec.MTU)
		}
		if !state.OwnedByUs {
			t.Error("an interface we created must be reported as ours")
		}
		if state.PublicKey.IsZero() {
			t.Error("the kernel must report a derived public key")
		}
	})
}

// Applying the same spec twice must converge rather than fail or duplicate.
func TestEnsureInterfaceIsIdempotent(t *testing.T) {
	requirePrivileges(t)

	withNamespace(t, func() {
		adapter, err := wireguard.NewLinuxAdapter()
		if err != nil {
			t.Fatalf("opening adapter: %v", err)
		}
		defer func() { _ = adapter.Close() }()

		ctx := context.Background()
		spec := testSpec(t, "nm0")

		var first wireguard.InterfaceState
		for attempt := 1; attempt <= 3; attempt++ {
			state, err := adapter.EnsureInterface(ctx, spec)
			if err != nil {
				t.Fatalf("attempt %d: %v", attempt, err)
			}
			if attempt == 1 {
				first = state
				continue
			}
			if state.PublicKey != first.PublicKey {
				t.Error("repeated apply changed the interface key")
			}
			if len(state.Addresses) != len(first.Addresses) {
				t.Errorf("attempt %d has %d addresses, want %d",
					attempt, len(state.Addresses), len(first.Addresses))
			}
		}
	})
}

func TestApplyAndRemovePeer(t *testing.T) {
	requirePrivileges(t)

	withNamespace(t, func() {
		adapter, err := wireguard.NewLinuxAdapter()
		if err != nil {
			t.Fatalf("opening adapter: %v", err)
		}
		defer func() { _ = adapter.Close() }()

		ctx := context.Background()
		if _, err := adapter.EnsureInterface(ctx, testSpec(t, "nm0")); err != nil {
			t.Fatalf("creating interface: %v", err)
		}

		endpoint := netip.MustParseAddrPort("198.51.100.10:51820")
		peer := wireguard.PeerSpec{
			PublicKey:           testPublicKey(t, 100),
			Endpoint:            &endpoint,
			AllowedIPs:          []netip.Prefix{netip.MustParsePrefix("100.96.0.2/32")},
			PersistentKeepalive: 25 * time.Second,
		}

		if err := adapter.ApplyPeer(ctx, "nm0", peer); err != nil {
			t.Fatalf("applying peer: %v", err)
		}

		state, err := adapter.ObserveInterface(ctx, "nm0")
		if err != nil {
			t.Fatalf("observing: %v", err)
		}
		if len(state.Peers) != 1 {
			t.Fatalf("peer count = %d, want 1", len(state.Peers))
		}
		if state.Peers[0].PublicKey != peer.PublicKey {
			t.Error("the kernel reports a different peer key")
		}

		// Applying twice must update rather than duplicate.
		if err := adapter.ApplyPeer(ctx, "nm0", peer); err != nil {
			t.Fatalf("re-applying peer: %v", err)
		}
		state, err = adapter.ObserveInterface(ctx, "nm0")
		if err != nil {
			t.Fatalf("observing: %v", err)
		}
		if len(state.Peers) != 1 {
			t.Errorf("re-applying duplicated the peer: count = %d", len(state.Peers))
		}

		if err := adapter.RemovePeer(ctx, "nm0", peer.PublicKey); err != nil {
			t.Fatalf("removing peer: %v", err)
		}
		state, err = adapter.ObserveInterface(ctx, "nm0")
		if err != nil {
			t.Fatalf("observing: %v", err)
		}
		if len(state.Peers) != 0 {
			t.Errorf("peer survived removal: count = %d", len(state.Peers))
		}

		// Removing an absent peer must not error, so compensation can run
		// without checking first.
		if err := adapter.RemovePeer(ctx, "nm0", peer.PublicKey); err != nil {
			t.Errorf("removing an absent peer must succeed: %v", err)
		}
	})
}

// The ownership rule, tested against a real interface: an operator may have
// their own WireGuard interfaces, and removing one would break their networking
// with no way for NostMesh to restore it.
func TestRefusesToTouchForeignInterface(t *testing.T) {
	requirePrivileges(t)

	withNamespace(t, func() {
		adapter, err := wireguard.NewLinuxAdapter()
		if err != nil {
			t.Fatalf("opening adapter: %v", err)
		}
		defer func() { _ = adapter.Close() }()

		ctx := context.Background()

		// Create an interface that does not carry the NostMesh prefix, as a
		// user's own wg0 would.
		foreign := testSpec(t, "wg0")
		if _, err := adapter.EnsureInterface(ctx, foreign); err == nil {
			t.Fatal("the adapter must refuse to configure a non-NostMesh interface")
		}

		if err := adapter.RemoveInterface(ctx, "wg0"); err == nil {
			t.Fatal("the adapter must refuse to remove a non-NostMesh interface")
		}
	})
}

func TestRemoveInterfaceIsIdempotent(t *testing.T) {
	requirePrivileges(t)

	withNamespace(t, func() {
		adapter, err := wireguard.NewLinuxAdapter()
		if err != nil {
			t.Fatalf("opening adapter: %v", err)
		}
		defer func() { _ = adapter.Close() }()

		ctx := context.Background()
		if _, err := adapter.EnsureInterface(ctx, testSpec(t, "nm0")); err != nil {
			t.Fatalf("creating interface: %v", err)
		}

		for attempt := 1; attempt <= 2; attempt++ {
			if err := adapter.RemoveInterface(ctx, "nm0"); err != nil {
				t.Fatalf("removal attempt %d: %v", attempt, err)
			}
		}

		if _, err := adapter.ObserveInterface(ctx, "nm0"); err == nil {
			t.Error("the interface must be gone after removal")
		}
	})
}

// Nothing may survive a test: a leaked interface would make the next run
// non-deterministic and, outside a namespace, would litter the host.
func TestNamespaceIsolationLeavesNoResidue(t *testing.T) {
	requirePrivileges(t)

	withNamespace(t, func() {
		adapter, err := wireguard.NewLinuxAdapter()
		if err != nil {
			t.Fatalf("opening adapter: %v", err)
		}
		defer func() { _ = adapter.Close() }()

		if _, err := adapter.EnsureInterface(context.Background(), testSpec(t, "nm-residue")); err != nil {
			t.Fatalf("creating interface: %v", err)
		}
	})

	// Back in the original namespace, the interface must not exist.
	adapter, err := wireguard.NewLinuxAdapter()
	if err != nil {
		t.Fatalf("opening adapter: %v", err)
	}
	defer func() { _ = adapter.Close() }()

	if _, err := adapter.ObserveInterface(context.Background(), "nm-residue"); err == nil {
		t.Error("an interface created inside a namespace leaked into the host")
	}
}

// A route installed through the adapter reaches the kernel and comes back.
//
// The fake models routes, and a fake validates the implementation against
// itself. This is the confrontation with the real thing: netlink installs it,
// netlink reports it, and netlink takes it away.
func TestAdapterInstallsAndRemovesARoute(t *testing.T) {
	requirePrivileges(t)

	withNamespace(t, func() {
		adapter, closeAdapter, err := wireguard.NewController()
		if err != nil {
			t.Fatalf("opening the controller: %v", err)
		}
		defer func() { _ = closeAdapter() }()

		ctx := context.Background()
		spec := testSpec(t, "nm-route")
		if _, err := adapter.EnsureInterface(ctx, spec); err != nil {
			t.Fatalf("creating the interface: %v", err)
		}

		prefix := netip.MustParsePrefix("10.77.0.0/16")

		// Before installing, the kernel does not have it. Asserted rather than
		// assumed: a HasRoute that always answered true would pass every other
		// check here.
		if had, err := adapter.HasRoute(ctx, "nm-route", prefix); err != nil {
			t.Fatalf("checking for the route: %v", err)
		} else if had {
			t.Fatal("the kernel reported a route nobody installed")
		}

		if err := adapter.AddRoute(ctx, "nm-route", prefix); err != nil {
			t.Fatalf("installing the route: %v", err)
		}

		if had, err := adapter.HasRoute(ctx, "nm-route", prefix); err != nil {
			t.Fatalf("checking for the route: %v", err)
		} else if !had {
			t.Error("the route was installed but the kernel does not report it")
		}

		// Idempotent, as the port promises.
		if err := adapter.AddRoute(ctx, "nm-route", prefix); err != nil {
			t.Errorf("installing the same route twice: %v", err)
		}

		if err := adapter.RemoveRoute(ctx, "nm-route", prefix); err != nil {
			t.Fatalf("removing the route: %v", err)
		}
		if had, err := adapter.HasRoute(ctx, "nm-route", prefix); err != nil {
			t.Fatalf("checking for the route: %v", err)
		} else if had {
			t.Error("the route is still in the kernel after removal")
		}

		// Removing an absent route succeeds, so compensation need not check.
		if err := adapter.RemoveRoute(ctx, "nm-route", prefix); err != nil {
			t.Errorf("removing an absent route: %v", err)
		}
	})
}

// The kernel takes an interface's routes with the interface.
//
// The behaviour the fake claims. Confronting it here is what makes the fake's
// version evidence rather than an assumption.
func TestRemovingAnInterfaceTakesItsRoutesInTheKernel(t *testing.T) {
	requirePrivileges(t)

	withNamespace(t, func() {
		adapter, closeAdapter, err := wireguard.NewController()
		if err != nil {
			t.Fatalf("opening the controller: %v", err)
		}
		defer func() { _ = closeAdapter() }()

		ctx := context.Background()
		if _, err := adapter.EnsureInterface(ctx, testSpec(t, "nm-route")); err != nil {
			t.Fatalf("creating the interface: %v", err)
		}

		prefix := netip.MustParsePrefix("10.78.0.0/16")
		if err := adapter.AddRoute(ctx, "nm-route", prefix); err != nil {
			t.Fatalf("installing the route: %v", err)
		}

		before := countRoutes(t)
		if err := adapter.RemoveInterface(ctx, "nm-route"); err != nil {
			t.Fatalf("removing the interface: %v", err)
		}

		if after := countRoutes(t); after >= before {
			t.Errorf("routes = %d before and %d after; removing a link must take its routes", before, after)
		}
		if had, err := adapter.HasRoute(ctx, "nm-route", prefix); err != nil {
			t.Fatalf("checking for the route: %v", err)
		} else if had {
			t.Error("a route survived the interface it pointed through")
		}
	})
}

// The adapter refuses to install a default route.
//
// NM-09's rule, and NM-25 leaves it in force here: policy may decide an operator
// is willing to be asked, but this is not where the asking happens, and a route
// capturing the tunnel's transport is a loop whatever decided it.
func TestAdapterRefusesADefaultRoute(t *testing.T) {
	requirePrivileges(t)

	withNamespace(t, func() {
		adapter, closeAdapter, err := wireguard.NewController()
		if err != nil {
			t.Fatalf("opening the controller: %v", err)
		}
		defer func() { _ = closeAdapter() }()

		ctx := context.Background()
		if _, err := adapter.EnsureInterface(ctx, testSpec(t, "nm-route")); err != nil {
			t.Fatalf("creating the interface: %v", err)
		}

		for _, route := range []string{"0.0.0.0/0", "::/0"} {
			err := adapter.AddRoute(ctx, "nm-route", netip.MustParsePrefix(route))
			if err == nil {
				t.Errorf("%s was installed; a default route captures the tunnel's own transport", route)
			}
		}
	})
}

// Observing an interface reports the routes the kernel holds for it.
//
// The fake models routes, and a fake validates the implementation against
// itself. This is the confrontation with netlink: install a route, observe, and
// require the observation to contain it.
//
// `nostmesh status` reads exactly this, so an observation that omitted routes
// would leave an operator unable to see the forwarding table at all.
func TestObservationReportsTheKernelRoutes(t *testing.T) {
	requirePrivileges(t)

	withNamespace(t, func() {
		adapter, closeAdapter, err := wireguard.NewController()
		if err != nil {
			t.Fatalf("opening the controller: %v", err)
		}
		defer func() { _ = closeAdapter() }()

		ctx := context.Background()
		if _, err := adapter.EnsureInterface(ctx, testSpec(t, "nm-observe")); err != nil {
			t.Fatalf("creating the interface: %v", err)
		}

		// Before installing anything, so a report that always returned the same
		// list would fail here rather than pass everything below.
		before, err := adapter.ObserveInterface(ctx, "nm-observe")
		if err != nil {
			t.Fatalf("observing: %v", err)
		}
		if len(before.Routes) != 0 {
			t.Fatalf("routes = %v before anything was installed", before.Routes)
		}

		wanted := []netip.Prefix{
			netip.MustParsePrefix("10.71.0.0/16"),
			netip.MustParsePrefix("10.72.0.0/16"),
		}
		for _, prefix := range wanted {
			if err := adapter.AddRoute(ctx, "nm-observe", prefix); err != nil {
				t.Fatalf("installing %s: %v", prefix, err)
			}
		}

		after, err := adapter.ObserveInterface(ctx, "nm-observe")
		if err != nil {
			t.Fatalf("observing: %v", err)
		}
		if len(after.Routes) != len(wanted) {
			t.Fatalf("routes = %v, want %v", after.Routes, wanted)
		}
		// Sorted, so two observations of one interface read the same way.
		for i, prefix := range wanted {
			if after.Routes[i] != prefix {
				t.Errorf("route %d = %s, want %s", i, after.Routes[i], prefix)
			}
		}

		// And a removal is reflected, so the report tracks the kernel rather
		// than accumulating what it has seen.
		if err := adapter.RemoveRoute(ctx, "nm-observe", wanted[0]); err != nil {
			t.Fatalf("removing: %v", err)
		}
		final, err := adapter.ObserveInterface(ctx, "nm-observe")
		if err != nil {
			t.Fatalf("observing: %v", err)
		}
		if len(final.Routes) != 1 || final.Routes[0] != wanted[1] {
			t.Errorf("routes = %v, want only %s after removal", final.Routes, wanted[1])
		}
	})
}
