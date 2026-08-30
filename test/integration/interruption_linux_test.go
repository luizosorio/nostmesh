//go:build linux && privileged

// Tests that a run interrupted part-way leaves the host recoverable.
//
// The transactional logic is already tested against a fake controller, but a
// fake cannot leave half an interface configured and a real kernel can. These
// tests inject a failure at each step of a real apply and assert that nothing
// is left behind — which is the M0.3 gate criterion that the fake alone does
// not satisfy.
package integration

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"

	"github.com/luizosorio/nostmesh/internal/netstate"
	"github.com/luizosorio/nostmesh/internal/wireguard"
)

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

// interruptionFixture is a lab with a manager wired to the real adapter.
type interruptionFixture struct {
	adapter *wireguard.LinuxAdapter
	manager *netstate.Manager
	journal *netstate.JournalStore
	lab     *lab
}

func newInterruptionFixture(t *testing.T) *interruptionFixture {
	t.Helper()

	l := newLab(t)

	if err := netns.Set(l.alice); err != nil {
		t.Fatalf("entering alice's namespace: %v", err)
	}

	adapter, err := wireguard.NewLinuxAdapter()
	if err != nil {
		t.Fatalf("opening adapter: %v", err)
	}
	t.Cleanup(func() { _ = adapter.Close() })

	journal := netstate.NewJournalStore(filepath.Join(t.TempDir(), "journal"))

	return &interruptionFixture{
		adapter: adapter,
		manager: netstate.NewManager(adapter, journal, realClock{}),
		journal: journal,
		lab:     l,
	}
}

func (f *interruptionFixture) plan(t *testing.T, transactionID string) netstate.Plan {
	t.Helper()

	spec := wireguard.InterfaceSpec{
		Name:       "nm0",
		PrivateKey: f.lab.aliceKey,
		ListenPort: alicePort,
		Addresses:  []netip.Prefix{netip.MustParsePrefix(aliceOverlay)},
		MTU:        1420,
	}
	endpoint := netip.MustParseAddrPort(fmt.Sprintf("10.99.0.2:%d", bobPort))
	peers := []wireguard.PeerSpec{{
		PublicKey:  f.lab.bobPub,
		Endpoint:   &endpoint,
		AllowedIPs: []netip.Prefix{netip.MustParsePrefix(bobOverlay)},
	}}

	plan, err := f.manager.PlanInterface(context.Background(), transactionID, spec, peers)
	if err != nil {
		t.Fatalf("planning: %v", err)
	}
	return plan
}

// TestInterruptedApplyLeavesNoKernelState is the M0.3 gate criterion against a
// real kernel: failing at any step must leave no interface, address or route.
//
// The fake controller cannot demonstrate this. Only the kernel can be left with
// an interface that exists but was never configured.
func TestInterruptedApplyLeavesNoKernelState(t *testing.T) {
	requirePrivileges(t)

	for _, failAfter := range []netstate.OperationKind{
		netstate.OpCreateInterface,
		netstate.OpConfigureInterface,
		netstate.OpSetLinkUp,
		netstate.OpAddAddress,
		netstate.OpApplyPeer,
	} {
		t.Run(string(failAfter), func(t *testing.T) {
			f := newInterruptionFixture(t)
			ctx := context.Background()

			linksBefore := countLinks(t)
			routesBefore := countRoutes(t)

			plan := f.plan(t, "tx-interrupted")
			f.manager.InjectFailureAfter(failAfter)

			if _, err := f.manager.Apply(ctx, plan); err == nil {
				t.Fatalf("apply must fail when interrupted after %s", failAfter)
			}

			// The interface must be gone from the kernel, not merely from the
			// journal's point of view.
			if _, err := f.adapter.ObserveInterface(ctx, "nm0"); err == nil {
				t.Errorf("interface nm0 survived an interruption after %s", failAfter)
			} else if !errors.Is(err, wireguard.ErrInterfaceNotFound) {
				t.Errorf("unexpected error observing nm0: %v", err)
			}

			if got := countLinks(t); got != linksBefore {
				t.Errorf("link count changed: %d -> %d", linksBefore, got)
			}
			if got := countRoutes(t); got != routesBefore {
				t.Errorf("route count changed: %d -> %d", routesBefore, got)
			}

			// The journal must record the failure rather than a success.
			stored, err := f.journal.Load("tx-interrupted")
			if err != nil {
				t.Fatalf("loading journal: %v", err)
			}
			if stored.Committed {
				t.Error("an interrupted transaction must not be committed")
			}
			for _, op := range stored.Operations {
				if op.Status == netstate.StatusApplied {
					t.Errorf("%s remained applied after rollback", op.Kind)
				}
			}
		})
	}
}

// TestApplyAfterInterruptionConverges proves the recovery path end to end: a
// failed apply followed by a clean one leaves a working tunnel.
//
// This is what an operator actually does after a failure — retry — and it must
// not require manual cleanup first.
func TestApplyAfterInterruptionConverges(t *testing.T) {
	requirePrivileges(t)

	f := newInterruptionFixture(t)
	ctx := context.Background()

	f.manager.InjectFailureAfter(netstate.OpApplyPeer)
	if _, err := f.manager.Apply(ctx, f.plan(t, "tx-failed")); err == nil {
		t.Fatal("the first apply must fail")
	}

	// Retry without any manual intervention.
	transaction, err := f.manager.Apply(ctx, f.plan(t, "tx-retry"))
	if err != nil {
		t.Fatalf("retry after interruption must succeed: %v", err)
	}
	if !transaction.Committed {
		t.Error("the retry must commit")
	}

	state, err := f.adapter.ObserveInterface(ctx, "nm0")
	if err != nil {
		t.Fatalf("observing after retry: %v", err)
	}
	if len(state.Peers) != 1 {
		t.Errorf("peer count = %d, want 1", len(state.Peers))
	}
	if state.MTU != 1420 {
		t.Errorf("MTU = %d, want 1420", state.MTU)
	}
}

// TestPartialStateIsRecoverable simulates a process killed mid-apply: the
// interface exists, the journal says "applying", and nothing compensated.
//
// This is the state a crash leaves, which a graceful failure never produces,
// and the one where guessing from the host alone would be unsafe.
func TestPartialStateIsRecoverable(t *testing.T) {
	requirePrivileges(t)

	f := newInterruptionFixture(t)
	ctx := context.Background()

	// Create the interface outside any transaction, as a killed process would
	// have left it.
	if _, err := f.adapter.EnsureInterface(ctx, wireguard.InterfaceSpec{
		Name:       "nm0",
		PrivateKey: f.lab.aliceKey,
		ListenPort: alicePort,
		Addresses:  []netip.Prefix{netip.MustParsePrefix(aliceOverlay)},
		MTU:        1420,
	}); err != nil {
		t.Fatalf("creating partial state: %v", err)
	}

	// Write a journal entry stuck mid-flight.
	transaction := netstate.NewTransaction("tx-killed", "nm0", time.Now())
	if err := transaction.Plan(netstate.Operation{
		ID:     netstate.NewOperationID(netstate.OpCreateInterface, "nm0"),
		Kind:   netstate.OpCreateInterface,
		Target: "nm0",
	}, time.Now()); err != nil {
		t.Fatalf("planning: %v", err)
	}
	if err := transaction.MarkApplying(netstate.NewOperationID(netstate.OpCreateInterface, "nm0")); err != nil {
		t.Fatalf("marking applying: %v", err)
	}
	if err := f.journal.Save(transaction); err != nil {
		t.Fatalf("saving journal: %v", err)
	}

	pending, err := f.journal.PendingRecovery()
	if err != nil {
		t.Fatalf("reading journal: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("expected the interrupted transaction to be detected, got %d", len(pending))
	}

	// Removing what NostMesh owns returns the host to a known baseline.
	if err := f.adapter.RemoveInterface(ctx, "nm0"); err != nil {
		t.Fatalf("clearing partial state: %v", err)
	}
	if _, err := f.adapter.ObserveInterface(ctx, "nm0"); err == nil {
		t.Error("partial state survived removal")
	}
}

// TestInterruptionPreservesForeignInterface confirms the ownership rule holds
// under failure: rollback must not reach an interface NostMesh does not own.
func TestInterruptionPreservesForeignInterface(t *testing.T) {
	requirePrivileges(t)

	f := newInterruptionFixture(t)
	ctx := context.Background()

	// Stand in for an operator's own WireGuard interface.
	foreign := &netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: "wg-operator"}}
	if err := netlink.LinkAdd(foreign); err != nil {
		t.Skipf("cannot create a foreign interface: %v", err)
	}

	f.manager.InjectFailureAfter(netstate.OpApplyPeer)
	if _, err := f.manager.Apply(ctx, f.plan(t, "tx-interrupted")); err == nil {
		t.Fatal("apply must fail")
	}

	if _, err := netlink.LinkByName("wg-operator"); err != nil {
		t.Errorf("rollback removed an interface NostMesh does not own: %v", err)
	}
}

func countLinks(t *testing.T) int {
	t.Helper()

	links, err := netlink.LinkList()
	if err != nil {
		t.Fatalf("listing links: %v", err)
	}
	return len(links)
}

func countRoutes(t *testing.T) int {
	t.Helper()

	routes, err := netlink.RouteList(nil, netlink.FAMILY_ALL)
	if err != nil {
		t.Fatalf("listing routes: %v", err)
	}
	return len(routes)
}
