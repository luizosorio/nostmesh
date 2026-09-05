package orchestrator

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/luizosorio/nostmesh/internal/netstate"
	"github.com/luizosorio/nostmesh/internal/wireguard"
)

// How many journal writes a roam costs, and what each one costs.
func TestZZDiagJournalCost(t *testing.T) {
	dir := t.TempDir()
	store := netstate.NewJournalStore(dir)

	tx := netstate.NewTransaction("diag", "nm0", time.Now())

	start := time.Now()
	if err := store.Save(tx); err != nil {
		t.Fatalf("save: %v", err)
	}
	t.Logf("one journal Save took %s (tmpdir=%s)", time.Since(start), dir)

	start = time.Now()
	for range 10 {
		_ = store.Save(tx)
	}
	t.Logf("ten journal Saves took %s", time.Since(start))
}

// How many operations a roam plan contains.
func TestZZDiagPlanSize(t *testing.T) {
	fixture := newHoldFixture(t)

	iface, err := fixture.controller.ObserveInterface(context.Background(), "nm0")
	if err != nil {
		t.Fatalf("observe: %v", err)
	}

	spec := wireguard.InterfaceSpec{
		Name: iface.Name, ListenPort: iface.ListenPort,
		Addresses: iface.Addresses, MTU: iface.MTU,
	}
	endpoint := netip.MustParseAddrPort("203.0.113.88:51820")
	peer := wireguard.PeerSpec{
		PublicKey: fixture.tunnel, Endpoint: &endpoint,
		AllowedIPs: iface.Peers[0].AllowedIPs,
	}

	plan, err := fixture.driver.manager.netstate.PlanInterface(
		context.Background(), "diag-plan", spec, []wireguard.PeerSpec{peer})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	t.Logf("roam plan has %d operations", len(plan.Operations))
	for _, op := range plan.Operations {
		t.Logf("  %s %s", op.Kind, op.Target)
	}
}
