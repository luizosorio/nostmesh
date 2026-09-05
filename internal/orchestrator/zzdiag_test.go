package orchestrator

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func TestZZDiagRoam(t *testing.T) {
	fixture := newHoldFixture(t)

	moved := netip.MustParseAddrPort("203.0.113.88:51820")
	if err := fixture.controller.MoveEndpoint("nm0", fixture.tunnel, moved); err != nil {
		t.Fatalf("moving: %v", err)
	}

	start := time.Now()
	obs, err := fixture.driver.observePeer(context.Background(), fixture.tunnel)
	t.Logf("observePeer took %s: err=%v endpoint=%v", time.Since(start), err, obs.Endpoint)

	start = time.Now()
	rerr := fixture.driver.manager.RecordObservedEndpoint(context.Background(), fixture.peer, moved, "nm0")
	t.Logf("RecordObservedEndpoint took %s: err=%v", time.Since(start), rerr)
}

// How long a single journalled apply costs here.
func TestZZDiagApplyCost(t *testing.T) {
	fixture := newHoldFixture(t)

	for i := range 3 {
		addr := netip.MustParseAddrPort("203.0.113.88:51820")
		if i == 1 {
			addr = netip.MustParseAddrPort("203.0.113.89:51820")
		}
		if i == 2 {
			addr = netip.MustParseAddrPort("203.0.113.90:51820")
		}
		fixture.clock.advance(time.Minute)
		start := time.Now()
		err := fixture.driver.manager.RecordObservedEndpoint(context.Background(), fixture.peer, addr, "nm0")
		t.Logf("apply %d took %s err=%v", i, time.Since(start), err)
	}
}
