package orchestrator

import (
	"context"
	"net/netip"
	"testing"
)

func TestZZDiagRoam(t *testing.T) {
	fixture := newHoldFixture(t)

	moved := netip.MustParseAddrPort("203.0.113.88:51820")
	if err := fixture.controller.MoveEndpoint("nm0", fixture.tunnel, moved); err != nil {
		t.Fatalf("moving: %v", err)
	}

	obs, err := fixture.driver.observePeer(context.Background(), fixture.tunnel)
	t.Logf("observePeer: err=%v endpoint=%v handshake=%v", err, obs.Endpoint, obs.HasHandshake())

	st, known := fixture.driver.manager.Get(fixture.peer)
	t.Logf("state: known=%v phase=%v endpoint=%v allowed=%v tunnelKey=%v",
		known, st.Phase, st.Endpoint, st.AllowedIPs, st.TunnelPublicKey != nil)

	t.Logf("netstate nil? %v", fixture.driver.manager.netstate == nil)

	iface, ierr := fixture.controller.ObserveInterface(context.Background(), "nm0")
	t.Logf("iface: err=%v ownedByUs=%v addrs=%v", ierr, iface.OwnedByUs, iface.Addresses)

	rerr := fixture.driver.manager.RecordObservedEndpoint(context.Background(), fixture.peer, moved, "nm0")
	t.Logf("RecordObservedEndpoint: err=%v", rerr)
}
