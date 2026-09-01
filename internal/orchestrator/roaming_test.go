package orchestrator

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/luizosorio/nostmesh/internal/wireguard"
)

// A peer that moved keeps its session.
//
// That is the whole requirement: the same session id, the same tunnel keys and
// the same authorization, with only the route changed. Renegotiating instead
// would discard all three to learn a routing fact.
func TestFollowingAMovedEndpointKeepsTheSession(t *testing.T) {
	manager, controller := newTestManager(t)
	peer := nostrIdentity(t, 1)

	controller.PreexistingInterface("nm0", nil)
	establishedSession(t, manager, peer)
	before, _ := manager.Get(peer)

	moved := netip.MustParseAddrPort("203.0.113.77:51820")
	if err := manager.RecordObservedEndpoint(context.Background(), peer, moved, "nm0"); err != nil {
		t.Fatalf("following the endpoint: %v", err)
	}

	after, _ := manager.Get(peer)

	if after.SessionID != before.SessionID {
		t.Error("following a moved endpoint changed the session identity")
	}
	if *after.TunnelPublicKey != *before.TunnelPublicKey {
		t.Error("following a moved endpoint changed the tunnel key")
	}
	if after.Endpoint == nil || *after.Endpoint != moved {
		t.Errorf("endpoint is %v, want %s", after.Endpoint, moved)
	}
	if after.RoamCount != 1 {
		t.Errorf("roam count is %d, want 1", after.RoamCount)
	}
}

// What the peer may send does not change when it moves.
//
// The adapter replaces a peer's AllowedIPs wholesale, so a roam that reapplied
// an empty set would strip the peer's routing while looking like a success.
func TestFollowingPreservesWhatThePeerMaySend(t *testing.T) {
	manager, controller := newTestManager(t)
	peer := nostrIdentity(t, 1)

	controller.PreexistingInterface("nm0", nil)
	establishedSession(t, manager, peer)

	before, _ := manager.Get(peer)
	if len(before.AllowedIPs) == 0 {
		t.Fatal("the fixture established a session with no allowed prefixes")
	}

	if err := manager.RecordObservedEndpoint(context.Background(), peer,
		netip.MustParseAddrPort("203.0.113.77:51820"), "nm0"); err != nil {
		t.Fatalf("following: %v", err)
	}

	observed, err := controller.ObserveInterface(context.Background(), "nm0")
	if err != nil {
		t.Fatalf("observing: %v", err)
	}
	for _, applied := range observed.Peers {
		if len(applied.AllowedIPs) != len(before.AllowedIPs) {
			t.Errorf("the peer is routed %d prefixes after moving, was %d",
				len(applied.AllowedIPs), len(before.AllowedIPs))
		}
	}
}

// A move that keeps the NAT mapping open must survive the roam.
//
// applyRoam restates the peer without a keepalive, and the netlink adapter
// leaves the existing one alone when the spec carries zero. A peer behind NAT
// whose keepalive was silently dropped would stop refreshing its mapping and the
// session would die minutes later, far from the cause.
func TestFollowingPreservesTheKeepalive(t *testing.T) {
	manager, controller := newTestManager(t)
	peer := nostrIdentity(t, 1)

	controller.PreexistingInterface("nm0", nil)
	establishedSession(t, manager, peer)

	// As establish configures it.
	if err := controller.ApplyPeer(context.Background(), "nm0", wireguard.PeerSpec{
		PublicKey:           testTunnelKey(t, 50),
		AllowedIPs:          []netip.Prefix{netip.MustParsePrefix("100.96.0.2/32")},
		PersistentKeepalive: 25 * time.Second,
	}); err != nil {
		t.Fatalf("applying peer: %v", err)
	}

	if err := manager.RecordObservedEndpoint(context.Background(), peer,
		netip.MustParseAddrPort("203.0.113.77:51820"), "nm0"); err != nil {
		t.Fatalf("following: %v", err)
	}

	observed, err := controller.ObserveInterface(context.Background(), "nm0")
	if err != nil {
		t.Fatalf("observing: %v", err)
	}
	for _, applied := range observed.Peers {
		if applied.PersistentKeepalive != 25*time.Second {
			t.Errorf("keepalive is %s after moving, want 25s", applied.PersistentKeepalive)
		}
	}
}

// An endpoint that has not moved is not rewritten.
func TestAnUnmovedEndpointIsNotRewritten(t *testing.T) {
	manager, controller := newTestManager(t)
	peer := nostrIdentity(t, 1)

	controller.PreexistingInterface("nm0", nil)
	establishedSession(t, manager, peer)

	state, _ := manager.Get(peer)
	same := *state.Endpoint

	if err := manager.RecordObservedEndpoint(context.Background(), peer, same, "nm0"); err != nil {
		t.Fatalf("following: %v", err)
	}

	after, _ := manager.Get(peer)
	if after.RoamCount != 0 {
		t.Errorf("roam count is %d after no movement, want 0", after.RoamCount)
	}
}

// A path that oscillates is followed once per window, not once per poll.
//
// A host multihomed between two paths can alternate source addresses packet by
// packet. Following each one would rewrite kernel state every few seconds and
// grow the journal for a tunnel that is working perfectly well.
func TestAFlappingEndpointIsFollowedAtMostOncePerWindow(t *testing.T) {
	manager, controller, _ := newTestManagerWithJournal(t)
	peer := nostrIdentity(t, 1)

	controller.PreexistingInterface("nm0", nil)
	establishedSession(t, manager, peer)

	first := netip.MustParseAddrPort("203.0.113.1:51820")
	second := netip.MustParseAddrPort("203.0.113.2:51820")

	// The first move is followed; everything inside the window after it is not.
	if err := manager.RecordObservedEndpoint(context.Background(), peer, first, "nm0"); err != nil {
		t.Fatalf("first move: %v", err)
	}
	for i := range 6 {
		target := first
		if i%2 == 0 {
			target = second
		}
		err := manager.RecordObservedEndpoint(context.Background(), peer, target, "nm0")
		if err != nil && !errors.Is(err, ErrRoamingRejected) {
			t.Fatalf("unexpected error while flapping: %v", err)
		}
	}

	state, _ := manager.Get(peer)
	if state.RoamCount != 1 {
		t.Errorf("followed %d moves in one window, want 1", state.RoamCount)
	}
}

// A session that is not established is not followed.
//
// Writing kernel state for a session still negotiating would configure a peer
// the handshake has not finished authorizing.
func TestFollowingRefusesASessionThatIsNotEstablished(t *testing.T) {
	manager, controller := newTestManager(t)
	peer := nostrIdentity(t, 1)

	controller.PreexistingInterface("nm0", nil)
	if _, err := manager.Begin(peer, newSessionID(t)); err != nil {
		t.Fatalf("beginning: %v", err)
	}

	err := manager.RecordObservedEndpoint(context.Background(), peer,
		netip.MustParseAddrPort("203.0.113.77:51820"), "nm0")

	if !errors.Is(err, ErrRoamingRejected) {
		t.Errorf("expected ErrRoamingRejected, got: %v", err)
	}
}

// Following goes through the journal, like every other network change.
//
// A direct write would leave an endpoint no rollback could undo and no audit
// could explain.
func TestFollowingIsRecordedInTheJournal(t *testing.T) {
	manager, controller, journal := newTestManagerWithJournal(t)
	peer := nostrIdentity(t, 1)

	controller.PreexistingInterface("nm0", nil)
	establishedSession(t, manager, peer)

	before, err := journal.List()
	if err != nil {
		t.Fatalf("reading journal: %v", err)
	}

	if err := manager.RecordObservedEndpoint(context.Background(), peer,
		netip.MustParseAddrPort("203.0.113.77:51820"), "nm0"); err != nil {
		t.Fatalf("following: %v", err)
	}

	after, err := journal.List()
	if err != nil {
		t.Fatalf("reading journal: %v", err)
	}
	if len(after) <= len(before) {
		t.Error("the move was applied without a journal entry; it cannot be rolled back or audited")
	}
}

// Roam still refuses a candidate nothing verified.
//
// The two paths differ in what must be true before they run. Sharing their
// effect must not share their precondition, or the check that protects
// control-plane migration would be gone.
func TestRoamStillRefusesAnUnverifiedCandidate(t *testing.T) {
	manager, controller := newTestManager(t)
	peer := nostrIdentity(t, 1)

	controller.PreexistingInterface("nm0", nil)
	establishedSession(t, manager, peer)

	unverified := verifiedCandidate("203.0.113.90:51820")
	unverified.Status = "unverified"

	if err := manager.Roam(context.Background(), peer, unverified, "nm0"); !errors.Is(err, ErrRoamingRejected) {
		t.Errorf("an unverified candidate was accepted, got: %v", err)
	}
}
