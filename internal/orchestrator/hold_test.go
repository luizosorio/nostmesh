package orchestrator

import (
	"context"
	"crypto/rand"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/luizosorio/nostmesh/internal/domain"
	"github.com/luizosorio/nostmesh/internal/wireguard"
)

// holdFixture is a driver with one established session on the fake data plane.
//
// It reaches the state Hold starts from without running a negotiation, so the
// tests below exercise holding rather than connecting.
type holdFixture struct {
	driver     *Driver
	controller *wireguard.FakeController
	clock      *fixedClock
	peer       domain.NostrPublicKey
	tunnel     domain.WireGuardPublicKey
}

func newHoldFixture(t *testing.T) *holdFixture {
	t.Helper()

	driver, controller, _, _, peer := newDriverFixture(t, true)

	clock, ok := driver.clock.(*fixedClock)
	if !ok {
		t.Fatal("fixture clock is not adjustable")
	}

	driver.options.HoldPollInterval = time.Millisecond
	driver.options.HandshakeStaleAfter = time.Minute
	driver.options.KeepaliveInterval = 25 * time.Second

	tunnel, _, err := deterministicKey()
	if err != nil {
		t.Fatalf("building tunnel key: %v", err)
	}

	sessionID, err := domain.NewSessionID(rand.Reader)
	if err != nil {
		t.Fatalf("building session id: %v", err)
	}
	if _, err := driver.manager.Begin(peer, sessionID); err != nil {
		t.Fatalf("beginning session: %v", err)
	}
	if err := driver.manager.BindTunnelKey(peer, tunnel); err != nil {
		t.Fatalf("binding key: %v", err)
	}
	// An established session always has these: the driver records the nominated
	// endpoint and the policy's prefixes before it configures anything. A
	// fixture without them would be a session shape production never produces.
	if err := driver.manager.SetAllowedIPs(peer, []netip.Prefix{netip.MustParsePrefix("100.96.0.2/32")}); err != nil {
		t.Fatalf("setting allowed ips: %v", err)
	}
	if err := driver.manager.RecordEndpoint(peer, verifiedCandidate("198.51.100.10:51820")); err != nil {
		t.Fatalf("recording endpoint: %v", err)
	}
	if err := driver.manager.AdvancePhase(peer, PhaseEstablished); err != nil {
		t.Fatalf("advancing: %v", err)
	}

	// The data plane, as the kernel would report it after a session came up.
	controller.HandshakeOnApply(clock.Now())
	if _, err := controller.EnsureInterface(context.Background(), wireguard.InterfaceSpec{
		Name:       "nm0",
		ListenPort: 51820,
		Addresses:  []netip.Prefix{netip.MustParsePrefix("100.96.0.1/32")},
	}); err != nil {
		t.Fatalf("creating interface: %v", err)
	}
	if err := controller.ApplyPeer(context.Background(), "nm0", wireguard.PeerSpec{
		PublicKey:           tunnel,
		AllowedIPs:          []netip.Prefix{netip.MustParsePrefix("100.96.0.2/32")},
		PersistentKeepalive: 25 * time.Second,
	}); err != nil {
		t.Fatalf("applying peer: %v", err)
	}

	return &holdFixture{driver: driver, controller: controller, clock: clock, peer: peer, tunnel: tunnel}
}

// hold runs Hold in the background and reports how it ended.
func (f *holdFixture) hold(ctx context.Context) <-chan error {
	done := make(chan error, 1)
	go func() { done <- f.driver.Hold(ctx, f.peer, nil) }()
	return done
}

// A session whose handshake keeps refreshing is held, not re-attempted.
//
// This is the whole point: Connect returning means the tunnel works, and
// treating that as a finished unit of work is what made the service tear down
// its own working session and then fail to bind the port it still held.
func TestHoldKeepsASessionThatKeepsHandshaking(t *testing.T) {
	fixture := newHoldFixture(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := fixture.hold(ctx)

	// Time passes well beyond the staleness limit, but the data plane keeps
	// rekeying the way a live path does.
	for range 5 {
		fixture.clock.advance(30 * time.Second)
		if err := fixture.controller.AdvanceHandshake("nm0", fixture.tunnel, fixture.clock.Now()); err != nil {
			t.Fatalf("advancing handshake: %v", err)
		}
		time.Sleep(5 * time.Millisecond)
	}

	select {
	case err := <-done:
		t.Fatalf("a live session was dropped: %v", err)
	default:
	}

	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Errorf("expected cancellation, got %v", err)
	}
}

// A handshake that stops refreshing means the path died.
func TestHoldEndsWhenTheHandshakeGoesStale(t *testing.T) {
	fixture := newHoldFixture(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := fixture.hold(ctx)

	// Nothing advances the handshake: the tunnel stopped carrying.
	fixture.clock.advance(2 * time.Minute)

	select {
	case err := <-done:
		if !errors.Is(err, ErrSessionDropped) {
			t.Errorf("expected ErrSessionDropped, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("a dead session was held indefinitely")
	}
}

// An interface that disappears ends the session.
func TestHoldEndsWhenTheInterfaceDisappears(t *testing.T) {
	fixture := newHoldFixture(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := fixture.hold(ctx)

	if err := fixture.controller.RemoveInterface(ctx, "nm0"); err != nil {
		t.Fatalf("removing interface: %v", err)
	}

	select {
	case err := <-done:
		if !errors.Is(err, ErrSessionDropped) {
			t.Errorf("expected ErrSessionDropped, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("the session outlived its interface")
	}
}

// A peer removed from the interface ends the session.
func TestHoldEndsWhenThePeerIsNoLongerConfigured(t *testing.T) {
	fixture := newHoldFixture(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := fixture.hold(ctx)

	if err := fixture.controller.RemovePeer(ctx, "nm0", fixture.tunnel); err != nil {
		t.Fatalf("removing peer: %v", err)
	}

	select {
	case err := <-done:
		if !errors.Is(err, ErrSessionDropped) {
			t.Errorf("expected ErrSessionDropped, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("the session outlived its peer")
	}
}

// One failed observation must not destroy a working tunnel.
//
// Netlink can fail transiently. Treating the first error as the session ending
// would tear down a healthy path because one read went wrong.
func TestATransientObservationFailureDoesNotDropTheSession(t *testing.T) {
	fixture := newHoldFixture(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fixture.controller.FailNext("ObserveInterface", observeFailureBudget-1, errors.New("netlink is busy"))

	done := fixture.hold(ctx)

	for range 4 {
		fixture.clock.advance(10 * time.Second)
		_ = fixture.controller.AdvanceHandshake("nm0", fixture.tunnel, fixture.clock.Now())
		time.Sleep(5 * time.Millisecond)
	}

	select {
	case err := <-done:
		t.Fatalf("a transient failure dropped a live session: %v", err)
	default:
	}

	cancel()
	<-done
}

// Observation that keeps failing does end the session.
func TestRepeatedObservationFailuresDropTheSession(t *testing.T) {
	fixture := newHoldFixture(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fixture.controller.FailOn["ObserveInterface"] = errors.New("netlink is gone")

	select {
	case err := <-fixture.hold(ctx):
		if !errors.Is(err, ErrSessionDropped) {
			t.Errorf("expected ErrSessionDropped, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("a session nobody could observe was held forever")
	}
}

// Cancellation returns promptly, because the supervisor waits on it.
//
// Revoking a peer cancels its worker and blocks until it stops before the
// notice is sent. A hold that only noticed cancellation on its next poll would
// make revocation as slow as the poll interval.
func TestHoldReturnsPromptlyOnCancellation(t *testing.T) {
	fixture := newHoldFixture(t)
	fixture.driver.options.HoldPollInterval = time.Hour

	ctx, cancel := context.WithCancel(context.Background())
	done := fixture.hold(ctx)

	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("expected cancellation, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("cancellation waited for the poll interval")
	}
}

// Without a keepalive an idle tunnel legitimately stops refreshing, so the
// staleness rule would tear down something that works.
//
// Losing the liveness check is the safe direction; killing healthy tunnels is
// not.
func TestHoldWithoutKeepaliveNeverDeclaresADrop(t *testing.T) {
	fixture := newHoldFixture(t)
	fixture.driver.options.KeepaliveInterval = 0

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := fixture.hold(ctx)

	// Hours pass with no handshake at all.
	fixture.clock.advance(6 * time.Hour)
	time.Sleep(20 * time.Millisecond)

	select {
	case err := <-done:
		t.Fatalf("an idle tunnel was torn down with no keepalive to judge it by: %v", err)
	default:
	}

	cancel()
	<-done
}

// Release removes the interface that holds the listen port.
//
// This is the regression test for the measured failure: an established session
// left its interface up, the interface kept port 51890, and every later attempt
// died with "address already in use".
func TestReleaseRemovesTheInterfaceHoldingThePort(t *testing.T) {
	fixture := newHoldFixture(t)

	if err := fixture.driver.Release(context.Background(), fixture.peer); err != nil {
		t.Fatalf("releasing: %v", err)
	}

	if _, err := fixture.controller.ObserveInterface(context.Background(), "nm0"); !errors.Is(err, wireguard.ErrInterfaceNotFound) {
		t.Error("the interface survived the session and still holds the port")
	}
	if _, known := fixture.driver.manager.Get(fixture.peer); known {
		t.Error("the manager still reports a session that ended")
	}
}

// Release must work when the context is already cancelled.
//
// It usually runs precisely because the caller was cancelled — on shutdown or
// revocation — and a teardown that gives up then is how a port stays claimed
// after the service stops.
//
// This asserts the call still happens; it cannot assert that cancellation was
// detached, because the fake controller ignores the context it is handed. That
// property is only observable against a real netlink socket, and is covered by
// the privileged suite.
func TestReleaseRunsEvenWhenTheContextIsCancelled(t *testing.T) {
	fixture := newHoldFixture(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := fixture.driver.Release(ctx, fixture.peer); err != nil {
		t.Fatalf("releasing under a cancelled context: %v", err)
	}
	if _, err := fixture.controller.ObserveInterface(context.Background(), "nm0"); !errors.Is(err, wireguard.ErrInterfaceNotFound) {
		t.Error("cancellation left the interface holding the port")
	}
}

// A hold follows an endpoint the kernel moved to.
//
// This is the defect the roaming work exists to fix: Roam was implemented,
// transactional and tested, and nothing ever called it. An endpoint that changed
// surfaced as a stale handshake, the session was torn down, and the worker
// renegotiated from nothing — discarding a session id, a key pair and an
// authorization to learn a route.
func TestAHeldSessionFollowsAMovedEndpoint(t *testing.T) {
	fixture := newHoldFixture(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := fixture.hold(ctx)

	moved := netip.MustParseAddrPort("203.0.113.88:51820")
	if err := fixture.controller.MoveEndpoint("nm0", fixture.tunnel, moved); err != nil {
		t.Fatalf("moving the endpoint: %v", err)
	}

	// The hold keeps the session alive while it follows.
	deadline := time.After(2 * time.Second)
	for {
		state, known := fixture.driver.manager.Get(fixture.peer)
		if known && state.Endpoint != nil && *state.Endpoint == moved {
			break
		}

		select {
		case err := <-done:
			t.Fatalf("the hold ended instead of following the move: %v", err)
		case <-deadline:
			t.Fatal("the endpoint moved and the session did not follow it")
		default:
		}

		fixture.clock.advance(time.Second)
		_ = fixture.controller.AdvanceHandshake("nm0", fixture.tunnel, fixture.clock.Now())
		time.Sleep(5 * time.Millisecond)
	}

	cancel()
	<-done
}

// A move that cannot be recorded does not end the session.
//
// The tunnel is already carrying on the new address — the kernel moved it after
// authenticating a packet. Failing to write down our agreement with that is a
// bookkeeping problem, and ending the hold over it would turn a successful roam
// into a teardown.
func TestAFailedFollowDoesNotEndTheSession(t *testing.T) {
	fixture := newHoldFixture(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := fixture.hold(ctx)

	fixture.controller.FailOn["ApplyPeer"] = errors.New("netlink refused the write")
	if err := fixture.controller.MoveEndpoint("nm0", fixture.tunnel,
		netip.MustParseAddrPort("203.0.113.99:51820")); err != nil {
		t.Fatalf("moving the endpoint: %v", err)
	}

	for range 5 {
		fixture.clock.advance(time.Second)
		_ = fixture.controller.AdvanceHandshake("nm0", fixture.tunnel, fixture.clock.Now())
		time.Sleep(5 * time.Millisecond)
	}

	select {
	case err := <-done:
		t.Fatalf("a bookkeeping failure ended a carrying session: %v", err)
	default:
	}

	cancel()
	<-done
}

// Roaming must not become a way for a dead session to look alive.
//
// Following an endpoint runs after the staleness check, never before, so a
// session whose handshake stopped refreshing is torn down rather than followed.
func TestAMovedEndpointDoesNotMaskAStaleHandshake(t *testing.T) {
	fixture := newHoldFixture(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := fixture.hold(ctx)

	if err := fixture.controller.MoveEndpoint("nm0", fixture.tunnel,
		netip.MustParseAddrPort("203.0.113.55:51820")); err != nil {
		t.Fatalf("moving the endpoint: %v", err)
	}

	// The endpoint moved, but nothing refreshes the handshake.
	fixture.clock.advance(2 * time.Minute)

	select {
	case err := <-done:
		if !errors.Is(err, ErrSessionDropped) {
			t.Errorf("expected ErrSessionDropped, got: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("a session with a stale handshake was held because its endpoint moved")
	}
}
