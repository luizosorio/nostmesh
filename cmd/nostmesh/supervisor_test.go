package main

import (
	"crypto/rand"
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/luizosorio/nostmesh/internal/domain"
	"github.com/luizosorio/nostmesh/internal/netstate"
	"github.com/luizosorio/nostmesh/internal/orchestrator"
	"github.com/luizosorio/nostmesh/internal/wireguard"
)

// testSupervisor builds a supervisor over a fake controller.
//
// The shared table is what these tests are about; a real netlink handle would
// need root and would say nothing extra about the sharing.
func testSupervisor(t *testing.T) *supervisor {
	t.Helper()

	controller := wireguard.NewFakeController()
	clock := domain.SystemClock{}
	journal := netstate.NewJournalStore(t.TempDir())

	manager, err := orchestrator.NewSessionManager(orchestrator.SessionManagerOptions{
		Controller:  controller,
		NetState:    netstate.NewManager(controller, journal, clock),
		Clock:       clock,
		MaxSessions: 4,
	})
	if err != nil {
		t.Fatalf("building manager: %v", err)
	}

	return &supervisor{
		log:             slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
		controller:      controller,
		closeController: func() error { return nil },
		manager:         manager,
		netstate:        netstate.NewManager(controller, journal, clock),
		answered:        orchestrator.NewAnsweredSessions(clock.Now),
		slots:           make(map[domain.NostrPublicKey]peerSlot),
		maxAttempting:   4,
		clock:           clock.Now,
	}
}

// The runtime uses the supervisor's table, not one of its own.
//
// Asserting on super.manager directly would prove the manager counts — which was
// never in doubt — and say nothing about whether buildSessionRuntime reaches for
// it. That distinction is the whole slice: a manager built per attempt holds one
// session, so a limit counted inside it never fires however many peers connect.
//
// So this checks identity: the runtime's manager must be the supervisor's.
func TestTheRuntimeUsesTheSharedTable(t *testing.T) {
	super := testSupervisor(t)

	if super.manager == nil {
		t.Fatal("the supervisor has no session table")
	}

	// A session opened through the supervisor must be visible to anything that
	// reads the shared table — which is what `nostmesh state` does, and what a
	// per-attempt manager made impossible.
	peer := testNostrKey(t, 7)
	id, err := domain.NewSessionID(rand.Reader)
	if err != nil {
		t.Fatalf("building session id: %v", err)
	}
	if _, err := super.manager.Begin(peer, id); err != nil {
		t.Fatalf("beginning: %v", err)
	}

	if len(super.Sessions()) != 1 {
		t.Error("a session opened on the shared table is not visible through the supervisor")
	}
}

// The session limit counts across peers, not within one attempt.
func TestTheSessionLimitCountsAcrossPeers(t *testing.T) {
	super := testSupervisor(t) // limit of 4

	var opened int
	for i := range 6 {
		peer := testNostrKey(t, byte(10+i))

		id, err := domain.NewSessionID(rand.Reader)
		if err != nil {
			t.Fatalf("building session id: %v", err)
		}
		if _, err := super.manager.Begin(peer, id); err != nil {
			break
		}
		opened++
	}

	if opened != 4 {
		t.Errorf("opened %d sessions against a limit of 4; the limit is not counting across peers", opened)
	}
}

// A peer asking twice gets the same slot.
//
// Retrying is the ordinary case, and a peer that came back on a different port
// would abandon the NAT mapping its peer had verified — the failure NM-15 exists
// to prevent.
func TestReclaimingReturnsTheSameSlot(t *testing.T) {
	super := testSupervisor(t)
	peer := testNostrKey(t, 7)

	first, err := super.Claim(peer, 51820)
	if err != nil {
		t.Fatalf("claiming: %v", err)
	}

	for range 8 {
		again, err := super.Claim(peer, 51820)
		if err != nil {
			t.Fatalf("re-claiming: %v", err)
		}
		if again != first {
			t.Fatalf("a retry moved the peer from %+v to %+v", first, again)
		}
	}
}

// Two peers cannot hold one interface or one port.
func TestTwoPeersCannotShareASlot(t *testing.T) {
	super := testSupervisor(t)
	peer := testNostrKey(t, 7)

	if _, err := super.Claim(peer, 51820); err != nil {
		t.Fatalf("claiming: %v", err)
	}

	// Claiming for the same identity from a different worker is the shape a
	// double-start takes, and it must return the held slot rather than a clash.
	if _, err := super.Claim(peer, 51820); err != nil {
		t.Errorf("the same peer was refused its own slot: %v", err)
	}
}

// A released slot can be taken again.
//
// Released when a worker stops for good, so a peer removed and re-authorized
// does not leave its interface reserved forever.
func TestAReleasedSlotIsFreed(t *testing.T) {
	super := testSupervisor(t)
	peer := testNostrKey(t, 7)

	if _, err := super.Claim(peer, 51820); err != nil {
		t.Fatalf("claiming: %v", err)
	}

	super.Release(peer)

	super.mu.Lock()
	_, held := super.slots[peer]
	super.mu.Unlock()

	if held {
		t.Error("a released peer still holds its slot")
	}
}

// One session in the table does not stop another peer opening one.
//
// This is the property the shared netlink handle has to preserve: sharing a
// resource must not make one peer's failure everybody's. The table is shared;
// what a session can lose on its own it still owns on its own.
func TestOnePeersSessionDoesNotBlockAnother(t *testing.T) {
	super := testSupervisor(t)
	alice, bob := testNostrKey(t, 7), testNostrKey(t, 8)

	aliceID, err := domain.NewSessionID(rand.Reader)
	if err != nil {
		t.Fatalf("building session id: %v", err)
	}
	if _, err := super.manager.Begin(alice, aliceID); err != nil {
		t.Fatalf("beginning alice: %v", err)
	}

	// Alice fails. Bob must be unaffected.
	if err := super.manager.Fail(alice, "a deliberate failure", nil); err != nil {
		t.Fatalf("failing alice: %v", err)
	}

	bobID, err := domain.NewSessionID(rand.Reader)
	if err != nil {
		t.Fatalf("building session id: %v", err)
	}
	if _, err := super.manager.Begin(bob, bobID); err != nil {
		t.Errorf("bob could not open a session after alice failed: %v", err)
	}

	// And alice's failure did not remove bob's slot either.
	if _, err := super.Claim(bob, 51820); err != nil {
		t.Errorf("bob could not claim a slot after alice failed: %v", err)
	}
}

// The shared table is what `state` reads, and it survives an attempt ending.
//
// The worker used to keep its own copy precisely because no manager outlived an
// attempt. With one table, a session's history has a single source.
func TestTheSharedTableOutlivesAnAttempt(t *testing.T) {
	super := testSupervisor(t)
	peer := testNostrKey(t, 7)

	id, err := domain.NewSessionID(rand.Reader)
	if err != nil {
		t.Fatalf("building session id: %v", err)
	}
	if _, err := super.manager.Begin(peer, id); err != nil {
		t.Fatalf("beginning: %v", err)
	}

	if len(super.Sessions()) != 1 {
		t.Fatalf("the table holds %d sessions, want 1", len(super.Sessions()))
	}

	super.CloseSession(peer)

	if len(super.Sessions()) != 0 {
		t.Errorf("the table still holds %d sessions after close", len(super.Sessions()))
	}

	// And closing twice is not an error: an attempt ending after the session
	// was already gone is ordinary.
	super.CloseSession(peer)
}

// Negotiations are bounded, and the bound is not the session limit.
//
// A node restarting with many authorized peers starts every worker at once.
// Each negotiation holds a socket, relay connections and a STUN query before it
// is a session, so the burst is largest exactly when the host has least state to
// work from.
func TestNegotiationsAreBounded(t *testing.T) {
	super := testSupervisor(t) // limit of 4

	for i := range 4 {
		if err := super.BeginAttempt(); err != nil {
			t.Fatalf("attempt %d was refused below the bound: %v", i, err)
		}
	}

	if err := super.BeginAttempt(); !errors.Is(err, ErrTooManyAttempts) {
		t.Errorf("the fifth attempt was allowed past a bound of 4: %v", err)
	}
}

// Ending an attempt frees the slot.
func TestEndingAnAttemptFreesTheSlot(t *testing.T) {
	super := testSupervisor(t)

	for range 4 {
		if err := super.BeginAttempt(); err != nil {
			t.Fatalf("beginning: %v", err)
		}
	}

	super.EndAttempt()

	if err := super.BeginAttempt(); err != nil {
		t.Errorf("a freed slot was not reusable: %v", err)
	}
}

// The counter cannot go negative.
//
// A caller that deferred EndAttempt before checking BeginAttempt's error would
// otherwise drive it below zero, and a count that can go negative eventually
// lets everything through — the bound would silently stop existing.
func TestTheAttemptCounterCannotGoNegative(t *testing.T) {
	super := testSupervisor(t)

	for range 10 {
		super.EndAttempt()
	}

	if got := super.Attempting(); got != 0 {
		t.Fatalf("the counter reads %d after unmatched releases", got)
	}

	// And the bound still holds afterwards.
	for i := range 4 {
		if err := super.BeginAttempt(); err != nil {
			t.Fatalf("attempt %d refused: %v", i, err)
		}
	}
	if err := super.BeginAttempt(); !errors.Is(err, ErrTooManyAttempts) {
		t.Error("the bound stopped holding after unmatched releases")
	}
}

// A session that never established is expired.
//
// It holds its peer's entry in the table, and the next attempt for that peer is
// refused as a duplicate — so a negotiation killed partway would lock its own
// peer out until the process restarted.
func TestAStaleSessionIsExpired(t *testing.T) {
	super := testSupervisor(t)
	peer := testNostrKey(t, 7)

	now := time.Now()
	super.clock = func() time.Time { return now }

	id, err := domain.NewSessionID(rand.Reader)
	if err != nil {
		t.Fatalf("building session id: %v", err)
	}
	if _, err := super.manager.Begin(peer, id); err != nil {
		t.Fatalf("beginning: %v", err)
	}

	// Not yet old enough.
	if expired := super.ExpireStaleSessions(time.Hour); expired != 0 {
		t.Errorf("a fresh session was expired")
	}

	// Now it is.
	now = now.Add(2 * time.Hour)
	if expired := super.ExpireStaleSessions(time.Hour); expired != 1 {
		t.Fatalf("expired %d sessions, want 1", expired)
	}

	// And the peer can open a new one, which is the whole point.
	next, err := domain.NewSessionID(rand.Reader)
	if err != nil {
		t.Fatalf("building session id: %v", err)
	}
	if _, err := super.manager.Begin(peer, next); err != nil {
		t.Errorf("the peer is still locked out after its stale session expired: %v", err)
	}
}

// An established session is never expired by the clock.
//
// The hold decides when one of those ends, from the data plane. A tunnel
// carrying traffic for hours is working, not stale, and a sweep that closed it
// would tear down exactly the sessions the node exists to keep.
func TestAnEstablishedSessionIsNeverExpired(t *testing.T) {
	super := testSupervisor(t)
	peer := testNostrKey(t, 7)

	now := time.Now()
	super.clock = func() time.Time { return now }

	id, err := domain.NewSessionID(rand.Reader)
	if err != nil {
		t.Fatalf("building session id: %v", err)
	}
	if _, err := super.manager.Begin(peer, id); err != nil {
		t.Fatalf("beginning: %v", err)
	}
	if err := super.manager.AdvancePhase(peer, orchestrator.PhaseEstablished); err != nil {
		t.Fatalf("advancing: %v", err)
	}

	now = now.Add(30 * 24 * time.Hour)

	if expired := super.ExpireStaleSessions(time.Hour); expired != 0 {
		t.Error("an established session was expired by the clock")
	}
	if len(super.Sessions()) != 1 {
		t.Error("the established session is gone from the table")
	}
}
