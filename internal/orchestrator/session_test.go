package orchestrator

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/luizosorio/nostmesh/internal/connectivity"
	"github.com/luizosorio/nostmesh/internal/domain"
	"github.com/luizosorio/nostmesh/internal/netstate"
	"github.com/luizosorio/nostmesh/internal/session"
	"github.com/luizosorio/nostmesh/internal/wireguard"
)

func nostrIdentity(t *testing.T, seed byte) domain.NostrPublicKey {
	t.Helper()

	var key domain.NostrPublicKey
	for i := range key {
		key[i] = seed + byte(i)
	}
	return key
}

func testTunnelKey(t *testing.T, seed byte) domain.WireGuardPublicKey {
	t.Helper()

	var key domain.WireGuardPublicKey
	for i := range key {
		key[i] = seed + byte(i)
	}
	return key
}

func newSessionID(t *testing.T) domain.SessionID {
	t.Helper()

	var id domain.SessionID
	for i := range id {
		id[i] = byte(i + 1)
	}
	return id
}

func verifiedCandidate(address string) connectivity.Candidate {
	return connectivity.Candidate{
		ID:      "c1",
		Kind:    connectivity.KindHost,
		Address: netip.MustParseAddrPort(address),
		Status:  connectivity.StatusValid,
	}
}

func unverifiedCandidate(address string) connectivity.Candidate {
	c := verifiedCandidate(address)
	c.Status = connectivity.StatusUnverified
	return c
}

func newTestManager(t *testing.T) (*SessionManager, *wireguard.FakeController) {
	manager, controller, _ := newTestManagerWithJournal(t)
	return manager, controller
}

// newTestManagerWithJournal also returns the journal, so a test can assert that
// a network change was recorded rather than written directly.
func newTestManagerWithJournal(t *testing.T) (*SessionManager, *wireguard.FakeController, *netstate.JournalStore) {
	t.Helper()

	controller := wireguard.NewFakeController()
	clock := &fixedClock{now: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}

	journal := netstate.NewJournalStore(t.TempDir())

	manager, err := NewSessionManager(SessionManagerOptions{
		Controller: controller,
		NetState:   netstate.NewManager(controller, journal, clock),
		Clock:      clock,
	})
	if err != nil {
		t.Fatalf("building manager: %v", err)
	}
	return manager, controller, journal
}

// establishedSession drives a session to the established phase.
func establishedSession(t *testing.T, manager *SessionManager, peer domain.NostrPublicKey) {
	t.Helper()

	if _, err := manager.Begin(peer, newSessionID(t)); err != nil {
		t.Fatalf("beginning session: %v", err)
	}
	if err := manager.BindTunnelKey(peer, testTunnelKey(t, 50)); err != nil {
		t.Fatalf("binding tunnel key: %v", err)
	}
	if err := manager.SetAllowedIPs(peer, []netip.Prefix{netip.MustParsePrefix("100.96.0.2/32")}); err != nil {
		t.Fatalf("setting allowed ips: %v", err)
	}
	if err := manager.RecordEndpoint(peer, verifiedCandidate("198.51.100.10:51820")); err != nil {
		t.Fatalf("recording endpoint: %v", err)
	}
	if err := manager.AdvancePhase(peer, PhaseEstablished); err != nil {
		t.Fatalf("advancing phase: %v", err)
	}
}

func TestSessionLifecycle(t *testing.T) {
	manager, _ := newTestManager(t)
	peer := nostrIdentity(t, 1)

	state, err := manager.Begin(peer, newSessionID(t))
	if err != nil {
		t.Fatalf("beginning: %v", err)
	}
	if state.Phase != PhaseAuthorizing {
		t.Errorf("initial phase = %s, want authorizing", state.Phase)
	}

	for _, phase := range []Phase{PhaseNegotiating, PhaseGathering, PhaseChecking, PhaseConfiguring, PhaseVerifying} {
		if err := manager.AdvancePhase(peer, phase); err != nil {
			t.Fatalf("advancing to %s: %v", phase, err)
		}
	}

	if err := manager.AdvancePhase(peer, PhaseEstablished); err != nil {
		t.Fatalf("establishing: %v", err)
	}

	final, known := manager.Get(peer)
	if !known {
		t.Fatal("the session must be tracked")
	}
	if !final.IsEstablished() {
		t.Errorf("phase = %s, want established", final.Phase)
	}
	if final.EstablishedAt == nil {
		t.Error("establishment time must be recorded")
	}
}

// An unverified candidate must not become an endpoint, whatever path it takes
// through the code.
func TestUnverifiedCandidateCannotBecomeEndpoint(t *testing.T) {
	manager, _ := newTestManager(t)
	peer := nostrIdentity(t, 1)

	if _, err := manager.Begin(peer, newSessionID(t)); err != nil {
		t.Fatalf("beginning: %v", err)
	}

	err := manager.RecordEndpoint(peer, unverifiedCandidate("198.51.100.10:51820"))
	if !errors.Is(err, connectivity.ErrUnverified) {
		t.Fatalf("expected ErrUnverified, got: %v", err)
	}

	state, _ := manager.Get(peer)
	if state.Endpoint != nil {
		t.Error("an unverified candidate was recorded as the endpoint")
	}
}

// A peer whose address changed is the same peer: the session identity, its
// authorization and its keys all persist. Forcing a new session would mean
// re-running policy and key exchange for what is a routing change.
func TestRoamingKeepsSessionIdentity(t *testing.T) {
	manager, controller := newTestManager(t)
	peer := nostrIdentity(t, 1)

	controller.PreexistingInterface("nm0", nil)
	establishedSession(t, manager, peer)

	before, _ := manager.Get(peer)

	moved := verifiedCandidate("203.0.113.50:51820")
	if err := manager.Roam(context.Background(), peer, moved, "nm0"); err != nil {
		t.Fatalf("roaming: %v", err)
	}

	after, _ := manager.Get(peer)

	if after.SessionID != before.SessionID {
		t.Error("roaming changed the session identity")
	}
	if *after.TunnelPublicKey != *before.TunnelPublicKey {
		t.Error("roaming changed the tunnel key")
	}
	if after.Endpoint.String() != "203.0.113.50:51820" {
		t.Errorf("endpoint = %s, want the new address", after.Endpoint)
	}
	if after.RoamCount != 1 {
		t.Errorf("roam count = %d, want 1", after.RoamCount)
	}
	if after.LastRoamAt == nil {
		t.Error("the roam must be timestamped")
	}
}

// Every network change is transactional, attributable and reversible — and a
// roam is a network change. Writing the new endpoint straight to the kernel
// would leave state that no rollback could undo and no audit could explain, so
// the roam must appear in the journal.
func TestRoamingIsRecordedInTheJournal(t *testing.T) {
	manager, controller, journal := newTestManagerWithJournal(t)
	peer := nostrIdentity(t, 1)

	controller.PreexistingInterface("nm0", nil)
	establishedSession(t, manager, peer)

	before, err := journal.List()
	if err != nil {
		t.Fatalf("listing journal: %v", err)
	}

	moved := verifiedCandidate("203.0.113.50:51820")
	if err := manager.Roam(context.Background(), peer, moved, "nm0"); err != nil {
		t.Fatalf("roaming: %v", err)
	}

	after, err := journal.List()
	if err != nil {
		t.Fatalf("listing journal: %v", err)
	}

	if len(after) <= len(before) {
		t.Fatal("the roam wrote to the kernel without a journal entry; it cannot be rolled back or audited")
	}

	// The entry must record the peer application, or the journal knows a
	// transaction happened without knowing what to undo.
	var recorded bool
	for _, transaction := range after {
		for _, op := range transaction.Operations {
			if op.Kind == netstate.OpApplyPeer {
				recorded = true
			}
		}
	}
	if !recorded {
		t.Error("the journal entry does not record the peer application")
	}
}

// A roam must refuse an interface NostMesh does not own, exactly as every other
// network change does. Roaming is not an exception to that rule.
func TestRoamingRefusesForeignInterface(t *testing.T) {
	manager, controller, _ := newTestManagerWithJournal(t)
	peer := nostrIdentity(t, 1)

	// An interface whose name is not ours: observed, but not owned.
	controller.PreexistingInterface("eth0", nil)
	establishedSession(t, manager, peer)

	err := manager.Roam(context.Background(), peer, verifiedCandidate("203.0.113.50:51820"), "eth0")
	if err == nil {
		t.Fatal("roaming onto a foreign interface must be refused")
	}
}

// Accepting an unverified endpoint would let anyone who can forge a packet
// redirect an established tunnel — a worse attack than anything the handshake
// defends against.
func TestRoamingRefusesUnverifiedEndpoint(t *testing.T) {
	manager, controller := newTestManager(t)
	peer := nostrIdentity(t, 1)

	controller.PreexistingInterface("nm0", nil)
	establishedSession(t, manager, peer)

	before, _ := manager.Get(peer)

	err := manager.Roam(context.Background(), peer, unverifiedCandidate("203.0.113.99:51820"), "nm0")
	if !errors.Is(err, ErrRoamingRejected) {
		t.Fatalf("expected ErrRoamingRejected, got: %v", err)
	}

	after, _ := manager.Get(peer)
	if after.Endpoint.String() != before.Endpoint.String() {
		t.Error("a refused roam changed the endpoint")
	}
	if after.RoamCount != 0 {
		t.Error("a refused roam was counted")
	}
}

// Roaming applies only to an established session: one still negotiating has no
// tunnel to move.
func TestRoamingRequiresEstablishedSession(t *testing.T) {
	manager, _ := newTestManager(t)
	peer := nostrIdentity(t, 1)

	if _, err := manager.Begin(peer, newSessionID(t)); err != nil {
		t.Fatalf("beginning: %v", err)
	}

	err := manager.Roam(context.Background(), peer, verifiedCandidate("203.0.113.50:51820"), "nm0")
	if !errors.Is(err, ErrRoamingRejected) {
		t.Errorf("expected ErrRoamingRejected, got: %v", err)
	}
}

// Roaming to the address already in use is a no-op rather than a needless
// kernel write.
func TestRoamingToSameAddressIsNoOp(t *testing.T) {
	manager, controller := newTestManager(t)
	peer := nostrIdentity(t, 1)

	controller.PreexistingInterface("nm0", nil)
	establishedSession(t, manager, peer)

	same := verifiedCandidate("198.51.100.10:51820")
	if err := manager.Roam(context.Background(), peer, same, "nm0"); err != nil {
		t.Fatalf("roaming: %v", err)
	}

	state, _ := manager.Get(peer)
	if state.RoamCount != 0 {
		t.Errorf("roam count = %d; moving to the same address is not a roam", state.RoamCount)
	}
}

// A peer moving does not change what it may send.
func TestRoamingPreservesAllowedIPs(t *testing.T) {
	manager, controller := newTestManager(t)
	peer := nostrIdentity(t, 1)

	controller.PreexistingInterface("nm0", nil)
	establishedSession(t, manager, peer)

	before, _ := manager.Get(peer)

	if err := manager.Roam(context.Background(), peer, verifiedCandidate("203.0.113.50:51820"), "nm0"); err != nil {
		t.Fatalf("roaming: %v", err)
	}

	after, _ := manager.Get(peer)
	if len(after.AllowedIPs) != len(before.AllowedIPs) {
		t.Fatalf("allowed IPs changed: %v -> %v", before.AllowedIPs, after.AllowedIPs)
	}
	for i := range after.AllowedIPs {
		if after.AllowedIPs[i] != before.AllowedIPs[i] {
			t.Errorf("allowed IP %d changed from %s to %s", i, before.AllowedIPs[i], after.AllowedIPs[i])
		}
	}
}

// Substitution mid-session is the attack the handshake binding prevents, and it
// must not be reachable through the session manager either.
func TestTunnelKeySubstitutionIsRefused(t *testing.T) {
	manager, _ := newTestManager(t)
	peer := nostrIdentity(t, 1)

	if _, err := manager.Begin(peer, newSessionID(t)); err != nil {
		t.Fatalf("beginning: %v", err)
	}
	if err := manager.BindTunnelKey(peer, testTunnelKey(t, 50)); err != nil {
		t.Fatalf("binding: %v", err)
	}

	err := manager.BindTunnelKey(peer, testTunnelKey(t, 200))
	if !errors.Is(err, session.ErrKeySubstituted) {
		t.Errorf("expected ErrKeySubstituted, got: %v", err)
	}

	// Rebinding the same key is idempotent, since relays duplicate messages.
	if err := manager.BindTunnelKey(peer, testTunnelKey(t, 50)); err != nil {
		t.Errorf("rebinding the same key must be idempotent: %v", err)
	}
}

// A default route through a peer would capture the tunnel's own transport.
func TestDefaultRouteIsRefused(t *testing.T) {
	manager, _ := newTestManager(t)
	peer := nostrIdentity(t, 1)

	if _, err := manager.Begin(peer, newSessionID(t)); err != nil {
		t.Fatalf("beginning: %v", err)
	}

	for _, prefix := range []string{"0.0.0.0/0", "::/0"} {
		t.Run(prefix, func(t *testing.T) {
			err := manager.SetAllowedIPs(peer, []netip.Prefix{netip.MustParsePrefix(prefix)})
			if err == nil {
				t.Errorf("a default route (%s) must be refused", prefix)
			}
		})
	}
}

func TestDuplicateSessionIsRefused(t *testing.T) {
	manager, _ := newTestManager(t)
	peer := nostrIdentity(t, 1)

	if _, err := manager.Begin(peer, newSessionID(t)); err != nil {
		t.Fatalf("beginning: %v", err)
	}

	if _, err := manager.Begin(peer, newSessionID(t)); !errors.Is(err, ErrSessionExists) {
		t.Errorf("expected ErrSessionExists, got: %v", err)
	}
}

// A failed session may be retried, which is what an operator does after fixing
// whatever caused the failure.
func TestFailedSessionCanBeRetried(t *testing.T) {
	manager, _ := newTestManager(t)
	peer := nostrIdentity(t, 1)

	if _, err := manager.Begin(peer, newSessionID(t)); err != nil {
		t.Fatalf("beginning: %v", err)
	}
	if err := manager.Fail(peer, "no candidate verified", nil); err != nil {
		t.Fatalf("failing: %v", err)
	}

	if _, err := manager.Begin(peer, newSessionID(t)); err != nil {
		t.Errorf("a failed session must be retryable: %v", err)
	}
}

// The failure has to say why, with the candidate diagnostics that explain it.
func TestFailureRecordsDiagnostics(t *testing.T) {
	manager, _ := newTestManager(t)
	peer := nostrIdentity(t, 1)

	if _, err := manager.Begin(peer, newSessionID(t)); err != nil {
		t.Fatalf("beginning: %v", err)
	}

	diagnostics := []connectivity.Candidate{{
		ID:            "srflx",
		Kind:          connectivity.KindServerReflexive,
		Address:       netip.MustParseAddrPort("198.51.100.10:51820"),
		Status:        connectivity.StatusFailed,
		Source:        "stun.example.invalid",
		FailureReason: "no response within timeout",
	}}

	if err := manager.Fail(peer, "no candidate verified", diagnostics); err != nil {
		t.Fatalf("failing: %v", err)
	}

	state, _ := manager.Get(peer)
	if state.Phase != PhaseFailed {
		t.Errorf("phase = %s, want failed", state.Phase)
	}
	if len(state.Diagnostics) != 1 {
		t.Fatalf("%d diagnostics recorded, want 1", len(state.Diagnostics))
	}
	if state.Diagnostics[0].Source == "" {
		t.Error("the diagnostic must say who suggested the candidate")
	}
}

func TestSessionLimitIsEnforced(t *testing.T) {
	controller := wireguard.NewFakeController()

	manager, err := NewSessionManager(SessionManagerOptions{
		Controller:  controller,
		Clock:       &fixedClock{now: time.Now()},
		MaxSessions: 2,
	})
	if err != nil {
		t.Fatalf("building manager: %v", err)
	}

	for i := range 2 {
		if _, err := manager.Begin(nostrIdentity(t, byte(i*40+1)), newSessionID(t)); err != nil {
			t.Fatalf("beginning session %d: %v", i, err)
		}
	}

	if _, err := manager.Begin(nostrIdentity(t, 200), newSessionID(t)); err == nil {
		t.Error("exceeding the session limit must be refused")
	}
}

func TestUnknownSessionIsReported(t *testing.T) {
	manager, _ := newTestManager(t)
	peer := nostrIdentity(t, 1)

	if err := manager.AdvancePhase(peer, PhaseNegotiating); !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("expected ErrSessionNotFound, got: %v", err)
	}
	if _, known := manager.Get(peer); known {
		t.Error("an unknown session must not be reported as known")
	}
}
