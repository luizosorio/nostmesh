package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/luizosorio/nostmesh/internal/connectivity"
	"github.com/luizosorio/nostmesh/internal/domain"
	"github.com/luizosorio/nostmesh/internal/netstate"
	"github.com/luizosorio/nostmesh/internal/session"
	"github.com/luizosorio/nostmesh/internal/wireguard"
)

// Phase names where a connection attempt stands.
//
// Phases exist so a failure can say what was being attempted. "Could not
// connect" is useless; "gathering candidates failed because no observer
// answered" tells an operator what to fix.
type Phase string

const (
	// PhaseAuthorizing is checking local policy.
	PhaseAuthorizing Phase = "authorizing"

	// PhaseNegotiating is exchanging session messages over relays.
	PhaseNegotiating Phase = "negotiating"

	// PhaseGathering is discovering candidate addresses.
	PhaseGathering Phase = "gathering"

	// PhaseChecking is probing candidates.
	PhaseChecking Phase = "checking"

	// PhaseConfiguring is applying the tunnel transactionally.
	PhaseConfiguring Phase = "configuring"

	// PhaseVerifying is confirming the tunnel carries traffic.
	//
	// Separate from configuring because a configured interface that does not
	// pass packets is exactly the failure MVP 0 found the hard way.
	PhaseVerifying Phase = "verifying"

	// PhaseEstablished means the tunnel is confirmed working.
	PhaseEstablished Phase = "established"

	// PhaseFailed means the attempt ended without a tunnel.
	PhaseFailed Phase = "failed"
)

var (
	// ErrSessionExists reports a second attempt for a peer already connected.
	ErrSessionExists = errors.New("a session with this peer already exists")

	// ErrSessionNotFound reports an unknown session.
	ErrSessionNotFound = errors.New("session not found")

	// ErrRoamingRejected reports an endpoint change that was not accepted.
	ErrRoamingRejected = errors.New("endpoint change rejected")
)

// SessionState is what the orchestrator knows about one session.
type SessionState struct {
	// Peer is the remote identity.
	Peer domain.NostrPublicKey

	// SessionID identifies the session.
	SessionID domain.SessionID

	// Phase is where the attempt stands.
	Phase Phase

	// Endpoint is the verified path, once one exists.
	Endpoint *netip.AddrPort

	// TunnelPublicKey is the peer's WireGuard key, once bound.
	TunnelPublicKey *domain.WireGuardPublicKey

	// FailureReason explains a failed attempt in operator terms.
	FailureReason string

	// Diagnostics records what each candidate did, so "why did this not
	// connect" has an answer.
	Diagnostics []connectivity.Candidate

	StartedAt     time.Time
	EstablishedAt *time.Time
	LastRoamAt    *time.Time

	// RoamCount tracks how often the endpoint moved. A session that roams
	// constantly is a signal worth surfacing rather than hiding.
	RoamCount int

	// AllowedIPs are the prefixes routed to this peer, derived from local
	// policy when the session was authorized. They are stored here because a
	// peer moving does not change what it may send, so roaming must reapply
	// exactly these rather than recompute anything.
	AllowedIPs []netip.Prefix
}

// IsEstablished reports whether the tunnel is confirmed working.
func (s SessionState) IsEstablished() bool { return s.Phase == PhaseEstablished }

// SessionManager tracks active sessions and handles roaming.
//
// It owns the mapping from peer to session, which is what makes a duplicate
// connection attempt detectable and an endpoint change attributable to a
// session rather than guessed at.
type SessionManager struct {
	mu sync.RWMutex

	sessions map[domain.NostrPublicKey]*SessionState

	// handshakes holds the protocol state for sessions still negotiating.
	handshakes map[domain.NostrPublicKey]*session.Handshake

	controller wireguard.Controller
	clock      domain.Clock

	// netstate applies network changes transactionally. Roaming rewrites a live
	// peer's endpoint, which is a network change like any other and therefore
	// goes through the journal rather than straight to the controller.
	netstate *netstate.Manager

	// maxSessions bounds concurrent sessions, since each holds kernel state.
	maxSessions int

	// minRoamInterval bounds how often a session follows a moved endpoint.
	minRoamInterval time.Duration
}

// defaultMinRoamInterval is the hysteresis a session applies to roaming.
//
// Comfortably longer than the hold's poll interval, so an oscillating path
// produces one write per window instead of one per poll, and far shorter than
// the staleness bound that tears a session down — so waiting out the window can
// never cost a session that a genuine move would have saved.
const defaultMinRoamInterval = 15 * time.Second

// SessionManagerOptions configures a SessionManager.
type SessionManagerOptions struct {
	Controller wireguard.Controller

	// NetState applies roaming changes transactionally. Required: without it a
	// roam would write to the kernel outside the journal, leaving a change that
	// cannot be attributed or reversed.
	NetState *netstate.Manager

	Clock       domain.Clock
	MaxSessions int

	// MinRoamInterval is how long a session must hold an endpoint before it may
	// follow another. A host multihomed between two paths can alternate source
	// addresses packet by packet, and without a bound every poll would rewrite
	// kernel state and grow the journal for a tunnel that is working fine.
	//
	// The kernel flaps regardless of what this does; the bound protects this
	// node's own record, not the tunnel.
	MinRoamInterval time.Duration
}

// NewSessionManager builds a SessionManager.
func NewSessionManager(opts SessionManagerOptions) (*SessionManager, error) {
	if opts.Controller == nil {
		return nil, errors.New("session manager requires a wireguard controller")
	}
	if opts.Clock == nil {
		opts.Clock = domain.SystemClock{}
	}
	if opts.MinRoamInterval == 0 {
		opts.MinRoamInterval = defaultMinRoamInterval
	}
	if opts.MaxSessions <= 0 {
		opts.MaxSessions = 64
	}

	return &SessionManager{
		sessions:        make(map[domain.NostrPublicKey]*SessionState),
		handshakes:      make(map[domain.NostrPublicKey]*session.Handshake),
		controller:      opts.Controller,
		netstate:        opts.NetState,
		clock:           opts.Clock,
		maxSessions:     opts.MaxSessions,
		minRoamInterval: opts.MinRoamInterval,
	}, nil
}

// Begin registers a new session attempt.
func (m *SessionManager) Begin(peer domain.NostrPublicKey, sessionID domain.SessionID) (*SessionState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if existing, active := m.sessions[peer]; active && existing.Phase != PhaseFailed {
		return nil, fmt.Errorf("%w: %s is in phase %s", ErrSessionExists, peer.Short(), existing.Phase)
	}
	if len(m.sessions) >= m.maxSessions {
		return nil, fmt.Errorf("session limit of %d reached", m.maxSessions)
	}

	state := &SessionState{
		Peer:      peer,
		SessionID: sessionID,
		Phase:     PhaseAuthorizing,
		StartedAt: m.clock.Now(),
	}
	m.sessions[peer] = state

	snapshot := *state
	return &snapshot, nil
}

// trackHandshake associates protocol state with a session.
//
// The manager holds it so that a message arriving for a session can be routed
// to the handshake that expects it, and so a session torn down releases its
// protocol state with everything else.
func (m *SessionManager) trackHandshake(peer domain.NostrPublicKey, handshake *session.Handshake) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.handshakes[peer] = handshake
}

// Handshake returns the protocol state for a session, if it is still
// negotiating.
func (m *SessionManager) Handshake(peer domain.NostrPublicKey) (*session.Handshake, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	handshake, known := m.handshakes[peer]
	return handshake, known
}

// AdvancePhase records progress.
func (m *SessionManager) AdvancePhase(peer domain.NostrPublicKey, phase Phase) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	state, known := m.sessions[peer]
	if !known {
		return fmt.Errorf("%w: %s", ErrSessionNotFound, peer.Short())
	}

	state.Phase = phase
	if phase == PhaseEstablished {
		now := m.clock.Now()
		state.EstablishedAt = &now
	}
	return nil
}

// RecordEndpoint stores the verified path.
//
// It refuses to record anything the connectivity engine did not verify: the
// caller passes a candidate, and only a valid one is accepted.
func (m *SessionManager) RecordEndpoint(peer domain.NostrPublicKey, candidate connectivity.Candidate) error {
	if !candidate.Status.Permits() {
		return fmt.Errorf("%w: candidate %s is %s",
			connectivity.ErrUnverified, candidate.ID, candidate.Status)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	state, known := m.sessions[peer]
	if !known {
		return fmt.Errorf("%w: %s", ErrSessionNotFound, peer.Short())
	}

	endpoint := candidate.Address
	state.Endpoint = &endpoint
	return nil
}

// Roam updates a session's endpoint after the peer moved.
//
// The session identity does not change. That is the point: a peer whose address
// changed is the same peer, with the same authorization and the same tunnel
// keys, and forcing a new session would mean re-running policy and key exchange
// for what is a routing change.
//
// The new endpoint must be verified first. Accepting an unverified one would
// let anyone who can forge a packet redirect an established tunnel, which is a
// worse attack than anything the handshake defends against.
func (m *SessionManager) Roam(ctx context.Context, peer domain.NostrPublicKey,
	candidate connectivity.Candidate, iface string,
) error {
	if !candidate.Status.Permits() {
		return fmt.Errorf("%w: candidate %s is %s",
			ErrRoamingRejected, candidate.ID, candidate.Status)
	}

	return m.applyEndpointChange(ctx, peer, candidate.Address, iface, false)
}

// RecordObservedEndpoint follows an endpoint the kernel has already moved to.
//
// WireGuard updates a peer's endpoint on its own, but only after authenticating
// a packet from the new address under that session's tunnel keys. Whoever can do
// that holds the tunnel; whoever cannot — anyone spoofing a source address,
// flooding the port or replaying stale traffic — moves nothing, because the
// kernel discards what it cannot authenticate.
//
// So this records a move that already happened rather than authorizing one, and
// that is why the candidate check in Roam has no place here. Passing a synthetic
// candidate marked verified would satisfy that guard by deceiving it, and leave
// a future reader holding a candidate that nothing verified. See NM-20.
//
// Writing it back matters even though the tunnel already works: a stored
// endpoint the peer has left is a value a later reconciliation would push back
// into the kernel, undoing a move the kernel got right.
func (m *SessionManager) RecordObservedEndpoint(ctx context.Context, peer domain.NostrPublicKey,
	observed netip.AddrPort, iface string,
) error {
	return m.applyEndpointChange(ctx, peer, observed, iface, true)
}

// applyEndpointChange rewrites a live session's endpoint through the journal.
//
// Shared by the two ways an endpoint moves — one this node chose after proving
// the path, one the kernel adopted after authenticating a packet. They differ in
// what must be true before they may run, which is why that check stays with each
// caller; they agree entirely on what to do afterwards.
func (m *SessionManager) applyEndpointChange(ctx context.Context, peer domain.NostrPublicKey,
	address netip.AddrPort, iface string, observed bool,
) error {
	m.mu.Lock()
	state, known := m.sessions[peer]
	if !known {
		m.mu.Unlock()
		return fmt.Errorf("%w: %s", ErrSessionNotFound, peer.Short())
	}
	if state.Phase != PhaseEstablished {
		m.mu.Unlock()
		return fmt.Errorf("%w: session is in phase %s, not established",
			ErrRoamingRejected, state.Phase)
	}
	if state.TunnelPublicKey == nil {
		m.mu.Unlock()
		return fmt.Errorf("%w: session has no bound tunnel key", ErrRoamingRejected)
	}

	// Hysteresis, for a move the kernel made rather than one this node chose.
	// A path that oscillates would otherwise rewrite kernel state on every poll
	// and grow the journal for a tunnel that is working. The record is left
	// stale deliberately: the next poll past the window still sees the
	// difference and follows it.
	if observed && state.LastRoamAt != nil {
		if since := m.clock.Now().Sub(*state.LastRoamAt); since < m.minRoamInterval {
			m.mu.Unlock()
			return fmt.Errorf("%w: %s moved %s ago, minimum interval is %s",
				ErrRoamingRejected, peer.Short(), since.Truncate(time.Second), m.minRoamInterval)
		}
	}

	tunnelKey := *state.TunnelPublicKey
	previous := state.Endpoint
	allowed := make([]netip.Prefix, len(state.AllowedIPs))
	copy(allowed, state.AllowedIPs)
	m.mu.Unlock()

	// Nothing to do if the endpoint has not actually moved.
	if previous != nil && *previous == address {
		return nil
	}

	// The adapter replaces a peer's AllowedIPs wholesale, so applying an empty
	// set would strip what the peer is routed rather than leave it alone. A
	// session that reached ESTABLISHED has them; reaching here without them
	// means something upstream lost them, and stopping is the safe answer.
	if len(allowed) == 0 {
		return fmt.Errorf("%w: session for %s has no allowed prefixes to reapply",
			ErrRoamingRejected, peer.Short())
	}

	// The kernel is updated with the same peer key at a new address. The
	// AllowedIPs are untouched: they come from local policy, and a peer moving
	// does not change what it is allowed to send.
	//
	// This goes through the journal rather than straight to the controller. A
	// roam is a network change like any other, and the invariant is that every
	// one of them is transactional, attributable and reversible — a direct
	// write would leave an endpoint no rollback could undo and no audit could
	// explain.
	endpoint := address
	if err := m.applyRoam(ctx, iface, wireguard.PeerSpec{
		PublicKey:  tunnelKey,
		Endpoint:   &endpoint,
		AllowedIPs: allowed,
	}); err != nil {
		return fmt.Errorf("updating endpoint for %s: %w", peer.Short(), err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	now := m.clock.Now()
	state.Endpoint = &endpoint
	state.LastRoamAt = &now
	state.RoamCount++

	return nil
}

// applyRoam rewrites a live peer's endpoint through the journal.
//
// The interface is observed rather than reconstructed: the roam changes one
// peer's endpoint and must not restate anything else about the interface. In
// particular the private key is never read back from the kernel and is not
// needed — the interface already exists, and EnsureInterface is idempotent over
// one that does.
func (m *SessionManager) applyRoam(ctx context.Context, iface string, peer wireguard.PeerSpec) error {
	if m.netstate == nil {
		// Refused rather than silently falling back to a direct write. A roam
		// that bypassed the journal would leave kernel state that no rollback
		// could undo, which is exactly the invariant this path exists to keep.
		return errors.New("roaming requires a transactional network manager")
	}

	observed, err := m.controller.ObserveInterface(ctx, iface)
	if err != nil {
		return fmt.Errorf("observing %s: %w", iface, err)
	}

	// Refusing to touch an interface that is not ours is the same rule that
	// governs every other network change; roaming is not an exception to it.
	if !observed.OwnedByUs {
		return fmt.Errorf("%w: %s is not owned by nostmesh", ErrRoamingRejected, iface)
	}

	spec := wireguard.InterfaceSpec{
		Name:       observed.Name,
		ListenPort: observed.ListenPort,
		Addresses:  observed.Addresses,
		MTU:        observed.MTU,
	}

	transactionID := fmt.Sprintf("roam-%s-%d", iface, m.clock.Now().UnixNano())

	plan, err := m.netstate.PlanInterface(ctx, transactionID, spec, []wireguard.PeerSpec{peer})
	if err != nil {
		return fmt.Errorf("planning roam: %w", err)
	}
	if _, err := m.netstate.Apply(ctx, plan); err != nil {
		return fmt.Errorf("applying roam: %w", err)
	}
	return nil
}

// Fail marks a session failed with a reason.
func (m *SessionManager) Fail(peer domain.NostrPublicKey, reason string, diagnostics []connectivity.Candidate) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	state, known := m.sessions[peer]
	if !known {
		return fmt.Errorf("%w: %s", ErrSessionNotFound, peer.Short())
	}

	state.Phase = PhaseFailed
	state.FailureReason = reason
	state.Diagnostics = diagnostics
	return nil
}

// Close removes a session.
func (m *SessionManager) Close(peer domain.NostrPublicKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, known := m.sessions[peer]; !known {
		return fmt.Errorf("%w: %s", ErrSessionNotFound, peer.Short())
	}

	delete(m.sessions, peer)
	delete(m.handshakes, peer)
	return nil
}

// Get returns a session's state.
func (m *SessionManager) Get(peer domain.NostrPublicKey) (SessionState, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	state, known := m.sessions[peer]
	if !known {
		return SessionState{}, false
	}
	return *state, true
}

// List returns every tracked session.
func (m *SessionManager) List() []SessionState {
	m.mu.RLock()
	defer m.mu.RUnlock()

	states := make([]SessionState, 0, len(m.sessions))
	for _, state := range m.sessions {
		states = append(states, *state)
	}
	return states
}

// BindTunnelKey records the peer's WireGuard key for a session.
func (m *SessionManager) BindTunnelKey(peer domain.NostrPublicKey, key domain.WireGuardPublicKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	state, known := m.sessions[peer]
	if !known {
		return fmt.Errorf("%w: %s", ErrSessionNotFound, peer.Short())
	}

	// A key already bound must not change: substitution mid-session is the
	// attack the handshake's binding prevents, and it must not be reachable
	// through this path either.
	if state.TunnelPublicKey != nil && *state.TunnelPublicKey != key {
		return fmt.Errorf("%w: tunnel key already bound for %s",
			session.ErrKeySubstituted, peer.Short())
	}

	state.TunnelPublicKey = &key
	return nil
}

// SetAllowedIPs records what local policy permits a peer to send.
//
// The candidate's address is deliberately not part of this: that is the
// transport the tunnel runs over, and routing it through the tunnel creates a
// loop.
func (m *SessionManager) SetAllowedIPs(peer domain.NostrPublicKey, allowed []netip.Prefix) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	state, known := m.sessions[peer]
	if !known {
		return fmt.Errorf("%w: %s", ErrSessionNotFound, peer.Short())
	}

	for _, prefix := range allowed {
		if prefix.Bits() == 0 {
			return fmt.Errorf("refusing a default route (%s) for peer %s; transit is a negotiated service",
				prefix, peer.Short())
		}
	}

	state.AllowedIPs = make([]netip.Prefix, len(allowed))
	copy(state.AllowedIPs, allowed)
	return nil
}
