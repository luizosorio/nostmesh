package orchestrator

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/luizosorio/nostmesh/internal/connectivity"
	"github.com/luizosorio/nostmesh/internal/domain"
	"github.com/luizosorio/nostmesh/internal/netstate"
	"github.com/luizosorio/nostmesh/internal/policy"
	"github.com/luizosorio/nostmesh/internal/protocol"
	"github.com/luizosorio/nostmesh/internal/session"
	"github.com/luizosorio/nostmesh/internal/wireguard"
)

var (
	// ErrUnauthorized reports a peer local policy does not permit.
	ErrUnauthorized = errors.New("peer is not authorized")

	// ErrNoValidPath reports that no candidate could be verified.
	ErrNoValidPath = errors.New("no candidate path could be verified")

	// ErrTunnelNotCarrying reports an interface configured without traffic
	// flowing. Configuration succeeding and the tunnel working are different
	// claims, and only the second one matters.
	ErrTunnelNotCarrying = errors.New("tunnel was configured but carries no traffic")
)

// Transport is the probe transport the driver hands to the checker.
//
// It is an interface here so the driver can be tested without a network, while
// the real implementation owns the session's UDP port.
type Transport interface {
	connectivity.Transport

	// LocalPort is the port every candidate refers to and WireGuard binds.
	LocalPort() uint16

	// Close releases the port for WireGuard.
	Close() error
}

// Publisher sends a sealed control message to the peer.
//
// The driver does not know about relays, events or encryption: it produces
// payloads and consumes them, and the wiring decides how they travel.
type Publisher interface {
	Publish(ctx context.Context, kind protocol.MessageType, seq uint64, payload protocol.Payload) error

	// BindSession names the session every subsequent message belongs to.
	//
	// The driver owns the session id, and the transport has to agree with it or
	// the two sides label the same conversation differently. It also lets the
	// transport reject a relay's replay of an older session, which arrives
	// correctly signed and correctly addressed and is distinguishable only by
	// this id.
	//
	// A responder calls it with an empty id: it adopts whichever session the
	// request it answers belongs to, and Session reports what that was.
	BindSession(sessionID string) error

	// Session reports the session this conversation settled on.
	Session() string

	// SessionCreatedAt reports when the message that named the current session
	// was published, according to its sender.
	//
	// A responder needs it to tell a live request from one a relay replayed out
	// of storage: both are valid, and only their age separates them.
	SessionCreatedAt() time.Time
}

// Receiver delivers the peer's control messages in arrival order.
type Receiver interface {
	Next(ctx context.Context) (protocol.MessageType, uint64, protocol.Payload, error)
}

// Driver sequences one session from authorization to a carrying tunnel.
//
// Every component it uses already existed and was tested; what was missing was
// the order they run in and the decisions between them. That order is not
// incidental — authorization happens before any socket is opened, AllowedIPs
// come from local configuration and never from the peer, and an endpoint is
// only written after a candidate has been verified.
type Driver struct {
	manager    *SessionManager
	allowlist  *policy.Allowlist
	netstate   *netstate.Manager
	controller wireguard.Controller
	clock      domain.Clock

	identity  domain.NostrPublicKey
	keys      keyGenerator
	transport Transport
	publisher Publisher
	receiver  Receiver
	gatherer  *connectivity.Gatherer

	// pending holds messages that arrived before the step consuming them, and
	// tried records the sessions this responder has already answered.
	pendingMu sync.Mutex
	pending   map[protocol.MessageType][]heldMessage
	tried     map[domain.SessionID]bool

	options DriverOptions
}

// keyGenerator produces this session's ephemeral WireGuard key pair.
type keyGenerator interface {
	Generate() (domain.WireGuardPublicKey, domain.WireGuardPrivateKey, error)
}

// DriverOptions configures a Driver.
type DriverOptions struct {
	// Interface is the local interface to configure. Its AllowedIPs and
	// addresses come from here — that is, from local configuration — and never
	// from anything the peer sends.
	InterfaceName string
	OverlayAddrs  []netip.Prefix
	MTU           int

	// AllowedIPs is what this node will accept from the peer. Derived from
	// local policy: a peer asking for a prefix does not grant it.
	AllowedIPs []netip.Prefix

	// KeepaliveInterval holds the NAT mapping open after the handover.
	KeepaliveInterval time.Duration

	// HandshakeTimeout bounds the control-plane negotiation.
	HandshakeTimeout time.Duration

	// VerifyTimeout bounds how long to wait for the first data-plane handshake.
	VerifyTimeout time.Duration

	// Observers are STUN servers used during gathering.
	Observers []string
}

func (o *DriverOptions) applyDefaults() {
	if o.InterfaceName == "" {
		o.InterfaceName = "nm0"
	}
	if o.MTU == 0 {
		o.MTU = 1420
	}
	if o.KeepaliveInterval == 0 {
		o.KeepaliveInterval = 25 * time.Second
	}
	if o.HandshakeTimeout == 0 {
		o.HandshakeTimeout = 60 * time.Second
	}
	if o.VerifyTimeout == 0 {
		o.VerifyTimeout = 15 * time.Second
	}
}

// DriverDeps are the components a Driver sequences.
type DriverDeps struct {
	Manager    *SessionManager
	Allowlist  *policy.Allowlist
	NetState   *netstate.Manager
	Controller wireguard.Controller
	Identity   domain.NostrPublicKey
	Keys       keyGenerator
	Transport  Transport
	Publisher  Publisher
	Receiver   Receiver
	Gatherer   *connectivity.Gatherer
	Clock      domain.Clock
}

// NewDriver builds a Driver.
func NewDriver(deps DriverDeps, opts DriverOptions) (*Driver, error) {
	switch {
	case deps.Manager == nil:
		return nil, errors.New("driver requires a session manager")
	case deps.Allowlist == nil:
		// Deny-by-default cannot be expressed by an absent allowlist: no list
		// would mean no denials. A driver without one is refused.
		return nil, errors.New("driver requires an allowlist")
	case deps.NetState == nil:
		return nil, errors.New("driver requires a transactional network manager")
	case deps.Controller == nil:
		return nil, errors.New("driver requires a wireguard controller")
	case deps.Keys == nil:
		return nil, errors.New("driver requires a key generator")
	case deps.Transport == nil:
		return nil, errors.New("driver requires a transport")
	case deps.Publisher == nil:
		return nil, errors.New("driver requires a publisher")
	case deps.Receiver == nil:
		return nil, errors.New("driver requires a receiver")
	case deps.Gatherer == nil:
		return nil, errors.New("driver requires a gatherer")
	case deps.Identity.IsZero():
		return nil, errors.New("driver requires a local identity")
	}

	if deps.Clock == nil {
		deps.Clock = domain.SystemClock{}
	}
	opts.applyDefaults()

	return &Driver{
		manager:    deps.Manager,
		allowlist:  deps.Allowlist,
		netstate:   deps.NetState,
		controller: deps.Controller,
		clock:      deps.Clock,
		identity:   deps.Identity,
		keys:       deps.Keys,
		transport:  deps.Transport,
		publisher:  deps.Publisher,
		receiver:   deps.Receiver,
		gatherer:   deps.Gatherer,
		options:    opts,
	}, nil
}

// Role says whether this node opens the session or answers it.
type Role int

const (
	// RoleInitiator opens a session.
	RoleInitiator Role = iota

	// RoleResponder answers one.
	RoleResponder
)

// Connect runs a session to a carrying tunnel, or fails leaving nothing behind.
//
// The order of what follows is the substance of this function. Authorization
// precedes any socket or relay traffic; a tunnel key is bound once and never
// replaced; an endpoint is written only after a candidate is verified; and the
// session is not established until the data plane has actually carried a
// handshake.
func (d *Driver) Connect(ctx context.Context, peer domain.NostrPublicKey, role Role) (err error) {
	// Phase 0: authorize. Before a socket is opened, before a relay is told
	// anything. An unauthorized peer must cost this node nothing and must not
	// learn that it was asked about.
	if checkErr := d.allowlist.Check(peer, policy.ActionSession); checkErr != nil {
		return fmt.Errorf("%w: %s: %w", ErrUnauthorized, peer.Short(), checkErr)
	}

	// The initiator names the session; the responder adopts the one the request
	// it answers belongs to. Waiting for the request here means the responder's
	// handshake, its manager entry and the transport all agree on one id — and
	// a relay's replay of an older session is refused rather than answered as
	// though it were current.
	var (
		sessionID domain.SessionID
		pending   *pendingRequest
	)

	if role == RoleInitiator {
		sessionID, err = domain.NewSessionID(rand.Reader)
		if err != nil {
			return fmt.Errorf("generating session id: %w", err)
		}
		if err = d.publisher.BindSession(sessionID.String()); err != nil {
			return err
		}
	} else {
		pending, err = d.awaitRequest(ctx)
		if err != nil {
			return err
		}
		sessionID = pending.sessionID
	}

	if _, err = d.manager.Begin(peer, sessionID); err != nil {
		return err
	}

	// Any failure from here leaves the session marked failed with the reason,
	// so an operator sees what was being attempted rather than a bare error.
	defer func() {
		if err != nil {
			_ = d.manager.Fail(peer, err.Error(), nil)
		}
	}()

	handshake, err := d.beginHandshake(peer, sessionID, role)
	if err != nil {
		return err
	}

	// AllowedIPs are set from local configuration before any message is
	// exchanged, so there is no window in which a peer's claim could influence
	// them.
	if err = d.manager.SetAllowedIPs(peer, d.options.AllowedIPs); err != nil {
		return err
	}

	if err = d.negotiate(ctx, handshake, role, pending); err != nil {
		return err
	}

	engine, err := d.verifyPath(ctx, handshake, peer)
	if err != nil {
		return err
	}

	nominated := engine.Nominated()
	if nominated == nil {
		return ErrNoValidPath
	}
	if err = d.manager.RecordEndpoint(peer, *nominated); err != nil {
		return err
	}

	return d.establish(ctx, handshake, peer, *nominated)
}

// beginHandshake generates this session's tunnel keys and protocol state.
//
// The key pair is per session and never reused: a key that outlived its session
// would let a peer that once held it decrypt a later one.
func (d *Driver) beginHandshake(peer domain.NostrPublicKey, sessionID domain.SessionID, role Role) (*session.Handshake, error) {
	public, private, err := d.keys.Generate()
	if err != nil {
		return nil, fmt.Errorf("generating tunnel key: %w", err)
	}

	sessionRole := session.RoleInitiator
	if role == RoleResponder {
		sessionRole = session.RoleResponder
	}

	handshake, err := session.New(session.Options{
		Role:          sessionRole,
		SessionID:     sessionID,
		LocalKey:      d.identity,
		PeerKey:       peer,
		TunnelPublic:  public,
		TunnelPrivate: private,
		Timeout:       d.options.HandshakeTimeout,
		Now:           d.clock.Now(),
	})
	if err != nil {
		return nil, err
	}

	d.manager.trackHandshake(peer, handshake)
	return handshake, nil
}

// negotiate runs the control-plane exchange.
func (d *Driver) negotiate(ctx context.Context, handshake *session.Handshake, role Role, pending *pendingRequest) error {
	peer := handshake.PeerKey()

	if err := d.manager.AdvancePhase(peer, PhaseNegotiating); err != nil {
		return err
	}

	if role == RoleInitiator {
		if err := d.negotiateAsInitiator(ctx, handshake); err != nil {
			return err
		}
	} else if err := d.negotiateAsResponder(ctx, handshake, pending); err != nil {
		return err
	}

	// The peer's tunnel key is bound once. A second, different key for the same
	// session is a substitution attempt and the handshake refuses it.
	peerTunnel := handshake.PeerTunnelKey()
	if peerTunnel == nil {
		return errors.New("negotiation completed without a peer tunnel key")
	}

	bound, err := domain.ParseWireGuardPublicKey(peerTunnel.PublicKey)
	if err != nil {
		return fmt.Errorf("peer tunnel key is unusable: %w", err)
	}
	return d.manager.BindTunnelKey(peer, bound)
}

// negotiateAsInitiator sends the request and consumes the offer.
func (d *Driver) negotiateAsInitiator(ctx context.Context, handshake *session.Handshake) error {
	nonce, err := domain.NewNonce(rand.Reader)
	if err != nil {
		return fmt.Errorf("generating nonce: %w", err)
	}

	request, err := handshake.BuildRequest(nonce, keyLifetime, d.clock.Now())
	if err != nil {
		return err
	}
	seq := handshake.NextSeq()
	if err := d.publisher.Publish(ctx, protocol.TypeSessionRequest, seq, request); err != nil {
		return fmt.Errorf("publishing session request: %w", err)
	}

	offer, offerSeq, err := d.awaitMessage(ctx, protocol.TypeSessionOffer)
	if err != nil {
		return err
	}
	if offer.Offer == nil {
		return errors.New("offer message carries no offer")
	}
	if err := handshake.ReceiveOffer(*offer.Offer, offerSeq, d.clock.Now()); err != nil {
		return err
	}

	accept, err := handshake.BuildAccept(d.clock.Now())
	if err != nil {
		return err
	}
	return d.publisher.Publish(ctx, protocol.TypeSessionAccept, handshake.NextSeq(), accept)
}

// negotiateAsResponder consumes the request and answers with an offer.
func (d *Driver) negotiateAsResponder(ctx context.Context, handshake *session.Handshake, pending *pendingRequest) error {
	if pending == nil {
		return errors.New("a responder needs the request that opened the session")
	}

	request, requestSeq := pending.payload, pending.seq
	if request.Request == nil {
		return errors.New("request message carries no request")
	}
	// The allowlist is consulted again here, at the protocol layer. The driver
	// already checked before opening anything, so this is redundant by design:
	// the check that matters is the one closest to the state being committed,
	// and a future caller reaching the handshake by another path still meets it.
	if err := handshake.ReceiveRequest(*request.Request, requestSeq, d.allowlist, d.clock.Now()); err != nil {
		return err
	}

	nonce, err := domain.NewNonce(rand.Reader)
	if err != nil {
		return fmt.Errorf("generating nonce: %w", err)
	}

	offer, _, err := handshake.BuildOffer(nonce, keyLifetime, d.clock.Now())
	if err != nil {
		return err
	}
	if err := d.publisher.Publish(ctx, protocol.TypeSessionOffer, handshake.NextSeq(), offer); err != nil {
		return fmt.Errorf("publishing session offer: %w", err)
	}

	accept, acceptSeq, err := d.awaitMessage(ctx, protocol.TypeSessionAccept)
	if err != nil {
		return err
	}
	if accept.Accept == nil {
		return errors.New("accept message carries no accept")
	}
	return handshake.ReceiveAccept(*accept.Accept, acceptSeq, d.clock.Now())
}

// awaitMessage waits for one message type, holding onto the others.
//
// Messages of other types are kept rather than dropped. Relays reorder, and the
// two sides run concurrently, so a message legitimately arrives before the step
// that consumes it — a candidate update while the responder is still waiting for
// an accept, say. Discarding it would lose it permanently, and both sides would
// then wait out their timeouts for something that already came and went.
func (d *Driver) awaitMessage(ctx context.Context, want protocol.MessageType) (protocol.Payload, uint64, error) {
	d.pendingMu.Lock()
	if held, waiting := d.pending[want]; waiting && len(held) > 0 {
		next := held[0]
		d.pending[want] = held[1:]
		d.pendingMu.Unlock()
		return next.payload, next.seq, nil
	}
	d.pendingMu.Unlock()

	ctx, cancel := context.WithTimeout(ctx, d.options.HandshakeTimeout)
	defer cancel()

	for {
		kind, seq, payload, err := d.receiver.Next(ctx)
		if err != nil {
			return protocol.Payload{}, 0, fmt.Errorf("waiting for %s: %w", want, err)
		}
		if kind == want {
			return payload, seq, nil
		}

		d.pendingMu.Lock()
		if d.pending == nil {
			d.pending = make(map[protocol.MessageType][]heldMessage)
		}
		// Bounded: a peer that floods one type must not grow this without
		// limit. Beyond the bound the oldest is dropped, since a stale message
		// of a type nothing is waiting for is the least useful thing held.
		held := d.pending[kind]
		if len(held) >= maxHeldPerType {
			held = held[1:]
		}
		d.pending[kind] = append(held, heldMessage{seq: seq, payload: payload})
		d.pendingMu.Unlock()
	}
}

// heldMessage is a message that arrived before the step that consumes it.
type heldMessage struct {
	seq     uint64
	payload protocol.Payload
}

// maxHeldPerType bounds how many out-of-turn messages are kept per type.
const maxHeldPerType = 4

// pendingRequest is the request a responder answers, and the session it names.
type pendingRequest struct {
	sessionID domain.SessionID
	seq       uint64
	payload   protocol.Payload

	// createdAt is when the initiator says it published. It decides whether
	// this request belongs to a live attempt or to one already abandoned.
	createdAt time.Time
}

// awaitRequest waits for the request that opens a session.
//
// It runs before the handshake exists, because the session id the handshake
// needs is the one this request carries. The transport adopts that id as it
// arrives, so everything afterwards — the manager entry, the handshake, the
// messages published — refers to the same session.
func (d *Driver) awaitRequest(ctx context.Context) (*pendingRequest, error) {
	// A relay answers a new subscription with everything it already holds, so
	// a request from an earlier attempt arrives first and looks perfectly
	// valid: correctly signed, correctly addressed, not yet expired.
	//
	// Answering it is not a harmless mistake. The initiator has moved on to a
	// new session, so the offer references one it is no longer running, and
	// both sides wait out their timeouts having exchanged messages that could
	// never match.
	//
	// Timestamps cannot settle this on their own. The tolerance a healthy pair
	// of hosts needs for clock skew is minutes, and the age difference between
	// a live request and an abandoned one is often seconds, so any threshold
	// wide enough to be safe is also wide enough to admit the stale one.
	//
	// What does separate them is the session. A responder takes the newest
	// request it sees within a short window after the first one arrives, and
	// having answered a session, never adopts it again: an initiator that is
	// still running republishes, so its request comes back, while an abandoned
	// one does not.
	deadline := d.clock.Now().Add(requestSelectionWindow)

	var newest *pendingRequest
	for {
		remaining := time.Until(deadline)
		if newest != nil && remaining <= 0 {
			return d.settle(newest)
		}

		request, err := d.readWithin(ctx, newest != nil, remaining)
		if err != nil {
			if newest != nil {
				// The window closed with something in hand, which is the
				// expected end rather than a failure.
				return d.settle(newest)
			}
			return nil, err
		}

		if d.alreadyTried(request.sessionID) {
			continue
		}
		if newest == nil || request.createdAt.After(newest.createdAt) {
			newest = request
		}
	}
}

// settle binds the session the responder chose.
//
// Reading requests leaves the transport reset, so the session has to be bound
// back before anything is published. Without it the offer goes out naming no
// session, and the initiator discards it as belonging to a different
// conversation — which is exactly how it failed against a real relay.
func (d *Driver) settle(request *pendingRequest) (*pendingRequest, error) {
	if err := d.publisher.BindSession(request.sessionID.String()); err != nil {
		return nil, err
	}
	return request, nil
}

// readWithin reads a request, bounded by the selection window once one is held.
//
// Before anything has arrived the wait is unbounded, because a responder may
// legitimately sit idle for as long as the operator allows. Once a request is in
// hand the wait is short: it is only looking for a newer one to supersede it.
func (d *Driver) readWithin(ctx context.Context, bounded bool, remaining time.Duration) (*pendingRequest, error) {
	if !bounded {
		return d.readRequest(ctx)
	}

	window, cancel := context.WithTimeout(ctx, remaining)
	defer cancel()

	return d.readRequest(window)
}

// alreadyTried reports whether this responder has already answered a session.
//
// A relay hands back stored requests on every poll, so without this the
// responder answers the same abandoned session indefinitely, never reaching the
// live one behind it.
func (d *Driver) alreadyTried(sessionID domain.SessionID) bool {
	d.pendingMu.Lock()
	defer d.pendingMu.Unlock()

	if d.tried == nil {
		d.tried = make(map[domain.SessionID]bool)
	}
	if d.tried[sessionID] {
		return true
	}
	d.tried[sessionID] = true
	return false
}

// requestSelectionWindow is how long a responder collects requests before
// answering the newest.
//
// It starts when the responder begins waiting, not when the first request
// arrives, so a relay replaying its backlog and a live request published moments
// later are weighed against each other rather than raced.
const requestSelectionWindow = 5 * time.Second

// readRequest waits for one request and reports the session it named.
//
// The transport is reset to "adopt whatever arrives" on each call, because this
// runs in a loop that may see several requests and must learn each one's session
// rather than keep the first. The caller is responsible for binding the session
// it finally settles on — leaving the transport reset would publish the offer
// with no session at all, which is a message the initiator cannot match.
func (d *Driver) readRequest(ctx context.Context) (*pendingRequest, error) {
	previous := d.publisher.Session()

	if err := d.publisher.BindSession(""); err != nil {
		return nil, err
	}

	payload, seq, err := d.awaitMessage(ctx, protocol.TypeSessionRequest)
	if err != nil {
		// The reset must not outlive a failed read. Leaving the transport
		// cleared here is how an offer goes out naming no session at all: the
		// loop resets, times out looking for a newer request, and the session
		// it had already settled on is gone.
		_ = d.publisher.BindSession(previous)
		return nil, err
	}

	adopted := d.publisher.Session()
	if adopted == "" {
		return nil, errors.New("the request named no session")
	}

	sessionID, err := domain.ParseSessionID(adopted)
	if err != nil {
		return nil, fmt.Errorf("the request named an unusable session: %w", err)
	}

	return &pendingRequest{
		sessionID: sessionID,
		seq:       seq,
		payload:   payload,
		createdAt: d.publisher.SessionCreatedAt(),
	}, nil
}



// keyLifetime bounds how long a negotiated tunnel key stays valid.
const keyLifetime = time.Hour

// verifyPath gathers candidates, exchanges them, and proves one works.
//
// Nothing a peer sends is trusted here. Its candidates enter the engine as
// UNVERIFIED, and only a response authenticated with the session key, arriving
// from the exact address probed, promotes one.
func (d *Driver) verifyPath(ctx context.Context, handshake *session.Handshake,
	peer domain.NostrPublicKey,
) (*connectivity.Engine, error) {
	if err := d.manager.AdvancePhase(peer, PhaseGathering); err != nil {
		return nil, err
	}

	engine, err := connectivity.NewEngine(connectivity.EngineOptions{
		SessionID: handshake.SessionID().String(),
		Clock:     d.clock.Now,
	})
	if err != nil {
		return nil, err
	}

	// Candidates describe the port the transport holds, which is the port
	// WireGuard binds after the handover. Gathering for any other port would
	// describe a NAT mapping nothing ends up using.
	local := d.gatherer.Gather(ctx, int(d.transport.LocalPort()))

	expiry := d.clock.Now().Add(candidateLifetime)
	update := protocol.Payload{
		Candidate: &protocol.CandidateUpdate{
			Added: toWireAll(local.Candidates, expiry),
			Final: true,
		},
	}
	if err := d.publisher.Publish(ctx, protocol.TypeCandidateUpdate, handshake.NextSeq(), update); err != nil {
		return nil, fmt.Errorf("publishing candidates: %w", err)
	}

	if err := d.consumePeerCandidates(ctx, engine, peer); err != nil {
		return nil, err
	}

	if err := d.manager.AdvancePhase(peer, PhaseChecking); err != nil {
		return nil, err
	}

	key := connectivity.DeriveSessionKey(
		handshake.SessionID().String(),
		handshake.LocalTunnelPublic().String(),
		peerTunnelKeyString(handshake),
	)

	checker, err := connectivity.NewChecker(connectivity.CheckerOptions{
		Engine:    engine,
		Transport: d.transport,
		Key:       key,
		Clock:     d.clock.Now,
	})
	if err != nil {
		return nil, err
	}

	if _, err := checker.Run(ctx); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNoValidPath, err)
	}
	if engine.Nominated() == nil {
		// The diagnostics say which candidate failed and why, which is what
		// makes a NAT problem distinguishable from a firewall one.
		_ = d.manager.Fail(peer, "no candidate verified", engine.Diagnostics())
		return nil, ErrNoValidPath
	}

	return engine, nil
}

// consumePeerCandidates reads the peer's candidate update into the engine.
func (d *Driver) consumePeerCandidates(ctx context.Context, engine *connectivity.Engine,
	peer domain.NostrPublicKey,
) error {
	payload, _, err := d.awaitMessage(ctx, protocol.TypeCandidateUpdate)
	if err != nil {
		return err
	}
	if payload.Candidate == nil {
		return errors.New("candidate message carries no candidates")
	}

	var accepted int
	for _, wire := range payload.Candidate.Added {
		candidate, convertErr := toConnectivity(wire, peer.Short())
		if convertErr != nil {
			// An unusable candidate is dropped, not fatal: the peer may offer
			// several and one being malformed says nothing about the rest.
			continue
		}
		// AddCandidate refuses loopback, multicast and unspecified addresses,
		// so a peer cannot aim this node's probes at something that is not a
		// routable peer.
		if addErr := engine.AddCandidate(candidate); addErr != nil {
			continue
		}
		accepted++
	}

	if accepted == 0 {
		return fmt.Errorf("%w: the peer offered no usable candidate", ErrNoValidPath)
	}
	return nil
}

// establish hands the port to WireGuard and confirms traffic flows.
func (d *Driver) establish(ctx context.Context, handshake *session.Handshake,
	peer domain.NostrPublicKey, nominated connectivity.Candidate,
) error {
	if err := d.manager.AdvancePhase(peer, PhaseConfiguring); err != nil {
		return err
	}

	// The port must be known before the transport releases it, since the
	// transport is what holds the authoritative number.
	port := int(d.transport.LocalPort())

	// Phase B of NM-15: the transport gives up the port so the kernel can bind
	// it. Everything the peer verified refers to this port.
	if err := d.transport.Close(); err != nil {
		return fmt.Errorf("releasing the session port: %w", err)
	}

	peerTunnel, err := domain.ParseWireGuardPublicKey(peerTunnelKeyString(handshake))
	if err != nil {
		return fmt.Errorf("peer tunnel key is unusable: %w", err)
	}

	endpoint := nominated.Address
	iface := wireguard.InterfaceSpec{
		Name:       d.options.InterfaceName,
		PrivateKey: handshake.LocalTunnelPrivate(),
		ListenPort: port,
		Addresses:  d.options.OverlayAddrs,
		MTU:        d.options.MTU,
	}

	peerSpec := wireguard.PeerSpec{
		PublicKey: peerTunnel,
		Endpoint:  &endpoint,

		// From local configuration, never from the peer. This is the field a
		// malicious peer would most want to influence: it decides what source
		// addresses this node will accept through the tunnel.
		AllowedIPs:          d.options.AllowedIPs,
		PersistentKeepalive: d.options.KeepaliveInterval,
	}

	transactionID := fmt.Sprintf("session-%s", handshake.SessionID().String())

	plan, err := d.netstate.PlanInterface(ctx, transactionID, iface, []wireguard.PeerSpec{peerSpec})
	if err != nil {
		return fmt.Errorf("planning interface: %w", err)
	}
	if _, err := d.netstate.Apply(ctx, plan); err != nil {
		return fmt.Errorf("configuring interface: %w", err)
	}

	// Phase 11. Configuration succeeding proves the kernel accepted a
	// description; it proves nothing about traffic. A tunnel that is fully
	// configured and carries no packet is the exact failure this waits for.
	if err := d.manager.AdvancePhase(peer, PhaseVerifying); err != nil {
		return err
	}
	if err := d.awaitHandshake(ctx, peerTunnel); err != nil {
		return err
	}

	if err := handshake.ConfirmEstablished(d.clock.Now()); err != nil {
		return err
	}
	if err := d.manager.AdvancePhase(peer, PhaseEstablished); err != nil {
		return err
	}

	ready := protocol.Payload{
		Ready: &protocol.SessionReady{
			SelectedCandidate: nominated.ID,
		},
	}
	// The tunnel is already carrying traffic at this point. Failing to announce
	// that is not a reason to tear it down: the peer learns the same fact from
	// its own data plane, so the announcement is a courtesy rather than a step
	// the session depends on. The error is deliberately dropped.
	_ = d.publisher.Publish(ctx, protocol.TypeSessionReady, handshake.NextSeq(), ready)
	return nil
}

// awaitHandshake waits for the data plane to carry its first handshake.
//
// This is the only evidence that the tunnel works. Everything before it — an
// interface created, a peer applied, an endpoint written — is a claim about
// configuration, and each of them holds true for a tunnel that carries nothing.
func (d *Driver) awaitHandshake(ctx context.Context, peerTunnel domain.WireGuardPublicKey) error {
	ctx, cancel := context.WithTimeout(ctx, d.options.VerifyTimeout)
	defer cancel()

	ticker := time.NewTicker(handshakePollInterval)
	defer ticker.Stop()

	for {
		state, err := d.controller.ObserveInterface(ctx, d.options.InterfaceName)
		if err == nil {
			for _, observed := range state.Peers {
				if observed.PublicKey == peerTunnel && observed.HasHandshake() {
					return nil
				}
			}
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("%w: no handshake with %s within %s",
				ErrTunnelNotCarrying, peerTunnel.Short(), d.options.VerifyTimeout)
		case <-ticker.C:
		}
	}
}

// peerTunnelKeyString reads the negotiated peer tunnel key.
func peerTunnelKeyString(handshake *session.Handshake) string {
	if key := handshake.PeerTunnelKey(); key != nil {
		return key.PublicKey
	}
	return ""
}

const (
	// candidateLifetime bounds how long a published candidate is offered as
	// usable.
	candidateLifetime = 5 * time.Minute

	// handshakePollInterval is how often the data plane is checked for its
	// first handshake.
	handshakePollInterval = 250 * time.Millisecond
)
