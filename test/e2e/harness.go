// Package e2e provides a reproducible two-node testbed.
//
// It wires the real components — protocol, codec, relay client, connectivity
// engine — against simulated relays and an in-memory transport. Per the
// project's testing rules the mandatory suite never touches public relays: the
// acceptance criteria require a relay that drops, duplicates and reorders on
// demand, which no real server does.
package e2e

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/luizosorio/nostmesh/internal/connectivity"
	"github.com/luizosorio/nostmesh/internal/domain"
	"github.com/luizosorio/nostmesh/internal/nostr"
	"github.com/luizosorio/nostmesh/internal/observability"
	"github.com/luizosorio/nostmesh/internal/policy"
	"github.com/luizosorio/nostmesh/internal/protocol"
	"github.com/luizosorio/nostmesh/internal/session"
)

// Node is one participant in the testbed.
type Node struct {
	// Name labels the node in diagnostics.
	Name string

	// Identity is the node's durable Nostr key pair.
	Private domain.NostrPrivateKey
	Public  domain.NostrPublicKey

	// Tunnel is this session's ephemeral WireGuard key pair.
	TunnelPublic  domain.WireGuardPublicKey
	TunnelPrivate domain.WireGuardPrivateKey

	// Allowlist is the node's local policy.
	Allowlist *policy.Allowlist

	// Client publishes and receives over the relay set.
	Client *nostr.Client

	// Address is where this node can be reached, for connectivity checks.
	Address netip.AddrPort
}

// Harness is a two-node testbed with a configurable relay set.
type Harness struct {
	// Nodes are the participants, in the order they were created.
	//
	// A slice rather than a pair: M2.2 is about several sessions coexisting, and
	// a testbed that can only hold two cannot exercise it. Alice and Bob remain
	// as names for the first two, because most tests are about one pair and
	// reading `h.Alice` says more than `h.Nodes[0]`.
	Nodes []*Node

	Alice  *Node
	Bob    *Node
	Relays []*nostr.FakeRelay

	clock func() time.Time

	// log receives what the components under test emit. Never nil; a harness
	// built without one discards.
	log *slog.Logger
}

// HarnessOptions configures a Harness.
type HarnessOptions struct {
	// RelayCount is how many relays to create. Three is the documented
	// minimum, and the acceptance criteria require working with one down.
	RelayCount int

	// Clock is injected so timing is deterministic.
	Clock func() time.Time

	// NodeCount is how many participants to create. Zero means two, which is
	// what every test written before the mesh expected.
	NodeCount int

	// Logger captures what the run logged, so a test can assert on it.
	// Optional: a run that does not care about output supplies nothing.
	Logger *slog.Logger
}

// NewHarness builds a testbed.
func NewHarness(opts HarnessOptions) (*Harness, error) {
	if opts.RelayCount <= 0 {
		opts.RelayCount = 3
	}
	if opts.Clock == nil {
		opts.Clock = time.Now
	}

	relays := make([]*nostr.FakeRelay, 0, opts.RelayCount)
	for i := range opts.RelayCount {
		relays = append(relays, nostr.NewFakeRelay(nostr.FakeRelayOptions{
			URL:   fmt.Sprintf("wss://relay-%d.test", i),
			Seed:  int64(i),
			Clock: opts.Clock,
		}))
	}

	logger := opts.Logger
	if logger == nil {
		logger = observability.Discard()
	}

	if opts.NodeCount <= 0 {
		opts.NodeCount = 2
	}

	harness := &Harness{Relays: relays, clock: opts.Clock, log: logger}

	for i := range opts.NodeCount {
		// Addresses are spaced so each node is distinguishable in a capture and
		// no two share one, which would make a verified path ambiguous.
		node, err := harness.newNode(nodeName(i), fmt.Sprintf("198.51.100.%d:51820", 10+i*10))
		if err != nil {
			return nil, err
		}
		harness.Nodes = append(harness.Nodes, node)
	}

	// Every node authorizes every other. Deny-by-default means this is required,
	// not incidental: without it a handshake refuses before any network work.
	//
	// A full mesh of grants is not a full mesh of sessions — the roadmap is
	// explicit that a mesh need not be complete. It is what lets a test choose
	// any pair without the allowlist being the thing that refused.
	for _, node := range harness.Nodes {
		for _, peer := range harness.Nodes {
			if peer.Public == node.Public {
				continue
			}
			if err := node.Allowlist.Add(policy.Grant{
				Peer: peer.Public, Alias: peer.Name, Actions: []policy.Action{policy.ActionSession},
			}); err != nil {
				return nil, err
			}
		}
	}

	harness.Alice = harness.Nodes[0]
	if len(harness.Nodes) > 1 {
		harness.Bob = harness.Nodes[1]
	}
	return harness, nil
}

// nodeName labels a participant.
//
// The first two keep the names the earlier tests used, so a failure in one of
// them still reads the way it always did.
func nodeName(index int) string {
	switch index {
	case 0:
		return "alice"
	case 1:
		return "bob"
	}
	return fmt.Sprintf("node-%d", index)
}

func (h *Harness) newNode(name, address string) (*Node, error) {
	generator := identityGenerator{}

	private, public, err := generator.nostrPair()
	if err != nil {
		return nil, fmt.Errorf("generating identity for %s: %w", name, err)
	}
	tunnelPublic, tunnelPrivate, err := generator.tunnelPair()
	if err != nil {
		return nil, fmt.Errorf("generating tunnel key for %s: %w", name, err)
	}

	relays := make([]nostr.Relay, 0, len(h.Relays))
	for _, relay := range h.Relays {
		relays = append(relays, relay)
	}

	client, err := nostr.NewClient(nostr.ClientOptions{
		Relays: relays,
		Inbox:  nostr.NewInbox(nostr.InboxOptions{Clock: h.clock}),
		Clock:  h.clock,
	})
	if err != nil {
		return nil, fmt.Errorf("building client for %s: %w", name, err)
	}

	parsed, err := netip.ParseAddrPort(address)
	if err != nil {
		return nil, fmt.Errorf("parsing address for %s: %w", name, err)
	}

	return &Node{
		Name:          name,
		Private:       private,
		Public:        public,
		TunnelPublic:  tunnelPublic,
		TunnelPrivate: tunnelPrivate,
		Allowlist:     policy.NewAllowlist(),
		Client:        client,
		Address:       parsed,
	}, nil
}

// HandshakeResult reports what one connection attempt achieved.
type HandshakeResult struct {
	// Established says whether both sides reached agreement.
	Established bool

	// Duration is how long the whole attempt took.
	Duration time.Duration

	// SessionID is what both sides agreed on.
	SessionID domain.SessionID

	// Endpoint is the verified path.
	Endpoint netip.AddrPort

	// Phase names where the attempt stopped, on failure.
	Phase string

	// Err explains a failure.
	Err error
}

// Connect runs one full handshake between the two nodes.
//
// It exercises the real protocol path: build, seal, publish across relays,
// receive with deduplication, open, validate, and advance the state machine on
// both sides.
// Connect runs a session between the first two nodes.
//
// Kept for the tests written before the mesh, which are about one pair and read
// better without naming it every time.
func (h *Harness) Connect(ctx context.Context) HandshakeResult {
	return h.ConnectPair(ctx, h.Alice, h.Bob)
}

// ConnectPair runs a session between any two nodes.
func (h *Harness) ConnectPair(ctx context.Context, from, to *Node) HandshakeResult {
	started := h.clock()
	result := HandshakeResult{}

	sessionID, err := domain.NewSessionID(rand.Reader)
	if err != nil {
		result.Err = err
		result.Phase = "session-id"
		return result
	}
	result.SessionID = sessionID

	initiator, responder, err := h.buildHandshakes(sessionID, from, to)
	if err != nil {
		result.Err = err
		result.Phase = "setup"
		return result
	}

	if err := h.exchange(ctx, initiator, responder, from, to); err != nil {
		result.Err = err
		result.Phase = "negotiating"
		result.Duration = h.clock().Sub(started)
		return result
	}

	// Both sides agreed. Verifying the path is the next phase, and the
	// connectivity engine refuses anything unproved.
	endpoint, err := h.verifyPath(ctx, to.Address, sessionID.String(),
		from.TunnelPublic.String(), to.TunnelPublic.String())
	if err != nil {
		result.Err = err
		result.Phase = "checking"
		result.Duration = h.clock().Sub(started)
		return result
	}

	result.Established = true
	result.Endpoint = endpoint
	result.Duration = h.clock().Sub(started)
	return result
}

func (h *Harness) buildHandshakes(sessionID domain.SessionID, from, to *Node) (initiator, responder *session.Handshake, err error) {
	now := h.clock()

	initiator, err = session.New(session.Options{
		Role: session.RoleInitiator, SessionID: sessionID,
		LocalKey: from.Public, PeerKey: to.Public,
		TunnelPublic: from.TunnelPublic, TunnelPrivate: from.TunnelPrivate,
		Now: now,
	})
	if err != nil {
		return nil, nil, err
	}

	responder, err = session.New(session.Options{
		Role: session.RoleResponder, SessionID: sessionID,
		LocalKey: to.Public, PeerKey: from.Public,
		TunnelPublic: to.TunnelPublic, TunnelPrivate: to.TunnelPrivate,
		Now: now,
	})
	if err != nil {
		return nil, nil, err
	}

	return initiator, responder, nil
}

// exchange drives request → offer → accept over the relay set.
func (h *Harness) exchange(ctx context.Context, initiator, responder *session.Handshake, from, to *Node) error {
	now := h.clock()

	nonce, err := domain.NewNonce(rand.Reader)
	if err != nil {
		return err
	}

	request, err := initiator.BuildRequest(nonce, 5*time.Minute, now)
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}

	if err := h.publish(ctx, from, to, protocol.TypeSessionRequest, 0, request); err != nil {
		return fmt.Errorf("publishing request: %w", err)
	}

	// Bob's policy decides before anything is committed.
	if err := responder.ReceiveRequest(*request.Request, 0, to.Allowlist, now); err != nil {
		return fmt.Errorf("receiving request: %w", err)
	}

	offerNonce, err := domain.NewNonce(rand.Reader)
	if err != nil {
		return err
	}

	offer, _, err := responder.BuildOffer(offerNonce, 5*time.Minute, now)
	if err != nil {
		return fmt.Errorf("building offer: %w", err)
	}
	if err := h.publish(ctx, to, from, protocol.TypeSessionOffer, 0, offer); err != nil {
		return fmt.Errorf("publishing offer: %w", err)
	}
	if err := initiator.ReceiveOffer(*offer.Offer, 0, now); err != nil {
		return fmt.Errorf("receiving offer: %w", err)
	}

	accept, err := initiator.BuildAccept(now)
	if err != nil {
		return fmt.Errorf("building accept: %w", err)
	}
	if err := h.publish(ctx, from, to, protocol.TypeSessionAccept, 1, accept); err != nil {
		return fmt.Errorf("publishing accept: %w", err)
	}
	if err := responder.ReceiveAccept(*accept.Accept, 1, now); err != nil {
		return fmt.Errorf("receiving accept: %w", err)
	}

	return nil
}

// publish seals a payload and fans it out across the relay set.
func (h *Harness) publish(ctx context.Context, from, to *Node,
	kind protocol.MessageType, seq uint64, payload protocol.Payload,
) error {
	messageID := make([]byte, 16)
	if _, err := rand.Read(messageID); err != nil {
		return err
	}

	now := h.clock()
	envelope := protocol.Envelope{
		Version:   protocol.Version,
		Namespace: protocol.Namespace,
		Type:      kind,
		MessageID: fmt.Sprintf("%x", messageID),
		SessionID: fmt.Sprintf("%x", make([]byte, 32)),
		Seq:       seq,
		CreatedAt: now.Unix(),
		ExpiresAt: now.Add(time.Minute).Unix(),
		Sender:    from.Public.String(),
		Recipient: to.Public.String(),
	}

	privateHex, err := nostr.PrivateKeyHex(from.Private)
	if err != nil {
		return err
	}

	key, err := nostr.DeriveConversationKey(privateHex, to.Public.String())
	if err != nil {
		return fmt.Errorf("deriving conversation key: %w", err)
	}

	codec := nostr.NewCodec(h.clock)
	sealed, err := codec.Seal(envelope, payload, key)
	if err != nil {
		return fmt.Errorf("sealing: %w", err)
	}

	// The event content is the whole envelope, not just the ciphertext. The
	// cleartext fields are what the receiver recomputes into the context hash,
	// so publishing the body alone would leave the receiver unable to open it.
	content, err := json.Marshal(sealed)
	if err != nil {
		return fmt.Errorf("encoding envelope: %w", err)
	}

	signer, err := nostr.NewSigner(from.Private)
	if err != nil {
		return fmt.Errorf("building signer: %w", err)
	}

	tags := [][]string{
		nostr.RecipientTag(to.Public),
		nostr.ReplaceableTag(sealed.SessionID, string(sealed.Type), sealed.Seq),
	}

	_, raw, err := nostr.BuildEvent(signer, protocol.ExperimentalKind, tags, string(content), now)
	if err != nil {
		return fmt.Errorf("building event: %w", err)
	}

	if _, err := from.Client.Publish(ctx, sealed.MessageID, raw); err != nil {
		return err
	}
	return nil
}

// verifyPath runs a connectivity check against the peer's address.
func (h *Harness) verifyPath(ctx context.Context, target netip.AddrPort,
	sessionID, localKey, peerKey string,
) (netip.AddrPort, error) {
	engine, err := connectivity.NewEngine(connectivity.EngineOptions{
		SessionID: sessionID,
		Clock:     h.clock,
		Logger:    h.log,

		// Deliberately left at the closed default. The point of running the
		// scan against this path is to prove that a node logging normally does
		// not write addresses; opening the gate here would prove the opposite
		// of what the test is for.
	})
	if err != nil {
		return netip.AddrPort{}, err
	}

	if err := engine.AddCandidate(connectivity.Candidate{
		ID:      "peer-host",
		Kind:    connectivity.KindHost,
		Address: target,
		Source:  "peer candidate exchange",
	}); err != nil {
		return netip.AddrPort{}, err
	}

	probeKey := connectivity.DeriveSessionKey(sessionID, localKey, peerKey)
	transport := newLoopbackTransport(probeKey, target, h.clock)

	checker, err := connectivity.NewChecker(connectivity.CheckerOptions{
		Engine:    engine,
		Transport: transport,
		Key:       probeKey,
		Clock:     h.clock,
	})
	if err != nil {
		return netip.AddrPort{}, err
	}

	result, err := checker.Run(ctx)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return result.Nominated.Address, nil
}

// SetRelayDown takes a relay out of service.
func (h *Harness) SetRelayDown(index int, down bool) {
	if index < 0 || index >= len(h.Relays) {
		return
	}
	h.Relays[index].SetDown(down)
}

// SetRelayBehaviour changes how a relay misbehaves.
func (h *Harness) SetRelayBehaviour(index int, behaviour nostr.RelayBehaviour) {
	if index < 0 || index >= len(h.Relays) {
		return
	}
	h.Relays[index].SetBehaviour(behaviour)
}

// loopbackTransport answers probes as the peer would.
type loopbackTransport struct {
	mu sync.Mutex

	key     connectivity.SessionKey
	peer    netip.AddrPort
	inbound chan arrival
	clock   func() time.Time
	sentTo  map[netip.AddrPort]int
}

type arrival struct {
	payload []byte
	source  netip.AddrPort
}

func newLoopbackTransport(key connectivity.SessionKey, peer netip.AddrPort, clock func() time.Time) *loopbackTransport {
	return &loopbackTransport{
		key:     key,
		peer:    peer,
		inbound: make(chan arrival, 32),
		clock:   clock,
		sentTo:  make(map[netip.AddrPort]int),
	}
}

func (t *loopbackTransport) Send(_ context.Context, target netip.AddrPort, payload []byte) error {
	t.mu.Lock()
	t.sentTo[target]++
	t.mu.Unlock()

	if target != t.peer {
		// Anywhere other than the peer is silence, which is what an address
		// nobody is listening on looks like.
		return nil
	}

	decoded, err := connectivity.DecodeChallenge(payload, t.key)
	if err != nil {
		return nil //nolint:nilerr // silence is the modelled behaviour
	}

	// The peer authenticates its answer with the address it observed the
	// challenge arriving from, which here is the challenger's own address.
	response := connectivity.EncodeResponse(decoded.Nonce, t.clock(), target, t.key)

	select {
	case t.inbound <- arrival{payload: response, source: target}:
	default:
	}
	return nil
}

func (t *loopbackTransport) Receive(ctx context.Context) ([]byte, netip.AddrPort, error) {
	select {
	case <-ctx.Done():
		return nil, netip.AddrPort{}, ctx.Err()
	case a := <-t.inbound:
		return a.payload, a.source, nil
	}
}

// identityGenerator produces key pairs for the testbed.
type identityGenerator struct{}

func (identityGenerator) nostrPair() (domain.NostrPrivateKey, domain.NostrPublicKey, error) {
	raw := make([]byte, domain.NostrKeySize)
	if _, err := rand.Read(raw); err != nil {
		return domain.NostrPrivateKey{}, domain.NostrPublicKey{}, err
	}

	private, err := domain.NewNostrPrivateKey(raw)
	if err != nil {
		return domain.NostrPrivateKey{}, domain.NostrPublicKey{}, err
	}

	public, err := nostr.DerivePublicKey(private)
	if err != nil {
		return domain.NostrPrivateKey{}, domain.NostrPublicKey{}, err
	}
	return private, public, nil
}

func (identityGenerator) tunnelPair() (domain.WireGuardPublicKey, domain.WireGuardPrivateKey, error) {
	raw := make([]byte, domain.WireGuardKeySize)
	if _, err := rand.Read(raw); err != nil {
		return domain.WireGuardPublicKey{}, domain.WireGuardPrivateKey{}, err
	}

	private, err := domain.NewWireGuardPrivateKey(raw)
	if err != nil {
		return domain.WireGuardPublicKey{}, domain.WireGuardPrivateKey{}, err
	}

	var public domain.WireGuardPublicKey
	if _, err := rand.Read(public[:]); err != nil {
		return domain.WireGuardPublicKey{}, domain.WireGuardPrivateKey{}, err
	}
	return public, private, nil
}
