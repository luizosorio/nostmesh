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
	"net/netip"
	"sync"
	"time"

	"github.com/luizosorio/nostmesh/internal/connectivity"
	"github.com/luizosorio/nostmesh/internal/domain"
	"github.com/luizosorio/nostmesh/internal/nostr"
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
	Alice  *Node
	Bob    *Node
	Relays []*nostr.FakeRelay

	clock func() time.Time
}

// HarnessOptions configures a Harness.
type HarnessOptions struct {
	// RelayCount is how many relays to create. Three is the documented
	// minimum, and the acceptance criteria require working with one down.
	RelayCount int

	// Clock is injected so timing is deterministic.
	Clock func() time.Time
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

	harness := &Harness{Relays: relays, clock: opts.Clock}

	alice, err := harness.newNode("alice", "198.51.100.10:51820")
	if err != nil {
		return nil, err
	}
	bob, err := harness.newNode("bob", "198.51.100.20:51820")
	if err != nil {
		return nil, err
	}

	// Each authorizes the other. Deny-by-default means this is required, not
	// incidental: without it the handshake refuses before any network work.
	if err := alice.Allowlist.Add(policy.Grant{
		Peer: bob.Public, Alias: "bob", Actions: []policy.Action{policy.ActionSession},
	}); err != nil {
		return nil, err
	}
	if err := bob.Allowlist.Add(policy.Grant{
		Peer: alice.Public, Alias: "alice", Actions: []policy.Action{policy.ActionSession},
	}); err != nil {
		return nil, err
	}

	harness.Alice, harness.Bob = alice, bob
	return harness, nil
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
func (h *Harness) Connect(ctx context.Context) HandshakeResult {
	started := h.clock()
	result := HandshakeResult{}

	sessionID, err := domain.NewSessionID(rand.Reader)
	if err != nil {
		result.Err = err
		result.Phase = "session-id"
		return result
	}
	result.SessionID = sessionID

	initiator, responder, err := h.buildHandshakes(sessionID)
	if err != nil {
		result.Err = err
		result.Phase = "setup"
		return result
	}

	if err := h.exchange(ctx, initiator, responder); err != nil {
		result.Err = err
		result.Phase = "negotiating"
		result.Duration = h.clock().Sub(started)
		return result
	}

	// Both sides agreed. Verifying the path is the next phase, and the
	// connectivity engine refuses anything unproved.
	endpoint, err := h.verifyPath(ctx, h.Bob.Address, sessionID.String(),
		h.Alice.TunnelPublic.String(), h.Bob.TunnelPublic.String())
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

func (h *Harness) buildHandshakes(sessionID domain.SessionID) (initiator, responder *session.Handshake, err error) {
	now := h.clock()

	initiator, err = session.New(session.Options{
		Role: session.RoleInitiator, SessionID: sessionID,
		LocalKey: h.Alice.Public, PeerKey: h.Bob.Public,
		TunnelPublic: h.Alice.TunnelPublic, TunnelPrivate: h.Alice.TunnelPrivate,
		Now: now,
	})
	if err != nil {
		return nil, nil, err
	}

	responder, err = session.New(session.Options{
		Role: session.RoleResponder, SessionID: sessionID,
		LocalKey: h.Bob.Public, PeerKey: h.Alice.Public,
		TunnelPublic: h.Bob.TunnelPublic, TunnelPrivate: h.Bob.TunnelPrivate,
		Now: now,
	})
	if err != nil {
		return nil, nil, err
	}

	return initiator, responder, nil
}

// exchange drives request → offer → accept over the relay set.
func (h *Harness) exchange(ctx context.Context, initiator, responder *session.Handshake) error {
	now := h.clock()

	nonce, err := domain.NewNonce(rand.Reader)
	if err != nil {
		return err
	}

	request, err := initiator.BuildRequest(nonce, 5*time.Minute, now)
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}

	if err := h.publish(ctx, h.Alice, h.Bob, protocol.TypeSessionRequest, 0, request); err != nil {
		return fmt.Errorf("publishing request: %w", err)
	}

	// Bob's policy decides before anything is committed.
	if err := responder.ReceiveRequest(*request.Request, 0, h.Bob.Allowlist, now); err != nil {
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
	if err := h.publish(ctx, h.Bob, h.Alice, protocol.TypeSessionOffer, 0, offer); err != nil {
		return fmt.Errorf("publishing offer: %w", err)
	}
	if err := initiator.ReceiveOffer(*offer.Offer, 0, now); err != nil {
		return fmt.Errorf("receiving offer: %w", err)
	}

	accept, err := initiator.BuildAccept(now)
	if err != nil {
		return fmt.Errorf("building accept: %w", err)
	}
	if err := h.publish(ctx, h.Alice, h.Bob, protocol.TypeSessionAccept, 1, accept); err != nil {
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

	decoded, err := connectivity.DecodeProbe(payload, target, t.key)
	if err != nil || decoded.IsResponse {
		return nil //nolint:nilerr // silence is the modelled behaviour
	}

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
