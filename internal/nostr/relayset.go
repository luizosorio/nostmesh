package nostr

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/luizosorio/nostmesh/internal/domain"
	"github.com/luizosorio/nostmesh/internal/protocol"
)

// ErrNoRelayReachable reports that no configured relay could be reached.
var ErrNoRelayReachable = errors.New("no relay could be reached")

// RelaySet connects a node's configured relays and keeps them connected.
//
// It is the missing piece between configuration and the client: the client
// takes a list of Relay values and knows nothing about URLs, dialling or
// reconnection, and until now nothing built that list outside tests.
//
// Reconnection lives here rather than in WebSocketRelay because the decision it
// makes is about the set: a node stays usable while any relay is up, and a
// relay that has been down for an hour is still worth retrying because the peer
// may be publishing to it.
type RelaySet struct {
	relays []*WebSocketRelay
	client *Client

	backoff BackoffPolicy
	clock   func() time.Time
	random  *rand.Rand

	// self is the identity whose inbox is subscribed, kept so a reconnecting
	// relay can reissue the subscription.
	self domain.NostrPublicKey

	mu             sync.Mutex
	subscriptionID string
	supervising    bool
}

// RelaySetOptions configures a RelaySet.
type RelaySetOptions struct {
	// URLs are the relays to use.
	URLs []string

	// Outbox persists publications that no relay accepted.
	Outbox *Outbox

	// MinAcceptances is how many relays must accept a publication.
	MinAcceptances int

	Backoff BackoffPolicy
	Clock   func() time.Time
	Seed    int64
}

// NewRelaySet builds a set from configured URLs.
//
// Nothing is dialled here: construction validates, Connect reaches the network.
// Keeping them apart means a configuration error is reported immediately rather
// than as a connection failure.
func NewRelaySet(opts RelaySetOptions) (*RelaySet, error) {
	if len(opts.URLs) == 0 {
		return nil, ErrNoRelays
	}
	if opts.Clock == nil {
		opts.Clock = time.Now
	}
	if opts.Backoff.Initial <= 0 {
		opts.Backoff = DefaultBackoff()
	}

	relays := make([]*WebSocketRelay, 0, len(opts.URLs))
	asRelay := make([]Relay, 0, len(opts.URLs))

	seen := make(map[string]bool, len(opts.URLs))
	for _, url := range opts.URLs {
		// A duplicate URL would be counted twice toward the acceptance
		// threshold, so a node could believe it had redundancy it does not have.
		if seen[url] {
			return nil, fmt.Errorf("relay %s is configured more than once", url)
		}
		seen[url] = true

		relay, err := NewWebSocketRelay(WebSocketRelayOptions{URL: url, Clock: opts.Clock})
		if err != nil {
			return nil, fmt.Errorf("configuring relay %s: %w", url, err)
		}
		relays = append(relays, relay)
		asRelay = append(asRelay, relay)
	}

	client, err := NewClient(ClientOptions{
		Relays:         asRelay,
		Outbox:         opts.Outbox,
		MinAcceptances: opts.MinAcceptances,
		Backoff:        opts.Backoff,
		Clock:          opts.Clock,
		Seed:           opts.Seed,
	})
	if err != nil {
		return nil, err
	}

	return &RelaySet{
		relays:  relays,
		client:  client,
		backoff: opts.Backoff,
		clock:   opts.Clock,
		random:  rand.New(rand.NewSource(opts.Seed)), //nolint:gosec // jitter, not cryptography
	}, nil
}

// Client returns the publishing client backed by this set.
func (s *RelaySet) Client() *Client { return s.client }

// Connect dials every relay.
//
// Partial success is success. Relays are redundant by design, and refusing to
// start because one of three is unreachable would make the weakest relay a
// single point of failure — the opposite of why there are several.
func (s *RelaySet) Connect(ctx context.Context) error {
	var wg sync.WaitGroup

	failures := make([]error, len(s.relays))
	for i, relay := range s.relays {
		wg.Add(1)
		go func() {
			defer wg.Done()
			failures[i] = relay.Connect(ctx)
		}()
	}
	wg.Wait()

	var connected int
	var reasons []error
	for i, err := range failures {
		if err == nil {
			connected++
			continue
		}
		reasons = append(reasons, fmt.Errorf("%s: %w", s.relays[i].URL(), err))
	}

	if connected == 0 {
		return fmt.Errorf("%w: %w", ErrNoRelayReachable, errors.Join(reasons...))
	}
	return nil
}

// Connected reports how many relays are currently up.
func (s *RelaySet) Connected() int {
	var up int
	for _, relay := range s.relays {
		if relay.IsConnected() {
			up++
		}
	}
	return up
}

// SubscribeToInbox asks every relay for the events addressed to this node.
//
// The filter selects by kind and by the indexed recipient tag, so a relay sends
// only what concerns this node rather than every message of this kind on the
// network.
func (s *RelaySet) SubscribeToInbox(ctx context.Context, self domain.NostrPublicKey) error {
	subscriptionID, err := randomSubscriptionID()
	if err != nil {
		return err
	}

	s.mu.Lock()
	s.self = self
	s.subscriptionID = subscriptionID
	s.mu.Unlock()

	var subscribed int
	for _, relay := range s.relays {
		if err := relay.RequestEvents(ctx, subscriptionID, inboxFilter(self)); err == nil {
			subscribed++
		}
	}

	if subscribed == 0 {
		return fmt.Errorf("%w: no relay accepted the subscription", ErrNoRelayReachable)
	}
	return nil
}

// inboxFilter selects events addressed to a node.
func inboxFilter(self domain.NostrPublicKey) map[string]any {
	return map[string]any{
		"kinds": []int{protocol.ExperimentalKind},
		"#p":    []string{self.String()},
	}
}

// Supervise keeps relays connected until the context ends.
//
// A relay that drops is redialled with backoff, and its subscription is
// reissued: a relay keeps no memory of a subscription across connections, so a
// reconnection without one produces a socket that is open and silent. That
// failure is invisible — the node looks connected and simply never receives
// anything — which is why the reissue is not optional.
func (s *RelaySet) Supervise(ctx context.Context) {
	s.mu.Lock()
	if s.supervising {
		s.mu.Unlock()
		return
	}
	s.supervising = true
	s.mu.Unlock()

	var wg sync.WaitGroup
	for _, relay := range s.relays {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.superviseOne(ctx, relay)
		}()
	}
	wg.Wait()
}

// superviseOne keeps a single relay connected.
func (s *RelaySet) superviseOne(ctx context.Context, relay *WebSocketRelay) {
	var attempt int

	for {
		if ctx.Err() != nil {
			return
		}

		if relay.IsConnected() {
			attempt = 0
			select {
			case <-ctx.Done():
				return
			case <-time.After(supervisionInterval):
			}
			continue
		}

		// Backoff with jitter: without it every node that lost the same relay
		// redials at the same instant, and the relay's return is met with a
		// thundering herd.
		delay := s.backoff.Delay(attempt, s.random)
		attempt++

		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}

		if err := relay.Connect(ctx); err != nil {
			continue
		}
		s.resubscribe(ctx, relay)
	}
}

// resubscribe reissues this node's inbox subscription on a reconnected relay.
func (s *RelaySet) resubscribe(ctx context.Context, relay *WebSocketRelay) {
	s.mu.Lock()
	subscriptionID := s.subscriptionID
	self := s.self
	s.mu.Unlock()

	if subscriptionID == "" || self.IsZero() {
		return
	}
	_ = relay.RequestEvents(ctx, subscriptionID, inboxFilter(self))
}

// supervisionInterval is how often a connected relay is rechecked.
const supervisionInterval = 5 * time.Second

// randomSubscriptionID produces an identifier for a relay subscription.
//
// It is random rather than derived from the node's identity: a predictable
// subscription id would let an observer correlate a node's subscriptions across
// relays without ever seeing its key.
func randomSubscriptionID() (string, error) {
	raw := make([]byte, 16)
	if _, err := cryptorand.Read(raw); err != nil {
		return "", fmt.Errorf("generating subscription id: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

// Close disconnects every relay.
func (s *RelaySet) Close() error {
	var reasons []error
	for _, relay := range s.relays {
		if err := relay.Close(); err != nil {
			reasons = append(reasons, fmt.Errorf("%s: %w", relay.URL(), err))
		}
	}
	return errors.Join(reasons...)
}

// EnvelopeKey reads an event's logical position without decrypting it.
//
// Deduplication has to happen before decryption: the same message arrives once
// per relay, and decrypting each copy would waste the work the redundancy is
// meant to buy. The envelope's routing fields are cleartext precisely so this
// is possible, and they are not trusted for anything else — the sender they
// claim is only meaningful after the signature and the payload verify.
func EnvelopeKey(event PublishedEvent) (LogicalKey, error) {
	parsed, err := ParseEvent(event.Raw)
	if err != nil {
		return LogicalKey{}, err
	}

	var envelope struct {
		Type      string `json:"type"`
		SessionID string `json:"session_id"`
		Seq       uint64 `json:"seq"`
	}
	if err := json.Unmarshal([]byte(parsed.Content), &envelope); err != nil {
		return LogicalKey{}, fmt.Errorf("reading envelope: %w", err)
	}
	if envelope.SessionID == "" || envelope.Type == "" {
		return LogicalKey{}, errors.New("envelope has no session or type")
	}

	return LogicalKey{
		SessionID: envelope.SessionID,
		Type:      envelope.Type,
		Seq:       envelope.Seq,
	}, nil
}
