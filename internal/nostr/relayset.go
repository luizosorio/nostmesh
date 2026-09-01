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
	since          time.Time
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

// Dropped reports how many deliveries the set discarded for want of a reader.
//
// A non-zero count means the relays delivered messages this node then threw
// away, which looks exactly like the peer never sending them. It belongs in any
// report of why a wait ended empty.
func (s *RelaySet) Dropped() int {
	var total int
	for _, relay := range s.relays {
		total += relay.Dropped()
	}
	return total
}

// ClosedSubscriptions reports subscriptions the relays ended, and the last
// reason any of them gave.
func (s *RelaySet) ClosedSubscriptions() (int, string) {
	var total int
	var reason string
	for _, relay := range s.relays {
		count, why := relay.SubscriptionClosed()
		total += count
		if why != "" {
			reason = why
		}
	}
	return total, reason
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
	// The identifier is generated once and reused for every later reissue.
	//
	// A relay caps concurrent subscriptions per connection. Sending a fresh
	// identifier on each poll opens a new one every interval, and once the cap
	// is reached the relay refuses or closes them — after which the client
	// believes it is subscribed and receives nothing at all. Reusing the
	// identifier makes a reissue replace the subscription rather than add one.
	s.mu.Lock()
	subscriptionID := s.subscriptionID
	s.mu.Unlock()

	if subscriptionID == "" {
		generated, err := randomSubscriptionID()
		if err != nil {
			return err
		}
		subscriptionID = generated
	}

	// One envelope lifetime back, plus an allowance for clock skew.
	//
	// The skew allowance is not padding. This window is computed from the local
	// clock, but it filters events stamped by the sender's clock, and the two
	// disagree in practice — a host running two minutes behind publishes events
	// that a strictly computed window silently excludes. The session then fails
	// with no message ever arriving, which looks like a network problem and is
	// not one.
	//
	// It reuses the protocol's own tolerance rather than defining a second one:
	// a message this filter admits is exactly one the validator would accept,
	// and two constants that could drift apart would eventually disagree.
	since := s.clock().Add(-inboxLookback - protocol.MaxClockSkew)

	s.mu.Lock()
	s.self = self
	s.subscriptionID = subscriptionID
	s.since = since
	s.mu.Unlock()

	var subscribed int
	for _, relay := range s.relays {
		if err := relay.RequestEvents(ctx, subscriptionID, inboxFilter(self, since)); err == nil {
			subscribed++
		}
	}

	if subscribed == 0 {
		return fmt.Errorf("%w: no relay accepted the subscription", ErrNoRelayReachable)
	}
	return nil
}

// inboxFilter selects events addressed to a node.
//
// The `since` bound is not an optimization. Control messages are short-lived and
// every one of them expires, but a relay keeps them and replays the whole
// backlog to each new subscription. Without a lower bound a node starting up
// receives every message it was ever sent, all of them expired and all of them
// rejected — and the live message it is actually waiting for arrives somewhere
// in that flood, or not at all.
//
// The bound is one envelope lifetime back rather than "now": a message published
// moments before this node subscribed is still valid and still wanted.
func inboxFilter(self domain.NostrPublicKey, since time.Time) map[string]any {
	return map[string]any{
		"kinds": []int{protocol.ExperimentalKind},
		"#p":    []string{self.String()},
		"since": since.Unix(),
	}
}

// PollInterval reports how often the subscription is reissued.
//
// Exposed because anything waiting for a message to arrive has to outlast it: a
// wait shorter than one interval can close before the poll that would have
// delivered the message.
func PollInterval() time.Duration { return pollInterval }

// Poll reissues the inbox subscription periodically.
//
// NIP-01 relays are expected to push events matching an open subscription as
// they arrive, and most do. Some do not: they answer the initial query from
// storage and then stay silent for the subscription's lifetime. Against one of
// those, a responder holding an open subscription never learns that a request
// arrived, even though the relay stored it and will return it to the very next
// query.
//
// Reissuing the subscription turns that silence into a poll. It costs one small
// query per interval and makes the client work against both behaviours, which
// is the right trade when the alternative is a session that hangs depending on
// which relay the operator configured.
func (s *RelaySet) Poll(ctx context.Context) {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.mu.Lock()
			self := s.self
			s.mu.Unlock()

			if self.IsZero() {
				continue
			}
			// Errors are not reported: a relay that refuses one poll is
			// retried on the next tick, and the supervisor handles a relay
			// that has genuinely gone away.
			_ = s.SubscribeToInbox(ctx, self)
		}
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
	since := s.since
	s.mu.Unlock()

	if subscriptionID == "" || self.IsZero() {
		return
	}
	_ = relay.RequestEvents(ctx, subscriptionID, inboxFilter(self, since))
}

const (
	// supervisionInterval is how often a connected relay is rechecked.
	supervisionInterval = 5 * time.Second

	// inboxLookback bounds how far back a subscription asks for messages. It
	// matches the control protocol's envelope lifetime: anything older is
	// expired and would be refused anyway.
	inboxLookback = 5 * time.Minute

	// pollInterval is how often the subscription is reissued, so a relay that
	// does not push live events still delivers within a bounded delay.
	pollInterval = 3 * time.Second

)

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
