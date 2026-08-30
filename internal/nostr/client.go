package nostr

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"time"
)

// Relay is what the client needs from a relay.
//
// The interface is narrow so the fake and a real WebSocket client are
// interchangeable, and so the client's behaviour under adversarial conditions
// can be tested without a network.
type Relay interface {
	// URL identifies the relay.
	URL() string

	// Publish offers an event.
	Publish(ctx context.Context, id string, raw []byte) error

	// Subscribe returns delivered events.
	Subscribe(buffer int) <-chan PublishedEvent
}

var (
	// ErrNoRelays reports a client with nothing to publish to.
	ErrNoRelays = errors.New("no relays configured")

	// ErrPublishFailed reports that no relay accepted an event.
	ErrPublishFailed = errors.New("no relay accepted the event")
)

// Client publishes to and receives from several relays.
//
// Relays are redundant, not authoritative. They do not vote: the first valid
// copy of a message is processed and the rest are ignored. A relay saying
// nothing is not evidence that a message does not exist, and a relay saying
// something is not evidence that it does.
type Client struct {
	mu sync.RWMutex

	relays []Relay
	inbox  *Inbox
	outbox *Outbox

	// minAcceptances is how many relays must accept before publication counts
	// as done. It bounds how much redundancy is required, not how much is
	// attempted: publication always fans out to every relay.
	minAcceptances int

	backoff BackoffPolicy
	clock   func() time.Time
	random  *rand.Rand
}

// BackoffPolicy controls retry timing.
//
// Jitter matters more than it looks: without it, every node that lost the same
// relay retries at the same instant, and the relay's return is met with a
// thundering herd that knocks it down again.
type BackoffPolicy struct {
	// Initial is the first retry delay.
	Initial time.Duration

	// Max caps the delay.
	Max time.Duration

	// Multiplier grows the delay per attempt.
	Multiplier float64

	// Jitter is the fraction of randomness applied, 0 to 1.
	Jitter float64
}

// DefaultBackoff returns a sensible policy.
func DefaultBackoff() BackoffPolicy {
	return BackoffPolicy{
		Initial:    time.Second,
		Max:        5 * time.Minute,
		Multiplier: 2,
		Jitter:     0.3,
	}
}

// Delay computes the wait before the given attempt, counting from zero.
func (b BackoffPolicy) Delay(attempt int, random *rand.Rand) time.Duration {
	if attempt < 0 {
		attempt = 0
	}

	delay := float64(b.Initial)
	for range attempt {
		delay *= b.Multiplier
		if delay >= float64(b.Max) {
			delay = float64(b.Max)
			break
		}
	}

	if b.Jitter > 0 && random != nil {
		// Jitter is applied symmetrically so the delay stays centred on the
		// intended value rather than drifting upward.
		spread := delay * b.Jitter
		delay += (random.Float64()*2 - 1) * spread
	}

	if delay < 0 {
		delay = 0
	}
	if delay > float64(b.Max) {
		delay = float64(b.Max)
	}
	return time.Duration(delay)
}

// ClientOptions configures a Client.
type ClientOptions struct {
	Relays []Relay
	Inbox  *Inbox
	Outbox *Outbox

	// MinAcceptances is how many relays must accept. Defaults to one: a single
	// relay having the message is enough for it to be deliverable.
	MinAcceptances int

	Backoff BackoffPolicy
	Clock   func() time.Time
	Seed    int64
}

// NewClient builds a Client.
func NewClient(opts ClientOptions) (*Client, error) {
	if len(opts.Relays) == 0 {
		return nil, ErrNoRelays
	}
	if opts.Inbox == nil {
		opts.Inbox = NewInbox(InboxOptions{Clock: opts.Clock})
	}
	if opts.MinAcceptances <= 0 {
		opts.MinAcceptances = 1
	}
	if opts.MinAcceptances > len(opts.Relays) {
		return nil, fmt.Errorf("min acceptances %d exceeds %d configured relays",
			opts.MinAcceptances, len(opts.Relays))
	}
	if opts.Backoff.Initial <= 0 {
		opts.Backoff = DefaultBackoff()
	}
	if opts.Clock == nil {
		opts.Clock = time.Now
	}

	return &Client{
		relays:         opts.Relays,
		inbox:          opts.Inbox,
		outbox:         opts.Outbox,
		minAcceptances: opts.MinAcceptances,
		backoff:        opts.Backoff,
		clock:          opts.Clock,
		random:         rand.New(rand.NewSource(opts.Seed)), //nolint:gosec // retry jitter, not cryptography
	}, nil
}

// PublishResult reports what happened when publishing.
type PublishResult struct {
	// AcceptedBy names the relays that took the event.
	AcceptedBy []string

	// Failures maps relay URL to why it refused.
	Failures map[string]error
}

// Succeeded reports whether enough relays accepted.
func (r PublishResult) Succeeded(minAcceptances int) bool {
	return len(r.AcceptedBy) >= minAcceptances
}

// Publish fans an event out to every relay.
//
// Every relay is tried even after enough have accepted: redundancy is the point,
// and a relay that has the message can deliver it when another goes down. The
// result reports what each did, so a caller can distinguish "one relay is
// rejecting" from "the network is unreachable".
func (c *Client) Publish(ctx context.Context, id string, raw []byte) (PublishResult, error) {
	c.mu.RLock()
	relays := make([]Relay, len(c.relays))
	copy(relays, c.relays)
	c.mu.RUnlock()

	result := PublishResult{Failures: make(map[string]error, len(relays))}

	var (
		mu sync.Mutex
		wg sync.WaitGroup
	)

	for _, relay := range relays {
		wg.Add(1)
		go func(r Relay) {
			defer wg.Done()

			err := r.Publish(ctx, id, raw)

			mu.Lock()
			defer mu.Unlock()

			if err != nil {
				result.Failures[r.URL()] = err
				return
			}
			result.AcceptedBy = append(result.AcceptedBy, r.URL())
		}(relay)
	}

	wg.Wait()

	if !result.Succeeded(c.minAcceptances) {
		return result, fmt.Errorf("%w: %d of %d relays accepted, %d required",
			ErrPublishFailed, len(result.AcceptedBy), len(relays), c.minAcceptances)
	}
	return result, nil
}

// PublishWithOutbox publishes, queuing the event if too few relays accept.
//
// Queuing rather than failing is what lets a node keep working through a relay
// outage: the message is retried when connectivity returns, and survives a
// restart in between.
func (c *Client) PublishWithOutbox(ctx context.Context, entry Entry) (PublishResult, error) {
	result, err := c.Publish(ctx, entry.ID, entry.Event)

	if c.outbox == nil {
		return result, err
	}

	if err == nil {
		// Enough relays have it; nothing to retry.
		return result, nil
	}

	entry.AcceptedBy = result.AcceptedBy
	if queueErr := c.outbox.Enqueue(entry); queueErr != nil {
		return result, fmt.Errorf("%w; queuing also failed: %w", err, queueErr)
	}
	return result, err
}

// Drain retries queued events once, and reports how many were completed.
func (c *Client) Drain(ctx context.Context) (completed int, err error) {
	if c.outbox == nil {
		return 0, nil
	}

	pending, err := c.outbox.Pending()
	if err != nil {
		return 0, err
	}

	for _, entry := range pending {
		if ctx.Err() != nil {
			return completed, ctx.Err()
		}

		result, publishErr := c.Publish(ctx, entry.ID, entry.Event)

		if recordErr := c.outbox.RecordAttempt(entry.ID, result.AcceptedBy); recordErr != nil {
			return completed, recordErr
		}

		if publishErr == nil {
			if removeErr := c.outbox.Remove(entry.ID); removeErr != nil {
				return completed, removeErr
			}
			completed++
		}
	}

	return completed, nil
}

// Received is a message that passed deduplication.
type Received struct {
	Event   PublishedEvent
	Verdict Verdict
}

// Subscribe merges every relay's deliveries into one stream, deduplicated.
//
// The same message arrives once per relay by design. The first valid copy is
// forwarded and the rest are dropped; relays do not vote, so a second copy adds
// no information.
func (c *Client) Subscribe(ctx context.Context, buffer int, key func(PublishedEvent) (LogicalKey, error)) <-chan Received {
	if buffer <= 0 {
		buffer = 64
	}

	c.mu.RLock()
	relays := make([]Relay, len(c.relays))
	copy(relays, c.relays)
	c.mu.RUnlock()

	out := make(chan Received, buffer)

	var wg sync.WaitGroup
	for _, relay := range relays {
		wg.Add(1)

		go func(r Relay) {
			defer wg.Done()

			stream := r.Subscribe(buffer)
			for {
				select {
				case <-ctx.Done():
					return
				case event, open := <-stream:
					if !open {
						return
					}
					c.forward(ctx, out, event, key)
				}
			}
		}(relay)
	}

	go func() {
		wg.Wait()
		close(out)
	}()

	return out
}

// forward deduplicates one event and passes it on if it is new.
func (c *Client) forward(ctx context.Context, out chan<- Received, event PublishedEvent,
	key func(PublishedEvent) (LogicalKey, error),
) {
	logical := LogicalKey{}
	if key != nil {
		derived, err := key(event)
		if err != nil {
			// An event whose logical key cannot be derived is malformed. It is
			// dropped here rather than forwarded, since nothing downstream
			// could interpret it either.
			return
		}
		logical = derived
	}

	verdict := c.inbox.Observe(event.ID, logical)
	if verdict == VerdictDuplicate {
		return
	}

	select {
	case out <- Received{Event: event, Verdict: verdict}:
	case <-ctx.Done():
	}
}

// Relays returns the configured relay URLs.
func (c *Client) Relays() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	urls := make([]string, 0, len(c.relays))
	for _, relay := range c.relays {
		urls = append(urls, relay.URL())
	}
	return urls
}
