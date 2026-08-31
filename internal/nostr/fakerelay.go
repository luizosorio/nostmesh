package nostr

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"time"
)

// FakeRelay simulates a Nostr relay that misbehaves on demand.
//
// The acceptance criteria for this milestone require the client to survive a
// relay that drops, rejects, delays, duplicates and reorders. A real relay does
// none of those on request, and testing against one would make the suite depend
// on infrastructure nobody here controls. This is that relay, under test
// control.
type FakeRelay struct {
	mu sync.Mutex

	url string

	// published holds every event this relay accepted.
	published []PublishedEvent

	// behaviour controls how it misbehaves.
	behaviour RelayBehaviour

	// down reports the relay as unreachable.
	down bool

	// subscribers receive delivered events.
	subscribers []chan PublishedEvent

	random *rand.Rand
	clock  func() time.Time
}

// RelayBehaviour describes how a fake relay misbehaves.
//
// Each field models a real failure mode: relays do go down mid-publish, do
// reject events they dislike, do deliver copies, and do deliver out of order.
type RelayBehaviour struct {
	// RejectAll makes every publication fail, as a relay refusing an unknown
	// kind would.
	RejectAll bool

	// RejectReason is what the relay says when it refuses.
	RejectReason string

	// PublishDelay is added before accepting, modelling a slow relay.
	PublishDelay time.Duration

	// DeliveryDelay is added before delivering to subscribers.
	DeliveryDelay time.Duration

	// DuplicateDeliveries is how many extra copies each event is delivered.
	// Relays legitimately deliver a copy per subscription overlap.
	DuplicateDeliveries int

	// ReorderDeliveries delivers in reverse rather than arrival order.
	ReorderDeliveries bool

	// DropRate is the fraction of publications silently discarded, modelling a
	// relay that accepts and then loses the event. This is the nastiest failure
	// mode, because the client is told everything worked.
	DropRate float64
}

// PublishedEvent is an event a relay accepted.
type PublishedEvent struct {
	// ID is the Nostr event id.
	ID string

	// Raw is the serialized event.
	Raw []byte

	// Relay is where it was published.
	Relay string

	// At is when the relay accepted it.
	At time.Time
}

var (
	// ErrRelayDown reports an unreachable relay.
	ErrRelayDown = errors.New("relay is unreachable")

	// ErrRelayRejected reports a refused publication.
	ErrRelayRejected = errors.New("relay rejected the event")
)

// FakeRelayOptions configures a FakeRelay.
type FakeRelayOptions struct {
	URL       string
	Behaviour RelayBehaviour
	Seed      int64
	Clock     func() time.Time
}

// NewFakeRelay builds a fake relay.
func NewFakeRelay(opts FakeRelayOptions) *FakeRelay {
	if opts.URL == "" {
		opts.URL = "wss://fake.invalid"
	}
	if opts.Clock == nil {
		opts.Clock = time.Now
	}

	return &FakeRelay{
		url:       opts.URL,
		behaviour: opts.Behaviour,
		// A fixed seed keeps a failing test reproducible: random misbehaviour
		// that cannot be replayed is not a test, it is a rumour.
		random: rand.New(rand.NewSource(opts.Seed)), //nolint:gosec // deterministic test behaviour, not cryptography
		clock:  opts.Clock,
	}
}

// URL returns the relay's address.
func (r *FakeRelay) URL() string { return r.url }

// SetDown marks the relay reachable or not, so a test can take one down
// mid-run.
func (r *FakeRelay) SetDown(down bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.down = down
}

// SetBehaviour changes how the relay misbehaves, mid-run.
func (r *FakeRelay) SetBehaviour(behaviour RelayBehaviour) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.behaviour = behaviour
}

// Publish offers an event to the relay.
//
// The id parameter is the caller's own tracking label and is deliberately
// ignored, exactly as a real relay ignores it: the event is stored and answered
// for under the id embedded in its bytes. Honouring the caller's label here
// would let a client that matches on the wrong one pass the suite and then time
// out against every real relay.
func (r *FakeRelay) Publish(ctx context.Context, _ string, raw []byte) error {
	r.mu.Lock()
	behaviour := r.behaviour
	down := r.down
	r.mu.Unlock()

	if down {
		return fmt.Errorf("%w: %s", ErrRelayDown, r.url)
	}

	if behaviour.PublishDelay > 0 {
		select {
		case <-time.After(behaviour.PublishDelay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	if behaviour.RejectAll {
		reason := behaviour.RejectReason
		if reason == "" {
			reason = "blocked"
		}
		return fmt.Errorf("%w: %s: %s", ErrRelayRejected, r.url, reason)
	}

	// A real relay parses the event and refuses anything that is not a valid
	// NIP-01 event, so the fake must too. Accepting arbitrary bytes here — or
	// falling back to the caller's id when parsing fails — makes the fake
	// tolerate what every real relay rejects, and the suite then validates the
	// implementation against itself rather than against Nostr.
	parsed, err := ParseEvent(raw)
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrRelayRejected, r.url, err)
	}
	if err := VerifyEvent(parsed); err != nil {
		return fmt.Errorf("%w: %s: %w", ErrRelayRejected, r.url, err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// A silent drop reports success and keeps nothing. The client believes the
	// event is published, which is exactly why redundancy across relays matters.
	if behaviour.DropRate > 0 && r.random.Float64() < behaviour.DropRate {
		return nil
	}

	event := PublishedEvent{ID: parsed.ID, Raw: raw, Relay: r.url, At: r.clock()}
	r.published = append(r.published, event)

	r.deliver(event, behaviour)
	return nil
}

// deliver sends an event to subscribers, applying duplication and reordering.
func (r *FakeRelay) deliver(event PublishedEvent, behaviour RelayBehaviour) {
	copies := 1 + behaviour.DuplicateDeliveries

	for _, subscriber := range r.subscribers {
		for range copies {
			target := subscriber
			payload := event

			if behaviour.DeliveryDelay > 0 {
				go func() {
					time.Sleep(behaviour.DeliveryDelay)
					select {
					case target <- payload:
					default:
					}
				}()
				continue
			}

			select {
			case target <- payload:
			default:
				// A subscriber that is not reading is dropped, as a real relay
				// would with a slow client.
			}
		}
	}
}

// Subscribe returns a channel of delivered events.
func (r *FakeRelay) Subscribe(buffer int) <-chan PublishedEvent {
	r.mu.Lock()
	defer r.mu.Unlock()

	if buffer <= 0 {
		buffer = 64
	}

	channel := make(chan PublishedEvent, buffer)
	r.subscribers = append(r.subscribers, channel)

	// Replay what the relay already holds, as a real relay does for a new
	// subscription matching stored events.
	stored := make([]PublishedEvent, len(r.published))
	copy(stored, r.published)

	if r.behaviour.ReorderDeliveries {
		for i, j := 0, len(stored)-1; i < j; i, j = i+1, j-1 {
			stored[i], stored[j] = stored[j], stored[i]
		}
	}

	go func() {
		for _, event := range stored {
			select {
			case channel <- event:
			default:
				return
			}
		}
	}()

	return channel
}

// Published returns every event the relay accepted and kept.
func (r *FakeRelay) Published() []PublishedEvent {
	r.mu.Lock()
	defer r.mu.Unlock()

	out := make([]PublishedEvent, len(r.published))
	copy(out, r.published)
	return out
}

// Has reports whether the relay kept an event.
func (r *FakeRelay) Has(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, event := range r.published {
		if event.ID == id {
			return true
		}
	}
	return false
}

// Clear discards stored events.
func (r *FakeRelay) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.published = nil
}
