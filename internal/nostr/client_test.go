package nostr

import (
	"context"
	"errors"
	"math/rand"
	"path/filepath"
	"testing"
	"time"
)

func testRelays(t *testing.T, count int) []*FakeRelay {
	t.Helper()

	relays := make([]*FakeRelay, 0, count)
	for i := range count {
		relays = append(relays, NewFakeRelay(FakeRelayOptions{
			URL:   relayURL(i),
			Seed:  int64(i),
			Clock: func() time.Time { return testNow() },
		}))
	}
	return relays
}

func relayURL(index int) string {
	return "wss://relay-" + string(rune('a'+index)) + ".invalid"
}

func asRelays(fakes []*FakeRelay) []Relay {
	relays := make([]Relay, 0, len(fakes))
	for _, fake := range fakes {
		relays = append(relays, fake)
	}
	return relays
}

func newTestClient(t *testing.T, fakes []*FakeRelay, minAcceptances int) *Client {
	t.Helper()

	outbox, err := NewOutbox(OutboxOptions{
		Dir:   filepath.Join(t.TempDir(), "outbox"),
		Clock: func() time.Time { return testNow() },
	})
	if err != nil {
		t.Fatalf("building outbox: %v", err)
	}

	client, err := NewClient(ClientOptions{
		Relays:         asRelays(fakes),
		Outbox:         outbox,
		MinAcceptances: minAcceptances,
		Inbox:          NewInbox(InboxOptions{Clock: func() time.Time { return testNow() }}),
		Clock:          func() time.Time { return testNow() },
	})
	if err != nil {
		t.Fatalf("building client: %v", err)
	}
	return client
}

// testEvent builds a genuinely signed event carrying the given label.
//
// It cannot fabricate an event with a chosen id: a real relay recomputes the id
// and verifies the signature, so a test that published a hand-made map would
// only ever prove that the fake is more permissive than Nostr. The label goes
// in the d tag, and testEventID recovers the resulting id for assertions.
func testEvent(t *testing.T, label string) []byte {
	t.Helper()

	_, raw, err := BuildEvent(testSigner(t, 42), 31111, [][]string{{"d", label}}, "test", testNow())
	if err != nil {
		t.Fatalf("building test event: %v", err)
	}
	return raw
}

// testEventID returns the id a relay will store the event under.
func testEventID(t *testing.T, raw []byte) string {
	t.Helper()

	event, err := ParseEvent(raw)
	if err != nil {
		t.Fatalf("parsing test event: %v", err)
	}
	return event.ID
}

func TestPublishFansOutToEveryRelay(t *testing.T) {
	fakes := testRelays(t, 3)
	client := newTestClient(t, fakes, 1)

	event := testEvent(t, "event-1")

	result, err := client.Publish(context.Background(), "event-1", event)
	if err != nil {
		t.Fatalf("publishing: %v", err)
	}

	if len(result.AcceptedBy) != 3 {
		t.Errorf("accepted by %d relays, want 3", len(result.AcceptedBy))
	}

	// The relay stores the event under its own id, not under whatever label the
	// caller used to track it.
	stored := testEventID(t, event)
	for i, fake := range fakes {
		if !fake.Has(stored) {
			t.Errorf("relay %d did not receive the event", i)
		}
	}
}

// The acceptance criterion: the control plane keeps working with one of three
// relays down. Redundancy exists precisely so a single relay is never critical.
func TestOperatesWithOneRelayDown(t *testing.T) {
	fakes := testRelays(t, 3)
	client := newTestClient(t, fakes, 1)

	fakes[1].SetDown(true)

	result, err := client.Publish(context.Background(), "event-1", testEvent(t, "event-1"))
	if err != nil {
		t.Fatalf("publishing must succeed with two relays up: %v", err)
	}

	if len(result.AcceptedBy) != 2 {
		t.Errorf("accepted by %d relays, want 2", len(result.AcceptedBy))
	}
	if len(result.Failures) != 1 {
		t.Errorf("expected 1 failure, got %d", len(result.Failures))
	}
	if !errors.Is(result.Failures[relayURL(1)], ErrRelayDown) {
		t.Errorf("expected ErrRelayDown, got: %v", result.Failures[relayURL(1)])
	}
}

// A relay rejecting the event — as one refusing an unknown kind would — must
// not stop the others.
func TestOneRelayRejectingDoesNotBlockPublication(t *testing.T) {
	fakes := testRelays(t, 3)
	client := newTestClient(t, fakes, 1)

	fakes[0].SetBehaviour(RelayBehaviour{RejectAll: true, RejectReason: "unknown kind"})

	result, err := client.Publish(context.Background(), "event-1", testEvent(t, "event-1"))
	if err != nil {
		t.Fatalf("publishing: %v", err)
	}
	if len(result.AcceptedBy) != 2 {
		t.Errorf("accepted by %d relays, want 2", len(result.AcceptedBy))
	}
	if !errors.Is(result.Failures[relayURL(0)], ErrRelayRejected) {
		t.Errorf("expected ErrRelayRejected, got: %v", result.Failures[relayURL(0)])
	}
}

func TestPublicationFailsWhenAllRelaysDown(t *testing.T) {
	fakes := testRelays(t, 3)
	client := newTestClient(t, fakes, 1)

	for _, fake := range fakes {
		fake.SetDown(true)
	}

	_, err := client.Publish(context.Background(), "event-1", testEvent(t, "event-1"))
	if !errors.Is(err, ErrPublishFailed) {
		t.Fatalf("expected ErrPublishFailed, got: %v", err)
	}
}

// Requiring more acceptances than are available must fail rather than silently
// accept less redundancy than asked for.
func TestMinAcceptancesIsEnforced(t *testing.T) {
	fakes := testRelays(t, 3)
	client := newTestClient(t, fakes, 3)

	fakes[2].SetDown(true)

	result, err := client.Publish(context.Background(), "event-1", testEvent(t, "event-1"))
	if err == nil {
		t.Fatal("publishing must fail when the acceptance threshold is not met")
	}
	if len(result.AcceptedBy) != 2 {
		t.Errorf("accepted by %d relays, want 2", len(result.AcceptedBy))
	}
}

// A failed publication is queued and completed on retry. This is what lets a
// node work through a relay outage rather than losing the message.
func TestFailedPublishIsQueuedAndDrained(t *testing.T) {
	fakes := testRelays(t, 2)
	client := newTestClient(t, fakes, 1)

	for _, fake := range fakes {
		fake.SetDown(true)
	}

	entry := Entry{
		ID:        "event-1",
		Event:     testEvent(t, "event-1"),
		ExpiresAt: testNow().Add(time.Hour),
	}

	if _, err := client.PublishWithOutbox(context.Background(), entry); err == nil {
		t.Fatal("publishing must fail with every relay down")
	}

	size, err := client.outbox.Size()
	if err != nil {
		t.Fatalf("reading outbox: %v", err)
	}
	if size != 1 {
		t.Fatalf("outbox holds %d entries, want 1", size)
	}

	// Relays return.
	for _, fake := range fakes {
		fake.SetDown(false)
	}

	completed, err := client.Drain(context.Background())
	if err != nil {
		t.Fatalf("draining: %v", err)
	}
	if completed != 1 {
		t.Errorf("completed %d entries, want 1", completed)
	}

	size, err = client.outbox.Size()
	if err != nil {
		t.Fatalf("reading outbox: %v", err)
	}
	if size != 0 {
		t.Errorf("outbox still holds %d entries", size)
	}
}

// The same message arrives once per relay by design. Deduplication turns that
// redundancy back into a single message.
func TestDuplicateDeliveriesAreDeduplicated(t *testing.T) {
	fakes := testRelays(t, 3)
	client := newTestClient(t, fakes, 1)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stream := client.Subscribe(ctx, 64, func(e PublishedEvent) (LogicalKey, error) {
		return LogicalKey{SessionID: "s1", Type: "request", Seq: 0}, nil
	})

	if _, err := client.Publish(ctx, "event-1", testEvent(t, "event-1")); err != nil {
		t.Fatalf("publishing: %v", err)
	}

	received := collect(t, stream, 200*time.Millisecond)

	if len(received) != 1 {
		t.Errorf("received %d messages, want 1 after deduplication", len(received))
	}
}

// A relay delivering extra copies must not produce extra messages.
func TestRelayDuplicationIsAbsorbed(t *testing.T) {
	fakes := testRelays(t, 1)
	fakes[0].SetBehaviour(RelayBehaviour{DuplicateDeliveries: 4})
	client := newTestClient(t, fakes, 1)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stream := client.Subscribe(ctx, 64, func(e PublishedEvent) (LogicalKey, error) {
		return LogicalKey{SessionID: "s1", Type: "request", Seq: 0}, nil
	})

	if _, err := client.Publish(ctx, "event-1", testEvent(t, "event-1")); err != nil {
		t.Fatalf("publishing: %v", err)
	}

	received := collect(t, stream, 200*time.Millisecond)
	if len(received) != 1 {
		t.Errorf("received %d messages despite deduplication, want 1", len(received))
	}
}

// Two different events claiming the same session position is not a duplicate:
// one of them is not what it claims to be, and the caller must be told.
func TestConflictingEventsAtSameSequenceAreReported(t *testing.T) {
	fakes := testRelays(t, 1)
	client := newTestClient(t, fakes, 1)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stream := client.Subscribe(ctx, 64, func(e PublishedEvent) (LogicalKey, error) {
		// Both events map to the same logical position.
		return LogicalKey{SessionID: "s1", Type: "request", Seq: 0}, nil
	})

	for _, id := range []string{"event-1", "event-2"} {
		if _, err := client.Publish(ctx, id, testEvent(t, id)); err != nil {
			t.Fatalf("publishing %s: %v", id, err)
		}
	}

	received := collect(t, stream, 300*time.Millisecond)

	var conflicts int
	for _, message := range received {
		if message.Verdict == VerdictConflict {
			conflicts++
		}
	}
	if conflicts != 1 {
		t.Errorf("got %d conflicts, want 1 (received %d messages)", conflicts, len(received))
	}
}

// Backoff without jitter synchronizes every node that lost the same relay, and
// the relay's return is met with a thundering herd.
func TestBackoffGrowsAndJitters(t *testing.T) {
	policy := BackoffPolicy{
		Initial:    time.Second,
		Max:        time.Minute,
		Multiplier: 2,
		Jitter:     0.3,
	}
	random := rand.New(rand.NewSource(1))

	t.Run("grows with attempts", func(t *testing.T) {
		noJitter := policy
		noJitter.Jitter = 0

		previous := time.Duration(0)
		for attempt := range 5 {
			delay := noJitter.Delay(attempt, nil)
			if delay < previous {
				t.Errorf("attempt %d delay %s is shorter than the previous %s", attempt, delay, previous)
			}
			previous = delay
		}
	})

	t.Run("respects the cap", func(t *testing.T) {
		for attempt := range 20 {
			if delay := policy.Delay(attempt, random); delay > policy.Max {
				t.Errorf("attempt %d delay %s exceeds the cap %s", attempt, delay, policy.Max)
			}
		}
	})

	t.Run("jitter spreads retries", func(t *testing.T) {
		seen := make(map[time.Duration]bool)
		for range 20 {
			seen[policy.Delay(3, random)] = true
		}
		if len(seen) < 2 {
			t.Error("jitter produced identical delays; every node would retry at once")
		}
	})

	t.Run("never negative", func(t *testing.T) {
		wild := BackoffPolicy{Initial: time.Second, Max: time.Minute, Multiplier: 2, Jitter: 5}
		for attempt := range 10 {
			if delay := wild.Delay(attempt, random); delay < 0 {
				t.Errorf("attempt %d produced a negative delay %s", attempt, delay)
			}
		}
	})
}

func TestClientRequiresRelays(t *testing.T) {
	if _, err := NewClient(ClientOptions{}); !errors.Is(err, ErrNoRelays) {
		t.Errorf("expected ErrNoRelays, got: %v", err)
	}
}

func TestClientRejectsImpossibleThreshold(t *testing.T) {
	fakes := testRelays(t, 2)

	_, err := NewClient(ClientOptions{Relays: asRelays(fakes), MinAcceptances: 5})
	if err == nil {
		t.Error("requiring more acceptances than relays must be refused")
	}
}

// collect drains a stream for a bounded time.
func collect(t *testing.T, stream <-chan Received, window time.Duration) []Received {
	t.Helper()

	var received []Received
	deadline := time.After(window)

	for {
		select {
		case message, open := <-stream:
			if !open {
				return received
			}
			received = append(received, message)
		case <-deadline:
			return received
		}
	}
}
