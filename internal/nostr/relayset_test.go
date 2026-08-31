package nostr

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/luizosorio/nostmesh/internal/protocol"
)

func testRelaySet(t *testing.T, urls ...string) *RelaySet {
	t.Helper()

	set, err := NewRelaySet(RelaySetOptions{
		URLs:  urls,
		Clock: func() time.Time { return testNow() },
	})
	if err != nil {
		t.Fatalf("building relay set: %v", err)
	}
	t.Cleanup(func() { _ = set.Close() })
	return set
}

func TestRelaySetRequiresRelays(t *testing.T) {
	if _, err := NewRelaySet(RelaySetOptions{}); !errors.Is(err, ErrNoRelays) {
		t.Errorf("expected ErrNoRelays, got %v", err)
	}
}

// A duplicated URL would be counted twice toward the acceptance threshold, so
// a node would believe it had redundancy it does not have.
func TestRelaySetRejectsDuplicateURLs(t *testing.T) {
	_, err := NewRelaySet(RelaySetOptions{
		URLs: []string{"wss://relay.invalid", "wss://relay.invalid"},
	})
	if err == nil {
		t.Error("a duplicated relay URL must be refused")
	}
}

// Partial connectivity is success. Relays are redundant precisely so one being
// unreachable does not stop the node — refusing to start would make the weakest
// relay a single point of failure.
func TestConnectSucceedsWithOneRelayUp(t *testing.T) {
	up := newRelayServer(t)

	set := testRelaySet(t, up.url(), "ws://127.0.0.1:1/unreachable")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := set.Connect(ctx); err != nil {
		t.Fatalf("connect must succeed with one relay up: %v", err)
	}
	if set.Connected() != 1 {
		t.Errorf("%d relays connected, want 1", set.Connected())
	}
}

// With nothing reachable the failure must be reported, not swallowed: a node
// that believes it is connected would wait forever for a message that can never
// arrive.
func TestConnectFailsWithEveryRelayDown(t *testing.T) {
	set := testRelaySet(t, "ws://127.0.0.1:1/a", "ws://127.0.0.1:2/b")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := set.Connect(ctx)
	if !errors.Is(err, ErrNoRelayReachable) {
		t.Fatalf("expected ErrNoRelayReachable, got %v", err)
	}
	if set.Connected() != 0 {
		t.Errorf("%d relays reported connected", set.Connected())
	}
}

// The subscription must select by kind and by recipient, or the node either
// receives nothing or receives every message of this kind on the relay.
func TestInboxSubscriptionFiltersByKindAndRecipient(t *testing.T) {
	server := newRelayServer(t)
	set := testRelaySet(t, server.url())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := set.Connect(ctx); err != nil {
		t.Fatalf("connecting: %v", err)
	}

	self := testSigner(t, 11).PublicKey()
	if err := set.SubscribeToInbox(ctx, self); err != nil {
		t.Fatalf("subscribing: %v", err)
	}

	filters := waitForSubscriptions(t, server, 1)
	filter := filters[0]

	kinds, ok := filter["kinds"].([]any)
	if !ok || len(kinds) != 1 {
		t.Fatalf("filter must select one kind, got %v", filter["kinds"])
	}
	if int(kinds[0].(float64)) != protocol.ExperimentalKind {
		t.Errorf("filter selects kind %v, want %d", kinds[0], protocol.ExperimentalKind)
	}

	recipients, ok := filter["#p"].([]any)
	if !ok || len(recipients) != 1 {
		t.Fatalf("filter must select this node as recipient, got %v", filter["#p"])
	}
	if recipients[0] != self.String() {
		t.Errorf("filter selects %v, want this node", recipients[0])
	}
}

// A relay keeps no memory of a subscription across connections. A reconnection
// that does not reissue one leaves a socket that is open and permanently
// silent — the node looks healthy and never receives anything, which is the
// worst shape this failure could take.
func TestReconnectionReissuesTheSubscription(t *testing.T) {
	server := newRelayServer(t)

	set, err := NewRelaySet(RelaySetOptions{
		URLs:  []string{server.url()},
		Clock: func() time.Time { return testNow() },
		Backoff: BackoffPolicy{
			Initial:    10 * time.Millisecond,
			Max:        50 * time.Millisecond,
			Multiplier: 2,
		},
	})
	if err != nil {
		t.Fatalf("building set: %v", err)
	}
	defer func() { _ = set.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := set.Connect(ctx); err != nil {
		t.Fatalf("connecting: %v", err)
	}

	self := testSigner(t, 12).PublicKey()
	if err := set.SubscribeToInbox(ctx, self); err != nil {
		t.Fatalf("subscribing: %v", err)
	}
	waitForSubscriptions(t, server, 1)

	go set.Supervise(ctx)

	// Drop the connection the way a relay restart would.
	if err := set.relays[0].Close(); err != nil {
		t.Fatalf("closing relay: %v", err)
	}

	filters := waitForSubscriptions(t, server, 2)
	if len(filters) < 2 {
		t.Fatal("the reconnected relay never reissued the subscription")
	}

	reissued := filters[len(filters)-1]
	recipients, ok := reissued["#p"].([]any)
	if !ok || len(recipients) != 1 || recipients[0] != self.String() {
		t.Errorf("the reissued subscription does not select this node: %v", reissued)
	}
}

// Deduplication happens before decryption, so the logical key must be readable
// from the cleartext routing fields alone.
func TestEnvelopeKeyReadsRoutingFieldsWithoutDecrypting(t *testing.T) {
	envelope := protocol.Envelope{
		Version:   protocol.Version,
		Namespace: protocol.Namespace,
		Type:      protocol.TypeSessionOffer,
		SessionID: "session-abc",
		Seq:       7,
		Body:      "not-decryptable-ciphertext",
	}

	content, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("encoding envelope: %v", err)
	}

	_, raw, err := BuildEvent(testSigner(t, 13), protocol.ExperimentalKind, nil, string(content), testNow())
	if err != nil {
		t.Fatalf("building event: %v", err)
	}

	key, err := EnvelopeKey(PublishedEvent{Raw: raw})
	if err != nil {
		t.Fatalf("reading key: %v", err)
	}

	if key.SessionID != "session-abc" {
		t.Errorf("session %q, want session-abc", key.SessionID)
	}
	if key.Type != string(protocol.TypeSessionOffer) {
		t.Errorf("type %q, want %s", key.Type, protocol.TypeSessionOffer)
	}
	if key.Seq != 7 {
		t.Errorf("seq %d, want 7", key.Seq)
	}
}

// An event that is not one of ours must be reported rather than mapped to an
// empty key, which would collide with every other unparseable event and make
// them look like duplicates of each other.
func TestEnvelopeKeyRejectsForeignContent(t *testing.T) {
	_, raw, err := BuildEvent(testSigner(t, 14), protocol.ExperimentalKind, nil, "not an envelope", testNow())
	if err != nil {
		t.Fatalf("building event: %v", err)
	}

	if _, err := EnvelopeKey(PublishedEvent{Raw: raw}); err == nil {
		t.Error("content that is not an envelope must be refused")
	}
}

func TestEnvelopeKeyRejectsEnvelopeWithoutSession(t *testing.T) {
	content, err := json.Marshal(protocol.Envelope{Type: protocol.TypeSessionOffer})
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}

	_, raw, err := BuildEvent(testSigner(t, 15), protocol.ExperimentalKind, nil, string(content), testNow())
	if err != nil {
		t.Fatalf("building event: %v", err)
	}

	if _, err := EnvelopeKey(PublishedEvent{Raw: raw}); err == nil {
		t.Error("an envelope with no session id must be refused")
	}
}

func TestSubscribeToInboxFailsWithNoRelayConnected(t *testing.T) {
	set := testRelaySet(t, "ws://127.0.0.1:1/a")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := set.SubscribeToInbox(ctx, testSigner(t, 16).PublicKey()); err == nil {
		t.Error("subscribing with no connection must fail")
	}
}

// waitForSubscriptions waits until the relay has seen at least count REQs.
func waitForSubscriptions(t *testing.T, server *relayServer, count int) []map[string]any {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if filters := server.subscriptionFilters(); len(filters) >= count {
			return filters
		}
		time.Sleep(20 * time.Millisecond)
	}

	filters := server.subscriptionFilters()
	t.Fatalf("relay saw %d subscriptions, expected %d", len(filters), count)
	return nil
}
