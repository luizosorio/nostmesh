package nostr

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// relayServer is a Nostr relay for testing.
//
// It speaks the real protocol over a real socket, so the client is exercised
// against framing and message handling rather than against a mock of itself.
type relayServer struct {
	mu sync.Mutex

	// accept decides the verdict for each published event.
	accept bool

	// reason accompanies a refusal.
	reason string

	// received records published events.
	received []json.RawMessage

	// deliver is sent to subscribers when set.
	deliver []json.RawMessage

	// silent makes the relay accept a publication and never answer, which is
	// how a relay that has stopped responding looks from the client side.
	silent bool

	// subscriptions records the filter of every REQ received, in order. A real
	// relay forgets a subscription when the connection ends, so this is what
	// shows whether a reconnecting client reissued one.
	subscriptions []map[string]any

	server *httptest.Server
}

// deliverEvent seeds an event the relay already holds, so a subscription is
// answered with stored content the way a real relay answers one.
func (s *relayServer) deliverEvent(raw []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.deliver = append(s.deliver, json.RawMessage(raw))
}

// subscriptionFilters returns the filters this relay was asked to subscribe.
func (s *relayServer) subscriptionFilters() []map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]map[string]any, len(s.subscriptions))
	copy(out, s.subscriptions)
	return out
}

func newRelayServer(t *testing.T) *relayServer {
	t.Helper()

	relay := &relayServer{accept: true}
	relay.server = httptest.NewServer(http.HandlerFunc(relay.handle))
	t.Cleanup(relay.server.Close)

	return relay
}

func (s *relayServer) url() string {
	return "ws" + strings.TrimPrefix(s.server.URL, "http")
}

func (s *relayServer) handle(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer func() { _ = conn.CloseNow() }()

	ctx := r.Context()

	for {
		_, payload, err := conn.Read(ctx)
		if err != nil {
			return
		}

		var frame []json.RawMessage
		if err := json.Unmarshal(payload, &frame); err != nil || len(frame) < 2 {
			continue
		}

		var kind string
		if err := json.Unmarshal(frame[0], &kind); err != nil {
			continue
		}

		switch kind {
		case "EVENT":
			s.handlePublish(ctx, conn, frame[1])
		case "REQ":
			var filter json.RawMessage
			if len(frame) > 2 {
				filter = frame[2]
			}
			s.handleRequest(ctx, conn, frame[1], filter)
		}
	}
}

func (s *relayServer) handlePublish(ctx context.Context, conn *websocket.Conn, raw json.RawMessage) {
	s.mu.Lock()
	s.received = append(s.received, raw)
	accept, reason, silent := s.accept, s.reason, s.silent
	s.mu.Unlock()

	if silent {
		return
	}

	var event struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(raw, &event); err != nil {
		return
	}

	answer, err := json.Marshal([]any{"OK", event.ID, accept, reason})
	if err != nil {
		return
	}
	_ = conn.Write(ctx, websocket.MessageText, answer)
}

func (s *relayServer) handleRequest(ctx context.Context, conn *websocket.Conn, rawID, rawFilter json.RawMessage) {
	var subscriptionID string
	if err := json.Unmarshal(rawID, &subscriptionID); err != nil {
		return
	}

	var filter map[string]any
	if len(rawFilter) > 0 {
		_ = json.Unmarshal(rawFilter, &filter)
	}

	s.mu.Lock()
	s.subscriptions = append(s.subscriptions, filter)
	deliver := make([]json.RawMessage, len(s.deliver))
	copy(deliver, s.deliver)
	s.mu.Unlock()

	for _, event := range deliver {
		frame, err := json.Marshal([]any{"EVENT", subscriptionID, event})
		if err != nil {
			continue
		}
		_ = conn.Write(ctx, websocket.MessageText, frame)
	}

	eose, err := json.Marshal([]any{"EOSE", subscriptionID})
	if err != nil {
		return
	}
	_ = conn.Write(ctx, websocket.MessageText, eose)
}

func (s *relayServer) setAccept(accept bool, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.accept, s.reason = accept, reason
}

func (s *relayServer) setSilent(silent bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.silent = silent
}

func (s *relayServer) setDeliver(events []json.RawMessage) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.deliver = events
}

func (s *relayServer) receivedCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return len(s.received)
}

func connectedRelay(t *testing.T, server *relayServer) *WebSocketRelay {
	t.Helper()

	relay, err := NewWebSocketRelay(WebSocketRelayOptions{
		URL:   server.url(),
		Clock: func() time.Time { return testNow() },
	})
	if err != nil {
		t.Fatalf("building relay: %v", err)
	}

	if err := relay.Connect(context.Background()); err != nil {
		t.Fatalf("connecting: %v", err)
	}
	t.Cleanup(func() { _ = relay.Close() })

	return relay
}

func testRawEvent(id string) []byte {
	raw, _ := json.Marshal(map[string]any{
		"id":      id,
		"kind":    31111,
		"content": "encrypted",
	})
	return raw
}

func TestWebSocketPublishAccepted(t *testing.T) {
	server := newRelayServer(t)
	relay := connectedRelay(t, server)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := relay.Publish(ctx, "event-1", testRawEvent("event-1")); err != nil {
		t.Fatalf("publishing: %v", err)
	}
	if server.receivedCount() != 1 {
		t.Errorf("relay received %d events, want 1", server.receivedCount())
	}
}

// A relay refusing an event — as one rejecting an unknown kind would — must be
// reported as a refusal rather than a transport failure, so the client can tell
// "this relay will not take it" from "this relay is unreachable".
func TestWebSocketPublishRejected(t *testing.T) {
	server := newRelayServer(t)
	server.setAccept(false, "kind not accepted")

	relay := connectedRelay(t, server)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := relay.Publish(ctx, "event-1", testRawEvent("event-1"))
	if !errors.Is(err, ErrRelayRejected) {
		t.Fatalf("expected ErrRelayRejected, got: %v", err)
	}
	if !strings.Contains(err.Error(), "kind not accepted") {
		t.Errorf("the relay's reason must be reported, got: %v", err)
	}
}

// A relay that accepts and never answers must not block forever: the context
// bounds the wait, and the caller falls back to other relays.
func TestWebSocketSilentRelayTimesOut(t *testing.T) {
	server := newRelayServer(t)
	server.setSilent(true)

	relay := connectedRelay(t, server)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	started := time.Now()
	err := relay.Publish(ctx, "event-1", testRawEvent("event-1"))

	if err == nil {
		t.Fatal("a silent relay must not appear successful")
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Errorf("waited %s; the context must bound the wait", elapsed)
	}
}

func TestWebSocketDeliversEvents(t *testing.T) {
	server := newRelayServer(t)
	server.setDeliver([]json.RawMessage{
		testRawEvent("delivered-1"),
		testRawEvent("delivered-2"),
	})

	relay := connectedRelay(t, server)
	stream := relay.Subscribe(16)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := relay.RequestEvents(ctx, "sub-1", map[string]any{"kinds": []int{31111}}); err != nil {
		t.Fatalf("subscribing: %v", err)
	}

	received := make(map[string]bool)
	deadline := time.After(2 * time.Second)

	for len(received) < 2 {
		select {
		case event := <-stream:
			received[event.ID] = true
			if event.Relay != server.url() {
				t.Errorf("event attributed to %s, want %s", event.Relay, server.url())
			}
		case <-deadline:
			t.Fatalf("received %d of 2 events before the deadline", len(received))
		}
	}
}

// Publishing without a connection must fail clearly rather than panic or block.
func TestWebSocketPublishWithoutConnection(t *testing.T) {
	relay, err := NewWebSocketRelay(WebSocketRelayOptions{URL: "wss://unused.invalid"})
	if err != nil {
		t.Fatalf("building relay: %v", err)
	}

	err = relay.Publish(context.Background(), "event-1", testRawEvent("event-1"))
	if !errors.Is(err, ErrRelayNotConnected) {
		t.Errorf("expected ErrRelayNotConnected, got: %v", err)
	}
}

// Closing must release a waiting publisher rather than leaving it blocked on a
// connection that is gone.
func TestWebSocketCloseReleasesWaiters(t *testing.T) {
	server := newRelayServer(t)
	server.setSilent(true)

	relay := connectedRelay(t, server)

	done := make(chan error, 1)
	go func() {
		done <- relay.Publish(context.Background(), "event-1", testRawEvent("event-1"))
	}()

	// Give the publish time to register as pending.
	time.Sleep(100 * time.Millisecond)

	if err := relay.Close(); err != nil {
		t.Fatalf("closing: %v", err)
	}

	select {
	case err := <-done:
		if err == nil {
			t.Error("a publish interrupted by close must fail")
		}
	case <-time.After(2 * time.Second):
		t.Error("closing did not release the waiting publisher")
	}
}

// A relay sending garbage is misbehaving; the client keeps working rather than
// failing.
func TestWebSocketIgnoresMalformedMessages(t *testing.T) {
	relay, err := NewWebSocketRelay(WebSocketRelayOptions{URL: "wss://unused.invalid"})
	if err != nil {
		t.Fatalf("building relay: %v", err)
	}

	for _, garbage := range [][]byte{
		[]byte("not json"),
		[]byte("[]"),
		[]byte(`["OK"]`),
		[]byte(`["EVENT"]`),
		[]byte(`{"not":"an array"}`),
		[]byte(`["OK", 123, "not a bool"]`),
	} {
		// Must not panic.
		relay.dispatch(garbage)
	}
}

func TestWebSocketRequiresURL(t *testing.T) {
	if _, err := NewWebSocketRelay(WebSocketRelayOptions{}); err == nil {
		t.Error("a relay without a URL must be refused")
	}
}

// Connecting to something that is not a relay must fail rather than hang.
func TestWebSocketConnectionFailure(t *testing.T) {
	relay, err := NewWebSocketRelay(WebSocketRelayOptions{URL: "ws://127.0.0.1:1"})
	if err != nil {
		t.Fatalf("building relay: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := relay.Connect(ctx); err == nil {
		t.Error("connecting to a closed port must fail")
	}
	if relay.IsConnected() {
		t.Error("a failed connection must not report as connected")
	}
}
