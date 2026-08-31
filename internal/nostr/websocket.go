package nostr

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// Relay message limits.
//
// A relay is untrusted, so every bound here is a defence rather than a
// preference: an unbounded read from a hostile relay is memory exhaustion
// handed over for free.
const (
	// maxRelayMessage bounds one incoming frame.
	maxRelayMessage = 512 * 1024

	// relayHandshakeTimeout bounds connection setup.
	relayHandshakeTimeout = 10 * time.Second

	// relayWriteTimeout bounds one publish.
	relayWriteTimeout = 10 * time.Second
)

var (
	// ErrRelayNotConnected reports use of a relay that is not connected.
	ErrRelayNotConnected = errors.New("relay is not connected")

	// ErrRelayClosed reports a relay whose connection ended.
	ErrRelayClosed = errors.New("relay connection closed")
)

// WebSocketRelay connects to a Nostr relay over WebSocket.
//
// It implements the same Relay interface the fake does, so every test written
// against adversarial behaviour in M1.2 describes this too.
type WebSocketRelay struct {
	mu sync.Mutex

	url  string
	conn *websocket.Conn

	// subscribers receive delivered events. Each gets its own channel so a slow
	// one cannot block the others.
	subscribers []chan PublishedEvent

	// pending maps an event id to the channel awaiting the relay's verdict.
	pending map[string]chan relayVerdict

	// dropped counts deliveries discarded because a subscriber was not reading.
	//
	// A drop is invisible from the outside: the relay sent the event, the client
	// never saw it, and nothing reports a failure. Counting them is what turns
	// "the message never arrived" into "the message arrived and we discarded it",
	// which are different problems with different fixes.
	dropped int

	clock func() time.Time
}

// eventIDOf extracts the id a relay will answer with.
func eventIDOf(raw []byte) (string, error) {
	var event struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(raw, &event); err != nil {
		return "", fmt.Errorf("parsing event: %w", err)
	}
	if event.ID == "" {
		return "", errors.New("event has no id")
	}
	return event.ID, nil
}

// relayVerdict is a relay's answer to a publication.
type relayVerdict struct {
	accepted bool
	reason   string
}

// WebSocketRelayOptions configures a relay connection.
type WebSocketRelayOptions struct {
	// URL is the relay address, for example wss://relay.example.
	URL string

	// Clock is injected for testing.
	Clock func() time.Time
}

// NewWebSocketRelay builds an unconnected relay.
func NewWebSocketRelay(opts WebSocketRelayOptions) (*WebSocketRelay, error) {
	if opts.URL == "" {
		return nil, errors.New("relay requires a URL")
	}
	if opts.Clock == nil {
		opts.Clock = time.Now
	}

	return &WebSocketRelay{
		url:     opts.URL,
		pending: make(map[string]chan relayVerdict),
		clock:   opts.Clock,
	}, nil
}

// URL returns the relay address.
func (r *WebSocketRelay) URL() string { return r.url }

// Connect opens the WebSocket and starts reading.
func (r *WebSocketRelay) Connect(ctx context.Context) error {
	r.mu.Lock()
	if r.conn != nil {
		r.mu.Unlock()
		return nil
	}
	r.mu.Unlock()

	dialCtx, cancel := context.WithTimeout(ctx, relayHandshakeTimeout)
	defer cancel()

	conn, handshake, err := websocket.Dial(dialCtx, r.url, nil)
	if handshake != nil && handshake.Body != nil {
		// The handshake response body is not used, but leaving it open leaks
		// the underlying connection — including on the error path, where a
		// relay that refused the upgrade would otherwise cost a socket per
		// reconnection attempt.
		_ = handshake.Body.Close()
	}
	if err != nil {
		return fmt.Errorf("connecting to %s: %w", r.url, err)
	}
	conn.SetReadLimit(maxRelayMessage)

	r.mu.Lock()
	r.conn = conn
	r.mu.Unlock()

	go r.read(ctx, conn)
	return nil
}

// Close ends the connection.
func (r *WebSocketRelay) Close() error {
	r.mu.Lock()
	conn := r.conn
	r.conn = nil

	// Waiting publishers are released rather than left blocked on a connection
	// that is gone.
	for id, waiter := range r.pending {
		close(waiter)
		delete(r.pending, id)
	}
	r.mu.Unlock()

	if conn == nil {
		return nil
	}
	return conn.Close(websocket.StatusNormalClosure, "")
}

// Publish sends an event and waits for the relay's verdict.
//
// A relay that accepts and then discards the event is indistinguishable from
// one that stored it, which is why publication fans out across relays rather
// than trusting any single acceptance.
func (r *WebSocketRelay) Publish(ctx context.Context, id string, raw []byte) error {
	// A relay answers with the event's own id, not with whatever the caller
	// used to track it. Registering the waiter under the caller's id would mean
	// the verdict never matches and every publish times out — which looks
	// exactly like a relay refusing the message.
	eventID, err := eventIDOf(raw)
	if err != nil {
		return fmt.Errorf("reading event id: %w", err)
	}
	_ = id

	r.mu.Lock()
	conn := r.conn
	if conn == nil {
		r.mu.Unlock()
		return fmt.Errorf("%w: %s", ErrRelayNotConnected, r.url)
	}

	verdict := make(chan relayVerdict, 1)
	r.pending[eventID] = verdict
	r.mu.Unlock()

	defer func() {
		r.mu.Lock()
		delete(r.pending, eventID)
		r.mu.Unlock()
	}()

	frame, err := json.Marshal([]any{"EVENT", json.RawMessage(raw)})
	if err != nil {
		return fmt.Errorf("encoding event: %w", err)
	}

	writeCtx, cancel := context.WithTimeout(ctx, relayWriteTimeout)
	defer cancel()

	if err := conn.Write(writeCtx, websocket.MessageText, frame); err != nil {
		return fmt.Errorf("publishing to %s: %w", r.url, err)
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case answer, open := <-verdict:
		if !open {
			return fmt.Errorf("%w: %s", ErrRelayClosed, r.url)
		}
		if !answer.accepted {
			return fmt.Errorf("%w: %s: %s", ErrRelayRejected, r.url, answer.reason)
		}
		return nil
	}
}

// Subscribe returns a channel of events this relay delivers.
func (r *WebSocketRelay) Subscribe(buffer int) <-chan PublishedEvent {
	if buffer <= 0 {
		buffer = 64
	}

	channel := make(chan PublishedEvent, buffer)

	r.mu.Lock()
	r.subscribers = append(r.subscribers, channel)
	r.mu.Unlock()

	return channel
}

// RequestEvents asks the relay for events matching a filter.
func (r *WebSocketRelay) RequestEvents(ctx context.Context, subscriptionID string, filter map[string]any) error {
	r.mu.Lock()
	conn := r.conn
	r.mu.Unlock()

	if conn == nil {
		return fmt.Errorf("%w: %s", ErrRelayNotConnected, r.url)
	}

	frame, err := json.Marshal([]any{"REQ", subscriptionID, filter})
	if err != nil {
		return fmt.Errorf("encoding request: %w", err)
	}

	writeCtx, cancel := context.WithTimeout(ctx, relayWriteTimeout)
	defer cancel()

	if err := conn.Write(writeCtx, websocket.MessageText, frame); err != nil {
		return fmt.Errorf("subscribing on %s: %w", r.url, err)
	}
	return nil
}

// read consumes relay messages until the connection ends.
func (r *WebSocketRelay) read(ctx context.Context, conn *websocket.Conn) {
	defer func() {
		r.mu.Lock()
		if r.conn == conn {
			r.conn = nil
		}
		r.mu.Unlock()
	}()

	for {
		_, payload, err := conn.Read(ctx)
		if err != nil {
			return
		}
		r.dispatch(payload)
	}
}

// dispatch routes one relay message.
//
// A message that cannot be parsed is dropped. A relay sending garbage is
// misbehaving, and the client's job is to keep working rather than to complain.
func (r *WebSocketRelay) dispatch(payload []byte) {
	var frame []json.RawMessage
	if err := json.Unmarshal(payload, &frame); err != nil || len(frame) == 0 {
		return
	}

	var kind string
	if err := json.Unmarshal(frame[0], &kind); err != nil {
		return
	}

	switch kind {
	case "OK":
		r.handleVerdict(frame)
	case "EVENT":
		r.handleEvent(frame)
	case "NOTICE", "EOSE", "CLOSED":
		// Informational. A NOTICE is a relay's opinion, and this client does
		// not act on opinions.
	}
}

// handleVerdict processes ["OK", <id>, <accepted>, <reason>].
func (r *WebSocketRelay) handleVerdict(frame []json.RawMessage) {
	if len(frame) < 3 {
		return
	}

	var id string
	if err := json.Unmarshal(frame[1], &id); err != nil {
		return
	}

	var accepted bool
	if err := json.Unmarshal(frame[2], &accepted); err != nil {
		return
	}

	reason := ""
	if len(frame) > 3 {
		_ = json.Unmarshal(frame[3], &reason)
	}

	r.mu.Lock()
	waiter, waiting := r.pending[id]
	r.mu.Unlock()

	if !waiting {
		return
	}

	select {
	case waiter <- relayVerdict{accepted: accepted, reason: reason}:
	default:
	}
}

// handleEvent processes ["EVENT", <subscription>, <event>].
func (r *WebSocketRelay) handleEvent(frame []json.RawMessage) {
	if len(frame) < 3 {
		return
	}

	var envelope struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(frame[2], &envelope); err != nil || envelope.ID == "" {
		return
	}

	event := PublishedEvent{
		ID:    envelope.ID,
		Raw:   frame[2],
		Relay: r.url,
		At:    r.clock(),
	}

	r.mu.Lock()
	subscribers := make([]chan PublishedEvent, len(r.subscribers))
	copy(subscribers, r.subscribers)
	r.mu.Unlock()

	var dropped int
	for _, subscriber := range subscribers {
		select {
		case subscriber <- event:
		default:
			// A subscriber that is not reading is skipped rather than blocking
			// the read loop, which would stall every other subscriber too. The
			// drop is counted so it can be reported: silently losing an event
			// the relay did deliver is indistinguishable from never receiving
			// it, and the two have opposite fixes.
			dropped++
		}
	}

	if dropped > 0 {
		r.mu.Lock()
		r.dropped += dropped
		r.mu.Unlock()
	}
}

// Dropped reports how many deliveries this relay discarded for want of a reader.
func (r *WebSocketRelay) Dropped() int {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.dropped
}

// IsConnected reports whether the relay has a live connection.
func (r *WebSocketRelay) IsConnected() bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.conn != nil
}

var _ Relay = (*WebSocketRelay)(nil)
