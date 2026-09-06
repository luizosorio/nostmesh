package main

import (
	"context"
	"log/slog"
	"strings"
	"sync"

	"github.com/luizosorio/nostmesh/internal/observability"
)

// progressHandler renders log records as prose for a person watching a session
// come up.
//
// The daemon wants JSON in a journal; somebody running `nostmesh session` wants
// to read what is happening. Both want the same events, which is what makes
// defining them once worthwhile: this renders the structured record rather than
// carrying a second, parallel set of progress strings that could drift from it.
//
// Only events with something to say to a person are rendered. A record with no
// phrasing here is dropped rather than printed raw, because a terminal filling
// with JSON is worse than a terminal saying less.
type progressHandler struct {
	out   *output
	level slog.Level

	// inherited carries attributes fixed by WithAttrs, so a child logger's
	// component tag reaches the phrasing.
	inherited map[string]string

	// mu serializes writes, since records arrive from the driver's goroutines.
	//
	// A pointer so that a handler derived by WithAttrs shares the parent's lock
	// rather than taking its own: they write to the same terminal, and two locks
	// over one writer serialize nothing.
	mu *sync.Mutex
}

func newProgressHandler(out *output, level slog.Level) *progressHandler {
	return &progressHandler{out: out, level: level, mu: &sync.Mutex{}}
}

// sessionProgressLogger is what `nostmesh session` hands to the runtime.
//
// Named rather than built inline at the call site so a test can assert on the
// logger the command actually uses. Asserting on a handler the test constructs
// itself proves the handler works and says nothing about whether the command
// wires it up — which is exactly how a terminal would end up full of JSON with
// every test still green.
func sessionProgressLogger(out *output) *slog.Logger {
	return slog.New(newProgressHandler(out, slog.LevelDebug))
}

// Enabled reports whether the level passes.
func (h *progressHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level
}

// Handle renders one record, if it has a phrasing.
func (h *progressHandler) Handle(_ context.Context, record slog.Record) error {
	attrs := make(map[string]string, record.NumAttrs()+len(h.inherited))
	for key, value := range h.inherited {
		attrs[key] = value
	}
	record.Attrs(func(attr slog.Attr) bool {
		attrs[attr.Key] = attr.Value.Resolve().String()
		return true
	})

	line, ok := phrase(attrs)
	if !ok {
		return nil
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	h.out.printf("  %s\n", line)
	return nil
}

// WithAttrs returns a handler carrying the given attributes.
//
// The attributes are folded into the handler so a child logger's component tag
// reaches the phrasing, which is how a line knows which layer it came from.
func (h *progressHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	child := &progressHandler{out: h.out, level: h.level, mu: h.mu}
	child.inherited = make(map[string]string, len(h.inherited)+len(attrs))
	for key, value := range h.inherited {
		child.inherited[key] = value
	}
	for _, attr := range attrs {
		child.inherited[attr.Key] = attr.Value.Resolve().String()
	}
	return child
}

// WithGroup is a no-op: prose has no nesting.
func (h *progressHandler) WithGroup(string) slog.Handler { return h }

// phrase turns a record's attributes into a sentence, if it has one.
//
// The vocabulary is deliberately partial. A session that comes up cleanly should
// print a handful of lines, not a transcript — the transcript is what the log
// file is for, and this is what a person reads while waiting.
func phrase(attrs map[string]string) (string, bool) {
	event := attrs[observability.KeyEvent]
	reason := attrs[observability.KeyReason]

	switch event {
	case "relay.connected":
		return "connected to " + attrs["relay"], true
	case "relay.disconnected":
		return "lost " + attrs["relay"] + describeReason(reason), true
	case "relay.subscribed":
		return "subscribed for messages", true

	case "envelope.published":
		return "sent " + attrs["type"] + " to " + attrs["accepted"] + " relay(s)", true
	case "envelope.publish.failed":
		return "could not send " + attrs["type"] + describeReason(reason), true
	case "envelope.decrypted":
		return "received " + attrs["type"] + " seq=" + attrs["seq"], true
	case "envelope.rejected":
		return "ignored a message" + describeReason(reason), true

	case "session.state":
		return attrs["from"] + " -> " + attrs["to"], true
	case "candidate.gather.done":
		return "gathered " + attrs["count"] + " candidate(s)", true
	case "candidate.promoted":
		return "path verified", true
	case "handshake.observed":
		return "tunnel handshake completed", true
	}

	return "", false
}

// describeReason appends a cause when there is one.
func describeReason(reason string) string {
	if strings.TrimSpace(reason) == "" {
		return ""
	}
	return " (" + strings.ReplaceAll(reason, "_", " ") + ")"
}
