// Package observabilitytest captures log records so a test can assert on them.
//
// It is a separate package so that production code cannot link it: a capture
// handler in the binary would be a way for records to be retained in memory,
// which is the opposite of what a log is for.
package observabilitytest

import (
	"context"
	"log/slog"
	"sync"
)

// Handler records everything it is given.
//
// It does not format: a test asserting on an attribute should read the
// attribute, not parse it back out of JSON. Formatting is the JSON handler's
// job and is tested where it belongs.
type Handler struct {
	level slog.Level

	// attrs and groups are this handler's own, accumulated through WithAttrs
	// and WithGroup. They are immutable once set, so they need no lock.
	attrs  []slog.Attr
	groups []string

	// transcript is shared with every handler derived from this one.
	//
	// A child logger's output belongs in the same transcript as its parent's:
	// a test asserting that a component logged something should not have to
	// know which logger in the chain emitted it.
	transcript *transcript
}

// transcript is the shared record of everything captured.
type transcript struct {
	mu      sync.Mutex
	records []Record
}

func (t *transcript) append(record Record) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.records = append(t.records, record)
}

func (t *transcript) all() []Record {
	t.mu.Lock()
	defer t.mu.Unlock()

	return append([]Record{}, t.records...)
}

// Record is one captured log record, flattened for assertion.
type Record struct {
	Level   slog.Level
	Message string
	Attrs   map[string]slog.Value
}

// New returns a logger and the handler recording for it.
func New(level slog.Level) (*slog.Logger, *Handler) {
	handler := &Handler{level: level, transcript: &transcript{}}
	return slog.New(handler), handler
}

// Enabled reports whether the level passes.
func (h *Handler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level
}

// Handle records one entry.
func (h *Handler) Handle(_ context.Context, record slog.Record) error {
	captured := Record{
		Level:   record.Level,
		Message: record.Message,
		Attrs:   make(map[string]slog.Value, record.NumAttrs()+len(h.attrs)),
	}

	for _, attr := range h.attrs {
		captured.Attrs[attr.Key] = attr.Value.Resolve()
	}
	record.Attrs(func(attr slog.Attr) bool {
		captured.Attrs[attr.Key] = attr.Value.Resolve()
		return true
	})

	h.transcript.append(captured)

	return nil
}

// WithAttrs returns a handler carrying the given attributes.
func (h *Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &Handler{
		level:      h.level,
		attrs:      append(append([]slog.Attr{}, h.attrs...), attrs...),
		groups:     h.groups,
		transcript: h.transcript,
	}
}

// WithGroup returns a handler nesting under the given group.
func (h *Handler) WithGroup(name string) slog.Handler {
	return &Handler{
		level:      h.level,
		attrs:      h.attrs,
		groups:     append(append([]string{}, h.groups...), name),
		transcript: h.transcript,
	}
}

// Records returns everything captured so far, by any derived logger.
func (h *Handler) Records() []Record { return h.transcript.all() }

// Events returns the event name of each captured record, in order.
func (h *Handler) Events() []string {
	records := h.Records()
	events := make([]string, 0, len(records))

	for _, record := range records {
		if value, ok := record.Attrs["event"]; ok {
			events = append(events, value.String())
		}
	}
	return events
}

// Find returns the first record carrying the given event name.
func (h *Handler) Find(event string) (Record, bool) {
	for _, record := range h.Records() {
		if value, ok := record.Attrs["event"]; ok && value.String() == event {
			return record, true
		}
	}
	return Record{}, false
}

// Reset discards what has been captured.
func (h *Handler) Reset() {
	h.transcript.mu.Lock()
	defer h.transcript.mu.Unlock()

	h.transcript.records = nil
}
