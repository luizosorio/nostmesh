package nostr

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newTestOutbox(t *testing.T, dir string) *Outbox {
	t.Helper()

	outbox, err := NewOutbox(OutboxOptions{
		Dir:         dir,
		MaxEntries:  10,
		MaxAttempts: 3,
		Clock:       func() time.Time { return testNow() },
	})
	if err != nil {
		t.Fatalf("building outbox: %v", err)
	}
	return outbox
}

func testEntry(id string) Entry {
	raw, _ := json.Marshal(map[string]string{"id": id})
	return Entry{
		ID:        id,
		Event:     raw,
		QueuedAt:  testNow(),
		ExpiresAt: testNow().Add(time.Hour),
	}
}

// The point of a persistent outbox: work survives a restart. A queue that lives
// only in memory loses exactly the messages a crash made most important.
func TestOutboxSurvivesRestart(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "outbox")

	first := newTestOutbox(t, dir)
	for _, id := range []string{"a", "b", "c"} {
		if err := first.Enqueue(testEntry(id)); err != nil {
			t.Fatalf("enqueueing %s: %v", id, err)
		}
	}

	// A new instance over the same directory stands in for a restart.
	second := newTestOutbox(t, dir)

	pending, err := second.Pending()
	if err != nil {
		t.Fatalf("reading pending: %v", err)
	}
	if len(pending) != 3 {
		t.Fatalf("recovered %d entries, want 3", len(pending))
	}
}

// Re-queuing the same id replaces rather than duplicates, so a caller retrying
// after a crash does not produce two copies.
func TestEnqueueIsIdempotent(t *testing.T) {
	outbox := newTestOutbox(t, filepath.Join(t.TempDir(), "outbox"))

	for range 3 {
		if err := outbox.Enqueue(testEntry("a")); err != nil {
			t.Fatalf("enqueueing: %v", err)
		}
	}

	size, err := outbox.Size()
	if err != nil {
		t.Fatalf("reading size: %v", err)
	}
	if size != 1 {
		t.Errorf("outbox holds %d entries, want 1", size)
	}
}

// An unbounded queue turns a relay outage into unbounded disk use, discovered
// as a full disk rather than as a networking problem.
func TestOutboxRefusesWhenFull(t *testing.T) {
	outbox := newTestOutbox(t, filepath.Join(t.TempDir(), "outbox"))

	for i := range 10 {
		if err := outbox.Enqueue(testEntry(string(rune('a' + i)))); err != nil {
			t.Fatalf("enqueueing entry %d: %v", i, err)
		}
	}

	err := outbox.Enqueue(testEntry("overflow"))
	if !errors.Is(err, ErrOutboxFull) {
		t.Errorf("expected ErrOutboxFull, got: %v", err)
	}
}

// Replacing an entry must not count against capacity, or a full queue could
// never be updated.
func TestReplacingDoesNotConsumeCapacity(t *testing.T) {
	outbox := newTestOutbox(t, filepath.Join(t.TempDir(), "outbox"))

	for i := range 10 {
		if err := outbox.Enqueue(testEntry(string(rune('a' + i)))); err != nil {
			t.Fatalf("enqueueing: %v", err)
		}
	}

	if err := outbox.Enqueue(testEntry("a")); err != nil {
		t.Errorf("replacing an existing entry in a full queue must succeed: %v", err)
	}
}

// A message past its validity window would be rejected by the recipient anyway,
// so retrying it wastes attempts that newer messages need.
func TestExpiredEntriesAreDropped(t *testing.T) {
	outbox := newTestOutbox(t, filepath.Join(t.TempDir(), "outbox"))

	expired := testEntry("stale")
	expired.ExpiresAt = testNow().Add(-time.Hour)
	if err := outbox.Enqueue(expired); err != nil {
		t.Fatalf("enqueueing: %v", err)
	}
	if err := outbox.Enqueue(testEntry("fresh")); err != nil {
		t.Fatalf("enqueueing: %v", err)
	}

	pending, err := outbox.Pending()
	if err != nil {
		t.Fatalf("reading pending: %v", err)
	}
	if len(pending) != 1 || pending[0].ID != "fresh" {
		t.Errorf("expected only the fresh entry, got %d", len(pending))
	}
}

// An entry nobody accepts after enough tries is not going to be accepted, and
// retrying it forever starves newer work.
func TestExhaustedEntriesAreAbandoned(t *testing.T) {
	outbox := newTestOutbox(t, filepath.Join(t.TempDir(), "outbox"))

	if err := outbox.Enqueue(testEntry("stubborn")); err != nil {
		t.Fatalf("enqueueing: %v", err)
	}

	for range 3 {
		if err := outbox.RecordAttempt("stubborn", nil); err != nil {
			t.Fatalf("recording attempt: %v", err)
		}
	}

	pending, err := outbox.Pending()
	if err != nil {
		t.Fatalf("reading pending: %v", err)
	}
	if len(pending) != 0 {
		t.Errorf("an exhausted entry must be abandoned, %d remain", len(pending))
	}
}

// Which relays already have an event is tracked so a retry need not re-offer it
// to a relay that accepted.
func TestAcceptancesAccumulate(t *testing.T) {
	outbox := newTestOutbox(t, filepath.Join(t.TempDir(), "outbox"))

	if err := outbox.Enqueue(testEntry("a")); err != nil {
		t.Fatalf("enqueueing: %v", err)
	}

	if err := outbox.RecordAttempt("a", []string{"wss://one"}); err != nil {
		t.Fatalf("recording: %v", err)
	}
	if err := outbox.RecordAttempt("a", []string{"wss://one", "wss://two"}); err != nil {
		t.Fatalf("recording: %v", err)
	}

	pending, err := outbox.Pending()
	if err != nil {
		t.Fatalf("reading pending: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(pending))
	}
	if got := len(pending[0].AcceptedBy); got != 2 {
		t.Errorf("tracked %d acceptances, want 2 without duplicates", got)
	}
}

// An id becomes a filename, so it must not escape the outbox directory.
func TestOutboxRejectsPathTraversal(t *testing.T) {
	outbox := newTestOutbox(t, filepath.Join(t.TempDir(), "outbox"))

	for _, id := range []string{"../escape", "sub/dir", "a.b"} {
		t.Run(id, func(t *testing.T) {
			entry := testEntry("placeholder")
			entry.ID = id

			if err := outbox.Enqueue(entry); err == nil {
				t.Errorf("id %q must be rejected", id)
			}
		})
	}
}

// One corrupt entry must not stop the queue: there is still work to do.
func TestCorruptEntryDoesNotHideOthers(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "outbox")
	outbox := newTestOutbox(t, dir)

	if err := outbox.Enqueue(testEntry("good")); err != nil {
		t.Fatalf("enqueueing: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "corrupt.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatalf("writing corrupt entry: %v", err)
	}

	pending, err := outbox.Pending()
	if err != nil {
		t.Fatalf("reading pending: %v", err)
	}
	if len(pending) != 1 || pending[0].ID != "good" {
		t.Errorf("expected the readable entry, got %d", len(pending))
	}
}

func TestOutboxFilesAreOwnerOnly(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "outbox")
	outbox := newTestOutbox(t, dir)

	if err := outbox.Enqueue(testEntry("a")); err != nil {
		t.Fatalf("enqueueing: %v", err)
	}

	info, err := os.Stat(filepath.Join(dir, "a.json"))
	if err != nil {
		t.Fatalf("inspecting entry: %v", err)
	}
	if perm := info.Mode().Perm(); perm != outboxFileMode {
		t.Errorf("mode = %04o, want %04o", perm, outboxFileMode)
	}
}

// Oldest first: a message queued earlier is more likely to be near its expiry.
func TestPendingIsOldestFirst(t *testing.T) {
	outbox := newTestOutbox(t, filepath.Join(t.TempDir(), "outbox"))

	for i, id := range []string{"third", "first", "second"} {
		entry := testEntry(id)
		switch id {
		case "first":
			entry.QueuedAt = testNow()
		case "second":
			entry.QueuedAt = testNow().Add(time.Minute)
		case "third":
			entry.QueuedAt = testNow().Add(2 * time.Minute)
		}
		if err := outbox.Enqueue(entry); err != nil {
			t.Fatalf("enqueueing %d: %v", i, err)
		}
	}

	pending, err := outbox.Pending()
	if err != nil {
		t.Fatalf("reading pending: %v", err)
	}

	want := []string{"first", "second", "third"}
	for i, entry := range pending {
		if entry.ID != want[i] {
			t.Errorf("position %d is %s, want %s", i, entry.ID, want[i])
		}
	}
}
