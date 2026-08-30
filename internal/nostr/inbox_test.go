package nostr

import (
	"testing"
	"time"
)

func newTestInbox(t *testing.T, now *time.Time) *Inbox {
	t.Helper()

	return NewInbox(InboxOptions{
		TTL:        time.Hour,
		MaxEntries: 5,
		Clock:      func() time.Time { return *now },
	})
}

func testKeyFor(seq uint64) LogicalKey {
	return LogicalKey{SessionID: "session-1", Type: "session.request", Seq: seq}
}

func TestInboxAcceptsNewMessages(t *testing.T) {
	now := testNow()
	inbox := newTestInbox(t, &now)

	for i := range 3 {
		if verdict := inbox.Observe("event-"+string(rune('a'+i)), testKeyFor(uint64(i))); verdict != VerdictNew {
			t.Errorf("message %d verdict = %s, want new", i, verdict)
		}
	}
}

// The same event from several relays is the expected case, not a suspicious
// one: redundancy is why the control plane survives a relay going down.
func TestSameEventFromManyRelaysIsDeduplicated(t *testing.T) {
	now := testNow()
	inbox := newTestInbox(t, &now)

	if verdict := inbox.Observe("event-1", testKeyFor(0)); verdict != VerdictNew {
		t.Fatalf("first delivery verdict = %s, want new", verdict)
	}

	for i := range 5 {
		if verdict := inbox.Observe("event-1", testKeyFor(0)); verdict != VerdictDuplicate {
			t.Errorf("copy %d verdict = %s, want duplicate", i, verdict)
		}
	}
}

// Two distinct events claiming the same session position is not duplication.
// One of them is not what it claims, and the session's ordering can no longer
// be trusted.
func TestDifferentEventsAtSamePositionConflict(t *testing.T) {
	now := testNow()
	inbox := newTestInbox(t, &now)

	if verdict := inbox.Observe("event-1", testKeyFor(0)); verdict != VerdictNew {
		t.Fatalf("first verdict = %s, want new", verdict)
	}

	if verdict := inbox.Observe("event-2", testKeyFor(0)); verdict != VerdictConflict {
		t.Errorf("verdict = %s, want conflict", verdict)
	}
}

// The same event id under a different logical key is still a duplicate: the
// event id is checked first, and an identical event cannot mean two things.
func TestEventIDTakesPrecedence(t *testing.T) {
	now := testNow()
	inbox := newTestInbox(t, &now)

	inbox.Observe("event-1", testKeyFor(0))

	if verdict := inbox.Observe("event-1", testKeyFor(99)); verdict != VerdictDuplicate {
		t.Errorf("verdict = %s, want duplicate", verdict)
	}
}

// Forgetting is safe: a message older than the TTL is outside its own validity
// window, so replaying it fails on expiry instead.
func TestEntriesExpire(t *testing.T) {
	now := testNow()
	inbox := newTestInbox(t, &now)

	inbox.Observe("event-1", testKeyFor(0))
	if inbox.Size() != 1 {
		t.Fatalf("inbox holds %d entries, want 1", inbox.Size())
	}

	now = now.Add(2 * time.Hour)

	if verdict := inbox.Observe("event-2", testKeyFor(1)); verdict != VerdictNew {
		t.Errorf("verdict = %s, want new", verdict)
	}
	if inbox.Size() != 1 {
		t.Errorf("expired entries were not evicted, %d remain", inbox.Size())
	}
}

// A peer that floods must not be able to grow memory without limit.
func TestInboxIsBounded(t *testing.T) {
	now := testNow()
	inbox := newTestInbox(t, &now)

	for i := range 20 {
		inbox.Observe("event-"+string(rune('a'+i)), testKeyFor(uint64(i)))
	}

	if size := inbox.Size(); size > 5 {
		t.Errorf("inbox holds %d entries, above the limit of 5", size)
	}
}

// Concurrent delivery from several relays is the normal case, so the inbox has
// to be safe under it.
func TestInboxIsConcurrencySafe(t *testing.T) {
	now := testNow()
	inbox := NewInbox(InboxOptions{
		TTL:        time.Hour,
		MaxEntries: 1000,
		Clock:      func() time.Time { return now },
	})

	done := make(chan struct{})
	for worker := range 8 {
		go func(w int) {
			defer func() { done <- struct{}{} }()
			for i := range 50 {
				inbox.Observe("event-shared", testKeyFor(0))
				inbox.Observe("event-"+string(rune('a'+w))+string(rune('0'+i%10)), testKeyFor(uint64(i)))
			}
		}(worker)
	}
	for range 8 {
		<-done
	}

	// The shared event must have been counted once regardless of interleaving.
	if verdict := inbox.Observe("event-shared", testKeyFor(0)); verdict != VerdictDuplicate {
		t.Errorf("verdict = %s, want duplicate", verdict)
	}
}
