package nostr

import (
	"fmt"
	"sync"
	"time"
)

// Inbox tracks which messages have already been seen.
//
// Relays are independent and each delivers its own copy, so the same message
// arrives several times by design — that redundancy is what makes the control
// plane survive a relay going down. Deduplication turns it back into one
// message.
//
// Two keys are tracked, because they catch different things:
//
//   - The Nostr event id catches literal duplicates: the same event relayed
//     twice.
//   - The logical key (session, type, seq) catches a peer that re-sends the
//     same logical message as a new event, and detects the dangerous case where
//     two different events claim the same position in a session.
type Inbox struct {
	mu sync.Mutex

	// seenEvents maps event id to when it was first seen.
	seenEvents map[string]time.Time

	// seenLogical maps a logical key to the event id that claimed it.
	seenLogical map[string]string

	// ttl bounds how long an entry is remembered. Beyond it a replay is caught
	// by the message's own expiry window instead.
	ttl time.Duration

	// maxEntries bounds memory. A peer that floods must not be able to grow
	// this without limit.
	maxEntries int

	clock func() time.Time
}

// InboxOptions configures an Inbox.
type InboxOptions struct {
	// TTL is how long an entry is remembered. It should exceed the protocol's
	// validity window, so that a message still inside its window is always
	// recognised as a duplicate.
	TTL time.Duration

	// MaxEntries bounds how many entries are held.
	MaxEntries int

	// Clock is injected for testing.
	Clock func() time.Time
}

const (
	defaultInboxTTL     = 30 * time.Minute
	defaultInboxEntries = 10000
)

// NewInbox builds an Inbox.
func NewInbox(opts InboxOptions) *Inbox {
	if opts.TTL <= 0 {
		opts.TTL = defaultInboxTTL
	}
	if opts.MaxEntries <= 0 {
		opts.MaxEntries = defaultInboxEntries
	}
	if opts.Clock == nil {
		opts.Clock = time.Now
	}

	return &Inbox{
		seenEvents:  make(map[string]time.Time),
		seenLogical: make(map[string]string),
		ttl:         opts.TTL,
		maxEntries:  opts.MaxEntries,
		clock:       opts.Clock,
	}
}

// Verdict is what the inbox concluded about a message.
type Verdict int

const (
	// VerdictNew means the message has not been seen and should be processed.
	VerdictNew Verdict = iota

	// VerdictDuplicate means an identical copy was already processed. It is
	// ignored silently: duplicates are expected, not suspicious.
	VerdictDuplicate

	// VerdictConflict means a different event already claimed this logical
	// position. One of the two is not what it claims to be, and the session
	// cannot continue safely.
	VerdictConflict
)

// String returns the verdict name.
func (v Verdict) String() string {
	switch v {
	case VerdictNew:
		return "new"
	case VerdictDuplicate:
		return "duplicate"
	case VerdictConflict:
		return "conflict"
	default:
		return fmt.Sprintf("Verdict(%d)", int(v))
	}
}

// LogicalKey identifies a message's position in a session.
type LogicalKey struct {
	SessionID string
	Type      string
	Seq       uint64
}

func (k LogicalKey) String() string {
	return fmt.Sprintf("%s|%s|%d", k.SessionID, k.Type, k.Seq)
}

// Observe records a message and reports what to do with it.
//
// The event id is checked first: a literal duplicate needs no further thought.
// The logical key is checked second, and that is where a conflict surfaces —
// two distinct events claiming the same position in a session.
func (i *Inbox) Observe(eventID string, key LogicalKey) Verdict {
	i.mu.Lock()
	defer i.mu.Unlock()

	now := i.clock()
	i.evictExpired(now)

	if _, seen := i.seenEvents[eventID]; seen {
		return VerdictDuplicate
	}

	logical := key.String()
	if claimedBy, taken := i.seenLogical[logical]; taken {
		if claimedBy == eventID {
			// Cannot happen given the check above, but the invariant is worth
			// stating rather than assuming.
			return VerdictDuplicate
		}
		// Two different events claim the same session position. This is not a
		// relay duplicating; it is a peer sending contradictory messages, or an
		// attacker injecting one. Either way the session's ordering is no
		// longer trustworthy.
		return VerdictConflict
	}

	i.remember(eventID, logical, now)
	return VerdictNew
}

// remember stores an entry, evicting the oldest if at capacity.
func (i *Inbox) remember(eventID, logical string, now time.Time) {
	if len(i.seenEvents) >= i.maxEntries {
		i.evictOldest()
	}

	i.seenEvents[eventID] = now
	i.seenLogical[logical] = eventID
}

// evictExpired drops entries past their TTL.
//
// Forgetting is safe because a message older than the TTL is already outside
// its own validity window, so replaying it fails on expiry instead.
func (i *Inbox) evictExpired(now time.Time) {
	cutoff := now.Add(-i.ttl)

	for id, seen := range i.seenEvents {
		if seen.Before(cutoff) {
			delete(i.seenEvents, id)
		}
	}

	// Logical keys whose event is gone are dropped with it.
	for logical, id := range i.seenLogical {
		if _, alive := i.seenEvents[id]; !alive {
			delete(i.seenLogical, logical)
		}
	}
}

// evictOldest drops the single oldest entry to make room.
func (i *Inbox) evictOldest() {
	var (
		oldestID   string
		oldestSeen time.Time
	)

	for id, seen := range i.seenEvents {
		if oldestID == "" || seen.Before(oldestSeen) {
			oldestID, oldestSeen = id, seen
		}
	}
	if oldestID == "" {
		return
	}

	delete(i.seenEvents, oldestID)
	for logical, id := range i.seenLogical {
		if id == oldestID {
			delete(i.seenLogical, logical)
		}
	}
}

// Size returns how many events are remembered.
func (i *Inbox) Size() int {
	i.mu.Lock()
	defer i.mu.Unlock()

	return len(i.seenEvents)
}
