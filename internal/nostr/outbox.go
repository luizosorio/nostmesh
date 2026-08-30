package nostr

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Outbox holds events waiting to be published, so that a restart does not lose
// them.
//
// Per NM-11 it is file-backed: one file per entry, written atomically, so a
// partially written entry cannot corrupt the others and an operator debugging a
// stuck queue can read them.
type Outbox struct {
	mu sync.Mutex

	dir         string
	maxEntries  int
	maxAttempts int
	clock       func() time.Time
}

const (
	outboxDirMode  fs.FileMode = 0o700
	outboxFileMode fs.FileMode = 0o600

	defaultOutboxEntries  = 1000
	defaultOutboxAttempts = 10
)

var (
	// ErrOutboxFull reports a queue at capacity.
	//
	// Refusing is deliberate: an unbounded queue turns a relay outage into
	// unbounded disk use, and the operator would discover it as a full disk
	// rather than as a networking problem.
	ErrOutboxFull = errors.New("outbox is full")

	// ErrEntryNotFound reports a missing entry.
	ErrEntryNotFound = errors.New("outbox entry not found")
)

// OutboxOptions configures an Outbox.
type OutboxOptions struct {
	// Dir is where entries are stored.
	Dir string

	// MaxEntries bounds the queue.
	MaxEntries int

	// MaxAttempts bounds retries per entry. Beyond it the entry is abandoned:
	// a message nobody accepted after this many tries is not going to be
	// accepted, and retrying forever starves newer work.
	MaxAttempts int

	// Clock is injected for testing.
	Clock func() time.Time
}

// NewOutbox builds an Outbox.
func NewOutbox(opts OutboxOptions) (*Outbox, error) {
	if opts.Dir == "" {
		return nil, errors.New("outbox requires a directory")
	}
	if opts.MaxEntries <= 0 {
		opts.MaxEntries = defaultOutboxEntries
	}
	if opts.MaxAttempts <= 0 {
		opts.MaxAttempts = defaultOutboxAttempts
	}
	if opts.Clock == nil {
		opts.Clock = time.Now
	}

	if err := os.MkdirAll(opts.Dir, outboxDirMode); err != nil {
		return nil, fmt.Errorf("creating outbox directory: %w", err)
	}

	return &Outbox{
		dir:         opts.Dir,
		maxEntries:  opts.MaxEntries,
		maxAttempts: opts.MaxAttempts,
		clock:       opts.Clock,
	}, nil
}

// Entry is one event awaiting publication.
type Entry struct {
	// ID identifies the entry. It is the Nostr event id, so re-queuing the
	// same event replaces rather than duplicates.
	ID string `json:"id"`

	// Event is the serialized event to publish.
	Event json.RawMessage `json:"event"`

	// Relays that have accepted this event. Publication is fan-out, and a
	// relay that already has it need not be retried.
	AcceptedBy []string `json:"accepted_by,omitempty"`

	// Attempts counts publication rounds.
	Attempts int `json:"attempts"`

	// QueuedAt is when the entry entered the queue.
	QueuedAt time.Time `json:"queued_at"`

	// LastAttempt is when publication was last tried.
	LastAttempt *time.Time `json:"last_attempt,omitempty"`

	// ExpiresAt is when the entry stops being worth publishing. A control
	// message past its validity window would be rejected by the recipient
	// anyway.
	ExpiresAt time.Time `json:"expires_at"`
}

// Accepted reports whether a relay already has this event.
func (e Entry) Accepted(relay string) bool {
	for _, accepted := range e.AcceptedBy {
		if accepted == relay {
			return true
		}
	}
	return false
}

// IsExpired reports whether the entry is past its validity.
func (e Entry) IsExpired(now time.Time) bool { return !now.Before(e.ExpiresAt) }

// Exhausted reports whether the entry has used its attempts.
func (e Entry) Exhausted(maxAttempts int) bool { return e.Attempts >= maxAttempts }

func (o *Outbox) path(id string) string {
	return filepath.Join(o.dir, id+".json")
}

// Enqueue adds an event to the queue.
//
// Re-queuing an existing id replaces it, which is what makes enqueueing
// idempotent after a crash: the caller can retry without producing duplicates.
func (o *Outbox) Enqueue(entry Entry) error {
	o.mu.Lock()
	defer o.mu.Unlock()

	if entry.ID == "" {
		return errors.New("outbox entry requires an id")
	}
	if strings.ContainsAny(entry.ID, `/\.`) {
		return fmt.Errorf("outbox id %q must not contain path separators", entry.ID)
	}
	if len(entry.Event) == 0 {
		return errors.New("outbox entry requires an event")
	}

	existing, err := o.list()
	if err != nil {
		return err
	}

	// Replacing an existing entry does not count against capacity.
	_, replacing := existing[entry.ID]
	if !replacing && len(existing) >= o.maxEntries {
		return fmt.Errorf("%w: %d entries", ErrOutboxFull, len(existing))
	}

	if entry.QueuedAt.IsZero() {
		entry.QueuedAt = o.clock()
	}

	return o.write(entry)
}

// Pending returns entries still worth publishing, oldest first.
//
// Expired and exhausted entries are dropped as a side effect: the queue is read
// far more often than it is written, so cleaning here keeps it bounded without
// a separate sweep.
func (o *Outbox) Pending() ([]Entry, error) {
	o.mu.Lock()
	defer o.mu.Unlock()

	entries, err := o.list()
	if err != nil {
		return nil, err
	}

	now := o.clock()
	pending := make([]Entry, 0, len(entries))

	for id, entry := range entries {
		if entry.IsExpired(now) || entry.Exhausted(o.maxAttempts) {
			if err := os.Remove(o.path(id)); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return nil, fmt.Errorf("removing spent entry: %w", err)
			}
			continue
		}
		pending = append(pending, entry)
	}

	sort.Slice(pending, func(i, j int) bool {
		return pending[i].QueuedAt.Before(pending[j].QueuedAt)
	})
	return pending, nil
}

// RecordAttempt notes that publication was tried, and which relays accepted.
func (o *Outbox) RecordAttempt(id string, acceptedBy []string) error {
	o.mu.Lock()
	defer o.mu.Unlock()

	entry, err := o.read(id)
	if err != nil {
		return err
	}

	entry.Attempts++
	now := o.clock()
	entry.LastAttempt = &now

	for _, relay := range acceptedBy {
		if !entry.Accepted(relay) {
			entry.AcceptedBy = append(entry.AcceptedBy, relay)
		}
	}

	return o.write(entry)
}

// Remove drops an entry, typically once enough relays have accepted it.
func (o *Outbox) Remove(id string) error {
	o.mu.Lock()
	defer o.mu.Unlock()

	if err := os.Remove(o.path(id)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("removing outbox entry: %w", err)
	}
	return nil
}

// Size returns how many entries are stored, including spent ones.
func (o *Outbox) Size() (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()

	entries, err := o.list()
	if err != nil {
		return 0, err
	}
	return len(entries), nil
}

func (o *Outbox) list() (map[string]Entry, error) {
	dirEntries, err := os.ReadDir(o.dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return map[string]Entry{}, nil
		}
		return nil, fmt.Errorf("reading outbox: %w", err)
	}

	entries := make(map[string]Entry, len(dirEntries))
	for _, dirEntry := range dirEntries {
		name := dirEntry.Name()
		if dirEntry.IsDir() || !strings.HasSuffix(name, ".json") || strings.HasPrefix(name, ".") {
			continue
		}

		id := strings.TrimSuffix(name, ".json")
		entry, err := o.read(id)
		if err != nil {
			// A corrupt entry must not hide the rest: the queue still has work
			// to do, and one unreadable file should not stop it.
			continue
		}
		entries[id] = entry
	}
	return entries, nil
}

func (o *Outbox) read(id string) (Entry, error) {
	// The path is built from a validated id under the outbox directory.
	content, err := os.ReadFile(o.path(id)) //nolint:gosec // path derived from validated id
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Entry{}, fmt.Errorf("%w: %s", ErrEntryNotFound, id)
		}
		return Entry{}, fmt.Errorf("reading outbox entry: %w", err)
	}

	var entry Entry
	if err := json.Unmarshal(content, &entry); err != nil {
		return Entry{}, fmt.Errorf("outbox entry %s is corrupt: %w", id, err)
	}
	return entry, nil
}

// write persists an entry atomically, so a crash mid-write cannot leave a
// truncated entry that later reads would treat as real.
func (o *Outbox) write(entry Entry) (err error) {
	encoded, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding outbox entry: %w", err)
	}
	encoded = append(encoded, '\n')

	temp, err := os.CreateTemp(o.dir, ".outbox-*")
	if err != nil {
		return fmt.Errorf("creating temporary entry: %w", err)
	}
	tempPath := temp.Name()

	defer func() {
		if err != nil {
			_ = temp.Close()
			_ = os.Remove(tempPath)
		}
	}()

	if err = temp.Chmod(outboxFileMode); err != nil {
		return fmt.Errorf("restricting temporary entry: %w", err)
	}
	if _, err = temp.Write(encoded); err != nil {
		return fmt.Errorf("writing temporary entry: %w", err)
	}
	if err = temp.Sync(); err != nil {
		return fmt.Errorf("syncing temporary entry: %w", err)
	}
	if err = temp.Close(); err != nil {
		return fmt.Errorf("closing temporary entry: %w", err)
	}
	if err = os.Rename(tempPath, o.path(entry.ID)); err != nil {
		return fmt.Errorf("installing entry: %w", err)
	}
	return nil
}
