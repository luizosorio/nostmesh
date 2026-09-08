package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/luizosorio/nostmesh/internal/domain"
)

// answeredStore keeps the answered-session record on disk.
//
// Without it the record is memory, so a restart forgets every session this node
// answered — and a node with a durable identity then meets its own retained
// events on the relays and answers them again. See #59.
//
// The file lives beside the network journal, for the same reason the journal
// does: it is state this node needs to reconcile what it did with what it finds
// after a restart.
type answeredStore struct {
	path string
}

// answeredFileMode keeps the record private to the service account.
//
// It holds session identifiers this node has taken part in — not secret, but
// not something a local user has any reason to enumerate.
const answeredFileMode = 0o600

func newAnsweredStore(stateDir string) *answeredStore {
	return &answeredStore{path: filepath.Join(stateDir, "answered.json")}
}

// answeredRecord is the file's shape.
//
// Unix seconds rather than a formatted time: the record is compared against a
// retention window and never displayed, and a second is finer than any window
// that matters here.
type answeredRecord struct {
	Sessions map[string]int64 `json:"sessions"`
}

// Load reads the record a previous run left.
//
// A missing file is not an error: a node that never ran has answered nothing.
// A corrupt one is — the caller decides whether to continue, and continuing
// with a silently empty record would hide the reason a replay got through.
func (s *answeredStore) Load() (map[domain.SessionID]time.Time, error) {
	content, err := os.ReadFile(s.path) //nolint:gosec // a path this service composed
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading %s: %w", s.path, err)
	}

	var record answeredRecord
	if err := json.Unmarshal(content, &record); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", s.path, err)
	}

	answered := make(map[domain.SessionID]time.Time, len(record.Sessions))
	for raw, at := range record.Sessions {
		sessionID, err := domain.ParseSessionID(raw)
		if err != nil {
			// One unreadable entry does not condemn the rest: the record is a
			// set of independent facts, and dropping the others would forget
			// sessions this node really did answer.
			continue
		}
		answered[sessionID] = time.Unix(at, 0).UTC()
	}

	return answered, nil
}

// Save writes the record.
//
// Atomically, by the same temp-sync-rename the journal uses: a record truncated
// by a crash would report fewer answered sessions than there were, which is the
// state this file exists to prevent.
func (s *answeredStore) Save(answered map[domain.SessionID]time.Time) error {
	record := answeredRecord{Sessions: make(map[string]int64, len(answered))}
	for sessionID, at := range answered {
		record.Sessions[sessionID.String()] = at.Unix()
	}

	content, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("encoding the answered record: %w", err)
	}

	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating %s: %w", dir, err)
	}

	temp, err := os.CreateTemp(dir, ".answered-*")
	if err != nil {
		return fmt.Errorf("creating a temporary record: %w", err)
	}
	tempPath := temp.Name()

	defer func() {
		if err != nil {
			_ = temp.Close()
			_ = os.Remove(tempPath)
		}
	}()

	if err = temp.Chmod(answeredFileMode); err != nil {
		return fmt.Errorf("restricting the temporary record: %w", err)
	}
	if _, err = temp.Write(content); err != nil {
		return fmt.Errorf("writing the temporary record: %w", err)
	}
	if err = temp.Sync(); err != nil {
		return fmt.Errorf("syncing the temporary record: %w", err)
	}
	if err = temp.Close(); err != nil {
		return fmt.Errorf("closing the temporary record: %w", err)
	}
	if err = os.Rename(tempPath, s.path); err != nil {
		return fmt.Errorf("installing the record: %w", err)
	}

	return nil
}
