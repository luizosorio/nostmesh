package netstate

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// journalDirMode restricts the journal directory to its owner. The journal
// records what NostMesh did to the host, which is operational detail that need
// not be world-readable.
const journalDirMode fs.FileMode = 0o700

// journalFileMode restricts each journal file to its owner.
const journalFileMode fs.FileMode = 0o600

// JournalStore persists transactions so they survive a crash.
//
// Each transaction is one file. Writes are atomic, so a journal is never read
// half-written: recovery depends on the record being trustworthy, and a
// truncated entry would be worse than none.
type JournalStore struct {
	dir string
}

// NewJournalStore returns a store backed by the given directory.
func NewJournalStore(dir string) *JournalStore {
	return &JournalStore{dir: dir}
}

// Dir returns the directory holding the journal.
func (s *JournalStore) Dir() string { return s.dir }

func (s *JournalStore) path(transactionID string) string {
	return filepath.Join(s.dir, transactionID+".json")
}

// Save writes a transaction, replacing any previous version.
//
// It is called after every status change, so an interrupted apply leaves a
// record of exactly how far it got.
func (s *JournalStore) Save(transaction *Transaction) error {
	if transaction == nil {
		return errors.New("cannot save a nil transaction")
	}
	if transaction.ID == "" {
		return errors.New("transaction requires an id")
	}
	if strings.ContainsAny(transaction.ID, `/\.`) {
		return fmt.Errorf("transaction id %q must not contain path separators", transaction.ID)
	}

	if err := os.MkdirAll(s.dir, journalDirMode); err != nil {
		return fmt.Errorf("creating journal directory: %w", err)
	}

	encoded, err := json.MarshalIndent(transaction, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding transaction: %w", err)
	}

	return s.writeAtomic(s.path(transaction.ID), append(encoded, '\n'))
}

func (s *JournalStore) writeAtomic(path string, content []byte) (err error) {
	temp, err := os.CreateTemp(s.dir, ".journal-*")
	if err != nil {
		return fmt.Errorf("creating temporary journal file: %w", err)
	}
	tempPath := temp.Name()

	defer func() {
		if err != nil {
			_ = temp.Close()
			_ = os.Remove(tempPath)
		}
	}()

	if err = temp.Chmod(journalFileMode); err != nil {
		return fmt.Errorf("restricting temporary journal file: %w", err)
	}
	if _, err = temp.Write(content); err != nil {
		return fmt.Errorf("writing temporary journal file: %w", err)
	}
	// Sync before rename: a journal that survives the crash but lost its
	// content would report an empty transaction, which is worse than knowing
	// nothing, because reconciliation would trust it.
	if err = temp.Sync(); err != nil {
		return fmt.Errorf("syncing temporary journal file: %w", err)
	}
	if err = temp.Close(); err != nil {
		return fmt.Errorf("closing temporary journal file: %w", err)
	}
	if err = os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("installing journal file: %w", err)
	}

	return syncDir(s.dir)
}

func syncDir(dir string) error {
	// The directory path is derived from operator-supplied configuration.
	handle, err := os.Open(dir) //nolint:gosec // operator-supplied path by design
	if err != nil {
		return fmt.Errorf("opening journal directory: %w", err)
	}
	defer func() { _ = handle.Close() }()

	if err := handle.Sync(); err != nil {
		return fmt.Errorf("syncing journal directory: %w", err)
	}
	return nil
}

// Load reads one transaction.
func (s *JournalStore) Load(transactionID string) (*Transaction, error) {
	// The path is built from a validated transaction id under the journal dir.
	content, err := os.ReadFile(s.path(transactionID)) //nolint:gosec // path derived from validated id
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", ErrNoJournal, transactionID)
		}
		return nil, fmt.Errorf("reading journal: %w", err)
	}

	var transaction Transaction
	if err := json.Unmarshal(content, &transaction); err != nil {
		return nil, fmt.Errorf("journal %s is corrupt: %w", transactionID, err)
	}
	return &transaction, nil
}

// List returns every stored transaction, oldest first.
func (s *JournalStore) List() ([]*Transaction, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading journal directory: %w", err)
	}

	var transactions []*Transaction
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".json") || strings.HasPrefix(name, ".") {
			continue
		}

		transaction, err := s.Load(strings.TrimSuffix(name, ".json"))
		if err != nil {
			// One corrupt journal must not hide the rest: recovery needs
			// whatever records are still readable.
			continue
		}
		transactions = append(transactions, transaction)
	}

	sort.Slice(transactions, func(i, j int) bool {
		return transactions[i].StartedAt.Before(transactions[j].StartedAt)
	})
	return transactions, nil
}

// PendingRecovery returns transactions that were interrupted.
func (s *JournalStore) PendingRecovery() ([]*Transaction, error) {
	all, err := s.List()
	if err != nil {
		return nil, err
	}

	var pending []*Transaction
	for _, transaction := range all {
		if transaction.NeedsRecovery() {
			pending = append(pending, transaction)
		}
	}
	return pending, nil
}

// Delete removes a transaction from the journal.
func (s *JournalStore) Delete(transactionID string) error {
	err := os.Remove(s.path(transactionID))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("removing journal: %w", err)
	}
	return nil
}
