package netstate

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testTransaction(now time.Time) *Transaction {
	transaction := NewTransaction("tx-1", "nm0", now)
	_ = transaction.Plan(Operation{ID: "a", Kind: OpCreateInterface, Target: "nm0"}, now)
	_ = transaction.Plan(Operation{ID: "b", Kind: OpAddAddress, Target: "100.96.0.1/32"}, now)
	_ = transaction.Plan(Operation{ID: "c", Kind: OpApplyPeer, Target: "peer"}, now)
	return transaction
}

func TestJournalRoundTrip(t *testing.T) {
	store := NewJournalStore(filepath.Join(t.TempDir(), "journal"))
	now := testClock().Now()

	original := testTransaction(now)
	if err := original.MarkApplied("a", now); err != nil {
		t.Fatalf("marking applied: %v", err)
	}
	original.Commit(now)

	if err := store.Save(original); err != nil {
		t.Fatalf("saving: %v", err)
	}

	loaded, err := store.Load("tx-1")
	if err != nil {
		t.Fatalf("loading: %v", err)
	}

	if loaded.ID != original.ID || loaded.Interface != original.Interface {
		t.Error("identity did not survive the round trip")
	}
	if len(loaded.Operations) != len(original.Operations) {
		t.Errorf("operation count = %d, want %d", len(loaded.Operations), len(original.Operations))
	}
	if !loaded.Committed {
		t.Error("commit flag did not survive the round trip")
	}
}

// Undoing in reverse is not stylistic: an address must come off before the
// interface carrying it, and a peer before the interface it belongs to.
func TestCompensationOrderIsReversed(t *testing.T) {
	now := testClock().Now()
	transaction := testTransaction(now)

	for _, id := range []string{"a", "b", "c"} {
		if err := transaction.MarkApplied(id, now); err != nil {
			t.Fatalf("marking %s applied: %v", id, err)
		}
	}

	order := transaction.CompensationOrder()
	if len(order) != 3 {
		t.Fatalf("expected 3 operations, got %d", len(order))
	}

	want := []string{"c", "b", "a"}
	for i, op := range order {
		if op.ID != want[i] {
			t.Errorf("position %d = %s, want %s", i, op.ID, want[i])
		}
	}
}

// Only applied operations are compensated: undoing something that never
// reached the kernel would be acting on state that does not exist.
func TestCompensationSkipsUnappliedOperations(t *testing.T) {
	now := testClock().Now()
	transaction := testTransaction(now)

	if err := transaction.MarkApplied("a", now); err != nil {
		t.Fatalf("marking applied: %v", err)
	}
	if err := transaction.MarkFailed("b", errors.New("boom")); err != nil {
		t.Fatalf("marking failed: %v", err)
	}

	order := transaction.CompensationOrder()
	if len(order) != 1 || order[0].ID != "a" {
		t.Errorf("only applied operations compensate, got %d: %v", len(order), order)
	}
}

// A transaction left mid-flight means the process died. The host may carry
// partial state, which must be observed rather than assumed.
func TestNeedsRecovery(t *testing.T) {
	now := testClock().Now()

	tests := []struct {
		name    string
		prepare func(*Transaction)
		want    bool
	}{
		{
			name:    "still running",
			prepare: func(*Transaction) {},
			want:    true,
		},
		{
			name: "operation left applying",
			prepare: func(tr *Transaction) {
				_ = tr.MarkApplying("a")
				tr.Close(now)
			},
			want: true,
		},
		{
			name: "committed cleanly",
			prepare: func(tr *Transaction) {
				_ = tr.MarkApplied("a", now)
				tr.Commit(now)
			},
			want: false,
		},
		{
			name: "closed after rollback",
			prepare: func(tr *Transaction) {
				_ = tr.MarkRolledBack("a")
				tr.Close(now)
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transaction := testTransaction(now)
			tt.prepare(transaction)

			if got := transaction.NeedsRecovery(); got != tt.want {
				t.Errorf("NeedsRecovery() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPendingRecoveryListsInterruptedOnly(t *testing.T) {
	store := NewJournalStore(filepath.Join(t.TempDir(), "journal"))
	now := testClock().Now()

	committed := NewTransaction("committed", "nm0", now)
	_ = committed.Plan(Operation{ID: "a", Kind: OpCreateInterface}, now)
	_ = committed.MarkApplied("a", now)
	committed.Commit(now)

	interrupted := NewTransaction("interrupted", "nm1", now.Add(time.Second))
	_ = interrupted.Plan(Operation{ID: "a", Kind: OpCreateInterface}, now)
	_ = interrupted.MarkApplying("a")

	for _, transaction := range []*Transaction{committed, interrupted} {
		if err := store.Save(transaction); err != nil {
			t.Fatalf("saving %s: %v", transaction.ID, err)
		}
	}

	pending, err := store.PendingRecovery()
	if err != nil {
		t.Fatalf("listing pending: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending transaction, got %d", len(pending))
	}
	if pending[0].ID != "interrupted" {
		t.Errorf("pending = %s, want interrupted", pending[0].ID)
	}
}

func TestJournalFileIsOwnerOnly(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "journal")
	store := NewJournalStore(dir)

	if err := store.Save(testTransaction(testClock().Now())); err != nil {
		t.Fatalf("saving: %v", err)
	}

	info, err := os.Stat(filepath.Join(dir, "tx-1.json"))
	if err != nil {
		t.Fatalf("inspecting journal file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != journalFileMode {
		t.Errorf("mode = %04o, want %04o", perm, journalFileMode)
	}
}

// A transaction id becomes a filename, so it must not be able to escape the
// journal directory.
func TestJournalRejectsPathTraversal(t *testing.T) {
	store := NewJournalStore(filepath.Join(t.TempDir(), "journal"))
	now := testClock().Now()

	for _, id := range []string{"../escape", "sub/dir", "a.b", `back\slash`} {
		t.Run(id, func(t *testing.T) {
			transaction := NewTransaction(id, "nm0", now)

			err := store.Save(transaction)
			if err == nil {
				t.Fatalf("transaction id %q must be rejected", id)
			}
			if !strings.Contains(err.Error(), "path separators") {
				t.Errorf("error must explain the restriction, got: %v", err)
			}
		})
	}
}

// One corrupt journal must not hide the others: recovery needs whatever records
// are still readable.
func TestListSkipsCorruptJournals(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "journal")
	store := NewJournalStore(dir)
	now := testClock().Now()

	if err := store.Save(testTransaction(now)); err != nil {
		t.Fatalf("saving: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "corrupt.json"), []byte("{not json"), journalFileMode); err != nil {
		t.Fatalf("writing corrupt journal: %v", err)
	}

	transactions, err := store.List()
	if err != nil {
		t.Fatalf("listing: %v", err)
	}
	if len(transactions) != 1 || transactions[0].ID != "tx-1" {
		t.Errorf("expected the readable journal only, got %d", len(transactions))
	}
}

func TestLoadMissingJournal(t *testing.T) {
	store := NewJournalStore(filepath.Join(t.TempDir(), "journal"))

	_, err := store.Load("absent")
	if !errors.Is(err, ErrNoJournal) {
		t.Errorf("expected ErrNoJournal, got: %v", err)
	}
}

func TestClosedTransactionRejectsNewOperations(t *testing.T) {
	now := testClock().Now()
	transaction := testTransaction(now)
	transaction.Commit(now)

	err := transaction.Plan(Operation{ID: "d", Kind: OpAddAddress}, now)
	if !errors.Is(err, ErrTransactionClosed) {
		t.Errorf("expected ErrTransactionClosed, got: %v", err)
	}
}
