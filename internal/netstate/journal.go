// Package netstate applies network changes transactionally.
//
// Every change to the host — an interface, an address, a peer — is planned
// before it is applied, recorded as it happens, and reversible if a later step
// fails. A crash mid-apply leaves a journal that reconciliation can read to
// determine what was actually done.
package netstate

import (
	"errors"
	"fmt"
	"time"

	"github.com/luizosorio/nostmesh/internal/domain"
)

// OperationKind names what an operation does.
type OperationKind string

const (
	// OpCreateInterface creates a WireGuard interface.
	OpCreateInterface OperationKind = "create_interface"

	// OpConfigureInterface sets an interface's key, port and MTU.
	OpConfigureInterface OperationKind = "configure_interface"

	// OpAddAddress assigns an overlay address.
	OpAddAddress OperationKind = "add_address"

	// OpSetLinkUp brings the interface up.
	OpSetLinkUp OperationKind = "set_link_up"

	// OpApplyPeer configures a peer.
	OpApplyPeer OperationKind = "apply_peer"
)

// OperationStatus is where an operation stands.
//
// The distinction between Planned and Applied is what makes recovery possible:
// after a crash, an operation recorded as Applied definitely reached the
// kernel, while one left at Applying may or may not have.
type OperationStatus string

const (
	// StatusPlanned means the operation is recorded but not attempted.
	StatusPlanned OperationStatus = "planned"

	// StatusApplying means the operation is in flight. A journal entry left in
	// this state means the process died mid-operation, and the real state must
	// be observed rather than assumed.
	StatusApplying OperationStatus = "applying"

	// StatusApplied means the operation completed and was verified.
	StatusApplied OperationStatus = "applied"

	// StatusFailed means the operation did not complete.
	StatusFailed OperationStatus = "failed"

	// StatusRolledBack means the operation was applied and then compensated.
	StatusRolledBack OperationStatus = "rolled_back"
)

var (
	// ErrTransactionClosed reports an operation on a finished transaction.
	ErrTransactionClosed = errors.New("transaction is closed")

	// ErrNoJournal reports a missing journal.
	ErrNoJournal = errors.New("journal not found")
)

// Operation is one step in a transaction.
type Operation struct {
	ID     string          `json:"id"`
	Kind   OperationKind   `json:"kind"`
	Target string          `json:"target"`
	Status OperationStatus `json:"status"`

	// Detail describes the change in human terms, for diagnostics and dry-run
	// output. It never carries key material.
	Detail string `json:"detail"`

	// Existed records whether the resource was already present before this
	// operation. Compensation reads it to decide whether to remove the resource
	// or leave it: an interface NostMesh found rather than created must survive
	// a rollback.
	Existed bool `json:"existed"`

	PlannedAt time.Time  `json:"planned_at"`
	AppliedAt *time.Time `json:"applied_at,omitempty"`
	Error     string     `json:"error,omitempty"`
}

// Transaction is a set of operations applied as a unit.
type Transaction struct {
	ID         string      `json:"id"`
	SessionID  string      `json:"session_id,omitempty"`
	Interface  string      `json:"interface"`
	Operations []Operation `json:"operations"`
	StartedAt  time.Time   `json:"started_at"`
	EndedAt    *time.Time  `json:"ended_at,omitempty"`
	Committed  bool        `json:"committed"`
}

// NewTransaction starts a transaction against one interface.
func NewTransaction(id, iface string, now time.Time) *Transaction {
	return &Transaction{
		ID:        id,
		Interface: iface,
		StartedAt: now,
	}
}

// Plan records an intended operation without applying it.
func (t *Transaction) Plan(op Operation, now time.Time) error {
	if t.EndedAt != nil {
		return fmt.Errorf("%w: %s", ErrTransactionClosed, t.ID)
	}

	op.Status = StatusPlanned
	op.PlannedAt = now
	t.Operations = append(t.Operations, op)
	return nil
}

// MarkApplying records that an operation is in flight.
func (t *Transaction) MarkApplying(id string) error {
	return t.updateStatus(id, StatusApplying, nil, "")
}

// MarkApplied records that an operation completed.
func (t *Transaction) MarkApplied(id string, now time.Time) error {
	return t.updateStatus(id, StatusApplied, &now, "")
}

// MarkFailed records that an operation did not complete.
func (t *Transaction) MarkFailed(id string, cause error) error {
	message := ""
	if cause != nil {
		message = cause.Error()
	}
	return t.updateStatus(id, StatusFailed, nil, message)
}

// MarkRolledBack records that an applied operation was compensated.
func (t *Transaction) MarkRolledBack(id string) error {
	return t.updateStatus(id, StatusRolledBack, nil, "")
}

func (t *Transaction) updateStatus(id string, status OperationStatus, at *time.Time, message string) error {
	for i := range t.Operations {
		if t.Operations[i].ID != id {
			continue
		}
		t.Operations[i].Status = status
		if at != nil {
			t.Operations[i].AppliedAt = at
		}
		if message != "" {
			t.Operations[i].Error = message
		}
		return nil
	}
	return fmt.Errorf("operation %s not found in transaction %s", id, t.ID)
}

// Commit closes the transaction as successful.
func (t *Transaction) Commit(now time.Time) {
	t.Committed = true
	t.EndedAt = &now
}

// Close closes the transaction without committing.
func (t *Transaction) Close(now time.Time) {
	t.EndedAt = &now
}

// AppliedOperations returns the operations that reached the kernel, in the
// order they were applied.
func (t *Transaction) AppliedOperations() []Operation {
	var applied []Operation
	for _, op := range t.Operations {
		if op.Status == StatusApplied {
			applied = append(applied, op)
		}
	}
	return applied
}

// CompensationOrder returns applied operations in reverse order.
//
// Undoing in reverse is not a stylistic choice: an address must be removed
// before the interface that carries it, and a peer before the interface it
// belongs to. Any other order leaves the host in a state the adapter cannot
// reason about.
func (t *Transaction) CompensationOrder() []Operation {
	applied := t.AppliedOperations()

	reversed := make([]Operation, len(applied))
	for i, op := range applied {
		reversed[len(applied)-1-i] = op
	}
	return reversed
}

// NeedsRecovery reports whether the transaction was interrupted.
//
// A transaction that never ended, or that holds an operation stuck in
// StatusApplying, means the process died mid-flight. The host may carry partial
// state, and it must be observed rather than assumed.
func (t *Transaction) NeedsRecovery() bool {
	if t.EndedAt == nil {
		return true
	}
	for _, op := range t.Operations {
		if op.Status == StatusApplying {
			return true
		}
	}
	return false
}

// NewOperationID derives a stable operation identifier.
func NewOperationID(kind OperationKind, target string) string {
	return fmt.Sprintf("%s:%s", kind, target)
}

// Clock is re-exported so callers configure time in one place.
type Clock = domain.Clock
