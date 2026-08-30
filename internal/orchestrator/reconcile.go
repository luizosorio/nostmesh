package orchestrator

import (
	"context"
	"errors"
	"fmt"

	"github.com/luizosorio/nostmesh/internal/netstate"
	"github.com/luizosorio/nostmesh/internal/wireguard"
)

// Reconciliation reports what recovery did.
type Reconciliation struct {
	// Interrupted are transactions found mid-flight in the journal.
	Interrupted []*netstate.Transaction

	// Removed names the resources actually taken off the host.
	Removed []string

	// Kept names resources left alone because NostMesh does not own them.
	Kept []string
}

// Down removes what NostMesh applied and reconciles the journal.
//
// It is safe to run at any time, including when nothing is up: removing an
// absent interface is not an error. It never touches a resource NostMesh does
// not own, which is what makes it safe to run on a host carrying an operator's
// own WireGuard interfaces.
func (o *Orchestrator) Down(ctx context.Context) (Reconciliation, error) {
	result := Reconciliation{}

	observed, err := o.controller.ObserveInterface(ctx, defaultInterface)
	switch {
	case err == nil:
		if !wireguard.OwnsInterface(observed.Name) {
			// Cannot happen for defaultInterface, but the check is kept so the
			// invariant holds if the interface name ever becomes configurable.
			result.Kept = append(result.Kept, observed.Name)
			return result, nil
		}
		if removeErr := o.controller.RemoveInterface(ctx, defaultInterface); removeErr != nil {
			return result, fmt.Errorf("removing %s: %w", defaultInterface, removeErr)
		}
		result.Removed = append(result.Removed, defaultInterface)

	case errors.Is(err, wireguard.ErrInterfaceNotFound):
		// Nothing to remove.

	default:
		return result, fmt.Errorf("observing %s: %w", defaultInterface, err)
	}

	return o.reconcileJournal(result)
}

// reconcileJournal closes out interrupted transactions.
//
// Once the interface is gone, every operation recorded against it is moot: the
// kernel state they described no longer exists. Closing the entries stops
// status from reporting a recovery that has already happened.
func (o *Orchestrator) reconcileJournal(result Reconciliation) (Reconciliation, error) {
	pending, err := o.journal.PendingRecovery()
	if err != nil {
		return result, fmt.Errorf("reading journal: %w", err)
	}
	result.Interrupted = pending

	now := o.clock.Now()
	for _, transaction := range pending {
		for _, op := range transaction.Operations {
			switch op.Status {
			case netstate.StatusApplied, netstate.StatusApplying:
				if markErr := transaction.MarkRolledBack(op.ID); markErr != nil {
					return result, fmt.Errorf("reconciling %s: %w", transaction.ID, markErr)
				}
			case netstate.StatusPlanned, netstate.StatusFailed, netstate.StatusRolledBack:
				// Never reached the kernel, or already compensated.
			}
		}

		transaction.Close(now)
		if saveErr := o.journal.Save(transaction); saveErr != nil {
			return result, fmt.Errorf("recording reconciliation of %s: %w", transaction.ID, saveErr)
		}
	}

	return result, nil
}

// Recover reconciles the journal at startup without tearing the tunnel down.
//
// A transaction left mid-flight means the process died while applying. The
// journal says what was attempted, but only the host says what is true, so the
// interface is observed rather than assumed and the entry is resolved against
// what is actually there.
func (o *Orchestrator) Recover(ctx context.Context) (Reconciliation, error) {
	result := Reconciliation{}

	pending, err := o.journal.PendingRecovery()
	if err != nil {
		return result, fmt.Errorf("reading journal: %w", err)
	}
	result.Interrupted = pending

	if len(pending) == 0 {
		return result, nil
	}

	// A partially applied transaction leaves the host in a state no plan
	// describes. Removing what NostMesh owns returns it to a known baseline,
	// from which a fresh Up can be applied cleanly.
	observed, err := o.controller.ObserveInterface(ctx, defaultInterface)
	switch {
	case err == nil && wireguard.OwnsInterface(observed.Name):
		if removeErr := o.controller.RemoveInterface(ctx, defaultInterface); removeErr != nil {
			return result, fmt.Errorf("removing partial state on %s: %w", defaultInterface, removeErr)
		}
		result.Removed = append(result.Removed, defaultInterface)

	case errors.Is(err, wireguard.ErrInterfaceNotFound):
		// The transaction died before the interface existed.

	case err != nil:
		return result, fmt.Errorf("observing %s: %w", defaultInterface, err)
	}

	return o.reconcileJournal(result)
}
