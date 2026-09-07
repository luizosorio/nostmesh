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

	// Enumerated rather than named. A node that ran several sessions leaves
	// several interfaces, and removing one known name would leave the rest
	// holding their listen ports — which the next run then fails to bind, with
	// nothing on the host explaining why.
	owned, err := o.controller.ListOwnedInterfaces(ctx)
	if err != nil {
		return result, fmt.Errorf("listing interfaces: %w", err)
	}

	for _, name := range owned {
		removed, err := o.removeOne(ctx, name)
		if err != nil {
			// Reported with what was already removed, so a partial cleanup is
			// visible rather than looking like nothing happened.
			return result, err
		}
		if removed {
			result.Removed = append(result.Removed, name)
			continue
		}
		result.Kept = append(result.Kept, name)
	}

	return o.reconcileJournal(result)
}

// removeOne removes a single interface, reporting whether it did.
//
// An interface that vanished between the listing and the removal is not an
// error: something else cleaned it up, which is the outcome wanted anyway.
func (o *Orchestrator) removeOne(ctx context.Context, name string) (bool, error) {
	observed, err := o.controller.ObserveInterface(ctx, name)
	switch {
	case errors.Is(err, wireguard.ErrInterfaceNotFound):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("observing %s: %w", name, err)
	}

	// Checked again after observing, rather than trusting the listing. The two
	// are separate calls, and an interface renamed between them must not be
	// removed on the strength of the name it used to have.
	if !wireguard.OwnsInterface(observed.Name) {
		return false, nil
	}

	if err := o.controller.RemoveInterface(ctx, name); err != nil {
		if errors.Is(err, wireguard.ErrInterfaceNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("removing %s: %w", name, err)
	}
	return true, nil
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
	//
	// Every owned interface, not one: an interrupted run may have created
	// several, and the transaction that died says nothing about the others.
	owned, err := o.controller.ListOwnedInterfaces(ctx)
	if err != nil {
		return result, fmt.Errorf("listing interfaces: %w", err)
	}

	for _, name := range owned {
		removed, err := o.removeOne(ctx, name)
		if err != nil {
			return result, fmt.Errorf("removing partial state: %w", err)
		}
		if removed {
			result.Removed = append(result.Removed, name)
		}
	}

	return o.reconcileJournal(result)
}
