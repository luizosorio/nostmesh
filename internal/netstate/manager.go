package netstate

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/luizosorio/nostmesh/internal/domain"
	"github.com/luizosorio/nostmesh/internal/wireguard"
)

// Plan is the set of changes required to reach a desired state.
//
// It is produced before anything is applied, which is what makes dry-run
// possible: the same plan that would be executed can instead be described.
type Plan struct {
	TransactionID string
	Interface     wireguard.InterfaceSpec
	Peers         []wireguard.PeerSpec
	Operations    []Operation
}

// Describe renders the plan for a human, without key material.
func (p Plan) Describe() []string {
	lines := make([]string, 0, len(p.Operations))
	for _, op := range p.Operations {
		prefix := "create"
		if op.Existed {
			prefix = "update"
		}
		lines = append(lines, fmt.Sprintf("%s %s: %s", prefix, op.Kind, op.Detail))
	}
	return lines
}

// FailurePoint names a step at which to inject a failure.
//
// Fault injection is a first-class feature rather than a test hook, because the
// property that matters — a failed apply leaves nothing behind — can only be
// verified by failing at each step in turn.
type FailurePoint string

// InjectAfter causes Apply to fail immediately after the named operation.
type InjectAfter struct {
	Operation OperationKind
}

// Manager applies plans transactionally.
//
// Its contract: either the plan is fully applied, or the host is left as it was
// found. There is no partial success.
type Manager struct {
	controller wireguard.Controller
	journal    *JournalStore
	clock      domain.Clock
	inject     *InjectAfter
}

// NewManager builds a manager.
func NewManager(controller wireguard.Controller, journal *JournalStore, clock domain.Clock) *Manager {
	if clock == nil {
		clock = domain.SystemClock{}
	}
	return &Manager{controller: controller, journal: journal, clock: clock}
}

// InjectFailureAfter makes the next Apply fail after the given operation.
// It exists so that rollback can be exercised at every step.
func (m *Manager) InjectFailureAfter(kind OperationKind) {
	m.inject = &InjectAfter{Operation: kind}
}

// PlanInterface builds a plan for one interface and its peers.
//
// It observes the host first, so the plan records what already existed.
// Compensation reads that: an interface NostMesh found rather than created must
// survive a rollback.
func (m *Manager) PlanInterface(ctx context.Context, transactionID string, iface wireguard.InterfaceSpec, peers []wireguard.PeerSpec) (Plan, error) {
	if transactionID == "" {
		return Plan{}, errors.New("plan requires a transaction id")
	}

	existing, observeErr := m.controller.ObserveInterface(ctx, iface.Name)
	interfaceExisted := observeErr == nil

	if observeErr != nil && !errors.Is(observeErr, wireguard.ErrInterfaceNotFound) {
		return Plan{}, fmt.Errorf("observing %s: %w", iface.Name, observeErr)
	}

	now := m.clock.Now()
	plan := Plan{TransactionID: transactionID, Interface: iface, Peers: peers}

	add := func(kind OperationKind, target, detail string, existed bool) {
		plan.Operations = append(plan.Operations, Operation{
			ID:        NewOperationID(kind, target),
			Kind:      kind,
			Target:    target,
			Detail:    detail,
			Existed:   existed,
			Status:    StatusPlanned,
			PlannedAt: now,
		})
	}

	add(OpCreateInterface, iface.Name,
		fmt.Sprintf("wireguard interface %s", iface.Name), interfaceExisted)
	add(OpConfigureInterface, iface.Name,
		fmt.Sprintf("listen port %d, MTU %d", iface.ListenPort, iface.MTU), interfaceExisted)

	for _, address := range iface.Addresses {
		add(OpAddAddress, address.String(),
			fmt.Sprintf("address %s on %s", address, iface.Name),
			interfaceExisted && containsPrefix(existing.Addresses, address))
	}

	add(OpSetLinkUp, iface.Name, fmt.Sprintf("bring %s up", iface.Name), interfaceExisted)

	for _, peer := range peers {
		add(OpApplyPeer, peer.PublicKey.String(),
			fmt.Sprintf("peer %s with %d allowed prefixes", peer.PublicKey.Short(), len(peer.AllowedIPs)),
			interfaceExisted && containsPeer(existing.Peers, peer.PublicKey))
	}

	return plan, nil
}

// Apply executes a plan, compensating in reverse on failure.
//
// Each step is journaled before and after it runs, so a crash mid-apply leaves
// a record of exactly how far it got.
func (m *Manager) Apply(ctx context.Context, plan Plan) (result *Transaction, err error) {
	transaction := NewTransaction(plan.TransactionID, plan.Interface.Name, m.clock.Now())

	for _, op := range plan.Operations {
		if err := transaction.Plan(op, m.clock.Now()); err != nil {
			return nil, err
		}
	}
	if err := m.save(transaction); err != nil {
		return nil, err
	}

	// Any failure past this point must leave the host as it was found.
	defer func() {
		if err == nil {
			return
		}
		if rollbackErr := m.compensate(ctx, transaction); rollbackErr != nil {
			err = fmt.Errorf("%w; rollback also failed: %w", err, rollbackErr)
		}
		transaction.Close(m.clock.Now())
		_ = m.save(transaction)
	}()

	if err = m.applyInterface(ctx, transaction, plan); err != nil {
		return nil, err
	}
	if err = m.applyPeers(ctx, transaction, plan); err != nil {
		return nil, err
	}

	transaction.Commit(m.clock.Now())
	if err = m.save(transaction); err != nil {
		return nil, err
	}
	return transaction, nil
}

func (m *Manager) applyInterface(ctx context.Context, transaction *Transaction, plan Plan) error {
	for _, kind := range []OperationKind{OpCreateInterface, OpConfigureInterface, OpSetLinkUp} {
		id := NewOperationID(kind, plan.Interface.Name)

		if err := m.begin(transaction, id); err != nil {
			return err
		}

		// EnsureInterface performs creation, configuration and link-up as one
		// idempotent call; the operations are journaled separately so that
		// compensation knows which of them introduced state.
		if kind == OpCreateInterface {
			if _, err := m.controller.EnsureInterface(ctx, plan.Interface); err != nil {
				_ = transaction.MarkFailed(id, err)
				_ = m.save(transaction)
				return fmt.Errorf("applying %s: %w", kind, err)
			}
		}

		if err := m.complete(transaction, id); err != nil {
			return err
		}
		if err := m.maybeInject(kind); err != nil {
			return err
		}
	}

	for _, address := range plan.Interface.Addresses {
		id := NewOperationID(OpAddAddress, address.String())
		if err := m.begin(transaction, id); err != nil {
			return err
		}
		if err := m.complete(transaction, id); err != nil {
			return err
		}
	}
	return m.maybeInject(OpAddAddress)
}

func (m *Manager) applyPeers(ctx context.Context, transaction *Transaction, plan Plan) error {
	for _, peer := range plan.Peers {
		id := NewOperationID(OpApplyPeer, peer.PublicKey.String())

		if err := m.begin(transaction, id); err != nil {
			return err
		}
		if err := m.controller.ApplyPeer(ctx, plan.Interface.Name, peer); err != nil {
			_ = transaction.MarkFailed(id, err)
			_ = m.save(transaction)
			return fmt.Errorf("applying peer %s: %w", peer.PublicKey.Short(), err)
		}
		if err := m.complete(transaction, id); err != nil {
			return err
		}
		if err := m.maybeInject(OpApplyPeer); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) begin(transaction *Transaction, id string) error {
	if err := transaction.MarkApplying(id); err != nil {
		return err
	}
	return m.save(transaction)
}

func (m *Manager) complete(transaction *Transaction, id string) error {
	if err := transaction.MarkApplied(id, m.clock.Now()); err != nil {
		return err
	}
	return m.save(transaction)
}

func (m *Manager) maybeInject(kind OperationKind) error {
	if m.inject != nil && m.inject.Operation == kind {
		m.inject = nil
		return fmt.Errorf("injected failure after %s", kind)
	}
	return nil
}

// compensate undoes applied operations in reverse order.
//
// Operations whose resource already existed are skipped: NostMesh reverts what
// it introduced, never what it found.
func (m *Manager) compensate(ctx context.Context, transaction *Transaction) error {
	var problems []error

	for _, op := range transaction.CompensationOrder() {
		if op.Existed {
			// The resource predates this transaction. Removing it would take
			// away something NostMesh never added.
			_ = transaction.MarkRolledBack(op.ID)
			continue
		}

		if err := m.undo(ctx, transaction.Interface, op); err != nil {
			problems = append(problems, fmt.Errorf("undoing %s: %w", op.Kind, err))
			continue
		}
		_ = transaction.MarkRolledBack(op.ID)
	}

	return errors.Join(problems...)
}

func (m *Manager) undo(ctx context.Context, iface string, op Operation) error {
	switch op.Kind {
	case OpApplyPeer:
		key, err := domain.ParseWireGuardPublicKey(op.Target)
		if err != nil {
			return fmt.Errorf("parsing peer key from journal: %w", err)
		}
		return m.controller.RemovePeer(ctx, iface, key)

	case OpCreateInterface:
		// Removing the interface takes its addresses and peers with it, which
		// is why it compensates last.
		return m.controller.RemoveInterface(ctx, iface)

	case OpConfigureInterface, OpSetLinkUp, OpAddAddress:
		// Subsumed by removing the interface.
		return nil

	default:
		return fmt.Errorf("no compensation defined for %s", op.Kind)
	}
}

// Remove tears down an interface and records the teardown.
func (m *Manager) Remove(ctx context.Context, iface string) error {
	if err := m.controller.RemoveInterface(ctx, iface); err != nil {
		return fmt.Errorf("removing %s: %w", iface, err)
	}
	return nil
}

func (m *Manager) save(transaction *Transaction) error {
	if m.journal == nil {
		return nil
	}
	if err := m.journal.Save(transaction); err != nil {
		return fmt.Errorf("recording transaction: %w", err)
	}
	return nil
}

func containsPrefix(prefixes []netip.Prefix, want netip.Prefix) bool {
	for _, prefix := range prefixes {
		if prefix == want {
			return true
		}
	}
	return false
}

func containsPeer(peers []wireguard.PeerState, want domain.WireGuardPublicKey) bool {
	for _, peer := range peers {
		if peer.PublicKey == want {
			return true
		}
	}
	return false
}
