package wireguard

import (
	"context"
	"fmt"
	"net/netip"
	"sync"

	"github.com/luizosorio/nostmesh/internal/domain"
)

// FakeController is an in-memory Controller.
//
// It exists so the transactional logic — planning, journaling, compensation,
// recovery — can be tested without root or a kernel. The privileged tests in
// test/integration cover the netlink adapter itself.
type FakeController struct {
	mu sync.Mutex

	// interfaces holds the simulated host state.
	interfaces map[string]*InterfaceState

	// FailOn makes the named method fail, so callers can exercise error paths.
	FailOn map[string]error

	// Calls records every method invoked, in order, so a test can assert that
	// compensation ran in reverse.
	Calls []string
}

// NewFakeController returns an empty fake host.
func NewFakeController() *FakeController {
	return &FakeController{
		interfaces: make(map[string]*InterfaceState),
		FailOn:     make(map[string]error),
	}
}

// PreexistingInterface seeds an interface that NostMesh did not create, so
// tests can assert it survives a rollback.
func (f *FakeController) PreexistingInterface(name string, addresses []netip.Prefix) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.interfaces[name] = &InterfaceState{
		Name:      name,
		Addresses: addresses,
		OwnedByUs: OwnsInterface(name),
	}
}

// HasInterface reports whether the simulated host carries an interface.
func (f *FakeController) HasInterface(name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()

	_, ok := f.interfaces[name]
	return ok
}

// PeerCount returns how many peers an interface carries.
func (f *FakeController) PeerCount(name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()

	iface, ok := f.interfaces[name]
	if !ok {
		return 0
	}
	return len(iface.Peers)
}

func (f *FakeController) record(method string) error {
	f.Calls = append(f.Calls, method)
	if err, ok := f.FailOn[method]; ok {
		return err
	}
	return nil
}

// EnsureInterface creates or updates the simulated interface.
func (f *FakeController) EnsureInterface(_ context.Context, spec InterfaceSpec) (InterfaceState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if err := f.record("EnsureInterface"); err != nil {
		return InterfaceState{}, err
	}
	if !OwnsInterface(spec.Name) {
		return InterfaceState{}, fmt.Errorf("%w: %s", ErrNotOwned, spec.Name)
	}

	iface, ok := f.interfaces[spec.Name]
	if !ok {
		iface = &InterfaceState{Name: spec.Name, OwnedByUs: true}
		f.interfaces[spec.Name] = iface
	}

	iface.ListenPort = spec.ListenPort
	iface.Addresses = spec.Addresses
	iface.MTU = spec.MTU

	return *iface, nil
}

// ApplyPeer adds or updates a peer, converging rather than duplicating.
func (f *FakeController) ApplyPeer(_ context.Context, name string, spec PeerSpec) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if err := f.record("ApplyPeer"); err != nil {
		return err
	}

	iface, ok := f.interfaces[name]
	if !ok {
		return fmt.Errorf("%w: %s", ErrInterfaceNotFound, name)
	}

	for i := range iface.Peers {
		if iface.Peers[i].PublicKey == spec.PublicKey {
			iface.Peers[i].Endpoint = spec.Endpoint
			iface.Peers[i].AllowedIPs = spec.AllowedIPs
			iface.Peers[i].PersistentKeepalive = spec.PersistentKeepalive
			return nil
		}
	}

	iface.Peers = append(iface.Peers, PeerState{
		PublicKey:           spec.PublicKey,
		Endpoint:            spec.Endpoint,
		AllowedIPs:          spec.AllowedIPs,
		PersistentKeepalive: spec.PersistentKeepalive,
	})
	return nil
}

// RemovePeer removes a peer; removing an absent one is not an error.
func (f *FakeController) RemovePeer(_ context.Context, name string, key domain.WireGuardPublicKey) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if err := f.record("RemovePeer"); err != nil {
		return err
	}

	iface, ok := f.interfaces[name]
	if !ok {
		return nil
	}

	kept := iface.Peers[:0]
	for _, peer := range iface.Peers {
		if peer.PublicKey != key {
			kept = append(kept, peer)
		}
	}
	iface.Peers = kept
	return nil
}

// ObserveInterface reports the simulated state.
func (f *FakeController) ObserveInterface(_ context.Context, name string) (InterfaceState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if err := f.record("ObserveInterface"); err != nil {
		return InterfaceState{}, err
	}

	iface, ok := f.interfaces[name]
	if !ok {
		return InterfaceState{}, fmt.Errorf("%w: %s", ErrInterfaceNotFound, name)
	}
	return *iface, nil
}

// RemoveInterface deletes a simulated interface, refusing one not owned.
func (f *FakeController) RemoveInterface(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if err := f.record("RemoveInterface"); err != nil {
		return err
	}
	if !OwnsInterface(name) {
		return fmt.Errorf("%w: refusing to remove %s", ErrNotOwned, name)
	}

	delete(f.interfaces, name)
	return nil
}

var _ Controller = (*FakeController)(nil)
