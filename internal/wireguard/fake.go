package wireguard

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

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

	// failNext makes a method fail a bounded number of times and then recover.
	failNext    map[string]int
	failNextErr map[string]error

	// Calls records every method invoked, in order, so a test can assert that
	// compensation ran in reverse.
	Calls []string

	// handshakeOnApply makes an applied peer report a completed handshake.
	// Off by default: see HandshakeOnApply.
	handshakeOnApply bool
	handshakeAt      time.Time

	// routes holds the routes installed per interface.
	//
	// Modelled separately from an interface's peers because that is how the
	// kernel holds them: a route is an entry in a routing table pointing at a
	// link, not a property of a peer. A fake that stored them on the peer would
	// make withdrawing a route look like reconfiguring a peer, which is exactly
	// the coupling NM-25 breaks.
	routes map[string]map[netip.Prefix]bool
}

// NewFakeController returns an empty fake host.
func NewFakeController() *FakeController {
	return &FakeController{
		interfaces:  make(map[string]*InterfaceState),
		routes:      make(map[string]map[netip.Prefix]bool),
		FailOn:      make(map[string]error),
		failNext:    make(map[string]int),
		failNextErr: make(map[string]error),
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

// Attempted reports whether a method has been called at least once.
//
// Reading Calls directly races the goroutine under test whenever the caller is
// a background worker, so a test that polls for an attempt asks through here
// instead of touching the slice.
func (f *FakeController) Attempted(method string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()

	return slices.Contains(f.Calls, method)
}

func (f *FakeController) record(method string) error {
	f.Calls = append(f.Calls, method)

	// A budgeted failure is consumed before the permanent one, so a test can
	// model a call that fails a few times and then recovers — which is what a
	// transient netlink error looks like, and what distinguishes it from an
	// interface that is really gone.
	if remaining, ok := f.failNext[method]; ok && remaining > 0 {
		f.failNext[method] = remaining - 1
		return f.failNextErr[method]
	}
	if err, ok := f.FailOn[method]; ok {
		return err
	}
	return nil
}

// FailNext makes the named method fail its next n calls and then recover.
//
// FailOn fails every call, which cannot express a transient fault. A caller
// that tolerates a few failures before acting has no way to be tested against
// a fake that only knows "always" and "never".
func (f *FakeController) FailNext(method string, n int, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.failNext[method] = n
	f.failNextErr[method] = err
}

// AdvanceHandshake moves a peer's last handshake, modelling a rekey.
//
// The real data plane refreshes this on its own while the path works, and
// stops when it dies. Without a way to move it, a fake reports a handshake
// frozen at the moment it was applied: a hold checking for staleness would then
// pass or fail according to the test's clock alone, and would agree with
// whatever the implementation happened to do.
func (f *FakeController) AdvanceHandshake(name string, key domain.WireGuardPublicKey, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	iface, known := f.interfaces[name]
	if !known {
		return fmt.Errorf("%w: %s", ErrInterfaceNotFound, name)
	}

	for i := range iface.Peers {
		if iface.Peers[i].PublicKey == key {
			iface.Peers[i].LastHandshake = at
			return nil
		}
	}
	return fmt.Errorf("peer %s is not on %s", key.Short(), name)
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

			// A zero keepalive leaves the existing one alone, as the netlink
			// adapter does. Overwriting it here instead would mean a caller
			// that reapplies a peer without restating the keepalive — which is
			// what a roam does — silently disables it against this fake and not
			// against the kernel.
			if spec.PersistentKeepalive > 0 {
				iface.Peers[i].PersistentKeepalive = spec.PersistentKeepalive
			}
			return nil
		}
	}

	peer := PeerState{
		PublicKey:           spec.PublicKey,
		Endpoint:            spec.Endpoint,
		AllowedIPs:          spec.AllowedIPs,
		PersistentKeepalive: spec.PersistentKeepalive,
	}

	// A handshake is reported only when a test asks for one. The default is a
	// peer that is configured and carries nothing, which is the real failure
	// this fake must be able to reproduce: a fake that handshook automatically
	// would make every caller look successful and would never exercise the
	// check that distinguishes a configured tunnel from a working one.
	if f.handshakeOnApply {
		peer.LastHandshake = f.handshakeAt
	}

	iface.Peers = append(iface.Peers, peer)
	return nil
}

// MoveEndpoint relocates a peer's endpoint, modelling a roam.
//
// The real kernel does this on its own: it rewrites a peer's endpoint after
// authenticating a packet from a new address, without the application asking.
// Without a way to reproduce that, a fake reports the endpoint frozen at
// whatever was last written to it — so a test of roam detection would only ever
// observe this project's own write, and would agree with the implementation
// rather than test it.
func (f *FakeController) MoveEndpoint(name string, key domain.WireGuardPublicKey, to netip.AddrPort) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	iface, known := f.interfaces[name]
	if !known {
		return fmt.Errorf("%w: %s", ErrInterfaceNotFound, name)
	}

	for i := range iface.Peers {
		if iface.Peers[i].PublicKey == key {
			moved := to
			iface.Peers[i].Endpoint = &moved
			return nil
		}
	}
	return fmt.Errorf("peer %s is not on %s", key.Short(), name)
}

// HandshakeOnApply makes applied peers report a completed handshake.
//
// It exists so a test can reach the state that follows a working data plane
// without a kernel. It must be set deliberately: leaving it off is what lets a
// test assert that a tunnel carrying nothing is detected.
func (f *FakeController) HandshakeOnApply(at time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.handshakeOnApply = true
	f.handshakeAt = at
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

	// The peers are copied, not shared. A real observation is a snapshot taken
	// from the kernel; handing out the live slice would let a caller read it
	// while the fake mutates it, which is a property of the fake rather than of
	// anything under test.
	observed := *iface
	observed.Peers = append([]PeerState(nil), iface.Peers...)
	return observed, nil
}

// ListOwnedInterfaces reports the simulated interfaces this project owns.
//
// Sorted and prefix-filtered like the netlink adapter, because a fake that
// answered in map order would let a caller depend on an order the kernel does
// not promise — and the divergence would only show against a real host.
func (f *FakeController) ListOwnedInterfaces(_ context.Context) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if err := f.record("ListOwnedInterfaces"); err != nil {
		return nil, err
	}

	owned := make([]string, 0, len(f.interfaces))
	for name := range f.interfaces {
		if OwnsInterface(name) {
			owned = append(owned, name)
		}
	}

	slices.Sort(owned)
	return owned, nil
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

	// An interface taken away takes its routes with it, as the kernel does.
	// Leaving them would let a test assert a route survives its own link.
	delete(f.routes, name)
	return nil
}

// AddRoute installs a route through an interface.
func (f *FakeController) AddRoute(_ context.Context, name string, prefix netip.Prefix) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if err := f.record("AddRoute"); err != nil {
		return err
	}
	if !OwnsInterface(name) {
		return fmt.Errorf("%w: %s", ErrNotOwned, name)
	}
	if prefix.Bits() == 0 {
		return fmt.Errorf("%w: refusing to install a default route (%s)", ErrNotOwned, prefix)
	}

	// The kernel refuses a route to a link that does not exist, and a fake that
	// accepted one would let a test pass against an interface it never made.
	if _, exists := f.interfaces[name]; !exists {
		return fmt.Errorf("%w: %s", ErrInterfaceNotFound, name)
	}

	if f.routes[name] == nil {
		f.routes[name] = make(map[netip.Prefix]bool)
	}
	// Idempotent, like RouteAdd tolerating EEXIST.
	f.routes[name][prefix.Masked()] = true
	return nil
}

// RemoveRoute deletes a route. Removing an absent route is not an error.
func (f *FakeController) RemoveRoute(_ context.Context, name string, prefix netip.Prefix) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if err := f.record("RemoveRoute"); err != nil {
		return err
	}
	if !OwnsInterface(name) {
		return fmt.Errorf("%w: %s", ErrNotOwned, name)
	}

	delete(f.routes[name], prefix.Masked())
	return nil
}

// HasRoute reports whether the route exists on the interface.
func (f *FakeController) HasRoute(_ context.Context, name string, prefix netip.Prefix) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if err := f.record("HasRoute"); err != nil {
		return false, err
	}

	return f.routes[name][prefix.Masked()], nil
}

// Routes reports what a test installed, so assertions do not reach inside.
func (f *FakeController) Routes(name string) []netip.Prefix {
	f.mu.Lock()
	defer f.mu.Unlock()

	installed := make([]netip.Prefix, 0, len(f.routes[name]))
	for prefix := range f.routes[name] {
		installed = append(installed, prefix)
	}
	slices.SortFunc(installed, func(a, b netip.Prefix) int {
		return strings.Compare(a.String(), b.String())
	})
	return installed
}

var _ Controller = (*FakeController)(nil)
