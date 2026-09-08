// Package wireguard defines how NostMesh configures the data plane.
//
// The port here is platform-neutral; adapters implement it per operating
// system. Per NM-05 the Linux adapter speaks netlink directly and never shells
// out to wg, wg-quick or ip.
package wireguard

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"time"

	"github.com/luizosorio/nostmesh/internal/domain"
)

// InterfacePrefix marks interfaces created by NostMesh.
//
// Ownership has to be decidable from the host alone, because after a crash the
// journal may be incomplete and the adapter still must not delete something it
// did not create. The name is the marker: netlink offers no place to attach
// arbitrary metadata to a WireGuard link.
//
// This rule is platform-neutral by design: every adapter answers the ownership
// question the same way, so a port to another operating system cannot quietly
// adopt a laxer definition.
const InterfacePrefix = "nm"

// OwnsInterface reports whether an interface belongs to NostMesh.
func OwnsInterface(name string) bool {
	return strings.HasPrefix(name, InterfacePrefix)
}

var (
	// ErrInterfaceNotFound reports a missing interface.
	ErrInterfaceNotFound = errors.New("interface not found")

	// ErrPeerNotFound reports a missing peer.
	ErrPeerNotFound = errors.New("peer not found")

	// ErrNotOwned reports an interface that NostMesh did not create.
	//
	// The adapter refuses to touch it. Removing an interface someone else
	// configured would break their networking with no way to restore it, so
	// ownership is verified before every destructive operation.
	ErrNotOwned = errors.New("resource is not owned by nostmesh")
)

// InterfaceSpec is the desired state of a WireGuard interface.
type InterfaceSpec struct {
	// Name is the interface name, for example "nm0".
	Name string

	// PrivateKey is the interface's tunnel key. It reaches the kernel and
	// nowhere else.
	PrivateKey domain.WireGuardPrivateKey

	// ListenPort is the UDP port to bind. Zero lets the kernel choose.
	ListenPort int

	// Addresses are the overlay addresses assigned to the interface.
	Addresses []netip.Prefix

	// MTU is the interface MTU. Zero uses the adapter's default.
	MTU int
}

// PeerSpec is the desired state of one peer on an interface.
type PeerSpec struct {
	// PublicKey identifies the peer on the data plane.
	PublicKey domain.WireGuardPublicKey

	// Endpoint is where to send traffic, if known.
	Endpoint *netip.AddrPort

	// AllowedIPs are the prefixes routed to this peer.
	//
	// These are computed from local policy, never taken from what the peer
	// asked for. NM-04 is explicit: a received message is a proposal.
	AllowedIPs []netip.Prefix

	// PersistentKeepalive keeps a NAT mapping alive. Zero disables it.
	PersistentKeepalive time.Duration
}

// InterfaceState is the observed state of an interface.
//
// It is what the kernel reports, which is not necessarily what was asked for:
// the difference between desired and observed is what `status` shows and what
// reconciliation acts on.
type InterfaceState struct {
	Name       string
	PublicKey  domain.WireGuardPublicKey
	ListenPort int
	Addresses  []netip.Prefix
	MTU        int
	Peers      []PeerState
	OwnedByUs  bool

	// Routes are the destinations the kernel reaches through this interface.
	//
	// The forwarding table as it actually is, which is a different thing from
	// what a peer's AllowedIPs say it should be. An operator asking why a
	// subnet is unreachable needs the first; everything before this reported
	// only the second, so an announced route that failed to install looked
	// exactly like one that worked.
	Routes []netip.Prefix
}

// PeerState is the observed state of a peer.
type PeerState struct {
	PublicKey           domain.WireGuardPublicKey
	Endpoint            *netip.AddrPort
	AllowedIPs          []netip.Prefix
	LastHandshake       time.Time
	ReceiveBytes        int64
	TransmitBytes       int64
	PersistentKeepalive time.Duration
}

// HasHandshake reports whether the peer has completed a handshake.
func (p PeerState) HasHandshake() bool { return !p.LastHandshake.IsZero() }

// Controller configures WireGuard interfaces and peers.
//
// Every operation is idempotent: applying the same spec twice converges on the
// same state rather than failing or duplicating. This is what makes recovery
// after an interrupted run safe to simply retry.
type Controller interface {
	// EnsureInterface brings the interface to the desired state, creating it if
	// necessary, and returns what the kernel reports afterwards.
	EnsureInterface(ctx context.Context, spec InterfaceSpec) (InterfaceState, error)

	// ApplyPeer brings one peer to the desired state.
	ApplyPeer(ctx context.Context, iface string, spec PeerSpec) error

	// RemovePeer removes a peer. Removing an absent peer is not an error.
	RemovePeer(ctx context.Context, iface string, publicKey domain.WireGuardPublicKey) error

	// ObserveInterface reports the current state of an interface.
	ObserveInterface(ctx context.Context, iface string) (InterfaceState, error)

	// RemoveInterface deletes an interface, refusing one NostMesh does not own.
	RemoveInterface(ctx context.Context, iface string) error

	// ListOwnedInterfaces reports every interface NostMesh owns on this host.
	//
	// Reconciliation needs it: a node that ran several sessions leaves several
	// interfaces, and cleaning up one known name would leave the rest holding
	// their ports — which the next run would then fail to bind, forever.
	//
	// Only interfaces matching InterfacePrefix are returned. Something else on
	// the host is not ours to enumerate, let alone remove.
	ListOwnedInterfaces(ctx context.Context) ([]string, error)

	// AddRoute installs a route to a prefix through an interface.
	//
	// Separate from ApplyPeer because an announced route appears and disappears
	// independently of the tunnel carrying it (NM-25). The routes a peer implies
	// still ride with ApplyPeer, where NM-09 put them.
	//
	// Idempotent: a route already present is not an error.
	AddRoute(ctx context.Context, iface string, prefix netip.Prefix) error

	// RemoveRoute deletes a route. Removing an absent route is not an error.
	RemoveRoute(ctx context.Context, iface string, prefix netip.Prefix) error

	// HasRoute reports whether a route to the prefix already exists on the
	// interface.
	//
	// Compensation needs it. The journal records whether an operation created
	// something so that rollback does not remove what was already there, and
	// without this a rollback would delete a route the operator installed
	// themselves.
	HasRoute(ctx context.Context, iface string, prefix netip.Prefix) (bool, error)
}
