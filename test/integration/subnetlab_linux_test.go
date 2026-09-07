//go:build linux && privileged

package integration

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"

	"github.com/luizosorio/nostmesh/internal/domain"
	"github.com/luizosorio/nostmesh/internal/identity"
	"github.com/luizosorio/nostmesh/internal/wireguard"
)

// A two-subnet testbed: two gateways joined by a tunnel, each with a LAN behind
// it.
//
//	[lanA host] --- [gwA] === tunnel === [gwB] --- [lanB host]
//	 10.1.0.2       10.1.0.1              10.2.0.1     10.2.0.2
//	                    \_ 10.99.0.1 -- 10.99.0.2 _/
//
// This is what M2.4 is for. Every earlier test proves a tunnel between two
// hosts; none proves that a host *behind* one of them can reach a host behind
// the other, which is what installing an announced route is supposed to
// achieve. A route that installs and carries nothing is configuration, not
// function.
type subnetLab struct {
	t testing.TB

	gatewayA netns.NsHandle
	gatewayB netns.NsHandle
	lanA     netns.NsHandle
	lanB     netns.NsHandle

	keyA domain.WireGuardPrivateKey
	keyB domain.WireGuardPrivateKey
	pubA domain.WireGuardPublicKey
	pubB domain.WireGuardPublicKey
}

const (
	// The underlay joining the two gateways.
	gatewayATransport = "10.99.0.1/24"
	gatewayBTransport = "10.99.0.2/24"

	// The tunnel's own addresses.
	gatewayAOverlay = "100.96.0.1/32"
	gatewayBOverlay = "100.96.0.2/32"

	// The LANs behind each gateway. These are what gets announced.
	lanAPrefix  = "10.1.0.0/24"
	lanBPrefix  = "10.2.0.0/24"
	gatewayALAN = "10.1.0.1/24"
	gatewayBLAN = "10.2.0.1/24"
	lanAHost    = "10.1.0.2/24"
	lanBHost    = "10.2.0.2/24"

	subnetPortA = 51841
	subnetPortB = 51842
)

func newSubnetLab(t testing.TB) *subnetLab {
	t.Helper()
	requirePrivileges(t)

	runtime.LockOSThread()

	original, err := netns.Get()
	if err != nil {
		t.Fatalf("reading current namespace: %v", err)
	}

	l := &subnetLab{t: t}
	created := []*netns.NsHandle{&l.gatewayA, &l.gatewayB, &l.lanA, &l.lanB}
	for i, handle := range created {
		*handle, err = netns.New()
		if err != nil {
			for _, made := range created[:i] {
				_ = made.Close()
			}
			runtime.UnlockOSThread()
			t.Skipf("cannot create namespace %d (needs CAP_SYS_ADMIN): %v", i, err)
		}
	}

	t.Cleanup(func() {
		if err := netns.Set(original); err != nil {
			t.Errorf("restoring namespace: %v", err)
		}
		for _, handle := range created {
			_ = handle.Close()
		}
		_ = original.Close()
		runtime.UnlockOSThread()
	})

	l.generateKeys()
	l.buildTopology()

	return l
}

func (l *subnetLab) generateKeys() {
	l.t.Helper()

	generator := identity.NewKeyGenerator()

	var err error
	if l.pubA, l.keyA, err = generator.Generate(); err != nil {
		l.t.Fatalf("generating gateway A's key: %v", err)
	}
	if l.pubB, l.keyB, err = generator.Generate(); err != nil {
		l.t.Fatalf("generating gateway B's key: %v", err)
	}
}

// buildTopology wires the four namespaces together.
func (l *subnetLab) buildTopology() {
	l.t.Helper()

	// The underlay between the gateways.
	l.joinNamespaces(l.gatewayA, l.gatewayB, "wan-a", "wan-b", gatewayATransport, gatewayBTransport)

	// Each gateway's LAN.
	l.joinNamespaces(l.gatewayA, l.lanA, "lan-a", "host-a", gatewayALAN, lanAHost)
	l.joinNamespaces(l.gatewayB, l.lanB, "lan-b", "host-b", gatewayBLAN, lanBHost)

	// A LAN host reaches anything beyond its own segment through its gateway.
	l.addDefaultVia(l.lanA, "10.1.0.1")
	l.addDefaultVia(l.lanB, "10.2.0.1")

	// A gateway that does not forward is a host with two interfaces. This is
	// set here rather than by NostMesh: enabling it is a change to global host
	// state that the network journal does not revert, and an operator running a
	// subnet router has already made that decision deliberately.
	l.enableForwarding(l.gatewayA)
	l.enableForwarding(l.gatewayB)
}

// joinNamespaces creates a veth pair spanning two namespaces and addresses it.
func (l *subnetLab) joinNamespaces(near, far netns.NsHandle, nearName, farName, nearAddr, farAddr string) {
	l.t.Helper()

	if err := netns.Set(near); err != nil {
		l.t.Fatalf("entering namespace for %s: %v", nearName, err)
	}

	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: nearName},
		PeerName:  farName,
	}
	if err := netlink.LinkAdd(veth); err != nil {
		l.t.Fatalf("creating %s/%s: %v", nearName, farName, err)
	}

	peer, err := netlink.LinkByName(farName)
	if err != nil {
		l.t.Fatalf("looking up %s: %v", farName, err)
	}
	if err := netlink.LinkSetNsFd(peer, int(far)); err != nil {
		l.t.Fatalf("moving %s: %v", farName, err)
	}

	l.address(nearName, nearAddr)

	if err := netns.Set(far); err != nil {
		l.t.Fatalf("entering namespace for %s: %v", farName, err)
	}
	l.address(farName, farAddr)
}

// address assigns an address and brings the link up, in the current namespace.
func (l *subnetLab) address(name, address string) {
	l.t.Helper()

	link, err := netlink.LinkByName(name)
	if err != nil {
		l.t.Fatalf("looking up %s: %v", name, err)
	}
	addr, err := netlink.ParseAddr(address)
	if err != nil {
		l.t.Fatalf("parsing %s: %v", address, err)
	}
	if err := netlink.AddrAdd(link, addr); err != nil {
		l.t.Fatalf("assigning %s to %s: %v", address, name, err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		l.t.Fatalf("bringing up %s: %v", name, err)
	}
	if loopback, err := netlink.LinkByName("lo"); err == nil {
		_ = netlink.LinkSetUp(loopback)
	}
}

// addDefaultVia points a namespace at its gateway.
func (l *subnetLab) addDefaultVia(where netns.NsHandle, gateway string) {
	l.t.Helper()

	if err := netns.Set(where); err != nil {
		l.t.Fatalf("entering namespace: %v", err)
	}
	if err := netlink.RouteAdd(&netlink.Route{Gw: net.ParseIP(gateway)}); err != nil {
		l.t.Fatalf("adding default route via %s: %v", gateway, err)
	}
}

// enableForwarding turns a namespace into a router.
func (l *subnetLab) enableForwarding(where netns.NsHandle) {
	l.t.Helper()

	if err := netns.Set(where); err != nil {
		l.t.Fatalf("entering namespace: %v", err)
	}
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0o644); err != nil {
		l.t.Skipf("cannot enable forwarding (needs a writable /proc/sys): %v", err)
	}
}

// bringUpTunnel configures one gateway's side of the tunnel.
//
// allowed is what this side will route to the peer — the peer's overlay address
// plus whatever prefixes it has been authorized to announce.
func (l *subnetLab) bringUpTunnel(
	where netns.NsHandle,
	iface string,
	key domain.WireGuardPrivateKey,
	port int,
	overlay string,
	peerKey domain.WireGuardPublicKey,
	peerEndpoint string,
	allowed []string,
) {
	l.t.Helper()

	if err := netns.Set(where); err != nil {
		l.t.Fatalf("entering namespace: %v", err)
	}

	adapter, closeAdapter, err := wireguard.NewController()
	if err != nil {
		l.t.Fatalf("opening the controller: %v", err)
	}
	l.t.Cleanup(func() { _ = closeAdapter() })

	overlayPrefix, err := netip.ParsePrefix(overlay)
	if err != nil {
		l.t.Fatalf("parsing %s: %v", overlay, err)
	}

	ctx := l.t.Context()
	if _, err := adapter.EnsureInterface(ctx, wireguard.InterfaceSpec{
		Name:       iface,
		PrivateKey: key,
		ListenPort: port,
		Addresses:  []netip.Prefix{overlayPrefix},
		MTU:        1420,
	}); err != nil {
		l.t.Fatalf("creating %s: %v", iface, err)
	}

	endpoint, err := netip.ParseAddrPort(peerEndpoint)
	if err != nil {
		l.t.Fatalf("parsing %s: %v", peerEndpoint, err)
	}

	allowedIPs := make([]netip.Prefix, 0, len(allowed))
	for _, entry := range allowed {
		allowedIPs = append(allowedIPs, netip.MustParsePrefix(entry))
	}

	if err := adapter.ApplyPeer(ctx, iface, wireguard.PeerSpec{
		PublicKey:           peerKey,
		Endpoint:            &endpoint,
		AllowedIPs:          allowedIPs,
		PersistentKeepalive: 5 * time.Second,
	}); err != nil {
		l.t.Fatalf("applying the peer: %v", err)
	}
}

// pingFrom sends an ICMP echo from inside a namespace.
func (l *subnetLab) pingFrom(where netns.NsHandle, target string, timeout time.Duration) error {
	l.t.Helper()

	if err := netns.Set(where); err != nil {
		return fmt.Errorf("entering namespace: %w", err)
	}
	return sendICMPEcho(l.t, target, timeout)
}

// establishSubnetTunnel brings both sides up, routing each other's LAN.
func (l *subnetLab) establishSubnetTunnel(allowedToA, allowedToB []string) {
	l.t.Helper()

	l.bringUpTunnel(l.gatewayA, "nm-gwa", l.keyA, subnetPortA, gatewayAOverlay,
		l.pubB, "10.99.0.2:"+fmt.Sprint(subnetPortB), allowedToB)
	l.bringUpTunnel(l.gatewayB, "nm-gwb", l.keyB, subnetPortB, gatewayBOverlay,
		l.pubA, "10.99.0.1:"+fmt.Sprint(subnetPortA), allowedToA)
}

// A host behind one gateway reaches a host behind the other.
//
// This is what an announced route is for, and it is the only test in the suite
// that proves it. Everything else shows a tunnel between two hosts; a route
// that installs and carries nothing would pass all of them.
func TestTrafficCrossesBetweenSubnets(t *testing.T) {
	lab := newSubnetLab(t)

	// Each side routes the other's overlay address and the other's LAN. The
	// LAN entries are what an announcement would produce.
	lab.establishSubnetTunnel(
		[]string{gatewayAOverlay, lanAPrefix},
		[]string{gatewayBOverlay, lanBPrefix},
	)

	// From a host on LAN A to a host on LAN B: through gateway A, across the
	// tunnel, out gateway B.
	if err := lab.pingFrom(lab.lanA, "10.2.0.2", 10*time.Second); err != nil {
		t.Fatalf("a host behind gateway A cannot reach one behind gateway B: %v", err)
	}

	// And back, so this is not one-way reachability that happens to work.
	if err := lab.pingFrom(lab.lanB, "10.1.0.2", 10*time.Second); err != nil {
		t.Errorf("a host behind gateway B cannot reach one behind gateway A: %v", err)
	}
}

// Without the route, the same traffic does not cross.
//
// The control for the test above. Without it, that test could be passing
// because the namespaces are reachable some other way — and it would keep
// passing with the routing removed entirely, which is the failure mode this
// whole delivery exists to prevent.
func TestTrafficDoesNotCrossWithoutTheRoute(t *testing.T) {
	lab := newSubnetLab(t)

	// The tunnel comes up, but neither side routes the other's LAN.
	lab.establishSubnetTunnel(
		[]string{gatewayAOverlay},
		[]string{gatewayBOverlay},
	)

	// The gateways can still reach each other, so the tunnel is genuinely up.
	if err := lab.pingFrom(lab.gatewayA, "100.96.0.2", 10*time.Second); err != nil {
		t.Fatalf("the tunnel itself is not working, so this proves nothing: %v", err)
	}

	if err := lab.pingFrom(lab.lanA, "10.2.0.2", 2*time.Second); err == nil {
		t.Error("traffic crossed to a subnet nothing routed")
	}
}

// A route reaching only one subnet does not carry the other.
//
// Longest-prefix match stays the kernel's job, and this pins that a node
// authorized for one LAN does not get the other for free.
func TestOnlyTheRoutedSubnetIsReachable(t *testing.T) {
	lab := newSubnetLab(t)

	// Gateway A routes B's LAN; gateway B routes only A's overlay, not A's LAN.
	lab.establishSubnetTunnel(
		[]string{gatewayAOverlay},
		[]string{gatewayBOverlay, lanBPrefix},
	)

	// A's LAN host can send, but B's side has no return route to 10.1.0.0/24,
	// so the exchange cannot complete.
	if err := lab.pingFrom(lab.lanA, "10.2.0.2", 2*time.Second); err == nil {
		t.Error("an exchange completed without a return route")
	}
}
