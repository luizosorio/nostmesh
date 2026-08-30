//go:build linux && privileged

package integration

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"github.com/luizosorio/nostmesh/internal/domain"
	"github.com/luizosorio/nostmesh/internal/identity"
	"github.com/luizosorio/nostmesh/internal/wireguard"
)

// lab is a two-namespace WireGuard testbed.
//
// Two namespaces joined by a veth pair stand in for two hosts on a network. The
// tunnel runs over that link, so the test exercises the real data path: kernel
// WireGuard, real UDP, real encryption — not a simulation.
type lab struct {
	t testing.TB

	alice netns.NsHandle
	bob   netns.NsHandle

	aliceKey domain.WireGuardPrivateKey
	bobKey   domain.WireGuardPrivateKey
	alicePub domain.WireGuardPublicKey
	bobPub   domain.WireGuardPublicKey
}

const (
	// Transport addresses: the "underlay" the tunnel runs over.
	aliceTransport = "10.99.0.1/24"
	bobTransport   = "10.99.0.2/24"

	// Overlay addresses: what traffic inside the tunnel uses.
	aliceOverlay = "100.96.0.1/32"
	bobOverlay   = "100.96.0.2/32"

	alicePort = 51821
	bobPort   = 51822
)

// newLab builds the two namespaces and the link between them.
func newLab(t testing.TB) *lab {
	t.Helper()

	runtime.LockOSThread()

	original, err := netns.Get()
	if err != nil {
		t.Fatalf("reading current namespace: %v", err)
	}

	l := &lab{t: t}

	l.alice, err = netns.New()
	if err != nil {
		runtime.UnlockOSThread()
		t.Skipf("cannot create a network namespace (needs CAP_SYS_ADMIN): %v", err)
	}
	l.bob, err = netns.New()
	if err != nil {
		_ = l.alice.Close()
		runtime.UnlockOSThread()
		t.Skipf("cannot create a second namespace: %v", err)
	}

	t.Cleanup(func() {
		if err := netns.Set(original); err != nil {
			t.Errorf("restoring namespace: %v", err)
		}
		_ = l.alice.Close()
		_ = l.bob.Close()
		_ = original.Close()
		runtime.UnlockOSThread()
	})

	l.generateKeys()
	l.buildTransport()

	return l
}

func (l *lab) generateKeys() {
	l.t.Helper()

	generator := identity.NewKeyGenerator()

	var err error
	l.alicePub, l.aliceKey, err = generator.Generate()
	if err != nil {
		l.t.Fatalf("generating alice's key: %v", err)
	}
	l.bobPub, l.bobKey, err = generator.Generate()
	if err != nil {
		l.t.Fatalf("generating bob's key: %v", err)
	}
}

// buildTransport creates a veth pair with one end in each namespace, giving the
// two sides a routable path to run the tunnel over.
func (l *lab) buildTransport() {
	l.t.Helper()

	if err := netns.Set(l.alice); err != nil {
		l.t.Fatalf("entering alice's namespace: %v", err)
	}

	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: "veth-a"},
		PeerName:  "veth-b",
	}
	if err := netlink.LinkAdd(veth); err != nil {
		l.t.Fatalf("creating veth pair: %v", err)
	}

	peer, err := netlink.LinkByName("veth-b")
	if err != nil {
		l.t.Fatalf("looking up veth-b: %v", err)
	}
	if err := netlink.LinkSetNsFd(peer, int(l.bob)); err != nil {
		l.t.Fatalf("moving veth-b to bob's namespace: %v", err)
	}

	l.configureTransport("veth-a", aliceTransport)

	if err := netns.Set(l.bob); err != nil {
		l.t.Fatalf("entering bob's namespace: %v", err)
	}
	l.configureTransport("veth-b", bobTransport)
}

func (l *lab) configureTransport(name, address string) {
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

	// Loopback is needed for locally bound test servers.
	if loopback, err := netlink.LinkByName("lo"); err == nil {
		_ = netlink.LinkSetUp(loopback)
	}
}

// bringUp configures one side of the tunnel inside its namespace.
func (l *lab) bringUp(side netns.NsHandle, name string, key domain.WireGuardPrivateKey, port int,
	overlay string, peerKey domain.WireGuardPublicKey, peerEndpoint string, peerAllowed string,
) {
	l.t.Helper()

	if err := netns.Set(side); err != nil {
		l.t.Fatalf("entering namespace: %v", err)
	}

	adapter, err := wireguard.NewLinuxAdapter()
	if err != nil {
		l.t.Fatalf("opening adapter: %v", err)
	}
	defer func() { _ = adapter.Close() }()

	ctx := context.Background()

	if _, err := adapter.EnsureInterface(ctx, wireguard.InterfaceSpec{
		Name:       name,
		PrivateKey: key,
		ListenPort: port,
		Addresses:  []netip.Prefix{netip.MustParsePrefix(overlay)},
		MTU:        1420,
	}); err != nil {
		l.t.Fatalf("creating %s: %v", name, err)
	}

	endpoint := netip.MustParseAddrPort(peerEndpoint)
	if err := adapter.ApplyPeer(ctx, name, wireguard.PeerSpec{
		PublicKey:           peerKey,
		Endpoint:            &endpoint,
		AllowedIPs:          []netip.Prefix{netip.MustParsePrefix(peerAllowed)},
		PersistentKeepalive: time.Second,
	}); err != nil {
		l.t.Fatalf("applying peer to %s: %v", name, err)
	}
}

// establish brings both sides up and waits for a handshake.
func (l *lab) establish() {
	l.t.Helper()

	l.bringUp(l.alice, "nm0", l.aliceKey, alicePort, aliceOverlay,
		l.bobPub, fmt.Sprintf("10.99.0.2:%d", bobPort), bobOverlay)

	l.bringUp(l.bob, "nm0", l.bobKey, bobPort, bobOverlay,
		l.alicePub, fmt.Sprintf("10.99.0.1:%d", alicePort), aliceOverlay)

	l.waitForHandshake()
}

// waitForHandshake polls until the tunnel completes a handshake.
//
// Polling beats a fixed sleep: the handshake usually lands in milliseconds, and
// a timeout that reports the elapsed time makes a genuine failure diagnosable.
func (l *lab) waitForHandshake() {
	l.t.Helper()

	if err := netns.Set(l.alice); err != nil {
		l.t.Fatalf("entering alice's namespace: %v", err)
	}

	adapter, err := wireguard.NewLinuxAdapter()
	if err != nil {
		l.t.Fatalf("opening adapter: %v", err)
	}
	defer func() { _ = adapter.Close() }()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		// Traffic is what triggers the handshake, so send some.
		_ = sendICMPEcho(l.t, "100.96.0.2", time.Second)

		state, err := adapter.ObserveInterface(context.Background(), "nm0")
		if err == nil {
			for _, peer := range state.Peers {
				if peer.HasHandshake() {
					return
				}
			}
		}
		time.Sleep(200 * time.Millisecond)
	}

	l.t.Fatal("no handshake within 10s; the tunnel did not come up")
}

// sendICMPEcho sends one echo request through the tunnel and waits for a reply.
//
// This is done natively rather than by running ping: the test image then needs
// no extra package, and the project's own rule against shelling out applies to
// its tests too.
func sendICMPEcho(t testing.TB, target string, timeout time.Duration) error {
	t.Helper()

	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return fmt.Errorf("opening icmp socket: %w", err)
	}
	defer func() { _ = conn.Close() }()

	message := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: []byte("nostmesh"),
		},
	}
	encoded, err := message.Marshal(nil)
	if err != nil {
		return fmt.Errorf("encoding echo request: %w", err)
	}

	addr, err := net.ResolveIPAddr("ip4", target)
	if err != nil {
		return fmt.Errorf("resolving %s: %w", target, err)
	}
	if _, err := conn.WriteTo(encoded, addr); err != nil {
		return fmt.Errorf("sending echo request: %w", err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return fmt.Errorf("setting deadline: %w", err)
	}

	reply := make([]byte, 1500)
	n, _, err := conn.ReadFrom(reply)
	if err != nil {
		return fmt.Errorf("waiting for echo reply: %w", err)
	}

	parsed, err := icmp.ParseMessage(1, reply[:n])
	if err != nil {
		return fmt.Errorf("parsing reply: %w", err)
	}
	if parsed.Type != ipv4.ICMPTypeEchoReply {
		return fmt.Errorf("expected an echo reply, got %v", parsed.Type)
	}
	return nil
}

// TestLabTunnelCarriesICMP proves packets traverse the tunnel, not just that
// the interfaces exist.
func TestLabTunnelCarriesICMP(t *testing.T) {
	requirePrivileges(t)

	l := newLab(t)
	l.establish()

	for _, direction := range []struct {
		name   string
		from   netns.NsHandle
		target string
	}{
		{"alice to bob", l.alice, "100.96.0.2"},
		{"bob to alice", l.bob, "100.96.0.1"},
	} {
		t.Run(direction.name, func(t *testing.T) {
			if err := netns.Set(direction.from); err != nil {
				t.Fatalf("entering namespace: %v", err)
			}

			if err := sendICMPEcho(t, direction.target, 3*time.Second); err != nil {
				t.Fatalf("icmp to %s failed: %v", direction.target, err)
			}
		})
	}
}

// TestLabTunnelCarriesTCP proves a stream connection works end to end, which
// ICMP alone does not establish.
func TestLabTunnelCarriesTCP(t *testing.T) {
	requirePrivileges(t)

	l := newLab(t)
	l.establish()

	// Listen inside bob's namespace.
	if err := netns.Set(l.bob); err != nil {
		t.Fatalf("entering bob's namespace: %v", err)
	}

	listener, err := net.Listen("tcp", "100.96.0.2:9000")
	if err != nil {
		t.Fatalf("listening in bob's namespace: %v", err)
	}
	defer func() { _ = listener.Close() }()

	const message = "nostmesh tunnel works"
	served := make(chan error, 1)

	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			served <- acceptErr
			return
		}
		defer func() { _ = conn.Close() }()

		_, writeErr := conn.Write([]byte(message))
		served <- writeErr
	}()

	// Connect from alice's namespace, through the tunnel.
	if err := netns.Set(l.alice); err != nil {
		t.Fatalf("entering alice's namespace: %v", err)
	}

	conn, err := net.DialTimeout("tcp", "100.96.0.2:9000", 5*time.Second)
	if err != nil {
		t.Fatalf("connecting through the tunnel: %v", err)
	}
	defer func() { _ = conn.Close() }()

	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("setting deadline: %v", err)
	}

	buf := make([]byte, len(message))
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("reading through the tunnel: %v", err)
	}
	if string(buf) != message {
		t.Errorf("received %q, want %q", buf, message)
	}

	if err := <-served; err != nil {
		t.Errorf("server side: %v", err)
	}
}

// TestLabCountersAdvance confirms the kernel is actually moving bytes, which
// distinguishes a working tunnel from one that merely exists.
func TestLabCountersAdvance(t *testing.T) {
	requirePrivileges(t)

	l := newLab(t)
	l.establish()

	if err := netns.Set(l.alice); err != nil {
		t.Fatalf("entering alice's namespace: %v", err)
	}

	adapter, err := wireguard.NewLinuxAdapter()
	if err != nil {
		t.Fatalf("opening adapter: %v", err)
	}
	defer func() { _ = adapter.Close() }()

	ctx := context.Background()

	before, err := adapter.ObserveInterface(ctx, "nm0")
	if err != nil {
		t.Fatalf("observing: %v", err)
	}
	if len(before.Peers) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(before.Peers))
	}

	for i := 0; i < 5; i++ {
		if err := sendICMPEcho(t, "100.96.0.2", 3*time.Second); err != nil {
			t.Fatalf("generating traffic: %v", err)
		}
	}

	after, err := adapter.ObserveInterface(ctx, "nm0")
	if err != nil {
		t.Fatalf("observing: %v", err)
	}

	if after.Peers[0].TransmitBytes <= before.Peers[0].TransmitBytes {
		t.Errorf("transmit counter did not advance: %d -> %d",
			before.Peers[0].TransmitBytes, after.Peers[0].TransmitBytes)
	}
	if after.Peers[0].ReceiveBytes <= before.Peers[0].ReceiveBytes {
		t.Errorf("receive counter did not advance: %d -> %d",
			before.Peers[0].ReceiveBytes, after.Peers[0].ReceiveBytes)
	}
}

// TestLabMTUIsApplied confirms the configured MTU reaches the kernel. An MTU
// that silently defaults would fragment traffic under load.
func TestLabMTUIsApplied(t *testing.T) {
	requirePrivileges(t)

	l := newLab(t)
	l.establish()

	if err := netns.Set(l.alice); err != nil {
		t.Fatalf("entering alice's namespace: %v", err)
	}

	adapter, err := wireguard.NewLinuxAdapter()
	if err != nil {
		t.Fatalf("opening adapter: %v", err)
	}
	defer func() { _ = adapter.Close() }()

	state, err := adapter.ObserveInterface(context.Background(), "nm0")
	if err != nil {
		t.Fatalf("observing: %v", err)
	}
	if state.MTU != 1420 {
		t.Errorf("MTU = %d, want 1420", state.MTU)
	}
}

// TestLabTeardownLeavesNothing confirms the interface can be removed cleanly,
// which is what makes repeated cycles safe.
func TestLabTeardownLeavesNothing(t *testing.T) {
	requirePrivileges(t)

	l := newLab(t)
	l.establish()

	if err := netns.Set(l.alice); err != nil {
		t.Fatalf("entering alice's namespace: %v", err)
	}

	adapter, err := wireguard.NewLinuxAdapter()
	if err != nil {
		t.Fatalf("opening adapter: %v", err)
	}
	defer func() { _ = adapter.Close() }()

	ctx := context.Background()
	if err := adapter.RemoveInterface(ctx, "nm0"); err != nil {
		t.Fatalf("removing interface: %v", err)
	}

	if _, err := adapter.ObserveInterface(ctx, "nm0"); err == nil {
		t.Error("the interface survived removal")
	}

	// The transport link must be untouched: NostMesh removes only what it owns.
	if _, err := netlink.LinkByName("veth-a"); err != nil {
		t.Errorf("teardown removed the transport link: %v", err)
	}
}

// TestLabHundredCyclesLeaveNoResidue is the MVP 0 gate: repeated setup and
// teardown must not accumulate interfaces, addresses or routes.
//
// A leak that appears only after many cycles is the kind that shows up in
// production and not in a single-run test, which is why the count is high.
func TestLabHundredCyclesLeaveNoResidue(t *testing.T) {
	requirePrivileges(t)

	if testing.Short() {
		t.Skip("skipping the 100-cycle gate in short mode")
	}

	l := newLab(t)

	if err := netns.Set(l.alice); err != nil {
		t.Fatalf("entering alice's namespace: %v", err)
	}

	adapter, err := wireguard.NewLinuxAdapter()
	if err != nil {
		t.Fatalf("opening adapter: %v", err)
	}
	defer func() { _ = adapter.Close() }()

	ctx := context.Background()
	endpoint := netip.MustParseAddrPort(fmt.Sprintf("10.99.0.2:%d", bobPort))

	linksBefore, err := netlink.LinkList()
	if err != nil {
		t.Fatalf("listing links: %v", err)
	}
	routesBefore, err := netlink.RouteList(nil, netlink.FAMILY_ALL)
	if err != nil {
		t.Fatalf("listing routes: %v", err)
	}

	for cycle := 1; cycle <= 100; cycle++ {
		if _, err := adapter.EnsureInterface(ctx, wireguard.InterfaceSpec{
			Name:       "nm0",
			PrivateKey: l.aliceKey,
			ListenPort: alicePort,
			Addresses:  []netip.Prefix{netip.MustParsePrefix(aliceOverlay)},
			MTU:        1420,
		}); err != nil {
			t.Fatalf("cycle %d: creating interface: %v", cycle, err)
		}

		if err := adapter.ApplyPeer(ctx, "nm0", wireguard.PeerSpec{
			PublicKey:  l.bobPub,
			Endpoint:   &endpoint,
			AllowedIPs: []netip.Prefix{netip.MustParsePrefix(bobOverlay)},
		}); err != nil {
			t.Fatalf("cycle %d: applying peer: %v", cycle, err)
		}

		if err := adapter.RemoveInterface(ctx, "nm0"); err != nil {
			t.Fatalf("cycle %d: removing interface: %v", cycle, err)
		}
	}

	linksAfter, err := netlink.LinkList()
	if err != nil {
		t.Fatalf("listing links: %v", err)
	}
	if len(linksAfter) != len(linksBefore) {
		t.Errorf("link count changed after 100 cycles: %d -> %d", len(linksBefore), len(linksAfter))
		for _, link := range linksAfter {
			t.Logf("  present: %s (%s)", link.Attrs().Name, link.Type())
		}
	}

	routesAfter, err := netlink.RouteList(nil, netlink.FAMILY_ALL)
	if err != nil {
		t.Fatalf("listing routes: %v", err)
	}
	if len(routesAfter) != len(routesBefore) {
		t.Errorf("route count changed after 100 cycles: %d -> %d", len(routesBefore), len(routesAfter))
		for _, route := range routesAfter {
			t.Logf("  present: %v", route.Dst)
		}
	}

	if _, err := adapter.ObserveInterface(ctx, "nm0"); err == nil {
		t.Error("the interface survived the final teardown")
	}
}

// TestLabPeerRemovalTakesItsRoutes confirms a peer removed on its own does not
// leave a route pointing at something that no longer exists.
func TestLabPeerRemovalTakesItsRoutes(t *testing.T) {
	requirePrivileges(t)

	l := newLab(t)

	if err := netns.Set(l.alice); err != nil {
		t.Fatalf("entering alice's namespace: %v", err)
	}

	adapter, err := wireguard.NewLinuxAdapter()
	if err != nil {
		t.Fatalf("opening adapter: %v", err)
	}
	defer func() { _ = adapter.Close() }()

	ctx := context.Background()

	if _, err := adapter.EnsureInterface(ctx, wireguard.InterfaceSpec{
		Name:       "nm0",
		PrivateKey: l.aliceKey,
		ListenPort: alicePort,
		Addresses:  []netip.Prefix{netip.MustParsePrefix(aliceOverlay)},
		MTU:        1420,
	}); err != nil {
		t.Fatalf("creating interface: %v", err)
	}

	endpoint := netip.MustParseAddrPort(fmt.Sprintf("10.99.0.2:%d", bobPort))
	if err := adapter.ApplyPeer(ctx, "nm0", wireguard.PeerSpec{
		PublicKey:  l.bobPub,
		Endpoint:   &endpoint,
		AllowedIPs: []netip.Prefix{netip.MustParsePrefix(bobOverlay)},
	}); err != nil {
		t.Fatalf("applying peer: %v", err)
	}

	routed := func() bool {
		routes, listErr := netlink.RouteList(nil, netlink.FAMILY_V4)
		if listErr != nil {
			t.Fatalf("listing routes: %v", listErr)
		}
		for _, route := range routes {
			if route.Dst != nil && route.Dst.String() == bobOverlay {
				return true
			}
		}
		return false
	}

	if !routed() {
		t.Fatal("applying a peer must install a route for its allowed prefixes")
	}

	if err := adapter.RemovePeer(ctx, "nm0", l.bobPub); err != nil {
		t.Fatalf("removing peer: %v", err)
	}

	if routed() {
		t.Error("removing a peer left its route behind")
	}
}
