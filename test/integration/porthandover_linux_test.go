//go:build linux && privileged

// Tests the handover of a UDP port from the connectivity transport to kernel
// WireGuard.
//
// This is the step that lets one port serve the whole session. A NAT maps per
// source port, so the address a peer verified is only usable if WireGuard
// afterwards occupies the very same port. wgctrl cannot accept a file
// descriptor, so the port cannot be shared — it is released and immediately
// rebound, and these tests assert that the sequence works against a real kernel
// rather than against a mock that would agree with anything.
package integration

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/vishvananda/netlink"

	"github.com/luizosorio/nostmesh/internal/connectivity"
	"github.com/luizosorio/nostmesh/internal/wireguard"
)

// The core of the handover: the port the transport held must be the port
// WireGuard ends up listening on.
//
// Letting the kernel choose the WireGuard port instead would produce an
// interface listening somewhere the peer never verified. The tunnel would then
// fail with every candidate marked valid — a failure that looks like a NAT
// problem and is not one.
func TestTransportPortIsHandedOverToWireGuard(t *testing.T) {
	requirePrivileges(t)

	withNamespace(t, func() {
		transport, err := connectivity.NewUDPTransport(0)
		if err != nil {
			t.Fatalf("binding transport: %v", err)
		}

		port := transport.LocalPort()
		if port == 0 {
			t.Fatal("transport reported port 0")
		}

		// Phase B: the transport releases the port.
		if err := transport.Close(); err != nil {
			t.Fatalf("releasing the port: %v", err)
		}

		// Phase C: WireGuard takes it.
		adapter, err := wireguard.NewLinuxAdapter()
		if err != nil {
			t.Fatalf("opening adapter: %v", err)
		}
		defer func() { _ = adapter.Close() }()

		spec := testSpec(t, "nm-handover")
		spec.ListenPort = int(port)

		ctx := context.Background()
		state, err := adapter.EnsureInterface(ctx, spec)
		if err != nil {
			t.Fatalf("WireGuard could not take the port the transport released: %v", err)
		}
		defer func() { _ = adapter.RemoveInterface(context.Background(), spec.Name) }()

		if state.ListenPort != int(port) {
			t.Errorf("WireGuard listens on %d, the transport held %d; the peer verified the wrong port",
				state.ListenPort, port)
		}
	})
}

// The transport must not still hold the socket after Close, or WireGuard's bind
// fails at the last step of an otherwise successful session.
func TestPortIsFreeAfterTransportCloses(t *testing.T) {
	requirePrivileges(t)

	withNamespace(t, func() {
		first, err := connectivity.NewUDPTransport(0)
		if err != nil {
			t.Fatalf("binding: %v", err)
		}
		port := first.LocalPort()

		if err := first.Close(); err != nil {
			t.Fatalf("closing: %v", err)
		}

		// Rebinding the same port proves it was genuinely released. Anything
		// still holding it fails here rather than silently later.
		second, err := connectivity.NewUDPTransport(port)
		if err != nil {
			t.Fatalf("port %d was not released by Close: %v", port, err)
		}
		defer func() { _ = second.Close() }()

		if second.LocalPort() != port {
			t.Errorf("rebound to %d, expected %d", second.LocalPort(), port)
		}
	})
}

// Two transports must not silently share a port: the second bind has to fail,
// or two sessions would gather candidates for a port only one of them owns.
func TestASecondTransportCannotStealTheSamePort(t *testing.T) {
	requirePrivileges(t)

	withNamespace(t, func() {
		held, err := connectivity.NewUDPTransport(0)
		if err != nil {
			t.Fatalf("binding: %v", err)
		}
		defer func() { _ = held.Close() }()

		if _, err := connectivity.NewUDPTransport(held.LocalPort()); err == nil {
			t.Error("a second transport bound a port already held; the port is not exclusive")
		}
	})
}

// Real UDP must flow over the transport inside a namespace, not just bind.
// A socket that binds but cannot carry a datagram would pass every check above
// and fail the moment a probe is sent.
func TestTransportCarriesRealTrafficInNamespace(t *testing.T) {
	requirePrivileges(t)

	withNamespace(t, func() {
		// A fresh namespace has loopback down, so 127.0.0.1 is unreachable
		// until it is raised. Binding a socket succeeds regardless — which is
		// why only a test that sends real traffic notices.
		loopback, err := netlink.LinkByName("lo")
		if err != nil {
			t.Fatalf("looking up loopback: %v", err)
		}
		if err := netlink.LinkSetUp(loopback); err != nil {
			t.Fatalf("raising loopback: %v", err)
		}

		sender, err := connectivity.NewUDPTransport(0)
		if err != nil {
			t.Fatalf("binding sender: %v", err)
		}
		defer func() { _ = sender.Close() }()

		receiver, err := connectivity.NewUDPTransport(0)
		if err != nil {
			t.Fatalf("binding receiver: %v", err)
		}
		defer func() { _ = receiver.Close() }()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		target := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), receiver.LocalPort())
		payload := []byte("real datagram")

		if err := sender.Send(ctx, target, payload); err != nil {
			t.Fatalf("sending: %v", err)
		}

		received, source, err := receiver.Receive(ctx)
		if err != nil {
			t.Fatalf("receiving: %v", err)
		}
		if string(received) != string(payload) {
			t.Errorf("received %q, sent %q", received, payload)
		}
		if source.Port() != sender.LocalPort() {
			t.Errorf("source port %d, sender holds %d", source.Port(), sender.LocalPort())
		}
	})
}
