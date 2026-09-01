//go:build linux && privileged

package integration

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"

	"github.com/luizosorio/nostmesh/internal/wireguard"
)

// The overlay constants carry a prefix; ICMP wants the address alone.
const (
	aliceAddress = "100.96.0.1"
	bobAddress   = "100.96.0.2"
)

// The kernel follows a peer that changes address, on its own.
//
// This is the claim NM-20 rests on. Everything else in the roaming design —
// trusting the kernel's observation instead of running a connectivity check we
// no longer have a socket for — is only sound if the kernel really does move a
// peer's endpoint after authenticating a packet from a new address.
//
// A fake cannot establish that. It would report whatever this project believes
// about the kernel, which is the belief under test.
func TestTheKernelFollowsAPeerThatChangesAddress(t *testing.T) {
	lab := newLab(t)
	lab.establish()
	lab.waitForHandshake()

	// Bob moves: a second transport address replaces the first. His WireGuard
	// socket is bound to a port, not an address, so it keeps working and his
	// packets now leave from somewhere else.
	moveBob(t, lab, "10.99.0.7/24")

	// Traffic from Bob is what carries the new source address to Alice's kernel.
	if err := netns.Set(lab.bob); err != nil {
		t.Fatalf("entering bob's namespace: %v", err)
	}
	_ = sendICMPEcho(t, aliceAddress, 2*time.Second)

	moved := netip.MustParseAddrPort(fmt.Sprintf("10.99.0.7:%d", bobPort))
	waitForEndpoint(t, lab, moved)

	// And the tunnel still carries afterwards, which is the point of following.
	if err := netns.Set(lab.alice); err != nil {
		t.Fatalf("entering alice's namespace: %v", err)
	}
	if err := sendICMPEcho(t, bobAddress, 3*time.Second); err != nil {
		t.Errorf("the endpoint moved but the tunnel stopped carrying: %v", err)
	}
}

// Traffic nobody authenticated does not move the endpoint.
//
// This is the other half of NM-20's argument, and the half that is a security
// claim rather than a mechanism claim: an attacker who can reach the port and
// spoof a source address, but does not hold the tunnel key, must not be able to
// redirect an established tunnel.
func TestUnauthenticatedTrafficDoesNotMoveTheEndpoint(t *testing.T) {
	lab := newLab(t)
	lab.establish()
	lab.waitForHandshake()

	before := currentEndpoint(t, lab)
	if before == nil {
		t.Fatal("the tunnel came up with no endpoint")
	}

	// A second address in Bob's namespace stands in for an attacker who can
	// reach Alice's port from somewhere she is not expecting.
	if err := netns.Set(lab.bob); err != nil {
		t.Fatalf("entering bob's namespace: %v", err)
	}
	addSecondAddress(t, "veth-b", "10.99.0.66/24")

	// Bytes that are not a WireGuard packet under this session's keys.
	sendGarbage(t, fmt.Sprintf("10.99.0.1:%d", alicePort))

	time.Sleep(500 * time.Millisecond)

	after := currentEndpoint(t, lab)
	if after == nil {
		t.Fatal("the endpoint disappeared")
	}
	if *after != *before {
		t.Errorf("unauthenticated traffic moved the endpoint from %s to %s", before, after)
	}
}

// moveBob replaces Bob's transport address, keeping his WireGuard port.
func moveBob(t *testing.T, lab *lab, address string) {
	t.Helper()

	if err := netns.Set(lab.bob); err != nil {
		t.Fatalf("entering bob's namespace: %v", err)
	}

	link, err := netlink.LinkByName("veth-b")
	if err != nil {
		t.Fatalf("looking up veth-b: %v", err)
	}

	added, err := netlink.ParseAddr(address)
	if err != nil {
		t.Fatalf("parsing %s: %v", address, err)
	}
	if err := netlink.AddrAdd(link, added); err != nil {
		t.Fatalf("adding %s: %v", address, err)
	}

	old, err := netlink.ParseAddr(bobTransport)
	if err != nil {
		t.Fatalf("parsing %s: %v", bobTransport, err)
	}
	if err := netlink.AddrDel(link, old); err != nil {
		t.Fatalf("removing %s: %v", bobTransport, err)
	}
}

// addSecondAddress gives a link an additional address, keeping the first.
func addSecondAddress(t *testing.T, link, address string) {
	t.Helper()

	found, err := netlink.LinkByName(link)
	if err != nil {
		t.Fatalf("looking up %s: %v", link, err)
	}
	parsed, err := netlink.ParseAddr(address)
	if err != nil {
		t.Fatalf("parsing %s: %v", address, err)
	}
	if err := netlink.AddrAdd(found, parsed); err != nil {
		t.Fatalf("adding %s: %v", address, err)
	}
}

// sendGarbage sends bytes that are not a WireGuard packet to an address.
//
// The kernel must discard them without touching the peer's endpoint: they carry
// no authentication tag it can verify, which is the whole property under test.
func sendGarbage(t *testing.T, target string) {
	t.Helper()

	conn, err := net.Dial("udp", target)
	if err != nil {
		t.Fatalf("dialing %s: %v", target, err)
	}
	defer func() { _ = conn.Close() }()

	for range 5 {
		if _, err := conn.Write([]byte("this is not a wireguard packet")); err != nil {
			t.Fatalf("sending to %s: %v", target, err)
		}
	}
}

// currentEndpoint reports where Alice's kernel thinks Bob is.
func currentEndpoint(t *testing.T, lab *lab) *netip.AddrPort {
	t.Helper()

	if err := netns.Set(lab.alice); err != nil {
		t.Fatalf("entering alice's namespace: %v", err)
	}

	adapter, err := wireguard.NewLinuxAdapter()
	if err != nil {
		t.Fatalf("opening adapter: %v", err)
	}
	defer func() { _ = adapter.Close() }()

	state, err := adapter.ObserveInterface(context.Background(), "nm0")
	if err != nil {
		t.Fatalf("observing nm0: %v", err)
	}
	for _, peer := range state.Peers {
		if peer.PublicKey == lab.bobPub {
			return peer.Endpoint
		}
	}
	return nil
}

// waitForEndpoint polls until the kernel reports the expected endpoint.
func waitForEndpoint(t *testing.T, lab *lab, want netip.AddrPort) {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if got := currentEndpoint(t, lab); got != nil && *got == want {
			return
		}

		// Keep prodding: it is Bob's traffic that carries the new address.
		if err := netns.Set(lab.bob); err == nil {
			_ = sendICMPEcho(t, aliceAddress, time.Second)
		}
		time.Sleep(200 * time.Millisecond)
	}

	t.Fatalf("the kernel did not follow the peer to %s within 10s", want)
}
