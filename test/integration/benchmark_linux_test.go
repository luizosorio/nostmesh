//go:build linux && privileged

// Baseline measurements for the manual tunnel.
//
// These establish a reference point, not a performance claim. They run between
// two network namespaces on one machine, so there is no physical link, no
// competing traffic and no real network path: the numbers say what the code
// costs, not what a deployment would see.
//
// RNF-PERF targets tunnel-attributable overhead below 10% on a 1 Gbps lab.
// Measuring that needs two hosts and a real link, which MVP 0 does not have.
// What these establish is a baseline to detect regressions against.
package integration

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/vishvananda/netns"

	"github.com/luizosorio/nostmesh/internal/wireguard"
)

// BenchmarkInterfaceSetup measures how long it takes to bring an interface up.
//
// This is the latency an operator sees from `nostmesh up`, and the cost paid on
// every reconnect once roaming exists.
func BenchmarkInterfaceSetup(b *testing.B) {
	requirePrivileges(b)

	l := newLab(b)

	if err := netns.Set(l.alice); err != nil {
		b.Fatalf("entering namespace: %v", err)
	}

	adapter, err := wireguard.NewLinuxAdapter()
	if err != nil {
		b.Fatalf("opening adapter: %v", err)
	}
	defer func() { _ = adapter.Close() }()

	ctx := context.Background()
	spec := wireguard.InterfaceSpec{
		Name:       "nm-bench",
		PrivateKey: l.aliceKey,
		ListenPort: 51899,
		Addresses:  []netip.Prefix{netip.MustParsePrefix("100.96.0.9/32")},
		MTU:        1420,
	}

	b.ResetTimer()
	for range b.N {
		if _, err := adapter.EnsureInterface(ctx, spec); err != nil {
			b.Fatalf("creating interface: %v", err)
		}
		b.StopTimer()
		if err := adapter.RemoveInterface(ctx, "nm-bench"); err != nil {
			b.Fatalf("removing interface: %v", err)
		}
		b.StartTimer()
	}
}

// BenchmarkIdempotentApply measures a repeated apply against unchanged state.
//
// Convergence is the common case: reconciliation and retries both re-apply a
// plan that is mostly already in place, so this cost is paid often.
func BenchmarkIdempotentApply(b *testing.B) {
	requirePrivileges(b)

	l := newLab(b)

	if err := netns.Set(l.alice); err != nil {
		b.Fatalf("entering namespace: %v", err)
	}

	adapter, err := wireguard.NewLinuxAdapter()
	if err != nil {
		b.Fatalf("opening adapter: %v", err)
	}
	defer func() { _ = adapter.Close() }()

	ctx := context.Background()
	spec := wireguard.InterfaceSpec{
		Name:       "nm-bench",
		PrivateKey: l.aliceKey,
		ListenPort: 51899,
		Addresses:  []netip.Prefix{netip.MustParsePrefix("100.96.0.9/32")},
		MTU:        1420,
	}

	if _, err := adapter.EnsureInterface(ctx, spec); err != nil {
		b.Fatalf("creating interface: %v", err)
	}
	defer func() { _ = adapter.RemoveInterface(ctx, "nm-bench") }()

	b.ResetTimer()
	for range b.N {
		if _, err := adapter.EnsureInterface(ctx, spec); err != nil {
			b.Fatalf("re-applying: %v", err)
		}
	}
}

// BenchmarkTunnelThroughput measures TCP throughput through the tunnel.
//
// Both namespaces share a kernel and a CPU, so this measures encryption and
// packet handling cost, not network capacity. Treat it as a regression signal.
func BenchmarkTunnelThroughput(b *testing.B) {
	requirePrivileges(b)

	l := newLab(b)
	l.establish()

	if err := netns.Set(l.bob); err != nil {
		b.Fatalf("entering bob's namespace: %v", err)
	}

	listener, err := net.Listen("tcp", "100.96.0.2:9100")
	if err != nil {
		b.Fatalf("listening: %v", err)
	}
	defer func() { _ = listener.Close() }()

	const chunkSize = 64 * 1024
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_, _ = io.Copy(io.Discard, conn)
			}()
		}
	}()

	if err := netns.Set(l.alice); err != nil {
		b.Fatalf("entering alice's namespace: %v", err)
	}

	conn, err := net.DialTimeout("tcp", "100.96.0.2:9100", 5*time.Second)
	if err != nil {
		b.Fatalf("connecting: %v", err)
	}
	defer func() { _ = conn.Close() }()

	payload := make([]byte, chunkSize)
	b.SetBytes(chunkSize)
	b.ResetTimer()

	for range b.N {
		if _, err := conn.Write(payload); err != nil {
			b.Fatalf("writing: %v", err)
		}
	}
}

// BenchmarkHandshakeLatency measures time from a cold interface to a completed
// handshake — the delay before a tunnel carries traffic.
func BenchmarkHandshakeLatency(b *testing.B) {
	requirePrivileges(b)

	l := newLab(b)

	for range b.N {
		b.StopTimer()
		teardownBoth(b, l)
		b.StartTimer()

		l.establish()
	}
}

func teardownBoth(b *testing.B, l *lab) {
	b.Helper()

	for _, side := range []netns.NsHandle{l.alice, l.bob} {
		if err := netns.Set(side); err != nil {
			b.Fatalf("entering namespace: %v", err)
		}
		adapter, err := wireguard.NewLinuxAdapter()
		if err != nil {
			b.Fatalf("opening adapter: %v", err)
		}
		_ = adapter.RemoveInterface(context.Background(), "nm0")
		_ = adapter.Close()
	}
}
