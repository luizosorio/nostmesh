package connectivity

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"
)

// fakeInterfaces returns a fixed address list.
type fakeInterfaces struct {
	addresses []netip.Addr
	err       error
}

func (f fakeInterfaces) Addresses() ([]netip.Addr, error) {
	return f.addresses, f.err
}

// fakeObserver stands in for a STUN server, including a hostile one.
type fakeObserver struct {
	// responses maps server address to what it claims to have seen.
	responses map[string]netip.AddrPort

	// failures maps server address to an error.
	failures map[string]error

	// queried records which servers were contacted, so a test can assert that
	// a node with a usable local address never told a stranger it exists.
	queried []string
}

func (f *fakeObserver) Observe(_ context.Context, server string, _ int) (netip.AddrPort, error) {
	f.queried = append(f.queried, server)

	if err, failing := f.failures[server]; failing {
		return netip.AddrPort{}, err
	}
	if response, known := f.responses[server]; known {
		return response, nil
	}
	return netip.AddrPort{}, errors.New("no response configured")
}

func testGatherer(t *testing.T, policy GatherPolicy, interfaces InterfaceLister, observer Observer) *Gatherer {
	t.Helper()

	return NewGatherer(GathererOptions{
		Policy:     policy,
		Interfaces: interfaces,
		Observer:   observer,
		Clock:      func() time.Time { return testNow() },
	})
}

// The privacy property: a node with a usable local address never contacts an
// observer, so no stranger learns it exists.
func TestUsableLocalAddressSkipsTheObserver(t *testing.T) {
	observer := &fakeObserver{
		responses: map[string]netip.AddrPort{
			"stun.invalid:3478": netip.MustParseAddrPort("198.51.100.99:51820"),
		},
	}

	policy := DefaultGatherPolicy()
	policy.Observers = []string{"stun.invalid:3478"}

	gatherer := testGatherer(t, policy, fakeInterfaces{
		addresses: []netip.Addr{netip.MustParseAddr("203.0.113.5")},
	}, observer)

	result := gatherer.Gather(context.Background(), 51820)

	if len(result.Candidates) == 0 {
		t.Fatal("a routable local address must produce a candidate")
	}
	if len(observer.queried) != 0 {
		t.Errorf("an observer was contacted despite a usable local address: %v", observer.queried)
	}
}

// A node with only private addresses cannot reach a peer across the internet,
// so it does need to ask.
func TestPrivateOnlyNodeQueriesTheObserver(t *testing.T) {
	observer := &fakeObserver{
		responses: map[string]netip.AddrPort{
			"stun.invalid:3478": netip.MustParseAddrPort("198.51.100.99:51820"),
		},
	}

	policy := DefaultGatherPolicy()
	policy.Observers = []string{"stun.invalid:3478"}

	gatherer := testGatherer(t, policy, fakeInterfaces{
		addresses: []netip.Addr{netip.MustParseAddr("192.168.1.10")},
	}, observer)

	result := gatherer.Gather(context.Background(), 51820)

	if len(observer.queried) == 0 {
		t.Error("a node with only private addresses must query an observer")
	}

	var sawReflexive bool
	for _, candidate := range result.Candidates {
		if candidate.Kind == KindServerReflexive {
			sawReflexive = true
			if candidate.Status.Permits() {
				t.Error("an observed address must not be permitted without a probe")
			}
			if candidate.Source != "stun.invalid:3478" {
				t.Errorf("source = %q, want the observer that said it", candidate.Source)
			}
		}
	}
	if !sawReflexive {
		t.Error("the observer's answer must become a candidate")
	}
}

// An observer reporting a dangerous address is broken or hostile. Either way
// the answer is discarded rather than becoming a candidate.
func TestObserverReportingUnsafeAddressIsIgnored(t *testing.T) {
	for _, unsafe := range []string{
		"127.0.0.1:51820",
		"224.0.0.1:51820",
		"0.0.0.0:51820",
		"169.254.1.1:51820",
	} {
		t.Run(unsafe, func(t *testing.T) {
			observer := &fakeObserver{
				responses: map[string]netip.AddrPort{
					"hostile.invalid:3478": netip.MustParseAddrPort(unsafe),
				},
			}

			policy := GatherPolicy{
				Order:     []Method{MethodObserver},
				Observers: []string{"hostile.invalid:3478"},
			}

			gatherer := testGatherer(t, policy, fakeInterfaces{}, observer)
			result := gatherer.Gather(context.Background(), 51820)

			if len(result.Candidates) != 0 {
				t.Errorf("an unsafe observed address became a candidate: %v", result.Candidates)
			}
			if result.Failures[MethodObserver] == nil {
				t.Error("the refusal must be reported as a failure")
			}
		})
	}
}

// Every observer is queried rather than stopping at the first, because
// disagreement is informative: it reveals a symmetric NAT. Agreement proves
// nothing either way.
func TestDisagreeingObserversBothProduceCandidates(t *testing.T) {
	observer := &fakeObserver{
		responses: map[string]netip.AddrPort{
			"a.invalid:3478": netip.MustParseAddrPort("198.51.100.10:51820"),
			"b.invalid:3478": netip.MustParseAddrPort("198.51.100.11:40000"),
		},
	}

	policy := GatherPolicy{
		Order:     []Method{MethodObserver},
		Observers: []string{"a.invalid:3478", "b.invalid:3478"},
	}

	gatherer := testGatherer(t, policy, fakeInterfaces{}, observer)
	result := gatherer.Gather(context.Background(), 51820)

	if len(result.Candidates) != 2 {
		t.Fatalf("%d candidates, want both observers' claims recorded", len(result.Candidates))
	}
	for _, candidate := range result.Candidates {
		if candidate.Status.Permits() {
			t.Error("no observed address may be permitted before a probe")
		}
	}
}

// One observer failing must not stop the others.
func TestOneObserverFailingDoesNotBlockTheRest(t *testing.T) {
	observer := &fakeObserver{
		responses: map[string]netip.AddrPort{
			"good.invalid:3478": netip.MustParseAddrPort("198.51.100.10:51820"),
		},
		failures: map[string]error{
			"dead.invalid:3478": errors.New("connection refused"),
		},
	}

	policy := GatherPolicy{
		Order:     []Method{MethodObserver},
		Observers: []string{"dead.invalid:3478", "good.invalid:3478"},
	}

	gatherer := testGatherer(t, policy, fakeInterfaces{}, observer)
	result := gatherer.Gather(context.Background(), 51820)

	if len(result.Candidates) != 1 {
		t.Errorf("%d candidates, want 1 from the working observer", len(result.Candidates))
	}
}

// With no observer reachable and no local address, gathering must fail with an
// explanation rather than silently producing nothing.
func TestNoObserverAvailableIsReported(t *testing.T) {
	observer := &fakeObserver{
		failures: map[string]error{"dead.invalid:3478": errors.New("timeout")},
	}

	policy := GatherPolicy{
		Order:     []Method{MethodObserver},
		Observers: []string{"dead.invalid:3478"},
	}

	gatherer := testGatherer(t, policy, fakeInterfaces{}, observer)
	result := gatherer.Gather(context.Background(), 51820)

	if len(result.Candidates) != 0 {
		t.Error("no candidates should be produced")
	}
	if result.Failures[MethodObserver] == nil {
		t.Error("the failure must be reported, not swallowed")
	}
}

// A method absent from the policy is never used. A deployment that will not
// contact a third party can say so.
func TestPolicyExcludesMethods(t *testing.T) {
	observer := &fakeObserver{
		responses: map[string]netip.AddrPort{
			"stun.invalid:3478": netip.MustParseAddrPort("198.51.100.10:51820"),
		},
	}

	policy := GatherPolicy{
		Order:     []Method{MethodInterface},
		Observers: []string{"stun.invalid:3478"},
	}

	gatherer := testGatherer(t, policy, fakeInterfaces{
		addresses: []netip.Addr{netip.MustParseAddr("192.168.1.10")},
	}, observer)

	gatherer.Gather(context.Background(), 51820)

	if len(observer.queried) != 0 {
		t.Errorf("an excluded method was used: %v", observer.queried)
	}
}

// Announcing a private address to a peer that cannot use it is a small privacy
// leak, so a deployment can suppress it.
func TestPrivateAddressesCanBeSuppressed(t *testing.T) {
	policy := GatherPolicy{
		Order:                 []Method{MethodInterface},
		AllowPrivateAddresses: false,
	}

	gatherer := testGatherer(t, policy, fakeInterfaces{
		addresses: []netip.Addr{
			netip.MustParseAddr("192.168.1.10"),
			netip.MustParseAddr("203.0.113.5"),
		},
	}, nil)

	result := gatherer.Gather(context.Background(), 51820)

	for _, candidate := range result.Candidates {
		if IsPrivate(candidate.Address.Addr()) {
			t.Errorf("a private address was announced despite the policy: %s", candidate.Address)
		}
	}
	if len(result.Candidates) != 1 {
		t.Errorf("%d candidates, want only the routable one", len(result.Candidates))
	}
}

func TestIPv6CanBeSuppressed(t *testing.T) {
	policy := GatherPolicy{
		Order:                 []Method{MethodInterface},
		AllowIPv6:             false,
		AllowPrivateAddresses: true,
	}

	gatherer := testGatherer(t, policy, fakeInterfaces{
		addresses: []netip.Addr{
			netip.MustParseAddr("2001:db8::1"),
			netip.MustParseAddr("203.0.113.5"),
		},
	}, nil)

	result := gatherer.Gather(context.Background(), 51820)

	for _, candidate := range result.Candidates {
		if candidate.Address.Addr().Is6() {
			t.Errorf("an IPv6 candidate appeared despite the policy: %s", candidate.Address)
		}
	}
}

// Ordering encodes how much has to go right: a direct address before one a
// stranger vouched for.
func TestPriorityPrefersLessTrustedPathsLast(t *testing.T) {
	host := priorityFor(KindHost, netip.MustParseAddr("203.0.113.5"))
	static := priorityFor(KindStatic, netip.MustParseAddr("203.0.113.5"))
	reflexive := priorityFor(KindServerReflexive, netip.MustParseAddr("203.0.113.5"))

	if host >= static || static >= reflexive {
		t.Errorf("priority ordering is wrong: host=%d static=%d srflx=%d", host, static, reflexive)
	}
}

// IPv6 usually means no NAT, so it is tried before IPv4 of the same kind.
func TestIPv6IsPreferredWithinAKind(t *testing.T) {
	v6 := priorityFor(KindHost, netip.MustParseAddr("2001:db8::1"))
	v4 := priorityFor(KindHost, netip.MustParseAddr("203.0.113.5"))

	if v6 >= v4 {
		t.Errorf("IPv6 priority %d must come before IPv4 %d", v6, v4)
	}
}

// An unimplemented method reports that plainly rather than silently
// contributing nothing.
func TestUnimplementedMethodsAreReported(t *testing.T) {
	policy := GatherPolicy{Order: []Method{MethodPortMapping, MethodRecent}}
	gatherer := testGatherer(t, policy, fakeInterfaces{}, nil)

	result := gatherer.Gather(context.Background(), 51820)

	for _, method := range []Method{MethodPortMapping, MethodRecent} {
		if result.Failures[method] == nil {
			t.Errorf("%s must report that it is unimplemented", method)
		}
	}
}

// A cancelled context stops gathering rather than running every method.
func TestCancellationStopsGathering(t *testing.T) {
	observer := &fakeObserver{
		responses: map[string]netip.AddrPort{
			"stun.invalid:3478": netip.MustParseAddrPort("198.51.100.10:51820"),
		},
	}

	policy := GatherPolicy{
		Order:     []Method{MethodObserver},
		Observers: []string{"stun.invalid:3478"},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	gatherer := testGatherer(t, policy, fakeInterfaces{}, observer)
	result := gatherer.Gather(ctx, 51820)

	if len(result.Candidates) != 0 {
		t.Error("a cancelled context must not produce candidates")
	}
}
