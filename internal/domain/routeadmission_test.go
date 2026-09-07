package domain

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func labNetwork() LocalNetwork {
	return LocalNetwork{
		Transports:     []netip.Addr{netip.MustParseAddr("198.51.100.10")},
		Infrastructure: []netip.Addr{netip.MustParseAddr("203.0.113.5")},
		Prefixes:       []netip.Prefix{netip.MustParsePrefix("100.96.0.0/24")},
	}
}

// A route to somewhere this node does not otherwise reach is admitted.
//
// Without this the refusals below could all be passing because everything is
// refused.
func TestAnOrdinaryPrefixIsAdmitted(t *testing.T) {
	for _, prefix := range []string{"10.20.30.0/24", "192.168.5.0/24", "172.16.0.0/12", "fd00:1::/64"} {
		if err := AdmitRoute(netip.MustParsePrefix(prefix), labNetwork()); err != nil {
			t.Errorf("%s was refused: %v", prefix, err)
		}
	}
}

// A prefix covering the tunnel's own transport is refused.
//
// This is the loop the architecture names: routing the transport into the
// tunnel that depends on it. It is refused rather than contained by policy
// routing, because refusing is verifiable and a separate table is one more
// thing to leave behind.
func TestAPrefixCoveringTheTransportIsRefused(t *testing.T) {
	local := labNetwork()

	// Exactly the endpoint, and a wide net that happens to contain it. Both
	// break the same way; only the second looks innocent.
	for _, prefix := range []string{"198.51.100.10/32", "198.51.100.0/24", "198.0.0.0/8"} {
		err := AdmitRoute(netip.MustParsePrefix(prefix), local)
		if !errors.Is(err, ErrRouteRefused) {
			t.Errorf("%s was admitted; it captures this node's tunnel transport", prefix)
		}
		if err != nil && !strings.Contains(err.Error(), "transport") {
			t.Errorf("%s: the refusal does not say which rule fired: %v", prefix, err)
		}
	}
}

// A prefix covering a relay or observer is refused.
//
// The same loop one step removed: losing the path to a relay takes the control
// plane with it, and the node cannot then be told to withdraw the route that
// broke it.
func TestAPrefixCoveringInfrastructureIsRefused(t *testing.T) {
	err := AdmitRoute(netip.MustParsePrefix("203.0.113.0/24"), labNetwork())
	if !errors.Is(err, ErrRouteRefused) {
		t.Fatal("a prefix covering a relay was admitted")
	}
	if !strings.Contains(err.Error(), "relay or observer") {
		t.Errorf("the refusal does not say which rule fired: %v", err)
	}
}

// A prefix overlapping something this host already reaches is refused.
//
// Both directions: a narrower announcement steals part of a local network by
// longest-prefix match, and a wider one swallows it whole.
func TestAPrefixOverlappingALocalNetworkIsRefused(t *testing.T) {
	local := labNetwork() // holds 100.96.0.0/24

	for _, prefix := range []string{
		"100.96.0.0/24", // exactly
		"100.96.0.0/25", // narrower, wins longest-prefix match
		"100.96.0.0/16", // wider, swallows it
	} {
		err := AdmitRoute(netip.MustParsePrefix(prefix), local)
		if !errors.Is(err, ErrRouteRefused) {
			t.Errorf("%s was admitted; it overlaps a network this host already reaches", prefix)
		}
	}
}

// A default route is refused whatever else is configured.
func TestADefaultRouteIsRefused(t *testing.T) {
	for _, prefix := range []string{"0.0.0.0/0", "::/0"} {
		err := AdmitRoute(netip.MustParsePrefix(prefix), LocalNetwork{})
		if !errors.Is(err, ErrRouteRefused) {
			t.Errorf("%s was admitted", prefix)
		}
		if err != nil && !strings.Contains(err.Error(), "default route") {
			t.Errorf("%s: the refusal does not name it as a default route: %v", prefix, err)
		}
	}
}

// Martians are refused: nothing legitimate announces them.
func TestMartiansAreRefused(t *testing.T) {
	tests := []struct {
		prefix string
		says   string
	}{
		{"127.0.0.0/8", "loopback"},
		{"::1/128", "loopback"},
		{"224.0.0.0/4", "multicast"},
		{"ff00::/8", "multicast"},
		{"169.254.0.0/16", "link-local"},
		{"fe80::/10", "link-local"},
	}

	for _, test := range tests {
		t.Run(test.prefix, func(t *testing.T) {
			err := AdmitRoute(netip.MustParsePrefix(test.prefix), LocalNetwork{})
			if !errors.Is(err, ErrRouteRefused) {
				t.Fatalf("%s was admitted", test.prefix)
			}
			if !strings.Contains(err.Error(), test.says) {
				t.Errorf("the refusal does not say %q: %v", test.says, err)
			}
		})
	}
}

// A prefix that is not in canonical form is refused.
func TestANonCanonicalPrefixIsRefused(t *testing.T) {
	// netip parses this and keeps the host bits; two spellings of one
	// destination would let a provider hold two entries for it.
	prefix, err := netip.ParsePrefix("10.20.30.1/24")
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}

	if err := AdmitRoute(prefix, LocalNetwork{}); !errors.Is(err, ErrRouteRefused) {
		t.Error("a non-canonical prefix was admitted")
	}
}

// A node with nothing configured still refuses what it must.
//
// The refusals that protect the connection depend on local state, but the ones
// that describe an impossible destination do not — and a node that has not
// gathered its addresses yet must not become permissive.
func TestAnEmptyLocalNetworkStillRefusesMartians(t *testing.T) {
	for _, prefix := range []string{"127.0.0.0/8", "0.0.0.0/0", "224.0.0.0/4"} {
		if err := AdmitRoute(netip.MustParsePrefix(prefix), LocalNetwork{}); !errors.Is(err, ErrRouteRefused) {
			t.Errorf("%s was admitted by a node with nothing configured", prefix)
		}
	}
}
