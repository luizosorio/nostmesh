package policy

import (
	"net/netip"
	"testing"
	"time"

	"github.com/luizosorio/nostmesh/internal/domain"
)

func routerAt() time.Time {
	return time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
}

func routerLocal() domain.LocalNetwork {
	return domain.LocalNetwork{
		Transports: []netip.Addr{netip.MustParseAddr("198.51.100.10")},
		Prefixes:   []netip.Prefix{netip.MustParsePrefix("100.96.0.0/24")},
	}
}

// newRouter builds a router whose provider may route the given prefixes.
func newRouter(t *testing.T, provider domain.NostrPublicKey, allowed ...string) *Router {
	t.Helper()

	list := NewAllowlist()
	if err := list.Add(Grant{
		Peer:       provider,
		Actions:    []Action{ActionSession, ActionRoute},
		AllowedIPs: prefixes(allowed...),
	}); err != nil {
		t.Fatalf("granting: %v", err)
	}

	return NewRouter(list, domain.NewRouteTable(0), routerLocal())
}

func offered(prefix string, metric uint32) domain.Route {
	return domain.Route{
		Prefix:    netip.MustParsePrefix(prefix),
		Metric:    metric,
		ExpiresAt: routerAt().Add(10 * time.Minute),
		Version:   1,
	}
}

// An authorized announcement reaches the table and then the kernel.
func TestAnAuthorizedAnnouncementIsRouted(t *testing.T) {
	provider := decisionKey(t, "a subnet router")
	router := newRouter(t, provider, "10.20.30.0/24")

	outcomes := router.Announce(provider, []domain.Route{offered("10.20.30.0/24", 10)}, routerAt())
	if len(outcomes) != 1 || !outcomes[0].Accepted {
		t.Fatalf("outcomes = %+v, want the prefix accepted", outcomes)
	}

	install, remove := router.Reconcile(routerAt())
	if len(install) != 1 || install[0].Prefix.String() != "10.20.30.0/24" {
		t.Errorf("install = %v, want the announced prefix", install)
	}
	if len(remove) != 0 {
		t.Errorf("remove = %v, want none", remove)
	}
	if install[0].Provider != provider {
		t.Error("the installed route does not name the provider that offered it")
	}
}

// A prefix policy does not permit never reaches the table.
//
// Never recorded rather than recorded and skipped: an offer in the table can
// win a selection later, so an unauthorized one that merely lost today would be
// installed the moment its rival withdrew.
func TestAnUnauthorizedPrefixNeverReachesTheTable(t *testing.T) {
	provider := decisionKey(t, "a subnet router")
	router := newRouter(t, provider, "10.20.30.0/24")

	outcomes := router.Announce(provider, []domain.Route{offered("192.168.0.0/16", 1)}, routerAt())
	if outcomes[0].Accepted {
		t.Fatal("a prefix outside the rule was accepted")
	}
	if outcomes[0].Reason != ReasonPrefixNotAllowed {
		t.Errorf("reason = %q, want %q", outcomes[0].Reason, ReasonPrefixNotAllowed)
	}

	install, _ := router.Reconcile(routerAt())
	if len(install) != 0 {
		t.Errorf("install = %v; an unauthorized prefix must not be routable later", install)
	}
	if got := router.Installed(); len(got) != 0 {
		t.Errorf("installed = %v, want none", got)
	}
}

// A peer no rule authorizes routes nothing.
func TestAnUnauthorizedPeerRoutesNothing(t *testing.T) {
	provider := decisionKey(t, "a subnet router")
	stranger := decisionKey(t, "nobody")
	router := newRouter(t, provider, "10.20.30.0/24")

	outcomes := router.Announce(stranger, []domain.Route{offered("10.20.30.0/24", 10)}, routerAt())
	if outcomes[0].Accepted {
		t.Fatal("a peer no rule mentions had its route accepted")
	}
	if outcomes[0].Reason != ReasonNoRule {
		t.Errorf("reason = %q, want %q", outcomes[0].Reason, ReasonNoRule)
	}
}

// A prefix that could not be a destination is refused before policy is asked.
//
// The refusal must not vary with the sender's rules: one that did would say
// something about the sender's authorization, and the answer here is about the
// prefix.
func TestAnUnroutablePrefixIsRefusedBeforePolicy(t *testing.T) {
	provider := decisionKey(t, "a subnet router")

	// Authorized for everything, including the transport it is trying to
	// capture — so only the admission check can refuse this.
	router := newRouter(t, provider, "0.0.0.0/0", "198.51.100.0/24", "127.0.0.0/8")

	for _, prefix := range []string{"198.51.100.0/24", "127.0.0.0/8", "100.96.0.0/24"} {
		outcomes := router.Announce(provider, []domain.Route{offered(prefix, 1)}, routerAt())
		if outcomes[0].Accepted {
			t.Errorf("%s was accepted despite being unroutable", prefix)
		}
		if outcomes[0].Reason != ReasonNotRoutable {
			t.Errorf("%s: reason = %q, want %q", prefix, outcomes[0].Reason, ReasonNotRoutable)
		}
		// The code alone does not say which rule fired, and a martian and a
		// transport capture need different answers from an operator.
		if outcomes[0].Detail == "" {
			t.Errorf("%s: the refusal carries no detail saying why", prefix)
		}
	}
}

// Withdrawal removes the route from what the kernel should hold.
func TestWithdrawalRemovesTheRoute(t *testing.T) {
	provider := decisionKey(t, "a subnet router")
	router := newRouter(t, provider, "10.20.30.0/24")
	prefix := netip.MustParsePrefix("10.20.30.0/24")

	router.Announce(provider, []domain.Route{offered("10.20.30.0/24", 10)}, routerAt())
	router.Reconcile(routerAt())

	router.Withdraw(provider, []netip.Prefix{prefix})
	install, remove := router.Reconcile(routerAt())

	if len(install) != 0 {
		t.Errorf("install = %v, want none", install)
	}
	if len(remove) != 1 || remove[0] != prefix {
		t.Errorf("remove = %v, want the withdrawn prefix", remove)
	}
}

// A withdrawal is honoured even from a peer that lost authorization.
//
// Refusing it would leave the route installed, which is the opposite of what
// losing authorization should mean.
func TestAWithdrawalFromARevokedPeerStillApplies(t *testing.T) {
	provider := decisionKey(t, "a subnet router")
	list := NewAllowlist()
	if err := list.Add(Grant{
		Peer: provider, Actions: []Action{ActionRoute}, AllowedIPs: prefixes("10.20.30.0/24"),
	}); err != nil {
		t.Fatalf("granting: %v", err)
	}
	router := NewRouter(list, domain.NewRouteTable(0), routerLocal())

	prefix := netip.MustParsePrefix("10.20.30.0/24")
	router.Announce(provider, []domain.Route{offered("10.20.30.0/24", 10)}, routerAt())
	router.Reconcile(routerAt())

	if err := list.Revoke(provider); err != nil {
		t.Fatalf("revoking: %v", err)
	}

	router.Withdraw(provider, []netip.Prefix{prefix})
	_, remove := router.Reconcile(routerAt())

	if len(remove) != 1 {
		t.Errorf("remove = %v; a withdrawal must apply even after revocation", remove)
	}
}

// A provider that goes away takes its routes with it.
func TestDisconnectingAProviderRemovesItsRoutes(t *testing.T) {
	provider := decisionKey(t, "a subnet router")
	router := newRouter(t, provider, "10.0.0.0/8")

	router.Announce(provider, []domain.Route{
		offered("10.20.30.0/24", 10),
		offered("10.40.0.0/16", 10),
	}, routerAt())
	router.Reconcile(routerAt())

	router.Disconnect(provider)
	_, remove := router.Reconcile(routerAt())

	if len(remove) != 2 {
		t.Errorf("remove = %v, want both destinations", remove)
	}
	if got := router.Installed(); len(got) != 0 {
		t.Errorf("installed = %v, want none", got)
	}
}

// An expired announcement is removed without anyone saying so.
func TestAnExpiredAnnouncementIsRemoved(t *testing.T) {
	provider := decisionKey(t, "a subnet router")
	router := newRouter(t, provider, "10.20.30.0/24")

	route := offered("10.20.30.0/24", 10)
	router.Announce(provider, []domain.Route{route}, routerAt())
	router.Reconcile(routerAt())

	_, remove := router.Reconcile(route.ExpiresAt.Add(time.Second))
	if len(remove) != 1 {
		t.Errorf("remove = %v, want the expired prefix", remove)
	}
}

// A destination is not reported for removal twice.
//
// Expiry and selection can both name it, and a duplicate would have the caller
// ask the kernel to remove the same route twice.
func TestARemovalIsReportedOnce(t *testing.T) {
	provider := decisionKey(t, "a subnet router")
	router := newRouter(t, provider, "10.20.30.0/24")

	route := offered("10.20.30.0/24", 10)
	router.Announce(provider, []domain.Route{route}, routerAt())
	router.Reconcile(routerAt())

	_, remove := router.Reconcile(route.ExpiresAt.Add(time.Second))

	seen := make(map[netip.Prefix]int)
	for _, prefix := range remove {
		seen[prefix]++
	}
	for prefix, count := range seen {
		if count > 1 {
			t.Errorf("%s reported for removal %d times", prefix, count)
		}
	}
}

// A mixed announcement reports one outcome per prefix, in order.
//
// An operator debugging a partially refused announcement needs to know which
// prefix was refused, not that something was.
func TestEveryPrefixGetsItsOwnOutcome(t *testing.T) {
	provider := decisionKey(t, "a subnet router")
	router := newRouter(t, provider, "10.20.30.0/24")

	outcomes := router.Announce(provider, []domain.Route{
		offered("10.20.30.0/24", 10),  // allowed
		offered("192.168.0.0/16", 10), // outside the rule
		offered("127.0.0.0/8", 10),    // unroutable
	}, routerAt())

	if len(outcomes) != 3 {
		t.Fatalf("outcomes = %d, want one per prefix", len(outcomes))
	}
	if !outcomes[0].Accepted {
		t.Error("the authorized prefix was refused")
	}
	if outcomes[1].Accepted || outcomes[1].Reason != ReasonPrefixNotAllowed {
		t.Errorf("outcome[1] = %+v, want refused for policy", outcomes[1])
	}
	if outcomes[2].Accepted || outcomes[2].Reason != ReasonNotRoutable {
		t.Errorf("outcome[2] = %+v, want refused as unroutable", outcomes[2])
	}
	if outcomes[0].Prefix.String() != "10.20.30.0/24" {
		t.Error("outcomes are not in the order announced")
	}
}

// Moving the local network re-evaluates what may be captured.
//
// A node that roamed has a new transport address, and checking against the old
// one would admit a prefix that captures the live path.
func TestTheLocalNetworkCanBeRefreshed(t *testing.T) {
	provider := decisionKey(t, "a subnet router")
	router := newRouter(t, provider, "0.0.0.0/0", "203.0.113.0/24")

	// Not a transport yet, so only policy decides — and policy allows it.
	outcomes := router.Announce(provider, []domain.Route{offered("203.0.113.0/24", 10)}, routerAt())
	if !outcomes[0].Accepted {
		t.Fatalf("the prefix was refused before it captured anything: %+v", outcomes[0])
	}

	router.LocalNetwork(domain.LocalNetwork{
		Transports: []netip.Addr{netip.MustParseAddr("203.0.113.7")},
	})

	again := router.Announce(provider, []domain.Route{offered("203.0.113.0/24", 5)}, routerAt())
	if again[0].Accepted {
		t.Error("a prefix capturing the new transport was accepted")
	}
	if again[0].Reason != ReasonNotRoutable {
		t.Errorf("reason = %q, want %q", again[0].Reason, ReasonNotRoutable)
	}
}
