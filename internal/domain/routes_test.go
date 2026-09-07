package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"testing"
	"time"
)

func routeKey(t *testing.T, seed string) NostrPublicKey {
	t.Helper()

	digest := sha256.Sum256([]byte(seed))
	key, err := ParseNostrPublicKey(hex.EncodeToString(digest[:]))
	if err != nil {
		t.Fatalf("building key: %v", err)
	}
	return key
}

func routeAt() time.Time {
	return time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
}

func announced(t *testing.T, prefix, provider string, metric uint32) Route {
	t.Helper()

	return Route{
		Prefix:    netip.MustParsePrefix(prefix),
		Provider:  routeKey(t, provider),
		Metric:    metric,
		Source:    SourceAnnounced,
		ExpiresAt: routeAt().Add(10 * time.Minute),
		Version:   1,
	}
}

// One destination gets one route, never two.
//
// Equal offers do not become ECMP. A node that load-balanced across two
// providers would be making a routing decision nobody expressed, on evidence it
// did not gather.
func TestOneRoutePerDestination(t *testing.T) {
	table := NewRouteTable(0)
	table.Offer(announced(t, "10.20.30.0/24", "provider-a", 10))
	table.Offer(announced(t, "10.20.30.0/24", "provider-b", 10))

	install, remove := table.Select(routeAt())

	if len(install) != 1 {
		t.Fatalf("installed %d routes for one destination, want 1", len(install))
	}
	if len(remove) != 0 {
		t.Errorf("removals = %v, want none", remove)
	}
	if got := table.Installed(); len(got) != 1 {
		t.Errorf("installed = %v, want one route", got)
	}
}

// The loser stays visible.
//
// A conflict is not an error and does not stop selection, but an operator must
// be able to see that two providers claim the same destination and which one
// won. Discarding the loser is how a conflict becomes invisible.
func TestAConflictIsVisible(t *testing.T) {
	table := NewRouteTable(0)
	winner := announced(t, "10.20.30.0/24", "provider-a", 5)
	table.Offer(winner)
	table.Offer(announced(t, "10.20.30.0/24", "provider-b", 50))
	table.Select(routeAt())

	conflicts := table.Conflicts(routeAt())
	if len(conflicts) != 1 {
		t.Fatalf("conflicts = %d, want 1", len(conflicts))
	}
	if len(conflicts[0].Offers) != 2 {
		t.Errorf("offers = %d, want both providers", len(conflicts[0].Offers))
	}
	if conflicts[0].Installed != winner.Provider {
		t.Error("the conflict does not say which provider won")
	}
	if conflicts[0].Offers[0].Metric != 5 {
		t.Error("offers are not ordered best first")
	}
}

// A destination with one provider is not a conflict.
func TestOneProviderIsNoConflict(t *testing.T) {
	table := NewRouteTable(0)
	table.Offer(announced(t, "10.20.30.0/24", "provider-a", 10))
	table.Select(routeAt())

	if conflicts := table.Conflicts(routeAt()); len(conflicts) != 0 {
		t.Errorf("conflicts = %v, want none", conflicts)
	}
}

// A local route wins outright.
//
// This host already reaches the destination, and an announcement cannot know
// what replacing it would break.
func TestALocalRouteWins(t *testing.T) {
	table := NewRouteTable(0)

	// The local route carries the worst metric there is, so it can only win by
	// being local. Giving it a good metric let it win on the metric instead,
	// and the test passed with the local precedence deliberately removed.
	local := Route{
		Prefix: netip.MustParsePrefix("10.20.30.0/24"),
		Metric: ^uint32(0),
		Source: SourceLocal,
	}
	table.Offer(local)
	table.Offer(announced(t, "10.20.30.0/24", "provider-a", 0))

	install, _ := table.Select(routeAt())
	if len(install) != 1 {
		t.Fatalf("installed %d, want 1", len(install))
	}
	if install[0].Source != SourceLocal {
		t.Error("an announcement replaced a destination this host already reaches")
	}
}

// The lower metric wins, and ties break the same way on both sides.
func TestSelectionPrefersTheLowerMetric(t *testing.T) {
	table := NewRouteTable(0)
	table.Offer(announced(t, "10.20.30.0/24", "provider-a", 50))
	better := announced(t, "10.20.30.0/24", "provider-b", 5)
	table.Offer(better)

	install, _ := table.Select(routeAt())
	if len(install) != 1 || install[0].Provider != better.Provider {
		t.Errorf("selected %v, want the lower metric", install)
	}
}

// A selection is held for the hysteresis window.
//
// A rival that is better does not take over immediately: a decision that flips
// on noise rewrites kernel state and grows the journal for a route that is
// working.
func TestHysteresisHoldsASelection(t *testing.T) {
	table := NewRouteTable(30 * time.Second)
	now := routeAt()

	table.Offer(announced(t, "10.20.30.0/24", "provider-a", 50))
	install, _ := table.Select(now)
	if len(install) != 1 {
		t.Fatalf("nothing was installed to hold")
	}
	incumbent := install[0].Provider

	// A better rival arrives inside the window.
	table.Offer(announced(t, "10.20.30.0/24", "provider-b", 5))

	install, _ = table.Select(now.Add(10 * time.Second))
	if len(install) != 0 {
		t.Errorf("a rival replaced the selection inside the window: %v", install)
	}
	if got := table.Installed(); got[0].Provider != incumbent {
		t.Error("the incumbent lost its selection inside the window")
	}

	// Past the window the difference is still seen and followed.
	install, _ = table.Select(now.Add(31 * time.Second))
	if len(install) != 1 {
		t.Fatalf("the better route was not taken after the window: %v", install)
	}
	if install[0].Provider == incumbent {
		t.Error("the incumbent kept the selection past the window")
	}
}

// Hysteresis does not hold a destination that has no selection.
//
// The window governs replacement, not first installation: a node that waited
// before installing anything would leave a destination unreachable for no
// reason.
func TestHysteresisDoesNotDelayTheFirstRoute(t *testing.T) {
	table := NewRouteTable(time.Hour)

	table.Offer(announced(t, "10.20.30.0/24", "provider-a", 10))
	install, _ := table.Select(routeAt())

	if len(install) != 1 {
		t.Error("the first route for a destination was delayed by hysteresis")
	}
}

// An old announcement does not resurrect a withdrawn route.
//
// Relays redeliver, and messages arrive out of order. A version no newer than
// the one held is ignored rather than applied.
func TestAnOlderAnnouncementIsIgnored(t *testing.T) {
	table := NewRouteTable(0)

	current := announced(t, "10.20.30.0/24", "provider-a", 10)
	current.Version = 5
	table.Offer(current)

	stale := announced(t, "10.20.30.0/24", "provider-a", 99)
	stale.Version = 3
	if table.Offer(stale) {
		t.Error("an older announcement was accepted")
	}

	install, _ := table.Select(routeAt())
	if len(install) != 1 || install[0].Metric != 10 {
		t.Errorf("the stale announcement took effect: %v", install)
	}
}

// A repeated announcement at the same version changes nothing.
func TestADuplicateAnnouncementIsIgnored(t *testing.T) {
	table := NewRouteTable(0)
	route := announced(t, "10.20.30.0/24", "provider-a", 10)

	if !table.Offer(route) {
		t.Fatal("the first announcement was refused")
	}
	if table.Offer(route) {
		t.Error("a duplicate announcement was accepted")
	}
}

// Withdrawing the installed route removes it from the kernel's view.
func TestWithdrawingTheSelectedRouteRemovesIt(t *testing.T) {
	table := NewRouteTable(0)
	route := announced(t, "10.20.30.0/24", "provider-a", 10)
	table.Offer(route)
	table.Select(routeAt())

	table.Withdraw(route.Prefix, route.Provider)

	_, remove := table.Select(routeAt())
	if len(remove) != 1 || remove[0] != route.Prefix {
		t.Errorf("removals = %v, want the withdrawn prefix", remove)
	}
	if got := table.Installed(); len(got) != 0 {
		t.Errorf("installed = %v, want none", got)
	}
}

// Withdrawing the loser leaves the winner installed.
func TestWithdrawingALoserKeepsTheWinner(t *testing.T) {
	table := NewRouteTable(0)
	winner := announced(t, "10.20.30.0/24", "provider-a", 5)
	loser := announced(t, "10.20.30.0/24", "provider-b", 50)
	table.Offer(winner)
	table.Offer(loser)
	table.Select(routeAt())

	table.Withdraw(loser.Prefix, loser.Provider)
	_, remove := table.Select(routeAt())

	if len(remove) != 0 {
		t.Errorf("removals = %v; withdrawing a losing offer must not remove the route", remove)
	}
	if got := table.Installed(); len(got) != 1 || got[0].Provider != winner.Provider {
		t.Errorf("installed = %v, want the winner", got)
	}
}

// Withdrawing the winner promotes the runner-up rather than leaving nothing.
func TestWithdrawingTheWinnerPromotesTheRunnerUp(t *testing.T) {
	table := NewRouteTable(0)
	winner := announced(t, "10.20.30.0/24", "provider-a", 5)
	runnerUp := announced(t, "10.20.30.0/24", "provider-b", 50)
	table.Offer(winner)
	table.Offer(runnerUp)
	table.Select(routeAt())

	table.Withdraw(winner.Prefix, winner.Provider)
	install, remove := table.Select(routeAt())

	if len(remove) != 0 {
		t.Errorf("removals = %v; another provider still offers the destination", remove)
	}
	if len(install) != 1 || install[0].Provider != runnerUp.Provider {
		t.Errorf("installed %v, want the runner-up promoted", install)
	}
}

// A provider going away takes its reachability with it.
func TestAProviderLeavingRemovesItsRoutes(t *testing.T) {
	table := NewRouteTable(0)
	provider := routeKey(t, "provider-a")

	for _, prefix := range []string{"10.20.30.0/24", "10.40.0.0/16", "192.168.5.0/24"} {
		table.Offer(announced(t, prefix, "provider-a", 10))
	}
	table.Select(routeAt())

	table.WithdrawProvider(provider)
	_, remove := table.Select(routeAt())

	if len(remove) != 3 {
		t.Errorf("removals = %v, want all three destinations", remove)
	}
	if got := table.Installed(); len(got) != 0 {
		t.Errorf("installed = %v, want none after the provider left", got)
	}
}

// An expired offer is dropped without anyone saying so.
//
// Reachability that depends on a provider must not outlive the provider's
// ability to say so, so a node that stops hearing drops the route on its own.
func TestAnExpiredOfferIsDropped(t *testing.T) {
	table := NewRouteTable(0)
	route := announced(t, "10.20.30.0/24", "provider-a", 10)
	table.Offer(route)
	table.Select(routeAt())

	dropped := table.Expire(route.ExpiresAt.Add(time.Second))
	if len(dropped) != 1 || dropped[0] != route.Prefix {
		t.Errorf("dropped = %v, want the expired prefix", dropped)
	}
	if got := table.Installed(); len(got) != 0 {
		t.Errorf("installed = %v, want none after expiry", got)
	}
}

// Expiry of a losing offer does not disturb the installed route.
func TestExpiringALoserKeepsTheWinner(t *testing.T) {
	table := NewRouteTable(0)

	winner := announced(t, "10.20.30.0/24", "provider-a", 5)
	winner.ExpiresAt = routeAt().Add(time.Hour)
	loser := announced(t, "10.20.30.0/24", "provider-b", 50)
	loser.ExpiresAt = routeAt().Add(time.Minute)

	table.Offer(winner)
	table.Offer(loser)
	table.Select(routeAt())

	dropped := table.Expire(routeAt().Add(2 * time.Minute))
	if len(dropped) != 0 {
		t.Errorf("dropped = %v; the installed route had not expired", dropped)
	}
	if got := table.Installed(); len(got) != 1 || got[0].Provider != winner.Provider {
		t.Errorf("installed = %v, want the winner still there", got)
	}
}

// Selection is stable: evaluating twice changes nothing the second time.
//
// The caller applies what Select returns, so a table that reported the same
// route as new on every evaluation would rewrite kernel state forever.
func TestSelectingTwiceChangesNothing(t *testing.T) {
	table := NewRouteTable(0)
	table.Offer(announced(t, "10.20.30.0/24", "provider-a", 10))
	table.Offer(announced(t, "10.40.0.0/16", "provider-b", 10))

	if install, _ := table.Select(routeAt()); len(install) != 2 {
		t.Fatalf("first evaluation installed %d, want 2", len(install))
	}

	install, remove := table.Select(routeAt().Add(time.Second))
	if len(install) != 0 || len(remove) != 0 {
		t.Errorf("a second evaluation reported install=%v remove=%v, want nothing", install, remove)
	}
}

// A metric change from the installed provider does not reinstall the route.
//
// It is the same kernel entry: the destination and the interface have not
// moved, so reapplying would rewrite state for no effect.
func TestTheSameProviderImprovingDoesNotReinstall(t *testing.T) {
	table := NewRouteTable(0)
	table.Offer(announced(t, "10.20.30.0/24", "provider-a", 50))
	table.Select(routeAt())

	better := announced(t, "10.20.30.0/24", "provider-a", 5)
	better.Version = 2
	table.Offer(better)

	install, remove := table.Select(routeAt().Add(time.Second))
	if len(install) != 0 || len(remove) != 0 {
		t.Errorf("install=%v remove=%v; the same provider improving is the same route", install, remove)
	}
}

// Output is ordered, so two runs over one table produce the same result.
func TestSelectionOutputIsOrdered(t *testing.T) {
	first := NewRouteTable(0)
	second := NewRouteTable(0)

	prefixes := []string{"192.168.5.0/24", "10.20.30.0/24", "172.16.0.0/12", "10.40.0.0/16"}
	for _, prefix := range prefixes {
		first.Offer(announced(t, prefix, "provider-a", 10))
	}
	for i := len(prefixes) - 1; i >= 0; i-- {
		second.Offer(announced(t, prefixes[i], "provider-a", 10))
	}

	a, _ := first.Select(routeAt())
	b, _ := second.Select(routeAt())

	if len(a) != len(b) {
		t.Fatalf("lengths differ: %d and %d", len(a), len(b))
	}
	for i := range a {
		if a[i].Prefix != b[i].Prefix {
			t.Fatalf("order differs at %d: %v and %v; insertion order must not decide", i, a[i].Prefix, b[i].Prefix)
		}
	}
}
