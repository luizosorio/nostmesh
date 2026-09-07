package domain

import (
	"cmp"
	"net/netip"
	"slices"
	"time"
)

// The routing information base: every route this node has been offered, and
// which one it chose for each destination.
//
// The RIB is what a node was told. The FIB — the kernel's table — is what it
// decided, and it holds at most one route per prefix. Keeping the two apart is
// what makes a conflict visible: a rejected route is recorded rather than
// discarded, so an operator can see that two providers claim the same
// destination and which one lost.
//
// Everything here is computation over prefixes and times. Nothing touches the
// kernel, which is what keeps selection testable without root. See NM-25.

// RouteSource says where a route came from.
type RouteSource string

const (
	// SourceAnnounced is a route a peer offered.
	SourceAnnounced RouteSource = "announced"

	// SourceLocal is a destination this host already reaches without the mesh.
	//
	// Never installed by NostMesh and never replaced by an announcement: the
	// announcement cannot know what it would be breaking.
	SourceLocal RouteSource = "local"
)

// Route is one offer for one destination.
type Route struct {
	// Prefix is the destination.
	Prefix netip.Prefix

	// Provider is the peer offering it. Empty for a local route.
	Provider NostrPublicKey

	// Metric is what the provider claims about its own path.
	//
	// An input to selection, never the decision on its own. Two providers
	// claiming the same cost are two claims, not a measurement.
	Metric uint32

	// Source says whether this was announced or is already reachable locally.
	Source RouteSource

	// ExpiresAt is when the offer lapses. Zero means it does not.
	ExpiresAt time.Time

	// Version orders offers from one provider.
	Version uint64
}

// IsExpired reports whether the offer has lapsed.
func (r Route) IsExpired(now time.Time) bool {
	return !r.ExpiresAt.IsZero() && !now.Before(r.ExpiresAt)
}

// RouteTable holds every offer and the selection over them.
//
// Not safe for concurrent use; the caller owns synchronization, as with the
// other domain types.
type RouteTable struct {
	// offers holds every live offer, keyed by destination and then provider.
	//
	// Two levels because a conflict is two providers for one prefix, and that
	// has to be representable rather than resolved on arrival — resolving on
	// arrival is how the loser becomes invisible.
	offers map[netip.Prefix]map[NostrPublicKey]Route

	// selected is the winner per destination, and when it was chosen.
	selected map[netip.Prefix]selection

	// hysteresis is how long a selection is held before a rival can take it.
	hysteresis time.Duration
}

// selection is an installed route and when it won.
type selection struct {
	route      Route
	selectedAt time.Time
}

// NewRouteTable returns an empty table.
//
// The hysteresis window governs replacement: a rival has to be better and the
// current selection has to have stood for at least this long. Zero means a
// better route replaces immediately, which is right for tests and wrong for a
// network, where offers arrive in bursts.
func NewRouteTable(hysteresis time.Duration) *RouteTable {
	return &RouteTable{
		offers:     make(map[netip.Prefix]map[NostrPublicKey]Route),
		selected:   make(map[netip.Prefix]selection),
		hysteresis: hysteresis,
	}
}

// Offer records a route, replacing any earlier offer from the same provider.
//
// An offer with a version no newer than the one held is ignored: a relay
// redelivering an old announcement must not resurrect a withdrawn route, and
// out-of-order arrival is normal rather than exceptional.
//
// Recording is not installing. Selection decides what reaches the kernel.
func (t *RouteTable) Offer(route Route) bool {
	if t.offers[route.Prefix] == nil {
		t.offers[route.Prefix] = make(map[NostrPublicKey]Route)
	}

	if held, known := t.offers[route.Prefix][route.Provider]; known {
		if route.Version <= held.Version {
			return false
		}
	}

	t.offers[route.Prefix][route.Provider] = route
	return true
}

// Withdraw removes one provider's offer for a destination.
//
// Withdrawing something never offered is not an error: the two sides may
// disagree about what is held, and the wanted state is the same either way.
func (t *RouteTable) Withdraw(prefix netip.Prefix, provider NostrPublicKey) {
	delete(t.offers[prefix], provider)
	if len(t.offers[prefix]) == 0 {
		delete(t.offers, prefix)
	}

	// The selection is deliberately left in place. It names a route that is in
	// the kernel, and Select is what reports the difference between what is
	// installed and what should be — so dropping the record here would make the
	// route invisible to the very call that has to remove it.
	//
	// Select reconciles: if this provider still has no offer, the destination
	// either promotes another provider or is reported for removal.
}

// WithdrawProvider removes every offer from one provider.
//
// A peer that goes away takes its reachability with it. Reachability that
// depends on a provider must not outlive the provider's ability to say so.
func (t *RouteTable) WithdrawProvider(provider NostrPublicKey) {
	// Collected first, for the reason given in Expire: Withdraw deletes the
	// destination's entry once its last offer is gone.
	prefixes := make([]netip.Prefix, 0, len(t.offers))
	for prefix := range t.offers {
		prefixes = append(prefixes, prefix)
	}

	for _, prefix := range prefixes {
		t.Withdraw(prefix, provider)
	}
}

// Expire drops offers whose validity has passed.
//
// Returns the destinations that lost their installed route, so the caller knows
// what to take out of the kernel.
func (t *RouteTable) Expire(now time.Time) []netip.Prefix {
	// Collected before removing anything: Withdraw deletes from the maps this
	// would otherwise be ranging over, and a loop that mutates its own
	// collection is how an entry gets skipped.
	type lapsed struct {
		prefix   netip.Prefix
		provider NostrPublicKey
	}

	var gone []lapsed
	for prefix, providers := range t.offers {
		for provider, route := range providers {
			if route.IsExpired(now) {
				gone = append(gone, lapsed{prefix, provider})
			}
		}
	}

	for _, entry := range gone {
		t.Withdraw(entry.prefix, entry.provider)
	}

	// What is reported is what no longer has any live offer at all. A
	// destination whose losing offer lapsed still has a provider, so nothing
	// about the kernel changes; Select promotes a runner-up where there is one.
	var dropped []netip.Prefix
	for prefix := range t.selected {
		if len(t.offers[prefix]) == 0 {
			dropped = append(dropped, prefix)
		}
	}

	slices.SortFunc(dropped, comparePrefixes)
	return dropped
}

// Select resolves every destination to at most one route.
//
// Returns what changed: routes to install and prefixes to remove. Returning the
// difference rather than the whole table is what keeps the kernel from being
// rewritten on every evaluation — the caller applies exactly what moved.
//
// One route per destination, never two. Equal offers do not become ECMP: a node
// that silently load-balanced across two providers would be making a routing
// decision nobody expressed, on evidence it did not gather.
func (t *RouteTable) Select(now time.Time) (install []Route, remove []netip.Prefix) {
	for prefix, providers := range t.offers {
		best, found := t.bestFor(providers, now)
		current, chosen := t.selected[prefix]

		switch {
		case !found:
			// Every offer for this destination has expired.
			if chosen {
				delete(t.selected, prefix)
				remove = append(remove, prefix)
			}

		case !chosen:
			t.selected[prefix] = selection{route: best, selectedAt: now}
			install = append(install, best)

		case current.route.Provider == best.Provider:
			// The same provider still wins. Its metric may have moved, but the
			// kernel entry is the same one, so nothing is reapplied.
			t.selected[prefix] = selection{route: best, selectedAt: current.selectedAt}

		case !t.offered(prefix, current.route.Provider):
			// The installed provider withdrew or expired. Another still offers
			// the destination, so this is a replacement rather than a removal —
			// and hysteresis does not apply, because holding a route whose
			// provider is gone would keep a black hole in the kernel.
			t.selected[prefix] = selection{route: best, selectedAt: now}
			install = append(install, best)

		case t.holds(current, now):
			// A rival is better but the current selection is too young. Left
			// deliberately: a decision that flips on noise is worse than a
			// slightly stale one, and the next evaluation past the window still
			// sees the difference.

		default:
			t.selected[prefix] = selection{route: best, selectedAt: now}
			install = append(install, best)
		}
	}

	// Destinations that lost every offer between evaluations.
	for prefix := range t.selected {
		if _, offered := t.offers[prefix]; !offered {
			delete(t.selected, prefix)
			remove = append(remove, prefix)
		}
	}

	slices.SortFunc(install, func(a, b Route) int { return comparePrefixes(a.Prefix, b.Prefix) })
	slices.SortFunc(remove, comparePrefixes)
	return install, remove
}

// offered reports whether a provider still has a live offer for a destination.
func (t *RouteTable) offered(prefix netip.Prefix, provider NostrPublicKey) bool {
	_, present := t.offers[prefix][provider]
	return present
}

// holds reports whether a selection is still inside its hysteresis window.
func (t *RouteTable) holds(current selection, now time.Time) bool {
	return now.Sub(current.selectedAt) < t.hysteresis
}

// bestFor picks the winner among one destination's offers.
//
// A local route wins outright: this host already reaches the destination, and an
// announcement cannot know what replacing it would break. Otherwise the lowest
// metric wins, and the provider's key breaks a tie — arbitrary, but identical on
// both sides and stable across restarts, which "whichever arrived first" is not.
func (t *RouteTable) bestFor(providers map[NostrPublicKey]Route, now time.Time) (Route, bool) {
	var best Route
	var found bool

	for _, route := range providers {
		if route.IsExpired(now) {
			continue
		}
		if route.Source == SourceLocal {
			return route, true
		}
		if !found || betterThan(route, best) {
			best, found = route, true
		}
	}

	return best, found
}

// betterThan orders two offers for one destination.
func betterThan(candidate, incumbent Route) bool {
	if candidate.Metric != incumbent.Metric {
		return candidate.Metric < incumbent.Metric
	}
	return candidate.Provider.String() < incumbent.Provider.String()
}

// Conflicts reports destinations offered by more than one provider.
//
// A conflict is not an error and does not stop selection; it is something an
// operator should be able to see. Reported rather than logged once, because the
// question "who else claims this prefix" is asked after the fact.
func (t *RouteTable) Conflicts(now time.Time) []RouteConflict {
	var conflicts []RouteConflict

	for prefix, providers := range t.offers {
		live := make([]Route, 0, len(providers))
		for _, route := range providers {
			if !route.IsExpired(now) {
				live = append(live, route)
			}
		}
		if len(live) < 2 {
			continue
		}

		slices.SortFunc(live, func(a, b Route) int {
			if c := cmp.Compare(a.Metric, b.Metric); c != 0 {
				return c
			}
			return cmp.Compare(a.Provider.String(), b.Provider.String())
		})

		conflict := RouteConflict{Prefix: prefix, Offers: live}
		if current, chosen := t.selected[prefix]; chosen {
			conflict.Installed = current.route.Provider
		}
		conflicts = append(conflicts, conflict)
	}

	slices.SortFunc(conflicts, func(a, b RouteConflict) int { return comparePrefixes(a.Prefix, b.Prefix) })
	return conflicts
}

// RouteConflict is one destination claimed by several providers.
type RouteConflict struct {
	// Prefix is the contested destination.
	Prefix netip.Prefix

	// Offers are the live offers, best first.
	Offers []Route

	// Installed names the provider that won, if any.
	Installed NostrPublicKey
}

// Installed reports what the table says the kernel should hold.
//
// A selection whose offers have all gone is not reported. The record is kept
// until Select reconciles — that is what lets Select tell a caller to remove the
// route — but describing it as installed would have this method contradict
// Expire, which just said the destination was dropped.
func (t *RouteTable) Installed() []Route {
	routes := make([]Route, 0, len(t.selected))
	for prefix, current := range t.selected {
		if len(t.offers[prefix]) == 0 {
			continue
		}
		routes = append(routes, current.route)
	}

	slices.SortFunc(routes, func(a, b Route) int { return comparePrefixes(a.Prefix, b.Prefix) })
	return routes
}

// comparePrefixes orders prefixes so output is stable between runs.
func comparePrefixes(a, b netip.Prefix) int {
	return cmp.Compare(a.String(), b.String())
}
