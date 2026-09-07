package policy

import (
	"net/netip"
	"time"

	"github.com/luizosorio/nostmesh/internal/domain"
)

// The pipeline an announced route travels, from message to decision.
//
//	event → validation → policy → conflict detection → selection → plan → kernel
//
// Validation is the protocol's (shape) and the domain's (could this be a
// destination at all). This is the middle: policy, then the RIB. What comes out
// is what the kernel should hold — the caller plans and applies it.
//
// Nothing here touches the kernel, so every refusal and every selection is
// testable without root. See NM-25.

// RouteOutcome says what happened to one announced prefix.
type RouteOutcome struct {
	// Prefix is the destination announced.
	Prefix netip.Prefix

	// Accepted reports whether it reached the routing table.
	Accepted bool

	// Reason is a code from the closed vocabulary, for a refusal.
	Reason string

	// Rule names the policy rule that answered, when one did.
	Rule string

	// Detail explains a refusal the reason code alone does not distinguish.
	//
	// Locally produced, never peer text: the prefix is the only thing here that
	// came from the announcement, and it has been parsed and canonicalized.
	Detail string
}

// ReasonNotRoutable reports a prefix refused before policy was asked.
//
// Distinct from a policy refusal: the prefix could not be a destination
// whatever any rule said, so an operator widening a rule would be chasing the
// wrong thing.
const ReasonNotRoutable = "not_routable"

// Router admits announcements and maintains the routing table.
//
// Not safe for concurrent use; the caller owns synchronization, as it does for
// the allowlist it holds.
type Router struct {
	allowlist *Allowlist
	table     *domain.RouteTable
	local     domain.LocalNetwork
}

// NewRouter returns a router over an allowlist and a routing table.
func NewRouter(allowlist *Allowlist, table *domain.RouteTable, local domain.LocalNetwork) *Router {
	return &Router{allowlist: allowlist, table: table, local: local}
}

// LocalNetwork replaces what this node must not let an announcement capture.
//
// Refreshed as endpoints move: a node that roamed has a new transport address,
// and a check against the old one would admit a prefix that now captures the
// live path.
func (r *Router) LocalNetwork(local domain.LocalNetwork) {
	r.local = local
}

// Announce records what a peer offers, refusing what it may not.
//
// Order is deliberate and matters twice. Admission runs before policy so a
// prefix nothing could route is refused the same way whoever sent it — a
// refusal that varied with the sender's rules would say something about them.
// Policy runs before the table so an unauthorized offer is never recorded, and
// therefore never wins a selection.
//
// Returns one outcome per prefix, in the order announced, so a caller can
// report exactly which of them were refused and why.
func (r *Router) Announce(
	provider domain.NostrPublicKey,
	routes []domain.Route,
	now time.Time,
) []RouteOutcome {
	outcomes := make([]RouteOutcome, 0, len(routes))

	for _, route := range routes {
		if err := domain.AdmitRoute(route.Prefix, r.local); err != nil {
			// The refusal carries what it refused as well as the code. A
			// martian and a prefix capturing this node's own transport are both
			// not_routable and mean different things, and neither is something
			// an operator fixes by changing a rule — so the detail has to say
			// which, or the code sends them looking in the wrong place.
			outcomes = append(outcomes, RouteOutcome{
				Prefix: route.Prefix,
				Reason: ReasonNotRoutable,
				Detail: err.Error(),
			})
			continue
		}

		decision := r.allowlist.DecideRoute(provider, route.Prefix)
		if !decision.Allowed() {
			outcomes = append(outcomes, RouteOutcome{
				Prefix: route.Prefix,
				Reason: decision.Reason,
				Rule:   decision.Rule,
			})
			continue
		}

		route.Provider = provider
		route.Source = domain.SourceAnnounced
		accepted := r.table.Offer(route)

		outcomes = append(outcomes, RouteOutcome{
			Prefix:   route.Prefix,
			Accepted: accepted,
			Reason:   decision.Reason,
			Rule:     decision.Rule,
		})
	}

	return outcomes
}

// Withdraw retracts prefixes a provider announced.
//
// Not checked against policy: a peer withdrawing something is always allowed to
// reduce what this node routes through it. Refusing a withdrawal because the
// peer lost authorization would leave the route installed, which is the
// opposite of what losing authorization should mean.
func (r *Router) Withdraw(provider domain.NostrPublicKey, prefixes []netip.Prefix) {
	for _, prefix := range prefixes {
		r.table.Withdraw(prefix, provider)
	}
}

// Disconnect drops everything a provider offered.
//
// A peer that goes away takes its reachability with it: what it announced was
// only ever a claim about a path this node can no longer use.
func (r *Router) Disconnect(provider domain.NostrPublicKey) {
	r.table.WithdrawProvider(provider)
}

// Reconcile expires stale offers and resolves what the kernel should hold.
//
// Returns the difference — routes to install, prefixes to remove — so a caller
// applies exactly what moved rather than rewriting the table on every tick.
func (r *Router) Reconcile(now time.Time) (install []domain.Route, remove []netip.Prefix) {
	expired := r.table.Expire(now)
	install, remove = r.table.Select(now)

	// An expired destination that Select did not already report. Both can name
	// it — expiry drops the offer, selection notices the loss — and installing
	// a duplicate removal would have the caller ask the kernel twice.
	for _, prefix := range expired {
		if !containsExactly(remove, prefix) {
			remove = append(remove, prefix)
		}
	}

	return install, remove
}

// containsExactly reports whether a prefix is already listed.
func containsExactly(prefixes []netip.Prefix, wanted netip.Prefix) bool {
	for _, prefix := range prefixes {
		if prefix == wanted {
			return true
		}
	}
	return false
}

// Conflicts reports destinations several providers claim.
func (r *Router) Conflicts(now time.Time) []domain.RouteConflict {
	return r.table.Conflicts(now)
}

// Installed reports what the router says the kernel should hold.
func (r *Router) Installed() []domain.Route {
	return r.table.Installed()
}
