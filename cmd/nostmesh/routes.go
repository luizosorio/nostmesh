package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/luizosorio/nostmesh/internal/domain"
	"github.com/luizosorio/nostmesh/internal/netstate"
	"github.com/luizosorio/nostmesh/internal/observability"
	"github.com/luizosorio/nostmesh/internal/policy"
	"github.com/luizosorio/nostmesh/internal/protocol"
)

// routeHandler joins the decision path to the kernel.
//
// The router decides (policy, conflict, selection) and the netstate manager
// applies (journal, netlink). This owns neither: it translates a peer's message
// into the router's vocabulary, and the router's answer into a transaction.
//
// One per node, shared by every session, because a route is a property of this
// host rather than of one tunnel: two peers can offer the same destination, and
// only a shared table can tell that they did. See NM-25.
type routeHandler struct {
	log      *slog.Logger
	netstate *netstate.Manager
	clock    func() time.Time

	// mu guards the router, which is not safe for concurrent use and is reached
	// from every session's hold loop.
	mu     sync.Mutex
	router *policy.Router
}

// newRouteHandler builds the handler over a router and a netstate manager.
func newRouteHandler(
	router *policy.Router,
	manager *netstate.Manager,
	clock func() time.Time,
	log *slog.Logger,
) *routeHandler {
	return &routeHandler{log: log, netstate: manager, clock: clock, router: router}
}

// Announce records what a peer offered and reports what was decided.
//
// Every prefix gets a line, refusals included. An operator asking why a
// destination is not reachable needs to see that the announcement arrived and
// was refused, which is a different problem from it never arriving.
func (h *routeHandler) Announce(
	_ context.Context,
	peer domain.NostrPublicKey,
	announce protocol.RouteAnnounce,
) error {
	routes, err := announcedRoutes(announce)
	if err != nil {
		return err
	}

	h.mu.Lock()
	outcomes := h.router.Announce(peer, routes, h.clock())
	h.mu.Unlock()

	for _, outcome := range outcomes {
		if outcome.Accepted {
			h.log.Info("route offered",
				observability.Event("route.offered"),
				observability.Peer(peer),
				slog.String("prefix", outcome.Prefix.String()),
				slog.String("rule", outcome.Rule),
				observability.Result(observability.ResultOK))
			continue
		}

		h.log.Info("route refused",
			observability.Event("route.refused"),
			observability.Peer(peer),
			slog.String("prefix", outcome.Prefix.String()),
			observability.Reason(observability.ReasonPolicyRefused),
			slog.String("policy_reason", outcome.Reason),
			slog.String("detail", outcome.Detail),
			slog.String("rule", outcome.Rule))
	}

	return nil
}

// Withdraw retracts prefixes a peer announced.
func (h *routeHandler) Withdraw(
	_ context.Context,
	peer domain.NostrPublicKey,
	withdraw protocol.RouteWithdraw,
) error {
	prefixes := make([]netip.Prefix, 0, len(withdraw.Prefixes))
	for _, raw := range withdraw.Prefixes {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			// The protocol already validated this, so reaching here means a
			// caller bypassed validation rather than a peer sending nonsense.
			return fmt.Errorf("withdrawn prefix %q: %w", raw, err)
		}
		prefixes = append(prefixes, prefix)
	}

	h.mu.Lock()
	h.router.Withdraw(peer, prefixes)
	h.mu.Unlock()

	h.log.Info("routes withdrawn by peer",
		observability.Event("route.withdrawn.by_peer"),
		observability.Peer(peer),
		slog.Int("prefixes", len(prefixes)))

	// The kernel is not touched here. This runs from the hold loop, which calls
	// Reconcile immediately afterwards with the interface name — and applying
	// without one silently skipped every removal, leaving the route installed
	// after the peer withdrew it.
	return nil
}

// Reconcile expires stale offers and applies what changed.
func (h *routeHandler) Reconcile(ctx context.Context, peer domain.NostrPublicKey, iface string) error {
	return h.apply(ctx, peer, iface)
}

// Release drops everything a peer offered.
//
// Its reachability was only ever a claim about a path that is now gone. The
// routes are not removed from the kernel here: the interface is about to go and
// takes them with it, and asking netlink to remove a route on a link being
// deleted is a race with nothing to gain.
func (h *routeHandler) Release(_ context.Context, peer domain.NostrPublicKey, _ string) error {
	h.mu.Lock()
	h.router.Disconnect(peer)
	h.mu.Unlock()

	h.log.Info("peer routes released",
		observability.Event("route.released"),
		observability.Peer(peer))
	return nil
}

// apply installs and removes what the router decided.
//
// Installation is journaled as a transaction so a partial failure rolls back;
// removal is not, because a removal that fails leaves the route present, which
// is the state that was already true.
func (h *routeHandler) apply(ctx context.Context, peer domain.NostrPublicKey, iface string) error {
	h.mu.Lock()
	install, remove := h.router.Reconcile(h.clock())
	h.mu.Unlock()

	if len(install) == 0 && len(remove) == 0 {
		return nil
	}

	if iface == "" {
		return fmt.Errorf("applying %d installs and %d removals without an interface",
			len(install), len(remove))
	}

	// Removal first. A destination moving from one provider to another appears
	// as both, and installing before removing would have two routes to one
	// prefix in the kernel between the two calls.
	for _, prefix := range remove {
		if err := h.netstate.RemoveRoute(ctx, iface, prefix); err != nil {
			h.log.Warn("a route was not removed",
				observability.Event("route.remove.failed"),
				observability.Peer(peer),
				slog.String("prefix", prefix.String()),
				observability.Result(observability.ResultFailed),
				slog.String("error", err.Error()))
		}
	}

	if len(install) == 0 {
		return nil
	}

	prefixes := make([]netip.Prefix, 0, len(install))
	for _, route := range install {
		prefixes = append(prefixes, route.Prefix)
	}

	transactionID := fmt.Sprintf("routes-%s-%d", iface, h.clock().UnixNano())
	plan, err := h.netstate.PlanRoutes(ctx, transactionID, iface, prefixes)
	if err != nil {
		return fmt.Errorf("planning routes on %s: %w", iface, err)
	}
	if _, err := h.netstate.Apply(ctx, plan); err != nil {
		return fmt.Errorf("installing routes on %s: %w", iface, err)
	}

	return nil
}

// announcedRoutes converts a message into the router's vocabulary.
//
// The prefixes were validated by the protocol, so a parse failure here means a
// caller skipped validation rather than a peer sending nonsense — worth an
// error rather than a silent skip, which would route less than was decided.
func announcedRoutes(announce protocol.RouteAnnounce) ([]domain.Route, error) {
	validUntil := time.Unix(announce.ValidUntil, 0).UTC()

	routes := make([]domain.Route, 0, len(announce.Routes))
	for _, announced := range announce.Routes {
		prefix, err := netip.ParsePrefix(announced.Prefix)
		if err != nil {
			return nil, fmt.Errorf("announced prefix %q: %w", announced.Prefix, err)
		}

		routes = append(routes, domain.Route{
			Prefix:    prefix,
			Metric:    announced.Metric,
			ExpiresAt: validUntil,
			Version:   announce.Version,
		})
	}

	return routes, nil
}
