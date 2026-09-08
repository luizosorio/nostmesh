package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/luizosorio/nostmesh/internal/config"
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

	// advertise is what this node offers to reach. Empty means it offers
	// nothing, which is the default.
	advertise []netip.Prefix

	// metric is this node's claim about its own cost to those prefixes.
	metric uint32

	// networkID names the network the advertised prefixes belong to.
	networkID string

	// validity is how long an announcement stands before a peer drops it.
	//
	// Short deliberately: reachability that depends on this node must not
	// outlive its ability to say so, and the hold loop refreshes well inside
	// the window.
	validity time.Duration

	// mu guards the router, which is not safe for concurrent use and is reached
	// from every session's hold loop.
	mu     sync.Mutex
	router *policy.Router
}

// defaultAnnouncementValidity bounds how long a peer keeps a route after this
// node stops refreshing it.
const defaultAnnouncementValidity = 5 * time.Minute

// newRouteHandler builds the handler over a router and a netstate manager.
func newRouteHandler(
	router *policy.Router,
	manager *netstate.Manager,
	clock func() time.Time,
	log *slog.Logger,
) *routeHandler {
	return &routeHandler{
		log:      log,
		netstate: manager,
		clock:    clock,
		router:   router,
		validity: defaultAnnouncementValidity,
	}
}

// Advertising sets what this node offers to reach.
//
// Separate from construction because a node that routes nothing is the common
// case, and a constructor taking parameters nobody fills in invites them being
// filled in wrongly.
func (h *routeHandler) Advertising(prefixes []netip.Prefix, metric uint32, networkID string) {
	h.advertise = prefixes
	h.metric = metric
	h.networkID = networkID
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

	// Each prefix by name, not a count. "prefixes: 2" tells an operator asking
	// why a destination went away that something was withdrawn, which is the
	// half of the answer they already had.
	for _, prefix := range prefixes {
		h.log.Info("route withdrawn by peer",
			observability.Event("route.withdrawn.by_peer"),
			observability.Peer(peer),
			slog.String("prefix", prefix.String()))
	}

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

// Advertise returns what this node offers to reach.
//
// Built fresh each time rather than stored, because the validity has to be
// relative to now: a cached announcement would carry a window that started
// shrinking the moment it was made.
//
// nil when nothing is configured, which is the default. A node announces
// nothing unless its operator said it can reach something.
func (h *routeHandler) Advertise() *protocol.RouteAnnounce {
	if len(h.advertise) == 0 {
		return nil
	}

	routes := make([]protocol.AnnouncedRoute, 0, len(h.advertise))
	for _, prefix := range h.advertise {
		routes = append(routes, protocol.AnnouncedRoute{
			Prefix: prefix.String(),
			Metric: h.metric,
		})
	}

	// Version from the clock rather than a counter: it must increase across a
	// restart, and a counter starting at zero would be refused as stale by
	// every peer that still held the previous announcement.
	now := h.clock()

	return &protocol.RouteAnnounce{
		Routes:     routes,
		NetworkID:  h.networkID,
		Version:    uint64(now.UnixNano()),
		ValidUntil: now.Add(h.validity).Unix(),
	}
}

// buildRouteHandler assembles the node's routing from configuration.
//
// The local network it protects is filled in as sessions come and go, not here:
// at startup this node has no transport addresses yet, and checking against an
// empty list would admit a prefix that captures a path established a moment
// later. See LocalNetwork.
func buildRouteHandler(
	cfg config.Config,
	manager *netstate.Manager,
	clock domain.Clock,
	log *slog.Logger,
) (*routeHandler, error) {
	allowlist, err := loadAllowlist(cfg)
	if err != nil {
		return nil, err
	}

	advertise := make([]netip.Prefix, 0, len(cfg.Routes.Advertise))
	for _, raw := range cfg.Routes.Advertise {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("routes.advertise %q: %w", raw, err)
		}
		advertise = append(advertise, prefix)
	}

	router := policy.NewRouter(allowlist, domain.NewRouteTable(routeHysteresis), domain.LocalNetwork{})
	handler := newRouteHandler(router, manager, clock.Now, log)
	handler.Advertising(advertise, cfg.Routes.Metric, cfg.Network.Manifest)

	return handler, nil
}

// routeHysteresis is how long a selection stands before a rival can take it.
//
// Long enough that a burst of announcements does not rewrite the kernel
// repeatedly, short enough that a genuinely better path is taken within a
// minute. Mirrors the roaming interval's reasoning rather than its value: a
// route change is cheaper than a tunnel move and can afford to be quicker.
const routeHysteresis = 30 * time.Second

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
