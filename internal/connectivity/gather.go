package connectivity

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// Method names a way of discovering a candidate.
//
// They are ordered by how much trust each requires. A local interface needs
// nobody; a router mapping needs the router; a STUN observer needs a stranger.
// Trying them in that order means a node often connects without ever telling a
// third party it exists.
type Method string

const (
	// MethodInterface reads local interface addresses. Trusts nobody.
	MethodInterface Method = "interface"

	// MethodStatic uses an operator-configured endpoint. Trusts the operator.
	MethodStatic Method = "static"

	// MethodPortMapping asks the router for a mapping via PCP or NAT-PMP.
	// Trusts the router, which is already on the path.
	MethodPortMapping Method = "port-mapping"

	// MethodRecent reuses an endpoint that worked before. Trusts this node's
	// own history, and still probes.
	MethodRecent Method = "recent"

	// MethodObserver asks a STUN server. Trusts a stranger, which is why it
	// comes last.
	MethodObserver Method = "observer"
)

// GatherPolicy controls which methods are used and in what order.
//
// It is configuration rather than a constant because the trade-off is a
// deployment's to make: a node on a trusted LAN may never want to contact an
// observer, and one behind CGNAT has no choice.
type GatherPolicy struct {
	// Order is the sequence of methods to try. A method absent from the list
	// is never used.
	Order []Method

	// AllowPrivateAddresses permits candidates in private space. Useful on a
	// shared LAN, pointless across the internet, and a small privacy leak when
	// announced to a peer that cannot use them.
	AllowPrivateAddresses bool

	// AllowIPv6 permits IPv6 candidates.
	AllowIPv6 bool

	// Observers are STUN servers to query, used only if MethodObserver is in
	// Order.
	Observers []string

	// StaticEndpoint is an operator-configured address.
	StaticEndpoint string
}

// DefaultGatherPolicy returns the recommended ordering.
//
// IPv6 and LAN first because they need nobody's cooperation, then the router,
// then history, and a stranger last.
func DefaultGatherPolicy() GatherPolicy {
	return GatherPolicy{
		Order: []Method{
			MethodInterface,
			MethodStatic,
			MethodPortMapping,
			MethodRecent,
			MethodObserver,
		},
		AllowPrivateAddresses: true,
		AllowIPv6:             true,
	}
}

// Uses reports whether the policy permits a method.
func (p GatherPolicy) Uses(method Method) bool {
	for _, allowed := range p.Order {
		if allowed == method {
			return true
		}
	}
	return false
}

// Observer queries a STUN server for this node's observed address.
//
// The result is a claim, not a fact: it becomes a candidate marked UNVERIFIED,
// and only a probe can promote it.
type Observer interface {
	// Observe reports the address a server saw, and which server said so.
	Observe(ctx context.Context, server string, localPort int) (netip.AddrPort, error)
}

// InterfaceLister returns local addresses.
type InterfaceLister interface {
	// Addresses returns usable local addresses.
	Addresses() ([]netip.Addr, error)
}

// SystemInterfaces reads the host's interfaces.
type SystemInterfaces struct{}

// Addresses returns global unicast addresses on up, non-loopback interfaces.
//
// Loopback is excluded because a peer cannot reach it, and interfaces that are
// down are excluded because an address on one is a claim about nothing.
func (SystemInterfaces) Addresses() ([]netip.Addr, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("listing interfaces: %w", err)
	}

	var addresses []netip.Addr
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			// One unreadable interface must not hide the others.
			continue
		}

		for _, addr := range addrs {
			prefix, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			parsed, ok := netip.AddrFromSlice(prefix.IP)
			if !ok {
				continue
			}
			parsed = parsed.Unmap()

			if !parsed.IsGlobalUnicast() || parsed.IsLinkLocalUnicast() {
				continue
			}
			addresses = append(addresses, parsed)
		}
	}

	return addresses, nil
}

// Gatherer discovers candidates according to policy.
type Gatherer struct {
	policy     GatherPolicy
	interfaces InterfaceLister
	observer   Observer
	clock      func() time.Time
}

// GathererOptions configures a Gatherer.
type GathererOptions struct {
	Policy     GatherPolicy
	Interfaces InterfaceLister
	Observer   Observer
	Clock      func() time.Time
}

// NewGatherer builds a Gatherer.
func NewGatherer(opts GathererOptions) *Gatherer {
	if len(opts.Policy.Order) == 0 {
		opts.Policy = DefaultGatherPolicy()
	}
	if opts.Interfaces == nil {
		opts.Interfaces = SystemInterfaces{}
	}
	if opts.Clock == nil {
		opts.Clock = time.Now
	}

	return &Gatherer{
		policy:     opts.Policy,
		interfaces: opts.Interfaces,
		observer:   opts.Observer,
		clock:      opts.Clock,
	}
}

// GatherResult reports what discovery found and what it cost.
type GatherResult struct {
	// Candidates are the addresses discovered, all unverified.
	Candidates []Candidate

	// Attempted names the methods that ran.
	Attempted []Method

	// Failures explains why a method produced nothing, since "no candidates"
	// is far less useful than "the observer did not answer".
	Failures map[Method]error
}

// Gather discovers candidates, stopping early if enough are found.
//
// Stopping early is the privacy property: a node that finds a usable local
// address never contacts an observer, so no stranger learns it exists.
func (g *Gatherer) Gather(ctx context.Context, localPort int) GatherResult {
	result := GatherResult{Failures: make(map[Method]error)}

	for _, method := range g.policy.Order {
		if ctx.Err() != nil {
			result.Failures[method] = ctx.Err()
			break
		}

		result.Attempted = append(result.Attempted, method)

		found, err := g.gatherOne(ctx, method, localPort)
		if err != nil {
			result.Failures[method] = err
			continue
		}
		result.Candidates = append(result.Candidates, found...)

		// A directly discovered address is enough to stop: contacting an
		// observer would tell a stranger about this node for no gain.
		if method != MethodObserver && len(found) > 0 && g.sufficient(result.Candidates) {
			break
		}
	}

	return result
}

// sufficient reports whether discovery can stop.
//
// One routable, non-private address is enough to try connecting. Private
// addresses do not count, because a peer across the internet cannot use them.
func (g *Gatherer) sufficient(candidates []Candidate) bool {
	for _, candidate := range candidates {
		if !IsPrivate(candidate.Address.Addr()) {
			return true
		}
	}
	return false
}

func (g *Gatherer) gatherOne(ctx context.Context, method Method, localPort int) ([]Candidate, error) {
	switch method {
	case MethodInterface:
		return g.gatherInterfaces(localPort)
	case MethodStatic:
		return g.gatherStatic()
	case MethodObserver:
		return g.gatherFromObservers(ctx, localPort)
	case MethodPortMapping, MethodRecent:
		// PCP, NAT-PMP and endpoint history are not implemented yet. Reporting
		// that plainly beats silently skipping: an operator wondering why a
		// method contributed nothing gets an answer.
		return nil, fmt.Errorf("%s is not implemented yet", method)
	default:
		return nil, fmt.Errorf("unknown gather method %q", method)
	}
}

func (g *Gatherer) gatherInterfaces(localPort int) ([]Candidate, error) {
	addresses, err := g.interfaces.Addresses()
	if err != nil {
		return nil, err
	}

	now := g.clock()
	candidates := make([]Candidate, 0, len(addresses))

	for i, addr := range addresses {
		if addr.Is6() && !g.policy.AllowIPv6 {
			continue
		}
		if IsPrivate(addr) && !g.policy.AllowPrivateAddresses {
			continue
		}

		address := netip.AddrPortFrom(addr, uint16(localPort)) //nolint:gosec // caller supplies a bound port
		if err := ValidateAddress(address); err != nil {
			continue
		}

		candidates = append(candidates, Candidate{
			ID:      fmt.Sprintf("host-%d", i),
			Kind:    KindHost,
			Address: address,
			// A directly reachable address is preferred over anything a third
			// party had to tell us about.
			Priority:     priorityFor(KindHost, addr),
			Source:       "local interface",
			DiscoveredAt: now,
		})
	}

	if len(candidates) == 0 {
		return nil, errors.New("no usable interface addresses")
	}
	return candidates, nil
}

func (g *Gatherer) gatherStatic() ([]Candidate, error) {
	if g.policy.StaticEndpoint == "" {
		return nil, errors.New("no static endpoint configured")
	}

	address, err := netip.ParseAddrPort(g.policy.StaticEndpoint)
	if err != nil {
		return nil, fmt.Errorf("static endpoint %q: %w", g.policy.StaticEndpoint, err)
	}
	if err := ValidateAddress(address); err != nil {
		return nil, err
	}

	return []Candidate{{
		ID:           "static-0",
		Kind:         KindStatic,
		Address:      address,
		Priority:     priorityFor(KindStatic, address.Addr()),
		Source:       "configuration",
		DiscoveredAt: g.clock(),
	}}, nil
}

// gatherFromObservers queries each configured STUN server.
//
// Every observer is queried rather than stopping at the first, because
// disagreement is informative: a symmetric NAT produces a different mapping per
// destination, and seeing that is how a node learns direct connection is
// unlikely. Agreement, however, proves nothing.
func (g *Gatherer) gatherFromObservers(ctx context.Context, localPort int) ([]Candidate, error) {
	if g.observer == nil {
		return nil, errors.New("no observer configured")
	}
	if len(g.policy.Observers) == 0 {
		return nil, errors.New("no observers configured")
	}

	now := g.clock()
	var (
		candidates []Candidate
		lastErr    error
	)

	for i, server := range g.policy.Observers {
		if ctx.Err() != nil {
			break
		}

		observed, err := g.observer.Observe(ctx, server, localPort)
		if err != nil {
			lastErr = err
			continue
		}
		if err := ValidateAddress(observed); err != nil {
			// An observer reporting an unsafe address is either broken or
			// hostile. Either way its answer is discarded.
			lastErr = fmt.Errorf("observer %s reported an unusable address: %w", server, err)
			continue
		}

		candidates = append(candidates, Candidate{
			ID:      fmt.Sprintf("srflx-%d", i),
			Kind:    KindServerReflexive,
			Address: observed,
			// Lowest preference: a stranger's claim is tried after everything
			// this node could establish itself.
			Priority:     priorityFor(KindServerReflexive, observed.Addr()),
			Source:       server,
			DiscoveredAt: now,
		})
	}

	if len(candidates) == 0 {
		if lastErr != nil {
			return nil, lastErr
		}
		return nil, errors.New("no observer answered")
	}
	return candidates, nil
}

// priorityFor scores a candidate. Lower is tried first.
//
// The ordering encodes how much has to go right for a path to work: a direct
// address needs nothing, a mapped one needs the router to keep its promise, and
// a reflexive one needs a stranger to have told the truth.
func priorityFor(kind Kind, addr netip.Addr) uint32 {
	base := map[Kind]uint32{
		KindHost:            100,
		KindStatic:          200,
		KindPortMapped:      300,
		KindPeerReflexive:   400,
		KindServerReflexive: 500,
	}[kind]

	// IPv6 is preferred within a kind: it usually means no NAT at all.
	if addr.Is4() {
		base += 10
	}
	// A private address only works on a shared LAN, so it is tried after a
	// routable one of the same kind.
	if IsPrivate(addr) {
		base += 20
	}
	return base
}
