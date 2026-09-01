package main

import (
	"context"
	"fmt"
	"net/netip"
	"path/filepath"
	"time"

	"github.com/luizosorio/nostmesh/internal/config"
	"github.com/luizosorio/nostmesh/internal/connectivity"
	"github.com/luizosorio/nostmesh/internal/domain"
	"github.com/luizosorio/nostmesh/internal/identity"
	"github.com/luizosorio/nostmesh/internal/netstate"
	"github.com/luizosorio/nostmesh/internal/nostr"
	"github.com/luizosorio/nostmesh/internal/orchestrator"
	"github.com/luizosorio/nostmesh/internal/wireguard"
)

// sessionRuntime holds everything one session needs, and the order to release
// it in.
type sessionRuntime struct {
	driver *orchestrator.Driver
	set    *nostr.RelaySet
	plane  *controlPlane

	// cleanup releases the netlink socket, the UDP port and the relays. The
	// order matters: the transport must be released before the relays, since a
	// failed session still has to hand its port back.
	cleanup func()
}

// buildSessionRuntime wires a driver from configuration.
//
// Nothing here decides policy. AllowedIPs and overlay addresses come from the
// configuration file, which is the local operator's statement of what this node
// will accept — never from anything a peer sends.
func buildSessionRuntime(ctx context.Context, cfg config.Config, peer domain.NostrPublicKey,
	timeout time.Duration, trace func(string), answered *orchestrator.AnsweredSessions,
) (*sessionRuntime, error) {
	adapter, closeAdapter, err := wireguard.NewController()
	if err != nil {
		return nil, err
	}

	release := []func(){func() { _ = closeAdapter() }}
	cleanup := func() {
		for i := len(release) - 1; i >= 0; i-- {
			release[i]()
		}
	}

	fail := func(err error) (*sessionRuntime, error) {
		cleanup()
		return nil, err
	}

	nodeIdentity, err := loadIdentity(cfg)
	if err != nil {
		return fail(err)
	}

	allowlist, err := loadAllowlist(cfg)
	if err != nil {
		return fail(err)
	}

	clock := domain.SystemClock{}
	journal := netstate.NewJournalStore(journalDir(cfg.Node.StateDir))
	netManager := netstate.NewManager(adapter, journal, clock)

	manager, err := orchestrator.NewSessionManager(orchestrator.SessionManagerOptions{
		Controller:  adapter,
		NetState:    netManager,
		Clock:       clock,
		MaxSessions: cfg.Policy.MaxSessions,
	})
	if err != nil {
		return fail(err)
	}

	// The transport claims the port before anything else needs it, because
	// every candidate this node offers describes that port.
	//nolint:gosec // a configured listen port is a uint16
	transport, err := connectivity.NewUDPTransport(uint16(cfg.Node.ListenPort))
	if err != nil {
		return fail(fmt.Errorf("claiming the session port: %w", err))
	}
	release = append(release, func() { _ = transport.Close() })

	outbox, err := nostr.NewOutbox(nostr.OutboxOptions{
		Dir:   filepath.Join(cfg.Node.StateDir, "outbox"),
		Clock: clock.Now,
	})
	if err != nil {
		return fail(fmt.Errorf("opening outbox: %w", err))
	}

	set, err := nostr.NewRelaySet(nostr.RelaySetOptions{
		URLs:   cfg.Node.Relays,
		Outbox: outbox,
		Clock:  clock.Now,
	})
	if err != nil {
		return fail(err)
	}
	release = append(release, func() { _ = set.Close() })

	if err := set.Connect(ctx); err != nil {
		return fail(err)
	}

	// The control plane starts without a session: the driver owns the id and
	// binds it, generating one as initiator or adopting the request's as
	// responder.
	//
	// The reader is registered here, and it must exist before the subscription
	// is requested. A relay answers a REQ immediately with the events it already
	// holds, and a delivery with no reader registered is dropped rather than
	// queued — so subscribing first loses exactly the messages a responder is
	// waiting for.
	plane, err := newControlPlane(ctx, set, nodeIdentity, peer, "", clock.Now)
	if err != nil {
		return fail(err)
	}
	plane.trace = trace

	if err := set.SubscribeToInbox(ctx, nodeIdentity.PublicKey()); err != nil {
		return fail(err)
	}

	// The observer shares the transport's socket, so the address a STUN server
	// reports describes the mapping this session will actually use.
	observer, err := connectivity.NewSharedObserver(transport, 0)
	if err != nil {
		return fail(err)
	}

	gatherer := connectivity.NewGatherer(connectivity.GathererOptions{
		Policy: connectivity.GatherPolicy{
			Order:     connectivity.DefaultGatherPolicy().Order,
			Observers: cfg.Node.Observers,
		},
		Observer: observer,
		Clock:    clock.Now,
	})

	options, err := driverOptions(cfg, peer, timeout)
	if err != nil {
		return fail(err)
	}

	driver, err := orchestrator.NewDriver(orchestrator.DriverDeps{
		Manager:    manager,
		Allowlist:  allowlist,
		NetState:   netManager,
		Controller: adapter,
		Identity:   nodeIdentity.PublicKey(),
		Keys:       identity.NewKeyGenerator(),
		Transport:  transport,
		Publisher:  plane,
		Receiver:   plane,
		Gatherer:   gatherer,
		Clock:      clock,
		Answered:   answered,
	}, options)
	if err != nil {
		return fail(err)
	}

	return &sessionRuntime{driver: driver, set: set, plane: plane, cleanup: cleanup}, nil
}

// driverOptions reads the local interface policy from configuration.
//
// The AllowedIPs come from the peer's entry in this node's own configuration
// file. That is the whole point: a peer stating what it would like to route is
// a request, and this is the answer, decided locally and in advance.
func driverOptions(cfg config.Config, peer domain.NostrPublicKey,
	timeout time.Duration,
) (orchestrator.DriverOptions, error) {
	options := orchestrator.DriverOptions{
		InterfaceName: interfaceName,
		MTU:           cfg.Node.MTU,
		Observers:     cfg.Node.Observers,

		// The operator's --timeout governs the whole attempt, and waiting for a
		// peer is most of it. A responder in particular is idle until the other
		// side runs, so a shorter internal bound would make it give up while the
		// operator was still waiting — which is exactly what it looked like: a
		// listener exiting long before its own deadline.
		//
		// Zero from the operator means no deadline, which the driver expresses
		// as Unbounded — its own zero would take the default bound instead.
		HandshakeTimeout: handshakeBound(timeout),
	}

	if cfg.Node.OverlayAddress != "" {
		overlay, err := netip.ParsePrefix(cfg.Node.OverlayAddress)
		if err != nil {
			return orchestrator.DriverOptions{}, fmt.Errorf("node overlay address: %w", err)
		}
		options.OverlayAddrs = []netip.Prefix{overlay}
	}

	configured, found := findAuthorizedPeer(cfg, peer)
	if !found {
		return orchestrator.DriverOptions{}, fmt.Errorf(
			"peer %s is not listed under policy.authorized_peers", peer.Short())
	}

	for _, raw := range configured.AllowedIPs {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return orchestrator.DriverOptions{}, fmt.Errorf("peer %s allowed_ips: %w", peer.Short(), err)
		}
		options.AllowedIPs = append(options.AllowedIPs, prefix)
	}

	if len(options.AllowedIPs) == 0 {
		return orchestrator.DriverOptions{}, fmt.Errorf(
			"peer %s has no allowed_ips under policy.authorized_peers; a tunnel that accepts nothing is not worth building",
			peer.Short())
	}
	return options, nil
}

// handshakeBound converts an operator timeout into the driver's bound.
func handshakeBound(timeout time.Duration) time.Duration {
	if timeout <= 0 {
		return orchestrator.Unbounded
	}
	return timeout
}

// loadIdentity reads this node's Nostr identity.
//
// A session cannot proceed without it: the identity is what signs every control
// message, and an unsigned message is one no peer will accept.
func loadIdentity(cfg config.Config) (domain.NodeIdentity, error) {
	keystore := identity.NewDevelopmentKeystore(defaultKeystorePath(cfg.Node.StateDir), domain.SystemClock{})

	node, err := keystore.Load()
	if err != nil {
		return domain.NodeIdentity{}, fmt.Errorf("%w; run 'nostmesh identity init' first", err)
	}
	return node, nil
}

// findAuthorizedPeer locates a peer's grant in local configuration.
//
// The lookup is by Nostr identity, which is the only stable name the far side of
// a negotiated session has: its tunnel key is generated per session and is not
// known when the operator writes the configuration. The manually configured
// [[peers]] entries are keyed by WireGuard key instead, and belong to the manual
// `up` path rather than to session negotiation.
func findAuthorizedPeer(cfg config.Config, peer domain.NostrPublicKey) (config.AuthorizedPeer, bool) {
	for _, candidate := range cfg.Policy.AuthorizedPeers {
		parsed, err := domain.ParseNostrPublicKey(candidate.PublicKey)
		if err != nil {
			continue
		}
		if parsed == peer {
			return candidate, true
		}
	}
	return config.AuthorizedPeer{}, false
}

// interfaceName is the interface a session configures.
//
// It carries the ownership prefix that lets every other command tell a NostMesh
// interface from one it must never touch.
const interfaceName = "nm0"

// sessionTimeout bounds a whole connection attempt.
const sessionTimeout = 2 * time.Minute
