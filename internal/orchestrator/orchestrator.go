// Package orchestrator drives sessions and network changes.
//
// It is the only writer of a session's effective state. It receives intent from
// the CLI, decides transitions, and emits plans for the transactional adapter
// to carry out — never touching the kernel itself. That separation is what
// NM-04 requires and what keeps the decision logic testable without root.
package orchestrator

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/netip"

	"github.com/luizosorio/nostmesh/internal/config"
	"github.com/luizosorio/nostmesh/internal/domain"
	"github.com/luizosorio/nostmesh/internal/netstate"
	"github.com/luizosorio/nostmesh/internal/wireguard"
)

// defaultInterface is the interface NostMesh manages in MVP 0.
//
// One interface carries every manually configured peer, which is all MVP 0
// needs. Multiple interfaces arrive with the mesh in MVP 2.
const defaultInterface = "nm0"

var (
	// ErrNoPeers reports a configuration with nothing to bring up.
	ErrNoPeers = errors.New("no peers configured")

	// ErrAlreadyUp reports an interface that is already established.
	ErrAlreadyUp = errors.New("tunnel is already up")
)

// Orchestrator coordinates sessions, policy and network state.
type Orchestrator struct {
	controller wireguard.Controller
	manager    *netstate.Manager
	journal    *netstate.JournalStore
	clock      domain.Clock

	// tunnelKey generates the interface's ephemeral key. It is injected so a
	// test can supply a deterministic one.
	generateKey func() (domain.WireGuardPublicKey, domain.WireGuardPrivateKey, error)
}

// Options configures an Orchestrator.
type Options struct {
	Controller  wireguard.Controller
	Journal     *netstate.JournalStore
	Clock       domain.Clock
	GenerateKey func() (domain.WireGuardPublicKey, domain.WireGuardPrivateKey, error)
}

// New builds an Orchestrator.
func New(opts Options) (*Orchestrator, error) {
	if opts.Controller == nil {
		return nil, errors.New("orchestrator requires a wireguard controller")
	}
	if opts.Journal == nil {
		return nil, errors.New("orchestrator requires a journal")
	}

	clock := opts.Clock
	if clock == nil {
		clock = domain.SystemClock{}
	}

	return &Orchestrator{
		controller:  opts.Controller,
		manager:     netstate.NewManager(opts.Controller, opts.Journal, clock),
		journal:     opts.Journal,
		clock:       clock,
		generateKey: opts.GenerateKey,
	}, nil
}

// Status reports desired configuration against what the host actually carries.
//
// The distinction matters: a peer the configuration expects but the kernel does
// not have is exactly the situation an operator needs to see, and it is what
// distinguishes "configured" from "working".
type Status struct {
	Interface     string
	Configured    []config.Peer
	Observed      *wireguard.InterfaceState
	Pending       []*netstate.Transaction
	InterfaceUp   bool
	ObserveFailed error
}

// Status collects the current state.
func (o *Orchestrator) Status(ctx context.Context, cfg config.Config) (Status, error) {
	status := Status{
		Interface:  defaultInterface,
		Configured: cfg.Peers,
	}

	observed, err := o.controller.ObserveInterface(ctx, defaultInterface)
	switch {
	case err == nil:
		status.Observed = &observed
		status.InterfaceUp = true
	case errors.Is(err, wireguard.ErrInterfaceNotFound):
		// Not an error: the tunnel is simply down.
	default:
		status.ObserveFailed = err
	}

	pending, err := o.journal.PendingRecovery()
	if err != nil {
		return status, fmt.Errorf("reading journal: %w", err)
	}
	status.Pending = pending

	return status, nil
}

// PlanUp builds the plan that would bring the tunnel up, without applying it.
func (o *Orchestrator) PlanUp(ctx context.Context, cfg config.Config) (netstate.Plan, error) {
	if len(cfg.Peers) == 0 {
		return netstate.Plan{}, ErrNoPeers
	}

	spec, peers, err := o.buildSpecs(cfg)
	if err != nil {
		return netstate.Plan{}, err
	}

	transactionID, err := newTransactionID()
	if err != nil {
		return netstate.Plan{}, err
	}

	labels := make([]netstate.PeerLabel, 0, len(cfg.Peers))
	for _, peer := range cfg.Peers {
		labels = append(labels, netstate.PeerLabel{PublicKey: peer.PublicKey, Name: peer.Name})
	}

	return o.manager.PlanInterface(ctx, transactionID, spec, peers, labels...)
}

// Up brings the tunnel up transactionally.
//
// Either every peer is configured or the host is left as it was found; there is
// no partial application. A failure part-way compensates in reverse.
func (o *Orchestrator) Up(ctx context.Context, cfg config.Config) (*netstate.Transaction, error) {
	plan, err := o.PlanUp(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return o.manager.Apply(ctx, plan)
}

// buildSpecs derives the interface and peer specs from local configuration.
//
// Everything here comes from the operator's own file. Nothing is taken from a
// peer: AllowedIPs, addresses and endpoints are local intent, which is what
// NM-04 requires even in the manual case where no peer has spoken yet.
func (o *Orchestrator) buildSpecs(cfg config.Config) (wireguard.InterfaceSpec, []wireguard.PeerSpec, error) {
	_, private, err := o.tunnelKey()
	if err != nil {
		return wireguard.InterfaceSpec{}, nil, err
	}

	spec := wireguard.InterfaceSpec{
		Name:       defaultInterface,
		PrivateKey: private,
		ListenPort: cfg.Node.ListenPort,
		MTU:        cfg.Node.MTU,
	}

	if cfg.Node.OverlayAddress != "" {
		address, parseErr := netip.ParsePrefix(cfg.Node.OverlayAddress)
		if parseErr != nil {
			return wireguard.InterfaceSpec{}, nil, fmt.Errorf("node overlay address: %w", parseErr)
		}
		spec.Addresses = append(spec.Addresses, address)
	}

	peers := make([]wireguard.PeerSpec, 0, len(cfg.Peers))
	for _, peer := range cfg.Peers {
		converted, convertErr := toPeerSpec(peer)
		if convertErr != nil {
			return wireguard.InterfaceSpec{}, nil, fmt.Errorf("peer %s: %w", peer.Name, convertErr)
		}
		peers = append(peers, converted)
	}

	return spec, peers, nil
}

func (o *Orchestrator) tunnelKey() (domain.WireGuardPublicKey, domain.WireGuardPrivateKey, error) {
	if o.generateKey != nil {
		return o.generateKey()
	}
	return domain.WireGuardPublicKey{}, domain.WireGuardPrivateKey{},
		errors.New("orchestrator has no tunnel key generator configured")
}

func toPeerSpec(peer config.Peer) (wireguard.PeerSpec, error) {
	publicKey, err := domain.ParseWireGuardPublicKey(peer.PublicKey)
	if err != nil {
		return wireguard.PeerSpec{}, fmt.Errorf("public key: %w", err)
	}

	endpoint, err := netip.ParseAddrPort(peer.Endpoint)
	if err != nil {
		return wireguard.PeerSpec{}, fmt.Errorf("endpoint: %w", err)
	}

	allowed := make([]netip.Prefix, 0, len(peer.AllowedIPs))
	for _, entry := range peer.AllowedIPs {
		prefix, parseErr := netip.ParsePrefix(entry)
		if parseErr != nil {
			return wireguard.PeerSpec{}, fmt.Errorf("allowed ip %q: %w", entry, parseErr)
		}
		allowed = append(allowed, prefix)
	}

	return wireguard.PeerSpec{
		PublicKey:           publicKey,
		Endpoint:            &endpoint,
		AllowedIPs:          allowed,
		PersistentKeepalive: peer.KeepAlive,
	}, nil
}

func newTransactionID() (string, error) {
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("%w: generating transaction id: %w", domain.ErrInsufficientEntropy, err)
	}
	return fmt.Sprintf("tx-%x", raw), nil
}
