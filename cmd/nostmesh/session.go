package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/luizosorio/nostmesh/internal/config"
	"github.com/luizosorio/nostmesh/internal/domain"
	"github.com/luizosorio/nostmesh/internal/orchestrator"
	"github.com/luizosorio/nostmesh/internal/policy"
)

// runConnect opens a session with a peer over the control plane.
func runConnect(args []string, stdout, stderr *output) int {
	flags := flag.NewFlagSet("connect", flag.ContinueOnError)
	flags.SetOutput(stderr.w)
	configPath := flags.String("config", "", "path to the configuration file (required)")
	peerKey := flags.String("peer", "", "peer's Nostr public key, hex (required)")
	timeout := flags.Duration("timeout", sessionTimeout, "how long to wait for the session to establish")

	flags.Usage = func() {
		stderr.printf("Usage: nostmesh connect --config <path> --peer <pubkey>\n\n" +
			"Negotiate a session with a peer over Nostr.\n\n" +
			"The peer must already be authorized: local policy denies by default,\n" +
			"and a valid signature proves who is asking, not that they may.\n\nFlags:\n")
		flags.PrintDefaults()
	}

	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if *configPath == "" || *peerKey == "" {
		stderr.printf("nostmesh connect: --config and --peer are required\n")
		return exitUsage
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		stderr.printf("%v\n", err)
		return exitError
	}

	peer, err := domain.ParseNostrPublicKey(*peerKey)
	if err != nil {
		stderr.printf("nostmesh connect: %v\n", err)
		return exitError
	}

	// Policy is consulted before anything is attempted. Refusing here costs
	// nothing; refusing after a handshake wastes both sides' work.
	allowlist, err := loadAllowlist(cfg)
	if err != nil {
		stderr.printf("nostmesh connect: %v\n", err)
		return exitError
	}
	if err := allowlist.Check(peer, policy.ActionSession); err != nil {
		stderr.printf("nostmesh connect: %v\n", err)
		stderr.printf("add it to policy.authorized_peers in %s to authorize it\n", *configPath)
		return exitError
	}

	// The pair settles which end opens the session: both are willing to do
	// either, and the command name is not evidence about the peer.
	return runSession(cfg, peer, orchestrator.RoleAuto, *timeout, stdout, stderr)
}

// runSession builds the runtime and drives one session to a carrying tunnel.
//
// Interrupting it tears down cleanly rather than leaving a half-configured
// interface: a signal is a request to stop, not permission to abandon kernel
// state.
func runSession(cfg config.Config, peer domain.NostrPublicKey, role orchestrator.Role,
	timeout time.Duration, stdout, stderr *output,
) int {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if timeout > 0 {
		var timed context.CancelFunc
		ctx, timed = context.WithTimeout(ctx, timeout)
		defer timed()
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(stop)

	go func() {
		select {
		case <-stop:
			cancel()
		case <-ctx.Done():
		}
	}()

	stdout.printf("connecting to %s\n", peer.Short())

	// Progress is printed as it happens. A session spans two hosts and several
	// layers, and every failure in it looks the same from outside — a wait that
	// ends empty — so saying what did arrive is most of the diagnosis.
	//
	// The same records the daemon writes as JSON are rendered here as prose,
	// rather than carried as a second set of progress strings that could drift
	// from the events they describe.
	progress := sessionProgressLogger(stdout)

	runtime, err := buildSessionRuntime(ctx, cfg, peer, timeout, progress, nil)
	if err != nil {
		stderr.printf("nostmesh: %v\n", err)
		return exitError
	}
	defer runtime.cleanup()

	// Relays are kept connected for the duration. A relay that drops mid-session
	// is redialled and resubscribed, since a peer may still be publishing to it.
	go runtime.set.Supervise(ctx)

	// Some relays answer a subscription from storage and then never push what
	// arrives afterwards. Polling reissues the subscription so those still
	// deliver, at the cost of a small query every few seconds.
	go runtime.set.Poll(ctx)

	if err := runtime.driver.Connect(ctx, peer, role); err != nil {
		stderr.printf("nostmesh: %v\n", err)

		// What this node managed to publish is half the diagnosis. A session
		// that failed having published nothing is a different problem from one
		// that published and was not answered.
		for _, line := range runtime.plane.Publications() {
			stderr.printf("  published %s\n", line)
		}
		return exitError
	}

	stdout.printf("tunnel established with %s\n", peer.Short())
	stdout.printf("run 'nostmesh status --config <path>' to inspect it\n")
	return exitOK
}

// runSessions lists what the node knows about its sessions.
func runSessions(args []string, stdout, stderr *output) int {
	flags := flag.NewFlagSet("sessions", flag.ContinueOnError)
	flags.SetOutput(stderr.w)
	configPath := flags.String("config", "", "path to the configuration file (required)")
	asJSON := flags.Bool("json", false, "print as JSON")

	flags.Usage = func() {
		stderr.printf("Usage: nostmesh sessions --config <path> [--json]\n\n" +
			"List authorized peers and any active sessions.\n\nFlags:\n")
		flags.PrintDefaults()
	}

	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if *configPath == "" {
		stderr.printf("nostmesh sessions: --config is required\n")
		return exitUsage
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		stderr.printf("%v\n", err)
		return exitError
	}

	allowlist, err := loadAllowlist(cfg)
	if err != nil {
		stderr.printf("nostmesh sessions: %v\n", err)
		return exitError
	}

	grants := allowlist.Grants()

	if *asJSON {
		rendered := make([]map[string]any, 0, len(grants))
		for _, grant := range grants {
			actions := make([]string, 0, len(grant.Actions))
			for _, action := range grant.Actions {
				actions = append(actions, string(action))
			}
			rendered = append(rendered, map[string]any{
				"peer":    grant.Peer.String(),
				"alias":   grant.Alias,
				"actions": actions,
				"revoked": grant.Revoked,
			})
		}

		encoded, err := json.Marshal(rendered)
		if err != nil {
			stderr.printf("nostmesh sessions: %v\n", err)
			return exitError
		}
		stdout.printf("%s\n", encoded)
		return exitOK
	}

	if len(grants) == 0 {
		stdout.printf("no authorized peers\n")
		stdout.printf("\nlocal policy denies by default; authorize a peer with 'nostmesh peer authorize'\n")
		return exitOK
	}

	stdout.printf("authorized peers: %d\n\n", len(grants))
	for _, grant := range grants {
		status := "active"
		if grant.Revoked {
			status = "revoked"
		}

		label := grant.Alias
		if label == "" {
			label = grant.Peer.Short()
		}

		stdout.printf("%s\n", label)
		stdout.printf("  pubkey:  %s\n", grant.Peer.String())
		stdout.printf("  actions: %s\n", joinActions(grant.Actions))
		stdout.printf("  status:  %s\n", status)
	}

	stdout.printf("\nno active sessions; the relay transport arrives in M1.4\n")
	return exitOK
}

// runDisconnect closes a session.
func runDisconnect(args []string, stdout, stderr *output) int {
	flags := flag.NewFlagSet("disconnect", flag.ContinueOnError)
	flags.SetOutput(stderr.w)
	configPath := flags.String("config", "", "path to the configuration file (required)")
	peerKey := flags.String("peer", "", "peer's Nostr public key, hex (required)")

	flags.Usage = func() {
		stderr.printf("Usage: nostmesh disconnect --config <path> --peer <pubkey>\n\n" +
			"Close a session and remove what it applied to the host.\n\nFlags:\n")
		flags.PrintDefaults()
	}

	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if *configPath == "" || *peerKey == "" {
		stderr.printf("nostmesh disconnect: --config and --peer are required\n")
		return exitUsage
	}

	if _, err := config.Load(*configPath); err != nil {
		stderr.printf("%v\n", err)
		return exitError
	}
	if _, err := domain.ParseNostrPublicKey(*peerKey); err != nil {
		stderr.printf("nostmesh disconnect: %v\n", err)
		return exitError
	}

	stdout.printf("no session to close\n")
	stdout.printf("\nuse 'nostmesh down' to remove a manually configured tunnel\n")
	return exitOK
}

// loadAllowlist reads authorized peers from configuration.
//
// The allowlist lives in the configuration file rather than a separate store:
// it is operator intent, edited deliberately, and keeping it in one reviewable
// place matters more than the convenience of a mutable store.
func loadAllowlist(cfg config.Config) (*policy.Allowlist, error) {
	allowlist := policy.NewAllowlist()

	for _, authorized := range cfg.Policy.AuthorizedPeers {
		peer, err := domain.ParseNostrPublicKey(authorized.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("authorized peer %q: %w", authorized.Alias, err)
		}

		actions := make([]policy.Action, 0, len(authorized.Actions))
		for _, action := range authorized.Actions {
			actions = append(actions, policy.Action(action))
		}

		// The prefixes come with the grant rather than being looked up later.
		// They were dropped here and read straight from configuration at the
		// point of use, so whether a peer was authorized and what it could route
		// were answered separately — and only one of them was checked. See
		// NM-24.
		allowedIPs := make([]netip.Prefix, 0, len(authorized.AllowedIPs))
		for _, raw := range authorized.AllowedIPs {
			prefix, err := netip.ParsePrefix(raw)
			if err != nil {
				return nil, fmt.Errorf("authorized peer %q allowed_ips: %w", authorized.Alias, err)
			}
			allowedIPs = append(allowedIPs, prefix)
		}

		if err := allowlist.Add(policy.Grant{
			Peer:       peer,
			Alias:      authorized.Alias,
			Actions:    actions,
			AllowedIPs: allowedIPs,
			Revoked:    authorized.Revoked,
		}); err != nil {
			return nil, fmt.Errorf("authorized peer %q: %w", authorized.Alias, err)
		}
	}

	// Groups are added after the per-peer grants, but the order decides nothing:
	// the preference for a named peer lives in Decide, not here. See NM-24.
	for _, configured := range cfg.Policy.Groups {
		members := make([]domain.NostrPublicKey, 0, len(configured.Members))
		for _, raw := range configured.Members {
			member, err := domain.ParseNostrPublicKey(raw)
			if err != nil {
				return nil, fmt.Errorf("policy group %q: %w", configured.Name, err)
			}
			members = append(members, member)
		}

		actions := make([]policy.Action, 0, len(configured.Actions))
		for _, action := range configured.Actions {
			actions = append(actions, policy.Action(action))
		}

		allowedIPs := make([]netip.Prefix, 0, len(configured.AllowedIPs))
		for _, raw := range configured.AllowedIPs {
			prefix, err := netip.ParsePrefix(raw)
			if err != nil {
				return nil, fmt.Errorf("policy group %q allowed_ips: %w", configured.Name, err)
			}
			allowedIPs = append(allowedIPs, prefix)
		}

		if err := allowlist.AddGroup(policy.Group{
			Name:       configured.Name,
			Members:    members,
			Actions:    actions,
			AllowedIPs: allowedIPs,
		}); err != nil {
			return nil, fmt.Errorf("policy group %q: %w", configured.Name, err)
		}
	}

	return allowlist, nil
}

// sessionPeers reports every identity policy would hold a session with.
//
// The service starts one worker per entry, so this has to include group members
// and not only peers named individually: a rule covering ten devices authorizes
// ten peers, and listing the grants alone would authorize them while connecting
// to none.
//
// Membership is asked of the decision rather than read off the rules, so a
// revoked peer a group happens to name stays out — the precedence lives in one
// place (NM-24), and duplicating it here is how the two would drift apart.
//
// The result is sorted. It decides which workers run, and an order that varied
// between reloads would restart tunnels that nothing asked to change.
func sessionPeers(allowlist *policy.Allowlist) []domain.NostrPublicKey {
	seen := make(map[domain.NostrPublicKey]struct{})

	for _, grant := range allowlist.Grants() {
		seen[grant.Peer] = struct{}{}
	}
	for _, group := range allowlist.Groups() {
		for _, member := range group.Members {
			seen[member] = struct{}{}
		}
	}

	peers := make([]domain.NostrPublicKey, 0, len(seen))
	for peer := range seen {
		if !allowlist.Decide(peer, policy.ActionSession).Allowed() {
			continue
		}
		peers = append(peers, peer)
	}

	slices.SortFunc(peers, func(a, b domain.NostrPublicKey) int {
		return bytes.Compare(a[:], b[:])
	})
	return peers
}

func joinActions(actions []policy.Action) string {
	names := make([]string, 0, len(actions))
	for _, action := range actions {
		names = append(names, string(action))
	}
	return strings.Join(names, ", ")
}
