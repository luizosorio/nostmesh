package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"strings"

	"github.com/luizosorio/nostmesh/internal/config"
	"github.com/luizosorio/nostmesh/internal/domain"
	"github.com/luizosorio/nostmesh/internal/policy"
)

// runConnect opens a session with a peer over the control plane.
func runConnect(args []string, stdout, stderr *output) int {
	flags := flag.NewFlagSet("connect", flag.ContinueOnError)
	flags.SetOutput(stderr.w)
	configPath := flags.String("config", "", "path to the configuration file (required)")
	peerKey := flags.String("peer", "", "peer's Nostr public key, hex (required)")

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

	stderr.printf("nostmesh connect: relay transport is not wired yet; this arrives in M1.4\n")
	stderr.printf("the peer is authorized and the handshake is implemented; what is missing\n")
	stderr.printf("is publishing over relays, which needs the WebSocket client\n")
	return exitError
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

		if err := allowlist.Add(policy.Grant{
			Peer:    peer,
			Alias:   authorized.Alias,
			Actions: actions,
			Revoked: authorized.Revoked,
		}); err != nil {
			return nil, fmt.Errorf("authorized peer %q: %w", authorized.Alias, err)
		}
	}

	return allowlist, nil
}

func joinActions(actions []policy.Action) string {
	names := make([]string, 0, len(actions))
	for _, action := range actions {
		names = append(names, string(action))
	}
	return strings.Join(names, ", ")
}
