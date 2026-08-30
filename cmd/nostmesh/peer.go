package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/luizosorio/nostmesh/internal/config"
)

func runPeer(args []string, stdout, stderr *output) int {
	if len(args) == 0 {
		peerUsage(stderr)
		return exitUsage
	}

	switch args[0] {
	case "add":
		return runPeerAdd(args[1:], stdout, stderr)
	case "list":
		return runPeerList(args[1:], stdout, stderr)
	case "remove":
		return runPeerRemove(args[1:], stdout, stderr)
	case "-h", "--help", "help":
		peerUsage(stdout)
		return exitOK
	default:
		stderr.printf("nostmesh peer: unknown subcommand %q\n\n", args[0])
		peerUsage(stderr)
		return exitUsage
	}
}

func peerUsage(out *output) {
	out.printf("Usage: nostmesh peer <subcommand>\n\nSubcommands:\n")
	out.printf("  add      Add a peer to the configuration\n")
	out.printf("  list     List configured peers\n")
	out.printf("  remove   Remove a peer from the configuration\n")
}

func runPeerAdd(args []string, stdout, stderr *output) int {
	flags := flag.NewFlagSet("peer add", flag.ContinueOnError)
	flags.SetOutput(stderr.w)

	configPath := flags.String("config", "", "path to the configuration file (required)")
	name := flags.String("name", "", "local label for the peer (required)")
	publicKey := flags.String("public-key", "", "peer's WireGuard public key, base64 (required)")
	endpoint := flags.String("endpoint", "", "peer's transport address as host:port (required)")
	overlay := flags.String("overlay-address", "", "peer's address inside the tunnel, CIDR (required)")
	allowed := flags.String("allowed-ips", "", "comma-separated prefixes routed to this peer (required)")
	keepalive := flags.Duration("keepalive", 0, "persistent keepalive interval, zero to disable")

	flags.Usage = func() {
		stderr.printf("Usage: nostmesh peer add --config <path> --name <name> \\\n" +
			"         --public-key <key> --endpoint <host:port> \\\n" +
			"         --overlay-address <cidr> --allowed-ips <cidr,...>\n\n" +
			"Add a peer to the configuration file.\n\n" +
			"Allowed IPs are local policy: they decide what traffic this node\n" +
			"routes to the peer, and are never taken from what the peer claims.\n\nFlags:\n")
		flags.PrintDefaults()
	}

	if err := flags.Parse(args); err != nil {
		return exitUsage
	}

	required := map[string]string{
		"--config":          *configPath,
		"--name":            *name,
		"--public-key":      *publicKey,
		"--endpoint":        *endpoint,
		"--overlay-address": *overlay,
		"--allowed-ips":     *allowed,
	}
	for flagName, value := range required {
		if value == "" {
			stderr.printf("nostmesh peer add: %s is required\n", flagName)
			return exitUsage
		}
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		stderr.printf("%v\n", err)
		return exitError
	}

	peer := config.Peer{
		Name:           *name,
		PublicKey:      *publicKey,
		Endpoint:       *endpoint,
		OverlayAddress: *overlay,
		AllowedIPs:     splitPrefixes(*allowed),
		KeepAlive:      *keepalive,
	}

	for _, existing := range cfg.Peers {
		if existing.Name == peer.Name {
			stderr.printf("nostmesh peer add: a peer named %q already exists; remove it first\n", peer.Name)
			return exitError
		}
	}

	cfg.Peers = append(cfg.Peers, peer)

	// Validate the whole configuration, not just the new peer: a duplicate key
	// or a default route only shows up when the set is considered together.
	if err := cfg.Validate(); err != nil {
		stderr.printf("%v\n", err)
		return exitError
	}

	if err := writeConfig(*configPath, cfg); err != nil {
		stderr.printf("nostmesh peer add: %v\n", err)
		return exitError
	}

	stdout.printf("added peer %s\n", peer.Name)
	stdout.printf("  allowed ips: %s\n", strings.Join(peer.AllowedIPs, ", "))
	stdout.printf("\nrun 'nostmesh up --config %s' to apply\n", *configPath)

	return exitOK
}

func runPeerList(args []string, stdout, stderr *output) int {
	flags := flag.NewFlagSet("peer list", flag.ContinueOnError)
	flags.SetOutput(stderr.w)
	configPath := flags.String("config", "", "path to the configuration file (required)")
	asJSON := flags.Bool("json", false, "print the peers as JSON")

	flags.Usage = func() {
		stderr.printf("Usage: nostmesh peer list --config <path> [--json]\n\nList configured peers.\n\nFlags:\n")
		flags.PrintDefaults()
	}

	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if *configPath == "" {
		stderr.printf("nostmesh peer list: --config is required\n")
		return exitUsage
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		stderr.printf("%v\n", err)
		return exitError
	}

	if *asJSON {
		encoded, err := json.MarshalIndent(cfg.Peers, "", "  ")
		if err != nil {
			stderr.printf("nostmesh peer list: %v\n", err)
			return exitError
		}
		stdout.printf("%s\n", encoded)
		return exitOK
	}

	if len(cfg.Peers) == 0 {
		stdout.printf("no peers configured\n")
		return exitOK
	}

	for _, peer := range cfg.Peers {
		stdout.printf("%s\n", peer.Name)
		stdout.printf("  public key:  %s\n", peer.PublicKey)
		stdout.printf("  endpoint:    %s\n", peer.Endpoint)
		stdout.printf("  overlay:     %s\n", peer.OverlayAddress)
		stdout.printf("  allowed ips: %s\n", strings.Join(peer.AllowedIPs, ", "))
		if peer.KeepAlive > 0 {
			stdout.printf("  keepalive:   %s\n", peer.KeepAlive)
		}
	}

	return exitOK
}

func runPeerRemove(args []string, stdout, stderr *output) int {
	flags := flag.NewFlagSet("peer remove", flag.ContinueOnError)
	flags.SetOutput(stderr.w)
	configPath := flags.String("config", "", "path to the configuration file (required)")
	name := flags.String("name", "", "name of the peer to remove (required)")

	flags.Usage = func() {
		stderr.printf("Usage: nostmesh peer remove --config <path> --name <name>\n\n" +
			"Remove a peer from the configuration. This does not change the\n" +
			"running tunnel; run 'nostmesh up' afterwards to apply.\n\nFlags:\n")
		flags.PrintDefaults()
	}

	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if *configPath == "" || *name == "" {
		stderr.printf("nostmesh peer remove: --config and --name are required\n")
		return exitUsage
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		stderr.printf("%v\n", err)
		return exitError
	}

	kept := make([]config.Peer, 0, len(cfg.Peers))
	found := false
	for _, peer := range cfg.Peers {
		if peer.Name == *name {
			found = true
			continue
		}
		kept = append(kept, peer)
	}

	if !found {
		stderr.printf("nostmesh peer remove: no peer named %q\n", *name)
		return exitError
	}

	cfg.Peers = kept
	if err := writeConfig(*configPath, cfg); err != nil {
		stderr.printf("nostmesh peer remove: %v\n", err)
		return exitError
	}

	stdout.printf("removed peer %s\n", *name)
	stdout.printf("\nrun 'nostmesh up --config %s' to apply\n", *configPath)

	return exitOK
}

func splitPrefixes(value string) []string {
	parts := strings.Split(value, ",")
	prefixes := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			prefixes = append(prefixes, trimmed)
		}
	}
	return prefixes
}

// writeConfig replaces the configuration file atomically.
//
// A configuration truncated by an interrupted write would leave the node unable
// to start, so the same temp-then-rename discipline as the keystore applies.
func writeConfig(path string, cfg config.Config) (err error) {
	encoded, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding configuration: %w", err)
	}
	encoded = append(encoded, '\n')

	temp, err := os.CreateTemp(dirOf(path), ".nostmesh-config-*")
	if err != nil {
		return fmt.Errorf("creating temporary configuration: %w", err)
	}
	tempPath := temp.Name()

	defer func() {
		if err != nil {
			_ = temp.Close()
			_ = os.Remove(tempPath)
		}
	}()

	if err = temp.Chmod(0o600); err != nil {
		return fmt.Errorf("restricting temporary configuration: %w", err)
	}
	if _, err = temp.Write(encoded); err != nil {
		return fmt.Errorf("writing temporary configuration: %w", err)
	}
	if err = temp.Sync(); err != nil {
		return fmt.Errorf("syncing temporary configuration: %w", err)
	}
	if err = temp.Close(); err != nil {
		return fmt.Errorf("closing temporary configuration: %w", err)
	}
	if err = os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("installing configuration: %w", err)
	}
	return nil
}

func dirOf(path string) string {
	if index := strings.LastIndex(path, "/"); index >= 0 {
		return path[:index]
	}
	return "."
}
