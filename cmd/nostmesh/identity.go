package main

import (
	"encoding/json"
	"errors"
	"flag"
	"path/filepath"
	"time"

	"github.com/luizosorio/nostmesh/internal/domain"
	"github.com/luizosorio/nostmesh/internal/identity"
)

func runIdentity(args []string, stdout, stderr *output) int {
	if len(args) == 0 {
		identityUsage(stderr)
		return exitUsage
	}

	switch args[0] {
	case "init":
		return runIdentityInit(args[1:], stdout, stderr)
	case "show":
		return runIdentityShow(args[1:], stdout, stderr)
	case "-h", "--help", "help":
		identityUsage(stdout)
		return exitOK
	default:
		stderr.printf("nostmesh identity: unknown subcommand %q\n\n", args[0])
		identityUsage(stderr)
		return exitUsage
	}
}

func identityUsage(out *output) {
	out.printf("Usage: nostmesh identity <subcommand>\n\nSubcommands:\n")
	out.printf("  init   Generate this node's identity\n")
	out.printf("  show   Print the public identity\n")
}

// defaultKeystorePath returns where the identity lives under a state directory.
func defaultKeystorePath(stateDir string) string {
	return filepath.Join(stateDir, "identity.json")
}

func runIdentityInit(args []string, stdout, stderr *output) int {
	flags := flag.NewFlagSet("identity init", flag.ContinueOnError)
	flags.SetOutput(stderr.w)
	stateDir := flags.String("state-dir", "", "directory holding local state (required)")

	flags.Usage = func() {
		stderr.printf("Usage: nostmesh identity init --state-dir <path>\n\n" +
			"Generate this node's durable Nostr identity.\n\n" +
			"The key is written to a file readable only by its owner. This is a\n" +
			"development backend: a production deployment should use an external\n" +
			"signer that never surrenders the private key.\n\nFlags:\n")
		flags.PrintDefaults()
	}

	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if *stateDir == "" {
		stderr.printf("nostmesh identity init: --state-dir is required\n")
		return exitUsage
	}

	keystore := identity.NewDevelopmentKeystore(defaultKeystorePath(*stateDir), domain.SystemClock{})

	generator := identity.NewKeyGenerator()
	private, err := generator.GenerateNostrKey()
	if err != nil {
		stderr.printf("nostmesh identity init: %v\n", err)
		return exitError
	}

	// The public key is derived by the signing adapter, which owns the
	// secp256k1 implementation. Until that adapter exists in M1.1, the
	// development keystore records the identity with a placeholder derivation
	// so the storage path can be exercised end to end.
	public, err := identity.DeriveNostrPublicKey(private)
	if err != nil {
		stderr.printf("nostmesh identity init: %v\n", err)
		return exitError
	}

	node, err := domain.NewNodeIdentity(public, private, time.Now().UTC())
	if err != nil {
		stderr.printf("nostmesh identity init: %v\n", err)
		return exitError
	}

	if err := keystore.Store(node); err != nil {
		stderr.printf("nostmesh identity init: %v\n", err)
		return exitError
	}

	stdout.printf("identity created\n")
	stdout.printf("  public key: %s\n", node.PublicKey())
	stdout.printf("  stored in:  %s\n", keystore.Path())
	stdout.printf("\nwarning: %s\n", identity.DevelopmentWarning)

	return exitOK
}

func runIdentityShow(args []string, stdout, stderr *output) int {
	flags := flag.NewFlagSet("identity show", flag.ContinueOnError)
	flags.SetOutput(stderr.w)
	stateDir := flags.String("state-dir", "", "directory holding local state (required)")
	asJSON := flags.Bool("json", false, "print the identity as JSON")

	flags.Usage = func() {
		stderr.printf("Usage: nostmesh identity show --state-dir <path> [--json]\n\n" +
			"Print this node's public identity. The private key is never displayed.\n\nFlags:\n")
		flags.PrintDefaults()
	}

	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if *stateDir == "" {
		stderr.printf("nostmesh identity show: --state-dir is required\n")
		return exitUsage
	}

	keystore := identity.NewDevelopmentKeystore(defaultKeystorePath(*stateDir), domain.SystemClock{})

	node, err := keystore.Load()
	if err != nil {
		if errors.Is(err, identity.ErrNoIdentity) {
			stderr.printf("no identity found; run 'nostmesh identity init --state-dir %s' first\n", *stateDir)
			return exitError
		}
		stderr.printf("nostmesh identity show: %v\n", err)
		return exitError
	}

	// Only public material is rendered. The private key has no path to stdout.
	if *asJSON {
		encoded, err := json.Marshal(struct {
			PublicKey string `json:"public_key"`
			CreatedAt string `json:"created_at"`
		}{
			PublicKey: node.PublicKey().String(),
			CreatedAt: node.CreatedAt().UTC().Format(time.RFC3339),
		})
		if err != nil {
			stderr.printf("nostmesh identity show: %v\n", err)
			return exitError
		}
		stdout.printf("%s\n", encoded)
		return exitOK
	}

	stdout.printf("public key: %s\n", node.PublicKey())
	stdout.printf("created:    %s\n", node.CreatedAt().UTC().Format(time.RFC3339))

	return exitOK
}
