package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/luizosorio/nostmesh/internal/domain"
	"github.com/luizosorio/nostmesh/internal/identity"
	"github.com/luizosorio/nostmesh/internal/nostr"
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
	case "import":
		return runIdentityImport(args[1:], stdout, stderr)
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
	out.printf("  init    Generate this node's identity\n")
	out.printf("  import  Adopt a Nostr identity you already have\n")
	out.printf("  show    Print the public identity\n")
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
	if encoded, encodeErr := identity.EncodePublicKeyOrFail(public); encodeErr == nil {
		stdout.printf("  shown as:   %s\n", encoded)
	}
	stdout.printf("  stored in:  %s\n", keystore.Path())
	stdout.printf("\nwarning: %s\n", identity.DevelopmentWarning)

	return exitOK
}

func runIdentityShow(args []string, stdout, stderr *output) int {
	flags := flag.NewFlagSet("identity show", flag.ContinueOnError)
	flags.SetOutput(stderr.w)
	stateDir := flags.String("state-dir", "", "directory holding local state (required)")
	asJSON := flags.Bool("json", false, "print the identity as JSON")
	format := flags.String("format", "hex", "how to render the key: hex or npub")

	flags.Usage = func() {
		stderr.printf("Usage: nostmesh identity show --state-dir <path> [--json] [--format hex|npub]\n\n" +
			"Print this node's public identity. The private key is never displayed.\n\n" +
			"The npub form is what other Nostr applications display, so it is the one\n" +
			"to compare against when checking this node is the identity you meant.\n\nFlags:\n")
		flags.PrintDefaults()
	}

	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if *stateDir == "" {
		stderr.printf("nostmesh identity show: --state-dir is required\n")
		return exitUsage
	}

	// Checked before the keystore is touched, so a mistyped value is a usage
	// error rather than something discovered after the work.
	if *format != "hex" && *format != "npub" {
		stderr.printf("nostmesh identity show: --format must be hex or npub, got %q\n", *format)
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

	// Rendering can fail only if nothing wired the encoder, which is a build
	// that cannot sign either. The hex form is always available, so the npub is
	// reported as absent rather than turned into an error.
	shownAs, encodeErr := identity.EncodePublicKeyOrFail(node.PublicKey())
	if encodeErr != nil {
		shownAs = ""
	}

	// Only public material is rendered. The private key has no path to stdout.
	if *asJSON {
		encoded, err := json.Marshal(struct {
			PublicKey string `json:"public_key"`
			ShownAs   string `json:"shown_as,omitempty"`
			CreatedAt string `json:"created_at"`
		}{
			PublicKey: node.PublicKey().String(),
			ShownAs:   shownAs,
			CreatedAt: node.CreatedAt().UTC().Format(time.RFC3339),
		})
		if err != nil {
			stderr.printf("nostmesh identity show: %v\n", err)
			return exitError
		}
		stdout.printf("%s\n", encoded)
		return exitOK
	}

	if *format == "npub" {
		if shownAs == "" {
			stderr.printf("nostmesh identity show: this build cannot render the npub form\n")
			return exitError
		}
		stdout.printf("public key: %s\n", shownAs)
	} else {
		stdout.printf("public key: %s\n", node.PublicKey())
	}
	stdout.printf("created:    %s\n", node.CreatedAt().UTC().Format(time.RFC3339))

	return exitOK
}

// runIdentityImport adopts a Nostr identity the operator already has.
//
// The key is read from standard input, never from a flag. Anything on a command
// line is written to shell history, is visible in the process list to every
// user on the host, and is readable from /proc for as long as the process runs.
// A key that has been through any of those is a key that has to be treated as
// exposed, so the command does not offer the option.
func runIdentityImport(args []string, stdout, stderr *output) int {
	flags := flag.NewFlagSet("identity import", flag.ContinueOnError)
	flags.SetOutput(stderr.w)
	stateDir := flags.String("state-dir", "", "directory holding local state (required)")
	fromFile := flags.String("from-file", "", "read the key from this file instead of standard input")

	flags.Usage = func() {
		stderr.printf("Usage: nostmesh identity import --state-dir <path> [--from-file <path>]\n\n" +
			"Adopt a Nostr identity you already have, so this node signs as an\n" +
			"identity your peers may already know.\n\n" +
			"The key is read from standard input; paste it and press Ctrl-D. It is\n" +
			"accepted in the form other Nostr applications export, or as 64\n" +
			"hexadecimal characters.\n\n" +
			"It is never taken as a command-line argument: anything on a command\n" +
			"line is recorded in shell history and visible to every user on this\n" +
			"host through the process list.\n\nFlags:\n")
		flags.PrintDefaults()
	}

	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if *stateDir == "" {
		stderr.printf("nostmesh identity import: --state-dir is required\n")
		return exitUsage
	}

	supplied, err := readKeyInput(*fromFile)
	if err != nil {
		stderr.printf("nostmesh identity import: %v\n", err)
		return exitError
	}
	defer zeroString(&supplied)

	private, err := identity.DecodePrivateKeyOrFail(supplied)
	if err != nil {
		stderr.printf("nostmesh identity import: %v\n", err)
		stderr.printf("%s\n", importHint(err))
		return exitError
	}

	// Deriving is what proves the key is usable. The domain type checks length
	// and refuses an all-zero key, but a 32-byte number can still be outside
	// the curve's group order — and such a key would store cleanly, then fail
	// to sign anything, which is a far worse moment to discover it.
	public, err := identity.DeriveNostrPublicKey(private)
	if err != nil {
		stderr.printf("nostmesh identity import: the key is not a usable secp256k1 private key\n")
		return exitError
	}

	node, err := domain.NewNodeIdentity(public, private, time.Now().UTC())
	if err != nil {
		stderr.printf("nostmesh identity import: %v\n", err)
		return exitError
	}

	keystore := identity.NewDevelopmentKeystore(defaultKeystorePath(*stateDir), domain.SystemClock{})
	if err := keystore.Store(node); err != nil {
		stderr.printf("nostmesh identity import: %v\n", err)
		if errors.Is(err, identity.ErrIdentityExists) {
			stderr.printf("\nImporting over it would strand every peer that authorized the current key.\n")
			stderr.printf("To replace it deliberately, move the existing file aside, run this again,\n")
			stderr.printf("and give every peer the new public key.\n")
		}
		return exitError
	}

	stdout.printf("identity imported\n")
	stdout.printf("  public key: %s\n", public.String())
	if encoded, encodeErr := identity.EncodePublicKeyOrFail(public); encodeErr == nil {
		stdout.printf("  shown as:   %s\n", encoded)
	}
	stdout.printf("  stored in:  %s\n", keystore.Path())
	stdout.printf("\nCheck that against what the application you exported from shows.\n")
	stdout.printf("\nnote: this node now signs as an identity you use elsewhere. Its signalling\n")
	stdout.printf("      events and your other activity share a public key, which links them\n")
	stdout.printf("      on any relay that keeps them. A separate identity avoids that.\n")
	stdout.printf("\n%s\n", identity.DevelopmentWarning)

	return exitOK
}

// importHint turns a decoding failure into the next thing to try.
func importHint(err error) string {
	switch {
	case errors.Is(err, nostr.ErrPublicKeySupplied):
		return "that is the key you publish. Import needs the private one, which your application warns you never to share."
	case errors.Is(err, nostr.ErrEncryptedKeyUnsupported):
		return "decrypt it in the application that produced it, then import the decrypted key."
	case errors.Is(err, nostr.ErrKeyOutOfRange):
		return "a private key is a number below the secp256k1 group order; this one is not, so it is not the key it appears to be."
	case errors.Is(err, nostr.ErrBech32Checksum):
		return "the checksum does not match, which usually means a character was mistyped or the paste was cut short."
	default:
		return "expected the form other Nostr applications export, or 64 hexadecimal characters."
	}
}

// maxKeyInput bounds what will be read, so a misdirected file fails at once
// rather than being buffered as though it were a key.
const maxKeyInput = 4096

// readKeyInput reads the supplied key from a file or from standard input.
func readKeyInput(fromFile string) (string, error) {
	source := stdin

	if fromFile != "" {
		info, err := os.Stat(fromFile)
		if err != nil {
			return "", err
		}
		// The same rule the keystore applies to its own file: a key readable by
		// others has to be treated as already exposed, and tightening the mode
		// here would hide that rather than fix it.
		if mode := info.Mode().Perm(); mode&0o077 != 0 {
			return "", fmt.Errorf("%s has mode %#o; a key file readable by others may already be exposed", fromFile, mode)
		}

		// The path is the operator's own argument, naming a file they are
		// telling this command to read. Its permissions were checked above.
		file, err := os.Open(fromFile) //nolint:gosec // the operator names the file to read
		if err != nil {
			return "", err
		}
		defer func() { _ = file.Close() }()
		source = file
	}

	raw, err := io.ReadAll(io.LimitReader(source, maxKeyInput+1))
	if err != nil {
		return "", fmt.Errorf("reading the key: %w", err)
	}
	if len(raw) > maxKeyInput {
		return "", errors.New("input is too large to be a key")
	}

	supplied := strings.TrimSpace(string(raw))
	zero(raw)
	if supplied == "" {
		return "", errors.New("no key was supplied")
	}
	return supplied, nil
}

// zeroString overwrites a string's backing bytes where the runtime allows it.
//
// Go strings are immutable, so this cannot scrub the original allocation. It
// drops the reference so the value is collectable rather than lingering for the
// life of the process, which is the most this backend can offer — the same
// backend that writes the key to disk unencrypted.
func zeroString(s *string) { *s = "" }

// zero overwrites a byte slice.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
