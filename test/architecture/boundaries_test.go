// Package architecture enforces the project's internal dependency rules.
//
// NostMesh is a single, self-contained binary, but that alone does not keep it
// coherent. The core must stay free of the operating system so that porting to
// another platform is an adapter, not a rewrite. These tests fail the build the
// moment that boundary is crossed.
package architecture

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// corePackages must remain free of operating-system dependencies. They hold
// pure domain logic: types, state machines, validation and policy decisions.
var corePackages = []string{
	"internal/domain",
	"internal/protocol",
	"internal/policy",
	"internal/config",
}

// forbiddenInCore lists import prefixes that couple a package to a platform.
var forbiddenInCore = []string{
	"syscall",
	"os/exec",
	"golang.org/x/sys",
	"github.com/vishvananda/netlink",
	"github.com/google/nftables",
	"golang.zx2c4.com/wireguard",
}

// adapterPackages hold platform-specific code. They may import the core, but
// the core must never import them.
var adapterPackages = []string{
	"internal/wireguard",
	"internal/netstate",
}

func repoRoot(t *testing.T) string {
	t.Helper()

	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolving repository root: %v", err)
	}
	return root
}

// TestCoreDoesNotImportOperatingSystem keeps the domain portable. A violation
// here means the core can no longer be compiled for another platform without
// dragging Linux along.
func TestCoreDoesNotImportOperatingSystem(t *testing.T) {
	root := repoRoot(t)

	for _, pkg := range corePackages {
		t.Run(pkg, func(t *testing.T) {
			for _, imp := range importsOf(t, filepath.Join(root, pkg)) {
				for _, forbidden := range forbiddenInCore {
					if imp.path == forbidden || strings.HasPrefix(imp.path, forbidden+"/") {
						t.Errorf("%s imports %q; core packages must stay free of the operating system, put this behind an adapter port",
							imp.file, imp.path)
					}
				}
			}
		})
	}
}

// TestCoreDoesNotImportAdapters keeps dependencies pointing inward. The
// orchestrator emits plans; adapters execute them. The reverse coupling would
// let a platform detail dictate domain behavior.
func TestCoreDoesNotImportAdapters(t *testing.T) {
	root := repoRoot(t)
	const module = "github.com/luizosorio/nostmesh/"

	for _, pkg := range corePackages {
		t.Run(pkg, func(t *testing.T) {
			for _, imp := range importsOf(t, filepath.Join(root, pkg)) {
				for _, adapter := range adapterPackages {
					if imp.path == module+adapter || strings.HasPrefix(imp.path, module+adapter+"/") {
						t.Errorf("%s imports %q; dependencies must point inward, never from the core to an adapter",
							imp.file, imp.path)
					}
				}
			}
		})
	}
}

// TestNoShellOutForNetworkEffects enforces the single-binary contract: network
// state is applied through the kernel, never by driving an external tool whose
// presence, version and output format the binary cannot guarantee.
func TestNoShellOutForNetworkEffects(t *testing.T) {
	root := repoRoot(t)

	for _, pkg := range adapterPackages {
		t.Run(pkg, func(t *testing.T) {
			for _, imp := range importsOf(t, filepath.Join(root, pkg)) {
				if imp.path == "os/exec" {
					t.Errorf("%s imports \"os/exec\"; network effects must go through netlink, not by shelling out to wg, nft or ip",
						imp.file)
				}
			}
		})
	}
}

type importRef struct {
	file string
	path string
}

// importsOf returns every import in a package directory, including test files,
// so a boundary cannot be crossed by a test helper either.
func importsOf(t *testing.T, dir string) []importRef {
	t.Helper()

	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			// A package not yet created cannot violate a boundary. Later
			// deliveries add these; the rule applies as soon as they exist.
			return nil
		}
		t.Fatalf("reading %s: %v", dir, err)
	}

	fset := token.NewFileSet()
	var refs []importRef

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parsing %s: %v", path, err)
		}

		for _, spec := range file.Imports {
			refs = append(refs, importRef{
				file: relative(t, path),
				path: importPath(t, spec),
			})
		}
	}

	return refs
}

func importPath(t *testing.T, spec *ast.ImportSpec) string {
	t.Helper()

	path, err := strconv.Unquote(spec.Path.Value)
	if err != nil {
		t.Fatalf("unquoting import %s: %v", spec.Path.Value, err)
	}
	return path
}

func relative(t *testing.T, path string) string {
	t.Helper()

	rel, err := filepath.Rel(repoRoot(t), path)
	if err != nil {
		return path
	}
	return rel
}

// sanctionedSecretEscapes lists the functions that hand raw key material to a
// caller, and the files permitted to call each one.
//
// These are the only places where a secret leaves the protection of its type.
// Keeping the list here means adding a new escape requires editing this test,
// which is the review prompt the invariant needs.
var sanctionedSecretEscapes = map[string][]string{
	"HexForKeystore":    {"internal/identity/devkeystore.go"},
	"Base64ForKeystore": {"internal/identity/devkeystore.go"},
}

// TestSecretEscapesAreSanctioned enforces NM-06: the encoding methods that
// serialize a private key exist for the development keystore alone. A new
// caller elsewhere is how a secret ends up in a log, an event or a diagnostic
// bundle, so it must be a deliberate, reviewed change rather than an import.
func TestSecretEscapesAreSanctioned(t *testing.T) {
	root := repoRoot(t)

	for method, allowed := range sanctionedSecretEscapes {
		t.Run(method, func(t *testing.T) {
			for _, file := range callersOf(t, root, method) {
				if slices.Contains(allowed, file) {
					continue
				}
				t.Errorf("%s calls %s; this method hands over raw key material and is reserved for %s (see NM-06)",
					file, method, strings.Join(allowed, ", "))
			}
		})
	}
}

// callersOf returns the repository files that reference the given identifier,
// excluding the file that declares it and test files.
func callersOf(t *testing.T, root, identifier string) []string {
	t.Helper()

	var callers []string

	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			// Reference documentation is not part of the module.
			if name := entry.Name(); name == ".git" || name == "nostmesh-docs" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		rel := relative(t, path)

		// The declaring file necessarily mentions the name.
		if strings.Contains(string(content), "func (k ") && strings.Contains(string(content), ") "+identifier+"(") {
			return nil
		}
		if strings.Contains(string(content), "."+identifier+"(") {
			callers = append(callers, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scanning repository: %v", err)
	}

	return callers
}

// transportPackages own the Nostr dependencies. Nothing else may import them.
var transportPackages = []string{
	"internal/nostr",
}

// forbiddenOutsideTransport lists import prefixes that couple a package to the
// Nostr transport or its cryptography.
var forbiddenOutsideTransport = []string{
	"github.com/nbd-wtf/go-nostr",
	"github.com/btcsuite/btcd",
}

// TestProtocolStaysTransportNeutral enforces NM-10: internal/protocol defines
// envelopes and validation over bytes, and must not acquire a dependency on how
// those bytes reach the wire. A protocol coupled to its transport cannot be
// tested without one, and cannot be carried over a second transport later.
func TestProtocolStaysTransportNeutral(t *testing.T) {
	root := repoRoot(t)

	for _, pkg := range corePackages {
		t.Run(pkg, func(t *testing.T) {
			for _, imp := range importsOf(t, filepath.Join(root, pkg)) {
				for _, forbidden := range forbiddenOutsideTransport {
					if strings.HasPrefix(imp.path, forbidden) {
						t.Errorf("%s imports %q; transport and cryptography belong to %s (see NM-10)",
							imp.file, imp.path, strings.Join(transportPackages, ", "))
					}
				}
			}
		})
	}
}

// TestGoNostrRootIsNeverImported enforces the narrower half of NM-10: only the
// nip44 subpackage may be used. The root package pulls in a WebSocket client,
// three JSON libraries and a URL parser, none of which this project needs — the
// relay client is ours to write.
func TestGoNostrRootIsNeverImported(t *testing.T) {
	root := repoRoot(t)
	const forbidden = "github.com/nbd-wtf/go-nostr"

	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if name := entry.Name(); name == ".git" || name == "nostmesh-docs" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}

		for _, imp := range importsInFile(t, path) {
			// Subpackages are permitted; the root is not.
			if imp == forbidden {
				t.Errorf("%s imports the go-nostr root package; import only the subpackage you need (see NM-10)",
					relative(t, path))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scanning repository: %v", err)
	}
}

// privateKeyFieldNames are field names that would carry secret material if any
// serialized structure declared one.
var privateKeyFieldNames = []string{
	`"private_key"`,
	`"privkey"`,
	`"secret_key"`,
	`"wireguard_private"`,
	`"nsec"`,
}

// TestNoPrivateKeyFieldsInWireTypes enforces the project's central invariant:
// a WireGuard private key must never reach an event, the store, a log or a
// diagnostic bundle.
//
// The keystore is the one place that persists key material by design (NM-06),
// so it is exempt. Everywhere else, a struct tag naming a private key is a
// serialization path for a secret, and this test refuses to let one appear
// unnoticed.
func TestNoPrivateKeyFieldsInWireTypes(t *testing.T) {
	root := repoRoot(t)

	exempt := []string{
		// The development keystore persists the identity key deliberately.
		"internal/identity/devkeystore.go",
		// This test necessarily names the patterns it looks for.
		"test/architecture/boundaries_test.go",
	}

	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if name := entry.Name(); name == ".git" || name == "nostmesh-docs" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		rel := relative(t, path)
		if slices.Contains(exempt, rel) {
			return nil
		}

		content, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}

		for _, field := range privateKeyFieldNames {
			if strings.Contains(string(content), field) {
				t.Errorf("%s declares a %s field; private key material must never be serialized (see NM-06)",
					rel, field)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scanning repository: %v", err)
	}
}

// importsInFile returns every import path in one file.
func importsInFile(t *testing.T, path string) []string {
	t.Helper()

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}

	paths := make([]string, 0, len(file.Imports))
	for _, spec := range file.Imports {
		paths = append(paths, importPath(t, spec))
	}
	return paths
}
