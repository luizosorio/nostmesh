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
	"os"
	"path/filepath"
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
