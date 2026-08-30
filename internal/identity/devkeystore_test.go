package identity

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luizosorio/nostmesh/internal/domain"
)

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

func testClock() fixedClock {
	return fixedClock{now: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
}

func newTestKeystore(t *testing.T) *DevelopmentKeystore {
	t.Helper()
	return NewDevelopmentKeystore(filepath.Join(t.TempDir(), "identity.json"), testClock())
}

func testIdentity(t *testing.T) domain.NodeIdentity {
	t.Helper()

	generator := NewKeyGenerator()
	private, err := generator.GenerateNostrKey()
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	var public domain.NostrPublicKey
	for i := range public {
		public[i] = byte(i + 1)
	}

	identity, err := domain.NewNodeIdentity(public, private, testClock().Now())
	if err != nil {
		t.Fatalf("building identity: %v", err)
	}
	return identity
}

func TestStoreAndLoadRoundTrip(t *testing.T) {
	keystore := newTestKeystore(t)
	original := testIdentity(t)

	if err := keystore.Store(original); err != nil {
		t.Fatalf("storing identity: %v", err)
	}

	loaded, err := keystore.Load()
	if err != nil {
		t.Fatalf("loading identity: %v", err)
	}

	if loaded.PublicKey() != original.PublicKey() {
		t.Error("public key did not survive the round trip")
	}
	if !loaded.PrivateKey().Equal(original.PrivateKey()) {
		t.Error("private key did not survive the round trip")
	}
	if !loaded.CreatedAt().Equal(original.CreatedAt()) {
		t.Errorf("creation time = %s, want %s", loaded.CreatedAt(), original.CreatedAt())
	}
}

// The key file must be owner-only from the moment it exists. A window where it
// is world-readable is a window where it can be copied.
func TestStoredFileIsOwnerOnly(t *testing.T) {
	keystore := newTestKeystore(t)

	if err := keystore.Store(testIdentity(t)); err != nil {
		t.Fatalf("storing identity: %v", err)
	}

	info, err := os.Stat(keystore.Path())
	if err != nil {
		t.Fatalf("inspecting key file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != keyFileMode {
		t.Errorf("mode = %04o, want %04o", perm, keyFileMode)
	}
}

// A key readable beyond its owner is treated as compromised: loading fails
// rather than silently tightening the mode, because tightening would not undo
// whoever already read it.
func TestLoadRejectsInsecurePermissions(t *testing.T) {
	for _, mode := range []os.FileMode{0o644, 0o640, 0o604, 0o666, 0o660} {
		t.Run(mode.String(), func(t *testing.T) {
			keystore := newTestKeystore(t)
			if err := keystore.Store(testIdentity(t)); err != nil {
				t.Fatalf("storing identity: %v", err)
			}
			if err := os.Chmod(keystore.Path(), mode); err != nil {
				t.Fatalf("relaxing permissions: %v", err)
			}

			_, err := keystore.Load()
			if err == nil {
				t.Fatalf("mode %04o must be rejected", mode.Perm())
			}
			if !errors.Is(err, ErrInsecurePermissions) {
				t.Errorf("expected ErrInsecurePermissions, got: %v", err)
			}
			if !strings.Contains(err.Error(), "generate a new identity") {
				t.Errorf("error must tell the operator what to do, got: %v", err)
			}
		})
	}
}

// Overwriting is refused rather than confirmed: replacing an identity silently
// would revoke every authorization peers granted this node, unrecoverably.
func TestStoreRefusesToOverwrite(t *testing.T) {
	keystore := newTestKeystore(t)
	first := testIdentity(t)

	if err := keystore.Store(first); err != nil {
		t.Fatalf("storing identity: %v", err)
	}

	err := keystore.Store(testIdentity(t))
	if err == nil {
		t.Fatal("overwriting an identity must be refused")
	}
	if !errors.Is(err, ErrIdentityExists) {
		t.Errorf("expected ErrIdentityExists, got: %v", err)
	}

	// The original must be untouched.
	loaded, err := keystore.Load()
	if err != nil {
		t.Fatalf("loading identity: %v", err)
	}
	if !loaded.PrivateKey().Equal(first.PrivateKey()) {
		t.Error("the refused write modified the stored key")
	}
}

// An interrupted write must not corrupt an existing key. Since Store refuses to
// overwrite, this checks that a failed write leaves no partial file behind.
func TestFailedWriteLeavesNoResidue(t *testing.T) {
	dir := t.TempDir()
	keystore := NewDevelopmentKeystore(filepath.Join(dir, "sub", "identity.json"), testClock())

	// Make the parent unwritable so the atomic write cannot complete.
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatalf("preparing directory: %v", err)
	}
	if err := os.Chmod(filepath.Join(dir, "sub"), 0o500); err != nil {
		t.Fatalf("restricting directory: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(dir, "sub"), 0o700) })

	if err := keystore.Store(testIdentity(t)); err == nil {
		t.Skip("write succeeded; test requires an unwritable directory (likely running as root)")
	}

	if err := os.Chmod(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatalf("restoring directory: %v", err)
	}

	entries, err := os.ReadDir(filepath.Join(dir, "sub"))
	if err != nil {
		t.Fatalf("reading directory: %v", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".nostmesh-key-") {
			t.Errorf("a temporary key file was left behind: %s", entry.Name())
		}
	}
}

func TestLoadRejectsCorruptFile(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantMsg string
	}{
		{"not json", "this is not json", "corrupt"},
		{"truncated", `{"version": 1, "public_key":`, "corrupt"},
		{"empty", "", "corrupt"},
		{"unsupported version", `{"version": 99, "public_key": "aa"}`, "version"},
		{"bad public key", `{"version": 1, "public_key": "zz", "private_key": "aa", "created_at": "2026-01-01T12:00:00Z"}`, "public key"},
		{"bad private key", `{"version": 1, "public_key": "` + strings.Repeat("01", 32) + `", "private_key": "zz", "created_at": "2026-01-01T12:00:00Z"}`, "private key"},
		{"bad timestamp", `{"version": 1, "public_key": "` + strings.Repeat("01", 32) + `", "private_key": "` + strings.Repeat("02", 32) + `", "created_at": "not a time"}`, "creation time"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "identity.json")
			if err := os.WriteFile(path, []byte(tt.content), keyFileMode); err != nil {
				t.Fatalf("writing test file: %v", err)
			}

			_, err := NewDevelopmentKeystore(path, testClock()).Load()
			if err == nil {
				t.Fatal("a corrupt keystore must be rejected")
			}
			if !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("error must mention %q, got: %v", tt.wantMsg, err)
			}
		})
	}
}

func TestLoadMissingIdentity(t *testing.T) {
	_, err := newTestKeystore(t).Load()

	if err == nil {
		t.Fatal("loading a missing identity must fail")
	}
	if !errors.Is(err, ErrNoIdentity) {
		t.Errorf("expected ErrNoIdentity, got: %v", err)
	}
}

func TestExists(t *testing.T) {
	keystore := newTestKeystore(t)

	exists, err := keystore.Exists()
	if err != nil {
		t.Fatalf("checking existence: %v", err)
	}
	if exists {
		t.Error("a fresh keystore must not report an identity")
	}

	if err := keystore.Store(testIdentity(t)); err != nil {
		t.Fatalf("storing identity: %v", err)
	}

	exists, err = keystore.Exists()
	if err != nil {
		t.Fatalf("checking existence: %v", err)
	}
	if !exists {
		t.Error("a populated keystore must report an identity")
	}
}

// The stored file states that this backend is not for production, so an
// operator who finds the file knows what it is.
func TestStoredFileCarriesDevelopmentWarning(t *testing.T) {
	keystore := newTestKeystore(t)
	if err := keystore.Store(testIdentity(t)); err != nil {
		t.Fatalf("storing identity: %v", err)
	}

	content, err := os.ReadFile(keystore.Path())
	if err != nil {
		t.Fatalf("reading key file: %v", err)
	}

	var stored map[string]any
	if err := json.Unmarshal(content, &stored); err != nil {
		t.Fatalf("parsing key file: %v", err)
	}

	warning, ok := stored["warning"].(string)
	if !ok || !strings.Contains(warning, "development only") {
		t.Errorf("stored file must carry the development warning, got: %v", stored["warning"])
	}
}
