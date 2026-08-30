package identity

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/luizosorio/nostmesh/internal/domain"
)

// DevelopmentWarning is stated wherever the file keystore is used.
//
// It is not decoration. A private key sitting in a file is readable by anything
// running as this user, survives in backups and snapshots, and offers no
// protection if the host is compromised. Production deployments are expected to
// use an external signer that never surrenders the key.
const DevelopmentWarning = "the file keystore stores a private key on disk unprotected and is for development only"

// keyFileMode is the only acceptable permission set: readable and writable by
// the owner alone.
const keyFileMode fs.FileMode = 0o600

// keyDirMode restricts the containing directory to its owner.
const keyDirMode fs.FileMode = 0o700

var (
	// ErrNoIdentity reports that no identity has been stored yet.
	ErrNoIdentity = errors.New("no identity found")

	// ErrIdentityExists reports an attempt to overwrite an existing identity.
	//
	// Overwriting is refused rather than confirmed: replacing an identity
	// silently would revoke every authorization a peer has granted this node,
	// with no way to recover the previous key.
	ErrIdentityExists = errors.New("an identity already exists")

	// ErrInsecurePermissions reports a key file readable beyond its owner.
	ErrInsecurePermissions = errors.New("key file permissions are too permissive")
)

// DevelopmentKeystore stores the node identity in a protected file.
//
// It implements Keystore for development and testing. Writes are atomic, so an
// interrupted write cannot corrupt an existing key, and permissions are
// verified on every read.
type DevelopmentKeystore struct {
	path  string
	clock domain.Clock
}

// NewDevelopmentKeystore returns a keystore backed by the file at path.
func NewDevelopmentKeystore(path string, clock domain.Clock) *DevelopmentKeystore {
	if clock == nil {
		clock = domain.SystemClock{}
	}
	return &DevelopmentKeystore{path: path, clock: clock}
}

// Path returns the file backing this keystore.
func (k *DevelopmentKeystore) Path() string { return k.path }

// storedIdentity is the on-disk representation.
//
// Only the Nostr identity is persisted. WireGuard keys are ephemeral by design:
// they are generated per session and must not outlive it, so there is nothing
// here to store them in.
type storedIdentity struct {
	Version   int    `json:"version"`
	PublicKey string `json:"public_key"`
	// Storing the private key is what this development keystore is for; the
	// file is owner-only and NM-06 documents why this backend is not for
	// production.
	PrivateKey string `json:"private_key"` //nolint:gosec // development keystore by design
	CreatedAt  string `json:"created_at"`
	Warning    string `json:"warning"`
}

const storedIdentityVersion = 1

// Exists reports whether an identity is already stored.
func (k *DevelopmentKeystore) Exists() (bool, error) {
	_, err := os.Stat(k.path)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	default:
		return false, fmt.Errorf("checking keystore: %w", err)
	}
}

// Load reads the stored identity, refusing a file with unsafe permissions.
func (k *DevelopmentKeystore) Load() (domain.NodeIdentity, error) {
	info, err := os.Stat(k.path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return domain.NodeIdentity{}, fmt.Errorf("%w at %s", ErrNoIdentity, k.path)
		}
		return domain.NodeIdentity{}, fmt.Errorf("reading keystore: %w", err)
	}

	// A key readable by group or others is treated as compromised rather than
	// quietly repaired: tightening the mode would not undo whoever already read
	// it, and silently continuing would hide that from the operator.
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return domain.NodeIdentity{}, fmt.Errorf("%w: %s has mode %04o, expected %04o; the key may already be exposed, generate a new identity",
			ErrInsecurePermissions, k.path, perm, keyFileMode)
	}

	content, err := os.ReadFile(k.path)
	if err != nil {
		return domain.NodeIdentity{}, fmt.Errorf("reading keystore: %w", err)
	}

	var stored storedIdentity
	if err := json.Unmarshal(content, &stored); err != nil {
		return domain.NodeIdentity{}, fmt.Errorf("keystore at %s is corrupt: %w", k.path, err)
	}
	if stored.Version != storedIdentityVersion {
		return domain.NodeIdentity{}, fmt.Errorf("keystore at %s has unsupported version %d", k.path, stored.Version)
	}

	return k.decode(stored)
}

func (k *DevelopmentKeystore) decode(stored storedIdentity) (domain.NodeIdentity, error) {
	public, err := domain.ParseNostrPublicKey(stored.PublicKey)
	if err != nil {
		return domain.NodeIdentity{}, fmt.Errorf("keystore at %s has an invalid public key: %w", k.path, err)
	}

	rawPrivate, err := hex.DecodeString(stored.PrivateKey)
	if err != nil {
		return domain.NodeIdentity{}, fmt.Errorf("keystore at %s has an invalid private key encoding", k.path)
	}

	private, err := domain.NewNostrPrivateKey(rawPrivate)
	zero(rawPrivate)
	if err != nil {
		return domain.NodeIdentity{}, fmt.Errorf("keystore at %s has an invalid private key: %w", k.path, err)
	}

	created, err := time.Parse(time.RFC3339, stored.CreatedAt)
	if err != nil {
		return domain.NodeIdentity{}, fmt.Errorf("keystore at %s has an invalid creation time: %w", k.path, err)
	}

	return domain.NewNodeIdentity(public, private, created)
}

// Store writes an identity, refusing to overwrite an existing one.
//
// The write is atomic: content goes to a temporary file in the same directory,
// is synced, and is then renamed over the target. A crash at any point leaves
// either the previous key intact or no key at all — never a truncated one.
func (k *DevelopmentKeystore) Store(identity domain.NodeIdentity) error {
	exists, err := k.Exists()
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("%w at %s; remove it explicitly if you intend to replace it", ErrIdentityExists, k.path)
	}

	if err := os.MkdirAll(filepath.Dir(k.path), keyDirMode); err != nil {
		return fmt.Errorf("creating keystore directory: %w", err)
	}

	encoded, err := k.encode(identity)
	if err != nil {
		return err
	}
	defer zero(encoded)

	return k.writeAtomic(encoded)
}

func (k *DevelopmentKeystore) encode(identity domain.NodeIdentity) ([]byte, error) {
	private := identity.PrivateKey()

	// HexForKeystore is the sanctioned escape from the secret type, and this is
	// the only place in the codebase that may call it.
	privateHex, err := private.HexForKeystore()
	if err != nil {
		return nil, fmt.Errorf("encoding identity: %w", err)
	}

	stored := storedIdentity{
		Version:    storedIdentityVersion,
		PublicKey:  identity.PublicKey().String(),
		PrivateKey: privateHex,
		CreatedAt:  identity.CreatedAt().UTC().Format(time.RFC3339),
		Warning:    DevelopmentWarning,
	}

	// Serializing the private key is the purpose of this development keystore.
	// The file is owner-only, written atomically, and NM-06 records why this
	// backend must not be used in production.
	encoded, err := json.MarshalIndent(stored, "", "  ") //nolint:gosec // development keystore by design
	if err != nil {
		return nil, fmt.Errorf("encoding identity: %w", err)
	}
	return append(encoded, '\n'), nil
}

func (k *DevelopmentKeystore) writeAtomic(content []byte) (err error) {
	dir := filepath.Dir(k.path)

	temp, err := os.CreateTemp(dir, ".nostmesh-key-*")
	if err != nil {
		return fmt.Errorf("creating temporary key file: %w", err)
	}
	tempPath := temp.Name()

	// Any failure past this point must leave nothing behind: a temporary file
	// holding key material is exactly what this function exists to avoid.
	defer func() {
		if err != nil {
			_ = temp.Close()
			_ = os.Remove(tempPath)
		}
	}()

	// Restrict the file before writing, so the secret is never briefly readable.
	if err = temp.Chmod(keyFileMode); err != nil {
		return fmt.Errorf("restricting temporary key file: %w", err)
	}
	if _, err = temp.Write(content); err != nil {
		return fmt.Errorf("writing temporary key file: %w", err)
	}
	// Sync before rename: without it a crash can leave the rename durable but
	// the content not, producing an empty key file.
	if err = temp.Sync(); err != nil {
		return fmt.Errorf("syncing temporary key file: %w", err)
	}
	if err = temp.Close(); err != nil {
		return fmt.Errorf("closing temporary key file: %w", err)
	}
	if err = os.Rename(tempPath, k.path); err != nil {
		return fmt.Errorf("installing key file: %w", err)
	}

	return syncDir(dir)
}

// syncDir flushes the directory entry so the rename itself is durable.
func syncDir(dir string) error {
	// The directory is derived from the operator-supplied state path.
	handle, err := os.Open(dir) //nolint:gosec // operator-supplied path by design
	if err != nil {
		return fmt.Errorf("opening keystore directory: %w", err)
	}
	defer func() { _ = handle.Close() }()

	if err := handle.Sync(); err != nil {
		return fmt.Errorf("syncing keystore directory: %w", err)
	}
	return nil
}
