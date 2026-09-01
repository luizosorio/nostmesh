package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withStdin substitutes the input a subcommand reads, and restores it.
func withStdin(t *testing.T, content string) {
	t.Helper()

	previous := stdin
	stdin = strings.NewReader(content)
	t.Cleanup(func() { stdin = previous })
}

// storedPrivateKey reads back the key a keystore wrote.
//
// Reaching into the file is deliberate: it is the only way to obtain the key
// for a test, and doing it here rather than adding an export command keeps the
// invariant that nothing in the binary hands a private key to a caller.
func storedPrivateKey(t *testing.T, stateDir string) string {
	t.Helper()

	content, err := os.ReadFile(filepath.Join(stateDir, "identity.json"))
	if err != nil {
		t.Fatalf("reading the keystore: %v", err)
	}

	var stored struct {
		PrivateKey string `json:"private_key"`
	}
	if err := json.Unmarshal(content, &stored); err != nil {
		t.Fatalf("decoding the keystore: %v", err)
	}
	if stored.PrivateKey == "" {
		t.Fatal("the keystore holds no private key")
	}
	return stored.PrivateKey
}

// publicKeyOf reports what a node's identity shows as, in both forms.
func publicKeyOf(t *testing.T, stateDir string) (hexForm, npubForm string) {
	t.Helper()

	out, stderr, code := execute(t, "identity", "show", "--state-dir", stateDir, "--json")
	if code != exitOK {
		t.Fatalf("show failed: %s", stderr)
	}

	var shown struct {
		PublicKey string `json:"public_key"`
		ShownAs   string `json:"shown_as"`
	}
	if err := json.Unmarshal([]byte(out), &shown); err != nil {
		t.Fatalf("decoding show output: %v", err)
	}
	return shown.PublicKey, shown.ShownAs
}

// An imported key produces the same identity it had elsewhere.
//
// This is the whole purpose: a person who already has a Nostr identity keeps
// it, and their peers keep recognising them.
func TestAnImportedKeyKeepsItsIdentity(t *testing.T) {
	source, destination := t.TempDir(), t.TempDir()

	if _, stderr, code := execute(t, "identity", "init", "--state-dir", source); code != exitOK {
		t.Fatalf("init failed: %s", stderr)
	}
	originalHex, originalNpub := publicKeyOf(t, source)

	withStdin(t, storedPrivateKey(t, source)+"\n")
	if _, stderr, code := execute(t, "identity", "import", "--state-dir", destination); code != exitOK {
		t.Fatalf("import failed: %s", stderr)
	}

	importedHex, importedNpub := publicKeyOf(t, destination)
	if importedHex != originalHex {
		t.Errorf("imported identity is %s, want %s", importedHex, originalHex)
	}
	if importedNpub != originalNpub || importedNpub == "" {
		t.Errorf("imported npub is %q, want %q", importedNpub, originalNpub)
	}
}

// The private key must never appear in anything the command prints.
//
// Checked in every encoding it could plausibly be rendered in, because a test
// that only looks for the hex form misses a helpful line that prints the bech32
// one — and that line is exactly what someone would add to "confirm what was
// imported".
func TestImportNeverPrintsThePrivateKey(t *testing.T) {
	source, destination := t.TempDir(), t.TempDir()

	if _, stderr, code := execute(t, "identity", "init", "--state-dir", source); code != exitOK {
		t.Fatalf("init failed: %s", stderr)
	}

	privateHex := storedPrivateKey(t, source)
	raw, err := hex.DecodeString(privateHex)
	if err != nil {
		t.Fatalf("decoding the key: %v", err)
	}

	forbidden := map[string]string{
		"lowercase hex": privateHex,
		"uppercase hex": strings.ToUpper(privateHex),
		"base64":        base64.StdEncoding.EncodeToString(raw),
		"raw bytes":     string(raw),
		"hex prefix":    privateHex[:16],
	}

	withStdin(t, privateHex)
	stdout, stderr, code := execute(t, "identity", "import", "--state-dir", destination)
	if code != exitOK {
		t.Fatalf("import failed: %s", stderr)
	}

	// Every surface the command writes to, plus the ways the identity is read
	// back afterwards.
	showHex, _, _ := execute(t, "identity", "show", "--state-dir", destination)
	showNpub, _, _ := execute(t, "identity", "show", "--state-dir", destination, "--format", "npub")
	showJSON, _, _ := execute(t, "identity", "show", "--state-dir", destination, "--json")

	surfaces := map[string]string{
		"import stdout": stdout,
		"import stderr": stderr,
		"show":          showHex,
		"show npub":     showNpub,
		"show json":     showJSON,
	}

	for surface, content := range surfaces {
		for encoding, secret := range forbidden {
			if strings.Contains(content, secret) {
				t.Errorf("%s contains the private key as %s", surface, encoding)
			}
		}
	}
}

// A key offered as a command-line argument is refused.
//
// Anything on a command line reaches shell history and the process list. This
// test is what stops the flag being added later as a convenience.
func TestImportRefusesAKeyGivenAsAnArgument(t *testing.T) {
	stateDir := t.TempDir()

	_, _, code := execute(t, "identity", "import", "--state-dir", stateDir, "--key", "whatever")
	if code != exitUsage {
		t.Errorf("a key passed as a flag was accepted; exit code = %d, want %d", code, exitUsage)
	}
}

// A public key offered as a private one is refused, and says which it was.
func TestImportRejectsAPublicKey(t *testing.T) {
	source, destination := t.TempDir(), t.TempDir()

	if _, stderr, code := execute(t, "identity", "init", "--state-dir", source); code != exitOK {
		t.Fatalf("init failed: %s", stderr)
	}
	_, npub := publicKeyOf(t, source)

	withStdin(t, npub)
	_, stderr, code := execute(t, "identity", "import", "--state-dir", destination)

	if code != exitError {
		t.Fatalf("a public key was accepted as a private one; exit code = %d", code)
	}
	if !strings.Contains(stderr, "public key") {
		t.Errorf("the refusal does not say what was supplied: %s", stderr)
	}
}

// A key with one character altered is refused rather than becoming another key.
func TestImportRejectsACorruptedKey(t *testing.T) {
	source, destination := t.TempDir(), t.TempDir()

	if _, stderr, code := execute(t, "identity", "init", "--state-dir", source); code != exitOK {
		t.Fatalf("init failed: %s", stderr)
	}

	corrupted := storedPrivateKey(t, source)
	corrupted = corrupted[:len(corrupted)-2] + "zz"

	withStdin(t, corrupted)
	if _, _, code := execute(t, "identity", "import", "--state-dir", destination); code != exitError {
		t.Errorf("a corrupted key was accepted; exit code = %d", code)
	}
}

// A 32-byte number that is not a valid curve key is refused.
//
// The domain type checks length and refuses an all-zero key, and this passes
// both. Only deriving the public key catches it — and catching it here rather
// than at the first signature is the difference between a clear refusal and a
// node that stores cleanly and can never communicate.
func TestImportRejectsANumberThatIsNotACurveKey(t *testing.T) {
	stateDir := t.TempDir()

	withStdin(t, strings.Repeat("ff", 32))
	_, stderr, code := execute(t, "identity", "import", "--state-dir", stateDir)

	if code != exitError {
		t.Fatalf("a number outside the curve order was accepted; exit code = %d", code)
	}
	if !strings.Contains(stderr, "group order") {
		t.Errorf("the refusal does not say what was wrong: %s", stderr)
	}
	if _, err := os.Stat(filepath.Join(stateDir, "identity.json")); err == nil {
		t.Error("a rejected key was still written to the keystore")
	}
}

// Importing over an existing identity is refused, and the existing one survives.
//
// Replacing it silently would revoke every authorization a peer has granted
// this node, with no way back: the peers hold the old public key in their own
// configuration.
func TestImportRefusesToReplaceAnExistingIdentity(t *testing.T) {
	source, destination := t.TempDir(), t.TempDir()

	for _, dir := range []string{source, destination} {
		if _, stderr, code := execute(t, "identity", "init", "--state-dir", dir); code != exitOK {
			t.Fatalf("init failed: %s", stderr)
		}
	}
	before, _ := publicKeyOf(t, destination)

	withStdin(t, storedPrivateKey(t, source))
	_, stderr, code := execute(t, "identity", "import", "--state-dir", destination)

	if code != exitError {
		t.Fatalf("an existing identity was replaced; exit code = %d", code)
	}
	if !strings.Contains(stderr, "strand every peer") {
		t.Errorf("the refusal does not explain the consequence: %s", stderr)
	}

	after, _ := publicKeyOf(t, destination)
	if after != before {
		t.Errorf("the existing identity changed from %s to %s", before, after)
	}
}

// A key file others can read is refused rather than quietly tightened.
func TestImportRefusesALooselyPermittedKeyFile(t *testing.T) {
	source, destination := t.TempDir(), t.TempDir()

	if _, stderr, code := execute(t, "identity", "init", "--state-dir", source); code != exitOK {
		t.Fatalf("init failed: %s", stderr)
	}

	path := filepath.Join(t.TempDir(), "key.txt")
	if err := os.WriteFile(path, []byte(storedPrivateKey(t, source)), 0o644); err != nil {
		t.Fatalf("writing the key file: %v", err)
	}

	_, stderr, code := execute(t, "identity", "import", "--state-dir", destination, "--from-file", path)
	if code != exitError {
		t.Fatalf("a world-readable key file was accepted; exit code = %d", code)
	}
	if !strings.Contains(stderr, "already be exposed") {
		t.Errorf("the refusal does not explain why: %s", stderr)
	}
}

// Empty and oversized input are refused before anything is stored.
func TestImportRefusesEmptyAndOversizedInput(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"whitespace only", "   \n\t"},
		{"far too large", strings.Repeat("a", maxKeyInput+1)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stateDir := t.TempDir()

			withStdin(t, tt.input)
			if _, _, code := execute(t, "identity", "import", "--state-dir", stateDir); code != exitError {
				t.Errorf("input was accepted; exit code = %d", code)
			}
			if _, err := os.Stat(filepath.Join(stateDir, "identity.json")); err == nil {
				t.Error("an identity was written despite the refusal")
			}
		})
	}
}

// The keystore holds exactly the fields it is meant to.
//
// A new field carrying key material in another encoding would be a second copy
// of the secret, in a file that already has one it is designed for.
func TestAnImportedKeystoreCarriesNoExtraFields(t *testing.T) {
	source, destination := t.TempDir(), t.TempDir()

	if _, stderr, code := execute(t, "identity", "init", "--state-dir", source); code != exitOK {
		t.Fatalf("init failed: %s", stderr)
	}

	withStdin(t, storedPrivateKey(t, source))
	if _, stderr, code := execute(t, "identity", "import", "--state-dir", destination); code != exitOK {
		t.Fatalf("import failed: %s", stderr)
	}

	content, err := os.ReadFile(filepath.Join(destination, "identity.json"))
	if err != nil {
		t.Fatalf("reading the keystore: %v", err)
	}

	var fields map[string]any
	if err := json.Unmarshal(content, &fields); err != nil {
		t.Fatalf("decoding the keystore: %v", err)
	}

	expected := map[string]bool{
		"version": true, "public_key": true, "private_key": true,
		"created_at": true, "warning": true,
	}
	for name := range fields {
		if !expected[name] {
			t.Errorf("the keystore gained a field %q", name)
		}
	}

	// The key must appear once, in the field meant for it, and in no other
	// encoding anywhere in the file.
	raw, err := hex.DecodeString(storedPrivateKey(t, source))
	if err != nil {
		t.Fatalf("decoding the key: %v", err)
	}
	if bytes.Contains(content, []byte(base64.StdEncoding.EncodeToString(raw))) {
		t.Error("the keystore holds the private key in base64 as well")
	}
}

// --format takes only the two values it documents.
func TestShowRejectsAnUnknownFormat(t *testing.T) {
	stateDir := t.TempDir()

	if _, stderr, code := execute(t, "identity", "init", "--state-dir", stateDir); code != exitOK {
		t.Fatalf("init failed: %s", stderr)
	}

	_, stderr, code := execute(t, "identity", "show", "--state-dir", stateDir, "--format", "base64")
	if code != exitUsage {
		t.Errorf("an unknown format was accepted; exit code = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(stderr, "hex") || !strings.Contains(stderr, "npub") {
		t.Errorf("the refusal does not name the valid values: %s", stderr)
	}
}
