package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func execute(t *testing.T, args ...string) (stdout, stderr string, code int) {
	t.Helper()

	var out, errOut bytes.Buffer
	code = run(args, &out, &errOut)
	return out.String(), errOut.String(), code
}

func TestNoArgsShowsUsage(t *testing.T) {
	_, stderr, code := execute(t)

	if code != exitUsage {
		t.Errorf("exit code = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(stderr, "Usage:") {
		t.Errorf("expected usage on stderr, got: %q", stderr)
	}
}

func TestHelpListsEveryCommand(t *testing.T) {
	for _, flag := range []string{"-h", "--help", "help"} {
		t.Run(flag, func(t *testing.T) {
			stdout, _, code := execute(t, flag)

			if code != exitOK {
				t.Errorf("exit code = %d, want %d", code, exitOK)
			}
			for _, cmd := range commands() {
				if !strings.Contains(stdout, cmd.name) {
					t.Errorf("help must list %q, got: %q", cmd.name, stdout)
				}
			}
		})
	}
}

func TestUnknownCommand(t *testing.T) {
	_, stderr, code := execute(t, "nonexistent")

	if code != exitUsage {
		t.Errorf("exit code = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(stderr, "unknown command") {
		t.Errorf("expected an unknown-command message, got: %q", stderr)
	}
}

func TestVersion(t *testing.T) {
	stdout, _, code := execute(t, "version")

	if code != exitOK {
		t.Errorf("exit code = %d, want %d", code, exitOK)
	}
	if !strings.Contains(stdout, "nostmesh") {
		t.Errorf("expected the binary name, got: %q", stdout)
	}
}

func TestVersionJSON(t *testing.T) {
	stdout, _, code := execute(t, "version", "--json")

	if code != exitOK {
		t.Fatalf("exit code = %d, want %d", code, exitOK)
	}

	var info struct {
		Version   string `json:"version"`
		Commit    string `json:"commit"`
		GoVersion string `json:"go_version"`
	}
	if err := json.Unmarshal([]byte(stdout), &info); err != nil {
		t.Fatalf("output must be valid JSON: %v (%q)", err, stdout)
	}
	if info.Version == "" {
		t.Error("version must not be empty")
	}
}

func TestConfigValidateAcceptsValidFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nostmesh.json")
	content := `{
      "node": {"name": "lab", "state_dir": "/var/lib/nostmesh"},
      "peers": [{
        "name": "lab-a",
        "public_key": "iOBxLBRuVMFEnLBVDkPMz1x0dQlpTAiJEHrTNCXqGmM=",
        "endpoint": "198.51.100.10:51820",
        "overlay_address": "100.96.0.2/32",
        "allowed_ips": ["100.96.0.2/32"]
      }]
    }`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing configuration: %v", err)
	}

	stdout, stderr, code := execute(t, "config", "validate", path)

	if code != exitOK {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, exitOK, stderr)
	}
	if !strings.Contains(stdout, "valid") {
		t.Errorf("expected a success message, got: %q", stdout)
	}
}

// An invalid configuration must fail with a non-zero exit code and an
// actionable message naming the offending field.
func TestConfigValidateRejectsInvalidFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nostmesh.json")
	content := `{"node": {"name": "lab", "state_dir": "relative/path"}}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing configuration: %v", err)
	}

	_, stderr, code := execute(t, "config", "validate", path)

	if code != exitError {
		t.Errorf("exit code = %d, want %d", code, exitError)
	}
	if !strings.Contains(stderr, "node.state_dir") {
		t.Errorf("error must name the offending field, got: %q", stderr)
	}
	if !strings.Contains(stderr, "absolute path") {
		t.Errorf("error must state what is required, got: %q", stderr)
	}
}

func TestConfigValidateArguments(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"missing path", []string{"config", "validate"}},
		{"too many paths", []string{"config", "validate", "a.json", "b.json"}},
		{"unknown subcommand", []string{"config", "nonexistent"}},
		{"no subcommand", []string{"config"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, code := execute(t, tt.args...)
			if code != exitUsage {
				t.Errorf("exit code = %d, want %d", code, exitUsage)
			}
		})
	}
}

func TestIdentityInitAndShow(t *testing.T) {
	stateDir := t.TempDir()

	stdout, stderr, code := execute(t, "identity", "init", "--state-dir", stateDir)
	if code != exitOK {
		t.Fatalf("init exit code = %d, want %d (stderr: %s)", code, exitOK, stderr)
	}
	if !strings.Contains(stdout, "identity created") {
		t.Errorf("expected a confirmation, got: %q", stdout)
	}
	if !strings.Contains(stdout, "development only") {
		t.Error("init must warn that the file keystore is not for production")
	}

	stdout, stderr, code = execute(t, "identity", "show", "--state-dir", stateDir)
	if code != exitOK {
		t.Fatalf("show exit code = %d, want %d (stderr: %s)", code, exitOK, stderr)
	}
	if !strings.Contains(stdout, "public key:") {
		t.Errorf("expected the public key, got: %q", stdout)
	}
}

// The private key must have no path to stdout. This reads the stored key and
// asserts it does not appear anywhere the CLI prints.
func TestIdentityShowNeverPrintsPrivateKey(t *testing.T) {
	stateDir := t.TempDir()

	if _, stderr, code := execute(t, "identity", "init", "--state-dir", stateDir); code != exitOK {
		t.Fatalf("init failed: %s", stderr)
	}

	content, err := os.ReadFile(filepath.Join(stateDir, "identity.json"))
	if err != nil {
		t.Fatalf("reading key file: %v", err)
	}

	var stored struct {
		PrivateKey string `json:"private_key"`
	}
	if err := json.Unmarshal(content, &stored); err != nil {
		t.Fatalf("parsing key file: %v", err)
	}
	if stored.PrivateKey == "" {
		t.Fatal("test requires a stored private key")
	}

	for _, args := range [][]string{
		{"identity", "show", "--state-dir", stateDir},
		{"identity", "show", "--state-dir", stateDir, "--json"},
		{"identity", "init", "--state-dir", stateDir},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			stdout, stderr, _ := execute(t, args...)

			if strings.Contains(stdout, stored.PrivateKey) {
				t.Error("the private key reached stdout")
			}
			if strings.Contains(stderr, stored.PrivateKey) {
				t.Error("the private key reached stderr")
			}
		})
	}
}

func TestIdentityShowWithoutIdentity(t *testing.T) {
	_, stderr, code := execute(t, "identity", "show", "--state-dir", t.TempDir())

	if code != exitError {
		t.Errorf("exit code = %d, want %d", code, exitError)
	}
	if !strings.Contains(stderr, "identity init") {
		t.Errorf("error must point at the command that fixes it, got: %q", stderr)
	}
}

func TestIdentityInitRefusesOverwrite(t *testing.T) {
	stateDir := t.TempDir()

	if _, stderr, code := execute(t, "identity", "init", "--state-dir", stateDir); code != exitOK {
		t.Fatalf("first init failed: %s", stderr)
	}

	_, stderr, code := execute(t, "identity", "init", "--state-dir", stateDir)
	if code != exitError {
		t.Errorf("exit code = %d, want %d", code, exitError)
	}
	if !strings.Contains(stderr, "already exists") {
		t.Errorf("error must explain the refusal, got: %q", stderr)
	}
}

func TestIdentityArguments(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"init without state dir", []string{"identity", "init"}},
		{"show without state dir", []string{"identity", "show"}},
		{"unknown subcommand", []string{"identity", "nonexistent"}},
		{"no subcommand", []string{"identity"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, code := execute(t, tt.args...); code != exitUsage {
				t.Errorf("exit code = %d, want %d", code, exitUsage)
			}
		})
	}
}

func writeValidConfig(t *testing.T, stateDir string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "nostmesh.json")
	content := `{
      "node": {"name": "lab", "state_dir": "` + stateDir + `"},
      "peers": [{
        "name": "lab-a",
        "public_key": "iOBxLBRuVMFEnLBVDkPMz1x0dQlpTAiJEHrTNCXqGmM=",
        "endpoint": "198.51.100.10:51820",
        "overlay_address": "100.96.0.2/32",
        "allowed_ips": ["100.96.0.2/32"]
      }]
    }`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing configuration: %v", err)
	}
	return path
}

// Status needs the netlink socket to report observed state. Without privileges
// it must say so rather than emit a raw syscall error.
func TestStatusWithoutPrivileges(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root; this test checks the unprivileged failure path")
	}

	configPath := writeValidConfig(t, t.TempDir())

	_, stderr, code := execute(t, "status", "--config", configPath)
	if code != exitError {
		t.Errorf("exit code = %d, want %d", code, exitError)
	}
	if !strings.Contains(stderr, "nostmesh status") {
		t.Errorf("error must name the command, got: %q", stderr)
	}
}

// Dry run must describe changes without touching anything.
func TestUpDryRunDescribesWithoutApplying(t *testing.T) {
	stateDir := t.TempDir()
	configPath := writeValidConfig(t, stateDir)

	stdout, stderr, code := execute(t, "up", "--config", configPath, "--dry-run")
	if code != exitOK {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, exitOK, stderr)
	}

	for _, want := range []string{"dry run", "no changes", "lab-a"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("dry run must mention %q, got: %q", want, stdout)
		}
	}

	// Nothing may be written to the state directory by a dry run.
	entries, err := os.ReadDir(stateDir)
	if err != nil {
		t.Fatalf("reading state directory: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("dry run wrote to the state directory: %v", entries)
	}
}

// Applying and tearing down need the netlink socket, so without privileges they
// must fail with a message naming the missing prerequisite rather than a raw
// syscall error.
func TestUpAndDownReportMissingPrivileges(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root; this test checks the unprivileged failure path")
	}

	configPath := writeValidConfig(t, t.TempDir())

	for _, command := range []string{"up", "down"} {
		t.Run(command, func(t *testing.T) {
			_, stderr, code := execute(t, command, "--config", configPath)

			if code != exitError {
				t.Errorf("exit code = %d, want %d", code, exitError)
			}
			if !strings.Contains(stderr, "nostmesh "+command) {
				t.Errorf("error must name the command, got: %q", stderr)
			}
		})
	}
}

func TestTunnelCommandsRequireConfig(t *testing.T) {
	for _, command := range []string{"status", "up", "down"} {
		t.Run(command, func(t *testing.T) {
			if _, _, code := execute(t, command); code != exitUsage {
				t.Errorf("exit code = %d, want %d", code, exitUsage)
			}
		})
	}
}
