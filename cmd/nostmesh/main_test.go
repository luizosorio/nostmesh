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
