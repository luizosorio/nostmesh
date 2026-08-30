package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const secondPeerKey = "GkiQFKn8kJVCEG9EJHQdCVJEQQ2c3wVBpU3zZbCfvVI="

func writeEmptyConfig(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "nostmesh.json")
	content := `{"node": {"name": "lab", "state_dir": "/var/lib/nostmesh"}}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing configuration: %v", err)
	}
	return path
}

func addPeer(t *testing.T, configPath, name, key string, allowed string) (string, string, int) {
	t.Helper()

	return execute(t, "peer", "add",
		"--config", configPath,
		"--name", name,
		"--public-key", key,
		"--endpoint", "198.51.100.10:51820",
		"--overlay-address", "100.96.0.2/32",
		"--allowed-ips", allowed)
}

func TestPeerAddThenList(t *testing.T) {
	configPath := writeEmptyConfig(t)

	stdout, stderr, code := addPeer(t, configPath, "lab-b", secondPeerKey, "100.96.0.2/32")
	if code != exitOK {
		t.Fatalf("adding peer: exit %d (stderr: %s)", code, stderr)
	}
	if !strings.Contains(stdout, "added peer lab-b") {
		t.Errorf("expected a confirmation, got: %q", stdout)
	}

	stdout, stderr, code = execute(t, "peer", "list", "--config", configPath)
	if code != exitOK {
		t.Fatalf("listing peers: exit %d (stderr: %s)", code, stderr)
	}
	for _, want := range []string{"lab-b", secondPeerKey, "198.51.100.10:51820"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("list must mention %q, got: %q", want, stdout)
		}
	}
}

func TestPeerListJSON(t *testing.T) {
	configPath := writeEmptyConfig(t)

	if _, stderr, code := addPeer(t, configPath, "lab-b", secondPeerKey, "100.96.0.2/32"); code != exitOK {
		t.Fatalf("adding peer: %s", stderr)
	}

	stdout, _, code := execute(t, "peer", "list", "--config", configPath, "--json")
	if code != exitOK {
		t.Fatalf("exit code = %d", code)
	}

	var peers []struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal([]byte(stdout), &peers); err != nil {
		t.Fatalf("output must be valid JSON: %v (%q)", err, stdout)
	}
	if len(peers) != 1 || peers[0].Name != "lab-b" {
		t.Errorf("expected one peer named lab-b, got %v", peers)
	}
}

func TestPeerRemove(t *testing.T) {
	configPath := writeEmptyConfig(t)

	if _, stderr, code := addPeer(t, configPath, "lab-b", secondPeerKey, "100.96.0.2/32"); code != exitOK {
		t.Fatalf("adding peer: %s", stderr)
	}

	stdout, stderr, code := execute(t, "peer", "remove", "--config", configPath, "--name", "lab-b")
	if code != exitOK {
		t.Fatalf("removing peer: exit %d (stderr: %s)", code, stderr)
	}
	if !strings.Contains(stdout, "removed peer lab-b") {
		t.Errorf("expected a confirmation, got: %q", stdout)
	}

	stdout, _, _ = execute(t, "peer", "list", "--config", configPath)
	if !strings.Contains(stdout, "no peers configured") {
		t.Errorf("the peer must be gone, got: %q", stdout)
	}
}

func TestPeerRemoveUnknown(t *testing.T) {
	configPath := writeEmptyConfig(t)

	_, stderr, code := execute(t, "peer", "remove", "--config", configPath, "--name", "absent")
	if code != exitError {
		t.Errorf("exit code = %d, want %d", code, exitError)
	}
	if !strings.Contains(stderr, "no peer named") {
		t.Errorf("error must say the peer is unknown, got: %q", stderr)
	}
}

func TestPeerAddRejectsDuplicateName(t *testing.T) {
	configPath := writeEmptyConfig(t)

	if _, stderr, code := addPeer(t, configPath, "lab-b", secondPeerKey, "100.96.0.2/32"); code != exitOK {
		t.Fatalf("adding peer: %s", stderr)
	}

	_, stderr, code := addPeer(t, configPath, "lab-b", "iOBxLBRuVMFEnLBVDkPMz1x0dQlpTAiJEHrTNCXqGmM=", "100.96.0.3/32")
	if code != exitError {
		t.Errorf("exit code = %d, want %d", code, exitError)
	}
	if !strings.Contains(stderr, "already exists") {
		t.Errorf("error must explain the conflict, got: %q", stderr)
	}
}

// A default route through a manually configured peer would capture all traffic
// including the tunnel's own transport. Adding one must be refused.
func TestPeerAddRejectsDefaultRoute(t *testing.T) {
	for _, prefix := range []string{"0.0.0.0/0", "::/0"} {
		t.Run(prefix, func(t *testing.T) {
			path := writeEmptyConfig(t)
			_, stderr, code := addPeer(t, path, "gateway", secondPeerKey, prefix)

			if code != exitError {
				t.Fatalf("a default route must be refused, exit %d", code)
			}
			if !strings.Contains(stderr, "default route") {
				t.Errorf("error must explain the refusal, got: %q", stderr)
			}
		})
	}
}

// The whole configuration is validated on add, so a conflict that only appears
// when peers are considered together is caught before it reaches the file.
func TestPeerAddRejectsDuplicateKey(t *testing.T) {
	configPath := writeEmptyConfig(t)

	if _, stderr, code := addPeer(t, configPath, "first", secondPeerKey, "100.96.0.2/32"); code != exitOK {
		t.Fatalf("adding peer: %s", stderr)
	}

	_, stderr, code := addPeer(t, configPath, "second", secondPeerKey, "100.96.0.3/32")
	if code != exitError {
		t.Errorf("exit code = %d, want %d", code, exitError)
	}
	if !strings.Contains(stderr, "distinct key") {
		t.Errorf("error must explain the duplicate key, got: %q", stderr)
	}
}

// A refused add must leave the file exactly as it was.
func TestRefusedAddDoesNotModifyConfig(t *testing.T) {
	configPath := writeEmptyConfig(t)

	before, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("reading configuration: %v", err)
	}

	if _, _, code := addPeer(t, configPath, "gateway", secondPeerKey, "0.0.0.0/0"); code != exitError {
		t.Fatal("a default route must be refused")
	}

	after, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("reading configuration: %v", err)
	}
	if string(before) != string(after) {
		t.Error("a refused add modified the configuration file")
	}
}

func TestPeerArguments(t *testing.T) {
	configPath := writeEmptyConfig(t)

	tests := []struct {
		name string
		args []string
	}{
		{"add without config", []string{"peer", "add", "--name", "x"}},
		{"add without name", []string{"peer", "add", "--config", configPath}},
		{"list without config", []string{"peer", "list"}},
		{"remove without name", []string{"peer", "remove", "--config", configPath}},
		{"unknown subcommand", []string{"peer", "nonexistent"}},
		{"no subcommand", []string{"peer"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, code := execute(t, tt.args...); code != exitUsage {
				t.Errorf("exit code = %d, want %d", code, exitUsage)
			}
		})
	}
}
