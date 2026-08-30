package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var goldenConfig = `{
  "node": {"name": "lab", "state_dir": "/var/lib/nostmesh"},
  "peers": [{
    "name": "lab-a",
    "public_key": "` + testPeerKey(90) + `",
    "endpoint": "198.51.100.10:51820",
    "overlay_address": "100.96.0.2/32",
    "allowed_ips": ["100.96.0.2/32"]
  }]
}`

func writeConfig(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "nostmesh.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing test configuration: %v", err)
	}
	return path
}

func TestLoadAppliesDefaults(t *testing.T) {
	cfg, err := Load(writeConfig(t, goldenConfig))
	if err != nil {
		t.Fatalf("expected the configuration to load, got: %v", err)
	}

	// The file omits log and policy entirely; both must come from defaults.
	if cfg.Log.Level != "info" || cfg.Log.Format != "json" {
		t.Errorf("log defaults not applied: %+v", cfg.Log)
	}
	if cfg.Policy.DefaultAction != "deny" {
		t.Errorf("policy default not applied: %+v", cfg.Policy)
	}
	if cfg.Policy.AcceptDefaultRoute {
		t.Error("accept_default_route must stay false when omitted")
	}
}

func TestLoadRejects(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantMsg string
	}{
		{
			name:    "malformed json",
			content: `{"node": `,
			wantMsg: "parsing",
		},
		{
			name:    "unknown field",
			content: `{"node": {"name": "lab", "state_dir": "/var/lib/nostmesh"}, "typo": true}`,
			wantMsg: "unknown field",
		},
		{
			name:    "wrong type",
			content: `{"node": {"name": 42, "state_dir": "/var/lib/nostmesh"}}`,
			wantMsg: "expects",
		},
		{
			name:    "trailing content",
			content: goldenConfig + `{"node": {"name": "second"}}`,
			wantMsg: "unexpected content",
		},
		{
			name:    "invalid values",
			content: `{"node": {"name": "lab", "state_dir": "relative"}}`,
			wantMsg: "node.state_dir",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(writeConfig(t, tt.content))
			if err == nil {
				t.Fatal("expected loading to fail")
			}
			if !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("error must mention %q, got: %v", tt.wantMsg, err)
			}
		})
	}
}

// A typo in a security-relevant key must fail loudly rather than leave the
// intended setting silently at its default.
func TestLoadRejectsTypoInSecuritySetting(t *testing.T) {
	// The key is misspelled on purpose. It is assembled here rather than
	// written literally so that spell checkers do not "fix" the test subject.
	typo := "accept_def" + "ualt_route"
	content := fmt.Sprintf(`{
      "node": {"name": "lab", "state_dir": "/var/lib/nostmesh"},
      "policy": {%q: true}
    }`, typo)

	_, err := Load(writeConfig(t, content))
	if err == nil {
		t.Fatal("a misspelled policy key must be rejected")
	}
	if !strings.Contains(err.Error(), "unknown field") {
		t.Errorf("error must identify the unknown field, got: %v", err)
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "absent.json"))
	if err == nil {
		t.Fatal("expected an error for a missing file")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error must say the file was not found, got: %v", err)
	}
}

func TestLoadDirectory(t *testing.T) {
	_, err := Load(t.TempDir())
	if err == nil {
		t.Fatal("expected an error for a directory")
	}
	if !strings.Contains(err.Error(), "directory") {
		t.Errorf("error must say the path is a directory, got: %v", err)
	}
}

func TestLoadOversizedFile(t *testing.T) {
	_, err := Load(writeConfig(t, strings.Repeat("x", maxConfigSize+1)))
	if err == nil {
		t.Fatal("expected an error for an oversized file")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("error must mention the size limit, got: %v", err)
	}
}
