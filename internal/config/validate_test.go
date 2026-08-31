package config

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

// validPeer returns a peer that passes validation, so each test can alter a
// single field and attribute the failure to that field alone.
// testPeerKey builds a WireGuard public key from a seed. Public keys are not
// secret, but a base64 literal is indistinguishable from a credential to a
// secret scanner; deriving it keeps the intent obvious.
func testPeerKey(seed byte) string {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = seed + byte(i)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func validPeer() Peer {
	return Peer{
		Name:           "lab-a",
		PublicKey:      testPeerKey(90),
		Endpoint:       "198.51.100.10:51820",
		OverlayAddress: "100.96.0.2/32",
		AllowedIPs:     []string{"100.96.0.2/32"},
		KeepAlive:      25 * time.Second,
	}
}

func validConfig() Config {
	cfg := Default()
	cfg.Node = Node{Name: "lab", StateDir: "/var/lib/nostmesh"}
	cfg.Peers = []Peer{validPeer()}
	return cfg
}

func TestValidateAcceptsValidConfig(t *testing.T) {
	if err := validConfig().Validate(); err != nil {
		t.Fatalf("expected valid configuration, got: %v", err)
	}
}

func TestDefaultIsDenyByDefault(t *testing.T) {
	cfg := Default()

	if cfg.Policy.DefaultAction != "deny" {
		t.Errorf("default action = %q, want deny", cfg.Policy.DefaultAction)
	}
	if cfg.Policy.AcceptDefaultRoute {
		t.Error("accept_default_route must default to false")
	}
	if len(cfg.Peers) != 0 {
		t.Errorf("default configuration must not authorize peers, got %d", len(cfg.Peers))
	}
}

// The zero-value defaults must not be usable on their own: a node that starts
// from Default() alone has no state directory and no identity.
func TestDefaultAloneIsNotValid(t *testing.T) {
	if err := Default().Validate(); err == nil {
		t.Fatal("default configuration alone must not validate")
	}
}

func TestValidateRejects(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*Config)
		wantField string
	}{
		{
			name:      "empty node name",
			mutate:    func(c *Config) { c.Node.Name = "" },
			wantField: "node.name",
		},
		{
			name:      "relative state dir",
			mutate:    func(c *Config) { c.Node.StateDir = "relative/path" },
			wantField: "node.state_dir",
		},
		{
			name:      "unknown log level",
			mutate:    func(c *Config) { c.Log.Level = "verbose" },
			wantField: "log.level",
		},
		{
			name:      "unknown log format",
			mutate:    func(c *Config) { c.Log.Format = "xml" },
			wantField: "log.format",
		},
		{
			name:      "allow by default",
			mutate:    func(c *Config) { c.Policy.DefaultAction = "allow" },
			wantField: "policy.default_action",
		},
		{
			name:      "zero max sessions",
			mutate:    func(c *Config) { c.Policy.MaxSessions = 0 },
			wantField: "policy.max_sessions",
		},
		{
			name:      "empty peer name",
			mutate:    func(c *Config) { c.Peers[0].Name = "" },
			wantField: "peers[0].name",
		},
		{
			name:      "public key not base64",
			mutate:    func(c *Config) { c.Peers[0].PublicKey = "not base64!" },
			wantField: "peers[0].public_key",
		},
		{
			name:      "public key wrong length",
			mutate:    func(c *Config) { c.Peers[0].PublicKey = "c2hvcnQ=" },
			wantField: "peers[0].public_key",
		},
		{
			name:      "endpoint without port",
			mutate:    func(c *Config) { c.Peers[0].Endpoint = "198.51.100.10" },
			wantField: "peers[0].endpoint",
		},
		{
			name:      "endpoint with invalid port",
			mutate:    func(c *Config) { c.Peers[0].Endpoint = "198.51.100.10:not-a-port" },
			wantField: "peers[0].endpoint",
		},
		{
			name:      "overlay address without prefix",
			mutate:    func(c *Config) { c.Peers[0].OverlayAddress = "100.96.0.2" },
			wantField: "peers[0].overlay_address",
		},
		{
			name:      "no allowed ips",
			mutate:    func(c *Config) { c.Peers[0].AllowedIPs = nil },
			wantField: "peers[0].allowed_ips",
		},
		{
			name:      "malformed allowed ip",
			mutate:    func(c *Config) { c.Peers[0].AllowedIPs = []string{"100.96.0.0/33"} },
			wantField: "peers[0].allowed_ips[0]",
		},
		{
			name:      "negative keepalive",
			mutate:    func(c *Config) { c.Peers[0].KeepAlive = -time.Second },
			wantField: "peers[0].keepalive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			tt.mutate(&cfg)

			err := cfg.Validate()
			if err == nil {
				t.Fatal("expected validation to fail")
			}
			if !strings.Contains(err.Error(), tt.wantField) {
				t.Errorf("error must name field %q, got: %v", tt.wantField, err)
			}
		})
	}
}

// A default route through a statically configured peer would capture all
// traffic, including the tunnel's own transport, creating a routing loop.
// Transit is a negotiated service with explicit consent, not a static setting.
func TestValidateRejectsDefaultRouteInAllowedIPs(t *testing.T) {
	for _, prefix := range []string{"0.0.0.0/0", "::/0"} {
		t.Run(prefix, func(t *testing.T) {
			cfg := validConfig()
			cfg.Peers[0].AllowedIPs = []string{prefix}

			err := cfg.Validate()
			if err == nil {
				t.Fatalf("default route %q must be rejected", prefix)
			}
			if !strings.Contains(err.Error(), "default route") {
				t.Errorf("error must explain the default route, got: %v", err)
			}
		})
	}
}

// Enabling accept_default_route makes a route eligible for confirmation; it
// must never turn a static peer into a default gateway.
func TestAcceptDefaultRouteDoesNotAllowStaticDefaultRoute(t *testing.T) {
	cfg := validConfig()
	cfg.Policy.AcceptDefaultRoute = true
	cfg.Peers[0].AllowedIPs = []string{"0.0.0.0/0"}

	if err := cfg.Validate(); err == nil {
		t.Fatal("accept_default_route must not permit a static default route")
	}
}

func TestValidateRejectsDuplicatePeers(t *testing.T) {
	t.Run("duplicate name", func(t *testing.T) {
		cfg := validConfig()
		second := validPeer()
		second.PublicKey = testPeerKey(40)
		cfg.Peers = append(cfg.Peers, second)

		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "unique") {
			t.Fatalf("duplicate name must be rejected, got: %v", err)
		}
	})

	t.Run("duplicate public key", func(t *testing.T) {
		cfg := validConfig()
		second := validPeer()
		second.Name = "lab-b"
		cfg.Peers = append(cfg.Peers, second)

		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "distinct key") {
			t.Fatalf("duplicate public key must be rejected, got: %v", err)
		}
	})
}

// Validation reports every problem at once so a malformed file can be fixed in
// a single pass rather than one error per run.
func TestValidateReportsAllProblems(t *testing.T) {
	cfg := validConfig()
	cfg.Node.Name = ""
	cfg.Log.Level = "verbose"
	cfg.Policy.DefaultAction = "allow"

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation to fail")
	}

	var errs Errors
	if !errors.As(err, &errs) {
		t.Fatalf("expected Errors, got %T", err)
	}
	if len(errs) != 3 {
		t.Fatalf("expected 3 problems, got %d: %v", len(errs), err)
	}
}

// A mistyped relay URL means a session with less redundancy than the operator
// intended, which is worth catching at validation rather than discovering when
// a relay goes down.
func TestRelayValidation(t *testing.T) {
	tests := []struct {
		name    string
		relays  []string
		wantErr bool
	}{
		{"valid wss", []string{"wss://relay.example"}, false},
		{"valid ws", []string{"ws://localhost:8080"}, false},
		{"three relays", []string{"wss://a.example", "wss://b.example", "wss://c.example"}, false},
		{"empty entry", []string{""}, true},
		{"missing scheme", []string{"relay.example"}, true},
		{"wrong scheme", []string{"https://relay.example"}, true},
		{"duplicate", []string{"wss://a.example", "wss://a.example"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			cfg.Node.Relays = tt.relays

			err := cfg.Validate()
			if tt.wantErr && err == nil {
				t.Error("expected validation to fail")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("expected the relays to validate, got: %v", err)
			}
		})
	}
}

func TestObserverValidation(t *testing.T) {
	tests := []struct {
		name      string
		observers []string
		wantErr   bool
	}{
		{"valid", []string{"stun.example:3478"}, false},
		{"empty entry", []string{""}, true},
		{"no port", []string{"stun.example"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			cfg.Node.Observers = tt.observers

			err := cfg.Validate()
			if tt.wantErr && err == nil {
				t.Error("expected validation to fail")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("expected the observers to validate, got: %v", err)
			}
		})
	}
}
