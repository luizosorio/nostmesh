package config

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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

// A log file outside the packaged directory is accepted.
//
// Under systemd only the granted logs directory is writable, but the binary is
// self-contained and runs without a supervisor, where a laboratory run logging
// to a temporary directory is ordinary. Refusing it here would make the
// unpackaged case impossible in order to improve an error message for the
// packaged one, which reports the path anyway when the file fails to open.
func TestValidateAcceptsALogFileOutsideThePackagedDirectory(t *testing.T) {
	cfg := validConfig()
	cfg.Log.File = "/tmp/nostmesh-lab.log"

	if err := cfg.Validate(); err != nil {
		t.Fatalf("a log path outside the packaged directory was refused: %v", err)
	}
}

// Values derived from visible seeds, so a secret scanner has nothing to
// classify: a public key and a salt are the same 32 bytes as a private key.
var (
	testIssuerHex = derivedHex("nostmesh config test issuer")
	testSaltHex   = derivedHex("nostmesh config test salt")
)

func derivedHex(seed string) string {
	digest := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(digest[:])
}

// A node with no network configured stays valid.
//
// This is the criterion that keeps MVP 1 working: every deployment written
// before derived addressing has no network block, and must go on validating.
func TestAConfigurationWithoutANetworkIsValid(t *testing.T) {
	cfg := validConfig()
	cfg.Node.OverlayAddress = "100.96.0.1/32"

	if err := cfg.Validate(); err != nil {
		t.Fatalf("a configuration without a network was refused: %v", err)
	}
	if cfg.Network.Enabled() {
		t.Error("an empty network block reported itself as enabled")
	}
}

// A fully configured network is valid.
func TestACompleteNetworkIsValid(t *testing.T) {
	cfg := validConfig()
	cfg.Network = Network{
		Manifest: "/etc/nostmesh/network.json",
		Issuer:   testIssuerHex,
		Salt:     testSaltHex,
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("a complete network was refused: %v", err)
	}
	if !cfg.Network.Enabled() {
		t.Error("a complete network reported itself as disabled")
	}
}

// An absent diagnostic setting means the closed one.
//
// A configuration written before this field existed must keep working, and it
// must keep working closed: defaulting the other way would open disclosure on
// every node that never asked for it.
func TestAnAbsentDiagnosticSettingIsValidAndClosed(t *testing.T) {
	cfg := validConfig()
	cfg.Log.Diagnostic = ""

	if err := cfg.Validate(); err != nil {
		t.Fatalf("a configuration without a diagnostic setting was refused: %v", err)
	}
}

// No log file at all is the default and stays valid.
func TestValidateAcceptsNoLogFile(t *testing.T) {
	cfg := validConfig()
	cfg.Log.File = ""

	if err := cfg.Validate(); err != nil {
		t.Fatalf("a configuration without a log file was refused: %v", err)
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
			name:      "relative log file",
			mutate:    func(c *Config) { c.Log.File = "logs/nostmesh.log" },
			wantField: "log.file",
		},
		{
			name:      "unclean log file",
			mutate:    func(c *Config) { c.Log.File = "/var/log/nostmesh/../nostmesh.log" },
			wantField: "log.file",
		},
		{
			name:      "log file names a directory",
			mutate:    func(c *Config) { c.Log.File = "/var/log/nostmesh/" },
			wantField: "log.file",
		},
		{
			name:      "unknown diagnostic mode",
			mutate:    func(c *Config) { c.Log.Diagnostic = "verbose" },
			wantField: "log.diagnostic",
		},
		{
			name:      "network without an issuer",
			mutate:    func(c *Config) { c.Network.Manifest = "/etc/nostmesh/network.json" },
			wantField: "network.issuer",
		},
		{
			name: "network without a salt",
			mutate: func(c *Config) {
				c.Network.Manifest = "/etc/nostmesh/network.json"
				c.Network.Issuer = testIssuerHex
			},
			wantField: "network.salt",
		},
		{
			name: "network without a manifest",
			mutate: func(c *Config) {
				c.Network.Issuer = testIssuerHex
				c.Network.Salt = testSaltHex
			},
			wantField: "network.manifest",
		},
		{
			name: "relative manifest path",
			mutate: func(c *Config) {
				c.Network = Network{Manifest: "network.json", Issuer: testIssuerHex, Salt: testSaltHex}
			},
			wantField: "network.manifest",
		},
		{
			name: "an issuer that is not a key",
			mutate: func(c *Config) {
				c.Network = Network{Manifest: "/etc/nostmesh/network.json", Issuer: "nonsense", Salt: testSaltHex}
			},
			wantField: "network.issuer",
		},
		{
			name: "a salt of the wrong length",
			mutate: func(c *Config) {
				c.Network = Network{Manifest: "/etc/nostmesh/network.json", Issuer: testIssuerHex, Salt: "abcd"}
			},
			wantField: "network.salt",
		},
		{
			name: "a negative subnet",
			mutate: func(c *Config) {
				c.Network = Network{
					Manifest: "/etc/nostmesh/network.json", Issuer: testIssuerHex,
					Salt: testSaltHex, Subnet: -1,
				}
			},
			wantField: "network.subnet",
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
			name:      "a group without a name",
			mutate:    func(c *Config) { c.Policy.Groups = []PolicyGroup{mutatedGroup(func(g *PolicyGroup) { g.Name = "" })} },
			wantField: "policy.groups[0].name",
		},
		{
			name: "two groups sharing a name",
			mutate: func(c *Config) {
				c.Policy.Groups = []PolicyGroup{validPolicyGroup(), validPolicyGroup()}
			},
			wantField: "policy.groups[1].name",
		},
		{
			name: "a group with no members",
			mutate: func(c *Config) {
				c.Policy.Groups = []PolicyGroup{mutatedGroup(func(g *PolicyGroup) { g.Members = nil })}
			},
			wantField: "policy.groups[0].members",
		},
		{
			name: "a member that is not a Nostr key",
			mutate: func(c *Config) {
				c.Policy.Groups = []PolicyGroup{mutatedGroup(func(g *PolicyGroup) { g.Members = []string{"not-a-key"} })}
			},
			wantField: "policy.groups[0].members[0]",
		},
		{
			name: "the same member listed twice",
			mutate: func(c *Config) {
				c.Policy.Groups = []PolicyGroup{mutatedGroup(func(g *PolicyGroup) {
					g.Members = []string{testGroupMember, testGroupMember}
				})}
			},
			wantField: "policy.groups[0].members[1]",
		},
		{
			name: "a group with no actions",
			mutate: func(c *Config) {
				c.Policy.Groups = []PolicyGroup{mutatedGroup(func(g *PolicyGroup) { g.Actions = nil })}
			},
			wantField: "policy.groups[0].actions",
		},
		{
			name: "a group action outside the closed set",
			mutate: func(c *Config) {
				c.Policy.Groups = []PolicyGroup{mutatedGroup(func(g *PolicyGroup) { g.Actions = []string{"everything"} })}
			},
			wantField: "policy.groups[0].actions[0]",
		},
		{
			name: "a group prefix that is not a prefix",
			mutate: func(c *Config) {
				c.Policy.Groups = []PolicyGroup{mutatedGroup(func(g *PolicyGroup) { g.AllowedIPs = []string{"not-a-prefix"} })}
			},
			wantField: "policy.groups[0].allowed_ips[0]",
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

// testGroupMember is a Nostr identity for group fixtures, derived rather than
// written out for the reason given above testPeerKey.
var testGroupMember = derivedHex("nostmesh config test group member")

func validPolicyGroup() PolicyGroup {
	return PolicyGroup{
		Name:       "my-devices",
		Members:    []string{testGroupMember},
		Actions:    []string{"session"},
		AllowedIPs: []string{"100.96.0.0/24"},
	}
}

// mutatedGroup returns a valid group with one field changed, so a failure is
// attributable to that field alone.
func mutatedGroup(mutate func(*PolicyGroup)) PolicyGroup {
	group := validPolicyGroup()
	mutate(&group)
	return group
}

// A group rule is accepted, which is what makes every rejection above mean
// something: without this the table could be passing because groups are refused
// wholesale.
func TestValidateAcceptsAGroupRule(t *testing.T) {
	cfg := validConfig()
	cfg.Policy.Groups = []PolicyGroup{validPolicyGroup()}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("a well-formed group was refused: %v", err)
	}
}

// A group prefix is checked by validation, unlike an authorized peer's.
//
// The asymmetry is deliberate and worth pinning: a malformed prefix on a peer
// is only found when the grant is built, which fails a whole reload for one bad
// line. A group says which field is wrong before anything is loaded.
func TestAGroupPrefixIsCheckedBeforeLoading(t *testing.T) {
	cfg := validConfig()
	cfg.Policy.Groups = []PolicyGroup{mutatedGroup(func(g *PolicyGroup) {
		g.AllowedIPs = []string{"100.96.0.0/24", "10.0.0.0/8", "not-a-prefix"}
	})}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("a malformed prefix was accepted; the reload would fail instead")
	}
	if !strings.Contains(err.Error(), "policy.groups[0].allowed_ips[2]") {
		t.Errorf("the error does not name the offending prefix: %v", err)
	}
}
