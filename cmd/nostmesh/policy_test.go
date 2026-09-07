package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writePolicyConfig writes a configuration exercising both kinds of rule.
func writePolicyConfig(t *testing.T, named, member string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "nostmesh.json")
	content := `{
  "node": {"name": "lab", "state_dir": "/var/lib/nostmesh"},
  "policy": {
    "default_action": "deny",
    "max_sessions": 64,
    "authorized_peers": [
      {"public_key": "` + named + `", "alias": "named-one",
       "actions": ["session"], "allowed_ips": ["100.96.0.1/32"]}
    ],
    "groups": [
      {"name": "my-devices", "members": ["` + member + `"],
       "actions": ["session", "route"], "allowed_ips": ["100.96.0.0/24"]}
    ]
  }
}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}
	return path
}

// writeRoutingConfig writes a configuration granting routes, willing to be
// asked about a default route.
func writeRoutingConfig(t *testing.T, router string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "nostmesh.json")
	content := `{
  "node": {"name": "lab", "state_dir": "/var/lib/nostmesh"},
  "policy": {
    "default_action": "deny",
    "accept_default_route": true,
    "max_sessions": 64,
    "authorized_peers": [
      {"public_key": "` + router + `", "alias": "a-router",
       "actions": ["session", "route"], "allowed_ips": ["10.0.0.0/8"]}
    ]
  }
}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}
	return path
}

// A prefix inside the rule is explained as allowed.
func TestPolicyExplainAnswersAboutAPrefix(t *testing.T) {
	router := testNostrKey(t, 100)
	path := writeRoutingConfig(t, router.String())

	stdout, stderr, code := execute(t, "policy", "explain",
		"--config", path, "--peer", router.String(), "--prefix", "10.1.0.0/16")
	if code != exitOK {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	if !strings.Contains(stdout, "route 10.1.0.0/16") {
		t.Errorf("the prefix asked about is not reported: %s", stdout)
	}
	if !strings.Contains(stdout, "allow") {
		t.Errorf("a prefix inside the rule was not allowed: %s", stdout)
	}
}

// A prefix outside the rule is explained as refused, with the reason.
func TestPolicyExplainRefusesAPrefixOutsideTheRule(t *testing.T) {
	router := testNostrKey(t, 101)
	path := writeRoutingConfig(t, router.String())

	stdout, _, code := execute(t, "policy", "explain",
		"--config", path, "--peer", router.String(), "--prefix", "192.168.0.0/16")
	if code != exitOK {
		t.Fatalf("code = %d", code)
	}
	if !strings.Contains(stdout, "prefix_not_allowed") {
		t.Errorf("the reason for refusing the prefix is missing: %s", stdout)
	}
}

// A default route is explained as needing confirmation, not as allowed.
//
// This is the only way an operator can see require_confirmation without waiting
// for a peer to announce one, which is the point of an explanation command.
func TestPolicyExplainShowsTheDefaultRouteQuestion(t *testing.T) {
	router := testNostrKey(t, 102)
	path := writeRoutingConfig(t, router.String())

	stdout, _, code := execute(t, "policy", "explain",
		"--config", path, "--peer", router.String(), "--prefix", "0.0.0.0/0")
	if code != exitOK {
		t.Fatalf("code = %d", code)
	}
	if !strings.Contains(stdout, "require_confirmation") {
		t.Errorf("a default route is not shown as a question: %s", stdout)
	}
	if !strings.Contains(stdout, "default_route_needs_confirmation") {
		t.Errorf("the reason code is missing: %s", stdout)
	}
}

// A prefix that is not a prefix is refused before the configuration is read.
func TestPolicyExplainRejectsABadPrefix(t *testing.T) {
	router := testNostrKey(t, 103)
	path := writeRoutingConfig(t, router.String())

	_, stderr, code := execute(t, "policy", "explain",
		"--config", path, "--peer", router.String(), "--prefix", "not-a-prefix")
	if code != exitError {
		t.Errorf("code = %d, want exitError", code)
	}
	if stderr == "" {
		t.Error("nothing explained why the prefix was refused")
	}
}

// The explanation names the rule that produced each answer.
func TestPolicyExplainNamesTheRule(t *testing.T) {
	named := testNostrKey(t, 80)
	member := testNostrKey(t, 81)
	path := writePolicyConfig(t, named.String(), member.String())

	stdout, stderr, code := execute(t, "policy", "explain", "--config", path, "--peer", named.String())
	if code != exitOK {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	if !strings.Contains(stdout, "peer "+named.Short()) && !strings.Contains(stdout, named.String()) {
		t.Error("the output does not identify the peer it is about")
	}
	if !strings.Contains(stdout, "allowed_by_rule") {
		t.Errorf("the reason code is missing: %s", stdout)
	}
	if !strings.Contains(stdout, "peer "+named.Short()) {
		t.Errorf("the rule that produced the answer is not named: %s", stdout)
	}
}

// A peer covered only by a group is explained by that group.
func TestPolicyExplainNamesTheGroup(t *testing.T) {
	named := testNostrKey(t, 82)
	member := testNostrKey(t, 83)
	path := writePolicyConfig(t, named.String(), member.String())

	stdout, stderr, code := execute(t, "policy", "explain", "--config", path, "--peer", member.String())
	if code != exitOK {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	if !strings.Contains(stdout, "group my-devices") {
		t.Errorf("the group is not named as the rule: %s", stdout)
	}
	if !strings.Contains(stdout, "allowed_by_group") {
		t.Errorf("the group reason code is missing: %s", stdout)
	}
}

// A peer no rule mentions is explained as a refusal, not as a blank.
//
// This is the question the command exists to answer: an operator whose peer
// will not connect needs to be told that nothing authorizes it, in those words.
func TestPolicyExplainSaysWhenNoRuleMatched(t *testing.T) {
	named := testNostrKey(t, 84)
	member := testNostrKey(t, 85)
	stranger := testNostrKey(t, 86)
	path := writePolicyConfig(t, named.String(), member.String())

	stdout, stderr, code := execute(t, "policy", "explain", "--config", path, "--peer", stranger.String())
	if code != exitOK {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	// The outcome field specifically, not the word anywhere in the output: the
	// closing line already says the node denies by default, and matching that
	// let a blank outcome pass when the rendering was broken deliberately.
	if !strings.Contains(stdout, "outcome: deny") {
		t.Errorf("a refusal is not reported as deny in the outcome: %s", stdout)
	}
	if !strings.Contains(stdout, "no_rule") {
		t.Errorf("the reason code is missing: %s", stdout)
	}
	if !strings.Contains(stdout, "none matched") {
		t.Errorf("an empty rule is printed as a blank rather than explained: %s", stdout)
	}
}

// Every action is reported, because one peer can differ between them.
func TestPolicyExplainReportsEveryAction(t *testing.T) {
	named := testNostrKey(t, 87)
	member := testNostrKey(t, 88)
	path := writePolicyConfig(t, named.String(), member.String())

	stdout, _, code := execute(t, "policy", "explain", "--config", path, "--peer", named.String())
	if code != exitOK {
		t.Fatalf("code = %d", code)
	}
	for _, action := range []string{"session", "route", "transit"} {
		if !strings.Contains(stdout, action) {
			t.Errorf("action %q is not reported: %s", action, stdout)
		}
	}

	// The named peer holds a session grant only, so the other two must refuse.
	if !strings.Contains(stdout, "action_not_permitted") {
		t.Errorf("an action the peer lacks is not shown as refused: %s", stdout)
	}

	// And the refusal names the rule that refused. Reporting "none matched" for
	// a peer a rule does cover sends the operator to write one they already
	// have; the fix here is to widen the rule, which is a different action.
	if strings.Contains(stdout, "none matched") {
		t.Errorf("a peer covered by a rule was told no rule matched: %s", stdout)
	}
}

// The explanation is deterministic.
//
// Two runs over one configuration produce identical bytes, so a change in the
// output means a change in policy rather than in map iteration.
func TestPolicyExplainIsDeterministic(t *testing.T) {
	named := testNostrKey(t, 89)
	member := testNostrKey(t, 90)
	path := writePolicyConfig(t, named.String(), member.String())

	first, _, code := execute(t, "policy", "explain", "--config", path, "--peer", member.String())
	if code != exitOK {
		t.Fatalf("code = %d", code)
	}
	for range 8 {
		again, _, _ := execute(t, "policy", "explain", "--config", path, "--peer", member.String())
		if again != first {
			t.Fatal("the explanation changed between runs over the same configuration")
		}
	}
}

// The JSON form carries the same answer in a shape a script can read.
func TestPolicyExplainJSON(t *testing.T) {
	named := testNostrKey(t, 91)
	member := testNostrKey(t, 92)
	path := writePolicyConfig(t, named.String(), member.String())

	stdout, stderr, code := execute(t, "policy", "explain", "--config", path, "--peer", member.String(), "--json")
	if code != exitOK {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}

	var decoded []struct {
		Action     string   `json:"action"`
		Outcome    string   `json:"outcome"`
		Reason     string   `json:"reason"`
		Rule       string   `json:"rule"`
		AllowedIPs []string `json:"allowed_ips"`
	}
	if err := json.Unmarshal([]byte(stdout), &decoded); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, stdout)
	}
	if len(decoded) != 3 {
		t.Fatalf("got %d actions, want one per action", len(decoded))
	}

	for _, entry := range decoded {
		if entry.Outcome == "" {
			t.Errorf("%s: outcome is empty; a refusal must read as deny, not as a missing field", entry.Action)
		}
	}

	if decoded[0].Action != "session" {
		t.Errorf("first action = %q, want session", decoded[0].Action)
	}
	if decoded[0].Rule != "group my-devices" {
		t.Errorf("rule = %q, want the group", decoded[0].Rule)
	}
}

// The explanation reveals nothing the operator's own file does not hold.
func TestPolicyExplainRevealsNoSecrets(t *testing.T) {
	named := testNostrKey(t, 93)
	member := testNostrKey(t, 94)
	path := writePolicyConfig(t, named.String(), member.String())

	stdout, _, _ := execute(t, "policy", "explain", "--config", path, "--peer", named.String())

	for _, forbidden := range []string{"private", "secret", "nsec", "identity.json"} {
		if strings.Contains(strings.ToLower(stdout), forbidden) {
			t.Errorf("the explanation mentions %q: %s", forbidden, stdout)
		}
	}
}

// Missing flags are a usage error, not a crash.
func TestPolicyExplainRequiresItsFlags(t *testing.T) {
	for _, args := range [][]string{
		{"policy", "explain"},
		{"policy", "explain", "--config", "/nonexistent"},
	} {
		if _, _, code := execute(t, args...); code == exitOK {
			t.Errorf("%v succeeded with missing or bad arguments", args)
		}
	}
}

// A key that is not a key is refused before the configuration is read.
func TestPolicyExplainRejectsABadKey(t *testing.T) {
	named := testNostrKey(t, 95)
	member := testNostrKey(t, 96)
	path := writePolicyConfig(t, named.String(), member.String())

	_, stderr, code := execute(t, "policy", "explain", "--config", path, "--peer", "not-a-key")
	if code != exitError {
		t.Errorf("code = %d, want exitError", code)
	}
	if stderr == "" {
		t.Error("nothing explained why the key was refused")
	}
}

// An unknown subcommand is reported rather than silently ignored.
func TestPolicyRejectsUnknownSubcommand(t *testing.T) {
	_, stderr, code := execute(t, "policy", "simulate")
	if code != exitUsage {
		t.Errorf("code = %d, want exitUsage", code)
	}
	if !strings.Contains(stderr, "unknown subcommand") {
		t.Errorf("stderr does not name the problem: %s", stderr)
	}
}
