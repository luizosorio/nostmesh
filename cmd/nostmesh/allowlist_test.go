package main

import (
	"net/netip"
	"testing"

	"github.com/luizosorio/nostmesh/internal/config"
	"github.com/luizosorio/nostmesh/internal/domain"
	"github.com/luizosorio/nostmesh/internal/policy"
)

// Group rules reach the engine.
//
// The engine has understood groups since NM-24, but nothing loaded them: a rule
// an operator wrote was silently absent, and every member fell through to
// deny-by-default. That is the failure this covers — not whether the engine can
// decide, which its own tests already assert, but whether what the file says
// arrives.
func TestAGroupInConfigurationReachesTheDecision(t *testing.T) {
	member := testNostrKey(t, 40)

	cfg := config.Default()
	cfg.Policy.Groups = []config.PolicyGroup{{
		Name:       "my-devices",
		Members:    []string{member.String()},
		Actions:    []string{"session"},
		AllowedIPs: []string{"100.96.0.0/24"},
	}}

	allowlist, err := loadAllowlist(cfg)
	if err != nil {
		t.Fatalf("loading: %v", err)
	}

	decision := allowlist.Decide(member, policy.ActionSession)
	if !decision.Allowed() {
		t.Fatalf("a member of a configured group was refused: %s", decision.Reason)
	}
	if decision.Reason != policy.ReasonAllowedByGroup {
		t.Errorf("reason = %q, want %q", decision.Reason, policy.ReasonAllowedByGroup)
	}
	if decision.Rule != "group my-devices" {
		t.Errorf("rule = %q; a decision has to name what produced it", decision.Rule)
	}
	if want := []netip.Prefix{netip.MustParsePrefix("100.96.0.0/24")}; !prefixesEqual(decision.AllowedIPs, want) {
		t.Errorf("allowed_ips = %v, want %v", decision.AllowedIPs, want)
	}
}

// A group grants nothing to an identity it does not name.
//
// The point of loading groups is to reduce what an operator writes, never to
// widen who is covered.
func TestAGroupCoversOnlyItsMembers(t *testing.T) {
	member := testNostrKey(t, 41)
	stranger := testNostrKey(t, 42)

	cfg := config.Default()
	cfg.Policy.Groups = []config.PolicyGroup{{
		Name:       "my-devices",
		Members:    []string{member.String()},
		Actions:    []string{"session"},
		AllowedIPs: []string{"100.96.0.0/24"},
	}}

	allowlist, err := loadAllowlist(cfg)
	if err != nil {
		t.Fatalf("loading: %v", err)
	}

	decision := allowlist.Decide(stranger, policy.ActionSession)
	if decision.Allowed() {
		t.Fatal("a group authorized somebody it does not list")
	}
	if decision.Reason != policy.ReasonNoRule {
		t.Errorf("reason = %q, want %q", decision.Reason, policy.ReasonNoRule)
	}
}

// A per-peer rule still wins over a group after both come from one file.
//
// The precedence is the engine's (NM-24), and its own tests assert it. What
// this adds is that loading does not disturb it: the two rules arrive by
// different paths in loadAllowlist, and appending groups last must not make
// them override what the operator said about one named peer.
func TestLoadingKeepsThePerPeerRuleWinning(t *testing.T) {
	peer := testNostrKey(t, 43)

	cfg := config.Default()
	cfg.Policy.AuthorizedPeers = []config.AuthorizedPeer{{
		PublicKey: peer.String(),
		Alias:     "the-one-i-named",
		Actions:   []string{"session"},
		Revoked:   true,
	}}
	cfg.Policy.Groups = []config.PolicyGroup{{
		Name:       "my-devices",
		Members:    []string{peer.String()},
		Actions:    []string{"session"},
		AllowedIPs: []string{"100.96.0.0/24"},
	}}

	allowlist, err := loadAllowlist(cfg)
	if err != nil {
		t.Fatalf("loading: %v", err)
	}

	decision := allowlist.Decide(peer, policy.ActionSession)
	if decision.Allowed() {
		t.Fatal("a group rule undid a revocation; revoking is the operator saying not this one")
	}
	if decision.Reason != policy.ReasonRevoked {
		t.Errorf("reason = %q, want %q", decision.Reason, policy.ReasonRevoked)
	}
}

// A group naming an unparseable identity fails the load rather than dropping it.
//
// Skipping the member would produce a rule narrower than what was written,
// which is a security decision the operator did not make.
func TestAGroupWithAnUnparseableMemberFailsTheLoad(t *testing.T) {
	cfg := config.Default()
	cfg.Policy.Groups = []config.PolicyGroup{{
		Name:    "my-devices",
		Members: []string{"not-a-key"},
		Actions: []string{"session"},
	}}

	if _, err := loadAllowlist(cfg); err == nil {
		t.Fatal("an unparseable member was accepted; the group would silently cover nobody")
	}
}

// Every identity policy would authorize is reported, group members included.
//
// The service starts a worker per entry here. A peer authorized only by a group
// passed every check and still got no worker, because this listed per-peer
// grants alone — so the rule an operator wrote validated, loaded, decided
// "allow", and connected to nobody.
func TestAuthorizedPeersIncludeGroupMembers(t *testing.T) {
	named := testNostrKey(t, 50)
	viaGroup := testNostrKey(t, 51)

	cfg := config.Default()
	cfg.Policy.AuthorizedPeers = []config.AuthorizedPeer{{
		PublicKey:  named.String(),
		Alias:      "named",
		Actions:    []string{"session"},
		AllowedIPs: []string{"100.96.0.1/32"},
	}}
	cfg.Policy.Groups = []config.PolicyGroup{{
		Name:       "my-devices",
		Members:    []string{viaGroup.String()},
		Actions:    []string{"session"},
		AllowedIPs: []string{"100.96.0.0/24"},
	}}

	allowlist, err := loadAllowlist(cfg)
	if err != nil {
		t.Fatalf("loading: %v", err)
	}

	found := make(map[domain.NostrPublicKey]bool)
	for _, peer := range sessionPeers(allowlist) {
		found[peer] = true
	}

	if !found[named] {
		t.Error("a peer named individually is not reported")
	}
	if !found[viaGroup] {
		t.Error("a peer authorized only by a group is not reported; it would never get a worker")
	}
}

// A revoked peer is not reported even when a group names it.
//
// The list decides who gets a worker, so including a revoked peer here would
// serve somebody policy refuses.
func TestAuthorizedPeersOmitARevokedMember(t *testing.T) {
	peer := testNostrKey(t, 52)

	cfg := config.Default()
	cfg.Policy.AuthorizedPeers = []config.AuthorizedPeer{{
		PublicKey: peer.String(),
		Alias:     "retired",
		Actions:   []string{"session"},
		Revoked:   true,
	}}
	cfg.Policy.Groups = []config.PolicyGroup{{
		Name:       "my-devices",
		Members:    []string{peer.String()},
		Actions:    []string{"session"},
		AllowedIPs: []string{"100.96.0.0/24"},
	}}

	allowlist, err := loadAllowlist(cfg)
	if err != nil {
		t.Fatalf("loading: %v", err)
	}

	for _, reported := range sessionPeers(allowlist) {
		if reported == peer {
			t.Fatal("a revoked peer is reported for a worker because a group names it")
		}
	}
}

// The report is deterministic, so a reload does not reorder what it starts.
func TestAuthorizedPeersAreOrdered(t *testing.T) {
	cfg := config.Default()
	members := make([]string, 0, 8)
	for seed := byte(60); seed < 68; seed++ {
		members = append(members, testNostrKey(t, seed).String())
	}
	cfg.Policy.Groups = []config.PolicyGroup{{
		Name:       "my-devices",
		Members:    members,
		Actions:    []string{"session"},
		AllowedIPs: []string{"100.96.0.0/24"},
	}}

	allowlist, err := loadAllowlist(cfg)
	if err != nil {
		t.Fatalf("loading: %v", err)
	}

	first := sessionPeers(allowlist)
	for range 8 {
		if got := sessionPeers(allowlist); !peersEqual(got, first) {
			t.Fatal("the order changed between calls; a reload would restart workers for no reason")
		}
	}
}

// The configuration flag reaches the decision.
//
// The field existed and nothing read it, so a node could not be asked about a
// default route however its operator configured it.
func TestAcceptDefaultRouteReachesTheDecision(t *testing.T) {
	peer := testNostrKey(t, 70)
	defaultRoute := netip.MustParsePrefix("0.0.0.0/0")

	build := func(accept bool) policy.Decision {
		cfg := config.Default()
		cfg.Policy.AcceptDefaultRoute = accept
		cfg.Policy.AuthorizedPeers = []config.AuthorizedPeer{{
			PublicKey:  peer.String(),
			Alias:      "a-router",
			Actions:    []string{"route"},
			AllowedIPs: []string{"0.0.0.0/0"},
		}}

		allowlist, err := loadAllowlist(cfg)
		if err != nil {
			t.Fatalf("loading: %v", err)
		}
		return allowlist.DecideRoute(peer, defaultRoute)
	}

	if outcome := build(false).Outcome; outcome != policy.OutcomeDeny {
		t.Errorf("with the setting off, outcome = %q, want deny", outcome)
	}
	if outcome := build(true).Outcome; outcome != policy.OutcomeConfirm {
		t.Errorf("with the setting on, outcome = %q, want require_confirmation", outcome)
	}
	if build(true).Allowed() {
		t.Error("enabling the setting granted permission rather than a question")
	}
}

func peersEqual(got, want []domain.NostrPublicKey) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func prefixesEqual(got, want []netip.Prefix) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
