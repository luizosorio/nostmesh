package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"testing"

	"github.com/luizosorio/nostmesh/internal/domain"
)

func decisionKey(t *testing.T, seed string) domain.NostrPublicKey {
	t.Helper()

	digest := sha256.Sum256([]byte(seed))
	key, err := domain.ParseNostrPublicKey(hex.EncodeToString(digest[:]))
	if err != nil {
		t.Fatalf("building key: %v", err)
	}
	return key
}

func prefixes(values ...string) []netip.Prefix {
	parsed := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		parsed = append(parsed, netip.MustParsePrefix(value))
	}
	return parsed
}

// Absence of a rule denies, whatever else is configured.
//
// Asserted as a property rather than a case: this is the whole of
// deny-by-default, and it has to hold for a peer nobody thought about.
func TestAbsenceOfARuleDenies(t *testing.T) {
	list := NewAllowlist()

	// A populated allowlist, so this is not passing because nothing is set up.
	if err := list.Add(Grant{
		Peer: decisionKey(t, "somebody else"), Actions: []Action{ActionSession},
		AllowedIPs: prefixes("100.96.0.2/32"),
	}); err != nil {
		t.Fatalf("adding: %v", err)
	}

	for _, action := range []Action{ActionSession, ActionRoute, ActionTransit} {
		decision := list.Decide(decisionKey(t, "a stranger"), action)

		if decision.Allowed() {
			t.Errorf("a peer no rule mentions was allowed to %s", action)
		}
		if decision.Reason != ReasonNoRule {
			t.Errorf("reason = %q, want %q", decision.Reason, ReasonNoRule)
		}
		if len(decision.AllowedIPs) != 0 {
			t.Errorf("a denial carried %d prefixes", len(decision.AllowedIPs))
		}
	}
}

// The zero Decision denies.
//
// A caller that forgot to decide, or a struct returned from an error path
// nobody filled in, must refuse. The failure mode of forgetting has to be denial.
func TestTheZeroDecisionDenies(t *testing.T) {
	var decision Decision

	if decision.Allowed() {
		t.Error("the zero decision permits")
	}
	if decision.Outcome != OutcomeDeny {
		t.Errorf("the zero outcome is %q, not deny", decision.Outcome)
	}
}

// Confirmation is not permission.
//
// A caller treating it as allowed would produce exactly the effect the outcome
// exists to gate.
func TestConfirmationIsNotPermission(t *testing.T) {
	decision := Decision{Outcome: OutcomeConfirm, Reason: ReasonAllowedByRule}

	if decision.Allowed() {
		t.Error("require-confirmation reported itself as allowed")
	}
}

// An allowed peer's decision carries the prefixes it may be routed.
//
// This is the gap NM-24 closes: the limits used to be read from configuration
// separately from the check, so the two could disagree.
func TestAnAllowCarriesItsLimits(t *testing.T) {
	list := NewAllowlist()
	peer := decisionKey(t, "a peer")

	if err := list.Add(Grant{
		Peer: peer, Actions: []Action{ActionSession},
		AllowedIPs: prefixes("100.96.0.2/32", "10.20.30.0/24"),
	}); err != nil {
		t.Fatalf("adding: %v", err)
	}

	decision := list.Decide(peer, ActionSession)

	if !decision.Allowed() {
		t.Fatalf("an authorized peer was denied: %s", decision.Reason)
	}
	if len(decision.AllowedIPs) != 2 {
		t.Fatalf("the decision carries %d prefixes, want 2", len(decision.AllowedIPs))
	}
}

// The decision's prefixes are a copy, not the rule's own slice.
//
// A caller that appended to what it was handed would widen the rule for every
// later decision — a peer granted more than policy ever decided, from a mutation
// nobody would connect to the cause.
func TestADecisionCannotWidenTheRule(t *testing.T) {
	list := NewAllowlist()
	peer := decisionKey(t, "a peer")

	if err := list.Add(Grant{
		Peer: peer, Actions: []Action{ActionSession},
		AllowedIPs: prefixes("100.96.0.2/32"),
	}); err != nil {
		t.Fatalf("adding: %v", err)
	}

	// Overwriting an element, not appending: append on a full slice reallocates,
	// so it would not touch the rule even when the slice is shared. Writing in
	// place is what a shared backing array actually exposes.
	first := list.Decide(peer, ActionSession)
	first.AllowedIPs[0] = netip.MustParsePrefix("0.0.0.0/0")

	second := list.Decide(peer, ActionSession)
	if second.AllowedIPs[0].Bits() == 0 {
		t.Error("a caller's write reached the rule: the next decision carries the default route")
	}
}

// An allowed peer with nothing to route is refused.
//
// A tunnel that carries nothing is not a working session, and an operator who
// wrote the rule meant something by it.
func TestAnAllowWithNothingRoutedIsRefused(t *testing.T) {
	list := NewAllowlist()
	peer := decisionKey(t, "a peer")

	if err := list.Add(Grant{Peer: peer, Actions: []Action{ActionSession}}); err != nil {
		t.Fatalf("adding: %v", err)
	}

	decision := list.Decide(peer, ActionSession)

	if decision.Allowed() {
		t.Error("a peer with no prefixes was allowed to open a session")
	}
	if decision.Reason != ReasonNothingRouted {
		t.Errorf("reason = %q, want %q", decision.Reason, ReasonNothingRouted)
	}
}

// A group rule covers every member.
//
// This is what makes one person's ten devices one rule rather than ten, without
// the default relaxing: the rule still has to be written.
func TestAGroupRuleCoversItsMembers(t *testing.T) {
	list := NewAllowlist()
	members := []domain.NostrPublicKey{
		decisionKey(t, "laptop"), decisionKey(t, "phone"), decisionKey(t, "server"),
	}

	if err := list.AddGroup(Group{
		Name: "mine", Members: members,
		Actions: []Action{ActionSession}, AllowedIPs: prefixes("fd00::/64"),
	}); err != nil {
		t.Fatalf("adding a group: %v", err)
	}

	for _, member := range members {
		decision := list.Decide(member, ActionSession)

		if !decision.Allowed() {
			t.Errorf("%s was denied by a group that contains it: %s", member.Short(), decision.Reason)
		}
		if decision.Reason != ReasonAllowedByGroup {
			t.Errorf("reason = %q, want %q", decision.Reason, ReasonAllowedByGroup)
		}
	}

	// Somebody outside the group is still refused.
	if list.Decide(decisionKey(t, "a stranger"), ActionSession).Allowed() {
		t.Error("a group rule allowed somebody who is not in it")
	}
}

// A per-peer rule takes precedence over a group, in both directions.
//
// Tested both ways so the order is a decision rather than an artefact of
// iteration: an operator who writes a specific rule to grant something must not
// find it silently ignored, and one who writes it to narrow must not find it
// widened.
func TestAPerPeerRuleWinsOverAGroup(t *testing.T) {
	peer := decisionKey(t, "laptop")

	t.Run("narrower than the group", func(t *testing.T) {
		list := NewAllowlist()
		if err := list.AddGroup(Group{
			Name: "mine", Members: []domain.NostrPublicKey{peer},
			Actions: []Action{ActionSession}, AllowedIPs: prefixes("fd00::/64", "10.0.0.0/8"),
		}); err != nil {
			t.Fatalf("adding a group: %v", err)
		}
		if err := list.Add(Grant{
			Peer: peer, Actions: []Action{ActionSession}, AllowedIPs: prefixes("fd00::1/128"),
		}); err != nil {
			t.Fatalf("adding: %v", err)
		}

		decision := list.Decide(peer, ActionSession)
		if len(decision.AllowedIPs) != 1 {
			t.Errorf("the specific rule was widened by the group: %d prefixes", len(decision.AllowedIPs))
		}
		if decision.Reason != ReasonAllowedByRule {
			t.Errorf("reason = %q, want the per-peer rule to have answered", decision.Reason)
		}
	})

	t.Run("wider than the group", func(t *testing.T) {
		list := NewAllowlist()
		if err := list.AddGroup(Group{
			Name: "mine", Members: []domain.NostrPublicKey{peer},
			Actions: []Action{ActionSession}, AllowedIPs: prefixes("fd00::1/128"),
		}); err != nil {
			t.Fatalf("adding a group: %v", err)
		}
		if err := list.Add(Grant{
			Peer: peer, Actions: []Action{ActionSession}, AllowedIPs: prefixes("fd00::/64", "10.0.0.0/8"),
		}); err != nil {
			t.Fatalf("adding: %v", err)
		}

		decision := list.Decide(peer, ActionSession)
		if len(decision.AllowedIPs) != 2 {
			t.Errorf("the specific rule was narrowed by the group: %d prefixes", len(decision.AllowedIPs))
		}
	})
}

// A revoked grant refuses even when a group would allow.
//
// Revocation is the operator saying "not this one", and a group rule must not
// undo it — otherwise removing a compromised device would mean editing every
// group that happens to contain it.
func TestRevocationSurvivesAGroupRule(t *testing.T) {
	list := NewAllowlist()
	peer := decisionKey(t, "a stolen laptop")

	if err := list.AddGroup(Group{
		Name: "mine", Members: []domain.NostrPublicKey{peer},
		Actions: []Action{ActionSession}, AllowedIPs: prefixes("fd00::/64"),
	}); err != nil {
		t.Fatalf("adding a group: %v", err)
	}
	if err := list.Add(Grant{
		Peer: peer, Actions: []Action{ActionSession},
		AllowedIPs: prefixes("fd00::/64"), Revoked: true,
	}); err != nil {
		t.Fatalf("adding: %v", err)
	}

	decision := list.Decide(peer, ActionSession)

	if decision.Allowed() {
		t.Error("a revoked peer was allowed by a group rule")
	}
	if decision.Reason != ReasonRevoked {
		t.Errorf("reason = %q, want %q", decision.Reason, ReasonRevoked)
	}
}

// An action the rule does not cover is refused, per action.
//
// Opening a session is not announcing a route, and a peer trusted for one is not
// trusted for the other.
func TestAnUncoveredActionIsRefused(t *testing.T) {
	list := NewAllowlist()
	peer := decisionKey(t, "a peer")

	if err := list.Add(Grant{
		Peer: peer, Actions: []Action{ActionSession}, AllowedIPs: prefixes("100.96.0.2/32"),
	}); err != nil {
		t.Fatalf("adding: %v", err)
	}

	if list.Decide(peer, ActionRoute).Allowed() {
		t.Error("a peer authorized for sessions was allowed to announce routes")
	}
	if reason := list.Decide(peer, ActionRoute).Reason; reason != ReasonActionNotPermitted {
		t.Errorf("reason = %q, want %q", reason, ReasonActionNotPermitted)
	}
}

// A group needs a name, because an explanation without one traces to nothing.
func TestAGroupNeedsAName(t *testing.T) {
	list := NewAllowlist()

	if err := list.AddGroup(Group{Members: []domain.NostrPublicKey{decisionKey(t, "a peer")}}); err == nil {
		t.Error("a group with no name was accepted")
	}
}

// Every decision names what produced it.
//
// An operator asking why a peer connects needs the rule, not just the outcome —
// especially for a peer they never named individually.
func TestAnAllowNamesItsRule(t *testing.T) {
	list := NewAllowlist()
	peer := decisionKey(t, "laptop")

	if err := list.AddGroup(Group{
		Name: "mine", Members: []domain.NostrPublicKey{peer},
		Actions: []Action{ActionSession}, AllowedIPs: prefixes("fd00::/64"),
	}); err != nil {
		t.Fatalf("adding a group: %v", err)
	}

	if rule := list.Decide(peer, ActionSession).Rule; rule != "group mine" {
		t.Errorf("rule = %q, want it to name the group", rule)
	}
}
