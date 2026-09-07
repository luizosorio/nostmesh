package policy

import (
	"net/netip"
	"slices"

	"github.com/luizosorio/nostmesh/internal/domain"
)

// A policy decision, per NM-24.
//
// The decision carries the limits it implies rather than leaving a caller to
// look them up. Before this, whether a peer was authorized and what it was
// allowed to route were answered by separate paths — only one of them checked —
// so the two could disagree, and the disagreement was silent.

// Outcome is what policy concluded.
type Outcome string

const (
	// OutcomeDeny refuses. It is the zero value, so a Decision nobody filled in
	// denies rather than permits: the failure mode of forgetting to decide has
	// to be refusal.
	OutcomeDeny Outcome = ""

	// OutcomeAllow permits, within the limits the decision carries.
	OutcomeAllow Outcome = "allow"

	// OutcomeConfirm permits only after a person says so.
	//
	// Not a deferred deny: it means the request is legitimate but its effect is
	// large enough that nobody should be able to cause it remotely. A route
	// covering the tunnel's own endpoint is the case it exists for.
	OutcomeConfirm Outcome = "require_confirmation"
)

// Reason codes explain a decision.
//
// A closed vocabulary rather than a message, so an operator asking twice gets
// the same answer and a log can be counted. Most refusals originate in something
// a peer sent, which is the other reason not to interpolate.
const (
	// ReasonNoRule reports a peer no rule mentions. The ordinary refusal: deny
	// by default is not an error condition, it is the answer to a question
	// nobody wrote a rule for.
	ReasonNoRule = "no_rule"

	// ReasonRevoked reports a grant deliberately withdrawn.
	ReasonRevoked = "revoked"

	// ReasonActionNotPermitted reports a peer authorized for something else.
	ReasonActionNotPermitted = "action_not_permitted"

	// ReasonAllowedByRule reports an allow from a per-peer rule.
	ReasonAllowedByRule = "allowed_by_rule"

	// ReasonAllowedByGroup reports an allow from a group rule.
	//
	// Distinct from the above so an operator can tell why a peer they never
	// named individually is connecting — which is the question a group rule
	// makes possible to ask.
	ReasonAllowedByGroup = "allowed_by_group"

	// ReasonNothingRouted reports an allowed peer with no prefixes.
	//
	// An allow with nothing to route builds a tunnel that carries nothing, so it
	// is refused rather than established: an operator who wrote a rule meant
	// something by it.
	ReasonNothingRouted = "nothing_routed"
)

// Decision is what policy concluded, and under what limits.
type Decision struct {
	// Outcome is allow, deny, or require-confirmation.
	Outcome Outcome

	// Reason is a code from the closed vocabulary above.
	Reason string

	// AllowedIPs are the prefixes this decision permits.
	//
	// The value that reaches the kernel. It may be narrower than what the
	// configuration file lists and is never wider: a caller that widened it
	// would be routing something policy did not decide on.
	AllowedIPs []netip.Prefix

	// Rule names what produced this, for an operator asking why. Empty for a
	// denial by default, which is produced by nothing.
	Rule string
}

// Allowed reports whether the decision permits the action outright.
//
// Confirmation is deliberately not allowed here: a caller that treated it as
// permission would produce exactly the effect the outcome exists to gate.
func (d Decision) Allowed() bool { return d.Outcome == OutcomeAllow }

// deny builds a refusal.
func deny(reason string) Decision {
	return Decision{Outcome: OutcomeDeny, Reason: reason}
}

// Group is a set of identities a rule may name at once.
//
// Its members come from a network manifest (NM-21), so the group tracks the
// membership rather than a copy of it: a device added to the manifest is covered
// by the rule that was already written, and one removed stops being covered.
type Group struct {
	// Name identifies the group in a rule and in an explanation.
	Name string

	// Members are the identities in it.
	Members []domain.NostrPublicKey

	// Actions are what members may do.
	Actions []Action

	// AllowedIPs are the prefixes a member may be routed.
	AllowedIPs []netip.Prefix
}

// Contains reports whether an identity is in the group.
func (g Group) Contains(peer domain.NostrPublicKey) bool {
	return slices.Contains(g.Members, peer)
}

// Allows reports whether the group covers an action.
func (g Group) Allows(action Action) bool {
	return slices.Contains(g.Actions, action)
}

// Decide answers what a peer may do, and under what limits.
//
// Per-peer rules take precedence over group rules, in both directions: a peer
// named individually gets that rule whether it is wider or narrower than the
// group's. The alternative — narrowest wins — sounds safer and is worse to
// operate, because an operator who writes a specific rule to grant something
// would find it silently ignored.
//
// A revoked per-peer grant therefore refuses even when a group would allow.
// Revocation is the operator saying "not this one", and a group rule must not
// undo it.
func (a *Allowlist) Decide(peer domain.NostrPublicKey, action Action) Decision {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if grant, known := a.grants[peer]; known {
		return decideFromGrant(grant, action)
	}

	for _, group := range a.groups {
		if !group.Contains(peer) {
			continue
		}
		return decideFromGroup(group, action)
	}

	// No rule mentions this peer. This is the default, and it is a decision
	// rather than a gap: absence of a rule is a refusal.
	return deny(ReasonNoRule)
}

// decideFromGrant applies a per-peer rule.
func decideFromGrant(grant Grant, action Action) Decision {
	if grant.Revoked {
		return deny(ReasonRevoked)
	}
	if !grant.Allows(action) {
		return deny(ReasonActionNotPermitted)
	}
	if len(grant.AllowedIPs) == 0 && action == ActionSession {
		return deny(ReasonNothingRouted)
	}

	return Decision{
		Outcome:    OutcomeAllow,
		Reason:     ReasonAllowedByRule,
		AllowedIPs: slices.Clone(grant.AllowedIPs),
		Rule:       "peer " + grant.Peer.Short(),
	}
}

// decideFromGroup applies a group rule.
func decideFromGroup(group Group, action Action) Decision {
	if !group.Allows(action) {
		return deny(ReasonActionNotPermitted)
	}
	if len(group.AllowedIPs) == 0 && action == ActionSession {
		return deny(ReasonNothingRouted)
	}

	return Decision{
		Outcome:    OutcomeAllow,
		Reason:     ReasonAllowedByGroup,
		AllowedIPs: slices.Clone(group.AllowedIPs),
		Rule:       "group " + group.Name,
	}
}

// AddGroup registers a group rule.
func (a *Allowlist) AddGroup(group Group) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if group.Name == "" {
		return errEmptyGroupName
	}
	a.groups = append(a.groups, group)
	return nil
}

// Groups reports the registered group rules.
func (a *Allowlist) Groups() []Group {
	a.mu.RLock()
	defer a.mu.RUnlock()

	return slices.Clone(a.groups)
}
