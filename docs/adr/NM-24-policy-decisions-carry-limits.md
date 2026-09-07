# NM-24 — Policy decisions carry limits

**Status:** Accepted
**Date:** 2026-09-07
**Milestone:** M2.3
**Resolves:** Q-05 — the format and semantics of the ACL

## Context

Policy today answers one question: may this peer do this? `Allowlist.Check`
returns an error or nothing, and three distinct refusals — unknown peer, revoked
grant, action not permitted — are already told apart inside it.

What it does not answer is *under what limits*. The architecture is explicit that
it should: the policy's output is "allow, deny ou require-confirmation, **além de
limites**".

The gap shows in one place concretely. `policy.authorized_peers[].allowed_ips` is
policy configuration — it says which prefixes this node will accept from a peer —
but the value reaches the kernel without passing through policy at all:
`wiring_session.go` looks the peer up with `findAuthorizedPeer` and reads the
field directly. The decision and the limit that decision implies travel by
separate paths, and only one of them is checked.

A second gap is scale rather than correctness. A rule is written per pubkey, so a
network of ten devices needs ten rules that say the same thing. For a team that
is right — each peer is a separate judgement. For one person's own devices it is
ceremony: they are all theirs, and the tenth rule carries no more intent than the
first.

## Decision

**A policy decision is a value carrying an outcome, a reason and the limits that
follow from it.**

```text
Decision{
    Outcome    ALLOW | DENY | REQUIRE_CONFIRMATION
    Reason     a code from a closed vocabulary
    AllowedIPs the prefixes this decision permits
    Limits     whatever else the action is bounded by
}
```

Every effect derives from the returned value. Nothing reads
`authorized_peers[].allowed_ips` to configure a peer; it reads what the decision
returned, which may be narrower than what the file says and is never wider.

**`REQUIRE_CONFIRMATION` is a real outcome, not a deferred DENY.** The
architecture names it, and route announcements need it: a prefix that would
capture the tunnel's own endpoint is not refused outright but must not be
installed without a person saying so. Treating it as DENY now would mean
rediscovering the case in M2.4 with the shape already fixed.

**Rules may name a group, and a group is a manifest's membership.** NM-21 already
defines who belongs to a network and requires the operator to pin its issuer. A
group rule says "every member of the network I pinned may open a session and
route these prefixes", written once.

**The default stays DENY, including for groups.** A group rule is a way to
express trust in fewer words, never a way to skip expressing it.

## Why the default does not relax for a personal network

A node cannot tell its owner's laptop from whoever stole its owner's key. Both
present a valid signature from an authorized identity; that is what a stolen key
is.

So "these are all my own devices" is a statement about intent, and deny-by-default
protects against the cases where intent is not what happened: a manifest edited
wrongly, a key compromised, a peer that should have been removed months ago. A
node that allowed everything because its network was labelled personal would have
no answer to any of them.

What is legitimate is reducing the *cost* of expressing that trust, which is what
group rules do. Ten devices become one rule rather than no rule.

**`REQUIRE_CONFIRMATION` is not offered for sessions in a personal network.**
There is nobody to confirm to: the operator is the peer. It stays available for
route announcements, where the question is about a prefix rather than about an
identity, and where the same person may well want to be asked.

## Consequences

- **Two questions become one call.** "May this peer connect?" and "what may it
  route?" are answered together, so they cannot disagree — which they can today,
  because one is checked and the other is copied.
- **A refusal has a code.** The three refusals already distinguished become part
  of a closed vocabulary, so an operator asking why can be answered the same way
  twice and a log can be counted. The vocabulary lives with the policy, not with
  each caller.
- **Rules are versioned and validated as a unit.** A policy that fails validation
  leaves the previous one in force rather than a half-applied mixture, which is
  what makes a reload safe to attempt on a running node.
- **A group rule depends on a manifest.** A node with no manifest configured has
  no groups, and its rules are per pubkey as before. That keeps the manual mode
  that every deployment before NM-21 uses.
- **Explaining a decision is a command, not a log line.** An operator asking "why
  can this peer not connect" should not have to reproduce the conditions to find
  out. It reports the outcome, the rule that produced it and the reason code, and
  it says nothing about material the caller could not already see.
- **M2.4 inherits the shape rather than extending it.** Route announcements are
  an action with prefixes and a confirmation case, all of which this decision
  already carries.

## Alternatives rejected

**Keep the boolean and pass limits alongside.** What the code does today. It
works until the two disagree, and the disagreement is silent: a peer authorized
with prefixes nobody checked is exactly the case where policy appears to have run
and did not.

**Let a network declare itself personal and relax the default.** Discussed and
refused above: the label describes intent, and the failures worth defending
against are the ones where intent is not what happened.

**Express groups as a list expanded at load time.** Simpler, and it loses the
property that makes groups worth having: a member added to the manifest would
need the policy rewritten, so the rule would drift from the membership it was
meant to track.

**Put the reason in free text.** Readable once and useless afterwards: it cannot
be counted, cannot be matched, and — since most refusals are about something a
peer sent — is how peer-controlled content reaches a log.

## Validation

- **Absence of a rule denies**, asserted as a property rather than a case: a
  decision over a peer no rule mentions is DENY whatever else is configured.
- **A group rule and a per-peer rule that disagree** resolve by a documented
  precedence, tested in both directions so the order is a decision rather than an
  artefact of iteration.
- **The limits a decision returns are what reaches the kernel**, which is the
  gap this closes. Guarded by a test that widens the configuration file and
  requires the narrower decision to win.
- **An invalid policy leaves the previous one in force**, asserted by reloading
  a broken one against a running node and checking that decisions do not change.
- **Every guard is exercised by planting the violation** and watching it fail
  before it is trusted.
