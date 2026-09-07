# NM-25 — Route announcements are proposals, and routes are their own operation

**Status:** Accepted
**Date:** 2026-09-07
**Milestone:** M2.4
**Amends:** NM-09 — routes follow AllowedIPs

## Context

A node can reach private networks the mesh cannot see. Until now the only way to
route one was to write its prefix into `allowed_ips` on both sides by hand, which
means an operator adding a subnet edits every node that should reach it.

M2.4 makes a node able to say "I can reach 10.20.30.0/24", and makes the receiver
decide whether to believe it. Two things in the repository have to move for that,
and both were decided deliberately before, so both are argued here rather than
changed quietly.

**The message table stops at eight types.** `04-protocolo-e-seguranca.md` §2
lists the session and candidate messages and no route messages. That table
describes the control plane MVP 1 needed; route announcements are what MVP 2
adds, and the delivery brief for this milestone asks for them by name.

**NM-09 rejected routes as a separate journaled operation.** Its reasoning was
that decoupling "admits a state where a peer exists without its routes, which is
never desirable". That reasoning was correct for what it described — the routes
implied by a peer's `AllowedIPs`, which exist because the peer exists and should
never outlive it. It does not describe an announced route, whose whole purpose is
to appear and disappear independently of the tunnel carrying it.

## Decision

### Two new message types

`route.announce` and `route.withdraw`, carrying the prefix, the network id, the
provider, a metric, capabilities, validity and a version. They are encrypted like
every other message, and their type is authenticated as associated data, so a
relay sees the type and nothing else.

They extend the table in §2 rather than contradicting it. Nothing about the
existing eight changes, and a node that does not understand the new types refuses
them as unknown — which is the correct answer from a node that cannot evaluate
them, not a failure.

### An announcement is a proposal, never a command

This is not new, it is NM-04 and ADR-005 applied to a new message: a valid
signature proves who is asking, not that the answer is yes. The pipeline the
architecture specifies is followed exactly:

```text
event → validation → policy → conflict detection → selection → plan → kernel
```

Policy is consulted through `DecideRoute` (NM-24), which already answers about a
particular prefix and already carries the limits. **M2.4 adds no policy
vocabulary.** That was the point of deciding the shape in M2.3.

### Routes become their own journaled operation

`OpAddRoute` joins the five operations in the network journal, with its own
compensation.

This amends NM-09 for announced routes and **leaves it in force for the routes a
peer implies**. Those still ride with `ApplyPeer`, still cannot drift from the
peer, and still take the peer's lifetime — NM-09's argument holds and nothing
about it is weakened.

What changes is that a route which arrived by announcement can be withdrawn,
expire, or lose a selection without touching the tunnel. Under NM-09's coupling
the only way to remove one prefix would be to reapply the peer with a new set,
which rewrites live kernel state — and a failure there takes down a working
tunnel to withdraw a route. That is a worse failure than the one NM-09 was
avoiding, and it is the one M2.4 would hit on every expiry.

### One route per prefix, and conflicts stay visible

Selection picks a single route per prefix. Two equal candidates do not become
ECMP, because a node that silently load-balances across two providers is making a
routing decision nobody expressed. The loser is recorded and reportable rather
than discarded, so an operator can see that a conflict exists.

Hysteresis governs replacement: a new route has to beat the installed one by a
margin, over a window, before it replaces it. This mirrors the roaming rule
already in `SessionManager`, for the same reason — a decision that flips on noise
is worse than a slightly stale one.

**Local routes win.** A prefix this host already reaches without the mesh is not
replaced by an announcement, because the announcement cannot know what it would
be breaking.

### What is refused, before policy is asked

- **Martians** — loopback, link-local, multicast, unspecified, documentation
  ranges. Nothing legitimate announces them.
- **The node's own prefixes**, which would black-hole local traffic.
- **Any prefix containing a tunnel endpoint, a relay, or a STUN observer.** This
  is the loop: routing the transport into the tunnel that depends on it. It is
  refused rather than protected by policy routing, because refusing is
  verifiable and a separate routing table is one more thing to leave behind.
- **Default routes.** `accept_default_route` can turn a refusal into a question
  (NM-24), and in this MVP the question has no way to be put to a person, so the
  answer stays no. Internet exit is MVP 4.

### Expiry, withdraw and close all remove the route

Transactionally, through the journal, by the same path. An announcement carries
its validity and a node that stops hearing from a provider drops the route on its
own — reachability that depends on a peer must not outlive the peer's ability to
say so.

## Consequences

- **A new message type is a wire event.** The payload is decoded with unknown
  fields refused, so an older build rejects a route message rather than ignoring
  it. That is deliberate: silently dropping a route message would leave the two
  nodes disagreeing about reachability with nothing to see.
- **The controller port grows a route surface.** Routes are an implementation
  detail of `ApplyPeer` today, so `AddRoute` and `RemoveRoute` are new on the
  port, and the fake controller has to model them or a FIB test would assert
  against nothing.
- **`Existed` is harder for a route than for an interface.** The journal records
  whether it created a thing so compensation does not remove something that was
  already there. Interface state does not currently report routes, so this must
  be answered by querying rather than assumed — and assuming would mean deleting
  an operator's own route on rollback.
- **The RIB is domain state and stays free of the OS.** Selection, conflict and
  hysteresis are computation over prefixes; only the FIB touches the kernel.
- **MVP 4 inherits the shape.** Internet exit is a default route with consent and
  loop protection, which is this pipeline with the answer to one question
  changed.

## Alternatives rejected

**Keep routes coupled to `ApplyPeer` and reapply the peer on every change.** No
new operation, no port change. Rejected above: withdrawing one route rewrites the
whole peer, so an expiry can take down a working tunnel, and `ApplyPeer` replaces
`AllowedIPs` wholesale — a caller that reapplied with a partial set would strip
the peer's routing silently.

**Install announced routes in a separate routing table with policy routing.**
Avoids colliding with the main table and would let a loop be contained rather
than refused. Rejected because it moves the loop from "refused and reported" to
"present but not selected", which is harder to verify and leaves more state to
reconcile after a crash.

**Allow ECMP when two providers announce the same prefix.** Uses both paths.
Rejected because equal-cost is a claim by two providers about themselves, and
believing it splits traffic on evidence this node did not gather.

**Trust the announced metric.** Simplest selection. Rejected for the reason the
architecture separates announced metrics from measured ones: a provider's claim
about its own path is an input to a decision, never the decision.

## Validation

- **An announcement never reaches the kernel without a decision**, asserted by
  planting a bypass and watching it fail.
- **Every refusal class has a test** — martian, local prefix, endpoint capture,
  relay and observer capture, default route — each with the announcement
  otherwise valid, so the refusal is attributable.
- **Withdraw, expiry and close remove the route** and leave no residue, asserted
  against real kernel state in namespaces rather than against the fake alone.
- **Duplicate and out-of-order announcements** converge on the same RIB.
- **A conflict is visible and singular**: one route installed, the loser
  reportable, no ECMP.
- **Restart reconciles**, installing what the RIB says and removing what it does
  not.
- **Two subnets behind gateways**, in namespaces, carry traffic only when policy
  allows — the effect test, since a FIB entry that routes nothing is
  configuration rather than function.
- **Every guard is exercised by planting the violation** before it is trusted.
