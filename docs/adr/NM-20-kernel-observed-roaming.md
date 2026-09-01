# NM-20 — Following a roamed endpoint

**Status:** Accepted
**Date:** 2026-09-01
**Milestone:** M1.5

## Context

A peer that changes address is the same peer. Its authorization has not changed,
its tunnel keys have not changed, and what it is allowed to send has not changed.
Only the route to it has.

`RF-NET-03` requires detecting that and updating the endpoint "sem trocar
identidade da sessão". The M1.5 acceptance criterion says the same in the form of
a demonstration: "endpoint muda e sessão se recupera".

`SessionManager.Roam` was written for this, is transactional, and is tested. It
has never had a caller. Today an endpoint change surfaces as a stale handshake,
the session is torn down, and the worker renegotiates from nothing — discarding a
session id, a key pair and an authorization in order to learn a routing fact.

### Why the obvious verification is unavailable

`Roam` refuses a candidate that has not been verified, and its doc comment gives
the reason: accepting an unverified endpoint would let anyone who can forge a
packet redirect an established tunnel.

That check cannot be performed after a session is established. NM-15 phase B
hands the UDP port to the kernel — `establish` closes the transport before
configuring WireGuard, because the port the peer verified is the port WireGuard
must bind. From that moment there is no socket from which to send an
authenticated probe, and opening a new one would bind a different port, which
describes a different NAT mapping to a different address.

So the rule as written is unreachable here, and a decision has to be made rather
than deferred: either roaming is not implemented, or something other than our own
probe has to carry the proof.

## Decision

**Follow the endpoint the kernel observed, and record the move rather than
authorize it.**

`Hold` already observes the data plane every few seconds. When the observed
endpoint differs from the one the session has recorded, the manager writes the
new one through the journal, leaving the session id, tunnel keys and AllowedIPs
untouched.

A separate method carries this: `RecordObservedEndpoint`, beside `Roam` rather
than replacing it.

## Why the kernel's observation is sufficient proof

WireGuard moves a peer's endpoint only after authenticating a packet from the new
address. The packet is AEAD-sealed under keys derived from that session's
handshake, and the anti-replay window rejects a captured datagram replayed with a
counter already seen.

So the capability required to move that endpoint is possession of the session's
tunnel key material. An attacker who has that already holds the tunnel; there is
nothing left for a connectivity probe to protect. An attacker who does not have
it — who can spoof a source address, flood the port, or replay stale traffic —
cannot move the endpoint at all, because the kernel discards what it cannot
authenticate.

**The probe this design cannot run authenticates with a session-derived
challenge. The kernel authenticates with the tunnel key that challenge exists to
protect.** Requiring the weaker proof to ratify the stronger one would be
ceremony, and the price of the ceremony would be no roaming at all.

The invariant this appears to bend — a third-party candidate stays UNVERIFIED
until an authenticated check at the exact address — governs *claims*. A STUN
observer, a peer, and a relay are parties this node does not control, and what
they say about reachability is evidence of what they saw. A kernel-observed
endpoint is not a claim from anyone. It is this node's own kernel recording what
it successfully decrypted.

## Why a sibling method, not a wider `Roam`

`Roam` takes a `connectivity.Candidate` and checks `Status.Permits()`. That
contract is right for the case it was written for — a path the connectivity
engine nominated after proving it — and control-plane migration will still need
it.

Constructing a synthetic candidate marked `StatusValid` to get past that check
would be lying to the guard, and would leave the guard meaning nothing at the one
call site that still depends on it. Adding an origin flag would push the branch
into every caller and make the check conditional, which is exactly what
`Status.Permits()` was written to prevent.

The two paths differ in kind: one authorizes an endpoint the node chose, the
other records one the kernel adopted. They share their effect — a journaled
`ApplyPeer` — and that is shared in code. They do not share their precondition.

## Consequences

- **Roaming needs no control-plane traffic and no port rebind.** Both ends
  observe their own kernel and converge independently. There is no message to
  exchange and none is sent.
- **The recorded endpoint stops going stale.** This is the strongest practical
  reason to write at all: a later reconciliation that trusted our stored endpoint
  would otherwise overwrite the kernel's correct one with an address the peer
  left.
- **Every move is journaled**, so it is attributable and auditable like any other
  network change.
- **Flapping is bounded and visible.** A host alternating between two paths would
  otherwise rewrite kernel state on every poll. A minimum interval collapses that
  to one write per window, and `RoamCount` in `nostmesh state` shows an operator a
  path that is not settling — before the session dies rather than after.
- **A failed roam does not end the session.** The tunnel is already carrying on
  the new address; failing to record our agreement with the kernel is a
  bookkeeping problem. Ending the hold over it would turn a successful roam into
  a teardown, which is the regression this work removes.
- **Consent freshness comes from the data plane, not from a probe.** The
  architecture asks for something periodic that stops a path being kept after it
  is abandoned. The keepalive, WireGuard's rekey and the hold's staleness bound
  together provide it: a path nobody is using stops refreshing its handshake and
  the session is torn down. An explicit control-plane consent check remains
  future work, and cannot be built from a socket this node no longer holds.
- **If both ends move at once, neither follows.** No authenticated packet reaches
  either kernel, so neither endpoint moves, both sessions go stale, and the
  workers renegotiate through the full path. That is the boundary where
  kernel-observed roaming stops and control-plane migration would have to begin.
  It is not a regression — it is today's behaviour for every move — and the
  single-ended case, which is the common one, is what this improves.

### The documented state machine

`04-protocolo-e-seguranca.md` §3 has `ESTABLISHED ─ migration → CONNECTING`. That
arrow describes a renegotiation: candidates gathered again, exchanged again,
probed again, the port rebound. Following a kernel-observed move is a different
event — no message, no candidate, no rebind, and the data plane never stops
carrying — so it stays inside `ESTABLISHED`.

Driving the documented transition instead would mean tearing down a working
tunnel to re-derive an address the kernel already has. The arrow remains correct
for the case it describes; this ADR records that kernel-observed roaming is not
that case.

## Alternatives rejected

**Reopen a socket and probe.** Contradicts NM-15: the port belongs to the kernel
now, and a new socket would bind a different port whose NAT mapping describes
something other than the tunnel's path. It would prove a different address works,
which is not the question.

**Renegotiate the session.** What happens today, by omission. It works, and it
fails the requirement: the session identity, the tunnel keys and the
authorization are all discarded to learn a route.

**Pass a synthetic verified candidate to `Roam`.** Satisfies the guard by
deceiving it. The next reader would find a candidate marked verified that nothing
verified.

**Carry the move over the control plane.** Slower than the kernel by seconds at
best, and unavailable exactly when a network change has also disrupted the relay
path. The kernel has already acted by the time such a message could arrive.

## Validation

Unit tests with each guard observed failing against a planted violation, and a
privileged test that moves a real address in a network namespace and confirms the
kernel follows it with traffic crossing afterwards.

The privileged test is the one that matters. Every argument above rests on one
empirical claim — that the kernel moves the endpoint on its own, after
authentication, without this node's involvement — and a fake would only agree
with whatever this project believes about the kernel. A second privileged test
sends unauthenticated traffic from an address the peer does not hold and asserts
the endpoint does **not** move, which is what makes the security argument a
demonstration rather than a paragraph.
