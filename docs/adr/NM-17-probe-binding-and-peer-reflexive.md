# NM-17 — Probe binding and peer-reflexive candidates

**Status:** Accepted
**Date:** 2026-09-01
**Milestone:** M1.5 (completing)
**Amends:** [NM-13](NM-13-connectivity-and-stun.md)

## Context

NM-13 established the connectivity check: this project's own authenticated
probe, bound to the session, so that an observer which lies about an address
cannot produce a valid response from it. That decision stands. What it did not
settle is which address the probe authenticates over, and that turned out to
decide whether a NAT'd pair can connect at all.

Two hosts were measured, one behind an address-dependent NAT. Both sides probed,
both answered every probe they received, neither verified a candidate, and
nothing reported an error. The instrumentation added while diagnosing it said:

```
vultr-nat:    5 datagram(s) arrived, 3 answered, 0 discarded
vultr-public: 8 datagram(s) arrived, 5 answered, 0 discarded
```

Nothing discarded, nothing failed to send, and no path found. Three separate
defects produced that, and each was invisible while the others held.

**The challenge authenticated over an address the two ends do not share.** The
sender knows where it aimed; the receiver knows where the datagram came from.
Behind NAT those differ, so a challenge bound to either was silently rejected by
the other side.

**Nobody held a candidate for the address that works.** A NAT maps per
destination. The `srflx` address a peer publishes is the mapping its NAT made
toward the STUN observer, and an address-dependent NAT uses a different one for
traffic toward the peer. That second address is knowable to neither side in
advance — it exists only once a packet has travelled it — and the arrival source
of an authenticated challenge was being discarded.

**A response arriving after its candidate was re-probed matched nothing.**
Outstanding challenges were held one per candidate and overwritten on every
round. `Run` re-probes every probable candidate each round while waiting only
`CheckTimeout` for a single datagram, so on a fast path a reply routinely
arrives after the next round has replaced its nonce. Between hosts 0.36 ms
apart, that was most of them.

## Decision

**A challenge carries no address; a response states the address it saw,
authenticated.**

The challenge authenticates session membership and freshness, and nothing about
the path it travelled — because there is nothing about the path that both ends
agree on. The response authenticates over the address the responder observed,
which is the challenger's own mapped address for that exact path: the only way
to learn it without trusting a third party.

The challenge is padded so both messages are 75 bytes. A probe that answers with
more bytes than it received is a reflector, and that amplification would be
available to anyone able to spoof a source address.

**An authenticated challenge from an unknown source becomes a peer-reflexive
candidate.**

`KindPeerReflexive` was already declared, ranked ahead of `srflx`, and mapped in
the orchestrator; nothing constructed one. It is now constructed from the arrival
source of a challenge that has passed authentication — never before, so an
off-path attacker contributes nothing regardless of what source it spoofs.

The candidate enters `UNVERIFIED` like every other. A packet arriving from an
address proves the peer can reach us through it, not that we can reach the peer;
the challenge/response that follows decides that. Learning only means the address
gets probed at all.

**Outstanding challenges are keyed by nonce.**

The nonce names the exact challenge a response answers, so a reply belonging to
an earlier round still matches. Entries are removed on the answer that matches;
an unanswered one lives until the run ends, bounded by
`MaxCandidates x MaxAttemptsPerCandidate`.

## Why the strict rule was kept

A response must still arrive from the exact address probed. That rule is what
stops a correctly-signed response from an unprobed address promoting a candidate,
and relaxing it was the tempting fix: let a response "matching a peer-reflexive
address" satisfy the candidate it answers.

It was rejected. Giving the learned address its own candidate with its own id
makes the strict rule *true* rather than weakened — the challenge goes to the
peer-reflexive address and the response comes back from it. The guard that
protects this is `TestAResponseFromTheWrongAddressPromotesNothing`, and it is
unchanged.

## Consequences

- **A peer-reflexive candidate counts against `MaxThirdPartyCandidates`.** It is
  an address contributed by the peer, not one this node observed locally, and it
  carries the same cap as an `srflx` address from a lying observer.
- **A hostile but authorized peer has a bounded budget.** It can spend at most
  `MaxThirdPartyCandidates` (8) addresses, probed `MaxAttemptsPerCandidate` (5)
  times each, at 75 bytes, toward addresses `ValidateAddress` permits — loopback,
  multicast, link-local and unspecified are excluded. Amplification stays below
  1, and answering still costs exactly one packet. This is the same exposure
  `srflx` candidates already had; it is written down here rather than left
  implicit.
- **Learned candidates are not published to the peer.** `toWireAll` publishes
  what the gatherer found, not what the engine learned. Announcing a peer's own
  NAT mapping back to it would be useless, and the code carries a note so nobody
  "fixes" it later.
- **The response's `Observed` field is deliberately not fed into the engine.**
  It names *this* node's address, while the candidate table holds addresses to
  send to. Inserting it would create a candidate pointing at our own NAT mapping,
  which `ValidateAddress` would not catch and a hairpinning NAT could answer.
  Its legitimate use — learning our own mapped address to publish, without
  trusting an observer — belongs to the gatherer and to its own decision.

## Validation

The end-to-end guard is `TestANatdPathVerifiesThroughAPeerReflexiveCandidate`,
which runs against a transport that models an address-dependent NAT: the
announced address is a black hole, and a mapping opens only when the peer sends
through it first.

That fake is deliberately not the one the other checker tests use. The existing
`fakeTransport` answers at whatever address it was aimed at — its own comment
says the announced and working addresses are the same value — so it cannot fail
on the difference this ADR exists to handle.

Each guard was confirmed by planting the violation and watching it fail. The one
that mattered most was making the NAT fake generous, opening the *announced*
address instead of the one the peer used: the test then failed, which is what
proves the pass comes from the learning rather than from an accommodating fake.

Verified between two real hosts, one behind NAT: `session.established` in 2.3
seconds, and four ICMP echoes over the overlay produced eight 128-byte encrypted
datagrams between the physical endpoints.
