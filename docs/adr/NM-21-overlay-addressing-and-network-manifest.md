# NM-21 — Overlay addressing and the network manifest

**Status:** Accepted
**Date:** 2026-09-06
**Milestone:** M2.1
**Resolves:** Q-04 — addressing strategy for IPv6/IPv4 and the network group

## Context

Overlay addresses are typed by hand today. `node.overlay_address` is a string in
the configuration file, and every peer's address is written twice — once as
`overlay_address` and once inside `allowed_ips` — because nothing derives one
from the other.

With two nodes this works. The mesh test that closed MVP 1 used `100.96.0.1`,
`.2` and `.3`, chosen by picking numbers. With several nodes somebody reuses an
address, and the failure does not announce itself: traffic reaches the wrong
node, and the tunnel that carries it is working exactly as configured.

Nothing detects this. `validatePeers` deduplicates peer names and public keys
and does not look at addresses at all, so two peers claiming the same overlay
address is a valid configuration file.

The architecture requires assignment without a central allocator, lists four
options to evaluate, and constrains the answer twice: *"Não se deve derivar um
IPv4 curto global diretamente da pubkey e supor unicidade"*, and *"A decisão
definitiva requer protótipo e análise de privacidade"*. Both constraints are
load-bearing, and this ADR answers them with numbers rather than assertions.

## Decision

**An address is derived from the node's Nostr identity and a network salt, in
IPv6. A signed network manifest defines the network. IPv4 is assigned
explicitly, never derived.**

```text
network prefix   fd <40-bit global id> :: /48        from the manifest's network id
subnet           16 bits                             carved by the manifest
interface id     64 bits = HKDF-SHA256(salt, pubkey, counter)
```

Four parts, each with its own reason.

**IPv6 ULA (RFC 4193), not IPv4.** The address space is what makes derivation
safe, and the arithmetic is not close:

| Nodes | IPv6, 64-bit host | IPv4 /16 | IPv4 /24 |
|---:|---:|---:|---:|
| 10 | ~0 | 6.9 × 10⁻⁴ | 1.6 × 10⁻¹ |
| 20 | ~0 | 2.9 × 10⁻³ | **5.2 × 10⁻¹** |
| 100 | 2.2 × 10⁻¹⁶ | 7.3 × 10⁻² | ~1 |
| 1 000 | 2.7 × 10⁻¹⁴ | ~1 | ~1 |

Expected nodes until the first collision: **5.4 × 10⁹** in 64 bits, **321** in a
/16, **20** in a /24. In IPv6 a collision is a correctness formality that must
still be handled; in IPv4 it is the ordinary case at the scale MVP 2 targets —
ten peers. This is the measurement behind the documentation's prohibition, and
it is why IPv4 is assigned rather than derived.

**A signed, versioned manifest defines the network**: network id, allowed
prefixes, members, a monotonic version, and any explicit IPv4 assignments. It is
distributed as a parameterized-replaceable Nostr event, so relays keep only the
newest per `(author, kind, d)` and versioning costs nothing to build.

**Derivation is deterministic and so is renumbering.** On conflict the counter
increments and the address is re-derived. Both ends compute the same sequence
from the same manifest, so renumbering is not negotiated — there is no message,
and no window in which the two disagree about which address is next.

**A conflict never installs silently.** Detection precedes installation, and an
unresolved conflict fails the operation with the two identities named.

## Why a manifest does not violate local intent

The project states in five places that addresses and `AllowedIPs` are local
intent, never taken from a peer (NM-04). A signed group manifest is, on its
face, remote authority. The two have to be reconciled rather than glossed.

They are reconciled by **who pins the issuer**. The operator names the manifest's
signing key in local configuration, exactly as `policy.authorized_peers` already
names the identities this node will talk to. A manifest signed by that key is
information this node asked for from a source it chose; a manifest signed by
anyone else is discarded without being read.

That makes the manifest *local intent obtained remotely*, which is the same shape
as an allowlist entry — and never a command. Nothing in it configures the kernel
directly: it supplies a prefix and a member list, from which local policy derives
what is installed. A manifest that named an address this node's policy does not
permit changes nothing.

## Privacy: what an address reveals, and to whom

An address is 64 bits of `HKDF(salt, pubkey)`. The question is who can invert
that to an identity.

| Observer | Can link address → identity? | Cost |
|---|---|---|
| Network member | **Yes** | One hash per member |
| Holds the salt, not the member list | No | Must search the pubkey space |
| Overlay traffic observer, no salt | No | Salt has full entropy |
| Nostr relay operator | No | Salt is never published |

So **linkability is bounded by possession of the manifest, not by the strength of
the hash.** A member mapping addresses to identities is not a leak: members are
listed in the manifest they hold, and they already know who each other are. The
property worth protecting is that this stops at the network boundary.

Three consequences follow, and they are design constraints rather than
observations:

- **The salt is network-secret and never published.** It does not appear in the
  manifest event, which is why a relay operator holding every event still cannot
  derive a single address.
- **The same identity in two networks gets unrelated addresses**, because the
  salt differs. Cross-network correlation by address is not possible, which
  matters because one identity is expected to join more than one network.
- **No secret key material enters the derivation.** The input is the public key.
  An address is therefore reproducible by anyone who should be able to reproduce
  it and reveals nothing that the public key did not already reveal.

This extends the observation table in `04-protocolo-e-seguranca.md` §9 with a row
for the overlay address; it does not restate it.

## Why the manifest is the tiebreaker, not the derivation

secp256k1 public keys are x-only, and the signer notes the consequence: two
private keys can produce the same public key, which is why the protocol
authenticates by signature rather than by key equality. A derived address
inherits that ambiguity — same public key, same address.

The derivation cannot resolve this, and should not try. The manifest can: it
lists members, so an identity that is not in it has no address in that network at
all, regardless of what it can derive. Membership is the authority; derivation is
only the function that turns membership into a number.

## Consequences

- **Addresses stop being typed twice.** A derived address is the obvious source
  for the peer's `AllowedIPs`, removing the hand-copied duplication that exists
  in every configuration file today.
- **The inert `overlay_address` field on the wire becomes checkable.**
  `SessionRequest` and `SessionOffer` carry it, and nothing writes, reads or
  validates it — it is covered by `OfferHash` and the envelope signature, and
  otherwise unused. With derivation, a receiver can recompute what the sender's
  address must be and compare, turning a proposal nobody consumed into a claim
  that either matches the manifest or is rejected. Populating it changes
  `OfferHash`, so it is a wire-compatibility event and belongs in the
  implementation, not in this ADR.
- **Manual addressing keeps working.** A node with `overlay_address` set and no
  manifest behaves exactly as it does now. MVP 1 is not degraded, which the
  sequencing rule requires.
- **Rollback is refused.** The manifest version is monotonic and persisted; a
  manifest older than the stored version is rejected. Without this, an old
  manifest replayed from a relay would renumber a working network backwards.
- **State stays in files.** NM-11 named MVP 2 as the moment to reconsider SQLite,
  and this is the first delivery to test that. The manifest is one signed
  document with a version, plus a map from address to identity — a file and an
  index, not a relational shape with cross-table invariants. NM-11 stands;
  M2.2's multi-peer state is where the question genuinely arrives.
- **Verification enters the core as a port.** `internal/domain`, `protocol`,
  `policy` and `config` cannot import `internal/nostr` or `btcec`, so manifest
  verification is an injected interface wired at `cmd/nostmesh`, mirroring
  `identity.Signer`. Derivation itself is pure and needs nothing forbidden:
  `crypto/hkdf` has been in the standard library since Go 1.24, so this adds no
  dependency.

## Alternatives rejected

**Derive a short IPv4 address from the public key.** Prohibited by the
documentation, and the table above is why: 20 nodes in a /24 collide more often
than not. Rejected on arithmetic, not preference.

**Assign addresses from a central allocator.** Solves collisions completely and
reintroduces the coordinator the project exists to avoid. A network whose
addressing depends on one reachable party has a single point of failure in the
one place the architecture refuses to have one.

**Negotiate addresses peer to peer.** Two nodes can agree, but agreement between
pairs does not produce a consistent assignment across a mesh, and the Nostr
control plane is explicitly eventual with no consensus (ADR-006). Deriving
independently from shared inputs gets consistency without agreement.

**Random address, retry on conflict.** Works, and loses reproducibility: an
address becomes state a node must persist and can lose, rather than a function of
identity it can always recompute. Detecting a conflict also requires having met
the other node, so two partitioned nodes would both believe they were unique.

**Publish the salt in the manifest.** Simplifies distribution and hands every
relay operator the ability to map addresses to identities across every network
using that manifest. The salt is the entire privacy boundary; publishing it
removes the boundary.

## Validation

Derivation is a pure function, so most of this is deterministic and testable
without root:

- **Golden vectors** in the existing `testdata` pattern: the same identity, salt
  and counter must produce the same address across runs and platforms. A change
  to that output is a compatibility break, and the diff is what says so.
- **Forced collisions**, by deriving two identities into a deliberately narrow
  space: renumbering must be deterministic on both sides, and an unresolved
  conflict must fail loudly rather than install.
- **A tampered manifest** must be rejected — recomputing the digest as well as
  checking the signature, following `VerifyEvent`, since checking only the
  signature accepts a document whose fields were rewritten around a valid
  signature of different content.
- **An older version** must be refused against persisted state, across a restart.
- **Two networks, one identity**, must produce unrelated addresses. This is the
  privacy claim, and it is the one that is worth asserting in a test rather than
  in a paragraph.
- **Manual mode** must be untouched.

Every guard is exercised by planting the violation and watching it fail before it
is trusted — a guard observed only in the passing state has not been validated.
