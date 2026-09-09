# NM-26 — Devices, published manifests, and where configuration lives

**Status:** Proposed
**Date:** 2026-09-08
**Milestone:** MVP 3
**Resolves:** #60 — whether one Nostr identity may cover several devices
**Extends:** NM-19 (identity import), NM-21 (addressing and manifests), NM-24 (policy)
**Amends:** NM-21 (the salt now travels), NM-04 (a signed manifest as local state)

## Context

A person with a laptop, a desktop and a phone wants all three in their mesh.
They already have a Nostr key, and the obvious thing to do — the thing NM-19
exists to enable — is to import that key onto all three.

That does not work, and until recently it failed silently. Four places assume
one identity means one device:

- **Role resolution** compares `local.String() < peer.String()`. With one key on
  both sides the comparison is false for both, so both become the responder and
  wait for a request nobody sends.
- **The inbox filter** subscribes on `#p` equal to the node's own key, so every
  device receives every other device's messages.
- **Recipient validation** compares the public key alone, so a message for the
  laptop is valid to the phone.
- **Address derivation** takes the public key, so every device computes the same
  overlay address.

The data plane is unaffected: WireGuard keys are ephemeral per session
(ADR-003), so tunnel keys never collide. The failure is entirely control plane
and addressing.

The silence is already fixed (#61): a peer presenting this node's identity is
refused with a reason. This ADR decides what to build instead, and in doing so
decides where a node's configuration lives.

## Decision

### 1. A device is an identity; a person is a manifest

Each device generates its own Nostr key pair, locally, and never transmits the
private half. The four breakages disappear, because each device remains a
distinct identity — nothing about role resolution, routing, validation or
addressing changes.

**The person's key is not a device key.** It signs the manifest; it never opens
a session. The user does not manage device keys and does not see them.

### 2. Three keys, and most nodes hold two

| Key | Purpose | Where |
|---|---|---|
| **Identity** | Signs the manifest | One device, or a remote signer |
| **Read** | Decrypts the manifest | Every device in the network |
| **Device** | Opens sessions | The device that generated it |

The read key is symmetric, 32 bytes, and **derived from the identity**:

```
readKey = HKDF(identityPrivateKey, "nostmesh/manifest-read/v<n>")
```

Derived rather than random so that any device holding the identity recomputes
it, including after a recovery from the seed — there is no separate thing to
back up.

**A node needs the identity key only to change the network.** A server approved
once holds the read key and its own device key: it reads the manifest, opens
sessions, and cannot publish, revoke or enrol. That is the recommended shape for
anything unattended, and it is why the read key exists as a separate thing.

### 3. `nostmesh init` asks two independent questions

**Which identity**, and **where it lives**. Every combination is valid:

|  | Local | Remote signer |
|---|---|---|
| **New key** | generate, encrypt with a password | generate, hand to the app, offer to erase |
| **Existing key** | paste `nsec`, `ncryptsec` or seed | pair by QR |

```
$ nostmesh init

  identity:
    1) create a new one
    2) use one I already have
  > 2

  how do you want to sign:
    1) paste the key here
    2) connect a nostr app
  > 1
```

Non-interactive: `nostmesh init --new --local`, `--import --app`, and so on.

**Local with a password is the default.** It depends on nothing external, which
is what a node must be able to do. The app is a choice the user makes and can
undo.

A fourth path exists for a node that will never hold the identity:
`nostmesh init --join`, which generates a device key, publishes a request, and
waits for approval.

### 4. Keys at rest use NIP-49; a seed is the backup

A key stored locally is encrypted with the user's password — scrypt and
XChaCha20-Poly1305, in the standard `ncryptsec` form. Storing a raw key stays
possible for an unattended server and is reported as the weaker choice it is.

**A new identity is shown a BIP39 seed once**, as the recovery path for a
forgotten password or a lost phone. Without it, both are unrecoverable, and
losing a phone is ordinary rather than an edge case.

NIP-06 is marked *unrecommended* upstream, and the recommendation is against
**deriving several keys** from a mnemonic — *"prefer a single nsec"*. Using
BIP39 only to render one key as memorable words is not that.

**The encrypted key is never published.** NIP-49 says so: accumulating encrypted
keys on relays helps somebody cracking them.

### 5. The remote signer is optional, and reversible in both directions

NIP-46 exposes `sign_event`, `nip44_encrypt` and `nip44_decrypt`, so an app can
both sign the manifest and read it. The `identity.Signer` port was written for
exactly this — *"a hardware token or remote signer can implement it by signing
without ever revealing key material"*.

```
laptop$ nostmesh identity export --to-app     # local → app
laptop$ nostmesh identity import              # app → local
```

Neither direction republishes anything or is visible to peers: it is the same
identity, held somewhere else.

**It is never required.** A node whose bunker relay is unreachable moves back to
local with one command, which keeps a third-party app from becoming a dependency
of the mesh.

### 6. The manifest gets its own event kind

**Kind 31112**, adjacent to the 31111 used for signalling and in the same
parameterized-replaceable range.

**Not 31111.** That kind carries session signalling, where every message is
distinct and must be delivered. Parameterized-replaceable means a relay keeps
only the newest per `(author, kind, d)` — right for a manifest, destructive for
signalling. Sharing one kind would let a relay legitimately discard a candidate
update because a manifest replaced it.

Both kinds remain provisional. **This reopens Q-03**, whose deadline has passed:
the experimental kind is in use with its rationale in the protocol document
rather than in an ADR. Settling it is a prerequisite for publishing outside a
lab.

### 7. The manifest is encrypted under the read key

NIP-44, keyed by the derived read key rather than by the identity directly. This
is what lets a node read the manifest without being able to publish one.

The pattern follows NIP-51, which encrypts private list entries with *"the same
scheme from NIP-44"* using a key *"computed using the author's public and private
key"*. Same mechanism, one derivation removed so that reading and writing are
separable.

**Encryption is not authentication.** NIP-44 is symmetric AEAD: anyone holding
the key can read and write. The **signature** authenticates, and `Accept` checks
it against the pinned issuer — which is why a stolen read key cannot forge a
manifest, only read one.

**What remains visible**, and is accepted: that a key published a manifest and
when, its approximate size, and how often it changes. Padding to size classes
reduces the second; recorded as a limitation, not decided here.

### 8. A device joins by being approved, and approval delivers the read key

**The new device publishes a request**, encrypted with NIP-44 to the network
owner's identity. It carries the device's public key and its proposed name.
Encrypted rather than plain so that a relay does not learn that a device called
`pc-novo` is joining a particular network.

**A device holding the identity approves it**, doing two things:

1. Publishes an event encrypted from itself to the new device's key, carrying
   the read key. Only that device can decrypt it, because the conversation key
   derives from the pair.
2. Republishes the manifest with the new device among the members.

**The new device completes on its own**: it decrypts the read key, decrypts the
manifest, and replicates the configuration.

**The first device needs no approval**, having just created or imported the
identity.

**Rotating the read key** — after a device is lost — means incrementing the
derivation counter and re-delivering to every remaining device. One command
that touches all of them, which is the cost of the read key being shared.

### 9. The salt travels in the manifest, which amends NM-21

NM-21 kept the salt out deliberately: *"shared out of band between members and
never published, which is what stops a relay operator holding every event from
deriving a single address."*

That reasoning assumes a manifest in cleartext. **This one is encrypted**, so a
relay operator holding every event decrypts none of them. The property NM-21
protects is preserved by a different mechanism.

The salt has to travel, because addresses derive from `HKDF(salt, pubkey,
counter)` and a new device computes nothing without it.

**The salt gains the protection the other secrets have.** NM-06 makes a private
key fail to serialize rather than leak; `NetworkSalt` is a plain array today and
must become a type that redacts in logs and diagnostics before it travels.

### 10. Routes are always local

The manifest carries **no route and no `AllowedIPs`.** Giving a peer access to a
LAN is a decision each node makes, and the invariant that routes derive from
local policy holds without exception — including for a manifest the node's own
owner signed.

This costs less than it appears. A session's `AllowedIPs` has two parts:

- **the peer's overlay address**, which is `Allocate(manifest, salt, subnet)` and
  needs no configuration at all
- **any subnet that peer routes**, which is the real decision and stays local

So a new device works unconfigured in the common case, and only somebody routing
a LAN configures anything — which is the case that should be deliberate.

### 11. Your own manifest carries your policy; a third party's carries only membership

**From your own manifest** a device reads: the other devices, the salt, the
network id and subnets, and the policy rules you wrote. That policy is your own
configuration, signed by you, following you between your own machines.

**From a third party's manifest** a node reads *only who their devices are*. A
group rule naming their manifest means "the members of the manifest I pinned";
what those members may do is decided here.

**These are two different pins.** `network.issuer` is the identity whose
manifest configures this node — one per node, because a device has one owner.
`groups[].manifest` names other people's manifests, and there may be many. The
current single `Issuer` field covers only the first.

### 12. This amends NM-04, deliberately and narrowly

NM-04 says overlay addresses and policy are *"derived from local policy and
local state. No remote field configures the kernel directly."*

Reading the salt and policy from a published manifest makes local state arrive
over Nostr. That is a change, and it is bounded:

- **Only from a manifest signed by the identity the operator pinned**, verified
  before anything is read.
- **Only the operator's own manifest.** A third party's contributes membership
  and nothing else.
- **Never routes.** §10 keeps the strictest part of NM-04 intact without
  exception.

The distinction: a peer proposing a route is remote authority; a person's own
signed configuration reaching their own machines is not. Recorded here rather
than left implicit, because "it is still local, really" is exactly the kind of
argument that erodes an invariant.

### 13. All of it is optional, and the manual mode stays exactly as it is

A node with no `network` section behaves as today: peers listed by key in a local
file, no manifest, no publishing, no relay lookup.

This is already how the code works and is already tested —
`TestANodeWithoutANetworkKeepsItsManualAddress`,
`TestAConfiguredNetworkWinsOverAManualAddress`, and
`TestABrokenNetworkDoesNotFallBackToManual`. That last one carries a decision
worth restating: **a configured network that cannot be loaded is an error, never
a quiet fall back to manual**, because an operator who configured one and
silently got the other has a node that is not on the network they think it is.

Every path this ADR adds keeps that shape. Manual is not a legacy mode kept for
compatibility; it is the mode a node uses when it has no network, and it must
stay complete on its own.

### 14. A local rule always wins, and lives in its own structure

**This is a new precedence, not the one NM-24 decided.** NM-24 settled per-peer
against group, because an operator writing a specific rule would otherwise find
it silently ignored. The same reasoning applies here — a rule written on one node
means that node — but it is a separate rule needing its own tests.

**Local rules live in a separate structure**, not in the published one with a
flag. If the two shared a shape, something would eventually synchronise the
wrong one. The publisher has no access to the local section: separation by
construction rather than convention.

### 15. Every command that changes policy states where it applies

```
nostmesh peer revoke ana
  error: say where this applies.
    --local     this node only
    --publish   all your devices (republishes the manifest)
```

**No default.** Either is wrong half the time, and the failures differ: `--local`
assumed gives a false sense of having revoked everywhere; `--publish` assumed
propagates a local decision to the whole network.

### 16. The origin of every rule is visible

```
nostmesh policy show

  network "casa" — manifest v7, published 2h ago by npub1abc...
  this node: read-only (no identity key)

  FROM THE MANIFEST (shared with your devices)
    my-devices     3 members       session
    ana            npub1xyz        session

  THIS NODE ONLY (never published)
    ana            revoked         ← overrides the manifest
    ana            10.0.0.5/32     ← routes are always local

  ⚠ 1 local rule differs from the manifest.
    Your other devices still accept "ana".
    To apply everywhere:  nostmesh peer revoke ana --publish
```

`policy explain` gains the same: which rule decided, where it came from, and
what it overrode.

### 17. The identity key is the root of trust, and this ADR does not change that

**Whoever holds the identity key can publish a manifest.** They can enrol a
device of their own, and publish a version revoking every real device.
Encryption does nothing against this: the signature is what peers check, and the
attacker holds the key that makes it.

That was already true — the key could always impersonate its owner. What this
adds is that it can change the membership other nodes act on. What it removes is
the need for that key to sit on every machine.

**Version monotonicity has a cost.** `Accept` refuses a version at or below the
one held, which stops a relay replaying an old manifest. It also means an
attacker publishing version 99 leaves the owner unable to publish 98: recovery
requires going above it, or rotating the identity.

**A suspicious jump is confirmed, not applied:**

```
⚠ manifest jumped from v7 to v99 and removed 3 devices.
  apply?  nostmesh network accept --version 99
```

This turns a silent compromise into a question. It does not prevent one.

## Consequences

- **A peer is configured once**, not once per device of theirs, and not again
  when they add one.
- **Replacing a machine is `init` plus one revoke.**
- **Most nodes never hold the identity key**, which is the security gain that
  justifies the read key's complexity.
- **A second kind must be claimed**, and Q-03 answered before this leaves a lab.
- **`config.Network.Issuer` must become two things** — the owner's manifest and
  the third-party manifests a group may name.
- **`NetworkSalt` must become a redacting type** before it travels.
- **Routing a LAN is configured per node.** Deliberate, and the only thing that
  does not replicate.
- **Losing a device means rotating the read key** to stop it reading future
  manifests. Removing it from the membership stops new sessions immediately;
  rotation is the slower, complete step.
- **Two devices approving at once** publish competing versions and the relay
  keeps one, losing an approval. The person re-approves.
- **Forgotten password and lost seed is unrecoverable.** Inherent, and the reason
  the seed is shown at creation rather than on request.

## Cases this does not cover

- **A device shared by two people.** A node has one `network.issuer`, so one
  owner; the other person is a peer. A limitation for the documented "two or more
  users sharing devices" persona.
- **Leaving somebody's network.** Removing their group stops this node trusting
  them; their manifest may still list a device of yours, and only they can remove
  it.
- **Nodes with disjoint relay sets.** One publishes where another does not read.
  The manifest is found or it is not; there is no reconciliation.
- **Changing the password**, **renaming a network**, and **listing another
  person's devices** have no commands yet.

## Alternatives rejected

**One identity with a device suffix**, addressing keyed by `(pubkey, device)`.
Fewer keys, and the address counter already accommodates it. Rejected on
revocation: a device id is authenticated by nothing, so whoever holds the key can
claim any device id. A stolen laptop compromises the identity and cannot be
revoked in isolation. For the persona whose documented risk is *configuration and
key loss*, that is the worst available failure mode. It also leaks device count
to relays, since every device's traffic carries one public key.

**The identity key on every device.** The simplest way to make `init` replicate
configuration: encrypt the manifest to the identity and give every device the
identity. Rejected because stealing any one device then steals the network — the
same failure mode rejected above, arrived at from the other direction. The read
key exists to avoid it.

**Deriving device keys from a seed** — one secret, many keys, unlinkable. Not
rejected, superseded: NIP-49 gives one thing to hold without deriving anything,
and preserves the identity the person already has.

**Publishing the manifest in cleartext.** Rejected in §7.

**Publishing a third party's policy with their membership.** Would remove the
last manual configuration. Rejected because it inverts ADR-005: whoever obtained
that person's key would rewrite the policy of every node trusting them.

**Refusing shared identities permanently.** Implemented as #61 and correct as an
interim answer. Rejected as an end state: it declines the use case NM-19 exists
to serve.

**Waiting for a standard.** Issue #1810 upstream raises this exact problem —
*"each device should have its own key, but they should be linked"* — and is
discussion without a specification. The manifest is this project's answer
meanwhile; if that becomes a NIP, this is worth revisiting.

## Validation

- **A node with no `network` section behaves exactly as before**, asserted by the
  existing suite passing unchanged, and by planting the new code paths to confirm
  none of them run.
- **A configured network that fails to load is an error**, never a fall back to
  manual — the existing guard, kept.
- **Nothing in the local section reaches the publisher**, exercised by planting a
  local rule and requiring it absent from the published manifest. The guard that
  matters most: a local decision leaking to the network breaks nothing visibly.
- **No manifest carries a route**, exercised by planting `allowed_ips` in one and
  requiring it ignored, from the node's own manifest as much as a stranger's.
- **A third party's manifest cannot introduce a policy rule**, exercised the same
  way.
- **A node with the read key but no identity key opens sessions and cannot
  publish**, which is the property §2 exists for.
- **A manifest signed by another key is refused**, even when it decrypts.
- **A published manifest is unreadable without the read key**, asserted against
  the encrypted event rather than the structure.
- **The read key is not recoverable from the manifest or from a device key.**
- **The salt round-trips**, so a new device derives the addresses an old one
  already uses.
- **The salt never appears in a log or a diagnostic bundle**, asserted the way
  NM-06 asserts it for private keys.
- **A local rule beats the manifest**, in both directions, as its own tests.
- **Manifest and signalling do not displace each other on a relay.**
- **A suspicious version jump stops rather than applies.**
- **Every guard is exercised by planting the violation** before it is trusted.
