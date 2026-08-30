# NM-10 — Nostr cryptography and library scope

**Status:** Accepted
**Date:** 2026-08-30
**Milestone:** M1.1
**Resolves:** Q-02 (signer backend and encryption scheme)

## Context

The control plane needs three cryptographic capabilities: secp256k1 x-only key
derivation, Schnorr signatures over NIP-01 event ids, and a directed encryption
scheme for payloads.

NM-07 deferred this decision from M0.2 on the grounds that the same library
would carry all three, and that choosing before the protocol work would fix it
prematurely. That protocol work is this milestone.

The project rule is explicit: do not invent cryptography. That narrows the
question to which existing implementation, and how much of it to take on.

## Decision

**NIP-44 v2** is the directed encryption scheme, via
`github.com/nbd-wtf/go-nostr/nip44`.

**Schnorr signatures and secp256k1** come from
`github.com/btcsuite/btcd/btcec/v2` and its `schnorr` subpackage.

**Only subpackages are imported. The `go-nostr` root package is never
imported.** That package pulls in a WebSocket client, three JSON libraries and a
URL parser — none of which this project needs, since the relay client is ours to
write and the codec is ours to control.

The dependency boundary is enforced the way other boundaries are: an
architecture test fails the build if `go-nostr` is imported anywhere but the
`nip44` subpackage, and if anything outside `internal/nostr` imports transport
libraries at all.

## Verification

The library was tested against the official NIP-44 vectors from
`paulmillr/nip44`, not against its own test suite:

- 35/35 conversation key derivations match.
- 10/10 official payloads decrypt to the expected plaintext. This is the
  interoperability check that matters: it proves agreement with other
  implementations rather than internal consistency.
- 11 invalid payloads rejected, 0 accepted.

Licenses across the resulting tree: MIT, ISC, BSD-3-Clause, Apache-2.0. No
copyleft. The build stays CGO-free and cross-compiles for Windows and macOS.

## Alternatives considered

**The full `go-nostr` library** — includes a relay client, subscription handling
and event types, which would save writing them. Rejected because it brings 16
modules into the binary against 4 for the subpackage, and because the relay
client's behaviour under adversarial conditions (duplicate, delayed, reordered,
dropped events) is a core concern of MVP 1 that this project needs to control
directly rather than inherit.

**Implementing NIP-44 from primitives** — `btcec` for ECDH, `x/crypto` for HKDF
and ChaCha20, standard library for HMAC. Would save one module. Rejected because
the v2 padding scheme has details that are easy to get subtly wrong, the project
rule forbids inventing cryptography, and a local implementation would need the
same official vectors to prove itself while becoming ours to maintain.

**NIP-04** — the older encryption scheme, simpler and more widely deployed.
Rejected: it is unauthenticated, leaks plaintext length, and is deprecated in
favour of NIP-44.

## Consequences

- **Forward secrecy is absent.** NIP-44 derives a conversation key from the two
  long-term identities, so a compromised Nostr private key allows decryption of
  historical signaling that relays retained. This is documented in the protocol
  specification, not hidden: mitigations are short validity windows, minimal
  metadata and ephemeral WireGuard keys. Recovery after compromise requires key
  rotation, which the identity versioning already supports.
- **What historical decryption would reveal**: endpoints, candidates, negotiated
  routes, and *public* WireGuard keys. It does not reveal a WireGuard private
  key, which is never transmitted (NM-06).
- NM-07 can now be superseded: real secp256k1 derivation replaces the
  development placeholder, and identities created by the placeholder must be
  rejected rather than silently accepted.
- `internal/protocol` stays free of these dependencies. It defines envelopes and
  validation over bytes; `internal/nostr` owns the transport and the crypto
  adapter. The architecture test enforces that split.
- A stronger session protocol with forward secrecy remains possible later. It
  would be a new protocol version, not a change to this one.
