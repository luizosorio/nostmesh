# NM-12 — Real key derivation replaces the placeholder

**Status:** Accepted
**Date:** 2026-08-30
**Milestone:** M1.3
**Supersedes:** [NM-07](NM-07-deferred-nostr-key-derivation.md)

## Context

NM-07 deferred secp256k1 key derivation from M0.2, on the grounds that the same
library would carry event signing and NIP-44 encryption, and that choosing
before the protocol work would fix the decision prematurely. In the meantime,
`DeriveNostrPublicKey` returned a domain-separated SHA-256 digest.

NM-10 selected the library. This milestone needs real signatures, so the
placeholder goes.

## Decision

**Derivation and signing use secp256k1 Schnorr** via `btcec`, in
`internal/nostr`. Public keys are x-only, as Nostr specifies.

**Identities created by the placeholder are rejected on load**, not silently
accepted. The keystore recomputes the public key from the stored private key and
refuses a mismatch with an error that says to regenerate.

**The identity package does not import the cryptography.** Derivation is
injected as a function value, wired at the composition point in `cmd/nostmesh`.
`internal/identity` stays testable without a curve implementation, and the
architecture test that forbids the coupling keeps applying.

## Why rejection rather than migration

A placeholder identity has no corresponding curve point. It cannot sign, cannot
be addressed by a peer, and cannot be converted into a valid identity — the
private key is fine, but the public key it was stored with is a digest of it
rather than a point derived from it.

Accepting one would produce a node that appears configured, generates events
nobody accepts, and fails in a way that points at the network rather than at the
identity. Refusing to load it turns that into one clear message at startup.

This is acceptable because MVP 0 had no peers, no relays and no persistent
authorizations: there is nothing an old identity is known by.

## Alternatives considered

**Re-deriving the public key on load and rewriting the file** — would migrate
silently. Rejected because it changes an identity's public key without the
operator knowing, and an identity's public key is how peers name it. A silent
change to that is exactly the kind of thing that should require consent.

**Keeping the placeholder behind a flag** — would ease testing without a curve.
Rejected: two derivation paths means the tested one and the shipped one can
differ, which is worse than requiring the real implementation everywhere.

## Consequences

- Any identity created before this milestone must be regenerated. Documented in
  the error message rather than only here.
- `internal/nostr` now owns signing as well as encryption, which keeps the
  cryptographic surface in one package.
- The `identity.DeriveNostrPublicKey` function value is nil until wired. The
  keystore treats that as "cannot verify" rather than "verified", so a caller
  that forgets to wire it gets an explicit failure rather than a skipped check.
- Signature verification failures do not distinguish malformed from wrong, for
  the same reason decryption failures do not: either distinction is an oracle.
