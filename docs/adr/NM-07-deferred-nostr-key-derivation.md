# NM-07 — Deferred Nostr key derivation

**Status:** Superseded by [NM-12](NM-12-real-key-derivation.md)
**Date:** 2026-08-30
**Milestone:** M0.2
**Superseded:** M1.3

## Context

M0.2 builds the identity domain and a development keystore. Storing a Nostr
identity requires a public key, and deriving a real one requires secp256k1
x-only key derivation.

That library choice is not isolated. The same dependency will provide event
signing and the NIP-44 encryption scheme, both of which arrive in M1.1 along
with the protocol specification. Q-02 in the project documentation lists the
signer backend and encryption scheme as open, to be resolved in M1.1.

Choosing a secp256k1 library now would fix that decision before the protocol
work that should inform it, and MVP 0 needs no Nostr functionality at all: it
configures tunnels manually and never contacts a relay.

## Decision

`DeriveNostrPublicKey` returns a **development placeholder**: a domain-separated
SHA-256 digest of the private key. It is not a secp256k1 point and is not a
valid Nostr identity.

The placeholder is documented at the function, in the CLI output, and here. Real
derivation arrives in M1.1 with the signing adapter.

**M1.1 must invalidate every identity created by this code.** A placeholder
identity has no corresponding secp256k1 key, so it cannot sign, cannot be
addressed by a peer, and must not be carried forward.

## Alternatives considered

**Adopting a secp256k1 library now** — would produce real keys immediately.
Rejected because it commits to the library that will also carry signing and
encryption, before M1.1 has specified either. Reversing that choice later is
more expensive than deferring it, and MVP 0 gains nothing from real keys.

**Storing only the private key and deriving on load** — avoids inventing a
public key. Rejected because it moves the same problem: derivation still needs
the library, and the keystore would have no stable identifier to record.

**Blocking M0.2 until the library is chosen** — technically clean. Rejected
because it inverts the roadmap: the keystore, the session machine and the secret
types are all independent of that choice and are what M0.3 builds on.

## Consequences

- The keystore, its permission checks and its atomic write are exercised end to
  end in MVP 0, which is what M0.2 is for.
- An identity created before M1.1 is not usable afterwards. This is acceptable
  only because MVP 0 has no peers, no relays and no persistent authorizations:
  there is nothing yet for an identity to be known by.
- M1.1 must, as part of its delivery: adopt the secp256k1 library, replace this
  function, and refuse to load any identity created by the placeholder rather
  than silently treating it as valid.
- The placeholder is domain-separated (`nostmesh-dev-placeholder-v1|`) so a
  value produced by it cannot collide with any real derivation scheme, and so
  the marker is greppable when M1.1 comes to remove it.
