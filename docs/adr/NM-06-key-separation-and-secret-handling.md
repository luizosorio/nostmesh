# NM-06 — Key separation and secret handling

**Status:** Accepted
**Date:** 2026-08-30
**Milestone:** M0.2

## Context

NostMesh holds two kinds of secret with different lifetimes and different
blast radii. The Nostr private key is durable and authorizes everything; the
WireGuard private key is ephemeral and per-session. The project documentation
states that they never share material and that the WireGuard private key never
leaves the node that generated it.

Stating an invariant in a document does not enforce it. The failure mode is
mundane: someone adds a debug log, a diagnostic export, or a struct that gets
serialized, and a key ends up somewhere it was never meant to be. By the time it
is noticed, the key is in a log aggregator.

## Decision

**Secrets are distinct types that cannot be printed.** `NostrPrivateKey` and
`WireGuardPrivateKey` implement `String`, `GoString`, `MarshalJSON` and
`slog.LogValue` so that every path which would normally reveal a value yields a
redaction marker instead. `MarshalJSON` returns an error rather than a redacted
string, so a struct carrying a secret fails to encode instead of silently
shipping a placeholder.

**Public keys are distinct types too.** `NostrPublicKey` and
`WireGuardPublicKey` are both 32 bytes, which is exactly why they are separate
types: confusing them becomes a compile error rather than a review comment.

**There is one sanctioned way out.** `HexForKeystore` and `Base64ForKeystore`
exist for the development keystore alone. `Bytes` serves callers that genuinely
need the material, such as key derivation, and every call site is a place where
protection ends.

**Keys are destroyable.** `Destroy` zeroes the material and marks the value
consumed, so an ephemeral session key is not resident for the process lifetime.

**Authorization is a binding, not a key.** `TunnelKeyBinding` ties a WireGuard
public key to a session id, sender, recipient, nonce, sequence and expiry.
`ValidateFor` checks it against the local context before the key can have any
effect.

## Alternatives considered

**Type aliases over `[32]byte` with a documented convention** — simpler and
zero-cost. Rejected because it enforces nothing: the compiler cannot tell the
two key roles apart, and no convention survives a hurried debug session.

**Redacting at the logging layer** — a custom handler that strips key-shaped
values. Rejected because it only protects one egress path. Secrets also leave
through JSON encoding, error strings, diagnostic bundles and `%v` in a message;
protection belongs on the type, where every path passes through it.

**Returning `"[REDACTED]"` from `MarshalJSON`** — friendlier than an error.
Rejected because it produces well-formed output containing no data, which is
worse than a failure: the encode succeeds, the payload ships, and the missing
field is discovered later by whoever needed it.

## Consequences

- A secret cannot reach a log or a JSON payload through an ordinary mistake. It
  can still be extracted deliberately via `Bytes`, which is the point: the
  boundary is visible at the call site.
- `Destroy` reduces the exposure window but does not guarantee erasure. Go's
  garbage collector may have copied the value; this is documented rather than
  overstated.
- Tests assert the invariant directly, including against a real `slog` handler.
  Writing that test is what surfaced the need for `slog.LogValue`: without it,
  logging a secret produced an error string in the log rather than a clean
  marker.
- Every new secret type must implement the same four methods. This is a
  convention that a future ADR may want to enforce by test.
