# NM-19 — Adopting an existing Nostr identity

**Status:** Accepted
**Date:** 2026-09-01
**Milestone:** M1.5

## Context

A NostMesh node's identity is a Nostr key pair, and `identity init` generates a
fresh one. That is right for a server built for the purpose and wrong for
somebody who already has a Nostr identity — from a phone client, a browser
extension, or anywhere else — and wants their node recognised as themselves.

Forcing a new identity on them is not a neutral default. It means every peer who
already knows them has to learn a second key and authorize it separately, for no
reason other than that the tool had no way to accept the first one.

The question was also asked from the other direction: reading the configuration
file, it is not obvious that a node has keys at all. Nothing in `nostmesh.json`
mentions one. That is deliberate, and it was not written down anywhere a person
would find it.

## Decision

**`nostmesh identity import` adopts an existing key**, accepting the bech32 form
other applications export and bare hexadecimal.

**The key is read from standard input, never from a command-line argument.**
Anything on a command line is written to shell history, is visible in the
process list to every user on the host, and is readable from `/proc` while the
process runs. A key that has been through any of those must be treated as
exposed. `--from-file` covers scripted provisioning, and a file whose mode is
readable beyond its owner is refused — the same rule the keystore already
applies to its own file, for the same reason.

**Importing never replaces an existing identity.** The keystore already refuses,
and no `--force` is added.

**No `identity export` is added.**

**Bech32 is implemented here** rather than taken from a library.

**`identity show --format npub`** renders the public key the way other
applications display it.

**A new document, `docs/identity.md`,** explains what the identity is, where it
lives, what the three encodings are, and what to weigh before reusing a personal
identity.

## Why bech32 is ours

The obvious source is go-nostr's `nip19`. It cannot be used: its first import is
the go-nostr root package, which NM-10 forbids and an architecture test refuses.
That package carries a WebSocket client, three JSON libraries and a URL parser —
NM-10 measured it at 16 modules against 4 for a subpackage — and the project has
its own relay client precisely so that behaviour under adversarial conditions is
its own to control.

The alternative was `btcsuite/btcd/btcutil`, already in the module graph as an
indirect dependency. Writing it was chosen instead: it is roughly 120 lines, the
specification is closed, and it adds nothing to the dependency inventory or the
SBOM.

This is not the "never invent cryptography" rule being bent. Bech32 is a
character encoding with a checksum. It keeps nothing secret, and no security
property of a key depends on it. What does depend on it — that a mistyped key is
rejected rather than silently accepted as a different key — is exactly what the
checksum provides, and it is verified against BIP-173's own vectors rather than
against this project's encoder.

## Why there is no export

Import and export are not symmetric obligations. "The private key never leaves
the node" is not violated by bringing one in; it is violated by definition by an
exporting command.

The one sanctioned way key material leaves its type is `HexForKeystore`, and an
architecture test allowlists exactly one caller for it. An export command would
need a second entry — which is precisely the review prompt that test exists to
raise, and the answer to it is no.

There is also no need it uniquely serves. The development keystore is a JSON file
at a known path; an operator who genuinely needs the key can read it, and doing
so is visibly reaching into a development backend rather than using a supported
feature. Blessing it as a command would also be a promise the architecture
intends to break: the production backend is an external signer that structurally
cannot produce the key.

## Why importing cannot overwrite

Replacing an identity revokes every authorization a peer has granted this node,
and the peers hold the old public key in their own configuration. From this side
it looks like success; from theirs the node simply stops being recognised, with
nothing to indicate why.

A `--force` flag would make that a one-token decision. Requiring the operator to
move the file aside is not friction for its own sake: it makes them produce the
backup as a side effect of the act, which is the thing `--force` would skip.

## Consequences

**A 32-byte number is not automatically a private key, and this had to be
enforced here.** A key must be below the secp256k1 group order. The signing
library reduces anything larger instead of rejecting it, so an out-of-range value
silently becomes a *different*, valid key — the node would work, under an
identity nobody chose, discovered only when peers failed to recognise it. The
group order itself reduces to zero and yields an all-zero public key. Import
checks the range explicitly; the domain type's length and non-zero checks do not
cover this, and neither does derivation.

**An imported key's provenance cannot be verified.** Nothing proves the person
importing it is the person it belongs to, and nothing detects that it is already
in use. Detection would mean asking relays about the key, which leaks it to them
before the operator has decided anything. The mitigation is what the command
prints: reusing a personal identity links the node's signalling to that identity
permanently on any relay that keeps it.

**Two guards constrain how this could be written.** An architecture test refuses
the four-letter private-key prefix in quotes outside the keystore, because a
struct tag naming a private key is how a secret reaches an event or a log. The
guard cannot tell a field name from a protocol constant, so the constant is
assembled rather than written out; carving an exception into the guard would cost
more than working with it.

**The secret scanner had a gap this delivery found and closed.** Its rule matched
a private key named as a field followed by a separator, which never fires on a
key in the exported form: that is one unbroken string with no separator between
prefix and payload. A rule for that form was added and confirmed by planting a
key-shaped string and observing the scan fail.

**`created_at` means two things.** Generation time for a generated identity,
import time for an imported one — the original date is not something a key
carries. Nothing depends on the field today; it is documented so nobody reads it
as key age.

**Importing a long-lived personal key widens the blast radius of a compromise.**
NM-10 records that the signalling encryption has no forward secrecy, so a future
compromise of the Nostr key decrypts retained signalling. A key that has been on
a phone for years, pasted into several applications, has a wider exposure than
one generated on a server for this purpose.

## Alternatives rejected

**Accepting the key as a flag value**, with a warning that it is now in shell
history. Rejected: a warning after the fact does not un-write the history entry,
and offering the leaking path as a legitimate option is not made safe by
describing it.

**Supporting encrypted keys (NIP-49).** Rejected for now, and named rather than
dismissed as malformed when one is supplied. It needs a passphrase prompt, which
means terminal handling and a new dependency, and it protects the key only on the
way in — the development keystore then writes it unencrypted regardless, so the
gain is nil while the surface is large.

**An environment variable.** Worse than stdin: inherited by every child process,
visible in `/proc`, and it leaks into container inspection and CI logs.

**Hex only, no bech32.** Zero code and zero dependency, but somebody whose client
shows them a prefixed key would have to convert it elsewhere — which in practice
means pasting a private key into a website. Removing that step is a security
improvement, not a convenience.

## Validation

Bech32 is tested against BIP-173's own valid and invalid vectors, including the
prefix being covered by the checksum and every single-character alteration being
caught. The `npub` this produces was compared against an independent
implementation of the specification and matched exactly — agreement with other
implementations is the property that matters, and testing an encoder against its
own decoder does not establish it.

Every guard was validated by planting the violation and observing it fail:
removing the range check accepted a number outside the group order at both the
decoding and the command level; printing the imported key was caught in all five
encodings the hygiene test checks; removing the keystore's refusal replaced an
existing identity; and restoring the scanner's old rule let a key-shaped string
through.
