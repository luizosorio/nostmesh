# Third-party licenses

| Module | Version | License |
|---|---|---|
| `golang.org/x/crypto` | v0.55.0 | BSD-3-Clause |

`golang.org/x/crypto` supplies the Curve25519 implementation used to derive
WireGuard public keys. It is maintained by the Go team, carries the same
permissive terms as the standard library, and requires no cgo.

## Policy

Only permissive licenses are accepted by default:

- Apache-2.0
- MIT
- BSD-2-Clause, BSD-3-Clause
- ISC
- MPL-2.0 (file-level copyleft, acceptable)

Strong copyleft licenses (GPL, AGPL, LGPL) are rejected by default. They
conflict with the project's goal of allowing unrestricted commercial use.
Introducing such a dependency requires explicit maintainer approval and a
recorded ADR.

CI fails the build when a dependency carries a license outside this policy.
