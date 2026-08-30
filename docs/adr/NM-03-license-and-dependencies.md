# NM-03 — License and dependency policy

**Status:** Accepted
**Date:** 2026-08-30
**Milestone:** M0.1
**Resolves:** Q-12 (license portion)

## Context

The project is open and intended to allow anyone to contribute, commercialize,
or otherwise build on the code without restriction. That intent constrains not
only the project's own license but every dependency it takes on, because a
copyleft dependency propagates its terms to the combined work.

The project also implements network protocols, NAT traversal and ICE-like path
selection — areas with a long history of patent claims.

## Decision

The project is licensed under **Apache-2.0**.

Dependencies are restricted to permissive licenses: Apache-2.0, MIT, BSD-2 and
BSD-3-Clause, ISC, and MPL-2.0.

Strong copyleft (GPL, AGPL, LGPL) is **rejected by default**. Introducing such a
dependency requires explicit maintainer approval and a superseding ADR.

Every dependency's license is documented in `THIRD-PARTY.md`, generated
automatically, and verified in CI. The build fails when a dependency falls
outside this policy.

## Alternatives considered

**MIT** — shorter, widely understood, and satisfies the same freedom to
commercialize. Rejected in favor of Apache-2.0 because it carries no express
patent grant. For a networking protocol implementation, that grant protects both
the project and anyone building on it; this is why Go, Kubernetes and most
modern network infrastructure use Apache-2.0.

**Permitting LGPL with dynamic linking** — would widen the dependency pool.
Rejected because the project ships a statically linked single binary (NM-05),
where the LGPL's relinking provision is impractical.

## Consequences

- Contributors grant a patent license along with their contribution.
- `NOTICE` must be preserved in redistributions, per Apache-2.0 section 4.
- A useful library under GPL/AGPL cannot be adopted without a recorded decision
  to change this policy.
- License scanning is part of CI, and SBOM generation becomes a release
  requirement rather than an afterthought.
