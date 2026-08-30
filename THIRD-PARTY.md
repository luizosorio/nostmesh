# Third-party licenses

This project currently has no third-party dependencies.

When dependencies are added, this file is regenerated automatically by CI and
must list every module, its version, and its license.

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
