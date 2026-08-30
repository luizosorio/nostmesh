# NM-05 — Single binary and direct kernel interface

**Status:** Accepted
**Date:** 2026-08-30
**Milestone:** M0.1

## Context

The project should ship as one coherent program rather than an assembly of parts
that happen to be installed together. There are two distinct ways a project like
this fragments, and only one of them is about the number of executables.

The subtler one is runtime dependency. A binary that drives `wg`, `nft` and `ip`
through `exec` is not self-contained: it depends on those tools being installed,
on their versions being compatible, and on their human-readable output remaining
stable enough to parse.

## Decision

`nostmesh` is a **single, self-contained binary**. The CLI, the daemon and the
auxiliary service roles are subcommands of the same executable.

**Network effects go directly to the kernel over netlink** — `wgctrl-go`,
`netlink`, `nftables`. No `exec` of an external tool in the critical path.

`exec` is permitted only in optional, degradable diagnostics, never to produce a
network effect and never as a source of truth about state.

The build is **static and CGO-free**, cross-compilable, with reproducible
checksums.

The MVP 3 data relay is a subcommand (`nostmesh relay serve`) but shares no
state or privilege with the node: it runs isolated, unprivileged, with egress
filtering and quotas.

## Alternatives considered

**Shelling out to `wg` and `nft`** — much faster to write, and the tools are
well understood. Rejected because it makes the binary dependent on host tooling,
turns errors into parsed text rather than typed values, and would make the
transactional journal unreliable: distinguishing "the rule was not applied" from
"the tool printed something unexpected" is not dependable.

**Separate `nostmesh` and `nostmeshd` binaries** — a conventional split. Not
adopted for now; the internal boundaries already permit separation, and a single
binary simplifies distribution. This can be revisited without protocol impact.

**Generating nftables rules as text and loading them** — a middle ground.
Rejected for the same reason as shelling out: rule ownership and rollback need
structured identification, which text generation does not provide.

## Consequences

- Pure netlink for nftables is meaningfully more work than emitting text,
  particularly in M0.3 and MVP 4. This cost is accepted deliberately.
- The binary carries no runtime dependency beyond the kernel itself; `wg` and
  `nft` need not be installed on the host.
- CGO-free constrains library choice, notably requiring a pure-Go SQLite driver.
- Rule and route ownership must be identifiable structurally, so the adapter can
  guarantee it never removes state that does not belong to NostMesh.
