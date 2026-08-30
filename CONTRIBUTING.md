# Contributing to NostMesh

Thanks for your interest. This document covers how to set up a development
environment, how work is organized, and what a change is expected to look like
before it can be merged.

## Ground rules

**Everything is in English.** Code, identifiers, comments, documentation, commit
messages, branch names and pull requests. Discussion in issues can happen in any
language, but what lands in the repository is English.

**Every stage is a branch and a pull request.** No commits go directly to
`master`. A pull request needs maintainer approval before it merges.

**A stage begins only after the previous one is complete.** Complete means:
green tests, passing lint, documented limitations, and an approved PR. Parallel
work is fine — each line of work gets its own branch and its own PR — but new
work is never stacked on an unapproved base.

## Development environment

Build and test run **in containers**, so contributing requires no local Go
toolchain. This is how the project is developed, not how it ships: NostMesh is
distributed as a single static binary that users install directly.

```bash
make docker-check     # format, vet, tests, portability guard
make docker-build     # produces bin/nostmesh
make docker-test      # tests only
```

Every `make` target is available with a `docker-` prefix. Without the prefix,
targets run against a local Go 1.25 toolchain if you prefer that.

### Privileged tests

Tests that touch WireGuard, nftables and network namespaces need `NET_ADMIN` and
a host kernel carrying the `wireguard` module. Containers share the host kernel,
so the module must be loaded **on the host**:

```bash
sudo modprobe wireguard
```

Domain, protocol and policy tests never require root. If a test in those
packages needs privileges, something has crossed a boundary it should not have.

## Architecture constraints

Two rules are enforced by CI rather than by review, because they are easy to
break by accident and expensive to repair later.

**The core stays free of the operating system.** `internal/domain`,
`internal/protocol`, `internal/policy` and `internal/config` must not import an
OS package, `syscall`, or any adapter. Platform code lives behind a port, in
`adapter_linux.go` and friends. `test/architecture` fails the build on
violation, and CI cross-compiles for Windows and macOS to keep the boundary
honest before adapters for those platforms exist.

**No shelling out for network effects.** State reaches the kernel through
netlink, never by running `wg`, `nft` or `ip` and parsing their output. `exec`
is acceptable only in optional, degradable diagnostics — never to produce an
effect, never as a source of truth.

The reasoning for both is in [NM-05](docs/adr/NM-05-single-binary-and-netlink.md).

## Security invariants

Some things are never traded for convenience, and a PR that weakens one will be
rejected regardless of what else it does well:

- The WireGuard private key never leaves the node that generated it — not in
  events, logs, the network journal, or diagnostic bundles.
- Nostr and WireGuard keys never share secret material.
- Nothing from a peer configures the kernel directly. `AllowedIPs`, routes, DNS
  and firewall rules come from local policy.
- Policy decisions are deny-by-default.
- Network changes are transactional, idempotent, and never remove a rule
  NostMesh does not own.
- No secrets, keys or mandatory endpoints are hardcoded. No keys are committed.

If you believe an invariant is wrong, argue for it in an issue and propose an
ADR. Do not work around it in code.

## Commits

**Keep commit messages short.** One line describing the change. Save the detail
for the pull request description, where it can be read in context alongside the
diff.

```
feat: add transactional wireguard adapter
fix: reject default route in static peer configuration
docs: record NM-06 addressing decision
```

Prefixes follow [Conventional Commits](https://www.conventionalcommits.org/):
`feat`, `fix`, `docs`, `test`, `refactor`, `chore`, `perf`.

### No tooling attribution

Commits, code comments, branch names, pull requests and documentation do not
mention AI assistants, models or tools. No `Co-Authored-By` trailers for them,
no "generated with" footers, no comments noting that a section was
machine-written.

This is not a restriction on how you work — see [AI tools](#ai-tools) below. It
is about what the repository records. Commit history exists to explain what
changed and why, to someone debugging it years from now. What editor, plugin or
model was open at the time is not part of that story, and attribution lines make
the history harder to read while telling the reader nothing actionable.

## AI tools

**Use them if they help.** There is no restriction, no disclosure requirement,
and no separate review track for AI-assisted contributions. They are judged
exactly like any other change.

What is required is the same thing required of any contributor:

- **You understand the code you are submitting.** Every line, including the
  parts you did not type.
- **You can defend the decisions in it** — why this approach, why this
  boundary, why this trade-off — in review.
- **You are responsible for it.** Correctness, security and fit with the
  project's invariants are yours, not your tooling's.

A pull request that cannot survive questions about its own design will not merge
regardless of how it was produced. In practice this project's architecture is
demanding — transactional network state, deny-by-default policy, strict plane
separation — and code generated without that context tends to violate an
invariant in ways that pass tests. Read the ADRs first.

## Pull requests

The PR description is where detail belongs. Include:

- **What changed and why.** The reasoning, not a restatement of the diff.
- **Which acceptance criteria are met**, one by one, if the change implements a
  roadmap delivery.
- **How it was validated.** Commands run and their results.
- **Decisions and risks**, including anything you were unsure about.
- **Known limitations** and what is explicitly left out.

### Definition of Done

A PR is not ready to merge until:

- automatable acceptance criteria have tests;
- documentation and examples reflect actual behavior;
- failures leave the host in a safe, predictable state;
- logs contain no keys, encrypted payloads, complete invoices or tokens;
- lint, unit tests and relevant integration tests pass;
- known limitations and new decisions are recorded.

## Architecture decisions

Significant decisions are recorded as ADRs in [`docs/adr/`](docs/adr/), prefixed
`NM` and numbered sequentially. Write one when you make a choice that constrains
future work, resolves an open question, or that a future contributor would
otherwise have to reverse-engineer from the code.

An ADR is never edited in place or deleted. Changing a decision means writing a
new one that supersedes it, recording context, alternatives, evidence, protocol
consequences, migration path, security impact, and affected milestones.

## Dependencies

Only permissive licenses: Apache-2.0, MIT, BSD-2/3-Clause, ISC, MPL-2.0. Strong
copyleft (GPL, AGPL, LGPL) is rejected by default — it conflicts with the goal
of allowing unrestricted commercial use, and CI enforces this.

The build is CGO-free, so a dependency requiring cgo needs a pure-Go
alternative or an ADR explaining why the constraint should change.

Prefer the standard library. Every dependency is a supply-chain liability and a
license obligation; the bar for adding one is real.

## Reporting security issues

Do not open a public issue. See [SECURITY.md](SECURITY.md).
