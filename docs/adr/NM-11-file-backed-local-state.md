# NM-11 — File-backed local state

**Status:** Accepted
**Date:** 2026-08-30
**Milestone:** M1.2

## Context

The project documentation lists SQLite as the local store, and the architecture
sketches tables for identities, sessions, messages, candidates, routes,
services, credits and the network journal.

Three deliveries have shipped without it. The keystore writes a JSON file, and
the network journal writes one file per transaction. Both use the same
discipline — write to a temporary file, fsync, rename, fsync the directory — and
both have been exercised: the journal survived a hundred interrupted apply
cycles with no corruption and no orphaned state.

M1.2 introduces a persistent outbox, which is the first store that must survive
a restart with pending work in it. That makes this the moment to either adopt
SQLite or record why not.

## Decision

**Local state stays in files** for MVP 0 and MVP 1.

Each store owns its own directory, writes atomically, and is read back with
strict validation. The outbox follows the journal's pattern: one file per
entry, so a partially written entry cannot corrupt the others.

SQLite is not adopted now. It is not rejected forever: the milestones that
introduce multi-peer state, route tables and payment credits (MVP 2 onward) have
relational shapes and cross-table invariants that files handle poorly, and this
decision should be revisited there.

## Alternatives considered

**Adopt SQLite now** — matches the documented architecture and would not need
revisiting. Rejected for MVP 1 because it adds a dependency and a schema
migration path to solve a problem the current stores do not have. Every store so
far is a flat collection of independent records; none needs a join, a
transaction spanning tables, or a query. Introducing a database to hold what is
effectively a directory of files is cost without benefit, and the CGO-free
constraint (NM-05) further narrows the driver choice.

**Adopt SQLite only for the outbox** — would leave two storage mechanisms with
different failure modes and two things to reason about during recovery.
Rejected: consistency of approach matters more than optimality of each piece
while the shapes are this simple.

**An embedded key-value store** — lighter than SQLite. Rejected for the same
reason as SQLite, with the added drawback that its files are not inspectable
during incident response, which the current JSON files are.

## Consequences

- Recovery stays inspectable: an operator debugging a stuck outbox can read the
  files. This has real value while the protocol is experimental.
- Every store must implement its own atomic write and validation. The pattern is
  established and shared in practice, but it is duplicated rather than provided
  by a database.
- There is no cross-store transaction. Nothing needs one today; a milestone that
  does is the milestone that should revisit this.
- Directory listing cost grows with entry count. The outbox is bounded by a
  configured limit, so this is contained, but an unbounded store would not be.
- **This ADR supersedes the SQLite choice in NM-01 for MVP 0 and MVP 1.** The
  documented architecture still names SQLite; that remains the expected
  direction for the milestones with relational state, and diverging from it here
  is a scope decision rather than a disagreement.
