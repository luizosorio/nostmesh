# NM-08 — Transactional network changes

**Status:** Accepted
**Date:** 2026-08-30
**Milestone:** M0.3

## Context

NostMesh changes the host's network: it creates interfaces, assigns addresses,
configures peers. Later milestones add routes, firewall rules and NAT.

Two failure modes make this dangerous. A process that dies halfway through
leaves the host in a state nothing is tracking — the operator has an interface
and a rule with no idea what created them. And a tool that cleans up too
enthusiastically removes something it did not create, breaking networking it was
never asked to touch.

Neither is hypothetical. Both are the ordinary behaviour of a program that
applies changes as it goes and cleans up by pattern-matching.

## Decision

**Every change is planned before it is applied.** The plan is a value: it can be
described (`--dry-run`) or executed, and the description is generated from the
same structure that would be executed rather than written separately.

**Every step is journaled before and after it runs.** The journal is persistent
and written atomically. An operation recorded as `applied` definitely reached
the kernel; one left at `applying` means the process died mid-flight and the
real state must be observed rather than assumed.

**Failure compensates in reverse.** Undoing in reverse order is not stylistic:
an address must come off before the interface carrying it, and a peer before the
interface it belongs to.

**Ownership is verified before every destructive operation.** NostMesh
interfaces carry the `nm` prefix, and the adapter refuses to configure or remove
anything else. Operations record whether the resource already existed;
compensation reverts what NostMesh introduced and leaves what it found.

**Every operation is idempotent.** Applying the same plan twice converges rather
than failing or duplicating, which is what makes retrying after an interrupted
run safe.

**Fault injection is a feature, not a test hook.** `InjectFailureAfter` fails
the apply after a named operation, so rollback can be exercised at each step in
turn.

## Alternatives considered

**Apply as you go, clean up on error** — the obvious approach. Rejected because
it has no answer for a process that dies: nothing records what was applied, so
recovery is guesswork over the host's current state.

**Tag resources with a marker and clean up by pattern** — simpler than a
journal. Rejected because netlink offers no general place to attach metadata to
a link, and pattern-matching interface names is exactly how a tool ends up
deleting something a user created that happened to match.

**Rely on the kernel's own atomicity** — netlink operations are individually
atomic. Rejected because the unit that matters is the whole plan: an interface
created but never configured is not a state the system should leave behind, even
though each step succeeded on its own.

**Roll forward instead of back** — retry the failed step. Rejected for MVP 0
because it needs a notion of which failures are transient, which the adapter
does not yet have. Compensation is the conservative default; roll-forward can be
added per operation later.

## Consequences

- A failed apply leaves the host as it was found. Tests verify this by injecting
  a failure at each of the five operations in turn and asserting nothing
  survives.
- The journal is a persistent record of what NostMesh did to the host, which is
  also what `status` reads to surface an interrupted transaction.
- The `nm` prefix becomes load-bearing: it is how ownership is decided when the
  journal is incomplete. Renaming an interface out of that prefix makes NostMesh
  disown it, which is intentional but must be documented for operators.
- Reconciliation — acting on a pending journal entry at startup — is specified
  here but implemented in M0.4, where the orchestrator exists to drive it.
- Compensation itself can fail. The error is joined to the original failure
  rather than replacing it, so the operator sees both what went wrong and what
  could not be undone.
