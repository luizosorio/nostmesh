# Architecture Decision Records

Each ADR records one decision: its context, the alternatives considered, the
decision itself, and the consequences that follow from it.

## Naming

ADRs use the `NM` prefix and sequential numbering: `NM-01`, `NM-02`, and so on.
The number is assigned when the ADR is written and never reused.

## Status

- **Accepted** — in force.
- **Superseded by NM-NN** — replaced; kept for the historical record.
- **Proposed** — under discussion, not yet in force.

An ADR is never deleted or rewritten in place. Changing a decision means writing
a new ADR that supersedes the old one.

## Changing a decision

Per the project documentation, superseding an ADR requires recording: context,
alternatives, evidence, protocol consequences, migration path, security impact,
and which milestones are affected. Compatibility is never broken silently.

## Index

| ADR | Title | Status |
|---|---|---|
| [NM-01](NM-01-language-and-stack.md) | Language and core stack | Accepted |
| [NM-02](NM-02-repository-layout.md) | Repository layout | Accepted |
| [NM-03](NM-03-license-and-dependencies.md) | License and dependency policy | Accepted |
| [NM-04](NM-04-control-data-plane-separation.md) | Control and data plane separation | Accepted |
| [NM-05](NM-05-single-binary-and-netlink.md) | Single binary and direct kernel interface | Accepted |
