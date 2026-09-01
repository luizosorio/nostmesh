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
| [NM-06](NM-06-key-separation-and-secret-handling.md) | Key separation and secret handling | Accepted |
| [NM-07](NM-07-deferred-nostr-key-derivation.md) | Deferred Nostr key derivation | Superseded by NM-12 |
| [NM-08](NM-08-transactional-network-changes.md) | Transactional network changes | Accepted |
| [NM-09](NM-09-routes-follow-allowed-ips.md) | Routes follow AllowedIPs | Accepted |
| [NM-10](NM-10-nostr-cryptography.md) | Nostr cryptography and library scope | Accepted |
| [NM-11](NM-11-file-backed-local-state.md) | File-backed local state | Accepted |
| [NM-12](NM-12-real-key-derivation.md) | Real key derivation replaces the placeholder | Accepted |
| [NM-13](NM-13-connectivity-and-stun.md) | Connectivity discovery and STUN | Accepted |
| [NM-14](NM-14-relay-websocket-client.md) | Relay WebSocket client | Accepted |
| [NM-15](NM-15-udp-port-lifecycle.md) | UDP port lifecycle and handover to WireGuard | Accepted |
| [NM-16](NM-16-session-process-model.md) | Session process model | Superseded by NM-18 |
| [NM-17](NM-17-probe-binding-and-peer-reflexive.md) | Probe binding and peer-reflexive candidates | Accepted |
| [NM-18](NM-18-service-process-model.md) | Service process model | Accepted |
| [NM-19](NM-19-identity-import.md) | Adopting an existing Nostr identity | Accepted |
| [NM-20](NM-20-kernel-observed-roaming.md) | Following a roamed endpoint | Accepted |
