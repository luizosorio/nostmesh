# NM-02 — Repository layout

**Status:** Accepted
**Date:** 2026-08-30
**Milestone:** M0.1

## Context

The project spans a control plane, a data plane, several auxiliary service roles
and multiple platforms. Without a layout that makes dependency direction
explicit, the code degrades into mutual imports where a platform detail can
dictate domain behavior.

## Decision

Adopt the structure defined in the project's technical architecture:

```text
cmd/nostmesh/             CLI and daemon entrypoint
internal/domain/          pure types and state machines
internal/protocol/        envelopes, codec, validation
internal/identity/        signer and keystore
internal/nostr/           relays, inbox, outbox
internal/connectivity/    candidates and checks
internal/wireguard/       port plus platform adapters
internal/netstate/        routes, firewall, DNS, journal
internal/policy/          local evaluation
internal/relay/           data relay client and server
internal/transit/         offers, sessions, QoS, accounting
internal/payment/         Lightning interface
internal/store/           SQLite and migrations
internal/observability/   logs, metrics, tracing
internal/config/          declarative configuration
internal/version/         build metadata
test/architecture/        dependency-rule enforcement
test/integration/         namespaces and simulated relays
docs/adr/                 architecture decision records
```

Dependencies point inward. `internal/domain`, `internal/protocol`,
`internal/policy` and `internal/config` form the core and must not import an
operating system package, `syscall`, or any adapter.

Platform code lives behind build tags in adapter files
(`adapter_linux.go`, `adapter_windows.go`) implementing a port declared in
`port.go`.

## Alternatives considered

**Flat packages under a single namespace** — fewer directories. Rejected because
it offers no structural place to enforce the boundary, leaving it to convention.

**Separate Go modules per layer** — enforces boundaries at the module level.
Rejected as disproportionate: it complicates the build and versioning for a
single binary, and the boundary can be enforced by test instead.

## Consequences

- The boundary is verified by `test/architecture`, which fails the build on
  violation rather than relying on review.
- Directories exist before their packages are implemented, marking where later
  milestones land and keeping the layout stable.
- Adding a platform means adding adapters, not restructuring the core.
