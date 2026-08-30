# NM-01 — Language and core stack

**Status:** Accepted
**Date:** 2026-08-30
**Milestone:** M0.1
**Resolves:** Q-01

## Context

The project documentation recommends Go for the first implementation but leaves
the decision open, along with the exact libraries. The choice constrains the
data plane's performance, the binary's portability, and how network state is
applied to the host.

A specific ambiguity had to be resolved: `wireguard-go` and `wgctrl-go` are
often conflated. They solve different problems.

- `wireguard-go` is a userspace implementation of the WireGuard protocol. The
  data plane runs inside the process.
- `wgctrl-go` is a control library. The data plane stays in the kernel; the
  library configures it over netlink.

## Decision

**Go** is the implementation language.

**`wgctrl-go`** is the default WireGuard control interface, with the data plane
in the Linux kernel.

**SQLite** is the local state store. *(Adjusted by [NM-11](NM-11-file-backed-local-state.md): MVP 0 and MVP 1 use file-backed state; SQLite remains the expected direction for the milestones with relational shapes.)*

`wireguard-go` is reserved as an alternative adapter behind the same port, for
future portability or for the MVP 3 relay, where userspace datagram handling may
be required. It is never the default.

## Alternatives considered

**Rust** — comparable performance and stronger memory-safety guarantees, with a
mature `boringtun`. Rejected because the WireGuard, netlink and ICE ecosystem
that this project depends on is more established in Go, and the upstream
WireGuard tooling for both Linux and Windows is written in Go.

**`wireguard-go` as the default** — simpler to run without kernel support and
portable by construction. Rejected because RNF-PERF targets tunnel-attributable
overhead below 10% on a 1 Gbps lab, which a userspace data plane does not meet,
and because the requirements already assume a Linux host with kernel WireGuard.

**Embedded key-value store instead of SQLite** — lighter. Rejected because the
network journal requires transactional guarantees across related records, and
because SQLite's durability and inspectability matter during incident response.

## Consequences

- The data plane runs at kernel speed, and the `wireguard` kernel module becomes
  a documented runtime prerequisite.
- `wgctrl-go` also supports Windows through WireGuardNT, so the same port is
  likely to serve both platforms when Windows enters scope.
- Choosing a kernel data plane means the lab environment needs `NET_ADMIN` and a
  host kernel carrying the WireGuard module; containers share the host kernel.
- SQLite is reached through a pure-Go driver to preserve the CGO-free build
  required by NM-05.
