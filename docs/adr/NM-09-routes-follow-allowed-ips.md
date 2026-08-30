# NM-09 — Routes follow AllowedIPs

**Status:** Accepted
**Date:** 2026-08-30
**Milestone:** M0.4

## Context

`AllowedIPs` and routes solve different problems, and conflating them produces a
tunnel that looks correct and carries nothing.

`AllowedIPs` is a WireGuard concept: it says which peer is permitted to send
traffic for a prefix, and which peer to encrypt for when sending. It is a
cryptographic authorization check inside the tunnel.

A route is a kernel concept: it says which interface a packet leaves by. Without
one, the kernel has no reason to hand a packet to the tunnel at all.

This was found the way it usually is: the M0.3 tests all passed — interface
created, peer applied, handshake completing, counters readable — and the first
test that sent real traffic through the tunnel failed with `network is
unreachable`. Configuration tests cannot distinguish "configured" from
"working".

## Decision

**Applying a peer installs a route for each of its allowed prefixes**, scoped to
the tunnel interface. Route installation is part of `ApplyPeer` rather than a
separate step, because a peer without routes is not a usable peer.

**Removing a peer removes its routes.** The routes are read from the device
before the peer is removed, since afterwards the prefixes that identify them are
gone. A route pointing at a peer that no longer exists is precisely the orphaned
state the journal exists to prevent.

**A default route is refused.** `0.0.0.0/0` or `::/0` would capture all traffic
including the tunnel's own transport endpoint, creating a loop. Transit is a
negotiated service with explicit consent and loop protection, introduced in
MVP 4.

**Route operations are idempotent.** An identical route already present is not
an error, and removing an absent route succeeds — so compensation can run
without checking first.

## Alternatives considered

**Leave routing to the operator** — as `wg` does, deferring to `wg-quick` or
manual `ip route` commands. Rejected because NostMesh is a single self-contained
binary (NM-05): telling an operator the tunnel is up while requiring a separate
tool to make it carry traffic breaks that contract.

**Install routes as a separate journaled operation** — arguably cleaner for the
transaction log. Rejected because it admits a state where a peer exists without
its routes, which is never desirable; coupling them means the two cannot drift.

**Use `SCOPE_UNIVERSE` with a gateway** — the conventional form for a routed
next hop. Rejected because a WireGuard interface is point-to-multipoint with no
link-layer gateway; `SCOPE_LINK` on the interface is the correct expression.

## Consequences

- A tunnel that comes up carries traffic, which the two-namespace lab now proves
  with ICMP and TCP in both directions rather than assuming.
- Route ownership follows interface ownership: routes are attached to an `nm`
  interface, so removing the interface takes them with it, and the adapter never
  touches a route on an interface it does not own.
- Refusing a default route here means a future transit implementation must
  install one through an explicit, separate path with its own consent and
  loop-protection logic. That is intended: it should not be reachable by
  configuring a peer.
- The lesson generalizes beyond routing: an integration test that exercises the
  real data path finds a class of bug that configuration tests structurally
  cannot. Later milestones that add firewall rules, DNS or NAT need the same
  treatment.
