# NM-04 — Control and data plane separation

**Status:** Accepted
**Date:** 2026-08-30
**Milestone:** M0.1

## Context

NostMesh coordinates over Nostr and carries traffic over WireGuard. Conflating
the two would be tempting in places: a signed event could carry configuration
directly, and a relay could be treated as authoritative about reachability.

Both shortcuts are unsafe. A valid signature proves control of a key — not
honesty, not authority over the receiving host.

## Decision

The control plane and the data plane are strictly separated.

**Nostr carries only control:** identity, discovery, announcements and
signaling. User IP packets never traverse Nostr relays.

**Received messages are proposals, never commands.** `AllowedIPs`, overlay
addresses, routes, DNS, forwarding, NAT and firewall rules are derived from
local policy and local state. No remote field configures the kernel directly.

**The orchestrator never touches the kernel.** It emits validated plans; a
transactional adapter applies them, verifies the result, and can compensate in
reverse order.

**Auxiliary roles are independent capabilities.** Nostr relay, STUN observer,
data relay and exit provider each carry their own authorization, isolation and
consent. Enabling one never grants another.

## Alternatives considered

**Letting a signed event configure the peer directly** — far less code, and the
signature does authenticate the sender. Rejected because authentication is not
authorization: it would let any authorized peer install arbitrary routes,
including one covering the tunnel's own transport endpoint.

**Treating relay agreement as truth** — using multiple relays as a quorum.
Rejected because relays are untrusted for availability and ordering, and because
NAT mappings can legitimately differ per destination, so agreement proves
nothing.

## Consequences

- Every network effect passes through policy evaluation, adding a step that
  cannot be bypassed for convenience.
- The state machine must distinguish "peer says the tunnel is ready" from "this
  node confirmed the tunnel locally". Only the latter establishes a session.
- Third-party candidates stay `UNVERIFIED` until an authenticated connectivity
  check on the exact address and port validates them.
- This separation is enforced structurally by the core's freedom from OS
  imports (NM-02), so domain code has no means to apply an effect.
