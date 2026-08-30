# NM-13 — Connectivity discovery and STUN

**Status:** Accepted
**Date:** 2026-08-30
**Milestone:** M1.4

## Context

Two nodes behind NAT need to find a UDP path to each other. The established
approach is ICE: gather candidate addresses, exchange them over a signalling
channel, then probe pairs until one works.

NostMesh needs a subset. It does not need media, DTLS, SCTP or data channels —
ADR-004 already settled that. What it needs is candidate gathering, an
authenticated probe, and a way to pick a winner.

The security requirement is sharper than in typical ICE deployments. A STUN
server is a third party that reports an address, and the project treats such
parties as untrusted: an observer that lies must not be able to make this node
send traffic to an address of the observer's choosing.

## Decision

**STUN uses `github.com/pion/stun/v3`** for the wire format: encoding a Binding
Request, decoding `XOR-MAPPED-ADDRESS`, and the transaction ID handling that
makes a response attributable to a request.

**Connectivity checks are ours.** The probe that promotes a candidate from
`UNVERIFIED` to `VALID` is a NostMesh challenge/response, authenticated with the
session's own key material. It is not STUN, and it is not ICE's connectivity
check: those authenticate with credentials exchanged in the signalling channel,
and this project already has a stronger binding available in the session.

**A candidate from any third party starts `UNVERIFIED`** and produces no effect
until a challenge/response completes over the exact address and port. That
includes candidates a peer sends, since a peer is also a party this node does
not control.

**Agreement between observers is not evidence.** A symmetric NAT produces a
different mapping per destination, so two observers reporting the same address
means they were reached the same way, not that the address is usable. Treating
agreement as a quorum would be reading a coincidence as proof.

## Alternatives considered

**A full ICE library (`pion/ice`)** — would provide gathering, pairing,
nomination and connectivity checks. Rejected because its connectivity check
authenticates with ICE credentials from the signalling channel, and NostMesh
would have to either adopt that weaker binding or bypass the library's core
loop. It also brings a large dependency surface for a state machine this project
needs to control directly: the ordering of attempts is policy, and policy is
what MVP 1 is about.

**Implementing STUN from the RFC** — the subset needed is roughly 150 lines:
a 20-byte header, a transaction ID, and `XOR-MAPPED-ADDRESS` decoding. Rejected
because the XOR encoding and the IPv6 handling have details that are easy to get
subtly wrong, the format is a wire protocol where a mistake means silent
incompatibility with every deployed server, and `pion/stun` is small, cgo-free
and maintained by the project that also maintains the reference Go ICE
implementation.

**No STUN at all** — rely on manual endpoints and IPv6. Rejected: it would make
MVP 1 unable to meet its own acceptance criteria, which name NAT traversal
explicitly.

## Consequences

- `pion/stun` and its dependencies (`pion/logging`, `pion/transport`,
  `wlynxg/anet`) enter the module graph. All permissive, all cgo-free, and the
  build still cross-compiles for Windows and macOS. `pion/dtls` also appears in
  the graph as a test dependency of `pion/stun`; it is not imported and does not
  reach the binary.
- The probe being ours means it can bind to the session: a challenge carries
  material only the two session participants have, so an observer that lies
  about an address cannot produce a valid response from it.
- **Attempt limits are mandatory, not optional.** An observer that reports a
  victim's address turns this node into a source of unsolicited traffic toward
  that victim. Bounding attempts per candidate, and total candidates per
  session, is what keeps a lie cheap for the victim rather than amplified.
- Ordering — IPv6, same LAN, static endpoint, PCP, recent endpoint, then a
  discovered observer — is policy, expressed in configuration rather than
  hard-coded. A deployment that does not want to contact a third-party observer
  at all can express that.
- Claims and measurements stay separate in the data model. An observer says
  what it saw; the local probe says what works. Only the second decides.
