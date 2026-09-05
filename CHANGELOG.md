# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.3] — 2026-09-05

**A peer that changes address keeps its session.**

Note that unlike 0.2.2 this one **does change behaviour**: an endpoint that moves
is now followed instead of ending the session.

### Added

- **Roaming.** A peer whose address changes keeps the same session, the same
  tunnel keys and the same authorization. Previously the change surfaced as a
  stale handshake, the session was torn down, and the worker renegotiated from
  nothing — discarding all three to learn a route.

  This closes the M1.5 criterion *"endpoint muda e sessão se recupera"* and
  `RF-NET-03`, both of which were open.

- `nostmesh state` reports the current endpoint and how often it has moved. A
  count that keeps climbing is a path that is not settling, and an operator
  should see that while the session is still up rather than infer it afterwards
  from a session that kept dying.

### Fixed

- **The fake WireGuard controller disagreed with the kernel about keepalives.**
  It overwrote `PersistentKeepalive` unconditionally while the netlink adapter
  only sets it when non-zero. Since reapplying a peer during a roam does not
  restate the keepalive, a roam would have silently disabled it against the fake
  and not against the kernel — killing a NAT'd session minutes later, far from
  the cause. Found while building roaming; now under test.
- **A roam could have stripped what a peer is routed.** The adapter replaces a
  peer's AllowedIPs wholesale, so reapplying an empty set removes them. Guarded.
- A test fixture built an established session with no recorded endpoint, a shape
  production never produces.

### Decisions

- **NM-20** — following a roamed endpoint. Records why the kernel's own
  authentication is sufficient proof where this project's connectivity check
  cannot run: NM-15 hands the UDP port to the kernel when a session establishes,
  so after that there is no socket to probe from. WireGuard moves a peer's
  endpoint only after authenticating a packet under that session's tunnel keys,
  which is a stronger credential than the probe would check.

### Known limitations

- **If both ends move at once, neither follows.** No authenticated packet reaches
  either kernel, both sessions go stale, and the workers renegotiate. That is the
  boundary where kernel-observed roaming stops and control-plane migration would
  begin. It is not a regression — it is the previous behaviour for every move.
- **One peer per node**, unchanged. The listen port is a single node-level value
  and the interface name is fixed, so a second worker cannot bind.
- **No relay fallback**, **no forward secrecy** in the signalling, and a
  development keystore holding the private key unencrypted — all unchanged.

## [0.2.2] — 2026-09-01

**Housekeeping. No behaviour changes.**

> **Renumbered 2026-09-05.** Published as 2.0.2 and retagged to 0.2.2, together
> with its predecessor. See the note under 0.2.1.

The binary does what 0.2.1 did. This removes code that no longer had a caller and
comments that described a command which no longer exists — both of which cost a
reader time and neither of which the running program noticed.

Upgrading is optional and carries no risk; there is nothing here a 0.2.1
deployment is missing.

### Removed

Three implementations that had been superseded and left behind. Each was a second
version of something the code already did elsewhere, with no production caller —
the cost being that a reader could find the wrong one, or a future change be made
to the copy nothing runs.

- **`domain.Session` and its state machine.** The documented session state
  machine is implemented by `internal/session`, which is what runs. This left two
  exported types named `SessionState`: an unused enum and the real one.
- **`domain.TunnelKeyBinding` and `domain.PeerIdentity`.** NM-06's binding of the
  WireGuard public key to sender, recipient, session, version, expiry and
  sequence exists and is enforced as `protocol.TunnelKey`. This was a second
  implementation of the same requirement.
- **`STUNObserver`.** Replaced by `SharedObserver`, which holds the session's own
  socket rather than opening one per query — closing a window in which another
  process could take the port between observing an address and binding it. The
  superseded type also had no tests of its own.

`parseSTUNResponse` and the observer errors moved to `observer_shared.go` first:
the live path used them, so the file could not simply be deleted.

Net: 1,083 lines removed, 94 added.

### Changed

- Comments in `internal/orchestrator` and `cmd/nostmesh` now describe the service
  and its peer workers rather than `listen`, which 0.2.1 removed.
- `listenRetryInterval` and `maxListenRetryInterval` are now `retryInterval` and
  `maxRetryInterval`, moved beside their only caller. Same values, same backoff.

### Kept deliberately

Static analysis reports these as unreachable and they are correct as they are:
the redaction methods on `SessionKey` (a guard is unreachable precisely when it
is working), the NIP-19 and derivation functions reached through injected
function variables that analysis cannot follow, and `SessionManager.Roam` —
implemented and tested, with no caller yet. Roaming is an MVP 1 acceptance
criterion, so removing a tested implementation of it would be the wrong kind of
tidiness; wiring it into the service is a change with its own ADR.

## [0.2.1] — 2026-09-01

**Two hosts, one behind NAT, hold a tunnel.**

> **Renumbered 2026-09-05.** This was published as 2.0.1 and retagged to 0.2.1.
> The original number jumped the project from 0.x to a stable major it had not
> reached, contradicting the Semantic Versioning note above. The tag and release
> were recreated on the same commit; the old ones no longer resolve.

### Added

- `nostmesh serve` — a long-running service holding one session per authorized
  peer. Either end may open a session and both are always ready to answer;
  which one opens is settled from the two Nostr keys, so both reach the same
  answer without exchanging a message. An established session is held and
  reconnected when it drops, rather than treated as finished work.
- `nostmesh state` — what a running service is doing, per peer: phase, attempts,
  how long, the last failure, and the age of the data-plane handshake. Read
  through a read-only Unix socket at mode 0600.
- `nostmesh identity import` — adopt a Nostr identity you already have. The key
  is read from standard input, never from a command-line argument.
- `nostmesh identity show --format npub` — the public key as other Nostr
  applications display it, so an imported identity can be checked against the
  application it came from.
- `examples/nostmesh.service` — a systemd unit running the service as its own
  user with `CAP_NET_ADMIN` and nothing else. `systemctl reload` authorizes or
  revokes a peer without dropping tunnels that are working.
- `docs/identity.md` — what the node identity is, where it lives, and what to
  weigh before reusing a personal one.

### Fixed

- **A NAT'd path could not verify.** The probe challenge authenticated over an
  address the two ends do not share, and the address a peer's traffic actually
  arrives from was discarded rather than becoming a candidate. Both are fixed;
  a peer-reflexive candidate is now learned from an authenticated challenge and
  proved by the ordinary check.
- **A response arriving after its candidate was re-probed matched nothing.**
  Outstanding challenges were held one per candidate and overwritten each round,
  so on a fast path most replies were discarded. They are keyed by nonce now.
- **The service competed with itself.** `Connect` returning was treated as
  completed work, so the next attempt could not bind: the interface from the
  session that had just succeeded still held the listen port.
- **A mutual drop deadlocked a pair.** Both a responder waiting for a request
  and an initiator waiting for an offer waited without bound, so after both ends
  lost a session neither ever called. Both waits are bounded, and a responder
  that waited for nobody takes the initiating role next time.
- **Discarding a probe response deadlocked the receiving goroutine.** The
  counters and the session state shared one mutex, and a Go mutex is not
  reentrant.
- **Revocation notices were never sent.** The session id a close must name was
  read but never recorded, so every notice returned early.
- **A private key outside the secp256k1 group order was accepted.** The signing
  library reduces such a value rather than rejecting it, so it silently became a
  different, valid key.
- **The secret scanner could not catch a Nostr private key.** Its rule required
  a separator between the prefix and the key body; a key in the exported form
  has none.
- Stale claims in the README and the Nostr tutorial: derivation has not been a
  placeholder since 0.2.0, and the tutorial told the reader to connect from one
  side only, which never completed a session.

### Changed

- `listen` is removed. `serve` answers continuously, which is what an ephemeral
  responder for one named peer was standing in for. `connect`, `sessions` and
  `disconnect` remain as the one-shot laboratory path.

### Known limitations

- **One peer per node.** The listen port is a single node-level value and the
  interface name is fixed, so a second worker cannot bind. The service no longer
  competes with itself; it is not yet multi-peer correct.
- **No relay fallback.** A direct path that cannot be found fails clearly. The
  data relay is MVP 3.
- **No forward secrecy**, unchanged from 0.2.0. See NM-10.

### Decisions

- **NM-17** — probe binding and peer-reflexive candidates, amending NM-13.
- **NM-18** — the service process model, superseding NM-16.
- **NM-19** — adopting an existing Nostr identity.

## [0.2.0] — 2026-08-31

**MVP 1 complete.**

Two hosts that know each other's Nostr identity negotiate a session through
relays, verify a direct UDP path, and establish a WireGuard tunnel. No
coordinator, and no keys exchanged by hand.

> **Corrected 2026-09-01.** This entry claimed more than the release delivered.
> The end-to-end gate below runs against simulated relays in one process, with a
> transport that answers probes wherever they are aimed; it proves the protocol
> under adverse relay behaviour and does not prove NAT traversal. Between two
> real hosts, one behind NAT, this release established no tunnel. The relay
> measurements are unaffected — those were made against the real public relays
> named. Fixed in 0.2.1. The published release notes carry the same correction.

### Proven, not assumed

- **Public relays accept the protocol.** Verified against `nos.lol` and
  `relay.primal.net`: the experimental kind is accepted with 184–217ms
  publication latency. This is the first evidence for a hypothesis the project
  documentation had only stated.
- 100 of 100 connections succeed in the end-to-end gate **against simulated
  relays**, with one relay of three down, with a relay duplicating deliveries,
  and with a relay accepting and silently discarding.
- An address supplied by any third party produces no effect until an
  authenticated challenge/response completes over that exact address and port.
- A lying observer cannot induce bulk traffic: probes to any single address are
  bounded, and dangerous targets are refused before a candidate is recorded.
- The WireGuard private key does not reach an event, a log, the store or a
  diagnostic — checked across four encodings, a real logging handler, and every
  formatting verb.

### Known limitations

- **No forward secrecy.** A compromised Nostr private key allows decryption of
  signalling a relay retained, revealing endpoints, candidates and historical
  *public* WireGuard keys. No WireGuard private key is ever transmitted.
- **No relay fallback.** Without a direct path the connection fails; the data
  relay is MVP 3.
- **Symmetric NAT on both sides may be impassable.** The failure is clear rather
  than an endless retry.
- **No mesh, routes or transit.** MVP 2 and MVP 4.
- **PCP and NAT-PMP are not implemented**, and report that rather than silently
  contributing nothing.
- **Linux only.** The core compiles for Windows and macOS; no adapter exists.
- **Not audited.** The protocol is experimental and claims no NIP number.

### Verification still outstanding

NAT traversal between two hosts with genuinely different topologies — one with a
public address, one behind NAT — has not been exercised. The gate runs
in-process, so real traversal remains unproven.


### Added

- End-to-end testbed: two nodes, three simulated relays, exercising the real
  protocol path from handshake to verified connectivity (M1.5).
- WebSocket relay client behind the same interface the fake implements, so the
  adversarial tests written in M1.2 describe the real transport too.
- Roaming: an endpoint change updates the tunnel without changing the session
  identity, its authorization or its keys — and only after the new address is
  verified.
- `nostmesh relay-check`, a manual verification against real relays using a
  throwaway identity. Not part of the test suite.
- Relay and observer configuration, with `doctor` warning when fewer than three
  relays are configured.
- Tutorial for a tunnel negotiated over Nostr, including the limits.

### Fixed

- The relay client matched publication verdicts against the caller's identifier
  rather than the event id a relay actually answers with, so every publication
  timed out and was reported as a refusal. Found by checking against real
  relays; the fake had been echoing the caller's id, which hid it entirely. The
  fake now answers with the event id, as a real relay does.

### Added

- Connectivity discovery: candidates gathered from local interfaces, static
  configuration and STUN observers, ordered so a node that can connect directly
  never tells a stranger it exists (M1.4).
- Authenticated connectivity checks. A candidate is a claim until a
  challenge/response completes over the exact address and port, and the probe
  key derives from session material a third party does not have.
- Address filtering that refuses loopback, multicast, link-local and
  unspecified targets before a candidate is recorded, so an observer reporting
  a victim's address cannot make this node send anything there.
- Separate limits on candidates contributed by third parties, on probes per
  candidate, and on total attempt time.
- ADR NM-13 (connectivity discovery and STUN).

### Added

- Session handshake: request → offer → accept, with the ephemeral WireGuard
  public key bound to sender, recipient, session and expiry (M1.3).
- Deny-by-default allowlist. Actions are separate, so a peer trusted to open a
  session is not thereby trusted to announce routes.
- Real secp256k1 Schnorr signing and key derivation, replacing the development
  placeholder (NM-12 supersedes NM-07).
- `nostmesh connect`, `sessions` and `disconnect`.

### Changed

- **Identities created before this release are rejected on load.** The
  placeholder derived a digest rather than a curve point, so such an identity
  cannot sign. Regenerate with `nostmesh identity init`.

### Security

- A peer's `session.ready` no longer implies anything about the local tunnel:
  only local verification establishes a session.
- Tunnel key substitution, replay at a used sequence, acceptance of terms that
  were never offered, and expired keys all fail without changing state.

### Added

- Multi-relay transport: fan-out publication, per-relay acceptance reporting,
  and a persistent outbox that survives a restart with pending work (M1.2).
- Deduplication on two keys — event id for literal copies, and a logical key
  (session, type, sequence) that also detects two different events claiming the
  same position in a session.
- Exponential backoff with symmetric jitter, so nodes that lost the same relay
  do not all retry at the same instant.
- Fake relays that go down, reject, delay, duplicate, reorder and silently drop,
  making the adversarial acceptance criteria testable without public relays.
- ADR NM-11 (file-backed local state), recording why MVP 0 and MVP 1 do not use
  SQLite and when that should be revisited.

### Added

- Control protocol v1: envelope, eight message types, capability negotiation,
  and validation in documented cheapest-first order (M1.1).
- NIP-44 v2 directed encryption, verified against the official test vectors,
  with the envelope's cleartext fields bound to the encrypted payload so a
  relay cannot re-address a captured message.
- Golden vectors covering both valid envelopes and every rejection reason.
- Four fuzz targets over the parsers, with the discovered corpus committed as
  permanent regression tests.
- Architecture guards: the protocol may not import transport or cryptography,
  the `go-nostr` root package is never imported, and no serialized type may
  declare a private-key field.
- `docs/protocol/v1.md`, including an explicit statement that the scheme has no
  forward secrecy and what that would expose.
- ADR NM-10 (Nostr cryptography and library scope), resolving Q-02.

## [0.1.0] — 2026-08-30

First tagged release: **MVP 0 complete**.

Two Linux hosts can establish an authenticated WireGuard tunnel through
NostMesh, configured by hand. There is no Nostr, no NAT traversal and no
discovery — those arrive in MVP 1. What this release provides is a foundation
whose guarantees are demonstrated against a real kernel rather than asserted.

**Proven, not assumed:**

- A tunnel carries ICMP and TCP in both directions between two network
  namespaces.
- A failure at any step of an apply leaves no interface, address or route
  behind, verified by injecting one at each of five steps.
- A hundred setup and teardown cycles leave link and route counts unchanged.
- NostMesh never removes an interface it does not own, including during
  rollback.
- Private keys cannot be printed, logged or serialized; the one sanctioned
  escape is guarded by an architecture test.

**Known limitations:**

- Public keys and endpoints are exchanged by hand.
- Nostr key derivation is a development placeholder, not secp256k1 (NM-07); it
  must be replaced in M1.1, and identities created now will not carry forward.
- The file keystore stores a private key on disk unprotected. It is for
  development only.
- Benchmarks establish a baseline; they do not measure RNF-PERF, which needs two
  hosts and a real link.
- Linux only. The core compiles for Windows and macOS, but no adapter exists.

This release has not been audited. Do not rely on it to protect anything that
matters.


### Added

- Interruption tests against a real kernel: a failure at any step of an apply
  leaves no interface, address or route behind, a retry converges without
  manual cleanup, and rollback preserves interfaces NostMesh does not own.
  This completes the M0.3 gate, which previously only exercised a fake.
- `make cover-all`, measuring coverage across both suites so the netlink
  adapter is no longer reported as 0%.
- Baseline benchmarks and `docs/benchmarks.md`, with explicit limits on what
  they do and do not measure.

- Orchestrator: brings the tunnel up transactionally, tears it down, and
  reconciles the journal after an interrupted run (M0.4).
- Routes installed for each peer's allowed prefixes, and removed with the peer.
- `nostmesh peer add/list/remove`, `up`, `down`, `status` and `doctor`.
- Two-namespace lab proving ICMP and TCP flow through a real tunnel, plus a
  hundred-cycle gate confirming no interfaces or routes accumulate.
- Tutorial for establishing a manual tunnel between two hosts.
- ADR NM-09 (routes follow AllowedIPs).

### Fixed

- A tunnel came up without routes, so traffic failed with "network is
  unreachable" despite a successful handshake. Applying a peer now installs the
  routes its allowed prefixes require.

- Transactional network state: plans are built before they are applied,
  journaled at each step, and compensated in reverse on failure (M0.3).
- Linux WireGuard adapter over netlink, with no shelling out to `wg` or `ip`.
- Interface ownership enforcement: NostMesh refuses to configure or remove an
  interface it did not create.
- Fault injection, so rollback is exercised at every step of a plan.
- Privileged integration tests running in isolated network namespaces.
- `nostmesh status`, and `nostmesh up --dry-run`.
- ADR NM-08 (transactional network changes).

- Identity and session domain: node and peer identities, tunnel key bindings,
  and the session state machine (M0.2).
- Private key types that cannot be printed, logged or serialized, with a single
  sanctioned escape enforced by an architecture test.
- Development file keystore with atomic writes, owner-only permissions, and
  refusal to load a key whose permissions have been relaxed.
- `nostmesh identity init` and `nostmesh identity show`.
- ADRs NM-06 (key separation and secret handling) and NM-07 (deferred Nostr key
  derivation, to be superseded in M1.1).

- Project foundation: module layout, build tooling and CI (M0.1).
- `nostmesh version` and `nostmesh config validate` commands.
- Declarative configuration with deny-by-default policy and validation that
  reports every problem at once.
- Architecture tests enforcing that the core imports no operating system
  package, no adapter, and never shells out for network effects.
- Portability guard: CI cross-compiles for Linux, Windows and macOS.
- License policy enforcement and secret scanning in CI.
- ADRs NM-01 through NM-05 recording language and stack, repository layout,
  license policy, control/data plane separation, and the single-binary
  netlink decision.
