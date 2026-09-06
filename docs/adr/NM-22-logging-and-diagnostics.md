# NM-22 — Logging and diagnostics

**Status:** Accepted
**Date:** 2026-09-06
**Milestone:** M2.1 (brings forward part of M2.5)

## Context

A node that cannot explain itself cannot be operated, and this one currently
cannot. There are twenty-one log events and every one of them is emitted from
`cmd/nostmesh/service.go`. The orchestrator, the Nostr client, the connectivity
engine, the WireGuard controller and the network journal emit nothing at all —
`driver.go` says so in a comment, explaining that a roam failure is invisible
because "the driver has no logger of its own".

The single tracing hook is a `trace func(string)` callback with two call sites in
`cmd/nostmesh/control.go`, both building strings with `fmt.Sprintf`. One of them
interpolates a rejection error directly into the line.

The cost is not hypothetical. Diagnosing why a held session failed to follow a
moved endpoint meant reading code and adding temporary instrumentation, because
there was no log to read. Every layer the negotiation passes through — relay
connection, envelope validation, decryption, state machine, candidate gathering,
STUN, connectivity checks, interface configuration, handshake — is silent.

`internal/observability/` exists as an empty directory. It is reserved: the
architecture assigns it "logs, métricas, tracing".

## Decision

**Everything is logged to the system log, and to a file as well when one is
configured. DEBUG is exhaustive; INFO is quiet. Address disclosure is gated
separately from verbosity.**

### The level rule

Stated once, so each event's level is derivable rather than memorised:

- **ERROR** — the node could not do its job and an operator must act.
- **WARN** — degraded but proceeding; something recovered or was refused.
- **INFO** — one line per state change an operator would describe out loud.
  **An idle node at INFO is silent**: nothing per message, per poll or per probe.
- **DEBUG** — everything else, including the full negotiation over both planes.

### What DEBUG shows of a message

This is where the specification has to be read carefully rather than
paraphrased. `06-operacao-e-testes.md` forbids logging "payload cifrado … IP
privado sem modo diagnóstico explícito ou conteúdo de tráfego", and
`04-protocolo-e-seguranca.md` adds "Nunca incluir conteúdo rejeitado
integralmente nos logs."

| Part of a message | Logged? |
|---|---|
| Envelope fields except `body` | **Yes, at DEBUG.** Every relay that carried the event already saw them; logging discloses nothing new. |
| `body` — the ciphertext | **Never, at any level.** Only `body_len` and a truncated digest. |
| The decrypted negotiation | **Yes, at DEBUG.** See below. |
| A rejected message's content | **Never.** A `reason_code` only. |
| Addresses, including RFC1918 | Reduced at INFO; full under the diagnostic gate. |

**The decrypted negotiation is logged because it is not what the rule
protects.** "Payload cifrado" is the ciphertext, and that is never written.
"Conteúdo de tráfego" is what crosses the tunnel — the user's packets, which this
project never sees in the first place. What remains is the plaintext of the
*control* plane: message types, capabilities, sequence numbers, expiry, offer
hashes, and the WireGuard **public** keys the two sides are agreeing on. None of
it is secret, all of it is what an operator needs to see when a handshake stalls,
and hiding it would leave the same blind spot this ADR exists to close.

The private key never appears because it is never transmitted and because
`domain.NostrPrivateKey` and `domain.WireGuardPrivateKey` already render as
`[REDACTED]` through `LogValue`.

`body_digest` — a truncated SHA-256 of the ciphertext — is what makes the
requirement to "capture the whole negotiation" actually work across two hosts.
Correlating the same message on both ends needs an identifier both compute from
the same bytes; `message_id` is chosen by the sender and does not prove the
bodies matched.

### The diagnostic gate

Addresses get their own axis, orthogonal to level:

```text
log.diagnostic = "off"        addresses reduced: a public address to its /24,
                              a private one to its block name
log.diagnostic = "addresses"  addresses in full, including RFC1918
```

**It is not a log level, and that is the point.** Raising verbosity to diagnose a
stalled handshake is routine. Consenting to write peer addresses to disk is not.
Collapsing the two would make the second happen by accident every time somebody
did the first.

It is settable **only from the configuration file** — never a flag, never an
environment variable. Editing a root-owned file is the friction that makes the
choice deliberate. Turning it on emits one `WARN` at startup, so the log records
that it contains addresses.

This is the "modo diagnóstico explícito" the specification requires.

### Two sinks, one format

The system log needs no code: the service already writes to stderr and the unit
sets `StandardOutput=journal`, so `journalctl -u nostmesh` works today and keeps
working where there is no journal at all.

A configured file is a second writer over the same formatted output —
`io.MultiWriter`, not a fan-out handler. A handler that fans out formats the
record once per sink and clones its attributes on every `WithAttrs`; a
MultiWriter formats once and writes twice, and both sinks want identical JSON.

**The file is wrapped in a writer that swallows its own errors.** `io.MultiWriter`
stops at the first failure, so without this a full disk would take the journal
down with it — losing the sink the operator is guaranteed to have in order to
protect a copy. Failures are counted and surfaced once.

## Consequences

- **The file lives in `/var/log/nostmesh`**, created by systemd through
  `LogsDirectory=nostmesh`. `ProtectSystem=strict` makes everything else
  unwritable, so a path elsewhere fails at runtime in a way that looks like a
  permissions bug rather than a configuration one. The validator rejects a path
  the service will not be able to open.
- **No rotation of our own.** Adding a rotation library means a dependency to
  audit for a problem `logrotate` already solves with `copytruncate`, which needs
  no cooperation from the process. Reopening on SIGHUP was rejected because
  SIGHUP already reloads the allowlist, and overloading it would make a log
  rotation silently re-read policy.
- **A file that cannot be opened stops the service.** Degrading to journal-only
  leaves an operator believing they have an audit trail they do not have.
- **Rejected messages log a `reason_code` from a closed vocabulary**, never the
  error text. Free-form error strings are unaggregatable and are how content from
  a peer reaches a log. This replaces the current `fmt.Sprintf("refused a
  message: %v", err)`, which is the behaviour the protocol document warns
  against.
- **The `trace func(string)` callback is replaced, not simply removed.** It has
  two consumers with different needs: the service wraps it into a DEBUG record,
  and `nostmesh session` prints it as indented prose for a person watching a
  session come up. The structured path becomes a real logger; the CLI gets a
  handler that renders the same events as sentences. Defining the events once and
  rendering them twice is what makes them worth defining.
- **Loggers are passed, not injected as a port.** `log/slog` is standard library,
  is forbidden nowhere, and has a no-op handler. A project-specific interface
  would add an indirection at every call site and a mock in every test to gain
  nothing. Each package takes an optional `*slog.Logger` defaulted to a discard
  logger, exactly as `DriverDeps` already defaults its `Clock`.
- **DEBUG must cost nothing when disabled.** Composite values implement
  `slog.LogValuer` so they are formatted only after the handler accepts the
  record, and no call site uses `fmt.Sprintf`. Two places need an explicit
  `Enabled()` check because building the argument itself is expensive:
  `Engine.Diagnostics()` copies every candidate, and the hold loop polls forever.
  The hold loop additionally logs an observation only when something changed —
  the driver already reads the previous state to detect roaming, so the
  comparison is free.
- **This brings forward part of M2.5.** The roadmap places observability there.
  Doing it now is a deliberate re-scoping, recorded here rather than left
  implicit: the addressing work of M2.1 and the multi-peer work of M2.2 are both
  easier to build and far easier to debug against a node that can say what it is
  doing. The sequencing rule is kept — this is its own delivery, in its own
  branches and pull requests.
- **Every log line carries `component` and `event`**, and where applicable
  `node`, `peer`, `session`, `result`, `reason_code` and `duration_ms`, which is
  the shape the operations document specifies. Identifiers are abbreviated by
  default: a full public key is not a secret, but it is a durable correlatable
  identifier, and the specification asks for `node_id` abbreviated.

## Alternatives rejected

**Log to the journal only.** Simplest, and it loses the copy an operator wants
when the journal is rate-limited, rotated by a policy they do not control, or
absent because the binary is running outside systemd. The project ships a static
binary that must work without a supervisor.

**Write to journald directly through its socket protocol.** Gains structured
fields natively and costs the property that the same binary logs correctly on a
host with no journal. Writing to stderr and letting the supervisor capture it
works everywhere, which is why it is already what the service does.

**One log level for addresses.** Rejected above: it makes disclosure a side
effect of debugging.

**Redact addresses always, with a stable hash.** Preserves correlation without
disclosure, and makes real NAT traversal diagnosis impossible — the question is
usually *which* address was tried, not whether two lines refer to the same one.

## Validation

- **A leakage test per attribute constructor**, extending the pattern already in
  `internal/session/leakage_test.go`: emit through a real JSON handler and scan
  the output for private key material in **all four encodings** — raw bytes, hex,
  base64 and bech32. Testing only hex is how a base64 leak survives.
- **Each guard is validated by planting the violation.** A scan that passes
  everything is not a scan, so a sibling test logs raw key material deliberately
  and asserts the scan reports it. The same shape covers the diagnostic gate: a
  private address must be redacted with the gate off, and the check that proves
  it must itself be shown to fail against a planted address.
- **An end-to-end scan** over a full negotiation at DEBUG with the gate off,
  asserting no private key, no RFC1918 literal and no ciphertext body reaches the
  output. This is what discharges the requirement that no secret is detectable by
  a scanner in logs and artifacts.
- **An architecture guard** that fails the build when a log call site bypasses
  the attribute constructors, keeping the taxonomy closed as the code grows.
- **A benchmark asserting zero allocations** at a disabled-DEBUG call site.
