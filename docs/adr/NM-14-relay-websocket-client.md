# NM-14 — Relay WebSocket client

**Status:** Accepted
**Date:** 2026-08-30
**Milestone:** M1.5

## Context

M1.2 defined a `Relay` interface and implemented it with a fake, so the client's
behaviour under adversarial conditions could be tested without a network. That
was deliberate: the failure modes that matter — a relay dropping mid-publish,
duplicating, reordering, silently discarding — do not happen on request against
a real server.

Closing MVP 1 requires the real transport behind the same interface.

Nostr relays speak a small protocol over WebSocket: `["EVENT", <event>]` to
publish, `["REQ", <id>, <filter>]` to subscribe, and `["OK", ...]`,
`["EVENT", ...]`, `["EOSE", ...]`, `["NOTICE", ...]` coming back.

## Decision

**`github.com/coder/websocket`** for the transport.

**The Nostr protocol layer is ours.** Framing, subscription management,
reconnection and the outbox are already implemented (M1.2); what was missing was
the socket underneath.

**One connection per relay, with independent lifecycles.** A relay going down
must not disturb the others — that is the property MVP 1's acceptance criteria
name, and sharing state between connections is how it gets accidentally
violated.

**Reconnection uses the existing backoff with jitter** rather than a new policy.

## Alternatives considered

**`gorilla/websocket`** — the most widely deployed Go WebSocket library.
Rejected because it was archived and later revived under new maintenance, its
API predates `context`, and it requires more care to use correctly from multiple
goroutines. `coder/websocket` is context-native and brings no transitive
dependencies at all.

**The `go-nostr` relay client** — would provide subscription handling and
reconnection. Rejected for the same reason as in NM-10: the root package pulls
in a WebSocket client, three JSON libraries and a URL parser, and more
importantly its behaviour under duplicate, delayed and dropped events is exactly
what this project needs to control rather than inherit. The deduplication and
outbox in M1.2 exist because that behaviour is a correctness concern.

**Raw TCP with a hand-written WebSocket framing layer** — would avoid the
dependency entirely. Rejected: WebSocket framing has masking, fragmentation and
close-handshake details that are easy to get subtly wrong, and getting them
wrong means silent incompatibility with deployed relays.

## Consequences

- One module enters the binary, with no transitive dependencies. It is already
  in the module graph as a `go-nostr` dependency, so the graph does not grow.
- The `Relay` interface is unchanged, so every M1.2 test still exercises the
  same contract against the fake. The real client is tested separately against a
  local server.
- A relay's connection state is per-relay. A test can take one down and assert
  the others keep working, which is the acceptance criterion.
- Read limits are mandatory. A relay is untrusted, and an unbounded read from a
  hostile one is a memory exhaustion the client hands over for free.
