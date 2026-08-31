# NM-16 — Session process model

**Status:** Accepted
**Date:** 2026-08-31
**Milestone:** M1.5 (completing)

## Context

A session needs both sides present at once. The responder must be subscribed to
its relay inbox before the initiator publishes a request, or the request lands on
a relay nobody is reading and expires unseen.

`connect` alone cannot provide that. It is a one-shot command, and the peer it
addresses may be a machine where nothing is running.

The obvious answer is a daemon. That answer carries costs which the current
acceptance criteria do not ask anyone to pay: a control socket, a pid file, an
IPC protocol between CLI and daemon, and a privilege boundary between them. Each
is a design decision with security consequences — a control socket is an
authorization surface — and none is needed to demonstrate that two hosts can
establish a tunnel.

## Decision

**Two foreground commands, no daemon.**

`nostmesh listen --config <path> --peer <pubkey>` waits for a specific peer to
open a session and answers it. It runs in the foreground until the tunnel is
established or the timeout expires.

`nostmesh connect --config <path> --peer <pubkey>` opens a session with a peer.

Both take `--timeout`. Both tear down cleanly on `SIGINT` and `SIGTERM`: a signal
is a request to stop, not permission to abandon kernel state.

**Supervision is the operating system's job.** A node that should stay reachable
runs `listen` under systemd or a container runtime, which already solve restart,
logging and resource limits better than a hand-written daemon would.

**`listen` names its peer.** It does not accept from anyone on the allowlist. The
allowlist says who *may* connect; this argument says who is expected *now*. The
distinction matters because a listener open to every authorized peer is a
different security posture, and one that should be chosen deliberately rather
than inherited from a command's convenience.

## Consequences

**Sessions do not survive the process.** When `connect` exits, its `SessionManager`
goes with it. The interface and its peer remain configured in the kernel — that
state is in the journal and `nostmesh down` removes it — but the session's phase,
roaming history and diagnostics are gone.

**`sessions` reports the allowlist, not live sessions.** It cannot report what it
cannot see. Making it report live sessions requires either a daemon to ask or
persisted session state, and both are decisions for when roaming across restarts
is actually in scope.

**Roaming works within a session's lifetime only.** `Roam` is implemented and
tested, but nothing outside a running `connect` or `listen` can invoke it. An
endpoint that changes after the process exits is not followed.

**Both sides must be started within the timeout of each other.** There is no
queuing: a request published while nothing listens is not retried when a listener
appears later. The relay may still hold the event, but the responder subscribes
after it, and a parameterized-replaceable event has no delivery guarantee for a
subscriber that arrives late.

## Alternatives rejected

**A daemon with a control socket.** The complete answer, and the right one
eventually. Rejected now because the socket is an authorization surface that
deserves its own design rather than being added as a side effect of wanting
`connect` to return immediately.

**`connect` listens as well, symmetrically.** Tempting — one command, both roles.
Rejected because it hides which side initiates, and the roles genuinely differ:
the initiator sends the request and the responder binds its tunnel key to what
arrives. A symmetric command would have to guess, and guessing wrong wastes a
timeout.

**Persisting session state to disk.** Would let `sessions` report the truth after
the process exits. Rejected for now: state that outlives the process it describes
becomes stale in ways that are worse than absent, and reconciling it against the
kernel is the daemon problem again in another shape.

## Validation

Both commands are exercised end to end during the three-node verification, where
`listen` runs on one host and `connect` on another. The failure modes — no
listener, an expired timeout, an interrupt mid-session — are checked there rather
than in unit tests, since what they must leave behind is host state.
