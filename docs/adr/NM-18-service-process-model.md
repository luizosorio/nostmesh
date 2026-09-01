# NM-18 — Service process model

**Status:** Accepted
**Date:** 2026-09-01
**Milestone:** M1.5 (completing)
**Supersedes:** [NM-16](NM-16-session-process-model.md)

## Context

NM-16 chose two foreground commands and no daemon: `listen` waits for one named
peer, `connect` opens a session with one peer, and the operating system supervises
whichever is wanted. It rejected a daemon on the grounds that a control socket is
an authorization surface deserving its own design rather than arriving as a side
effect of wanting `connect` to return immediately.

That reasoning was right about the cost and wrong about the shape of the problem.

Either side may open a session at any time, and the other has to be ready to
answer. `listen` and `connect` split that into two commands and force the operator
to decide in advance which machine is which — a decision the pair has to make for
itself, because neither end knows in advance which will move first. Worse, the
split is not stable: after a session ends, both ends want to be ready again, and
"ready" is not a command that terminates.

The design also produced a defect that only a running service reveals. NM-16's
`listen` was one-shot, so nothing had to decide what happens *after* a session is
established. Once a supervisor loop existed, `Connect` returning was treated as a
completed unit of work, and the next attempt could not bind: the interface from
the session that had just succeeded still held the listen port. The service
competed with itself while the tunnel it had built sat there working.

## Decision

**One long-running service: `nostmesh serve --config <path>`.**

It starts a worker per authorized peer. Each worker is always willing to open a
session *and* to answer one; which end opens is settled by `resolveRole`, a total
order on the two Nostr keys, so both sides reach the same answer without
exchanging a message.

**A worker holds an established session rather than finishing on it.** `Connect`
returning means the tunnel carries traffic; the work ends when the data plane
stops. `Hold` watches the kernel for that, and `Release` removes the interface
before anything tries to bind again.

**Liveness is read, not assumed.** WireGuard rekeys after roughly two minutes,
and the peer spec carries a 25-second persistent keepalive, so a live session
refreshes its handshake even with no user traffic. A handshake that stops
advancing therefore means the path died rather than that nobody used it.

**Every wait is bounded.** A worker lives as long as the operator leaves it
running; a single negotiation must not. A responder gives the attempt back after
`RequestWait` and takes the initiating role next time, and one attempt's whole
negotiation is bounded separately.

**The control socket is read-only.** It answers one verb, `state`, at mode 0600,
verified after creation because Go applies the umask. This is the entire security
argument: whoever reaches the socket learns what the service is doing and cannot
make it do anything.

**Logging is structured to stderr**, captured by whatever supervises the process
(`journalctl -u nostmesh` under systemd). Not journald natively: the binary has to
run on Windows and macOS eventually, and a Linux-only logging dependency in the
service would be an OS coupling for no gain.

**SIGHUP reloads the allowlist.** A peer added or revoked takes effect without
restarting, and an invalid configuration is refused rather than applied. Node
settings — listen port, relays, state directory — are not reloadable, and the
operator is told so rather than left to wonder why nothing changed.

## Consequences

**Sessions survive as long as the service does.** `state` reports live phase,
attempts, how long the phase has held, the last failure reason, and the age of
the data-plane handshake — the quantity the hold acts on, so an operator can see
a teardown coming rather than learn about it afterwards.

**Revocation is announced only to a peer that actually had a session.** Telling a
peer that never connected would make allowlist membership observable from
outside. The worker is deregistered before its context is cancelled, so there is
no window in which a revoked peer is still served.

**A liveness check requires a keepalive to be meaningful.** With
`KeepaliveInterval` at zero, an idle tunnel legitimately stops refreshing, and a
staleness rule would tear down something that works. `Hold` therefore degrades to
waiting on its caller and never declares a drop, which is the safe direction:
losing the check costs a slow reconnect, and killing healthy tunnels every three
minutes would be a worse defect than the one being fixed.

**Startup removes what an earlier run left behind.** A service killed while
holding a session leaves its interface up with the port bound, and the journal
records nothing because the transaction committed. A starting service holds no
sessions, so an interface it finds is residue by definition — and only one this
node owns is touched.

**`connect`, `sessions` and `disconnect` remain.** They are named in the MVP 1
scope for M1.3 and are the one-shot path for laboratory use. `listen` is what
`serve` replaces: an ephemeral responder for one named peer has no role once a
service answers continuously.

## Known limitation

**The service holds one peer per node today.** `listen_port` is a single
node-level value and the interface name is the constant `nm0`, while each worker
builds its own runtime and binds that port independently. With two or more
authorized peers, the second worker cannot bind.

This is recorded rather than hidden: the decision here fixes a node competing
with itself, and does not make the service multi-peer correct. Doing that needs
either a transport and interface owned by the service with a peer applied per
session, or a port per peer — a decision with its own consequences for what a
peer verifies and what WireGuard binds, and therefore its own ADR.

## Alternatives rejected

**Keeping `listen` alongside `serve`.** Two ways to answer a peer, differing in
whether the answer persists. Rejected: the operator would have to know which one
leaves the node reachable, and the answer is always `serve`.

**Folding the hold into `Connect`.** Tempting — one call, complete lifecycle.
Rejected because it destroys the one-shot semantics `connect` needs, and makes
"the tunnel came up" untestable as a bounded event.

**Polling liveness from the command layer.** Rejected: it would require exporting
the driver's controller and interface name so `cmd` could read the data plane,
inverting the dependency direction the layout maintains.

**A writable control socket.** Rejected for the same reason NM-16 rejected the
daemon, and the reason still holds. Read-only is what makes the socket's security
argument short enough to be obviously correct.

## Validation

Verified between two hosts, one behind a real NAT. A session established and was
held continuously; the handshake age was observed rising to 2m19s and falling
back to 55s as the keepalive triggered a rekey, which is the evidence that the
three-minute staleness bound is generous rather than merely assumed.

Drop detection was confirmed both ways: deleting the interface produced `nm0 is
gone`, and a genuinely dead path produced `last handshake was 3m3s ago`. Deleting
both interfaces simultaneously — the case that previously left both ends waiting
on each other indefinitely — re-established the session in eight seconds, with no
bind failures on either side.

Every guard was validated by planting the violation and observing it fail,
including in both directions where the constant admits two errors: with the
staleness check removed a dead session was held forever, and with it firing
immediately a live one was destroyed.
