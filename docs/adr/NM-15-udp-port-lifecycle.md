# NM-15 — UDP port lifecycle and handover to WireGuard

**Status:** Accepted
**Date:** 2026-08-31
**Milestone:** M1.4 (completing)

## Context

NM-13 established that a candidate is only usable once a connectivity check has
authenticated it at an exact address and port. That decision has a consequence
which was not stated at the time, and which the implementation did not honour: a
NAT allocates its mapping per source port. An address observed from one local
port describes a mapping that exists only for that port. Probing from a second
port and running WireGuard on a third produces three unrelated mappings, and the
address the peer verified is not the one the tunnel uses.

So STUN observation, connectivity checks and the WireGuard data plane must all
originate from one local UDP port.

They cannot share one socket. Observation and probing are Go code holding a
`net.UDPConn`; the data plane is the kernel's WireGuard module, and `wgctrl`
exposes no way to pass it a file descriptor. There is no API through which a
userspace socket and the kernel module can hold the same port simultaneously.

Two further constraints. `ListenPort: 0` — the default, and what an operator who
has not chosen a port gets — asks the kernel to pick, and asking twice yields two
different ports. And the previous `STUNObserver` opened a fresh socket per query,
so even the observation phase did not reliably use one port.

## Decision

**One port, held continuously, handed over once.**

`UDPTransport` (`internal/connectivity/udp.go`) owns the session's port and is
the single authority on its number.

**Phase A — Go owns the socket.** The transport binds the port. When the operator
configured port 0, the kernel chooses and the transport *reads the choice back*
from `LocalAddr`, so the number is known from that moment. STUN observation and
connectivity checks both run over this socket; `SharedObserver` borrows it rather
than opening its own.

**Phase B — release.** `Close()` frees the port.

**Phase C — the kernel binds it.** WireGuard is configured with
`ListenPort: transport.LocalPort()` — never 0, never a fresh choice.

**The socket is unconnected.** One socket serves every candidate address. A
connected socket would discard datagrams from all but one peer, and which peer
address will work is exactly what the checks exist to determine.

**Demultiplexing by shape.** Probes and STUN responses arrive on the same socket.
STUN carries a magic cookie at a fixed offset for precisely this purpose, so a
datagram carrying it goes to the observer and everything else to the prober.
Probes are additionally authenticated (NM-13), so a datagram that fakes the
cookie is at worst discarded as an unmatched STUN response.

## Consequences

**The mapping survives the gap.** A NAT mapping expires on inactivity, typically
30 seconds to a few minutes; it is not torn down when a local socket closes. The
window between phases B and C is milliseconds, and `PersistentKeepalive` holds
the mapping afterwards.

**The gap is not zero, and cannot be.** Between release and rebind another
process on the host could take the port. Nothing prevents this; the exposure is
bounded by making the window as short as the code allows, and a failure to rebind
surfaces as a session failure rather than as a tunnel that silently uses the
wrong port.

**A fixed port is the more predictable configuration.** An operator who sets one
gets the same port every session, which survives restarts better than a mapping
re-established from a new random port each time.

**`SharedObserver` refuses a port it does not hold.** Asking it to observe any
other port is a wiring error that would yield a candidate describing an unused
mapping, so it fails loudly rather than answering for the wrong port.

## Alternatives rejected

**Let WireGuard choose its own port.** Simplest, and wrong: the verified address
would describe a different mapping than the tunnel uses. This is the failure that
looks like a NAT problem while every candidate is marked valid, and the reason
this ADR exists is to keep a later simplification from reintroducing it.

**Userspace WireGuard to share the socket.** `wireguard-go` could in principle
share a socket with the prober. Rejected: the project's stack decision makes the
kernel data plane the default for RNF-PERF, and userspace remains an alternative
adapter, not a reason to reshape the port model.

**Keep the port and proxy the data plane through it.** Every packet would cross
userspace, which is precisely what the kernel data plane exists to avoid.

## Validation

The mechanism is tested against a real kernel in `test/integration`
(`porthandover_linux_test.go`, tag `privileged`): the transport binds, reports
its port, releases it, and WireGuard binds the same number and reports listening
on it. Exclusivity and real datagram flow are covered alongside.

What a namespace lab cannot show is the NAT mapping surviving the handover, since
there is no NAT in the path. That half is validated against real NAT during the
three-node verification.
