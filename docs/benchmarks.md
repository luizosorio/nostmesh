# Baseline measurements

These establish a reference point for detecting regressions. **They are not a
performance claim**, and the numbers should not be quoted as what a deployment
would see.

## What the setup actually measures

The benchmarks run between two network namespaces on a single machine. There is
no physical link, no competing traffic, no real network path, and both sides
share one CPU.

That measures what the code costs — encryption, packet handling, netlink round
trips — with the network removed. A real deployment's numbers are bounded by
things this setup does not have.

## What is not measured

`RNF-PERF` targets tunnel-attributable overhead below 10% on a 1 Gbps lab.
**This suite does not measure that**, and no claim is made about it. Doing so
requires two hosts and a real link, which MVP 0 does not build. That measurement
belongs to a milestone that has the topology to support it.

## Running them

```bash
sudo modprobe wireguard
make docker-bench
```

Same prerequisites as the privileged tests: `CAP_NET_ADMIN`, `CAP_SYS_ADMIN`,
and the `wireguard` module loaded on the host.

## What each one tells you

| Benchmark | Measures | Why it matters |
|---|---|---|
| `InterfaceSetup` | Cold interface creation | The latency of `nostmesh up`, and the cost paid on every future reconnect |
| `IdempotentApply` | Re-applying unchanged state | The common case: reconciliation and retries both re-apply a mostly-present plan |
| `TunnelThroughput` | TCP bytes through the tunnel | Encryption and packet-handling cost, isolated from network capacity |
| `HandshakeLatency` | Cold interface to first handshake | The delay before a tunnel carries traffic |

## Using them as a regression signal

Record a baseline before a change that touches the adapter or the transactional
path, then compare:

```bash
make docker-bench > before.txt
# make the change
make docker-bench > after.txt
benchstat before.txt after.txt
```

A single run is noisy. `-count=5` or more is worth the wait when the result
matters.

## Baseline, 2026-08-30

Recorded on the lab host: Intel Pentium Silver N6005 @ 2.00GHz, 4 cores, Debian
13, kernel 6.12, Go 1.25.14, `-benchtime 20x`.

| Benchmark | Result | Allocations |
|---|---|---|
| `InterfaceSetup` | 1.70 ms/op | 766 KB, 523 allocs |
| `IdempotentApply` | 10.68 ms/op | 501 KB, 392 allocs |
| `TunnelThroughput` | 385 MB/s | 4 B, 0 allocs |
| `HandshakeLatency` | 5.92 ms/op | 2.1 MB, 1888 allocs |

### What stands out

**`IdempotentApply` is six times slower than creating an interface**, which is
backwards: re-applying unchanged state should be cheaper than building it.

`EnsureInterface` already skips the MTU when it matches, but `configureDevice`
and `LinkSetUp` write unconditionally. Rewriting the private key is the
expensive part — the kernel re-derives the public key each time — and it happens
on every apply even when nothing changed.

This matters because convergence is the common case: reconciliation and every
retry re-apply a plan that is mostly already in place. It is a correctness-safe
inefficiency — the result is right, it just costs more than it should — and it
is recorded here rather than fixed in MVP 0, where nothing re-applies in a loop.
The fix is to observe first and write only what differs, which is worth doing
before MVP 2 introduces many peers reconciling together.

**Throughput allocates nothing per operation**, which is what a kernel data
plane should look like: the bytes never enter the Go process. The 385 MB/s
figure is CPU-bound encryption on a low-power part with both tunnel ends sharing
it, not a network measurement.

## Interpreting a change

An interface setup that gets slower usually means more netlink round trips. A
throughput drop with unchanged setup time usually means the data path, not the
control path. Handshake latency is dominated by the WireGuard protocol itself
and should be stable — a change there is more likely an environment difference
than a code regression.
