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

## Interpreting a change

An interface setup that gets slower usually means more netlink round trips. A
throughput drop with unchanged setup time usually means the data path, not the
control path. Handshake latency is dominated by the WireGuard protocol itself
and should be stable — a change there is more likely an environment difference
than a code regression.
