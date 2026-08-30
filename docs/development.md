# Development environment

Build and test run in containers, so nothing needs to be installed beyond a
container runtime.

This applies to development only. NostMesh ships as a single static binary that
users install directly on their machine — see [Installing](../README.md#installing).

## Quick start

```bash
make docker-check     # format, vet, tests, portability guard
make docker-build     # produces bin/nostmesh
```

Every target works with a `docker-` prefix. Without it, targets use a local Go
1.25 toolchain.

## Targets

| Target | Does |
|---|---|
| `check` | Format check, vet, tests, portability guard — what CI runs |
| `build` | Static CGO-free binary into `bin/` |
| `test` | Tests with the race detector |
| `cover` | Tests with a coverage summary |
| `lint` | golangci-lint (`make docker-lint` uses the pinned CI version) |
| `portability` | Cross-compile for Linux, Windows and macOS |
| `fmt` | Format the tree |
| `clean` | Remove build output |

The linter version is pinned in the Makefile and in CI so both analyze with the
same rules. Run `make docker-lint` before opening a PR — `make check` does not
include it, since it needs a different image.

## Privileged tests

Tests that touch WireGuard or network namespaces are behind the `privileged`
build tag and never run in the default suite:

```bash
make docker-test-privileged
```

### What they need

| Requirement | Why |
|---|---|
| `wireguard` kernel module | The data plane runs in the kernel (NM-01) |
| `CAP_NET_ADMIN` | Creating and configuring interfaces |
| `CAP_SYS_ADMIN` | Creating network namespaces |

Containers share the host kernel, so the module must be loaded **on the host**:

```bash
sudo modprobe wireguard
lsmod | grep wireguard
```

It is not loaded at boot on every distribution. To make it persistent:

```bash
echo wireguard | sudo tee /etc/modules-load.d/wireguard.conf
```

`CAP_SYS_ADMIN` is the one that surprises people: `CAP_NET_ADMIN` alone lets you
configure interfaces but not create a namespace to isolate them in. Without it
every test skips, which looks like success at a glance — check for `--- PASS`
rather than a green exit code.

### Isolation

Each test runs in its own network namespace, so a failure cannot disturb the
host or another test. The goroutine is locked to its OS thread while inside:
network namespaces are a per-thread property in Linux, and without the lock the
Go runtime could migrate the goroutine to a thread still in the original
namespace, silently configuring the host instead.

Domain, protocol, policy and config tests never need root. A test in those
packages requiring privileges means a boundary has been crossed.

## Linux requirements at runtime

The binary itself needs:

- a kernel with WireGuard (5.6+, or the module on older kernels)
- `CAP_NET_ADMIN` for commands that change network state

It does **not** need `wg`, `wg-quick`, `ip` or `nft` installed. All network
state is applied through netlink (NM-05).

### Interface ownership

NostMesh creates interfaces prefixed `nm` and refuses to configure or remove
anything else. This is how ownership is decided when the journal is incomplete
after a crash, so the prefix is load-bearing: renaming an interface out of it
makes NostMesh disown it.

## Layout

The core — `internal/domain`, `internal/protocol`, `internal/policy`,
`internal/config` — must not import an OS package, `syscall`, or any adapter.
`test/architecture` enforces this and fails the build on violation.

Platform code lives behind ports: `port.go` declares the interface,
`adapter_linux.go` and friends implement it under build tags.

## Before opening a PR

```bash
make docker-check
```

This runs the same checks CI does. See [CONTRIBUTING.md](../CONTRIBUTING.md) for
the workflow and the Definition of Done.
