# NostMesh

A decentralized overlay network that uses **Nostr** for identity, discovery and
negotiation, and **WireGuard** to carry packets between nodes.

The goal is to let two machines establish an authenticated tunnel — even behind
NAT — without depending on a proprietary coordinator. Later stages add mesh
topologies, private route announcements, data relays, and a transit market for
Internet access, free or paid over Bitcoin Lightning.

> **Status: early development.** MVP 0 is in progress. This is not yet a usable
> product, and it makes no claim of anonymity. See [Scope](#scope) for what
> NostMesh is not.

## How it works

Two planes, deliberately kept apart:

```text
                    CONTROL PLANE
        Nostr relays (signed, encrypted events)
       identity • discovery • offers • negotiation
                         │
              ┌──────────┴──────────┐
              │                     │
           node A                node B / gateway
              ╲                     ╱
               ╲  WireGuard/UDP    ╱
                ═══════════════════
                     DATA PLANE
              direct, or via a data relay
```

Nostr never carries user IP packets. It helps nodes find each other,
authenticate, and agree on temporary parameters. Useful traffic goes over
WireGuard. STUN and ICE-like connectivity checks look for a direct path; a data
relay is the fallback.

## Non-negotiable principles

These are invariants, not guidelines. They are not traded away for convenience
or deadline:

- Nostr identity keys are **never** reused as WireGuard keys.
- Only the WireGuard **public** key travels in encrypted signaling. The private
  key never leaves the node that generated it — not in events, logs, the network
  journal, or diagnostic bundles.
- Events are **proposals, not commands**. `AllowedIPs`, routes, DNS and firewall
  rules are derived from local policy, never from a remote field.
- Every policy decision is **deny by default**.
- Network changes are **transactional, idempotent and reversible**. NostMesh
  never removes a rule it does not own.
- A third-party candidate stays `UNVERIFIED` until an authenticated connectivity
  check validates it.
- Auxiliary roles — Nostr relay, STUN observer, data relay, exit provider — are
  independent. Enabling one never grants another.
- An exit node does not mean anonymity. The provider sees metadata and carries
  real legal risk.

## Scope

**NostMesh is not** Tor: it builds no layered circuits and does not promise to
hide who connects to whom. It is not a cryptocurrency or a blockchain. It does
not tunnel IP packets inside Nostr events. It does not remove legal
responsibility from an operator who shares their connection.

Out of scope for now: Windows, macOS, Android and iOS; onion routing; global
consensus; post-payment or fund custody.

## Installing

NostMesh is a single static binary. Put it on your `PATH` and run it — there is
nothing else to install, no runtime, no container.

```bash
sudo install -m 0755 nostmesh /usr/local/bin/
nostmesh version
```

Requirements on the machine that runs it:

- Linux with the `wireguard` kernel module (`sudo modprobe wireguard`)
- `CAP_NET_ADMIN` for the commands that change network state

`wg`, `wg-quick` and `nft` do **not** need to be installed. NostMesh configures
the kernel directly over netlink rather than driving external tools.

> Prebuilt binaries are not published yet — MVP 0 is still in progress. Until
> then, build from source with the instructions below.

## Building from source

```bash
git clone git@github.com:luizosorio/nostmesh.git
cd nostmesh
make build            # produces bin/nostmesh
```

That needs a local Go 1.25 toolchain. If you would rather not install one,
every target also runs in a container with a `docker-` prefix:

```bash
make docker-build
make docker-check     # format, vet, tests, portability guard
```

Containers are how this project develops and tests, not how it ships. See
[docs/development.md](docs/development.md).

### Try it

```bash
nostmesh version
nostmesh config validate examples/nostmesh.json

nostmesh identity init --state-dir ./state    # generate this node's identity
nostmesh peer add --config nostmesh.json ...  # describe the other side
sudo nostmesh up --config nostmesh.json       # bring the tunnel up
nostmesh status --config nostmesh.json        # configured vs. observed
sudo nostmesh down --config nostmesh.json     # remove what NostMesh applied
```

For a walk-through of establishing a tunnel between two hosts, see the
[manual tunnel tutorial](docs/tutorial-manual-tunnel.md).

Configuration is declarative and validated before it can influence anything.
Invalid input fails with a message naming the field and stating what is
required — and reports every problem at once, not one per run:

```
$ nostmesh config validate broken.json
invalid configuration: 2 problems found:
  - node.state_dir: must be an absolute path, got "relative/path"
  - policy.default_action: must be "deny"; allow-by-default is not supported, got "allow"
```

## Architecture

A **single, self-contained binary**. The CLI, the daemon and the auxiliary
service roles are subcommands of the same executable. It links statically, needs
no runtime dependencies, and never shells out to `wg`, `nft` or `ip` — network
state is applied directly through the kernel over netlink.

This is what makes installation a file copy: one binary, no runtime, no package
tree, nothing to keep in version lockstep on the host.

Dependencies point inward:

```text
cmd/nostmesh/             CLI and daemon entrypoint
internal/domain/          pure types and state machines
internal/protocol/        envelopes, codec, validation
internal/policy/          local authorization
internal/config/          declarative configuration
internal/wireguard/       port + platform adapters
internal/netstate/        routes, firewall, DNS, journal
...
test/architecture/        dependency rules, enforced by test
```

`internal/domain`, `internal/protocol`, `internal/policy` and `internal/config`
form the core and must not import an operating system package, `syscall`, or any
adapter. This is not a convention — `test/architecture` fails the build when it
is violated, and CI cross-compiles for Windows and macOS to prove the core stays
portable long before adapters for them exist.

Decisions are recorded as ADRs in [`docs/adr/`](docs/adr/), numbered `NM-01`
onward. Changing one means writing a new ADR that supersedes it, never editing
history.

## Handling of keys

Two secrets exist, with different lifetimes and different consequences if they
leak. They are separate types, and neither can be printed, logged or serialized
by accident: every path that would normally reveal a value yields `[REDACTED]`
instead, and JSON encoding fails outright rather than emitting a placeholder
that looks like data.

There is exactly one sanctioned way to get raw key material out, reserved for
the development keystore, and an architecture test fails the build if anything
else calls it. See [NM-06](docs/adr/NM-06-key-separation-and-secret-handling.md).

The file keystore writes the key to disk unprotected and is for development
only. Production deployments are expected to use an external signer that never
surrenders the private key.

> Nostr public key derivation is currently a development placeholder, not a real
> secp256k1 key — see [NM-07](docs/adr/NM-07-deferred-nostr-key-derivation.md).
> Identities created now are not valid Nostr identities and will not carry
> forward past MVP 1.

## Roadmap

| Stage | Delivers |
|---|---|
| **MVP 0** ✅ | Foundation and manual WireGuard tunnel between two Linux hosts |
| MVP 1 | Nostr control plane, NAT traversal, direct connection |
| MVP 2 | Mesh, local policy, private route announcements |
| MVP 3 | Data relay fallback for symmetric NAT |
| MVP 4 | Free transit and exit, with NAT, quotas and QoS |
| MVP 5 | Paid transit over Lightning, local reputation |

A stage begins only after the previous one has a reproducible demo, green tests,
and documented limitations.

## Contributing

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) before
opening a pull request — it covers the development environment, the branch and
PR workflow, and the conventions every change is expected to follow.

Two points worth stating up front:

**AI tools are welcome.** Use whatever helps you work. What matters is the
result: you understand the code, you can defend every decision in it, and you
are responsible for it. Contributions are judged on their merit, never on how
they were produced.

**No AI attribution in the repository.** Commits, code comments, branch names,
pull requests and documentation never mention AI assistants, models or tools —
no co-author trailers, no "generated with" footers. The commit history records
what changed and why, not what tooling was open at the time. See
[CONTRIBUTING.md](CONTRIBUTING.md#no-tooling-attribution) for the reasoning.

## Security

Do not open a public issue for a vulnerability. See
[SECURITY.md](SECURITY.md) for how to report one.

This project has not been audited. Do not rely on it to protect anything that
matters until it has been.

## License

[Apache-2.0](LICENSE). You may use, modify, distribute and commercialize this
code, including in closed-source products. See [NOTICE](NOTICE) for attribution
requirements and [THIRD-PARTY.md](THIRD-PARTY.md) for the dependency policy.
