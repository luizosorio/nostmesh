# NostMesh

Connect your machines over an encrypted tunnel, without a company in the middle.

NostMesh uses **Nostr** to let your devices find each other and agree on how to
connect, and **WireGuard** to carry the traffic. There is no coordinator to sign
up for, no account, and no server that has to stay online for your network to
work.

> **Early development.** MVP 2 is complete: several machines, local policy, and
> private route announcements. It has not been audited — do not use it to
> protect anything that matters yet, and it makes no claim of anonymity.

## What you can do with it today

- Connect several machines of your own into one private network
- Share one machine with somebody else, and nothing more
- Reach a whole home or office network through one machine on it
- Decide, per machine, exactly who may connect and what they may reach

Your traffic goes directly between machines. Nostr relays only carry the
"hello, here is how to reach me" part — they never see what you send.

## Installing

Download the package for your system from the
[releases page](https://github.com/luizosorio/nostmesh/releases):

```bash
# Debian, Ubuntu
sudo dpkg -i nostmesh_0.2.4_amd64.deb

# Fedora, RHEL, openSUSE
sudo rpm -i nostmesh-0.2.4-1.x86_64.rpm
```

Or the standalone binary, which needs nothing else installed:

```bash
tar xzf nostmesh_v0.2.4_linux_amd64.tar.gz
sudo install -m 0755 nostmesh /usr/local/bin/
```

Both `amd64` and `arm64` are published. Every release ships a `SHA256SUMS` file
worth checking:

```bash
sha256sum -c SHA256SUMS --ignore-missing
```

**One prerequisite:** the WireGuard kernel module.

```bash
sudo modprobe wireguard
echo wireguard | sudo tee /etc/modules-load.d/wireguard.conf
```

You do **not** need `wg`, `wg-quick` or `nft`. NostMesh talks to the kernel
directly.

## Getting started

### 1. Create this machine's identity

```bash
sudo -u nostmesh nostmesh identity init --state-dir /var/lib/nostmesh
```

It prints a public key. That is what you give other people so they can authorize
you — it is not a secret. The private half stays on this machine and never
leaves it.

### 2. Write a configuration

Start from an example:

```bash
sudo cp /etc/nostmesh/nostmesh.json.example /etc/nostmesh/nostmesh.json
sudo nano /etc/nostmesh/nostmesh.json
```

The [example configurations](examples/scenarios/) cover the common setups —
your own machines, sharing with one person, reaching a home network. Pick the
closest one.

Check it before starting anything:

```bash
nostmesh config validate /etc/nostmesh/nostmesh.json
```

### 3. Start it

```bash
sudo systemctl enable --now nostmesh
```

### 4. See whether it worked

```bash
nostmesh state --config /etc/nostmesh/nostmesh.json
```

If something is wrong, this usually says what:

```bash
nostmesh doctor --config /etc/nostmesh/nostmesh.json
```

## Commands

| Command | What it does |
|---|---|
| `nostmesh doctor` | Checks everything a working tunnel needs, and names what is missing |
| `nostmesh state` | What the running service is doing — peers, sessions, routes |
| `nostmesh status` | What the kernel actually has: interfaces, addresses, routes |
| `nostmesh policy explain --peer <key>` | Why a particular peer can or cannot connect |
| `nostmesh config validate <file>` | Every problem in a configuration file, not just the first |
| `nostmesh identity init` | Creates this machine's identity |
| `nostmesh identity import` | Uses a Nostr key you already have |
| `nostmesh peer add` / `list` / `remove` | Manages manually configured peers |
| `nostmesh sessions` | Lists authorized peers and any active sessions |
| `nostmesh up` / `down` | Brings a manual tunnel up or removes it |
| `nostmesh connect` / `disconnect` | Opens or closes one session by hand |
| `nostmesh serve` | The long-running service; systemd starts this for you |
| `nostmesh relay-check` | Checks that real relays accept this protocol |
| `nostmesh version` | Build information |

Every command takes `--help`.

## When something does not work

Two commands answer most of it:

**`nostmesh doctor`** checks the prerequisites — the module, the identity, the
relays, the clock, the permissions — and tells you which one is missing.

**`nostmesh policy explain --peer <key>`** answers "why will this peer not
connect". The distinction that matters: *no rule matched* means nothing
authorizes them and you need to write a rule; a named rule with
*action not permitted* means the rule exists and needs widening.

The [troubleshooting guide](docs/troubleshooting.md) covers the rest, in the
order problems usually appear.

## How it decides who may connect

**Nobody, until you say so.** A machine with no rules connects to nothing, and a
valid signature proves who is asking — never that they may.

What a peer sends is a **proposal**. Which addresses to route, which subnets to
accept, what goes in the firewall: all of that comes from your configuration.
Nothing arriving over the network configures your machine directly.

That is why authorizing somebody is two decisions, not one: *may they connect*,
and *what may they reach*.

## Documentation

| | |
|---|---|
| [Configuration reference](docs/configuration.md) | Every setting, its default, what it does |
| [Example configurations](examples/scenarios/) | Working files for common setups |
| [Troubleshooting](docs/troubleshooting.md) | Symptoms, and the command that answers each |
| [Security model](docs/security-model.md) | What it defends against, and what it does not |
| [Releasing](docs/releasing.md) | What each release contains and how it is built |
| [Manual tunnel tutorial](docs/tutorial-manual-tunnel.md) | Two machines, no Nostr |
| [Nostr tunnel tutorial](docs/tutorial-nostr-tunnel.md) | Two machines finding each other |

For how it is built: [architecture decisions](docs/adr/),
[protocol](docs/protocol/v1.md), [development](docs/development.md).

## What NostMesh is not

- **Not an anonymity network.** Your relays see your identity's traffic pattern,
  and nothing is padded or delayed to hide it.
- **Not a VPN service.** There is nothing to subscribe to.
- **Not audited.** See the [security model](docs/security-model.md) for what is
  and is not defended against.
- **Not a Nostr transport.** Your packets go over WireGuard; Nostr carries only
  the negotiation.

## Roadmap

| Stage | Delivers |
|---|---|
| **MVP 0** ✅ | Foundation and a manual tunnel between two Linux machines |
| **MVP 1** ✅ | Nostr control plane, NAT traversal, direct connection |
| **MVP 2** ✅ | Several machines, local policy, private route announcements |
| MVP 3 | Relay fallback for networks that cannot connect directly |
| MVP 4 | Sharing an Internet connection, with limits and quotas |
| MVP 5 | Paid transit over Lightning |

A stage begins only after the previous one has a reproducible demo, green tests,
and documented limitations.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) first — it covers the development
environment, the architecture rules CI enforces, and what a change is expected
to look like.

Build and test run in containers, so you need no local Go toolchain:

```bash
make docker-check     # format, vet, tests, portability
make docker-lint      # linter, pinned to the CI version
make docker-build     # produces bin/nostmesh
```

## Security

Do not open a public issue for a vulnerability. See [SECURITY.md](SECURITY.md).

This project has not been audited. Do not rely on it to protect anything that
matters until it has been.

## License

[Apache-2.0](LICENSE). You may use, modify, distribute and commercialize this
code, including in closed-source products. See [NOTICE](NOTICE) for attribution
requirements and [THIRD-PARTY.md](THIRD-PARTY.md) for the dependency policy.
