# Configuration reference

Every setting NostMesh reads, what it does, and what happens if you leave it
out. The file is JSON, and lives at `/etc/nostmesh/nostmesh.json` when installed
from a package.

After changing it:

```bash
nostmesh config validate /etc/nostmesh/nostmesh.json   # check before applying
sudo systemctl reload nostmesh                          # apply
```

Reloading applies changes to **who is authorized**. Changing the listen port,
the relays or the state directory needs a restart, and the service says so
rather than pretending otherwise.

## The smallest working file

```json
{
  "node": {
    "name": "laptop",
    "state_dir": "/var/lib/nostmesh",
    "overlay_address": "100.96.0.1/32",
    "listen_port": 51820,
    "relays": ["wss://relay.example", "wss://relay2.example"]
  },
  "policy": {
    "default_action": "deny",
    "max_sessions": 64,
    "authorized_peers": [
      { "public_key": "<peer's hex key>", "alias": "desktop", "actions": ["session"] }
    ]
  }
}
```

Everything else has a default.

---

## `node`

Who this node is and how it reaches the network.

| Field | Default | What it does |
|---|---|---|
| `name` | — | A label for this node, used in logs and diagnostics. Required. |
| `state_dir` | — | Where the identity key and network journal live. Absolute path, owned by the service user. Required. |
| `overlay_address` | — | This node's address inside the tunnel, in CIDR. Local intent — never negotiated. Not needed if `network` is configured. |
| `listen_port` | `0` | The UDP port WireGuard binds. Zero lets the kernel choose, which is fine for a machine that only dials out and wrong for one peers dial into. |
| `mtu` | `1420` | Tunnel interface MTU. The default leaves room for the WireGuard header inside a 1500-byte path. |
| `relays` | — | Nostr relays used for signalling. **Three or more is recommended**: a relay that goes down should not stop your control plane. They never carry your traffic. |
| `observers` | — | STUN servers used to find your public address, consulted only when nothing routable is found locally. **Two or more** — with one, a public address that changes between sessions cannot be detected. |

## `log`

| Field | Default | What it does |
|---|---|---|
| `level` | `info` | One of `debug`, `info`, `warn`, `error`. |
| `format` | `json` | `json` or `text`. JSON by default because logs are meant to be read by tools. |
| `file` | — | An optional second copy on disk. Logs always reach the system log regardless; this outlives it. |
| `diagnostic` | `off` | `off` or `addresses`. Opting in writes IP addresses in full. |

**`diagnostic` is not a log level.** Raising verbosity to work out why a
handshake stalls is routine; writing addresses into a file somebody may share is
a separate decision, so it is a separate setting.

## `policy`

Who may do what. **Every decision denies by default** — a node with an empty
policy connects to nobody, and that is the intended starting point.

| Field | Default | What it does |
|---|---|---|
| `default_action` | `deny` | Only `deny` is accepted. The field exists so an audit can see the stance, not to offer an allow-by-default mode. |
| `accept_default_route` | `false` | Whether this node is willing to be *asked* about a `0.0.0.0/0` route. Enabling it does not accept one. |
| `max_sessions` | `64` | How many tunnels this node holds at once. |
| `authorized_peers` | empty | Peers named individually. |
| `groups` | empty | Several peers authorized by one rule. |

### `authorized_peers[]`

```json
{
  "public_key": "a1b2c3...",
  "alias": "desktop",
  "actions": ["session"],
  "allowed_ips": ["100.96.0.2/32"],
  "revoked": false
}
```

| Field | What it does |
|---|---|
| `public_key` | The peer's Nostr identity, hex. This is what authorizes; everything else describes. |
| `alias` | A label for you. Carries no authority — two peers may share one. |
| `actions` | What they may do: `session`, `route`, `transit`. Anything not listed is refused. |
| `allowed_ips` | Which prefixes you will route to them. Your decision, not theirs. |
| `revoked` | Withdraws the grant while keeping the record, so you can see somebody was removed on purpose rather than never added. |

### `groups[]`

```json
{
  "name": "my-devices",
  "members": ["a1b2...", "c3d4...", "e5f6..."],
  "actions": ["session"],
  "allowed_ips": ["100.96.0.0/24"]
}
```

One rule for several peers. Useful when a set of machines is trusted the same
way — writing the tenth rule adds no intent the first did not already carry.

**A rule naming one peer individually beats a group rule**, in both directions.
If you write a specific rule, it is because you meant something specific.

**Groups do not relax the default.** A peer no rule names is still refused.

## `peers`

Manually configured WireGuard peers, for a tunnel set up without Nostr at all.

| Field | What it does |
|---|---|
| `name` | A label. |
| `public_key` | Their **WireGuard** public key, base64 — not their Nostr key. |
| `endpoint` | `host:port` where they can be reached. |
| `overlay_address` | Their address inside the tunnel. |
| `allowed_ips` | What you route to them. A default route is refused here. |
| `keepalive` | Nanoseconds between keepalives. `25000000000` is 25 seconds. |

This is the mode that needs no relays, no identity exchange and no signalling.
It keeps working exactly as it always has.

## `network`

Optional. Derives this node's address from a signed network manifest instead of
`node.overlay_address`.

| Field | What it does |
|---|---|
| `manifest` | Path to the manifest file. |
| `issuer` | The Nostr key you pin as its author, hex. |
| `salt` | The network's secret, hex. Without it no address can be derived. |
| `subnet` | Which subnet of the network this node sits in. Defaults to the first. |

**Leaving this out is normal.** A node without it uses
`node.overlay_address`, which is what every deployment did before manifests
existed.

**A manifest that is configured but cannot be loaded is an error**, not a quiet
fall back to the manual address. An operator who configured one and silently got
the other has a node that is not on the network they think it is.

## `routes`

Optional. What this node offers to reach on behalf of others.

| Field | Default | What it does |
|---|---|---|
| `advertise` | empty | Prefixes this node offers to route, in CIDR. |
| `metric` | `0` | Your claim about your own cost to those prefixes. A receiver treats it as one input among several. |

**Empty by default, and deliberately not derived from your interfaces.** A node
that announced whatever it happened to see would offer its own LAN to strangers
without anybody asking for it.

Announcing a prefix is not the same as being able to route it. The far side must
also forward:

```bash
sysctl -w net.ipv4.ip_forward=1
```

NostMesh does not set that. It is global host state, and turning it on is the
operator's decision.

`nostmesh doctor` checks whether the prefixes you advertise would be refused by
every receiver — a martian, a default route, or something covering your own
addresses.

---

## What is refused, and why

Some things are rejected no matter what the file says:

- **A default route in `allowed_ips`.** It captures everything, including the
  tunnel's own transport, which is a loop. Internet exit is a separate feature
  with its own consent.
- **Two peers with the same public key.** One grant per identity.
- **An action outside `session`, `route`, `transit`.** Silently dropping an
  unknown one would produce a narrower grant than you wrote.
- **A group prefix that is not valid CIDR**, caught by `config validate` rather
  than at reload.
- **`default_action` other than `deny`.**

## Checking your file

```bash
nostmesh config validate /etc/nostmesh/nostmesh.json
```

It reports **every** problem it finds, not the first, and names the field:

```
policy.groups[0].allowed_ips[2]: must be a CIDR prefix such as 10.0.0.0/24, got "10.0.0.0"
```
