# Example configuration

`nostmesh.json` is a complete, valid configuration for one node with a single
peer. Validate it directly:

```bash
nostmesh config validate examples/nostmesh.json
```

## What to change

| Field | Replace with |
|---|---|
| `node.name` | A label for this node |
| `node.state_dir` | An absolute path this user owns |
| `node.overlay_address` | This node's address inside the tunnel |
| `node.listen_port` | The UDP port to bind; zero lets the kernel choose |
| `peers[].public_key` | The WireGuard public key the other node reports |
| `peers[].endpoint` | Where to reach that node on the underlying network |
| `peers[].allowed_ips` | The prefixes this node routes to that peer |

> The public key in the example is the byte sequence 0–31 encoded as base64. It
> is valid in form and meaningless in practice, so the file validates without
> anyone mistaking it for a real key.

## Two address spaces

Conflating these is the usual source of confusion:

- **`endpoint`** is a transport address — how the two hosts reach each other on
  the network that already exists. The tunnel runs *over* it.
- **`overlay_address` and `allowed_ips`** exist only inside the tunnel.

## AllowedIPs is policy

`allowed_ips` decides what traffic this node routes to a peer. It is local
intent, never taken from what the peer claims, and a default route is refused
here — that is a transit service with explicit consent, arriving in MVP 4.

See the [manual tunnel tutorial](../docs/tutorial-manual-tunnel.md) for a full
walk-through.

## The default route is a question, never an answer

`accept_default_route` is `false`, and a peer announcing `0.0.0.0/0` or `::/0`
is refused. Such a route captures all traffic — including this node's own
transport to the peer carrying it — so installing one silently is how a node
loses the connection it was installed over.

Setting it to `true` does **not** accept a default route. It changes the answer
from "no" to "ask a person": policy returns `require_confirmation`, which is not
permission and never becomes permission on its own. Nothing a peer sends can
change the setting.

Routes themselves arrive in M2.4; today this decides, and
[NM-09](../docs/adr/NM-09-routes-follow-allowed-ips.md) keeps the adapter
refusing a default route outright regardless.

## Authorizing several identities at once

`policy.groups` authorizes every identity it names with one rule. It exists for
the case where a set of peers is trusted the same way — a person's own devices,
most obviously — and writing the tenth rule adds no intent the first did not
already carry.

```json
"groups": [
  {
    "name": "my-devices",
    "members": ["<hex Nostr public key>", "..."],
    "actions": ["session"],
    "allowed_ips": ["100.96.0.0/24"]
  }
]
```

**This does not relax the default.** A peer no rule names is still refused, and a
group is a shorter way to say who is trusted rather than a way to skip saying it.
A rule written for one peer by name wins over a group in both directions, so
revoking a peer individually holds even when a group would allow it.

The member key in `nostmesh.json` is synthetic, like the peer public key above.

Members are listed in the file today. [NM-24](../docs/adr/NM-24-policy-decisions-carry-limits.md)
describes a group as the membership of a signed network manifest, so that adding
a device to the manifest extends a rule already written; that arrives with the
manifest itself.

## Running as a service

`nostmesh.service` is a systemd unit for `nostmesh serve`, the long-running form
that holds a session with every authorized peer. Install it:

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin nostmesh
sudo install -m 0755 nostmesh /usr/local/bin/nostmesh
sudo install -m 0644 examples/nostmesh.service /etc/systemd/system/
sudo install -d -m 0700 -o nostmesh -g nostmesh /etc/nostmesh
sudo install -m 0600 -o nostmesh -g nostmesh nostmesh.json /etc/nostmesh/
sudo systemctl daemon-reload
sudo systemctl enable --now nostmesh
```

The `wireguard` module must be loaded before the service starts. The unit asks
for it, and a node that reboots wants it made permanent:

```bash
echo wireguard | sudo tee /etc/modules-load.d/wireguard.conf
```

### Changing the allowlist without dropping tunnels

Authorizing or revoking a peer takes effect on `SIGHUP`, and sessions that did
not change are left alone:

```bash
sudo systemctl reload nostmesh
```

Node settings — `listen_port`, `relays`, `state_dir` — are not reloadable. The
service reports that it kept the running values rather than appearing to apply
new ones; a restart is what puts them into effect.

### Watching it

```bash
nostmesh state --config /etc/nostmesh/nostmesh.json   # live phase per peer
journalctl -u nostmesh -f                             # what happened and why
```

`state` reads a read-only Unix socket in the state directory. It reports what the
service intends — phase, attempts, how long, the last failure, and the age of the
data-plane handshake. `nostmesh status` reads the kernel instead, which is the
right question when the two disagree.

### Keeping a copy on disk

Logs always reach the journal: the service writes to stderr and the unit captures
it. Setting `log.file` adds a copy for an operator who wants one that outlives
journald's retention, or who runs the binary without a supervisor at all.

```json
"log": { "level": "info", "format": "json", "file": "/var/log/nostmesh/nostmesh.log" }
```

Under the packaged unit the file must live in `/var/log/nostmesh`, which
`LogsDirectory=` creates and `ProtectSystem=strict` makes the only writable place
for it. It is written `0600`, and a path the service cannot open stops it from
starting rather than leaving an audit trail that was never written.

NostMesh does not rotate the file. Install `nostmesh.logrotate` as
`/etc/logrotate.d/nostmesh`; it uses `copytruncate`, because the service holds
the file open and a rename would leave it writing to a rotated copy nobody reads.

`level` accepts `debug`, `info`, `warn` and `error`. At `info` an idle node is
silent and each line is a state change worth reading. `debug` is verbose enough
to follow a negotiation message by message, which is what it is for.

### What the unit assumes

- **`CAP_NET_ADMIN` and nothing else.** Configuring an interface, its peers and
  its routes needs that capability; running as root would grant the rest for no
  reason.
- **The state directory holds the private key**, so it is `0700` and owned by the
  service user. Core dumps are disabled: a key that cannot be dumped cannot be
  read out of a dump.
- **One node per host.** `listen_port` is a single value and the interface name is
  fixed, so two instances on one host would contend for both.
