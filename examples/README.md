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

### What the unit assumes

- **`CAP_NET_ADMIN` and nothing else.** Configuring an interface, its peers and
  its routes needs that capability; running as root would grant the rest for no
  reason.
- **The state directory holds the private key**, so it is `0700` and owned by the
  service user. Core dumps are disabled: a key that cannot be dumped cannot be
  read out of a dump.
- **One node per host.** `listen_port` is a single value and the interface name is
  fixed, so two instances on one host would contend for both.
