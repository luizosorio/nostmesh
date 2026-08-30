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
