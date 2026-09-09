# Example configurations

Working files for common setups. Every one of these validates:

```bash
nostmesh config validate personal-mesh.json
```

Copy the closest one, replace the keys with your own, and check it before
starting the service.

**The keys in these files are made up.** Replace every `public_key` and every
`members` entry with real ones — `nostmesh identity init` prints yours, and each
peer gives you theirs.

## Which one you want

| File | For |
|---|---|
| [`personal-mesh.json`](personal-mesh.json) | Your own machines, nothing shared |
| [`shared-with-a-friend.json`](shared-with-a-friend.json) | Your machines, plus one person reaching one of them |
| [`subnet-router.json`](subnet-router.json) | A machine offering its LAN to the mesh |
| [`reaching-a-subnet.json`](reaching-a-subnet.json) | The other side of that — reaching somebody's LAN |
| [`team-with-groups.json`](team-with-groups.json) | Several people, grouped by what they do |
| [`manual-tunnel.json`](manual-tunnel.json) | A tunnel with no Nostr at all |

## What each one shows

### `personal-mesh.json`

The common case. One group rule covers every machine you own, so adding a
fourth means adding one key rather than writing another rule.

### `shared-with-a-friend.json`

Your devices in a group, one person named individually. The two differ on
purpose: your machines route the whole overlay, theirs routes one address.

A rule naming a peer individually **beats** a group rule. That is also how you
would make an exception for somebody who is in a group.

### `subnet-router.json`

A machine that offers `192.168.1.0/24` — its own LAN — to the mesh.

Announcing is not the same as forwarding. The machine also needs:

```bash
sudo sysctl -w net.ipv4.ip_forward=1
echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/99-nostmesh.conf
```

NostMesh does not set that. It is global host state, and turning it on is your
decision.

### `reaching-a-subnet.json`

The other end. The gateway is authorized for `route` as well as `session`, and
`allowed_ips` lists the subnet you are willing to accept from it.

**Both halves are needed.** Their announcement is a proposal; your `allowed_ips`
is the answer. Leave the subnet out and the announcement arrives and is refused.

### `team-with-groups.json`

Two groups for two purposes, and one revoked peer.

Revoking keeps the record instead of deleting the line, so a year later you can
see somebody was removed deliberately rather than never added.

### `manual-tunnel.json`

No relays, no identity exchange, no signalling — a static WireGuard peer with a
known endpoint and key.

This mode still works and is not going away. It is what you want on a lab
network, or between two machines whose addresses never change.

## Two things worth knowing

**Nothing is authorized by default.** A node with an empty policy connects to
nobody. That is intentional: a valid signature proves who is asking, not that
they may.

**Comments are not allowed.** The configuration rejects any field it does not
recognise, including `_comment`, so a typo in a security setting fails loudly
instead of leaving it at a default. The explanations live here rather than in
the files.

## Also here

- [`../nostmesh.service`](../nostmesh.service) — systemd unit
- [`../nostmesh.logrotate`](../nostmesh.logrotate) — for the optional log file
- [`../../docs/configuration.md`](../../docs/configuration.md) — every setting
- [`../../docs/troubleshooting.md`](../../docs/troubleshooting.md) — when it does not work
