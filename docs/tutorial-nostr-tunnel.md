# Tutorial: a tunnel negotiated over Nostr

This covers MVP 1: two hosts that know each other's Nostr identity, negotiating
a WireGuard tunnel through relays and connecting directly — including across
NAT.

The difference from [the manual tunnel](tutorial-manual-tunnel.md) is that
nothing is exchanged by hand. No copying public keys, no configuring endpoints.
The hosts find each other through relays neither of them operates.

> **Experimental.** The protocol claims no NIP number and has not been audited.
> Read the [known limits](#known-limits) before relying on any of it.

## What actually happens

```text
   host A                    Nostr relays                    host B
      │                    (control plane)                      │
      │──── session.request ────►│────────────────────────────►│
      │◄────────────────────────│◄──── session.offer ──────────│
      │──── session.accept ─────►│────────────────────────────►│
      │                          │                              │
      │◄═══ authenticated connectivity checks (UDP, direct) ═══►│
      │                                                          │
      │◄═══════════ WireGuard tunnel, direct ═══════════════════►│
```

Relays carry **signalling only**. Once the tunnel is up they are not involved,
and no user traffic ever passes through them.

## What you need

On both hosts:

- Linux with the `wireguard` kernel module
- `CAP_NET_ADMIN`
- the `nostmesh` binary
- outbound UDP

You do **not** need a public IP on either side. That is the point of the
connectivity checks.

## Step 1: identity

```bash
sudo nostmesh identity init --state-dir /var/lib/nostmesh
sudo nostmesh identity show --state-dir /var/lib/nostmesh
```

The public key it prints is how the other host will name you. It is a real
secp256k1 key: exchange it however you like — the protocol assumes you already
know who you want to talk to.

## Step 2: configuration

```bash
cat > /etc/nostmesh.json <<'JSON'
{
  "node": {
    "name": "host-a",
    "state_dir": "/var/lib/nostmesh",
    "overlay_address": "100.96.0.1/32",
    "listen_port": 51820,
    "mtu": 1420,
    "relays": [
      "wss://relay-one.example",
      "wss://relay-two.example",
      "wss://relay-three.example"
    ],
    "observers": ["stun.example:3478"]
  },
  "policy": {
    "default_action": "deny",
    "max_sessions": 64,
    "authorized_peers": [
      {
        "public_key": "<host B's Nostr public key>",
        "alias": "host-b",
        "actions": ["session"]
      }
    ]
  }
}
JSON

nostmesh config validate /etc/nostmesh.json
```

### Why three relays

Relays are untrusted for availability. They drop events, go down, and sometimes
accept an event and quietly discard it. Three means one failing does not stop
signalling — and `doctor` warns if you configure fewer.

### `authorized_peers` is the whole authorization surface

Local policy **denies by default**. A peer absent from this list cannot open a
session, whatever it sends and however valid its signature. A signature proves
who is asking, not that they may.

`actions` is deliberately granular: a peer trusted to open a tunnel is not
thereby trusted to announce routes into your network. MVP 1 only uses
`session`.

### Observers are consulted last

Discovery tries local interfaces, then a static endpoint, then the router, then
recent endpoints, and only then a STUN observer. A host with a routable address
**never contacts an observer**, so no third party learns it exists.

## Step 3: run the service on both hosts

```bash
sudo nostmesh serve --config /etc/nostmesh.json
```

Run it on **both** hosts. Either side may open a session at any time, and the
other has to be ready to answer — which is why this is a service rather than a
command that connects once and returns. Which end opens is settled from the two
Nostr keys, so both reach the same answer without exchanging a message.

Both sides need each other authorized. If B has not authorized A, the handshake
is refused at B — with no state created and nothing applied to either kernel.

It runs in the foreground here so you can watch it. On a node that should stay
reachable, run it under systemd: see `examples/nostmesh.service`.

Once a session is up, the service **holds** it and reconnects if it drops. There
is no step to keep it alive.

## Step 4: check

```bash
nostmesh state --config /etc/nostmesh.json
sudo nostmesh status --config /etc/nostmesh.json
```

`state` asks the running service what it is doing:

```
PEER                 SHORT      PHASE          ATTEMPTS  SINCE                  HANDSHAKE
host-b               a1cebb55   established           2  2026-09-01T12:24:20Z   55s ago
```

`HANDSHAKE` is the age of the last data-plane handshake. A live tunnel refreshes
it every couple of minutes on its own, so a number that keeps growing is the
session dying.

`status` shows what is configured beside what the kernel reports. The gap is the
useful part: a peer configured with no handshake means the tunnel is set up and
not working.

## Step 5: when it does not work

```bash
sudo nostmesh doctor --config /etc/nostmesh.json
```

```
✓ configuration          /etc/nostmesh.json
✓ state directory        /var/lib/nostmesh
✓ identity               3f9d015d
✓ journal                no interrupted transactions
✓ authorized peers       1 authorized
✓ relays                 3 configured
✓ wireguard              control socket available
! interface nm0          not present; run 'nostmesh up' to bring the tunnel up
```

`doctor` changes nothing and its output carries no key material, so it is safe
to paste into an issue.

Common causes:

| Symptom | Usually |
|---|---|
| Peer refused | Not in `authorized_peers` on the *other* host |
| No candidate verified | UDP blocked, or both sides behind symmetric NAT |
| Relay warnings | Fewer than three relays, or all unreachable |
| Handshake but no traffic | `allowed_ips` does not cover what you are sending |

### Symmetric NAT

If both hosts are behind symmetric NAT, a direct path may be impossible. Each
NAT produces a different mapping per destination, so the address an observer
reports is not the one the peer would reach.

MVP 1 fails clearly in this case rather than retrying forever. The data relay
that handles it is MVP 3.

## Roaming

If a host's address changes — a laptop moving networks, a NAT rebinding — the
session survives. The endpoint is updated after the new address is verified, and
**the session identity, its authorization and its keys do not change**: a peer
that moved is the same peer.

An unverified address is never accepted for roaming. Otherwise anyone able to
forge a packet could redirect an established tunnel.

## Known limits

**Not audited.** Experimental protocol, no independent review.

**No forward secrecy.** NIP-44 derives its key from the two long-term
identities, so a compromised Nostr private key allows decryption of signalling a
relay retained — revealing endpoints, candidates and historical *public*
WireGuard keys. It does not reveal any WireGuard private key, which is never
transmitted. See [NM-10](adr/NM-10-nostr-cryptography.md).

**Relays see metadata.** Which pubkeys exchange messages, when, and how often.
Connecting to relays over Tor reduces IP exposure but does not hide the pubkeys.

**No relay fallback.** If no direct path exists, the connection fails. MVP 3
adds the data relay.

**No mesh.** One session at a time per peer, no route announcements, no transit.
Those are MVP 2 and MVP 4.

**Linux only.** The core compiles for Windows and macOS; no adapter exists.

**PCP and NAT-PMP are not implemented.** They report as unimplemented rather
than silently contributing nothing.

## Verifying it yourself

```bash
sudo modprobe wireguard
make docker-check              # unit and integration suites
go test ./test/e2e/            # the 100-connection gate
make docker-test-privileged    # kernel tests in network namespaces
```

The end-to-end suite uses simulated relays deliberately: the acceptance criteria
require a relay that drops, duplicates and reorders on demand, and no real
server does that. Testing against public relays would also make the suite depend
on infrastructure nobody here controls.
