# Tutorial: a manual tunnel between two Linux hosts

This walks through MVP 0: two hosts, configured by hand, establishing a
WireGuard tunnel through NostMesh. No Nostr, no NAT traversal, no discovery —
those arrive in MVP 1. What this proves is that the foundation works.

By the end you will have a tunnel carrying real traffic, and you will have seen
it torn down cleanly.

## What you need

On both hosts:

- Linux with the `wireguard` kernel module
- `CAP_NET_ADMIN` (running as root is the simplest way)
- the `nostmesh` binary
- a network path between them — the tunnel runs over it

You do **not** need `wg`, `wg-quick` or `ip` installed. NostMesh talks to the
kernel directly.

Check the module:

```bash
sudo modprobe wireguard
lsmod | grep wireguard
```

## The shape of it

```text
   host A                                     host B
   198.51.100.1                               198.51.100.2
        │                                          │
        │◄──────── WireGuard over UDP ────────────►│
        │                                          │
   nm0: 100.96.0.1/32                     nm0: 100.96.0.2/32
```

Two address spaces are in play, and conflating them is the usual source of
confusion:

- **Transport addresses** (`198.51.100.x`) are how the hosts reach each other on
  the existing network. The tunnel runs *over* these.
- **Overlay addresses** (`100.96.0.x`) exist only inside the tunnel. This is
  what your traffic uses once the tunnel is up.

## Step 1: configuration on host A

```bash
sudo mkdir -p /var/lib/nostmesh
cat > /etc/nostmesh.json <<'JSON'
{
  "node": {
    "name": "host-a",
    "state_dir": "/var/lib/nostmesh",
    "overlay_address": "100.96.0.1/32",
    "listen_port": 51820,
    "mtu": 1420
  }
}
JSON

nostmesh config validate /etc/nostmesh.json
```

Validation reports every problem at once, naming the field and what it expects.
Fix them in one pass rather than one run per error.

## Step 2: identity on both hosts

```bash
sudo nostmesh identity init --state-dir /var/lib/nostmesh
```

This generates the node's durable identity and stores it owner-only. It warns
that the file keystore is for development — that warning is accurate, and a
production deployment should use an external signer.

> The Nostr public key shown is currently a development placeholder, not a real
> secp256k1 key. See [NM-07](adr/NM-07-deferred-nostr-key-derivation.md). It
> does not affect the tunnel, which uses separate WireGuard keys.

## Step 3: exchange WireGuard public keys

Each host needs the other's tunnel public key. NostMesh generates one per
interface when the tunnel comes up, so bring it up once on each side to obtain
it:

```bash
sudo nostmesh up --config /etc/nostmesh.json --dry-run
```

Then read the key the kernel assigned after a real `up`, via `status`. In MVP 0
this exchange is manual — automating it is precisely what the Nostr control
plane in MVP 1 is for.

## Step 4: add each other as peers

On host A, describing host B:

```bash
sudo nostmesh peer add \
  --config /etc/nostmesh.json \
  --name host-b \
  --public-key '<host B tunnel public key>' \
  --endpoint 198.51.100.2:51820 \
  --overlay-address 100.96.0.2/32 \
  --allowed-ips 100.96.0.2/32 \
  --keepalive 25s
```

And the mirror image on host B.

**`--allowed-ips` is local policy, not a request.** It decides what this node
routes to that peer. It is never taken from what the peer claims, and a default
route (`0.0.0.0/0`) is refused here: that is a transit service with explicit
consent, which arrives in MVP 4.

## Step 5: bring it up

```bash
sudo nostmesh up --config /etc/nostmesh.json
```

Preview first if you like — `--dry-run` describes every change and needs no
privileges, because it touches nothing:

```
dry run: no changes will be applied

  create create_interface: wireguard interface nm0
  create configure_interface: listen port 51820, MTU 1420
  create set_link_up: bring nm0 up
  create apply_peer: peer host-b with 1 allowed prefix(es)

4 operation(s) would be applied
```

Either the whole plan applies or the host is left exactly as it was found. There
is no partial state to clean up by hand.

## Step 6: confirm it works

```bash
sudo nostmesh status --config /etc/nostmesh.json
```

`status` shows configured intent beside what the kernel actually reports. The
gap between them is the useful part — a peer that is configured but has no
handshake tells you the tunnel is set up but not working:

```
node:      host-a
interface: nm0
state:     up

configured peers: 1
  host-b
    endpoint:    198.51.100.2:51820
    allowed ips: 100.96.0.2/32
    observed:    handshake 3s ago, rx 592, tx 736

observed: MTU 1420, listen port 51820

journal: no interrupted transactions
```

Then send real traffic:

```bash
ping -c 3 100.96.0.2
ssh user@100.96.0.2
```

## Step 7: when it does not work

```bash
sudo nostmesh doctor --config /etc/nostmesh.json
```

`doctor` changes nothing and its output carries no key material, so it is safe
to paste into an issue:

```
✓ configuration          /etc/nostmesh.json
✓ state directory        /var/lib/nostmesh
✓ identity               c05c8f12
✓ journal                no interrupted transactions
✓ peers                  1 configured
✓ wireguard              control socket available
✓ interface nm0          up, MTU 1420, 1 peer(s)
! handshakes             no peer has completed a handshake; check endpoint
                         reachability and UDP connectivity
```

Common causes, in the order worth checking:

| Symptom | Usually |
|---|---|
| No handshake | UDP blocked between the hosts, or the wrong endpoint |
| `control socket available` fails | The `wireguard` module is not loaded, or no `CAP_NET_ADMIN` |
| Interface up, no traffic | `--allowed-ips` does not cover the address you are sending to |
| Interrupted transaction | A previous run died; `nostmesh down` reconciles it |

## Step 8: tear it down

```bash
sudo nostmesh down --config /etc/nostmesh.json
```

This removes what NostMesh applied and nothing else. Other WireGuard interfaces
on the host are left alone — ownership is verified before every removal, and
NostMesh only owns interfaces it created with the `nm` prefix.

## What this does not do

MVP 0 deliberately stops here. There is no discovery, no NAT traversal, no relay
fallback, no route advertisement, and no transit. Public keys and endpoints are
exchanged by hand.

That is the point of the milestone: the WireGuard foundation, the transactional
guarantees and the ownership rules are all provable before anything is built on
them.

## Verifying the guarantees yourself

The repository's privileged test suite builds two network namespaces joined by a
veth pair, establishes a real tunnel between them, and proves ICMP and TCP flow
both ways:

```bash
sudo modprobe wireguard
make docker-test-privileged
```

See [development.md](development.md) for what those tests need.
