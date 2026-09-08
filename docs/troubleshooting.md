# Troubleshooting

Symptoms, in the order an operator meets them, with the command that answers
each. Every diagnosis here comes from output the node already produces.

Start with:

```bash
nostmesh doctor --config /etc/nostmesh/nostmesh.json
```

It checks the prerequisites a working tunnel depends on and names the ones that
are missing. Most of what follows is for when `doctor` is clean and something
still does not work.

## The service will not start

**`status=217/USER`** — the `nostmesh` account does not exist. The packages
create it; a manual install does not:

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin nostmesh
```

**`ConfigurationDirectory ... mode is different`** — `/etc/nostmesh` is not
`0755`. systemd manages that directory and refuses a mode it did not set:

```bash
sudo chmod 0755 /etc/nostmesh
```

The configuration file inside it stays `0600` and owned by the service account.

**`no identity found`** — the node has no key yet:

```bash
sudo -u nostmesh nostmesh identity init --state-dir /var/lib/nostmesh
```

As root, `sudo -u` fails; use `runuser -u nostmesh -- nostmesh ...` instead.

## No peer ever connects

```bash
nostmesh state --config /etc/nostmesh/nostmesh.json
```

This asks the running service, so it shows what is being attempted and why the
last attempt failed. If it says no service is running, use `nostmesh status`,
which reads the kernel and works without one.

**Every peer says `no_rule`** — nothing is authorized. Local policy denies by
default, so a node with an empty allowlist connects to nobody. To see exactly
what policy concludes about one peer:

```bash
nostmesh policy explain --config /etc/nostmesh/nostmesh.json --peer <hex pubkey>
```

The distinction that matters: `rule: none matched` means nothing authorizes the
peer and a rule has to be written. A named rule with `action_not_permitted`
means the rule exists and has to be widened.

**`unauthorized`** — the peer is in the allowlist but revoked, or authorized for
a different action.

## A peer negotiates but never establishes

**`no candidate could be verified`** — the two nodes exchanged signalling and
neither could reach the other. Look at how many candidates were found:

```bash
journalctl -u nostmesh -f | grep candidate.gather.done
```

**One candidate**, on a node behind NAT, means only one observer answered. A
single observer cannot detect a public address that changes between sessions,
and the node now says so at startup. Configure several.

**`nothing arrived on the probe socket`** — the address was reachable in theory
and nothing came back. Both nodes behind symmetric NAT cannot connect directly;
that needs a data relay, which is MVP 3.

## The tunnel is up but carries nothing

`nostmesh status` reports what the kernel holds:

```
interface: nm-a1b2c3d4 (MTU 1420, listen port 51820)
  route:   10.20.30.0/24
```

**No `route:` lines** — nothing was installed. Either no peer announced a prefix,
or every announcement was refused. `nostmesh state` shows the routing table the
node decided on; if a prefix appears there and not in `status`, the decision was
made and the installation failed.

**Traffic to a subnet does not pass** — check that the *far* node forwards:

```bash
sysctl net.ipv4.ip_forward
```

NostMesh does not set it. It is global host state, and enabling it is the
operator's decision.

## Routes appear and disappear

Announcements carry a validity and are refreshed while the session holds. A route
that lapses means the announcements stopped arriving — the provider stopped, or
the control plane cannot reach it. `nostmesh state` shows each route's expiry.

## Two peers claim the same subnet

Only one route per destination is installed; the other is recorded and reported:

```bash
nostmesh state --config /etc/nostmesh/nostmesh.json --json | jq .conflicts
```

This is not an error. It says two providers offered the same prefix and which
one won.

## A restart lost something

Routes are **not** restored from disk, deliberately: an announcement has a
validity, and reinstalling one nobody has reaffirmed would route to a
destination that may be gone. A restarted node relearns from the peers that are
still announcing.

Interfaces left by a previous run are removed at startup, and their routes go
with them.

## Reading the logs

```bash
journalctl -u nostmesh -f
```

Every line carries an `event` from a closed vocabulary, so a symptom can be
grepped:

| Event | Means |
|---|---|
| `peer.added` | a worker started for a peer, with the rule that authorized it |
| `candidate.gather.done` | discovery finished, with how many candidates |
| `route.offered` / `route.refused` | an announcement was accepted or declined |
| `route.installed` / `route.withdrawn` | the kernel's table changed |
| `session.expired` | a negotiation ended without establishing |

For more detail, set `log.level` to `debug` in the configuration and reload with
`systemctl reload nostmesh`. Debug output includes addresses, which is why it is
not the default.

## Reporting a problem

`nostmesh doctor` output is safe to paste: it carries no key material. So is
anything from `nostmesh state` and `nostmesh status`.

For a suspected security problem, see [SECURITY.md](../SECURITY.md) rather than
opening an issue.
