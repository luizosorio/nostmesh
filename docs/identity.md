# Identity: the keys that make a node a node

Every NostMesh node has one durable identity. It is what peers authorize, what
signs everything the node says, and the only thing that makes one node
distinguishable from another.

This explains what that identity is, where it lives, and how to use one you
already have. No cryptography background is assumed.

## Do I need a username and password?

No, and the difference matters.

A Nostr identity is a pair of numbers. One is secret and one is public, and they
are related in a way that lets the secret one prove ownership of the public one
without ever revealing itself.

There is no account. Nobody registers it, no server holds it, and no support
desk can reset it. That is the point — it is what lets two nodes recognise each
other without any company in between — but it has a consequence worth stating
plainly at the start: **if you lose the secret, the identity is gone.** There is
no recovery. If someone else obtains it, they are you, and the only remedy is to
abandon that identity and tell every peer about the new one.

## Where did NostMesh put my keys? They are not in the config file

They are deliberately not in `nostmesh.json`.

Configuration gets copied between machines, pasted into issues, committed to git
and included in backups. All of that is fine for a listen port and a list of
relays. None of it is fine for a private key.

So the key lives in its own file, in the state directory:

```
/var/lib/nostmesh/          <- node.state_dir from the configuration
├── identity.json           <- the key pair, readable only by its owner
├── journal/                <- record of network changes, for recovery
└── control.sock            <- where `nostmesh state` asks a running service
```

`identity.json` looks like this:

```json
{
  "version": 1,
  "public_key": "e0b79f77ccf37fae28edf248e16e6e8aa840fa396d0352473385f4d0f212f297",
  "private_key": "…the secret, 64 hexadecimal characters…",
  "created_at": "2026-09-01T15:04:13Z",
  "warning": "the file keystore stores a private key on disk unprotected and is for development only"
}
```

The configuration file points at the directory; the key never appears in it.

## What happens when I run `identity init`?

```bash
nostmesh identity init --state-dir /var/lib/nostmesh
```

Four things:

**1. It asks the operating system for 32 random bytes.** That is the whole
private key — no password, no passphrase, nothing derived from anything you
typed. It comes from the kernel's cryptographic randomness, the same source
everything else on the machine uses for keys.

**2. It computes the public key from the private one.** This is a multiplication
on a curve called secp256k1. The only property worth understanding: doing the
multiplication is fast, and undoing it is not — not slow, but beyond reach with
any amount of computing anyone has. That asymmetry is the entire basis of the
scheme. Everyone can hold your public key and nobody can work backwards to the
private one.

**3. It keeps 32 of the 64 bytes.** A point on the curve has two coordinates;
Nostr uses only the first. This is why a public key and a private key are the
same length, which is a common and dangerous source of confusion — see below.

**4. It writes the file.** Atomically, so an interrupted write cannot leave a
half-written key, and with mode `0600`, so only the owner can read it.

On every later read, NostMesh checks those permissions again. If the file has
become readable by anyone else, it **refuses to load it** rather than quietly
tightening the mode. Tightening would not un-read whatever had already been read;
refusing tells you that the key must be considered exposed.

## npub, nsec, and the long hexadecimal string

Three ways of writing the same bytes.

| Form | Example | What it is |
|---|---|---|
| `npub1…` | `npub1uzme7a7v7dl6u…` | The **public** key, in the form applications display |
| `nsec1…` | `nsec1…` | The **private** key, in the same form |
| 64 hex characters | `e0b79f77ccf3…` | Either one, with nothing to say which |

The prefixed forms carry two things the raw hexadecimal does not: a label saying
which kind of key it is, and a checksum that catches a mistyped or truncated
value. NostMesh checks that checksum on import, so a key with one character
wrong is refused rather than silently accepted as some other key.

**The `nsec` is the secret.** Anyone holding it is your node. It should never be
pasted into a website, sent to anyone, or typed where it will be recorded.

## I already have a Nostr identity. Can I use it?

Yes.

```bash
nostmesh identity import --state-dir /var/lib/nostmesh
```

The command reads the key from standard input: paste it, then press Ctrl-D. It
accepts an `nsec1…` or 64 hexadecimal characters.

To take it from a file, or from a password manager:

```bash
nostmesh identity import --state-dir /var/lib/nostmesh --from-file ./key.txt
pass show nostr/node | nostmesh identity import --state-dir /var/lib/nostmesh
```

A file must be readable only by its owner — mode `0600` — for the same reason
`identity.json` must be.

**The key is never accepted as a command-line argument.** Anything on a command
line is written to your shell history, is visible in the process list to every
user on the machine, and can be read from `/proc` while the command runs. There
is no flag for it, deliberately.

Note that `echo "nsec1…" | nostmesh identity import` puts the key in your shell
history too. Paste it interactively, or read it from a file or a password
manager.

After importing, check that you got the identity you meant:

```bash
nostmesh identity show --state-dir /var/lib/nostmesh --format npub
```

Compare that against what the application you exported from shows. They must
match exactly.

### Should you reuse a personal identity?

Usually not.

If you import the identity you use for social posts, your node signs its
signalling with the same key you post under. Anyone watching a relay can see
that the person and the node are the same — permanently, since relays keep what
they are given and there is no way to withdraw it.

The one good reason to do it anyway is recognition: if your peers already know
you by that identity, using it means they already know how to authorize you.

Weigh those against each other. Generating a separate identity for a node costs
one command.

### Importing will not replace an existing identity

If the state directory already has one, import refuses. This is not caution for
its own sake: your peers hold your current public key in *their* configuration
files, and replacing it silently would make every one of them stop recognising
this node with no indication of why.

To replace an identity deliberately, move the existing file aside, import, and
then give every peer the new public key.

## What about the WireGuard keys?

Different keys, different job, and they never mix.

The Nostr identity is durable and authorizes sessions. WireGuard keys carry the
traffic, and NostMesh generates **a new pair for every session**. They are never
written to disk, never reused, and never share material with the Nostr key.

Only the WireGuard *public* key is ever transmitted, inside the encrypted
signalling. The private one never leaves the node that generated it — not in an
event, not in a log, not in a diagnostic bundle.

See [NM-06](adr/NM-06-key-separation-and-secret-handling.md) for the rule and
what enforces it.

## What if I lose the key, or someone else gets it?

**Lost.** The identity is gone. Generate a new one and give every peer the new
public key; each of them has to authorize it before the node can connect again.

**Compromised.** Whoever holds it can sign as your node. They can also decrypt
any signalling of yours that relays still hold, because the encryption in use has
no forward secrecy — see [NM-10](adr/NM-10-nostr-cryptography.md). That reveals
endpoints, candidate addresses and the WireGuard *public* keys of past sessions.
It does not reveal a WireGuard private key, since those were never transmitted
and no longer exist.

Either way the procedure is the same: generate a new identity, have every peer
authorize it, and remove the old one from their allowlists.

This is the second reason to think twice about importing a personal identity. A
key that has been on your phone for years, pasted into several applications, has
a wider exposure than one generated on a server for this purpose alone.

## A note on `created_at`

For a generated identity it is when the key was made. For an imported one it is
when it was imported — the original creation date is not something the key
carries, so NostMesh cannot know it. Nothing depends on this field today; it is
worth knowing before reading it as key age.

## Is this how it works in production?

Not yet, and the file says so:

> the file keystore stores a private key on disk unprotected and is for
> development only

The key sits in a file, readable by anything running as that user, present in
backups and snapshots. The intended answer is an external signer that holds the
key and never surrenders it, with NostMesh asking it to sign rather than holding
the key itself. The interface for that already exists; the backend does not.

Until then, treat the state directory as what it is: the one place on the machine
where compromise means impersonation.

## See also

- [Nostr tunnel tutorial](tutorial-nostr-tunnel.md) — establishing a session
- [NM-06](adr/NM-06-key-separation-and-secret-handling.md) — key separation
- [NM-10](adr/NM-10-nostr-cryptography.md) — signatures and encryption
- [NM-12](adr/NM-12-real-key-derivation.md) — how derivation works
