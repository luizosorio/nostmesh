# Security model

What NostMesh defends against, what it does not, and why. Written so that
someone deciding whether to deploy it can tell the difference between a property
the design guarantees and one it merely has not broken yet.

**NostMesh has not been audited and is in early development.** Everything below
describes intent and implementation, not assurance.

## The shape of the system

Two planes, deliberately separate:

**The control plane** runs over Nostr relays. Nodes find each other, exchange
encrypted signalling, and agree on parameters. Relays are untrusted
infrastructure: they see who talks to whom and when, and they can drop, delay,
reorder or replay anything.

**The data plane** is the kernel's WireGuard. Traffic never passes through a
relay, and a relay never holds a key that could read it.

The separation is what bounds the damage a relay can do. A hostile relay can
stop a session from forming; it cannot read one that has.

## What an attacker gets from each position

### A relay operator

**Sees:** which identities exchange messages, when, how often, and how large each
message is. Every node using that relay is visible to it.

**Can:** drop messages, delay them, reorder them, deliver them twice, or replay
old ones. A node configured with one relay can be silenced by it.

**Cannot:** read the payload, learn a WireGuard private key, or make a node
install a route or accept a peer. Every message is encrypted, and every effect on
the host is decided by local policy.

**Mitigated by:** several relays, so one cannot silence a node; a session id
bound after the first message, so a replay of a closed session is refused; and a
record of answered sessions that survives a restart, so a node does not answer
its own retained events again.

**Not mitigated:** the metadata. A relay knows the shape of your mesh. Using
several relays spreads that knowledge rather than removing it.

### A peer you authorized

**Sees:** your node's overlay address, the prefixes you route to it, and the
endpoints your candidates disclose.

**Can:** propose anything — routes, addresses, capabilities. It can also stop
answering, which ends the session.

**Cannot:** configure your host. `AllowedIPs`, routes, DNS, forwarding and
firewall rules are derived from your policy; a proposal is an input to a
decision, never the decision. A peer announcing `0.0.0.0/0`, your own LAN, or a
prefix covering your tunnel's transport is refused before policy is consulted.

**Mitigated by:** deny-by-default, per-prefix authorization, and the refusals
listed in [NM-25](adr/NM-25-route-announcements.md).

**Not mitigated:** a peer you authorized for a prefix can route that prefix. The
grant is the trust decision; nothing after it re-examines whether you meant it.

### Someone who steals a Nostr private key

**Gets:** the ability to impersonate that identity — to open sessions as it, and
to be treated as it by every node that authorized it.

**Cannot:** read past traffic. WireGuard keys are ephemeral per session and never
transmitted, so a stolen Nostr key does not decrypt a tunnel that has closed.

**Can, however:** decrypt retained *signalling* if a relay still holds it. NIP-44
has no forward secrecy, so historical envelopes readable to that key reveal
endpoints, candidates and **public** WireGuard keys — never a private one. See
[NM-10](adr/NM-10-nostr-cryptography.md).

**Mitigated by:** short validity windows, minimal metadata, and ephemeral tunnel
keys.

**Not mitigated:** revocation is not instantaneous. Every node that authorized
the identity keeps doing so until its operator removes it.

### Someone with local access to a node

**Gets:** whatever the file permissions allow. The state directory holds this
node's Nostr private key, and the development keystore stores it **unencrypted**.

**Mitigated by:** the state directory is 0700 and owned by the service account;
the process runs with `CAP_NET_ADMIN` and nothing else, cannot dump core, and is
confined by the systemd unit's sandboxing.

**Not mitigated:** local root reads the key. The interface for an external signer
exists; no backend implements it yet.

### A STUN observer

**Sees:** your address and port, and that you asked.

**Can:** lie about what it saw.

**Cannot:** make you send anything anywhere. A reported address stays
`UNVERIFIED` until an authenticated probe succeeds at that exact address and
port, and loopback, multicast and link-local answers are refused outright.

**Mitigated by:** several observers, so one lying is visible as disagreement.

**Not mitigated:** a node configured with one observer cannot detect a lie, and
now says so.

## Properties the design holds to

These are invariants, not goals. A change that weakens one is a change to the
security model and needs an ADR.

- **The WireGuard private key never leaves the node that generated it** — not in
  an event, a log, the network journal, or a diagnostic bundle. Enforced by the
  type system and an architecture test.
- **Nostr and WireGuard keys never share secret material.**
- **Nothing a peer sends configures the kernel.** Every effect is derived from
  local policy.
- **Deny by default**, in every decision, including for a group rule.
- **Network changes are transactional and reversible**, and nothing removes a
  rule, route or interface it does not own.
- **No secret, key or mandatory endpoint is hardcoded**, and no key is committed.
- **Auxiliary roles are independent.** Enabling a relay role never grants an exit
  role.

## What is not defended against

Stated plainly, because a model that lists only its strengths is marketing.

- **Traffic analysis.** A relay sees timing and volume. Nothing pads or delays.
- **A compromised host.** If an attacker runs code as the service account, the
  node is theirs.
- **A malicious authorized peer within its grant.** You decided to trust it.
- **Denial of service.** A relay can refuse you; a peer can stop answering; a
  network can drop packets. Availability is not a cryptographic property.
- **Anonymity.** NostMesh is not an anonymity network and does not try to be.
  Your relays know your identity's traffic pattern.
- **Forward secrecy in signalling.** Recorded in NM-10 as a known limitation.

## Reporting

See [SECURITY.md](../SECURITY.md).
