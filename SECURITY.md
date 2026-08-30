# Security policy

## Status

**NostMesh has not been audited and is in early development.** Do not use it to
protect anything that matters. The protocol is experimental, the implementation
is incomplete, and no claim of anonymity or security should be inferred from the
design documents.

## Reporting a vulnerability

Please do not open a public issue for a security problem.

Report privately through
[GitHub Security Advisories](https://github.com/luizosorio/nostmesh/security/advisories/new),
which allows a fix to be prepared before the details become public.

Useful reports include: what the problem is, how to reproduce it, which
component and version are affected, and what an attacker gains. A proof of
concept helps but is not required.

You can expect an acknowledgement within a week. Since this is a small project
without a dedicated security team, please be patient about timelines, and let us
know if you plan to disclose publicly so the fix can be coordinated.

## Scope

In scope: anything that breaks one of the invariants below, or that lets a
remote party affect a node beyond what local policy authorized.

Out of scope: findings that require an attacker to already control the host or
the user's keys; denial of service through raw resource exhaustion against
public relays; and issues in third-party Nostr relays, STUN servers or exit
providers, which the threat model already treats as untrusted.

## Invariants

A violation of any of these is a security bug:

- The WireGuard private key leaves the node that generated it — appearing in an
  event, log, network journal or diagnostic bundle.
- Nostr and WireGuard keys share secret material.
- A remote field configures the kernel directly, without passing through local
  policy: `AllowedIPs`, routes, DNS, forwarding, NAT or firewall rules.
- A policy decision defaults to allow.
- A network change cannot be rolled back, or removes state NostMesh does not
  own.
- An unverified third-party candidate produces a network effect.
- Enabling one auxiliary role (Nostr relay, STUN observer, data relay, exit
  provider) implicitly grants another.
- A secret appears in logs, metrics or an exported diagnostic bundle.

## What this project does not promise

- **It is not Tor.** No layered circuits, no protection against traffic
  correlation by a global observer.
- **An exit provider is not anonymity.** The provider sees destinations, timing
  and volume, and can read traffic that is not end-to-end encrypted. Use TLS.
- **Metadata is visible.** Nostr relays, STUN observers, data relays and peers
  each observe a different part of the communication. This is documented, not
  solved.
- **Running an exit node carries legal risk.** The software does not shield an
  operator from responsibility for traffic they forward.
