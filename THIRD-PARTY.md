# Third-party licenses

| Module | Version | License |
|---|---|---|
| `golang.org/x/crypto` | v0.55.0 | BSD-3-Clause |
| `golang.org/x/sys` | v0.47.0 | BSD-3-Clause |
| `golang.zx2c4.com/wireguard/wgctrl` | v0.0.0-20241231184526 | MIT |
| `github.com/vishvananda/netlink` | v1.3.1 | Apache-2.0 |
| `github.com/vishvananda/netns` | v0.0.5 | Apache-2.0 |
| `github.com/mdlayher/netlink` | v1.7.2 | MIT |
| `github.com/mdlayher/genetlink` | v1.3.2 | MIT |
| `github.com/mdlayher/socket` | v0.5.1 | MIT |
| `github.com/josharian/native` | v1.1.0 | MIT |
| `golang.org/x/net` | v0.57.0 | BSD-3-Clause |
| `golang.org/x/sync` | v0.10.0 | BSD-3-Clause |

- `golang.org/x/crypto` supplies Curve25519, used to derive WireGuard public
  keys.
- `wgctrl` is the WireGuard project's own control library. It configures the
  kernel data plane over netlink, which is why the binary needs no `wg` command
  (NM-01, NM-05).
- `vishvananda/netlink` and `netns` handle links, addresses and network
  namespaces; the rest are their netlink transport dependencies.

All are permissive and require no cgo.

## Policy

Only permissive licenses are accepted by default:

- Apache-2.0
- MIT
- BSD-2-Clause, BSD-3-Clause
- ISC
- MPL-2.0 (file-level copyleft, acceptable)

Strong copyleft licenses (GPL, AGPL, LGPL) are rejected by default. They
conflict with the project's goal of allowing unrestricted commercial use.
Introducing such a dependency requires explicit maintainer approval and a
recorded ADR.

CI fails the build when a dependency carries a license outside this policy.
