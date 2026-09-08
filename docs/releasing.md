# Releasing

A release is made by pushing a tag. Everything after that is automated: GitHub
builds the artifacts, verifies them, and publishes them.

```bash
git tag -a v0.3.0 -m "0.3.0"
git push origin v0.3.0
```

Nothing is built on a maintainer's machine, and nothing is uploaded by hand.

## What gets published

Six artifacts and a checksum file, attached to the GitHub release:

| Artifact | Contents |
|---|---|
| `nostmesh_<version>_linux_amd64.tar.gz` | binary, `LICENSE`, `NOTICE`, `README.md` |
| `nostmesh_<version>_linux_arm64.tar.gz` | the same, for arm64 |
| `nostmesh_<version>_amd64.deb` | binary, systemd unit, logrotate config, example configuration |
| `nostmesh_<version>_arm64.deb` | the same, for arm64 |
| `nostmesh-<version>-1.x86_64.rpm` | the same contents as the `.deb` |
| `nostmesh-<version>-1.aarch64.rpm` | the same, for aarch64 |
| `SHA256SUMS` | one line per artifact above |

Verify a download before installing it:

```bash
sha256sum -c SHA256SUMS --ignore-missing
```

## What the workflow does

Three jobs, each depending on the last, so a failure stops the release rather
than publishing part of it.

**`verify`** runs `make check` and the linter — the same checks a pull request
faces. A tag that would have failed CI does not publish: an artifact users
install with nothing to say it was never verified is worse than no artifact.

**`build`** confirms the tag matches what `git describe` reports, then builds
every artifact and runs `make dist-verify` on the result.

**`publish`** attaches the artifacts to the release. It is the only job with
write permission, and it writes exactly the release.

**A tag containing a hyphen is marked a pre-release**, following SemVer: what
comes after the hyphen is a pre-release identifier. `v0.2.4-2b` is a step
towards `v0.2.4`; `v0.2.4` is the delivery.

The package versions say the same thing. nfpm renders `v0.2.4-2b` as
`0.2.4~2b`, and `~` orders *before* a plain version in both Debian and RPM — so
every pre-release loses to `0.2.4` when a package manager compares them. Written
with a hyphen instead, the package would be read as a *revision* of 0.2.4 and
would order after it, inverting the intent.

Verified rather than assumed:

```
0.2.4~1b < 0.2.4~2b     ok
0.2.4~2b < 0.2.4~10b    ok    (compared as a number, not as text)
0.2.4~10b < 0.2.4       ok
```

Git references cannot contain `~`, which is why the tag uses `-` and the
package `~`.

## What `dist-verify` checks

The packages are what users actually install, and nothing else in the test suite
looks inside one. A path typo would otherwise ship a package that installs a
binary nobody can run, and the pipeline would report success doing it.

For each architecture:

- the `.deb` contains the binary, the unit and the logrotate config, at the
  paths they must be installed to;
- **the unit's `ExecStart` matches where the binary was installed** — the two
  come from different files, and a mismatch survives review and fails on a
  user's machine;
- the maintainer scripts are present, without which the service account is never
  created and the unit fails with `status=217/USER`;
- the binary is an ELF built for the architecture the filename claims, read from
  the ELF header rather than trusted;
- the archive carries the licence, which Apache-2.0 requires;
- every artifact appears in `SHA256SUMS`.

Each of these was confirmed by planting the fault it describes and watching the
check fail.

## Building locally

Not needed to release, but useful to inspect what a tag would produce:

```bash
make docker-dist VERSION=v0.3.0   # no local Go toolchain required
make dist-verify
```

`make dist` is the same thing using the Go on `PATH`, which is what CI runs.

## What a package installs

- `/usr/bin/nostmesh`
- `/lib/systemd/system/nostmesh.service`
- `/etc/logrotate.d/nostmesh`
- `/etc/nostmesh/nostmesh.json.example`
- `/etc/nostmesh`, mode **0755**

The directory is 0755 rather than 0700 because systemd refuses to start when
`ConfigurationDirectory` has a mode other than the one it manages — a field test
found this the hard way. The configuration file itself is 0600 and owned by the
service account.

Installing **creates the `nostmesh` service account** and **does not start the
service**: a node with no configuration cannot serve, so enabling it would
guarantee a failed start on every fresh install.

Upgrading does not restart a running node. A mesh node dropping its tunnels is a
visible event, and doing it silently during an unattended upgrade is worse than
running the previous binary a while longer — the package says so and leaves the
choice to the operator.

Removing keeps `/var/lib/nostmesh` and the configuration. The state directory
holds this node's private key and its network journal: deleting the key would
make a reinstall a different node, and the journal is what reconciliation reads
to clean up interfaces a crash left behind.

## What is not signed

Nothing. Signing needs a key, and where that key lives is a decision to make
deliberately rather than acquire by adding a step. `SHA256SUMS` proves an
artifact was not corrupted in transit; it does not prove who built it.
