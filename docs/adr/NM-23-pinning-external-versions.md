# NM-23 — Pinning external versions

**Status:** Accepted
**Date:** 2026-09-06
**Milestone:** M2.1

## Context

The project already fixes what it depends on in Go: twenty-four modules at exact
versions, two of them at a specific commit, and a `go.sum` carrying a content
hash for each — so a version republished with different bytes breaks the build
instead of entering quietly.

Everything else that runs during a build is looser than that.

- **The Go toolchain is a range.** `GO_VERSION: "1.25"` in CI and `golang:1.25`
  in the Makefile both accept any patch release. A new one arrives on its own, in
  both places, at different times.
- **Every GitHub Action is referenced by a moving tag** — `actions/checkout@v4`,
  `actions/setup-go@v5`, `golangci/golangci-lint-action@v8`,
  `gitleaks/gitleaks-action@v2`. A Git tag is a mutable pointer: the repository
  owner can move `v4` to a different commit, and every build afterwards runs code
  nobody here reviewed.
- **Container images are referenced by tag**, which can be republished the same
  way.

The last of those is the largest exposure this project has. An action runs with
access to the checkout and the job's token; a compromised or simply changed one
is arbitrary code inside the build.

There is also a narrower failure this closes. The project already requires that
verification tools be fixed and identical between local and CI, because otherwise
"passed here, failed there" makes local validation meaningless. The compiler was
never covered by that rule, which was an oversight rather than a decision.

## Decision

**Everything external is referenced by an immutable identifier.**

| What | Referenced by |
|---|---|
| Go modules | exact version, plus the `go.sum` hash |
| Go toolchain | exact patch version — `1.25.14`, not `1.25` |
| GitHub Actions | commit SHA, with the version in a trailing comment |
| Container images | `name@sha256:...` digest, with the tag in a comment |

A tag or a range is never enough on its own. Where a human-readable version
exists it is kept beside the pin as a comment, because a bare SHA tells a reader
nothing about what they are looking at.

## Consequences

- **Updating a dependency becomes an explicit commit.** This is the cost, and it
  is the point: an update that changes what runs in CI should be a change
  somebody made, reviewed like any other. Automation can propose these; it cannot
  make them silently.
- **A moved tag no longer changes the build.** If an upstream repository
  repoints `v4`, this project keeps running the commit it pinned until somebody
  moves it deliberately.
- **A comment can go stale.** The SHA is what is enforced and the comment is only
  a label, so a wrong comment misleads without breaking anything. Updating both
  together is the discipline; the pin is what holds if the discipline slips.
- **`go.mod` needs no change.** It already satisfies the rule, which is why the
  gap went unnoticed: the part of the supply chain with the most eyes on it was
  the part already handled.
- **No `toolchain` directive is added.** `go 1.25.0` there is a minimum rather
  than a pin, so it looks like a gap — but the builds run with
  `GOTOOLCHAIN=local`, meaning the compiler is whichever one the image carries
  and nothing is downloaded. Pinning the image by digest therefore pins the
  toolchain already. Adding a `toolchain` line would be redundant where it
  matters and would introduce a download where it does not.

## Alternatives rejected

**Keep tags and rely on upstream not moving them.** This is the current state.
It rests on every upstream maintainer's release discipline and on none of their
accounts being compromised, which is not a property this project can verify or
influence.

**Pin only the third-party actions, trusting `actions/*` as first-party.** Being
published by GitHub makes an action better maintained, not immutable — the tag is
mutable in exactly the same way, and the distinction would put a permanent asterisk
on a rule that is worth more when it has none.

**Vendor the actions into the repository.** Removes the dependency on tags
entirely and replaces it with maintaining copies of four upstream projects. The
cost is continuous where pinning's is occasional.

**Use Dependabot's automatic updates without pinning.** Solves staleness rather
than mutability: it would keep the ranges moving on a schedule while leaving them
able to move on their own in between.

## Validation

The pins were resolved from the upstream repositories rather than written from
memory, and each SHA was mapped back to its exact release — `checkout` v4.4.0,
`setup-go` v5.6.0, `golangci-lint-action` v8.0.0, `gitleaks-action` v2.3.9 — so
the comments say what is actually pinned.

The image digests were read from the registry, and the Go version from the image
itself, so `1.25.14` is the patch the toolchain has been running rather than the
newest one published.

The change is validated by the build continuing to pass: a wrong SHA does not
resolve, and a wrong digest does not pull, so both fail loudly rather than
silently doing something else.
