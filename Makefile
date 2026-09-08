# NostMesh
#
# Build and test run inside containers on the remote host, never against tools
# installed locally. See CONTRIBUTING.md for the development environment.

BINARY      := nostmesh
GO          ?= go
# The full image, not alpine: the race detector requires a C toolchain.
#
# By digest rather than tag, because a tag can be republished and a build that
# silently changes toolchain is what this prevents. The version is named here
# because a bare digest tells a reader nothing. See NM-23.
#
# golang:1.25.14
GO_IMAGE    ?= golang@sha256:699337d620559a59b4a2bb298ad59611e535d2ee755a34cf2d2a98f37578dc80

# Run containers as the calling user. Without this, anything a container writes
# — fuzz corpus, coverage profiles, build output — lands owned by root, and the
# user can neither remove nor commit it.
DOCKER_USER ?= $(shell id -u):$(shell id -g)

# A non-root user in the container has no home directory, so Go and
# golangci-lint cannot create their build caches. HOME and the cache paths have
# to point somewhere writable or every target fails on a permission error.
DOCKER_ENV := -e GOFLAGS=-buildvcs=false \
	-e HOME=/tmp \
	-e GOCACHE=/tmp/.gocache \
	-e GOMODCACHE=/tmp/.gomodcache \
	-e GOLANGCI_LINT_CACHE=/tmp/.lintcache
# Pinned so local runs and CI analyze with the same linter version, and by
# digest so the tag cannot be republished underneath it.
#
# golangci/golangci-lint:v2.13.2
LINT_IMAGE  ?= golangci/golangci-lint@sha256:ba07dffad130794ae79ebaa0056809d18c0168f3f846480ffd3eb6c04578b83d
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT      ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE        ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
	-X github.com/luizosorio/nostmesh/internal/version.version=$(VERSION) \
	-X github.com/luizosorio/nostmesh/internal/version.commit=$(COMMIT) \
	-X github.com/luizosorio/nostmesh/internal/version.date=$(DATE)

.PHONY: all
all: check build

.PHONY: build
build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/$(BINARY) ./cmd/nostmesh

.PHONY: test
test:
	$(GO) test -race ./...

.PHONY: cover
cover:
	$(GO) test -coverprofile=coverage.out ./...
	$(GO) tool cover -func=coverage.out | tail -1

.PHONY: vet
vet:
	$(GO) vet ./...

.PHONY: fmt
fmt:
	$(GO) fmt ./...

.PHONY: fmt-check
fmt-check:
	@unformatted=$$(gofmt -l .); \
	if [ -n "$$unformatted" ]; then \
		echo "Not gofmt-formatted:"; echo "$$unformatted"; exit 1; \
	fi

.PHONY: lint
lint:
	golangci-lint run

# Lint in its own image, matching the version CI uses.
.PHONY: docker-lint
docker-lint:
	docker run --rm --user $(DOCKER_USER) -v "$(PWD)":/src -w /src \
		$(DOCKER_ENV) \
		$(LINT_IMAGE) golangci-lint run

# The core must stay free of the operating system. Building for out-of-scope
# targets proves the boundary holds before an adapter for them exists.
.PHONY: portability
portability:
	@for target in linux/amd64 linux/arm64 windows/amd64 darwin/arm64; do \
		os=$${target%/*}; arch=$${target#*/}; \
		printf '%-16s ' "$$os/$$arch"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch $(GO) build -buildvcs=false -o /dev/null ./... \
			&& echo ok || exit 1; \
	done

# Privileged tests exercise the netlink adapter against a real kernel. Creating
# a network namespace needs CAP_SYS_ADMIN, and configuring WireGuard needs
# CAP_NET_ADMIN; the wireguard module must be loaded on the host, since
# containers share the host kernel. Each test runs in its own namespace, so a
# failure cannot disturb the host.
.PHONY: test-privileged
test-privileged:
	$(GO) test -tags privileged -count=1 ./test/integration/...

# Coverage across both suites. The netlink adapter has no unit tests by design —
# it is a thin layer over the kernel, and testing it without one proves nothing —
# so its coverage comes from the privileged suite via -coverpkg. Measuring only
# the default suite reports 0% for it and hides how much is actually exercised.
.PHONY: cover-all
cover-all:
	$(GO) test -tags privileged -count=1 \
		-coverpkg=./internal/...,./cmd/... \
		-coverprofile=coverage-all.out \
		./... 
	@echo
	@$(GO) tool cover -func=coverage-all.out | tail -1
	@echo
	@echo "per package:"
	@$(GO) tool cover -func=coverage-all.out | \
		awk -F/ '{print $$0}' | \
		grep -oE 'nostmesh/[a-z/]+\.go' | sort -u | \
		sed 's|nostmesh/||' | cut -d/ -f1-2 | sort -u

# Fuzzing finds inputs that crash a parser. A hostile relay reaches the decoder
# first, so a panic there is a denial of service any peer can trigger.
#
# Corpus entries under testdata/fuzz are committed: they become permanent
# regression tests, run by the ordinary test suite.
FUZZTIME ?= 30s

.PHONY: fuzz
fuzz:
	@for target in FuzzDecodeEnvelope FuzzDecodePayload FuzzValidateEnvelope FuzzCheckDepth; do \
		printf '%-24s ' "$$target"; \
		$(GO) test -run '^$$' -fuzz "^$$target$$" -fuzztime $(FUZZTIME) ./internal/protocol/ \
			2>&1 | grep -E '^(PASS|FAIL|.*panic)' | tail -1; \
	done

.PHONY: docker-fuzz
docker-fuzz:
	docker run --rm --user $(DOCKER_USER) -v "$(PWD)":/src -w /src \
		$(DOCKER_ENV) -e FUZZTIME=$(FUZZTIME) \
		$(GO_IMAGE) sh -c 'git config --global --add safe.directory /src 2>/dev/null; make fuzz'

# Baseline measurements, not a performance claim. See docs/benchmarks.md for
# what this setup does and does not measure.
.PHONY: bench
bench:
	$(GO) test -tags privileged -run '^$$' -bench . -benchmem ./test/integration/...

.PHONY: docker-bench
docker-bench:
	docker run --rm --cap-add NET_ADMIN --cap-add SYS_ADMIN -v "$(PWD)":/src -w /src \
		-e GOFLAGS=-buildvcs=false \
		$(GO_IMAGE) sh -c 'git config --global --add safe.directory /src; make bench'

# Privileged targets need root for NET_ADMIN, so what they write lands owned by
# root. Ownership is restored afterwards, or the user cannot remove it.
.PHONY: docker-cover-all
docker-cover-all:
	docker run --rm --cap-add NET_ADMIN --cap-add SYS_ADMIN -v "$(PWD)":/src -w /src \
		-e GOFLAGS=-buildvcs=false \
		$(GO_IMAGE) sh -c 'git config --global --add safe.directory /src; make cover-all'
	@$(MAKE) --no-print-directory fix-ownership

# --privileged rather than two capabilities: the subnet tests write
# net.ipv4.ip_forward inside their own namespace, and Docker mounts /proc/sys
# read-only unless the container is privileged. Without it those tests skip,
# and a skipping test proves nothing.
.PHONY: docker-test-privileged
docker-test-privileged:
	docker run --rm --privileged -v "$(PWD)":/src -w /src \
		-e GOFLAGS=-buildvcs=false \
		$(GO_IMAGE) sh -c 'git config --global --add safe.directory /src; make test-privileged'

# Release artifacts: static binaries, archives, packages and checksums.
#
# Every target below is reproducible from a clean checkout and a tag. Nothing
# here signs anything: signing needs a key, and a key in CI is a decision to
# make deliberately rather than acquire by adding a step.
DIST      := dist
PLATFORMS := linux/amd64 linux/arm64

# nfpm builds .deb and .rpm from one description. By digest, per NM-23: a tag
# can be republished, and a packaging tool that changes underneath a release is
# a supply-chain problem in the artifact users install.
#
# goreleaser/nfpm:v2.43.1
NFPM_IMAGE ?= goreleaser/nfpm@sha256:f1e9f1adcf452a85ab7765aa7252cdb2f94816ead5363bbd52a4e563087c942b

# The packaged unit differs from the example by one line: a package installs to
# /usr/bin, while the example documents the manual install under /usr/local/bin.
# Generated rather than committed twice, so the two cannot drift.
$(DIST)/nostmesh.service: examples/nostmesh.service
	@mkdir -p $(DIST)
	sed 's|/usr/local/bin/nostmesh|/usr/bin/nostmesh|' $< > $@
	@grep -q '/usr/bin/nostmesh serve' $@ || { \
		echo "the packaged unit does not point at /usr/bin/nostmesh" >&2; exit 1; }

# One static binary per platform, each in its own directory so the archive can
# be built from it without renaming.
.PHONY: dist-binaries
dist-binaries:
	@mkdir -p $(DIST)
	@for target in $(PLATFORMS); do \
		os=$${target%/*}; arch=$${target#*/}; \
		printf 'building %s/%s\n' "$$os" "$$arch"; \
		mkdir -p $(DIST)/$$os-$$arch; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch \
			$(GO) build -trimpath -ldflags '$(LDFLAGS)' \
			-o $(DIST)/$$os-$$arch/$(BINARY) ./cmd/nostmesh || exit 1; \
	done

# Archives carry the licence and the notice alongside the binary: the licence
# requires it, and a user who downloaded a tarball has nothing else to read.
.PHONY: dist-archives
dist-archives: dist-binaries
	@for target in $(PLATFORMS); do \
		os=$${target%/*}; arch=$${target#*/}; \
		cp LICENSE NOTICE README.md $(DIST)/$$os-$$arch/ 2>/dev/null || true; \
		tar -czf $(DIST)/$(BINARY)_$(VERSION)_$$os_$$arch.tar.gz \
			-C $(DIST)/$$os-$$arch . || exit 1; \
		printf 'packaged %s\n' "$(BINARY)_$(VERSION)_$$os_$$arch.tar.gz"; \
	done

# Debian and RPM disagree about architecture names, and neither matches Go's for
# every case: amd64 is x86_64 to rpm, arm64 is aarch64. nfpm handles the
# translation when it builds; anything reading the filenames afterwards has to
# know both spellings, which is why dist-verify carries the mapping.
# Packaging runs docker itself, so it cannot run inside the Go container the way
# the other targets do — there is no docker in there, and mounting the socket to
# add one would give a build container control of the host's daemon. The binaries
# it packages are built by docker-dist-binaries first, from the host.
.PHONY: dist-packages
dist-packages: $(DIST)/nostmesh.service
	@mkdir -p bin
	@for target in $(PLATFORMS); do \
		arch=$${target#*/}; \
		[ -f $(DIST)/linux-$$arch/$(BINARY) ] || { \
			echo "no binary for $$arch; run dist-binaries first" >&2; exit 1; }; \
		cp $(DIST)/linux-$$arch/$(BINARY) bin/$(BINARY); \
		for format in deb rpm; do \
			docker run --rm --user $(DOCKER_USER) -v "$(PWD)":/src -w /src \
				-e PKG_ARCH=$$arch -e PKG_VERSION=$(PKG_VERSION) \
				$(NFPM_IMAGE) package \
				--config packaging/nfpm.yaml --target $(DIST) --packager $$format \
				|| exit 1; \
		done; \
	done
	@rm -f bin/$(BINARY)

# The version a package carries.
#
# Debian and RPM both refuse a leading "v", so the tag's is stripped. The "-" of
# a pre-release tag stays a "-" rather than becoming "~", because GitHub rejects
# "~" in a release asset name and silently rewrites it to "." — which leaves the
# published filenames disagreeing with SHA256SUMS, so `sha256sum -c` matches
# nothing and reports "no file was verified".
#
# The cost is ordering: "0.2.4-1b" is read by dpkg as revision 1b *of* 0.2.4 and
# sorts after it, where "0.2.4~1b" would sort before. That matters when a
# package manager compares a pre-release against the final version, which is not
# something this project's artifacts are installed through — they are downloaded
# from a release page. A verifiable checksum is worth more than an ordering
# nobody queries.
PKG_VERSION ?= $(patsubst v%,%,$(VERSION))

# One file listing every artifact, which is what a user verifies against.
# Produced last so nothing can be added afterwards without changing it.
.PHONY: dist-checksums
dist-checksums:
	@cd $(DIST) && rm -f SHA256SUMS && \
		sha256sum *.tar.gz *.deb *.rpm > SHA256SUMS 2>/dev/null && \
		cat SHA256SUMS

# Prove the packages carry what they claim.
#
# A package is the artifact users actually install, and nothing else in the
# suite looks inside one. Without this, a path typo ships a package that
# installs a binary nobody can run and reports success doing it.
#
# dpkg-deb and rpm read their own formats; both are in the container that builds
# them, so this needs no tool the release does not already have.
.PHONY: dist-verify
dist-verify:
	@set -e; \
	for pair in amd64:x86_64 arm64:aarch64; do \
		go_arch=$${pair%%:*}; rpm_arch=$${pair##*:}; \
		deb=$$(ls $(DIST)/*_$${go_arch}.deb 2>/dev/null | head -1); \
		rpm=$$(ls $(DIST)/*.$${rpm_arch}.rpm 2>/dev/null | head -1); \
		[ -n "$$deb" ] || { echo "no .deb for $$go_arch" >&2; exit 1; }; \
		[ -n "$$rpm" ] || { echo "no .rpm for $$rpm_arch" >&2; exit 1; }; \
		tar=$$(ls $(DIST)/*_$${go_arch}.tar.gz 2>/dev/null | head -1); \
		[ -n "$$tar" ] || { echo "no archive for $$go_arch" >&2; exit 1; }; \
		docker run --rm -v "$(PWD)":/src -w /src $(VERIFY_IMAGE) \
			sh /src/packaging/verify.sh "$$deb" "$$rpm" "$$tar" || exit 1; \
	done
	@echo "checksums cover every artifact:"
	@cd $(DIST) && for file in *.tar.gz *.deb *.rpm; do \
		grep -q " $$file$$" SHA256SUMS \
			|| { echo "$$file missing from SHA256SUMS" >&2; exit 1; }; \
	done && echo "  ok"

# debian:13-slim, for dpkg-deb. By digest, per NM-23.
VERIFY_IMAGE ?= debian@sha256:d7e12182ce18b85b93007c1dedf31f2d29e01ccf3182cc4017c709b6259bc132

# The whole release, using whatever Go is on PATH.
#
# This is the target CI runs: the runner already has the pinned toolchain, so
# wrapping the build in a container there would add a layer that changes
# nothing. Packaging and verification still use their own images, because nfpm
# and dpkg-deb are not on the runner and pinning them by digest is what keeps
# the artifact reproducible (NM-23).
.PHONY: dist
dist: dist-archives dist-packages dist-checksums

# The same release, for a developer with no local Go — the project's own
# development rule. The build runs in the Go container; the rest is identical.
.PHONY: docker-dist
docker-dist:
	$(MAKE) docker-dist-archives VERSION=$(VERSION)
	$(MAKE) dist-packages VERSION=$(VERSION)
	$(MAKE) dist-checksums

.PHONY: dist-clean
dist-clean:
	rm -rf $(DIST)

.PHONY: check
check: fmt-check vet test portability

# Restore ownership of anything a privileged container wrote, without sudo.
.PHONY: fix-ownership
fix-ownership:
	@docker run --rm -v "$(PWD)":/src -w /src alpine \
		sh -c 'chown -R $(DOCKER_USER) /src 2>/dev/null || true'

.PHONY: clean
clean:
	rm -rf bin coverage.out coverage-all.out $(DIST)

# Run any target inside the Go container, matching CI and the remote host.
.PHONY: docker-%
docker-%:
	docker run --rm --user $(DOCKER_USER) -v "$(PWD)":/src -w /src \
		$(DOCKER_ENV) \
		$(GO_IMAGE) sh -c 'git config --global --add safe.directory /src 2>/dev/null; make $* VERSION=$(VERSION)' 
