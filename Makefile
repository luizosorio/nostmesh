# NostMesh
#
# Build and test run inside containers on the remote host, never against tools
# installed locally. See CONTRIBUTING.md for the development environment.

BINARY      := nostmesh
GO          ?= go
# The full image, not alpine: the race detector requires a C toolchain.
GO_IMAGE    ?= golang:1.25
# Pinned so local runs and CI analyze with the same linter version.
LINT_IMAGE  ?= golangci/golangci-lint:v2.13.2
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
	docker run --rm -v "$(PWD)":/src -w /src \
		-e GOFLAGS=-buildvcs=false \
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

# Privileged tests exercise the netlink adapter against a real kernel. They
# need NET_ADMIN and the wireguard module loaded on the host, since containers
# share the host kernel. Each test runs in its own network namespace.
.PHONY: test-privileged
test-privileged:
	$(GO) test -tags privileged -count=1 ./test/integration/...

.PHONY: docker-test-privileged
docker-test-privileged:
	docker run --rm --cap-add NET_ADMIN -v "$(PWD)":/src -w /src \
		-e GOFLAGS=-buildvcs=false \
		$(GO_IMAGE) sh -c 'git config --global --add safe.directory /src; make test-privileged'

.PHONY: check
check: fmt-check vet test portability

.PHONY: clean
clean:
	rm -rf bin coverage.out

# Run any target inside the Go container, matching CI and the remote host.
.PHONY: docker-%
docker-%:
	docker run --rm -v "$(PWD)":/src -w /src \
		-e GOFLAGS=-buildvcs=false \
		$(GO_IMAGE) sh -c 'git config --global --add safe.directory /src; make $*' 
