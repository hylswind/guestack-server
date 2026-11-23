# EPOCH_ID is compiled into guestackd (measured). It has no default for
# release builds; dev targets default to the current UTC month.
EPOCH_ID ?=
DEV_EPOCH_ID ?= $(shell date -u +%Y-%m)
MODULE = github.com/hylswind/guestack-server
GOFLAGS_BUILD = -trimpath
LDFLAGS = -s -w -X $(MODULE)/internal/epoch.ID=

# Packages that own a file in spec/vectors.
VECTOR_PKGS = ./internal/epoch ./internal/phone ./internal/secret ./internal/binding ./internal/issuer ./internal/channel
DEV_VECTOR_PKGS = ./internal/devclient

.PHONY: build build-dev run-dev test test-short lint fmt vectors check

build:
	@test -n "$(EPOCH_ID)" || (echo "usage: make build EPOCH_ID=YYYY-MM"; exit 1)
	CGO_ENABLED=0 go build $(GOFLAGS_BUILD) -ldflags "$(LDFLAGS)$(EPOCH_ID)" -o bin/guestackd ./cmd/guestackd

build-dev:
	CGO_ENABLED=0 go build $(GOFLAGS_BUILD) -tags dev -ldflags "$(LDFLAGS)$(DEV_EPOCH_ID)" -o bin/guestackd-dev ./cmd/guestackd

run-dev: build-dev
	GUESTACK_LISTEN_ADDR=127.0.0.1:8080 ./bin/guestackd-dev

# Both builds: production (no tag) and dev (-tags dev, includes the privacy test).
test:
	go test -race ./...
	go test -race -tags dev ./...

# Skips the tests that build and run the binary.
test-short:
	go test -short ./...
	go test -short -tags dev ./...

lint:
	go vet ./...
	go vet -tags dev ./...
	go tool staticcheck ./...
	go tool staticcheck -tags dev ./...
	@test -z "$$(gofmt -l .)" || (gofmt -l .; echo "gofmt needed"; exit 1)

fmt:
	gofmt -w .

# Regenerates spec/vectors from the implementation. Randomised entries
# (signatures, HPKE encapsulations) change; review the diff before committing.
vectors:
	go test $(VECTOR_PKGS) -run Vectors -update-vectors
	go test -tags dev $(DEV_VECTOR_PKGS) -run Vectors -update-vectors

check: lint test
