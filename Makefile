# Common tasks. `make check` is what CI runs (minus the PostgreSQL and edge tests).

MODULE   := $(shell go list -m)
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS  := -s -w -X $(MODULE)/internal/version.Version=$(VERSION)
DIST     := dist

# Set TEST_DATABASE_URL to run the PostgreSQL tests too, for example:
#   docker run -d --name pgtest -e POSTGRES_USER=mancar -e POSTGRES_PASSWORD=testpw \
#     -e POSTGRES_DB=mancar_test -p 5432:5432 postgres:18-alpine
#   export TEST_DATABASE_URL='postgres://mancar:testpw@127.0.0.1:5432/mancar_test?sslmode=disable'

.PHONY: all build test race vet fmt fmt-check check shellcheck e2e-edge dist docker clean

all: check build

build:
	go build -trimpath -ldflags '$(LDFLAGS)' -o bin/mancard ./cmd/mancard
	go build -trimpath -ldflags '$(LDFLAGS)' -o bin/mancar  ./cmd/mancar

test:
	go test -count=1 ./...

race:
	go test -race -count=1 ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

fmt-check:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt needed on:"; echo "$$out"; exit 1; fi

shellcheck:
	shellcheck -x scripts/*.sh

check: fmt-check vet race shellcheck

# Real Caddy -> real gateway -> real agent. Needs caddy on PATH or CADDY_BIN.
e2e-edge:
	scripts/e2e-edge.sh

# Release binaries for every platform plus SHA-256 checksums.
dist:
	rm -rf $(DIST) && mkdir -p $(DIST)
	@set -e; \
	for p in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64; do \
	  os=$${p%/*}; arch=$${p#*/}; ext=; [ $$os = windows ] && ext=.exe; \
	  echo "building mancar $$os/$$arch"; \
	  CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags '$(LDFLAGS)' \
	    -o $(DIST)/mancar-$(VERSION)-$$os-$$arch$$ext ./cmd/mancar; \
	done; \
	for p in linux/amd64 linux/arm64; do \
	  os=$${p%/*}; arch=$${p#*/}; \
	  echo "building mancard $$os/$$arch"; \
	  CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags '$(LDFLAGS)' \
	    -o $(DIST)/mancard-$(VERSION)-$$os-$$arch ./cmd/mancard; \
	done
	cd $(DIST) && sha256sum * > SHA256SUMS && cat SHA256SUMS

docker:
	docker build --build-arg VERSION=$(VERSION) -t mancar:$(VERSION) .
	docker build -t mancar-edge:$(VERSION) docker/caddy

clean:
	rm -rf bin $(DIST)
