SHELL := /bin/sh
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
GOFLAGS := -trimpath -ldflags "-s -w -X main.version=$(VERSION)"
BIN := bin

.PHONY: all build build-client build-server test vet run-server run-client install clean cross

all: build

build: build-client build-server

build-client:
	@mkdir -p $(BIN)
	CGO_ENABLED=0 go build $(GOFLAGS) -o $(BIN)/munnel ./cmd/client

build-server:
	@mkdir -p $(BIN)
	CGO_ENABLED=0 go build $(GOFLAGS) -o $(BIN)/munnel-server ./cmd/server

test:
	go test -race ./...

vet:
	go vet ./...

run-server:
	go run ./cmd/server --domain localhost

# usage: make run-client PORT=3000
PORT ?= 3000
run-client:
	go run ./cmd/client $(PORT)

install: build
	@echo "installing to $(DESTDIR)$(PREFIX)/bin"
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 0755 $(BIN)/munnel $(DESTDIR)$(PREFIX)/bin/munnel
	install -m 0755 $(BIN)/munnel-server $(DESTDIR)$(PREFIX)/bin/munnel-server

PREFIX ?= /usr/local
DESTDIR ?=

clean:
	rm -rf $(BIN) dist

# Cross-compile release archives into dist/
cross:
	@mkdir -p dist
	@for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64; do \
	  os=$${target%/*}; arch=$${target#*/}; \
	  out=dist/munnel-$${os}-$${arch}; mkdir -p $$out; \
	  ext=""; [ "$$os" = "windows" ] && ext=".exe"; \
	  echo "→ $$target"; \
	  CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build $(GOFLAGS) -o $$out/munnel$$ext ./cmd/client; \
	  CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build $(GOFLAGS) -o $$out/munnel-server$$ext ./cmd/server; \
	  tar -C dist -czf $$out.tar.gz $$(basename $$out) && rm -rf $$out; \
	done
	@ls -la dist
