BINARY := freebox-ptr-dns
PKG    := ./cmd/freebox-ptr-dns
GOFLAGS := -trimpath

# Get version from git tags
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -s -w -X github.com/L3n41c/freebox_ptr_dns/internal/app.version=$(VERSION)

.PHONY: all build test vet race build-amd64 build-arm64 build-armv7 clean install-systemd

all: build

build:
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o $(BINARY) $(PKG)

build-amd64:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o dist/$(BINARY)-linux-amd64 $(PKG)

build-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o dist/$(BINARY)-linux-arm64 $(PKG)

build-armv7:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o dist/$(BINARY)-linux-armv7 $(PKG)

dist: build-amd64 build-arm64 build-armv7

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

clean:
	rm -f $(BINARY)
	rm -rf dist
