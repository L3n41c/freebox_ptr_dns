BINARY := freebox-ptr-dns
PKG    := ./cmd/freebox-ptr-dns
GOFLAGS := -trimpath
LDFLAGS := -s -w

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
