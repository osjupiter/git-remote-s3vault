GO ?= go
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test e2e vet lint clean install

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/git-remote-s3ee ./cmd/git-remote-s3ee

install:
	CGO_ENABLED=0 $(GO) install -trimpath -ldflags '$(LDFLAGS)' ./cmd/git-remote-s3ee

test:
	$(GO) test ./internal/...

e2e:
	$(GO) test ./e2e/ -v -timeout 10m

vet:
	$(GO) vet ./...

clean:
	rm -rf bin
