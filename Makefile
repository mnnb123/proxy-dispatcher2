APP_NAME := proxy-dispatcher
VERSION  := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD    := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
COMMIT   := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

LDFLAGS  := -s -w \
    -X main.Version=$(VERSION) \
    -X main.BuildDate=$(BUILD) \
    -X main.Commit=$(COMMIT)

.PHONY: build build-arm test clean release

build:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
		-ldflags "$(LDFLAGS)" \
		-o dist/$(APP_NAME)-linux-amd64 \
		./cmd/proxy-dispatcher/

build-arm:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build \
		-ldflags "$(LDFLAGS)" \
		-o dist/$(APP_NAME)-linux-arm64 \
		./cmd/proxy-dispatcher/

test:
	go test ./internal/... -v -race -cover

clean:
	rm -rf dist/

release: build build-arm
	@echo "Binaries ready in dist/"
