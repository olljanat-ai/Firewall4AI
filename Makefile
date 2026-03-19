BINARY_NAME := squid4claw
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-s -w -X main.Version=$(VERSION)"
GOOS := linux
GOARCH := amd64

.PHONY: all build test lint clean

all: lint test build

build:
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build $(LDFLAGS) -o bin/$(BINARY_NAME) ./cmd/squid4claw/

test:
	go test -race -timeout 60s ./...

lint:
	go vet ./...

clean:
	rm -rf bin/

run: build
	./bin/$(BINARY_NAME)
