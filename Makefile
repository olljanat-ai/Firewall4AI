BINARY_NAME := firewall4ai
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-s -w -X main.Version=$(VERSION)"
GOOS := linux
GOARCH := amd64

.PHONY: all build test lint clean

all: lint test build

build:
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build $(LDFLAGS) -o bin/$(BINARY_NAME) ./cmd/firewall4ai/

test:
	go test -race -timeout 60s ./...

lint:
	go vet ./...

clean:
	rm -rf bin/

run: build
	sudo ifconfig eth1 10.255.255.1 netmask 255.255.255.0 up
	sudo ./bin/$(BINARY_NAME)
