# Makefile for tlscheck
#
# Provides targets for building cross-platform binaries, running tests,
# and managing releases.

# Binary name
BINARY_NAME=tlscheck

# Version can be overridden via VERSION environment variable or git tag
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOCLEAN=$(GOCMD) clean
GOMOD=$(GOCMD) mod
GOFMT=gofmt

# Build flags
LDFLAGS=-ldflags "-X github.com/programmerq/tlscheck/internal/version.Version=$(VERSION)"

# Output directories
DIST_DIR=dist
BIN_DIR=bin

.PHONY: all
all: test build

.PHONY: help
help:
	@echo "Available targets:"
	@echo "  make build              - Build binary for current platform"
	@echo "  make test               - Run tests"
	@echo "  make fmt                - Run gofmt on all source files"
	@echo "  make clean              - Remove build artifacts"
	@echo "  make deps               - Download dependencies"
	@echo "  make release            - Build binaries for all platforms"
	@echo "  make release-linux      - Build Linux binaries (amd64, arm64)"
	@echo "  make release-darwin     - Build macOS binaries (amd64, arm64)"
	@echo "  make release-windows    - Build Windows binaries (amd64, arm64)"

.PHONY: deps
deps:
	$(GOMOD) download
	$(GOMOD) tidy

.PHONY: fmt
fmt:
	$(GOFMT) -w .

.PHONY: test
test:
	$(GOTEST) -v -race -coverprofile=coverage.txt -covermode=atomic ./...

.PHONY: build
build:
	$(GOBUILD) $(LDFLAGS) -o $(BINARY_NAME) ./cmd/tlscheck

.PHONY: clean
clean:
	$(GOCLEAN)
	rm -f $(BINARY_NAME)
	rm -rf $(DIST_DIR)
	rm -rf $(BIN_DIR)
	rm -f coverage.txt

# Cross-platform build targets
.PHONY: release
release: release-linux release-darwin release-windows

.PHONY: release-linux
release-linux: release-linux-amd64 release-linux-arm64

.PHONY: release-darwin
release-darwin: release-darwin-amd64 release-darwin-arm64

.PHONY: release-windows
release-windows: release-windows-amd64 release-windows-arm64

# Linux builds
.PHONY: release-linux-amd64
release-linux-amd64:
	@mkdir -p $(DIST_DIR)
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(DIST_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/tlscheck

.PHONY: release-linux-arm64
release-linux-arm64:
	@mkdir -p $(DIST_DIR)
	GOOS=linux GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(DIST_DIR)/$(BINARY_NAME)-linux-arm64 ./cmd/tlscheck

# macOS builds
.PHONY: release-darwin-amd64
release-darwin-amd64:
	@mkdir -p $(DIST_DIR)
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(DIST_DIR)/$(BINARY_NAME)-darwin-amd64 ./cmd/tlscheck

.PHONY: release-darwin-arm64
release-darwin-arm64:
	@mkdir -p $(DIST_DIR)
	GOOS=darwin GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(DIST_DIR)/$(BINARY_NAME)-darwin-arm64 ./cmd/tlscheck

# Windows builds
.PHONY: release-windows-amd64
release-windows-amd64:
	@mkdir -p $(DIST_DIR)
	GOOS=windows GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(DIST_DIR)/$(BINARY_NAME)-windows-amd64.exe ./cmd/tlscheck

.PHONY: release-windows-arm64
release-windows-arm64:
	@mkdir -p $(DIST_DIR)
	GOOS=windows GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(DIST_DIR)/$(BINARY_NAME)-windows-arm64.exe ./cmd/tlscheck
