# Go parameters
GOCMD=go
GOCLEAN=$(GOCMD) clean
GOGET=$(GOCMD) get
GOINSTALL=$(GOCMD) install
GOMOD=$(GOCMD) mod

# Version information
VERSION=$(shell git describe --tags --always 2>/dev/null || echo "dev")
COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

# Swagger parameters
SWAG_CMD=swag
SWAG_INIT=$(SWAG_CMD) init
SWAG_FMT=$(SWAG_CMD) fmt

# Build flags
LDFLAGS=-ldflags "-s -w"
BUILD_FLAGS=-trimpath $(LDFLAGS)

# Default config file path
DEFAULT_CONFIG_FILE=examples/embedded_config.hcl

# Binary paths
BIN_DIR=cmd/netclip/bin
BINARY=$(BIN_DIR)/netclip

# Default suffix is empty, can be overridden for different platforms
SUFFIX=
ifeq ($(GOOS),windows)
	SUFFIX=.exe
endif

.PHONY: all build clean deps swagger fmt vet lint run help version ensure_default_config dist

all: build

version:
	@echo "Generating version information..."
	@/bin/echo -e "package common\n\n// Version information\nconst (\n\t// Version is the current application version\n\tVersion = \"$(VERSION)\"\n\n\t// Commit is the git commit hash\n\tCommit = \"$(COMMIT)\"\n\n\t// BuildDate is when the binary was built\n\tBuildDate = \"$(BUILD_DATE)\"\n)" > common/version.go

build: ensure_default_config version swagger deps
	mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 $(GOCMD) build $(BUILD_FLAGS) -o $(BINARY)$(SUFFIX) ./cmd/netclip

clean:
	$(GOCLEAN)
	rm -rf $(BIN_DIR)
	rm -rf ./docs/swagger
	rm -f common/version.go

deps:
	$(GOMOD) tidy

swagger:
	env GOOS= GOARCH= $(GOINSTALL) github.com/swaggo/swag/cmd/swag@latest
	$(SWAG_INIT) -g server/server.go -o ./docs/swagger

swagger-fmt:
	$(SWAG_FMT)

fmt:
	$(GOCMD) fmt ./...

vet:
	$(GOCMD) vet ./...

lint:
	golangci-lint run

run: build
	./cmd/netclip/bin/netclip

help:
	@echo "Make targets:"
	@echo "  all        - Generate version info, swagger docs and build binary"
	@echo "  build      - Build the binary"
	@echo "  clean      - Remove binary, swagger docs, and generated version file"
	@echo "  deps       - Install dependencies including swag"
	@echo "  swagger    - Generate swagger documentation"
	@echo "  swagger-fmt- Format swagger comments"
	@echo "  fmt        - Run go fmt"
	@echo "  vet        - Run go vet"
	@echo "  lint       - Run golangci-lint"
	@echo "  run        - Build and run the application"
	@echo "  version    - Generate version information"
	@echo "  ensure_default_config - Create empty default config if missing"
	@echo "  dist       - Build binaries for multiple platforms (linux/amd64, linux/arm64, windows/amd64, darwin/amd64)"

ensure_default_config:
	@if [ ! -f "$(DEFAULT_CONFIG_FILE)" ]; then \
		touch "$(DEFAULT_CONFIG_FILE)"; \
	fi

dist: ensure_default_config version swagger deps
	@echo "Building for multiple platforms..."
	@mkdir -p dist
	
	# Linux amd64
	@echo "Building for Linux (amd64)..."
	@mkdir -p dist/linux_amd64
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOCMD) build $(BUILD_FLAGS) -o dist/linux_amd64/netclip ./cmd/netclip
	
	# Linux arm64
	@echo "Building for Linux (arm64)..."
	@mkdir -p dist/linux_arm64
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GOCMD) build $(BUILD_FLAGS) -o dist/linux_arm64/netclip ./cmd/netclip
	
	# Windows amd64
	@echo "Building for Windows (amd64)..."
	@mkdir -p dist/windows_amd64
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GOCMD) build $(BUILD_FLAGS) -o dist/windows_amd64/netclip.exe ./cmd/netclip
	
	# macOS amd64
	@echo "Building for macOS (amd64)..."
	@mkdir -p dist/darwin_amd64
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 $(GOCMD) build $(BUILD_FLAGS) -o dist/darwin_amd64/netclip ./cmd/netclip
	
	@echo "All builds completed in the dist/ directory"
