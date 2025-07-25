BINARY_NAME = warpportal
INSTALL_DIR = /usr/local/bin

.PHONY: all build clean install uninstall test deps help

all: build

# Build the CLI binary
build:
	@echo "Building portal CLI..."
	go build -o $(BINARY_NAME) main.go

# Build with optimizations for release
build-release:
	@echo "Building portal CLI for release..."
	CGO_ENABLED=0 go build -ldflags="-w -s" -o $(BINARY_NAME) main.go

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -f $(BINARY_NAME)
	go clean

# Install the CLI binary
install: build
	@echo "Installing portal CLI..."
	sudo cp $(BINARY_NAME) $(INSTALL_DIR)/
	sudo chmod +x $(INSTALL_DIR)/$(BINARY_NAME)
	@echo "Portal CLI installed to $(INSTALL_DIR)/$(BINARY_NAME)"
	@echo ""
	@echo "Usage: portal --help"

# Uninstall the CLI binary
uninstall:
	@echo "Uninstalling portal CLI..."
	sudo rm -f $(INSTALL_DIR)/$(BINARY_NAME)
	@echo "Portal CLI uninstalled"

# Run tests
test:
	@echo "Running tests..."
	go test ./...

# Download dependencies
deps:
	@echo "Downloading dependencies..."
	go mod download
	go mod tidy

# Install development dependencies
deps-dev: deps
	@echo "Installing development dependencies..."
	go install golang.org/x/tools/cmd/goimports@latest
	go install golang.org/x/lint/golint@latest

# Format code
fmt:
	@echo "Formatting code..."
	go fmt ./...
	goimports -w .

# Lint code
lint:
	@echo "Linting code..."
	golint ./...
	go vet ./...

# Run the CLI locally
run:
	go run main.go

# Run specific command locally
run-install:
	sudo go run main.go install --dry-run --verbose

run-status:
	go run main.go status --verbose

run-register:
	go run main.go register --dry-run --verbose

run-uninstall:
	sudo go run main.go uninstall --dry-run --verbose

# Build for multiple platforms
build-all:
	@echo "Building for multiple platforms..."
	mkdir -p build
	# Standard Linux builds
	GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o build/$(BINARY_NAME)-linux-amd64 main.go
	GOOS=linux GOARCH=arm64 go build -ldflags="-w -s" -o build/$(BINARY_NAME)-linux-arm64 main.go
	GOOS=linux GOARCH=386 go build -ldflags="-w -s" -o build/$(BINARY_NAME)-linux-386 main.go
	# Debian optimized static builds
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s -extldflags '-static'" -o build/$(BINARY_NAME)-debian-amd64 main.go
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="-w -s -extldflags '-static'" -o build/$(BINARY_NAME)-debian-arm64 main.go
	# macOS builds
	GOOS=darwin GOARCH=amd64 go build -ldflags="-w -s" -o build/$(BINARY_NAME)-darwin-amd64 main.go
	GOOS=darwin GOARCH=arm64 go build -ldflags="-w -s" -o build/$(BINARY_NAME)-darwin-arm64 main.go
	@echo "All platform binaries built in build/ directory:"
	@ls -lh build/

# Build specifically for Debian/Ubuntu (optimized)
build-debian:
	@echo "Building optimized binary for Debian/Ubuntu..."
	mkdir -p build
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s -extldflags '-static'" -o build/$(BINARY_NAME)-debian-amd64 main.go
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="-w -s -extldflags '-static'" -o build/$(BINARY_NAME)-debian-arm64 main.go
	@echo "Debian binaries built:"
	@ls -lh build/$(BINARY_NAME)-debian-*
	@echo ""
	@echo "Copy to Debian system with:"
	@echo "  scp build/$(BINARY_NAME)-debian-amd64 user@debian-host:/tmp/$(BINARY_NAME)"
	@echo "  ssh user@debian-host 'sudo mv /tmp/$(BINARY_NAME) /usr/local/bin/ && sudo chmod +x /usr/local/bin/$(BINARY_NAME)'"

# Package for distribution
package: build-all
	@echo "Creating distribution packages..."
	mkdir -p dist
	# Standard Linux packages
	tar -czf dist/$(BINARY_NAME)-linux-amd64.tar.gz -C build $(BINARY_NAME)-linux-amd64
	tar -czf dist/$(BINARY_NAME)-linux-arm64.tar.gz -C build $(BINARY_NAME)-linux-arm64
	tar -czf dist/$(BINARY_NAME)-linux-386.tar.gz -C build $(BINARY_NAME)-linux-386
	# Debian static packages
	tar -czf dist/$(BINARY_NAME)-debian-amd64.tar.gz -C build $(BINARY_NAME)-debian-amd64
	tar -czf dist/$(BINARY_NAME)-debian-arm64.tar.gz -C build $(BINARY_NAME)-debian-arm64
	# macOS packages
	tar -czf dist/$(BINARY_NAME)-darwin-amd64.tar.gz -C build $(BINARY_NAME)-darwin-amd64
	tar -czf dist/$(BINARY_NAME)-darwin-arm64.tar.gz -C build $(BINARY_NAME)-darwin-arm64
	@echo "Distribution packages created in dist/ directory:"
	@ls -lh dist/*.tar.gz

# Show help
help:
	@echo "Portal CLI Makefile"
	@echo "=================="
	@echo ""
	@echo "Available targets:"
	@echo "  build          - Build the CLI binary"
	@echo "  build-release  - Build optimized binary for release"
	@echo "  build-all      - Build for multiple platforms"
	@echo "  build-debian   - Build optimized static binary for Debian/Ubuntu"
	@echo "  install        - Install CLI binary to system"
	@echo "  uninstall      - Remove CLI binary from system"
	@echo "  clean          - Clean build artifacts"
	@echo "  test           - Run tests"
	@echo "  deps           - Download dependencies"
	@echo "  deps-dev       - Install development dependencies"
	@echo "  fmt            - Format code"
	@echo "  lint           - Lint code"
	@echo "  package        - Create distribution packages"
	@echo "  package-debian - Create Debian-ready package"
	@echo "  deploy-debian  - Create deployment script for Debian"
	@echo "  run            - Run CLI locally"
	@echo "  run-*          - Run specific commands locally"
	@echo "  help           - Show this help"
	@echo ""
	@echo "Examples:"
	@echo "  make build                    # Build the CLI"
	@echo "  make build-debian             # Build for Debian/Ubuntu"
	@echo "  make package-debian           # Create Debian deployment package"
	@echo "  make install                  # Install to system"
	@echo "  make run-status               # Test status command"
	@echo "  sudo make run-install         # Test install command"