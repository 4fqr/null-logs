# Makefile for null.log cross-platform builds

VERSION := 1.0.0
BINARY := null-log
MAIN := cmd/null-log/main.go

# Build flags
LDFLAGS := -ldflags "-s -w -X main.version=$(VERSION)"
BUILD_FLAGS := $(LDFLAGS) -trimpath

# Output directory
DIST := dist

.PHONY: all clean build linux windows darwin test install

all: clean build

build: linux windows darwin

linux:
	@echo "Building for Linux..."
	@mkdir -p $(DIST)
	GOOS=linux GOARCH=amd64 go build $(BUILD_FLAGS) -o $(DIST)/$(BINARY)-linux-amd64 $(MAIN)
	GOOS=linux GOARCH=arm64 go build $(BUILD_FLAGS) -o $(DIST)/$(BINARY)-linux-arm64 $(MAIN)
	@echo "✓ Linux builds complete"

windows:
	@echo "Building for Windows..."
	@mkdir -p $(DIST)
	GOOS=windows GOARCH=amd64 go build $(BUILD_FLAGS) -o $(DIST)/$(BINARY)-windows-amd64.exe $(MAIN)
	GOOS=windows GOARCH=386 go build $(BUILD_FLAGS) -o $(DIST)/$(BINARY)-windows-386.exe $(MAIN)
	@echo "✓ Windows builds complete"

darwin:
	@echo "Building for macOS..."
	@mkdir -p $(DIST)
	GOOS=darwin GOARCH=amd64 go build $(BUILD_FLAGS) -o $(DIST)/$(BINARY)-darwin-amd64 $(MAIN)
	GOOS=darwin GOARCH=arm64 go build $(BUILD_FLAGS) -o $(DIST)/$(BINARY)-darwin-arm64 $(MAIN)
	@echo "✓ macOS builds complete"

# Build for current platform only
dev:
	@echo "Building for current platform..."
	go build $(BUILD_FLAGS) -o $(BINARY) $(MAIN)
	@echo "✓ Development build complete: ./$(BINARY)"

# Quick build (no optimization)
quick:
	@echo "Quick build (debug mode)..."
	go build -o $(BINARY) $(MAIN)
	@echo "✓ Build complete: ./$(BINARY)"

# Install to system
install: dev
	@echo "Installing null-log..."
	@if [ -w /usr/local/bin ]; then \
		cp $(BINARY) /usr/local/bin/$(BINARY); \
		chmod +x /usr/local/bin/$(BINARY); \
		echo "✓ Installed to /usr/local/bin/$(BINARY)"; \
	else \
		mkdir -p $(HOME)/.local/bin; \
		cp $(BINARY) $(HOME)/.local/bin/$(BINARY); \
		chmod +x $(HOME)/.local/bin/$(BINARY); \
		echo "✓ Installed to $(HOME)/.local/bin/$(BINARY)"; \
		echo "⚠  Add to PATH: export PATH=\"\$$HOME/.local/bin:\$$PATH\""; \
	fi
	@mkdir -p $(HOME)/.null.log/rules
	@cp -r rules/* $(HOME)/.null.log/rules/ 2>/dev/null || true
	@echo "✓ Rules installed to $(HOME)/.null.log/rules"

# Uninstall
uninstall:
	@echo "Uninstalling null-log..."
	@rm -f /usr/local/bin/$(BINARY)
	@rm -f $(HOME)/.local/bin/$(BINARY)
	@echo "✓ Uninstalled (config kept at $(HOME)/.null.log)"

# Run tests
test:
	go test -v -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Install locally
install: dev
	@echo "Installing to ~/bin..."
	@mkdir -p ~/bin
	@cp $(BINARY) ~/bin/null.log
	@chmod +x ~/bin/null.log
	@echo "✓ Installed to ~/bin/null.log"

# Clean build artifacts
clean:
	@echo "Cleaning..."
	@rm -rf $(DIST)
	@rm -f $(BINARY)
	@rm -f coverage.out coverage.html
	@echo "✓ Clean complete"

# Download dependencies
deps:
	go mod download
	go mod tidy

# Format code
fmt:
	go fmt ./...
	gofmt -s -w .

# Run linter
lint:
	golangci-lint run

# Create release package
package: build
	@echo "Creating release packages..."
	@mkdir -p $(DIST)/release
	
	# Linux
	tar -czf $(DIST)/release/$(BINARY)-$(VERSION)-linux-amd64.tar.gz \
		-C $(DIST) $(BINARY)-linux-amd64 \
		-C ../rules .
	
	# macOS
	tar -czf $(DIST)/release/$(BINARY)-$(VERSION)-darwin-amd64.tar.gz \
		-C $(DIST) $(BINARY)-darwin-amd64 \
		-C ../rules .
	
	# Windows
	cd $(DIST) && zip -r release/$(BINARY)-$(VERSION)-windows-amd64.zip $(BINARY)-windows-amd64.exe ../rules
	
	@echo "✓ Release packages created in $(DIST)/release"

# Show help
help:
	@echo "null.log Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all      - Build for all platforms (default)"
	@echo "  build    - Build for all platforms"
	@echo "  linux    - Build for Linux (amd64, arm64)"
	@echo "  windows  - Build for Windows (amd64, 386)"
	@echo "  darwin   - Build for macOS (amd64, arm64)"
	@echo "  dev      - Build for current platform only"
	@echo "  test     - Run tests with coverage"
	@echo "  install  - Install to ~/bin"
	@echo "  clean    - Remove build artifacts"
	@echo "  deps     - Download dependencies"
	@echo "  fmt      - Format code"
	@echo "  lint     - Run linter"
	@echo "  package  - Create release packages"
	@echo "  help     - Show this help"
