#!/bin/bash
# null.log installation script for Linux/macOS
set -e

echo "╔════════════════════════════════════════════════════════╗"
echo "║         null.log - Installation Script                ║"
echo "╚════════════════════════════════════════════════════════╝"
echo ""

# Detect OS
OS="$(uname -s)"
ARCH="$(uname -m)"

echo "[1/5] Detecting system..."
echo "  OS: $OS"
echo "  Architecture: $ARCH"
echo ""

# Check if Go is installed
if ! command -v go >/dev/null 2>&1; then
    echo "ERROR: Go is not installed!"
    echo ""
    echo "Please install Go 1.21+ from: https://go.dev/dl/"
    echo ""
    echo "On Debian/Ubuntu/Kali:"
    echo "  sudo apt update"
    echo "  sudo apt install golang-go"
    echo ""
    exit 1
fi

GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
echo "[2/5] Go detected: $GO_VERSION"
echo ""

# Installation directory
INSTALL_DIR="/usr/local/bin"
LOCAL_BIN="$HOME/.local/bin"

# Check if we need sudo
if [ -w "$INSTALL_DIR" ]; then
    USE_SUDO=""
    TARGET_DIR="$INSTALL_DIR"
else
    # Try local bin if no sudo
    if [ "$EUID" -ne 0 ]; then
        echo "  No sudo access, installing to $LOCAL_BIN"
        TARGET_DIR="$LOCAL_BIN"
        USE_SUDO=""
        mkdir -p "$TARGET_DIR"
    else
        USE_SUDO="sudo"
        TARGET_DIR="$INSTALL_DIR"
    fi
fi

echo "[3/5] Building from source..."
echo "  Target: $TARGET_DIR/null-log"
echo ""

# Build the binary
go build -ldflags="-s -w" -o null-log cmd/null-log/main.go

if [ $? -ne 0 ]; then
    echo "ERROR: Build failed!"
    exit 1
fi

echo "  ✓ Build successful"
echo ""

echo "[4/5] Installing binary..."
# Install the binary
$USE_SUDO mv null-log "$TARGET_DIR/null-log"
$USE_SUDO chmod +x "$TARGET_DIR/null-log"
echo "  ✓ Binary installed to $TARGET_DIR/null-log"
echo ""

echo "[5/5] Setting up configuration..."
# Create config directory
CONFIG_DIR="$HOME/.null.log"
mkdir -p "$CONFIG_DIR/rules"
mkdir -p "$CONFIG_DIR/intel"

# Copy bundled rules
if [ -d "./rules" ]; then
    cp -r ./rules/* "$CONFIG_DIR/rules/"
    RULE_COUNT=$(ls -1 "$CONFIG_DIR/rules"/*.yml 2>/dev/null | wc -l)
    echo "  ✓ Installed $RULE_COUNT detection rules"
fi

# Copy threat intelligence
if [ -f "./assets/threat-intel.yml" ]; then
    cp ./assets/threat-intel.yml "$CONFIG_DIR/intel/"
    echo "  ✓ Installed threat intelligence database"
fi
echo ""

echo "╔════════════════════════════════════════════════════════╗"
echo "║         ✓ Installation Complete!                      ║"
echo "╚════════════════════════════════════════════════════════╝"
echo ""
echo "Installed to: $TARGET_DIR/null-log"
echo "Config dir:   $CONFIG_DIR"
echo "Rules:        $RULE_COUNT loaded"
echo ""

# Check if directory is in PATH
if command -v null-log >/dev/null 2>&1; then
    echo "✓ null-log is in your PATH"
    echo ""
    echo "Quick start:"
    echo "  null-log live        # Real-time threat monitoring"
    echo "  null-log net         # Network threat scanner"
    echo "  null-log hunt        # Hunt through historical logs"
    echo "  null-log --help      # Show all commands"
else
    echo "⚠ Add to PATH:"
    if [ "$TARGET_DIR" = "$LOCAL_BIN" ]; then
        echo ""
        echo "  echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.bashrc"
        echo "  source ~/.bashrc"
        echo ""
        echo "Or run directly:"
        echo "  $TARGET_DIR/null-log live"
    else
        echo ""
        echo "  Already in system PATH, but may need to reload shell"
        echo "  Run: hash -r"
        echo ""
        echo "Then try: null-log live"
    fi
fi
echo ""
