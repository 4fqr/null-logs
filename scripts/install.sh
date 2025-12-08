#!/bin/bash
# null.log installation script for Linux/macOS
set -e

echo "Installing null.log..."
echo ""

# Detect OS
OS="$(uname -s)"
ARCH="$(uname -m)"

# Determine binary name
if [ "$OS" = "Linux" ]; then
    BINARY="null-log-linux-${ARCH}"
elif [ "$OS" = "Darwin" ]; then
    BINARY="null-log-darwin-${ARCH}"
else
    echo "Unsupported operating system: $OS"
    exit 1
fi

# Installation directory
INSTALL_DIR="$HOME/bin"
mkdir -p "$INSTALL_DIR"

# Download URL (in production, this would be a real URL)
DOWNLOAD_URL="https://github.com/nullsector/null-log/releases/latest/download/${BINARY}"

echo "Downloading null.log for $OS ($ARCH)..."

# Check if curl or wget is available
if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$DOWNLOAD_URL" -o "$INSTALL_DIR/null.log" || {
        echo "Download failed. Installing from local build..."
        # Fallback for local development
        if [ -f "./null-log" ]; then
            cp ./null-log "$INSTALL_DIR/null.log"
        else
            echo "ERROR: Binary not found"
            exit 1
        fi
    }
elif command -v wget >/dev/null 2>&1; then
    wget -q "$DOWNLOAD_URL" -O "$INSTALL_DIR/null.log" || {
        echo "Download failed. Installing from local build..."
        if [ -f "./null-log" ]; then
            cp ./null-log "$INSTALL_DIR/null.log"
        else
            echo "ERROR: Binary not found"
            exit 1
        fi
    }
else
    echo "ERROR: curl or wget is required"
    exit 1
fi

# Make executable
chmod +x "$INSTALL_DIR/null.log"

# Create config directory
CONFIG_DIR="$HOME/.null.log"
mkdir -p "$CONFIG_DIR/rules"
mkdir -p "$CONFIG_DIR/intel"

# Copy bundled rules if available
if [ -d "./rules" ]; then
    cp -r ./rules/* "$CONFIG_DIR/rules/"
fi

echo ""
echo "✓ Installation complete!"
echo ""
echo "Installation location: $INSTALL_DIR/null.log"
echo ""

# Check if bin directory is in PATH
if [[ ":$PATH:" == *":$INSTALL_DIR:"* ]]; then
    echo "You can now run: null.log --help"
else
    echo "Add the following line to your ~/.bashrc or ~/.zshrc:"
    echo ""
    echo "  export PATH=\"\$HOME/bin:\$PATH\""
    echo ""
    echo "Then run: source ~/.bashrc (or ~/.zshrc)"
    echo ""
    echo "Or run directly: $INSTALL_DIR/null.log --help"
fi

echo ""
echo "Get started with: null.log live"
