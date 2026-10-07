#!/bin/bash
set -e

echo " BetterProxy Installer"
echo ""

# Detect OS and architecture
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case $ARCH in
    x86_64)
        ARCH="amd64"
        ;;
    arm64|aarch64)
        ARCH="arm64"
        ;;
    *)
        echo " Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

# Determine install location
if [ -w "/usr/local/bin" ]; then
    INSTALL_DIR="/usr/local/bin"
elif [ -w "$HOME/.local/bin" ]; then
    INSTALL_DIR="$HOME/.local/bin"
    mkdir -p "$INSTALL_DIR"
else
    INSTALL_DIR="$HOME/bin"
    mkdir -p "$INSTALL_DIR"
fi

echo " Detected: $OS/$ARCH"
echo " Install directory: $INSTALL_DIR"
echo ""

# Check if already installed
if [ -f "$INSTALL_DIR/betterproxy" ]; then
    echo "WARNING:  BetterProxy is already installed at $INSTALL_DIR/betterproxy"
    read -p "Overwrite? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo " Installation cancelled"
        exit 0
    fi
fi

# Build from source
echo " Building from source..."
if [ ! -f "./build.sh" ]; then
    echo " build.sh not found. Are you in the betterproxy directory?"
    exit 1
fi

chmod +x build.sh
./build.sh

# Install binary
echo " Installing to $INSTALL_DIR..."
cp betterproxy "$INSTALL_DIR/betterproxy"
chmod +x "$INSTALL_DIR/betterproxy"

# Verify installation
if command -v betterproxy &> /dev/null; then
    echo " Installation successful!"
    echo ""
    betterproxy --version || betterproxy --help | head -5
    echo ""
    echo " Get started:"
    echo "betterproxy test --script=examples/spam-filter.star"
    echo "betterproxy --help"
else
    echo "WARNING:  Installation complete but betterproxy not in PATH"
    echo "Add to PATH: export PATH=\"$INSTALL_DIR:\$PATH\""
    echo "Or run directly: $INSTALL_DIR/betterproxy"
fi
