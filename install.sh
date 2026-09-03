#!/bin/sh
# AgentGraph installer: downloads the latest release binary from GitHub.
# Usage: curl -fsSL https://raw.githubusercontent.com/blackrabbit1x0/agentgraph/main/install.sh | sh
set -e

REPO="blackrabbit1x0/agentgraph"

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in
    x86_64|amd64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *)
        echo "error: unsupported architecture $ARCH" >&2
        exit 1
        ;;
esac
case "$OS" in
    linux|darwin) ;;
    *)
        echo "error: unsupported OS $OS (use the release assets directly on Windows)" >&2
        exit 1
        ;;
esac

INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
if [ ! -w "$INSTALL_DIR" ] 2>/dev/null; then
    INSTALL_DIR="$HOME/.local/bin"
    mkdir -p "$INSTALL_DIR"
fi

# Resolve the latest release tag.
TAG=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | grep -o '"tag_name": *"[^"]*"' | head -1 | sed 's/.*"tag_name": *"//;s/"//')
if [ -z "$TAG" ]; then
    echo "error: could not resolve the latest release" >&2
    exit 1
fi

URL="https://github.com/$REPO/releases/download/$TAG/agentgraph-$OS-$ARCH.tar.gz"
echo "Downloading AgentGraph $TAG for $OS/$ARCH..."
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
curl -fsSL "$URL" -o "$TMP/agentgraph.tar.gz"
tar -xzf "$TMP/agentgraph.tar.gz" -C "$TMP"
mv "$TMP/agentgraph" "$INSTALL_DIR/agentgraph"
chmod +x "$INSTALL_DIR/agentgraph"

echo "Installed: $INSTALL_DIR/agentgraph"
echo
echo "Get started with the demo environment:"
echo "  agentgraph demo"
echo "  agentgraph demo watch"
