#!/bin/sh
# AgentGraph installer: downloads a release binary from GitHub and
# verifies its SHA-256 checksum before installation.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/blackrabbit1x0/agentgraph/main/install.sh | sh
#
# Pin a version:
#   AGENTGRAPH_VERSION=v0.5.1 curl -fsSL ... | sh
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

# Resolve the release tag (pin with AGENTGRAPH_VERSION).
TAG="${AGENTGRAPH_VERSION:-}"
if [ -z "$TAG" ]; then
    TAG=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | grep -o '"tag_name": *"[^"]*"' | head -1 | sed 's/.*"tag_name": *"//;s/"//')
fi
if [ -z "$TAG" ]; then
    echo "error: could not resolve the latest release" >&2
    exit 1
fi

ARTIFACT="agentgraph-$OS-$ARCH.tar.gz"
URL="https://github.com/$REPO/releases/download/$TAG/$ARTIFACT"
SUMS_URL="https://github.com/$REPO/releases/download/$TAG/SHA256SUMS"

echo "Downloading AgentGraph $TAG for $OS/$ARCH..."
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
curl -fsSL "$URL" -o "$TMP/$ARTIFACT"

# Integrity: verify against the published checksums (v0.5.1+ releases).
if curl -fsSL "$SUMS_URL" -o "$TMP/SHA256SUMS" 2>/dev/null; then
    if command -v sha256sum >/dev/null 2>&1; then
        (cd "$TMP" && grep " $ARTIFACT\$" SHA256SUMS | sha256sum -c -) \
            || { echo "error: checksum verification failed" >&2; exit 1; }
    elif command -v shasum >/dev/null 2>&1; then
        (cd "$TMP" && grep " $ARTIFACT\$" SHA256SUMS | shasum -a 256 -c -) \
            || { echo "error: checksum verification failed" >&2; exit 1; }
    else
        echo "warning: no sha256 tool found; skipping checksum verification" >&2
    fi
    echo "Checksum verified."
else
    echo "warning: SHA256SUMS not published for $TAG; skipping verification" >&2
fi

tar -xzf "$TMP/$ARTIFACT" -C "$TMP"
mv "$TMP/agentgraph" "$INSTALL_DIR/agentgraph"
chmod +x "$INSTALL_DIR/agentgraph"

echo "Installed: $INSTALL_DIR/agentgraph"
echo
echo "Get started with the demo environment:"
echo "  agentgraph demo"
echo "  agentgraph demo watch"
