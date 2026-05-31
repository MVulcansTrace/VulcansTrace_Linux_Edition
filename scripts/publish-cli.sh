#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CLI_PROJECT="$PROJECT_ROOT/VulcansTrace.Linux.Cli"
PUBLISH_DIR="$PROJECT_ROOT/publish"

echo "Publishing VulcansTrace CLI..."
echo "=============================="

# Publish as self-contained single-file for Linux x64
dotnet publish "$CLI_PROJECT" \
    -c Release \
    -r linux-x64 \
    --self-contained true \
    -p:PublishSingleFile=true \
    -p:PublishTrimmed=false \
    -o "$PUBLISH_DIR"

EXE_PATH="$PUBLISH_DIR/vulcanstrace"
if [ ! -f "$EXE_PATH" ]; then
    echo "ERROR: Expected published binary not found at $EXE_PATH"
    exit 1
fi

echo ""
echo "Published to: $EXE_PATH"
echo ""

# Make executable
chmod +x "$EXE_PATH"

# Optionally install system-wide
if [ "${INSTALL_SYSTEM:-}" = "1" ]; then
    echo "Installing to /usr/local/bin/vulcanstrace (requires sudo)..."
    sudo cp "$EXE_PATH" /usr/local/bin/vulcanstrace
    sudo chmod +x /usr/local/bin/vulcanstrace
    echo "Installed. Version:"
    /usr/local/bin/vulcanstrace --help | head -1
else
    echo "To install system-wide, run:"
    echo "  INSTALL_SYSTEM=1 $0"
    echo ""
    echo "Or manually symlink:"
    echo "  sudo ln -sf $EXE_PATH /usr/local/bin/vulcanstrace"
fi
