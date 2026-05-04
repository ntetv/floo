#!/bin/bash
#
# Calculate SHA256 checksums for Floo release artifacts
# Usage: ./calculate-checksums.sh VERSION
# Example: ./calculate-checksums.sh v0.1.2

set -e

if [ -z "$1" ]; then
    echo "Usage: $0 VERSION"
    echo "Example: $0 v0.1.2"
    exit 1
fi

VERSION=$1
BASE_URL="https://github.com/NTETV/floo/releases/download/${VERSION}"

# Create temp directory
TEMP_DIR=$(mktemp -d)
cd "$TEMP_DIR"

echo "Downloading release artifacts for $VERSION..."
echo ""

ARTIFACTS=(
    floo-x86_64-linux-musl.tar.gz
    floo-aarch64-linux-musl.tar.gz
    floo-x86_64-macos.tar.gz
    floo-aarch64-macos.tar.gz
)

for artifact in "${ARTIFACTS[@]}"; do
    echo "==> ${artifact}"
    wget -q "${BASE_URL}/${artifact}"
    if command -v shasum &> /dev/null; then
        shasum -a 256 "${artifact}"
    else
        sha256sum "${artifact}"
    fi
    echo ""
done

# Cleanup
cd -
rm -rf "$TEMP_DIR"

echo ""
echo "Done! Update the checksums in:"
echo "  - packaging/homebrew/floo.rb"
echo "  - packaging/aur/PKGBUILD"
