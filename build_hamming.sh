#!/bin/bash
# Build script for Linux/macOS

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HAMMING_DIR="${SCRIPT_DIR}/c_hamming"

cd "${HAMMING_DIR}"

echo "Building Hamming binary for $(uname -s)..."

# Check if gcc is available
if ! command -v gcc &> /dev/null; then
    echo "Error: gcc is not installed. Please install gcc to build the Hamming binary."
    exit 1
fi

# Build the binary
gcc -Wall -Wextra -std=c99 -O3 -o hamming hamming.c

if [ -f hamming ]; then
    echo "✅ Successfully built hamming binary"
    chmod +x hamming
else
    echo "❌ Build failed: hamming binary not created"
    exit 1
fi

