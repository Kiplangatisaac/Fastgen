#!/bin/bash
# fastgen - Ultra-fast password candidate generator
# Install script: curl -sSL https://.../install.sh | bash
# Or manually: cp fastgen.py ~/.local/bin/fastgen && chmod +x ~/.local/bin/fastgen

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="${HOME}/.local/bin"
SCRIPT_NAME="fastgen"

echo "Installing fastgen..."

# Create install directory
mkdir -p "$INSTALL_DIR"

# Copy script
cp "$SCRIPT_DIR/fastgen.py" "$INSTALL_DIR/$SCRIPT_NAME"
chmod +x "$INSTALL_DIR/$SCRIPT_NAME"

# Check if ~/.local/bin is in PATH
if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    echo ""
    echo "⚠️  $INSTALL_DIR is not in your PATH"
    echo "Add this to your ~/.bashrc or ~/.zshrc:"
    echo "    export PATH=\"\$HOME/.local/bin:\$PATH\""
    echo ""
    echo "Then reload: source ~/.bashrc"
fi

# Check for rockyou.txt
if [[ ! -f "$HOME/Downloads/rockyou.txt" ]]; then
    echo ""
    echo "📥 rockyou.txt not found in ~/Downloads"
    echo "Download it with:"
    echo "    wget -O ~/Downloads/rockyou.txt.gz https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt.gz"
    echo "    gunzip ~/Downloads/rockyou.txt.gz"
    echo ""
    echo "Or specify custom path: fastgen -w /path/to/wordlist.txt"
fi

echo ""
echo "✅ fastgen installed to $INSTALL_DIR/$SCRIPT_NAME"
echo ""
echo "Usage examples:"
echo "  fastgen --progress                    # Auto-finds rockyou.txt, shows progress"
echo "  fastgen -w rockyou.txt | hashcat -m 0 hashes.txt    # Pipe to hashcat (max speed)"
echo "  fastgen -w rockyou.txt -l 1M --progress            # Limit 1M, show progress"
echo "  fastgen --brute --brute-length 4:6 | hashcat...  # Brute force only"
echo "  fastgen --find-rockyou                # Show where rockyou.txt was found"
echo "  fastgen -w wordlist.txt | john --pipe --format=NT hashes.txt"