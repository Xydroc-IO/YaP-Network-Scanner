#!/bin/bash
# YaP Network Scanner Launcher
# Checks dependencies and launches the application

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CORE_DIR="$PROJECT_DIR/core"

# Check if Python 3 is available
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is not installed."
    echo "Please install Python 3.7 or higher."
    exit 1
fi

# Check Python version
PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
REQUIRED_VERSION="3.7"

if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
    echo "Error: Python 3.7 or higher is required. Found: $PYTHON_VERSION"
    exit 1
fi

# Check for required Python packages
MISSING_PACKAGES=()

if ! python3 -c "import tkinter" 2>/dev/null; then
    MISSING_PACKAGES+=("python3-tk")
fi

if ! python3 -c "import PIL" 2>/dev/null; then
    MISSING_PACKAGES+=("Pillow")
fi

if ! python3 -c "import pystray" 2>/dev/null; then
    MISSING_PACKAGES+=("pystray")
fi

# Install missing packages if any
if [ ${#MISSING_PACKAGES[@]} -gt 0 ]; then
    echo "Missing dependencies detected: ${MISSING_PACKAGES[*]}"
    echo "Attempting to install via pip..."
    
    for package in "${MISSING_PACKAGES[@]}"; do
        if [ "$package" = "python3-tk" ]; then
            echo "Please install python3-tk using your system package manager:"
            echo "  Debian/Ubuntu: sudo apt install python3-tk"
            echo "  Fedora: sudo dnf install python3-tkinter"
            echo "  Arch: sudo pacman -S python-tkinter"
        else
            python3 -m pip install --user "$package" 2>/dev/null || {
                echo "Failed to install $package. Please install manually:"
                echo "  pip install $package"
            }
        fi
    done
fi

# Change to core directory
cd "$CORE_DIR" || exit 1

# Run the application
echo "Starting YaP Network Scanner..."
python3 network_manager.py

