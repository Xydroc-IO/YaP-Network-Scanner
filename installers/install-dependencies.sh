#!/bin/bash
# YaP Network Scanner - Dependency Installer
# Automatically detects Linux distribution and installs required dependencies

set -e

echo "YaP Network Scanner - Dependency Installer"
echo "=========================================="
echo ""

# Detect Linux distribution
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
        DISTRO_LIKE=$ID_LIKE
    elif [ -f /etc/lsb-release ]; then
        . /etc/lsb-release
        DISTRO=$DISTRIB_ID
    elif [ -f /etc/debian_version ]; then
        DISTRO="debian"
    elif [ -f /etc/fedora-release ]; then
        DISTRO="fedora"
    elif [ -f /etc/arch-release ]; then
        DISTRO="arch"
    elif [ -f /etc/SuSE-release ]; then
        DISTRO="suse"
    else
        DISTRO="unknown"
    fi
    
    DISTRO=$(echo "$DISTRO" | tr '[:upper:]' '[:lower:]')
    DISTRO_LIKE=$(echo "$DISTRO_LIKE" | tr '[:upper:]' '[:lower:]')
}

# Install dependencies based on distribution
install_dependencies() {
    case $DISTRO in
        ubuntu|debian|linuxmint|pop|elementary)
            echo "Detected: Debian/Ubuntu-based distribution"
            echo "Installing dependencies..."
            sudo apt update
            sudo apt install -y python3 python3-pip python3-tk python3-dev
            ;;
        fedora|rhel|centos)
            echo "Detected: Fedora/RHEL-based distribution"
            echo "Installing dependencies..."
            if command -v dnf &> /dev/null; then
                sudo dnf install -y python3 python3-pip python3-tkinter python3-devel
            else
                sudo yum install -y python3 python3-pip python3-tkinter python3-devel
            fi
            ;;
        arch|manjaro|endeavour|garuda)
            echo "Detected: Arch-based distribution"
            echo "Installing dependencies..."
            sudo pacman -S --noconfirm python python-pip python-tkinter
            ;;
        opensuse*|sles)
            echo "Detected: openSUSE/SLE"
            echo "Installing dependencies..."
            sudo zypper install -y python3 python3-pip python3-tk
            ;;
        alpine)
            echo "Detected: Alpine Linux"
            echo "Installing dependencies..."
            sudo apk add python3 py3-pip python3-tkinter
            ;;
        solus)
            echo "Detected: Solus"
            echo "Installing dependencies..."
            sudo eopkg install -y python3 python3-pip python3-tk
            ;;
        gentoo)
            echo "Detected: Gentoo"
            echo "Installing dependencies..."
            sudo emerge --ask --noreplace dev-lang/python dev-python/pip
            ;;
        *)
            echo "Unknown distribution: $DISTRO"
            echo "Please install manually:"
            echo "  - Python 3.7+"
            echo "  - python3-tk or python3-tkinter"
            echo "  - pip"
            exit 1
            ;;
    esac
}

# Install Python packages
install_python_packages() {
    echo ""
    echo "Installing Python packages..."
    python3 -m pip install --user --upgrade pip
    python3 -m pip install --user -r "$(dirname "$0")/../requirements.txt"
}

# Main
detect_distro
install_dependencies
install_python_packages

echo ""
echo "Installation complete!"
echo "You can now run YaP Network Scanner using:"
echo "  ./launchers/start-network-scanner.sh"

