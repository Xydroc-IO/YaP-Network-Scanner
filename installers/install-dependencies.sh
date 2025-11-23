#!/bin/bash
# YaP Network Scanner - Dependency Installer
# Automatically detects Linux distribution and installs required dependencies
# Compatible with all major Linux distributions and desktop environments
# Supports: GNOME, KDE, XFCE, Cinnamon, MATE, LXDE, LXQt, and others

# Exit on errors for critical components, but continue for optional ones
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
            sudo apt install -y python3 python3-pip python3-tk python3-dev nmap curl
            
            # Install Metasploit Framework (optional, don't fail if it doesn't work)
            set +e  # Don't exit on Metasploit installation errors
            echo "Installing Metasploit Framework..."
            if ! command -v msfconsole >/dev/null 2>&1; then
                # Try to install from package manager first
                if sudo apt install -y metasploit-framework 2>/dev/null; then
                    echo "✓ Metasploit Framework installed via apt"
                else
                    echo "⚠ Metasploit Framework not available in repositories"
                    echo "  Attempting installation via Rapid7 installer..."
                    if command -v curl >/dev/null 2>&1; then
                        if curl -fsSL https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb | sudo bash 2>/dev/null; then
                            if [ -f /opt/metasploit-framework/bin/msfupdate ]; then
                                sudo /opt/metasploit-framework/bin/msfupdate 2>/dev/null || true
                                echo "✓ Metasploit Framework installed via Rapid7 installer"
                            else
                                echo "⚠ Metasploit Framework installation failed"
                                echo "  You can install it manually from: https://www.metasploit.com/"
                            fi
                        else
                            echo "⚠ Metasploit Framework installation failed"
                            echo "  You can install it manually from: https://www.metasploit.com/"
                        fi
                    else
                        echo "⚠ curl not available, cannot install Metasploit Framework"
                        echo "  You can install it manually from: https://www.metasploit.com/"
                    fi
                fi
            else
                echo "✓ Metasploit Framework already installed"
            fi
            set -e  # Re-enable error handling
            ;;
        fedora|rhel|centos)
            echo "Detected: Fedora/RHEL-based distribution"
            echo "Installing dependencies..."
            if command -v dnf &> /dev/null; then
                sudo dnf install -y python3 python3-pip python3-tkinter python3-devel nmap curl
                # Install Metasploit Framework (optional, don't fail if it doesn't work)
                set +e  # Don't exit on Metasploit installation errors
                echo "Installing Metasploit Framework..."
                if ! command -v msfconsole >/dev/null 2>&1; then
                    if sudo dnf install -y metasploit-framework 2>/dev/null; then
                        echo "✓ Metasploit Framework installed via dnf"
                    else
                        echo "⚠ Metasploit Framework not available in repositories"
                        echo "  Attempting installation via Rapid7 installer..."
                        if command -v curl >/dev/null 2>&1; then
                            if curl -fsSL https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb | sudo bash 2>/dev/null; then
                                if [ -f /opt/metasploit-framework/bin/msfupdate ]; then
                                    sudo /opt/metasploit-framework/bin/msfupdate 2>/dev/null || true
                                    echo "✓ Metasploit Framework installed via Rapid7 installer"
                                else
                                    echo "⚠ Metasploit Framework installation failed"
                                    echo "  You can install it manually from: https://www.metasploit.com/"
                                fi
                            else
                                echo "⚠ Metasploit Framework installation failed"
                                echo "  You can install it manually from: https://www.metasploit.com/"
                            fi
                        else
                            echo "⚠ curl not available, cannot install Metasploit Framework"
                            echo "  You can install it manually from: https://www.metasploit.com/"
                        fi
                    fi
                else
                    echo "✓ Metasploit Framework already installed"
                fi
                set -e  # Re-enable error handling
            else
                sudo yum install -y python3 python3-pip python3-tkinter python3-devel nmap curl
                # Install Metasploit Framework (optional, don't fail if it doesn't work)
                set +e  # Don't exit on Metasploit installation errors
                echo "Installing Metasploit Framework..."
                if ! command -v msfconsole >/dev/null 2>&1; then
                    if sudo yum install -y metasploit-framework 2>/dev/null; then
                        echo "✓ Metasploit Framework installed via yum"
                    else
                        echo "⚠ Metasploit Framework not available in repositories"
                        echo "  Attempting installation via Rapid7 installer..."
                        if command -v curl >/dev/null 2>&1; then
                            if curl -fsSL https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb | sudo bash 2>/dev/null; then
                                if [ -f /opt/metasploit-framework/bin/msfupdate ]; then
                                    sudo /opt/metasploit-framework/bin/msfupdate 2>/dev/null || true
                                    echo "✓ Metasploit Framework installed via Rapid7 installer"
                                else
                                    echo "⚠ Metasploit Framework installation failed"
                                    echo "  You can install it manually from: https://www.metasploit.com/"
                                fi
                            else
                                echo "⚠ Metasploit Framework installation failed"
                                echo "  You can install it manually from: https://www.metasploit.com/"
                            fi
                        else
                            echo "⚠ curl not available, cannot install Metasploit Framework"
                            echo "  You can install it manually from: https://www.metasploit.com/"
                        fi
                    fi
                else
                    echo "✓ Metasploit Framework already installed"
                fi
                set -e  # Re-enable error handling
            fi
            ;;
        arch|manjaro|endeavour|garuda)
            echo "Detected: Arch-based distribution"
            echo "Installing dependencies..."
            sudo pacman -S --noconfirm python python-pip python-tkinter nmap curl
            
            # Install Metasploit Framework (optional, don't fail if it doesn't work)
            set +e  # Don't exit on Metasploit installation errors
            echo "Installing Metasploit Framework..."
            if ! command -v msfconsole >/dev/null 2>&1; then
                if sudo pacman -S --noconfirm metasploit 2>/dev/null; then
                    echo "✓ Metasploit Framework installed via pacman"
                else
                    echo "⚠ Metasploit Framework not available in repositories"
                    echo "  Attempting installation via Rapid7 installer..."
                    if command -v curl >/dev/null 2>&1; then
                        if curl -fsSL https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb | sudo bash 2>/dev/null; then
                            if [ -f /opt/metasploit-framework/bin/msfupdate ]; then
                                sudo /opt/metasploit-framework/bin/msfupdate 2>/dev/null || true
                                echo "✓ Metasploit Framework installed via Rapid7 installer"
                            else
                                echo "⚠ Metasploit Framework installation failed"
                                echo "  You can install it manually from: https://www.metasploit.com/"
                            fi
                        else
                            echo "⚠ Metasploit Framework installation failed"
                            echo "  You can install it manually from: https://www.metasploit.com/"
                        fi
                    else
                        echo "⚠ curl not available, cannot install Metasploit Framework"
                        echo "  You can install it manually from: https://www.metasploit.com/"
                    fi
                fi
            else
                echo "✓ Metasploit Framework already installed"
            fi
            set -e  # Re-enable error handling
            ;;
        opensuse*|sles)
            echo "Detected: openSUSE/SLE"
            echo "Installing dependencies..."
            sudo zypper install -y python3 python3-pip python3-tk nmap
            
            # Install Metasploit Framework (optional, don't fail if it doesn't work)
            set +e  # Don't exit on Metasploit installation errors
            echo "Installing Metasploit Framework..."
            if ! command -v msfconsole >/dev/null 2>&1; then
                echo "⚠ Metasploit Framework not available in openSUSE repositories"
                echo "  Attempting installation via Rapid7 installer..."
                if command -v curl >/dev/null 2>&1; then
                    if curl -fsSL https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb | sudo bash 2>/dev/null; then
                        if [ -f /opt/metasploit-framework/bin/msfupdate ]; then
                            sudo /opt/metasploit-framework/bin/msfupdate 2>/dev/null || true
                            echo "✓ Metasploit Framework installed via Rapid7 installer"
                        else
                            echo "⚠ Metasploit Framework installation failed"
                            echo "  You can install it manually from: https://www.metasploit.com/"
                        fi
                    else
                        echo "⚠ Metasploit Framework installation failed"
                        echo "  You can install it manually from: https://www.metasploit.com/"
                    fi
                else
                    echo "⚠ curl not available, cannot install Metasploit Framework"
                    echo "  You can install it manually from: https://www.metasploit.com/"
                fi
            else
                echo "✓ Metasploit Framework already installed"
            fi
            set -e  # Re-enable error handling
            ;;
        alpine)
            echo "Detected: Alpine Linux"
            echo "Installing dependencies..."
            sudo apk add python3 py3-pip python3-tkinter nmap curl
            
            # Install Metasploit Framework (optional, don't fail if it doesn't work)
            set +e  # Don't exit on Metasploit installation errors
            echo "Installing Metasploit Framework..."
            if ! command -v msfconsole >/dev/null 2>&1; then
                echo "⚠ Metasploit Framework not available in Alpine repositories"
                echo "  Attempting installation via Rapid7 installer..."
                if command -v curl >/dev/null 2>&1; then
                    if curl -fsSL https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb | sudo bash 2>/dev/null; then
                        if [ -f /opt/metasploit-framework/bin/msfupdate ]; then
                            sudo /opt/metasploit-framework/bin/msfupdate 2>/dev/null || true
                            echo "✓ Metasploit Framework installed via Rapid7 installer"
                        else
                            echo "⚠ Metasploit Framework installation failed"
                            echo "  You can install it manually from: https://www.metasploit.com/"
                        fi
                    else
                        echo "⚠ Metasploit Framework installation failed"
                        echo "  You can install it manually from: https://www.metasploit.com/"
                    fi
                else
                    echo "⚠ curl not available, cannot install Metasploit Framework"
                    echo "  You can install it manually from: https://www.metasploit.com/"
                fi
            else
                echo "✓ Metasploit Framework already installed"
            fi
            set -e  # Re-enable error handling
            ;;
        solus)
            echo "Detected: Solus"
            echo "Installing dependencies..."
            sudo eopkg install -y python3 python3-pip python3-tk nmap curl
            
            # Install Metasploit Framework (optional, don't fail if it doesn't work)
            set +e  # Don't exit on Metasploit installation errors
            echo "Installing Metasploit Framework..."
            if ! command -v msfconsole >/dev/null 2>&1; then
                echo "⚠ Metasploit Framework not available in Solus repositories"
                echo "  Attempting installation via Rapid7 installer..."
                if command -v curl >/dev/null 2>&1; then
                    if curl -fsSL https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb | sudo bash 2>/dev/null; then
                        if [ -f /opt/metasploit-framework/bin/msfupdate ]; then
                            sudo /opt/metasploit-framework/bin/msfupdate 2>/dev/null || true
                            echo "✓ Metasploit Framework installed via Rapid7 installer"
                        else
                            echo "⚠ Metasploit Framework installation failed"
                            echo "  You can install it manually from: https://www.metasploit.com/"
                        fi
                    else
                        echo "⚠ Metasploit Framework installation failed"
                        echo "  You can install it manually from: https://www.metasploit.com/"
                    fi
                else
                    echo "⚠ curl not available, cannot install Metasploit Framework"
                    echo "  You can install it manually from: https://www.metasploit.com/"
                fi
            else
                echo "✓ Metasploit Framework already installed"
            fi
            set -e  # Re-enable error handling
            ;;
        gentoo)
            echo "Detected: Gentoo"
            echo "Installing dependencies..."
            sudo emerge --ask --noreplace dev-lang/python dev-python/pip net-analyzer/nmap net-misc/curl
            
            # Install Metasploit Framework
            echo "Installing Metasploit Framework..."
            # Install Metasploit Framework (optional, don't fail if it doesn't work)
            set +e  # Don't exit on Metasploit installation errors
            echo "Installing Metasploit Framework..."
            if ! command -v msfconsole >/dev/null 2>&1; then
                if sudo emerge --ask metasploit 2>/dev/null; then
                    echo "✓ Metasploit Framework installed via emerge"
                else
                    echo "⚠ Metasploit Framework not available in Gentoo repositories"
                    echo "  Attempting installation via Rapid7 installer..."
                    if command -v curl >/dev/null 2>&1; then
                        if curl -fsSL https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb | sudo bash 2>/dev/null; then
                            if [ -f /opt/metasploit-framework/bin/msfupdate ]; then
                                sudo /opt/metasploit-framework/bin/msfupdate 2>/dev/null || true
                                echo "✓ Metasploit Framework installed via Rapid7 installer"
                            else
                                echo "⚠ Metasploit Framework installation failed"
                                echo "  You can install it manually from: https://www.metasploit.com/"
                            fi
                        else
                            echo "⚠ Metasploit Framework installation failed"
                            echo "  You can install it manually from: https://www.metasploit.com/"
                        fi
                    else
                        echo "⚠ curl not available, cannot install Metasploit Framework"
                        echo "  You can install it manually from: https://www.metasploit.com/"
                    fi
                fi
            else
                echo "✓ Metasploit Framework already installed"
            fi
            set -e  # Re-enable error handling
            ;;
        *)
            echo "Unknown distribution: $DISTRO"
            echo "Installing basic dependencies..."
            # Try to install common packages
            set +e  # Don't exit on errors for unknown distros
            if command -v apt >/dev/null 2>&1; then
                sudo apt update && sudo apt install -y python3 python3-pip python3-tk nmap curl || true
            elif command -v dnf >/dev/null 2>&1; then
                sudo dnf install -y python3 python3-pip python3-tkinter nmap curl || true
            elif command -v yum >/dev/null 2>&1; then
                sudo yum install -y python3 python3-pip python3-tkinter nmap curl || true
            elif command -v pacman >/dev/null 2>&1; then
                sudo pacman -S --noconfirm python python-pip python-tkinter nmap curl || true
            elif command -v zypper >/dev/null 2>&1; then
                sudo zypper install -y python3 python3-pip python3-tk nmap curl || true
            fi
            set -e  # Re-enable error handling
            echo "Please install Metasploit Framework manually from: https://www.metasploit.com/"
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

# Verify installations
verify_installations() {
    echo ""
    echo "Verifying installations..."
    
    # Check Python
    if command -v python3 >/dev/null 2>&1; then
        PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
        echo "✓ Python $PYTHON_VERSION installed"
    else
        echo "✗ Python 3 not found"
    fi
    
    # Check pip
    if command -v pip3 >/dev/null 2>&1 || python3 -m pip --version >/dev/null 2>&1; then
        echo "✓ pip installed"
    else
        echo "✗ pip not found"
    fi
    
    # Check Tkinter
    if python3 -c "import tkinter" 2>/dev/null; then
        echo "✓ Tkinter installed"
    else
        echo "✗ Tkinter not found"
    fi
    
    # Check nmap
    if command -v nmap >/dev/null 2>&1; then
        NMAP_VERSION=$(nmap --version 2>&1 | head -n 1 | awk '{print $3}')
        echo "✓ Nmap $NMAP_VERSION installed"
    else
        echo "✗ Nmap not found"
    fi
    
    # Check Metasploit Framework
    if command -v msfconsole >/dev/null 2>&1; then
        MSF_VERSION=$(msfconsole --version 2>&1 | head -n 1 || echo "unknown")
        echo "✓ Metasploit Framework installed ($MSF_VERSION)"
    else
        echo "✗ Metasploit Framework not found"
        echo "  Some features will be disabled"
    fi
    
    # Check desktop environment (for system tray support)
    # Supports: GNOME, KDE, XFCE, Cinnamon, MATE, LXDE, LXQt, and others
    if [ -n "$XDG_CURRENT_DESKTOP" ]; then
        DE=$(echo "$XDG_CURRENT_DESKTOP" | tr '[:upper:]' '[:lower:]')
        echo "✓ Desktop Environment: $XDG_CURRENT_DESKTOP"
        case $DE in
            *gnome*|*kde*|*xfce*|*cinnamon*|*mate*|*lxde*|*lxqt*)
                echo "  System tray support: Enabled"
                ;;
            *)
                echo "  System tray support: Should work (pystray compatible)"
                ;;
        esac
    elif [ -n "$DESKTOP_SESSION" ]; then
        DS=$(echo "$DESKTOP_SESSION" | tr '[:upper:]' '[:lower:]')
        echo "✓ Desktop Session: $DESKTOP_SESSION"
        case $DS in
            *gnome*|*kde*|*xfce*|*cinnamon*|*mate*|*lxde*|*lxqt*)
                echo "  System tray support: Enabled"
                ;;
            *)
                echo "  System tray support: Should work (pystray compatible)"
                ;;
        esac
    else
        echo "ℹ Desktop environment not detected"
        echo "  System tray may still work (pystray is compatible with most DEs)"
    fi
}

# Main
echo "YaP Network Scanner - Complete Dependency Installer"
echo "===================================================="
echo ""
echo "This installer will install:"
echo "  - Python 3 and required packages"
echo "  - Tkinter (GUI framework)"
echo "  - Nmap (network scanner)"
echo "  - Metasploit Framework (penetration testing)"
echo "  - Python dependencies (Pillow, pystray, psutil)"
echo ""

# Check for sudo
if ! command -v sudo >/dev/null 2>&1; then
    echo "Error: sudo is required but not installed"
    echo "Please install sudo or run as root"
    exit 1
fi

detect_distro
install_dependencies
install_python_packages
verify_installations

echo ""
echo "===================================================="
echo "Installation complete!"
echo ""
echo "You can now run YaP Network Scanner using:"
echo "  ./launchers/start-network-scanner.sh"
echo ""
echo "All features are now available:"
echo "  ✓ Network scanning with Nmap integration"
echo "  ✓ Metasploit Framework integration"
echo "  ✓ Payload generation with FUD encoding"
echo "  ✓ Module management and search"
echo ""
echo "Supported desktop environments:"
echo "  - GNOME, KDE, XFCE, Cinnamon, MATE, LXDE, LXQt"
echo "  - System tray integration enabled"
echo ""

