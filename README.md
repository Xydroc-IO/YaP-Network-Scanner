<div align="center">

![YaP Network Scanner](yapnetworkscanner250.png)

# YaP Network Scanner

A modern, cross-platform desktop application to discover and configure devices on your network. Features automatic device discovery, detailed device information, and configuration management.

</div>

## Features

### Network Scanning
- **Network Discovery**: Automatically scan your network to find all connected devices
- **Device Information**: View IP address, MAC address, hostname, vendor, and open ports for each device
- **Device Configuration**: Save custom names and notes for devices
- **Port Scanning**: Detect open ports on discovered devices using multi-threaded scanning
- **Custom Port Ranges**: Specify exact ports or port ranges to scan (e.g., `80,443,8080-8090` or `1-50000`)
- **Auto-Detection**: Automatically detect your local network
- **Device Persistence**: Save device configurations for easy recall
- **Device Labeling**: Add custom labels to devices for easy identification
- **Nmap Integration**: Dedicated Nmap tab for advanced network scanning with root privilege support

### Metasploit Framework Integration
- **Metasploit Console**: Full Metasploit Framework integration with interactive console
- **Module Management**: Search, browse, and load all Metasploit modules (exploits, payloads, auxiliary, post, encoders, nops)
- **Module Filtering**: Filter modules by type and search by name
- **Payload Generator**: Generate payloads with comprehensive options:
  - Support for Windows, Linux, Android, macOS, PHP, Python, Java, PowerShell, and more
  - Multiple output formats (exe, raw, elf, python, ps1, sh, bash, perl, ruby, lua, java, war, jsp, asp, aspx, dll, so, deb, rpm, apk, jar, and more)
  - FUD (Fully Undetectable) encoding with multiple encoders:
    - x86/shikata_ga_nai, x86/call4_dword_xor, x86/countdown, x86/fnstenv_mov
    - x86/jmp_call_additive, x86/nonalpha, x86/opt_sub, x86/unicode_mixed
    - x86/unicode_upper, x64/xor, x64/xor_dynamic, x64/zutto_dekiru
    - cmd/powershell_base64
  - Configurable encoding iterations (1-10)
  - Custom output directory selection
- **Handler Setup**: Automatically configure multi/handler for generated payloads
- **Info Command**: Dialog-based module information lookup with JSON and Markdown options
- **Quick Commands**: One-click access to common Metasploit commands (sessions, jobs, show options, show payloads, back, exit)
- **Metasploit Help**: Comprehensive command reference tab with all Metasploit commands and usage examples
- **Root Privilege Support**: Password dialog for sudo operations when needed

### User Interface
- **Modern UI**: Clean, intuitive interface with real-time scanning progress
- **System Tray Integration**: Minimize to system tray instead of closing (Linux)
- **Multi-Monitor Support**: Automatically opens on your primary monitor
- **Password Dialogs**: Secure password input dialogs that appear on the same monitor as the main window

## Requirements

- **Python**: 3.7 or higher
- **Network Access**: Connection to your local network
- **Operating System**: Linux (all major distributions)

### System Requirements

- Python Tkinter support
- Network tools (ping, arp) - usually pre-installed on Linux
- **Metasploit Framework** (optional, for Metasploit tab features):
  - Install from: https://www.metasploit.com/
  - Or via package manager: `sudo apt install metasploit-framework` (Debian/Ubuntu)
  - The application will detect if Metasploit is installed and enable/disable features accordingly

## Installation

### Linux Installation

#### Automatic Installation (Recommended)

The easiest way to install all dependencies is using the universal installer script:

```bash
./installers/install-dependencies.sh
```

This script will:
- Detect your Linux distribution automatically
- Install all required system packages
- Install Python dependencies via pip
- Handle all desktop environments

**Supported Linux Distributions:**
- Debian/Ubuntu/Mint/Pop!_OS/Elementary OS (apt)
- Fedora/RHEL/CentOS (dnf/yum)
- Arch/Manjaro/EndeavourOS/Garuda (pacman)
- openSUSE/SLE (zypper)
- Alpine Linux (apk)
- Solus (eopkg)
- Gentoo (emerge)

#### Manual Installation (Linux)

If you prefer to install manually:

1. Install system dependencies (varies by distribution):
   - **Debian/Ubuntu**: 
     ```bash
     sudo apt install python3 python3-pip python3-tk
     ```
   - **Fedora**: 
     ```bash
     sudo dnf install python3 python3-pip python3-tkinter
     ```
   - **Arch/Manjaro**: 
     ```bash
     sudo pacman -S python python-pip python-tkinter
     ```

2. Install Python packages:
   ```bash
   pip install -r requirements.txt
   ```

   Or install individually:
   ```bash
   pip install Pillow pystray
   ```

## Usage

**Recommended**: Use the launcher script (automatically checks dependencies):
```bash
./launchers/start-network-scanner.sh
```

Or run directly:
```bash
python3 core/network_manager.py
```

### Application Features

#### Network Scanning Tab

1. **Network Scanning**:
   - Click "Auto-Detect" to automatically detect your local network
   - Or manually enter a network in CIDR notation (e.g., `192.168.1.0/24`)
   - Click "Scan Network" to start discovering devices
   - Monitor progress in real-time
   - Click "Stop" to cancel an ongoing scan

2. **Device Discovery**:
   - All discovered devices appear in the "Discovered Devices" list
   - View IP address, hostname, status, and vendor for each device
   - Click on a device to view detailed information

3. **Device Information**:
   - **IP Address**: The device's IP address on the network
   - **MAC Address**: The device's MAC address (if available)
   - **Hostname**: The device's network hostname
   - **Vendor**: Device manufacturer (detected from MAC address)
   - **Status**: Online/Offline status
   - **Open Ports**: Ports that are open on the device

4. **Device Configuration**:
   - Select a device from the list
   - Add a custom name for easy identification
   - Add notes about the device
   - Click "Save Configuration" to persist your settings
   - Click "Save Selected" to save the device to your device list

5. **Device Actions**:
   - **Ping Device**: Test connectivity to the selected device
   - **Open in Browser**: Open the device's web interface (if available)
   - **Delete Selected**: Remove a device from the list

#### Metasploit Framework Tab

1. **Metasploit Console**:
   - Interactive console for executing Metasploit commands
   - Commands execute directly via `msfconsole -q -x`
   - View output in real-time

2. **Module Management**:
   - **Search Modules**: Search for modules by name
   - **Load Modules**: Load all available Metasploit modules
   - **Filter Modules**: Filter by type (exploit, auxiliary, payload, post, encoder, nop) and search text
   - **Use Module**: Double-click or use "Use Selected" to load a module

3. **Payload Generator**:
   - **Select Payload Type**: Choose from comprehensive list of payloads
   - **Configure LHOST/LPORT**: Set listener host and port
   - **Select Format**: Choose output format (exe, raw, elf, python, ps1, etc.)
   - **FUD Encoding**: Select encoder and iterations for anti-virus evasion
   - **Output Directory**: Choose where to save generated payloads
   - **Generate**: Create the payload with all specified options

4. **Quick Commands**:
   - **Sessions**: View active sessions
   - **Jobs**: View and manage jobs
   - **Info**: Open dialog to get module information
   - **Show Options**: Display module options
   - **Show Payloads**: Display available payloads
   - **Back**: Exit current module context
   - **Exit**: Exit Metasploit console

5. **Handler Setup**:
   - Automatically configure multi/handler for generated payloads
   - Sets LHOST, LPORT, and payload type automatically

#### Metasploit Help Tab

- Comprehensive command reference
- All Metasploit commands with descriptions
- Usage examples for ranges and lists
- Quick reference for all command categories

#### System Tray (Linux)
- Clicking the X button minimizes to system tray
- Right-click tray icon to show window or quit
- Keeps the application running in the background

## Configuration

### Network Scanning

The application supports scanning networks in CIDR notation:
- `192.168.1.0/24` - Scans 192.168.1.1 to 192.168.1.254
- `10.0.0.0/16` - Scans 10.0.0.1 to 10.0.255.254
- `172.16.0.0/12` - Scans 172.16.0.1 to 172.31.255.254

**Note**: Scanning large networks may take time. Use the "Stop" button to cancel if needed.

### Device Storage

Device configurations are stored persistently in a JSON file:
- **Linux/Mac**: `~/.config/yap-network-scanner/devices.json`
- **Windows**: `%APPDATA%\YaP-Network-Scanner\devices.json`

Each device configuration contains:
- IP address
- MAC address
- Hostname
- Vendor information
- Status
- Open ports
- Last seen timestamp

### Port Scanning

The application uses multi-threaded port scanning for fast and reliable results:
- Supports custom port ranges (e.g., `1-65535`, `80,443,8080-8090`)
- Uses threading for concurrent port checks
- Configurable timeouts for reliable detection
- Root privilege support for faster SYN scans (password dialog when needed)

Common ports scanned:
- 22 (SSH)
- 23 (Telnet)
- 80 (HTTP)
- 443 (HTTPS)
- 8080 (HTTP Alt)
- 3389 (RDP)
- 5900 (VNC)
- And more...

## Advanced Usage

### Manual Network Entry

If auto-detection doesn't work, you can manually enter your network:
1. Find your network IP and subnet mask
2. Convert to CIDR notation (e.g., 192.168.1.0 with subnet 255.255.255.0 = 192.168.1.0/24)
3. Enter in the Network field
4. Click "Scan Network"

### Device Management

- **Saving Devices**: Devices are automatically saved when you click "Save Selected" or "Save Configuration"
- **Loading Devices**: Previously discovered devices are loaded automatically on startup
- **Deleting Devices**: Select a device and click "Delete Selected" to remove it

### Network Interface Detection

The application automatically detects your active network interfaces:
- Uses `ip addr` command on Linux
- Falls back to socket-based detection if needed
- Displays the detected network in the Network field

## Troubleshooting

### No Devices Found

If the scan doesn't find any devices:

1. **Check Network**: Ensure you're on the correct network
2. **Verify Network Range**: Make sure the network CIDR is correct
3. **Firewall**: Some devices may not respond to ping (firewall blocking)
4. **Permissions**: Ensure you have permission to scan the network
5. **Try Manual Entry**: Use "Auto-Detect" or manually enter your network

### Scan Takes Too Long

- Large networks (e.g., /16) can take several minutes
- Use the "Stop" button to cancel
- Consider scanning smaller subnets
- The application uses threading for faster scanning

### MAC Address Shows "Unknown"

- MAC addresses are retrieved from the ARP table
- Devices that haven't been contacted recently may not appear in ARP
- Try pinging the device first, then rescan

### Hostname Shows "Unknown"

- Hostnames are resolved via reverse DNS
- Some devices don't have DNS entries
- This is normal for many devices

### System Tray Not Working

If the system tray icon doesn't appear:

- Ensure `pystray` is installed: `pip install pystray`
- Some desktop environments may require additional packages
- Try restarting the application

### Missing Dependencies

1. Run the dependency installer: `./installers/install-dependencies.sh`
2. Or install manually: `pip install Pillow pystray psutil`
3. Ensure python3-tk is installed via your system package manager

### Metasploit Not Found

If the Metasploit tab shows "Metasploit Framework not found":
1. Install Metasploit Framework from https://www.metasploit.com/
2. Or install via package manager:
   - **Debian/Ubuntu**: `sudo apt install metasploit-framework`
   - **Arch/Manjaro**: `sudo pacman -S metasploit`
   - **Fedora**: `sudo dnf install metasploit-framework`
3. Restart the application after installation
4. The Metasploit tab features will be enabled automatically when detected

## Project Structure

```
YaP-Network-Scanner/
├── core/
│   ├── network_manager.py      # Main application and GUI (includes Metasploit integration)
│   ├── network_scanner.py      # Network scanning functionality
│   └── device_storage.py       # Device configuration storage
├── installers/
│   └── install-dependencies.sh # Dependency installer
├── launchers/
│   └── start-network-scanner.sh # Launcher script
├── build_appimage_advanced.sh  # AppImage build script
├── requirements.txt            # Python dependencies
├── LICENSE                     # License file
└── README.md                   # This file
```

## Dependencies

### Python Packages

- **Pillow** (>=9.0.0): Image processing for icons
- **pystray** (>=0.19.0): System tray support (Linux)

Note: Tkinter is included with Python but may need to be installed separately on some systems.

### System Packages (Linux)

- Python 3.7+ with Tkinter
- Network tools (ping, arp) - usually pre-installed
- Standard system libraries

## Development

### Running from Source

1. Clone or download the repository
2. Install dependencies (see Installation section)
3. Run using the launcher script:
   ```bash
   ./launchers/start-network-scanner.sh
   ```
   Or run directly:
   ```bash
   python3 core/network_manager.py
   ```

## Security & Privacy

- **Local Only**: All scanning is performed locally on your network
- **No Data Collection**: No device information is sent to external servers
- **Network Access**: Requires network access to scan and discover devices
- **Permissions**: May require elevated permissions for some network operations

## Limitations

- **Network Size**: Very large networks (e.g., /8) may take a very long time to scan
- **Firewall**: Devices behind firewalls may not respond to ping
- **MAC Addresses**: MAC addresses are only available for devices in the ARP table
- **Port Scanning**: Large port ranges may take time; use threading-based scanner for best results
- **OS Detection**: Basic OS detection is not implemented
- **Metasploit**: Requires Metasploit Framework to be installed separately for Metasploit tab features
- **Root Privileges**: Some network operations (nmap SYN scans) may require root privileges

## License

© YaP Labs

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## Support

For issues, questions, or feature requests, please open an issue on the project repository.

---

**Note**: This application requires network access to scan your local network. Ensure your firewall allows network scanning operations.

