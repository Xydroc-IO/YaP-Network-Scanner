<div align="center">

![YaP Network Scanner](yapnetworkscanner250.png)

# YaP Network Scanner

A modern, cross-platform desktop application to discover and configure devices on your network. Features automatic device discovery, detailed device information, and configuration management.

</div>

## Features

- **Network Discovery**: Automatically scan your network to find all connected devices
- **Device Information**: View IP address, MAC address, hostname, vendor, and open ports for each device
- **Device Configuration**: Save custom names and notes for devices
- **Port Scanning**: Detect open ports on discovered devices
- **Nmap Integration**: Automatically uses nmap for large port ranges (>1000 ports) for faster, more reliable scanning
- **Custom Port Ranges**: Specify exact ports or port ranges to scan (e.g., `80,443,8080-8090` or `1-50000`)
- **Auto-Detection**: Automatically detect your local network
- **Device Persistence**: Save device configurations for easy recall
- **Device Labeling**: Add custom labels to devices for easy identification
- **Modern UI**: Clean, intuitive interface with real-time scanning progress
- **System Tray Integration**: Minimize to system tray instead of closing (Linux)
- **Multi-Monitor Support**: Automatically opens on your primary monitor

## Requirements

- **Python**: 3.7 or higher
- **Network Access**: Connection to your local network
- **Operating System**: Linux (all major distributions)

### System Requirements

- Python Tkinter support
- Network tools (ping, arp) - usually pre-installed on Linux

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
   - **Open Ports**: Common ports that are open on the device

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

6. **System Tray (Linux)**:
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

The application scans common ports on discovered devices:
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
2. Or install manually: `pip install Pillow pystray`
3. Ensure python3-tk is installed via your system package manager

## Project Structure

```
YaP-Network-Scanner/
├── core/
│   ├── network_manager.py      # Main application and GUI
│   ├── network_scanner.py      # Network scanning functionality
│   └── device_storage.py       # Device configuration storage
├── installers/
│   └── install-dependencies.sh # Dependency installer
├── launchers/
│   └── start-network-scanner.sh # Launcher script
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
- **Port Scanning**: Only scans common ports; full port scans are not performed
- **OS Detection**: Basic OS detection is not implemented

## License

© YaP Labs

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## Support

For issues, questions, or feature requests, please open an issue on the project repository.

---

**Note**: This application requires network access to scan your local network. Ensure your firewall allows network scanning operations.

