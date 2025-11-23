#!/usr/bin/env python3
"""
YaP Network Scanner - Network Scanner
Scans the network for devices and collects device information.
"""

import ipaddress
import subprocess
import socket
import threading
import time
import platform
import re
import struct
import os
import signal
from typing import List, Dict, Optional, Callable
from dataclasses import dataclass, asdict
import json
import shutil


@dataclass
class NetworkDevice:
    """Represents a device on the network."""
    ip: str
    mac: str = "Unknown"
    hostname: str = "Unknown"
    vendor: str = "Unknown"
    status: str = "Unknown"  # "Online", "Offline", "Unknown"
    last_seen: float = 0.0
    open_ports: List[int] = None
    os_info: str = "Unknown"
    subnet_mask: str = "Unknown"
    custom_label: str = ""  # User-defined label for the device
    
    def __post_init__(self):
        if self.open_ports is None:
            self.open_ports = []
    
    def to_dict(self):
        """Convert to dictionary for JSON serialization."""
        return {
            'ip': self.ip,
            'mac': self.mac,
            'hostname': self.hostname,
            'vendor': self.vendor,
            'status': self.status,
            'last_seen': self.last_seen,
            'open_ports': self.open_ports,
            'os_info': self.os_info,
            'subnet_mask': self.subnet_mask,
            'custom_label': self.custom_label
        }
    
    @classmethod
    def from_dict(cls, data: dict):
        """Create from dictionary."""
        return cls(
            ip=data.get('ip', ''),
            mac=data.get('mac', 'Unknown'),
            hostname=data.get('hostname', 'Unknown'),
            vendor=data.get('vendor', 'Unknown'),
            status=data.get('status', 'Unknown'),
            last_seen=data.get('last_seen', 0.0),
            open_ports=data.get('open_ports', []),
            os_info=data.get('os_info', 'Unknown'),
            subnet_mask=data.get('subnet_mask', 'Unknown'),
            custom_label=data.get('custom_label', '')
        )
    
    def get_display_name(self) -> str:
        """Get display name for the device (label if set, otherwise hostname or IP)."""
        if self.custom_label:
            return self.custom_label
        elif self.hostname and self.hostname != "Unknown":
            return self.hostname
        else:
            return self.ip


class NetworkScanner:
    """Scans the network for devices."""
    
    def __init__(self):
        self.devices: Dict[str, NetworkDevice] = {}
        self.scanning = False
        self.progress_callback: Optional[Callable] = None
        self.mac_vendor_db = self._load_mac_vendor_db()
        self.has_nmap = self._check_nmap()
        self.sudo_password: Optional[str] = None
        self.password_callback: Optional[Callable] = None  # Callback to request password from GUI
    
    def _check_nmap(self) -> bool:
        """Check if nmap is available on the system."""
        return shutil.which('nmap') is not None
    
    def set_progress_callback(self, callback: Callable):
        """Set callback for scan progress updates."""
        self.progress_callback = callback
    
    def set_password_callback(self, callback: Callable):
        """Set callback to request password from GUI."""
        self.password_callback = callback
    
    def set_sudo_password(self, password: str):
        """Set sudo password for running privileged commands."""
        self.sudo_password = password
    
    def _load_mac_vendor_db(self) -> Dict[str, str]:
        """Load MAC address vendor database."""
        # Common MAC vendor prefixes
        # In a full implementation, you'd load from a file or API
        return {
            '00:50:56': 'VMware',
            '00:0C:29': 'VMware',
            '00:1C:42': 'Parallels',
            '00:16:3E': 'Xensource',
            '08:00:27': 'VirtualBox',
            '00:1B:21': 'Intel',
            '00:1E:67': 'Intel',
            '00:25:00': 'Apple',
            '00:26:BB': 'Apple',
            '00:23:DF': 'Apple',
            '00:50:56': 'VMware',
            'B8:27:EB': 'Raspberry Pi',
            'DC:A6:32': 'Raspberry Pi',
            'E4:5F:01': 'Raspberry Pi',
        }
    
    def _get_vendor_from_mac(self, mac: str) -> str:
        """Get vendor name from MAC address."""
        if not mac or mac == "Unknown":
            return "Unknown"
        
        # Normalize MAC address
        mac_upper = mac.upper().replace('-', ':')
        prefix = ':'.join(mac_upper.split(':')[:3])
        
        return self.mac_vendor_db.get(prefix, "Unknown")
    
    def get_network_interfaces(self) -> List[Dict[str, str]]:
        """Get list of network interfaces."""
        interfaces = []
        
        try:
            if platform.system() == "Linux":
                # Use ip command
                result = subprocess.run(['ip', 'addr', 'show'], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    current_interface = None
                    for line in result.stdout.split('\n'):
                        # Interface name
                        match = re.match(r'^\d+:\s+(\w+):', line)
                        if match:
                            current_interface = match.group(1)
                            if current_interface and current_interface != 'lo':
                                interfaces.append({
                                    'name': current_interface,
                                    'ip': '',
                                    'netmask': '',
                                    'status': 'unknown'
                                })
                        # IP address
                        if current_interface and 'inet ' in line:
                            ip_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)/(\d+)', line)
                            if ip_match:
                                ip = ip_match.group(1)
                                prefix = ip_match.group(2)
                                # Find the interface in our list
                                for iface in interfaces:
                                    if iface['name'] == current_interface:
                                        iface['ip'] = ip
                                        iface['netmask'] = self._prefix_to_netmask(int(prefix))
                                        iface['status'] = 'up'
                                        break
        except Exception as e:
            print(f"Error getting interfaces: {e}")
        
        # Fallback: try socket method
        if not interfaces:
            try:
                hostname = socket.gethostname()
                local_ip = socket.gethostbyname(hostname)
                if local_ip and local_ip != '127.0.0.1':
                    interfaces.append({
                        'name': 'default',
                        'ip': local_ip,
                        'netmask': '255.255.255.0',
                        'status': 'up'
                    })
            except:
                pass
        
        return interfaces
    
    def _prefix_to_netmask(self, prefix: int) -> str:
        """Convert CIDR prefix to netmask."""
        mask = (0xffffffff >> (32 - prefix)) << (32 - prefix)
        return socket.inet_ntoa(struct.pack("!I", mask))
    
    def get_local_network(self) -> Optional[str]:
        """Get the local network CIDR."""
        interfaces = self.get_network_interfaces()
        for iface in interfaces:
            if iface['ip'] and iface['netmask']:
                try:
                    ip = ipaddress.IPv4Address(iface['ip'])
                    netmask = ipaddress.IPv4Address(iface['netmask'])
                    # Calculate network
                    network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                    return str(network)
                except:
                    continue
        return None
    
    def ping_host(self, ip: str, timeout: float = 1.0) -> bool:
        """Ping a host to check if it's online."""
        try:
            if platform.system() == "Linux":
                result = subprocess.run(
                    ['ping', '-c', '1', '-W', str(int(timeout * 1000)), ip],
                    capture_output=True,
                    timeout=timeout + 0.5
                )
                return result.returncode == 0
            elif platform.system() == "Windows":
                result = subprocess.run(
                    ['ping', '-n', '1', '-w', str(int(timeout * 1000)), ip],
                    capture_output=True,
                    timeout=timeout + 0.5
                )
                return result.returncode == 0
            else:
                # Fallback: try socket connection
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((ip, 80))
                sock.close()
                return result == 0
        except:
            return False
    
    def get_mac_address(self, ip: str) -> str:
        """Get MAC address for an IP using ARP table."""
        try:
            if platform.system() == "Linux":
                result = subprocess.run(['arp', '-n', ip], 
                                      capture_output=True, text=True, timeout=2)
                if result.returncode == 0:
                    # Parse ARP output
                    lines = result.stdout.strip().split('\n')
                    for line in lines:
                        if ip in line:
                            # Extract MAC address
                            mac_match = re.search(r'([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})', line)
                            if mac_match:
                                return mac_match.group(0).upper()
            elif platform.system() == "Windows":
                result = subprocess.run(['arp', '-a', ip], 
                                      capture_output=True, text=True, timeout=2)
                if result.returncode == 0:
                    mac_match = re.search(r'([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})', result.stdout)
                    if mac_match:
                        return mac_match.group(0).upper()
        except:
            pass
        return "Unknown"
    
    def get_all_arp_entries(self) -> Dict[str, str]:
        """Get all entries from ARP table to discover devices."""
        arp_entries = {}
        try:
            if platform.system() == "Linux":
                result = subprocess.run(['arp', '-a'], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    # Parse ARP output - format: hostname (IP) at MAC [ether] on interface
                    for line in result.stdout.strip().split('\n'):
                        # Match pattern like: ? (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on eth0
                        ip_match = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)', line)
                        mac_match = re.search(r'([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})', line)
                        if ip_match and mac_match:
                            ip = ip_match.group(1)
                            mac = mac_match.group(0).upper()
                            arp_entries[ip] = mac
            elif platform.system() == "Windows":
                result = subprocess.run(['arp', '-a'], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    # Parse Windows ARP output
                    for line in result.stdout.strip().split('\n'):
                        # Match pattern like: 192.168.1.1    aa-bb-cc-dd-ee-ff    dynamic
                        parts = line.split()
                        if len(parts) >= 2:
                            ip = parts[0]
                            mac = parts[1]
                            # Validate IP and MAC
                            try:
                                ipaddress.IPv4Address(ip)
                                if re.match(r'([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})', mac, re.IGNORECASE):
                                    arp_entries[ip] = mac.upper().replace('-', ':')
                            except:
                                pass
        except:
            pass
        return arp_entries
    
    def check_device_reachable(self, ip: str) -> bool:
        """Check if a device is reachable using multiple methods."""
        # Try ping first (with shorter timeout to avoid hanging)
        if self.ping_host(ip, timeout=0.3):
            return True
        
        # Try to get MAC from ARP (device might be in ARP table even if ping fails)
        # Use shorter timeout to avoid hanging
        try:
            mac = self.get_mac_address(ip)
            if mac != "Unknown":
                return True
        except:
            pass
        
        # Try a quick port scan on common ports (some devices don't respond to ping)
        # Try just a couple of very common ports quickly with very short timeout
        for port in [80, 443, 22]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.2)  # Very short timeout
                result = sock.connect_ex((ip, port))
                sock.close()
                if result == 0:
                    return True
            except:
                continue
        
        return False
    
    def get_hostname(self, ip: str) -> str:
        """Get hostname for an IP address."""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except:
            return "Unknown"
    
    def scan_port(self, ip: str, port: int, timeout: float = 1.0) -> bool:
        """Check if a port is open on a host."""
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            # Set socket options for better reliability
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            result = sock.connect_ex((ip, port))
            is_open = result == 0
            return is_open
        except socket.timeout:
            return False
        except socket.error as e:
            # Connection refused, host unreachable, etc. - port is closed
            return False
        except Exception:
            return False
        finally:
            # Always close socket to prevent resource leaks
            if sock:
                try:
                    sock.close()
                except:
                    pass
    
    def parse_ports(self, port_string: str) -> List[int]:
        """Parse port string into list of ports.
        
        Supports:
        - Single ports: "80,443,22"
        - Port ranges: "8080-8090"
        - Mixed: "80,443,8080-8090,22"
        - Empty string returns common ports
        """
        if not port_string or not port_string.strip():
            # Return common ports if empty
            return [22, 23, 80, 443, 8080, 3389, 5900, 21, 25, 53, 135, 139, 445]
        
        ports = []
        port_string = port_string.strip()
        
        # Split by comma
        parts = port_string.split(',')
        
        for part in parts:
            part = part.strip()
            if not part:
                continue
            
            # Check if it's a range
            if '-' in part:
                try:
                    start, end = part.split('-', 1)
                    start_port = int(start.strip())
                    end_port = int(end.strip())
                    
                    # Validate range
                    if start_port < 1 or start_port > 65535:
                        continue
                    if end_port < 1 or end_port > 65535:
                        continue
                    if start_port > end_port:
                        start_port, end_port = end_port, start_port
                    
                    # Add all ports in range
                    ports.extend(range(start_port, end_port + 1))
                except ValueError:
                    continue
            else:
                # Single port
                try:
                    port = int(part)
                    if 1 <= port <= 65535:
                        ports.append(port)
                except ValueError:
                    continue
        
        # Remove duplicates and sort
        return sorted(list(set(ports)))
    
    def scan_ports_with_nmap(self, ip: str, ports: List[int]) -> List[int]:
        """Scan ports using nmap (faster and more reliable for large ranges)."""
        if not self.has_nmap or not ports:
            return []
        
        try:
            # Build port string for nmap
            if len(ports) == 1:
                port_str = str(ports[0])
            elif len(ports) <= 100:
                port_str = ','.join(map(str, ports))
            else:
                # For large ranges, optimize port string building
                ports_sorted = sorted(set(ports))  # Remove duplicates and sort
                
                # Check if this is a continuous or near-continuous range (like 1-65535)
                # If it covers most of the port range, just use the full range
                min_port = ports_sorted[0]
                max_port = ports_sorted[-1]
                total_ports = len(ports_sorted)
                expected_ports = max_port - min_port + 1
                
                # If we have 95%+ of a continuous range, use the full range
                # This handles cases like "1-65535" efficiently
                if expected_ports > 0 and (total_ports / expected_ports) >= 0.95:
                    if min_port == 1 and max_port == 65535:
                        # Full port scan - use simple range
                        port_str = "1-65535"
                    elif min_port == 1:
                        # Most ports from 1, use range
                        port_str = f"1-{max_port}"
                    else:
                        # Large continuous range
                        port_str = f"{min_port}-{max_port}"
                    
                    # Log for debugging
                    if self.progress_callback and len(ports) > 50000:
                        self.progress_callback(f"Using optimized port range: {port_str} for {ip}")
                else:
                    # For very large port lists (>50000), use optimized grouping
                    # Only process in chunks to avoid memory issues
                    if len(ports_sorted) > 50000:
                        # For extremely large lists, use a more efficient approach
                        # Group into larger ranges with minimal gaps
                        port_ranges = []
                        start = ports_sorted[0]
                        end = ports_sorted[0]
                        gap_threshold = 100  # Allow gaps up to 100 ports
                        
                        for i in range(1, len(ports_sorted)):
                            port = ports_sorted[i]
                            if port <= end + gap_threshold:
                                # Continue the range (allow small gaps)
                                end = port
                            else:
                                # End current range, start new one
                                if start == end:
                                    port_ranges.append(str(start))
                                else:
                                    port_ranges.append(f"{start}-{end}")
                                start = port
                                end = port
                        
                        # Add last range
                        if start == end:
                            port_ranges.append(str(start))
                        else:
                            port_ranges.append(f"{start}-{end}")
                        
                        port_str = ','.join(port_ranges)
                    else:
                        # For smaller large lists, use standard grouping
                        port_ranges = []
                        start = ports_sorted[0]
                        end = ports_sorted[0]
                        
                        for port in ports_sorted[1:]:
                            if port == end + 1:
                                end = port
                            else:
                                if start == end:
                                    port_ranges.append(str(start))
                                else:
                                    port_ranges.append(f"{start}-{end}")
                                start = port
                                end = port
                        
                        # Add last range
                        if start == end:
                            port_ranges.append(str(start))
                        else:
                            port_ranges.append(f"{start}-{end}")
                        
                        port_str = ','.join(port_ranges)
            
            # Validate port string length (command line limit is typically ~2MB, but be safe)
            # If port string is extremely long, it might cause issues
            if len(port_str) > 100000:  # ~100KB should be safe
                if self.progress_callback:
                    self.progress_callback(f"Warning: Port string very long ({len(port_str)} chars) for {ip}, this may cause issues")
            
            # Log port string for debugging large scans
            if self.progress_callback and len(ports) > 50000:
                port_str_preview = port_str[:100] + "..." if len(port_str) > 100 else port_str
                self.progress_callback(f"Using port string: {port_str_preview} (length: {len(port_str)}) for {ip}")
            
            # Validate port string isn't empty
            if not port_str or not port_str.strip():
                if self.progress_callback:
                    self.progress_callback(f"Error: Empty port string for {ip}")
                return []
            
            # Run nmap scan
            # For very large ranges, increase timeout significantly
            # Calculate timeout based on number of ports
            if len(ports) > 50000:
                # Full port scan or near-full scan - needs much more time
                host_timeout = '1800s'  # 30 minutes for full port scans
                scan_timeout = 1900  # 31+ minutes total
            elif len(ports) > 10000:
                host_timeout = '900s'  # 15 minutes for very large ranges
                scan_timeout = 960  # 16 minutes total
            elif len(ports) > 1000:
                host_timeout = '180s'  # 3 minutes
                scan_timeout = 200  # 3.5 minutes total
            else:
                host_timeout = '60s'
                scan_timeout = 70
            
            if self.progress_callback:
                self.progress_callback(f"Using nmap to scan {len(ports)} ports on {ip} (this may take a while)...")
            
            # Build nmap command with aggressive timeout settings to prevent hanging
            # -Pn: skip host discovery (we already know it's up)
            # -sS: SYN scan (fastest, requires root) or -sT: TCP connect scan (no root needed)
            # --max-retries 0: no retries (faster, prevents hanging on unresponsive ports)
            # --host-timeout: maximum time to spend on a host
            # --max-rtt-timeout: maximum time to wait for a response (prevents hanging)
            # --initial-rtt-timeout: initial probe timeout (speeds up scanning)
            # --open: only show open ports (faster output parsing)
            # --no-stylesheet: disable XSL stylesheet processing (faster)
            # -n: no DNS resolution (faster, we already have IP)
            # --unprivileged: if running without root, use slower but safer methods
            
            # Calculate RTT timeouts based on port count
            # For very large scans, use longer timeouts but still bounded
            if len(ports) > 50000:
                max_rtt = '2000ms'  # 2 seconds max per probe
                initial_rtt = '500ms'  # 500ms initial
            elif len(ports) > 10000:
                max_rtt = '1500ms'  # 1.5 seconds
                initial_rtt = '400ms'
            else:
                max_rtt = '1000ms'  # 1 second
                initial_rtt = '300ms'
            
            result = None
            process = None
            
            # Helper function to run command with sudo if password is available
            def run_with_sudo_if_needed(cmd_list, use_sudo=True):
                """Run command with sudo if password is available, otherwise return command as-is."""
                if use_sudo and self.sudo_password:
                    # Use sudo with password via stdin
                    sudo_cmd = ['sudo', '-S'] + cmd_list  # -S reads password from stdin
                    return sudo_cmd, self.sudo_password.encode()
                return cmd_list, None
            
            # Try SYN scan first (requires root, but much faster)
            # Note: Removed --open flag as it may cause parsing issues with some nmap versions
            # We'll parse and filter for open ports ourselves
            # Build command carefully to avoid issues
            base_cmd = ['nmap', '-Pn', '-n', '-sS', 
                       '--max-retries', '0',  # No retries - prevents hanging
                       '--host-timeout', host_timeout,
                       '--max-rtt-timeout', max_rtt,
                       '--initial-rtt-timeout', initial_rtt,
                       '--no-stylesheet',  # Disable XSL processing
                       '-p', port_str, ip]
            
            # Try to use sudo if password is available
            cmd, sudo_input = run_with_sudo_if_needed(base_cmd, use_sudo=True)
            
            # Validate command before running
            if self.progress_callback and len(ports) > 10000:
                cmd_preview = ' '.join(cmd[:5]) + ' ... -p ' + (port_str[:50] + '...' if len(port_str) > 50 else port_str) + ' ' + ip
                self.progress_callback(f"Running nmap command: {cmd_preview}")
            
            # Helper function to safely kill process and all children
            def kill_process_group(proc):
                """Kill process and its children."""
                if not proc:
                    return
                try:
                    if proc.poll() is None:  # Still running
                        # On Unix, try to kill the entire process group
                        if platform.system() != 'Windows':
                            try:
                                # Get the process group ID (negative PID kills the group)
                                pgid = os.getpgid(proc.pid)
                                os.killpg(pgid, signal.SIGTERM)
                                time.sleep(0.5)
                                # Force kill if still running
                                try:
                                    os.killpg(pgid, signal.SIGKILL)
                                except ProcessLookupError:
                                    pass  # Already dead
                            except (OSError, ProcessLookupError, AttributeError):
                                # Fallback to regular kill if process group method fails
                                proc.terminate()
                                try:
                                    proc.wait(timeout=1)
                                except subprocess.TimeoutExpired:
                                    proc.kill()
                                    proc.wait()
                        else:
                            # Windows - just kill the process
                            proc.terminate()
                            try:
                                proc.wait(timeout=1)
                            except subprocess.TimeoutExpired:
                                proc.kill()
                                proc.wait()
                except (ProcessLookupError, OSError, ValueError):
                    pass  # Process already dead
            
            # Helper to create process group function
            def create_process_group_fn():
                """Create new process group, fallback gracefully if it fails."""
                preexec_fn = None
                if platform.system() != 'Windows':
                    def create_process_group():
                        """Create new process group, fallback gracefully if it fails."""
                        try:
                            os.setsid()
                        except OSError:
                            pass  # Not a session leader, continue anyway
                    preexec_fn = create_process_group
                return preexec_fn
            
            # If SYN scan fails (needs root), try connect scan
            try:
                # Use Popen for better control and ability to kill stuck processes
                # Create new process group on Unix to allow killing all children
                preexec_fn = create_process_group_fn()
                
                process = subprocess.Popen(
                    cmd, 
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.PIPE, 
                    stdin=subprocess.PIPE if sudo_input else None,
                    text=True,
                    preexec_fn=preexec_fn
                )
                
                try:
                    # If using sudo, send password via stdin
                    if sudo_input:
                        stdout, stderr = process.communicate(input=sudo_input.decode() + '\n', timeout=scan_timeout)
                    else:
                        stdout, stderr = process.communicate(timeout=scan_timeout)
                    # Ensure we got the full output
                    if not stdout and process.returncode != 0:
                        # Check if there's any output waiting
                        if self.progress_callback:
                            self.progress_callback(f"Warning: No stdout from nmap for {ip}, return code: {process.returncode}")
                    result = subprocess.CompletedProcess(
                        process.args, process.returncode, stdout, stderr
                    )
                except subprocess.TimeoutExpired:
                    # Process hung - kill it forcefully
                    if self.progress_callback:
                        self.progress_callback(f"Nmap scan timed out for {ip}, killing process...")
                    kill_process_group(process)
                    # Don't re-raise, return empty list instead
                    if self.progress_callback:
                        self.progress_callback(f"Nmap scan timed out for {ip} after {scan_timeout}s")
                    return []
                    
            except subprocess.TimeoutExpired:
                if self.progress_callback:
                    self.progress_callback(f"Nmap scan timed out for {ip} after {scan_timeout}s")
                return []
            except PermissionError:
                # SYN scan requires root - try to get password if not already set
                if not self.sudo_password and self.password_callback:
                    if self.progress_callback:
                        self.progress_callback(f"SYN scan requires root privileges for {ip}...")
                    # Request password from GUI
                    password = self.password_callback()
                    if password:
                        self.sudo_password = password
                        # Retry with sudo
                        try:
                            cmd, sudo_input = run_with_sudo_if_needed(base_cmd, use_sudo=True)
                            preexec_fn = create_process_group_fn()
                            process = subprocess.Popen(
                                cmd, 
                                stdout=subprocess.PIPE, 
                                stderr=subprocess.PIPE, 
                                stdin=subprocess.PIPE if sudo_input else None,
                                text=True,
                                preexec_fn=preexec_fn
                            )
                            try:
                                if sudo_input:
                                    stdout, stderr = process.communicate(input=sudo_input.decode() + '\n', timeout=scan_timeout)
                                else:
                                    stdout, stderr = process.communicate(timeout=scan_timeout)
                                if not stdout and process.returncode != 0:
                                    if self.progress_callback:
                                        self.progress_callback(f"Warning: No stdout from nmap (with sudo) for {ip}, return code: {process.returncode}")
                                result = subprocess.CompletedProcess(
                                    process.args, process.returncode, stdout, stderr
                                )
                            except subprocess.TimeoutExpired:
                                if self.progress_callback:
                                    self.progress_callback(f"Nmap scan timed out for {ip}, killing process...")
                                kill_process_group(process)
                                if self.progress_callback:
                                    self.progress_callback(f"Nmap scan timed out for {ip} after {scan_timeout}s")
                                return []
                            except Exception as e:
                                if self.progress_callback:
                                    self.progress_callback(f"Error during sudo nmap scan for {ip}: {str(e)}")
                                if process:
                                    kill_process_group(process)
                                return []
                        except Exception as e:
                            if self.progress_callback:
                                self.progress_callback(f"Error running sudo nmap for {ip}: {str(e)}")
                            # Fall through to connect scan
                            pass
                
                # Try without -sS (connect scan, doesn't need root)
                if not result:  # Only if sudo attempt didn't work
                    if self.progress_callback:
                        self.progress_callback(f"Using connect scan (no root) for {ip}...")
                    cmd = ['nmap', '-Pn', '-n', '-sT',
                           '--max-retries', '0',  # No retries
                           '--host-timeout', host_timeout,
                           '--max-rtt-timeout', max_rtt,
                           '--initial-rtt-timeout', initial_rtt,
                           '--no-stylesheet',  # Disable XSL processing
                           '-p', port_str, ip]
                try:
                    # Use same process group creation as above
                    preexec_fn = create_process_group_fn()
                    
                    process = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        preexec_fn=preexec_fn
                    )
                    try:
                        stdout, stderr = process.communicate(timeout=scan_timeout)
                        # Ensure we got the full output
                        if not stdout and process.returncode != 0:
                            if self.progress_callback:
                                self.progress_callback(f"Warning: No stdout from nmap (connect scan) for {ip}, return code: {process.returncode}")
                        result = subprocess.CompletedProcess(
                            process.args, process.returncode, stdout, stderr
                        )
                    except subprocess.TimeoutExpired:
                        if self.progress_callback:
                            self.progress_callback(f"Nmap scan timed out for {ip}, killing process...")
                        kill_process_group(process)
                        # Don't re-raise, return empty list instead
                        if self.progress_callback:
                            self.progress_callback(f"Nmap scan timed out for {ip} after {scan_timeout}s")
                        return []
                except subprocess.TimeoutExpired:
                    if self.progress_callback:
                        self.progress_callback(f"Nmap scan timed out for {ip} after {scan_timeout}s")
                    return []
                except Exception as e:
                    # Catch any other errors during connect scan
                    if self.progress_callback:
                        self.progress_callback(f"Error during connect scan for {ip}: {str(e)}")
                    if process:
                        kill_process_group(process)
                    return []
            except FileNotFoundError:
                # nmap not found
                if self.progress_callback:
                    self.progress_callback(f"Nmap not found in PATH for {ip}")
                return []
            except Exception as e:
                # Catch any other unexpected errors
                error_msg = str(e)
                if self.progress_callback:
                    self.progress_callback(f"Nmap scan exception for {ip}: {error_msg}")
                # Try to get stderr if process exists
                if process and process.poll() is not None:
                    try:
                        # Process already finished, try to get any error output
                        if hasattr(process, 'stderr') and process.stderr:
                            stderr_output = process.stderr.read() if hasattr(process.stderr, 'read') else ""
                            if stderr_output:
                                if self.progress_callback:
                                    self.progress_callback(f"Nmap stderr for {ip}: {stderr_output[:200]}")
                    except:
                        pass
                return []
            finally:
                # Ensure process is cleaned up
                if process and process.poll() is None:
                    kill_process_group(process)
            
            if result is None:
                return []
            
            # Parse nmap output for open ports
            # Note: nmap may return non-zero exit codes for various reasons but still have valid output
            # So we check the output regardless of return code
            open_ports = []
            
            # Check for errors in stderr - always log stderr for debugging
            needs_root = False
            if result.stderr:
                stderr_lower = result.stderr.lower()
                # Check if nmap is requesting root privileges
                needs_root = any(phrase in stderr_lower for phrase in [
                    'requires root privileges', 
                    'root privileges', 
                    'you requested a scan type which requires root',
                    'operation not permitted'
                ])
                
                # Check for various error indicators
                has_error = any(keyword in stderr_lower for keyword in ['error', 'failed', 'failed to', 'cannot', 'unable', 'invalid', 'permission denied'])
                
                if needs_root and not self.sudo_password and self.password_callback:
                    # Nmap needs root - request password
                    if self.progress_callback:
                        self.progress_callback(f"Nmap requires root privileges for {ip}, requesting password...")
                    password = self.password_callback()
                    if password:
                        self.sudo_password = password
                        # Retry with sudo
                        cmd, sudo_input = run_with_sudo_if_needed(base_cmd, use_sudo=True)
                        preexec_fn = create_process_group_fn()
                        try:
                            process = subprocess.Popen(
                                cmd, 
                                stdout=subprocess.PIPE, 
                                stderr=subprocess.PIPE, 
                                stdin=subprocess.PIPE if sudo_input else None,
                                text=True,
                                preexec_fn=preexec_fn
                            )
                            try:
                                if sudo_input:
                                    stdout, stderr = process.communicate(input=sudo_input.decode() + '\n', timeout=scan_timeout)
                                else:
                                    stdout, stderr = process.communicate(timeout=scan_timeout)
                                # Update result with new output
                                result = subprocess.CompletedProcess(
                                    process.args, process.returncode, stdout, stderr
                                )
                                needs_root = False  # Reset flag since we retried
                            except subprocess.TimeoutExpired:
                                if self.progress_callback:
                                    self.progress_callback(f"Nmap scan timed out for {ip}, killing process...")
                                kill_process_group(process)
                                if self.progress_callback:
                                    self.progress_callback(f"Nmap scan timed out for {ip} after {scan_timeout}s")
                                return []
                        except Exception as e:
                            if self.progress_callback:
                                self.progress_callback(f"Error running sudo nmap for {ip}: {str(e)}")
                            # Fall through to connect scan
                            pass
                
                if has_error and not needs_root:
                    # Show full error message (up to reasonable length)
                    error_msg = result.stderr.strip()
                    if len(error_msg) > 500:
                        error_msg = error_msg[:500] + "..."
                    if self.progress_callback:
                        self.progress_callback(f"Nmap error for {ip}: {error_msg}")
                elif self.progress_callback and len(ports) > 1000 and not needs_root:
                    # For large scans, log stderr even if not an obvious error (might be warnings)
                    stderr_preview = result.stderr[:200].strip()
                    if stderr_preview:
                        self.progress_callback(f"Nmap stderr for {ip}: {stderr_preview}")
                # Still try to parse stdout in case there's partial results
            
            # Check if we need to retry with sudo due to root privilege error
            # This check happens after stderr analysis but before parsing
            if needs_root and not self.sudo_password and self.password_callback:
                # This should have been handled above, but double-check
                if self.progress_callback:
                    self.progress_callback(f"Root privileges needed for {ip}, but password not available")
            
            # Parse stdout for open ports
            # Nmap can output in various formats:
            # - "80/tcp   open  http"
            # - "80/tcp    open     http"
            # - "PORT   STATE SERVICE" (header, skip)
            # - With --open flag, might have different spacing
            # - Some versions use different whitespace
            
            # Debug: log first few lines of output for troubleshooting
            if self.progress_callback and len(ports) > 10000:
                lines_preview = result.stdout.split('\n')[:20]
                preview = '\n'.join(lines_preview)
                if len(result.stdout) > 500:
                    preview += f"\n... ({len(result.stdout)} total chars)"
                # Only log if there's actual content
                if result.stdout.strip():
                    self.progress_callback(f"Parsing nmap output for {ip} ({len(result.stdout)} chars)...")
            
            for line in result.stdout.split('\n'):
                line = line.strip()
                if not line:
                    continue
                
                # Skip header lines
                if 'PORT' in line and 'STATE' in line:
                    continue
                if 'Nmap scan report' in line:
                    continue
                
                # Match port patterns - be more flexible with whitespace
                # Pattern: number/tcp followed by "open"
                # Try multiple patterns to handle different nmap versions
                patterns = [
                    r'^(\d+)/tcp\s+open',  # Standard: "80/tcp   open"
                    r'^(\d+)/tcp\s+open\s+',  # With trailing space
                    r'^\s*(\d+)/tcp\s+open',  # With leading space
                    r'(\d+)/tcp.*open',  # More flexible: any chars between
                ]
                
                for pattern in patterns:
                    match = re.search(pattern, line, re.IGNORECASE)
                    if match:
                        try:
                            port = int(match.group(1))
                            if 1 <= port <= 65535 and port not in open_ports:
                                open_ports.append(port)
                                break  # Found port, try next line
                        except (ValueError, IndexError):
                            continue
            
            # Log parsing results for debugging large scans
            if self.progress_callback and len(ports) > 10000:
                if open_ports:
                    self.progress_callback(f"Parsed {len(open_ports)} open port(s) from nmap output for {ip}")
                elif result.stdout:
                    # Check if we got any output at all
                    lines_with_port = [l for l in result.stdout.split('\n') if '/tcp' in l]
                    if lines_with_port:
                        self.progress_callback(f"Found {len(lines_with_port)} port lines in output but none matched 'open' pattern for {ip}")
                    else:
                        self.progress_callback(f"Nmap output for {ip} contains no port lines")
            
            if open_ports:
                if self.progress_callback:
                    self.progress_callback(f"Found {len(open_ports)} open port(s) on {ip}")
                return sorted(open_ports)
            
            # Check return code and output
            if result.returncode == 0:
                # Scan completed successfully
                # Check if we got valid nmap output
                if 'Nmap scan report' in result.stdout or 'Host is up' in result.stdout or '/tcp' in result.stdout:
                    # Got valid nmap output, just no open ports found
                    if self.progress_callback and len(ports) > 1000:
                        self.progress_callback(f"Scan completed for {ip} but no open ports found")
                    return []
                else:
                    # Unexpected output format
                    if self.progress_callback:
                        output_preview = result.stdout[:300] if result.stdout else "No output"
                        self.progress_callback(f"Unexpected nmap output format for {ip}: {output_preview}")
                    return []
            else:
                # Non-zero return code - might be an error or might just be no ports found
                # First check if this is a root privilege error that needs password
                if result.stderr and ('requires root privileges' in result.stderr.lower() or 
                                    'you requested a scan type which requires root' in result.stderr.lower()):
                    # Root privilege error - try to get password and retry
                    if not self.sudo_password and self.password_callback:
                        if self.progress_callback:
                            self.progress_callback(f"Nmap requires root privileges for {ip}, requesting password...")
                        password = self.password_callback()
                        if password:
                            self.sudo_password = password
                            # Retry the entire scan with sudo
                            return self.scan_ports_with_nmap(ip, ports)  # Recursive call with sudo password set
                        else:
                            # Password cancelled - fall back to connect scan
                            if self.progress_callback:
                                self.progress_callback(f"Password cancelled, using slower connect scan for {ip}...")
                            # Fall through to use connect scan instead
                            # We'll handle this by modifying the scan to use -sT
                            # For now, return empty and let the caller handle fallback
                            return []
                    elif self.sudo_password:
                        # Password was set but sudo still failed - might be wrong password
                        if self.progress_callback:
                            self.progress_callback(f"Sudo password failed for {ip}, trying connect scan...")
                        return []
                
                # Check if we got any useful output despite the error code
                if 'Nmap scan report' in result.stdout or 'Host is up' in result.stdout or '/tcp' in result.stdout:
                    # Got valid nmap output despite error code - return what we found
                    if open_ports:
                        return sorted(open_ports)
                    # No open ports but got valid output
                    if self.progress_callback and len(ports) > 1000:
                        self.progress_callback(f"Scan completed for {ip} (exit code {result.returncode}) but no open ports found")
                    return []
                else:
                    # Likely an actual error - log it with full details
                    if self.progress_callback:
                        error_msg = result.stderr[:500].strip() if result.stderr else f"Exit code: {result.returncode}"
                        stdout_preview = result.stdout[:300] if result.stdout else "No output"
                        # Show command that failed for debugging
                        cmd_str = ' '.join(result.args) if hasattr(result, 'args') else 'nmap'
                        full_error = f"Nmap scan error for {ip} (exit {result.returncode}): {error_msg}"
                        if stdout_preview and stdout_preview != "No output":
                            full_error += f" | Output preview: {stdout_preview}"
                        full_error += f" | Command: {cmd_str[:100]}"
                        self.progress_callback(full_error)
                    return []
        except subprocess.TimeoutExpired as e:
            if self.progress_callback:
                self.progress_callback(f"Nmap scan timed out for {ip}")
            return []
        except KeyboardInterrupt:
            # User cancelled - don't log as error
            if self.progress_callback:
                self.progress_callback(f"Nmap scan cancelled for {ip}")
            return []
        except Exception as e:
            # Catch any other exceptions and log them
            import traceback
            error_details = str(e)
            error_type = type(e).__name__
            if self.progress_callback:
                # Get traceback for debugging but keep message short
                try:
                    tb_str = traceback.format_exc()
                    # Only show last few lines of traceback to avoid spam
                    tb_lines = tb_str.split('\n')
                    tb_preview = '\n'.join(tb_lines[-5:]) if len(tb_lines) > 5 else tb_str
                    self.progress_callback(f"Nmap scan exception ({error_type}) for {ip}: {error_details} | {tb_preview}")
                except:
                    # If traceback fails, just show the error
                    self.progress_callback(f"Nmap scan exception ({error_type}) for {ip}: {error_details}")
            return []
    
    def scan_ports(self, ip: str, ports: List[int], max_threads: int = 100, use_nmap: bool = False) -> List[int]:
        """Scan specified ports on a device using threading or nmap.
        
        Note: use_nmap defaults to False for network scanner to use built-in threading scanner.
        Nmap can be used via the separate nmap tab if needed.
        """
        if not ports:
            return []
        
        # Use nmap only if explicitly requested (for nmap tab functionality)
        # Network scanner uses threading-based scanning by default
        if use_nmap and self.has_nmap and len(ports) > 100:
            try:
                nmap_result = self.scan_ports_with_nmap(ip, ports)
                return nmap_result  # Return nmap result (empty list if failed)
            except Exception as e:
                # Fall back to threading if nmap fails
                if self.progress_callback:
                    self.progress_callback(f"Nmap failed for {ip}, using threading fallback...")
                pass  # Continue to threading method
        
        # For small port lists, use sequential scanning
        if len(ports) <= 20:
            open_ports = []
            for port in ports:
                if not self.scanning:  # Check if scan was cancelled
                    break
                if self.scan_port(ip, port, timeout=1.0):
                    open_ports.append(port)
            return open_ports
        
        # For very large port ranges, reduce thread count to avoid overwhelming system
        if len(ports) > 10000:
            max_threads = min(max_threads, 50)  # Limit threads for very large ranges
        
        # For large port lists, use threading
        open_ports = []
        ports_lock = threading.Lock()
        
        def scan_port_worker(port: int):
            """Worker function to scan a single port."""
            if not self.scanning:  # Check if scan was cancelled
                return
            
            # Use reasonable timeout for port scanning
            # Balance between speed and reliability
            timeout = 0.8  # Increased from 0.3 to improve detection of open ports
            
            if self.scan_port(ip, port, timeout=timeout):
                with ports_lock:
                    open_ports.append(port)
        
        # Create threads for port scanning
        threads = []
        batch_size = max_threads
        
        for i in range(0, len(ports), batch_size):
            if not self.scanning:  # Check if scan was cancelled
                break
            
            batch = ports[i:i + batch_size]
            batch_threads = []
            
            for port in batch:
                if not self.scanning:
                    break
                thread = threading.Thread(target=scan_port_worker, args=(port,), daemon=True)
                thread.start()
                batch_threads.append(thread)
            
            # Wait for batch to complete with reasonable timeout
            # For large port ranges, use fixed timeout to prevent hanging
            if len(ports) > 10000:
                join_timeout = 2.0  # Reasonable timeout for very large ranges
            else:
                join_timeout = min(3.0, (batch_size * 0.8) + 1.0)  # Max 3 seconds per batch, account for 0.8s timeout per port
            
            # Wait for threads with timeout, but don't block forever
            for thread in batch_threads:
                if not self.scanning:  # Check cancellation before waiting
                    break
                thread.join(timeout=join_timeout)
                # If thread is still alive after timeout, continue anyway
                # (it's a daemon thread, so it won't block program exit)
            
            threads.extend(batch_threads)
            
            # Update progress for large scans (every 1000 ports or at batch boundaries)
            if self.progress_callback and len(ports) > 100:
                progress = min(i + batch_size, len(ports))
                percent = int((progress / len(ports)) * 100)
                # Only update every 1% to avoid too many callbacks
                if progress % max(1, len(ports) // 100) == 0 or i + batch_size >= len(ports):
                    self.progress_callback(f"Scanning ports on {ip}: {progress}/{len(ports)} ({percent}%)...")
        
        # Quick cleanup - don't wait too long for stragglers
        for thread in threads:
            if thread.is_alive() and self.scanning:
                thread.join(timeout=0.1)  # Very short timeout for cleanup
        
        return sorted(open_ports)
    
    def scan_common_ports(self, ip: str) -> List[int]:
        """Scan common ports on a device."""
        common_ports = [22, 23, 80, 443, 8080, 3389, 5900, 21, 25, 53, 135, 139, 445]
        return self.scan_ports(ip, common_ports)
    
    def scan_ip(self, ip: str, quick: bool = False, subnet_mask: str = "Unknown", 
                custom_ports: Optional[List[int]] = None, known_mac: Optional[str] = None) -> Optional[NetworkDevice]:
        """Scan a single IP address."""
        if self.progress_callback:
            port_info = f" ({len(custom_ports)} ports)" if custom_ports and len(custom_ports) > 20 else ""
            self.progress_callback(f"Scanning {ip}{port_info}...")
        
        # Check if device is reachable (using multiple methods)
        is_reachable = self.check_device_reachable(ip)
        
        # If we have a known MAC from ARP table, consider device reachable
        if not is_reachable and known_mac and known_mac != "Unknown":
            is_reachable = True
        
        # If device is not reachable by any method, skip it
        if not is_reachable:
            return None
        
        # Get basic info
        mac = known_mac if known_mac else self.get_mac_address(ip)
        hostname = self.get_hostname(ip)
        vendor = self._get_vendor_from_mac(mac)
        
        # Scan ports if not quick mode
        open_ports = []
        if not quick:
            if custom_ports:
                # Warn user about very large scans
                if len(custom_ports) > 50000 and self.progress_callback:
                    self.progress_callback(f"Starting full port scan on {ip} (this will take a while)...")
                elif len(custom_ports) > 10000 and self.progress_callback:
                    self.progress_callback(f"Starting large port scan on {ip} (this may take a while)...")
                
                # Always use threading-based port scanning for network scanner
                # Nmap is available via the separate nmap tab if needed
                if len(custom_ports) > 10000:
                    max_port_threads = 50
                elif len(custom_ports) > 1000:
                    max_port_threads = 100
                else:
                    max_port_threads = 150
                open_ports = self.scan_ports(ip, custom_ports, max_threads=max_port_threads, use_nmap=False)
            else:
                open_ports = self.scan_common_ports(ip)
        
        device = NetworkDevice(
            ip=ip,
            mac=mac,
            hostname=hostname,
            vendor=vendor,
            status="Online",
            last_seen=time.time(),
            open_ports=open_ports,
            subnet_mask=subnet_mask
        )
        
        return device
    
    def _get_subnet_mask_from_network(self, network: ipaddress.IPv4Network) -> str:
        """Get subnet mask from network prefix length."""
        prefix = network.prefixlen
        mask = (0xffffffff >> (32 - prefix)) << (32 - prefix)
        return socket.inet_ntoa(struct.pack("!I", mask))
    
    def scan_network(self, network_cidr: str, quick: bool = False, max_threads: int = 50,
                    custom_ports: Optional[List[int]] = None) -> List[NetworkDevice]:
        """Scan a network for devices."""
        if self.scanning:
            return list(self.devices.values())
        
        self.scanning = True
        self.devices.clear()
        
        try:
            network = ipaddress.IPv4Network(network_cidr, strict=False)
            hosts = list(network.hosts())
            
            # Calculate subnet mask from network
            subnet_mask = self._get_subnet_mask_from_network(network)
            
            # Get ARP table entries first to discover devices that might not respond to ping
            if self.progress_callback:
                self.progress_callback("Checking ARP table for known devices...")
            arp_entries = self.get_all_arp_entries()
            
            # Filter ARP entries to only include devices in our target network
            network_arp = {}
            for ip, mac in arp_entries.items():
                try:
                    ip_obj = ipaddress.IPv4Address(ip)
                    if ip_obj in network:
                        network_arp[ip] = mac
                except:
                    pass
            
            # Pre-ping all hosts to populate ARP table (helps discover more devices)
            # Only do this for smaller networks to avoid long delays
            if len(hosts) <= 254:  # Only for /24 or smaller networks
                if self.progress_callback:
                    self.progress_callback(f"Pre-scanning {len(hosts)} hosts to populate ARP table...")
                
                def quick_ping_worker(ip_str: str):
                    """Quick ping to populate ARP table."""
                    try:
                        self.ping_host(ip_str, timeout=0.2)  # Very short timeout
                    except:
                        pass
                
                # Quick ping all hosts in parallel to populate ARP
                ping_threads = []
                ping_batch_size = 200  # Larger batches for faster processing
                for i in range(0, len(hosts), ping_batch_size):
                    if not self.scanning:
                        break
                    batch = hosts[i:i + ping_batch_size]
                    batch_threads = []
                    
                    for host in batch:
                        if not self.scanning:
                            break
                        ip_str = str(host)
                        thread = threading.Thread(target=quick_ping_worker, args=(ip_str,), daemon=True)
                        thread.start()
                        batch_threads.append(thread)
                    
                    # Wait for batch with short timeout
                    for thread in batch_threads:
                        thread.join(timeout=0.3)
                    
                    ping_threads.extend(batch_threads)
                    
                    # Update progress
                    if self.progress_callback:
                        progress = min(i + ping_batch_size, len(hosts))
                        percent = int((progress / len(hosts)) * 100)
                        self.progress_callback(f"Pre-scanning: {progress}/{len(hosts)} ({percent}%)...")
                
                # Quick cleanup - don't wait too long
                for thread in ping_threads:
                    if thread.is_alive():
                        thread.join(timeout=0.1)
                
                # Refresh ARP table after pings
                if self.progress_callback:
                    self.progress_callback("Refreshing ARP table...")
                arp_entries = self.get_all_arp_entries()
                network_arp = {}
                for ip, mac in arp_entries.items():
                    try:
                        ip_obj = ipaddress.IPv4Address(ip)
                        if ip_obj in network:
                            network_arp[ip] = mac
                    except:
                        pass
            else:
                # For larger networks, skip pre-ping to avoid long delays
                network_arp = {}
                for ip, mac in arp_entries.items():
                    try:
                        ip_obj = ipaddress.IPv4Address(ip)
                        if ip_obj in network:
                            network_arp[ip] = mac
                    except:
                        pass
            
            if self.progress_callback:
                port_info = f" ({len(custom_ports)} ports)" if custom_ports else ""
                arp_info = f", {len(network_arp)} found in ARP" if network_arp else ""
                self.progress_callback(f"Scanning {len(hosts)} hosts{port_info}{arp_info}...")
            
            # Thread pool for scanning
            threads = []
            results_lock = threading.Lock()
            
            def scan_worker(ip_str: str):
                # Check if we have this IP in ARP table
                known_mac = network_arp.get(ip_str)
                device = self.scan_ip(ip_str, quick=quick, subnet_mask=subnet_mask, 
                                    custom_ports=custom_ports, known_mac=known_mac)
                if device:
                    with results_lock:
                        self.devices[ip_str] = device
            
            # Start scanning in batches
            batch_size = max_threads
            for i in range(0, len(hosts), batch_size):
                if not self.scanning:  # Check if scan was cancelled
                    break
                    
                batch = hosts[i:i + batch_size]
                batch_threads = []
                
                for host in batch:
                    if not self.scanning:  # Check if scan was cancelled
                        break
                    ip_str = str(host)
                    thread = threading.Thread(target=scan_worker, args=(ip_str,), daemon=True)
                    thread.start()
                    batch_threads.append(thread)
                
                # Wait for batch to complete with reasonable timeout
                # For large port scans, we need much longer timeout since port scanning can take time
                # IMPORTANT: Don't timeout too early - let each device complete its port scan
                if quick:
                    timeout = 2.0
                elif custom_ports and len(custom_ports) > 10000:
                    # Very large port ranges - if using nmap, it can take several minutes
                    # If using threading, calculate based on ports
                    if self.has_nmap:
                        timeout = 720.0  # 12 minutes for nmap on 50k ports (nmap can be slow)
                    else:
                        # 50,000 ports with 50 threads at 0.3s each = ~300 seconds max
                        # But we need to account for all threads completing
                        timeout = max(180.0, (len(custom_ports) / max_threads) * 0.3 * 4)  # 4x safety margin
                elif custom_ports and len(custom_ports) > 1000:
                    if self.has_nmap:
                        timeout = 240.0  # 4 minutes for nmap on large ranges
                    else:
                        timeout = 90.0  # 1.5 minutes for threading
                elif custom_ports and len(custom_ports) > 100:
                    timeout = 45.0  # Longer for large port scans
                else:
                    timeout = 3.0  # Default for common ports
                
                # Wait for all threads in batch, but allow them to complete their work
                # Use a longer timeout per thread to ensure port scans complete
                for thread in batch_threads:
                    if not self.scanning:  # Check cancellation
                        break
                    # Give each thread enough time to complete its port scan
                    thread.join(timeout=timeout)
                    # Continue even if thread is still alive - it will finish in background
                    # This ensures we don't stop scanning other devices while one is still scanning ports
                
                # Don't wait forever - if threads are hanging, continue
                # Check if we should continue based on scanning flag
                if not self.scanning:
                    break
                
                # Update progress with percentage
                if self.progress_callback:
                    progress = min(i + batch_size, len(hosts))
                    percent = int((progress / len(hosts)) * 100)
                    found = len(self.devices)
                    self.progress_callback(f"Scanned {progress}/{len(hosts)} hosts ({percent}%) - Found {found} device(s)...")
            
        except Exception as e:
            print(f"Error scanning network: {e}")
        finally:
            self.scanning = False
        
        return list(self.devices.values())
    
    def stop_scan(self):
        """Stop the current scan."""
        self.scanning = False
    
    def get_devices(self) -> List[NetworkDevice]:
        """Get all discovered devices."""
        return list(self.devices.values())
    
    def get_device(self, ip: str) -> Optional[NetworkDevice]:
        """Get a specific device by IP."""
        return self.devices.get(ip)
    
    def update_device(self, device: NetworkDevice):
        """Update or add a device."""
        self.devices[device.ip] = device
    
    def remove_device(self, ip: str):
        """Remove a device."""
        if ip in self.devices:
            del self.devices[ip]


# Fix missing import
import struct

