#!/usr/bin/env python3
"""
YaP Network Scanner - Device Storage
Manages persistent storage of device configurations.
"""

import os
import json
from typing import Dict, List, Optional
from pathlib import Path
from network_scanner import NetworkDevice


class DeviceStorage:
    """Manages storage of device configurations."""
    
    def __init__(self, config_dir: Optional[str] = None):
        """Initialize device storage."""
        if config_dir is None:
            # Use standard config directory
            if os.name == 'nt':  # Windows
                config_dir = os.path.join(os.getenv('APPDATA', ''), 'YaP-Network-Scanner')
            else:  # Linux/Mac
                config_dir = os.path.join(os.path.expanduser('~'), '.config', 'yap-network-scanner')
        
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        self.devices_file = self.config_dir / 'devices.json'
        self.config_file = self.config_dir / 'config.json'
    
    def save_device(self, device: NetworkDevice) -> bool:
        """Save a device configuration."""
        try:
            devices = self.load_all_devices()
            devices[device.ip] = device.to_dict()
            
            with open(self.devices_file, 'w') as f:
                json.dump(devices, f, indent=2)
            
            return True
        except Exception as e:
            print(f"Error saving device: {e}")
            return False
    
    def load_all_devices(self) -> Dict[str, dict]:
        """Load all saved devices."""
        if not self.devices_file.exists():
            return {}
        
        try:
            with open(self.devices_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading devices: {e}")
            return {}
    
    def get_device(self, ip: str) -> Optional[NetworkDevice]:
        """Get a device by IP."""
        devices = self.load_all_devices()
        device_data = devices.get(ip)
        if device_data:
            return NetworkDevice.from_dict(device_data)
        return None
    
    def delete_device(self, ip: str) -> bool:
        """Delete a device."""
        try:
            devices = self.load_all_devices()
            if ip in devices:
                del devices[ip]
                with open(self.devices_file, 'w') as f:
                    json.dump(devices, f, indent=2)
                return True
            return False
        except Exception as e:
            print(f"Error deleting device: {e}")
            return False
    
    def save_config(self, config: dict) -> bool:
        """Save application configuration."""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2)
            return True
        except Exception as e:
            print(f"Error saving config: {e}")
            return False
    
    def load_config(self) -> dict:
        """Load application configuration."""
        if not self.config_file.exists():
            return {}
        
        try:
            with open(self.config_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading config: {e}")
            return {}
    
    def get_config_value(self, key: str, default=None):
        """Get a configuration value."""
        config = self.load_config()
        return config.get(key, default)
    
    def set_config_value(self, key: str, value) -> bool:
        """Set a configuration value."""
        config = self.load_config()
        config[key] = value
        return self.save_config(config)

