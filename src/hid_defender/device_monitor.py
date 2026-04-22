# ==========================================
# USB Device Monitoring Module
# ==========================================

import subprocess
import json
import threading
import time
from datetime import datetime
from typing import List, Dict, Callable, Optional, Any

# Handle both package imports and standalone execution
try:
    from .config import IS_WINDOWS, IS_MACOS, IS_LINUX
except ImportError:
    from config import IS_WINDOWS, IS_MACOS, IS_LINUX  # type: ignore


def get_macos_usb_devices():
    """Get USB devices on macOS using system_profiler."""
    try:
        result = subprocess.run(
            ["system_profiler", "SPUSBDataType", "-json"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            data = json.loads(result.stdout)
            devices = []
            for item in data.get("SPUSBDataType", []):
                devices.extend(_parse_macos_usb_item(item, []))
            return devices
    except Exception as e:
        print(f"Error querying USB devices: {e}")
    return []


def _parse_macos_usb_item(item, parent_path):
    """Recursively parse macOS USB device tree."""
    devices = []
    current_path = parent_path + [item.get("_name", "Unknown")]
    
    # Check if this item is a USB device (has vendor/product info)
    name = item.get("_name", "Unknown")
    vendor = item.get("manufacturer", "Unknown")
    product = item.get("product_name", name)
    
    # Extract VID/PID if available
    vid = item.get("vendor_id", "").replace("0x", "").upper()
    pid = item.get("product_id", "").replace("0x", "").upper()
    hw_id = f"VID_{vid}PID_{pid}" if vid and pid else name
    
    # If this item has device info, add it
    if vendor != "Unknown" or "USB" in str(current_path) or vid or pid:
        devices.append({
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "name": product,
            "vendor": vendor,
            "product": product,
            "id": hw_id
        })
    
    # Recurse into subitems if they exist
    if "_items" in item:
        for subitem in item["_items"]:
            devices.extend(_parse_macos_usb_item(subitem, current_path))
    
    return devices


def get_windows_usb_devices(wmi_client):
    """Get USB devices on Windows using WMI, falling back to wmic on failure."""
    devices = []
    try:
        for dev in wmi_client.Win32_PnPEntity():
            if _is_valid_hid(dev):
                devices.append(_parse_windows_device(dev))
        return devices
    except Exception as e:
        # WMI COM query failed (common on some Windows configs) — fall back to wmic
        return get_windows_usb_devices_wmic()



def get_windows_usb_devices_wmic():
    """Get USB HID devices using built-in wmic command (no wmi package needed)."""
    devices = []
    try:
        result = subprocess.run(
            [
                "wmic", "path", "Win32_PnPEntity",
                "where", "PNPDeviceID like 'USB%'",
                "get", "PNPDeviceID,Name,Manufacturer,Caption",
                "/format:csv"
            ],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            return devices

        lines = [l.strip() for l in result.stdout.splitlines() if l.strip()]
        # First line is header: Node,Caption,Manufacturer,Name,PNPDeviceID
        if len(lines) < 2:
            return devices

        header = [h.strip() for h in lines[0].split(",")]
        for line in lines[1:]:
            parts = line.split(",")
            if len(parts) < len(header):
                continue
            row = dict(zip(header, [p.strip() for p in parts]))
            pnp = row.get("PNPDeviceID", "")
            name = row.get("Name", "Unknown")
            manu = row.get("Manufacturer", "Unknown")
            caption = row.get("Caption", name)
            desc = name.lower()

            # Filter: must be USB and not a hub/host controller
            if "USB" not in pnp.upper():
                continue
            if "hub" in desc or "host controller" in desc:
                continue

            keywords = ["hid", "keyboard", "mouse", "input", "audio", "composite", "media"]
            if not any(k in desc for k in keywords):
                continue

            devices.append({
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "name": name,
                "vendor": manu,
                "product": caption,
                "id": pnp
            })
    except Exception as e:
        print(f"Error querying USB devices via wmic: {e}")
    return devices


def _is_valid_hid(dev):
    """Filters out non-HID system components (Windows)."""
    try:
        pnp = str(getattr(dev, "PNPDeviceID", "")).upper()
        desc = str(getattr(dev, "Description", "")).lower()
        guid = str(getattr(dev, "ClassGuid", "")).lower()
        
        # We only care about physical USB devices
        if "USB" not in pnp:
            return False
        
        # Ignore Root Hubs and Host Controllers
        if "hub" in desc or "host controller" in desc:
            return False

        # If it's explicitly HID/Input, catch it immediately
        if guid == "{745a17a0-74d3-11d0-b6fe-00a0c90f57da}":
            return True
        
        # Broaden to catch Audio Interfaces/Composite devices
        keywords = ["hid", "keyboard", "mouse", "input", "audio", "composite", "media"]
        return any(x in desc for x in keywords)
    except:
        return False


def _parse_windows_device(dev):
    """Parse Windows WMI device into standard format."""
    pnp_id = str(getattr(dev, "PNPDeviceID", "Unknown"))
    name = str(getattr(dev, "Name", "Unknown")).strip()
    manu = str(getattr(dev, "Manufacturer", "Unknown")).strip()
    prod = str(getattr(dev, "Caption", "Unknown")).strip()

    return {
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "name": name,
        "vendor": manu,
        "product": prod,
        "id": pnp_id
    }


class BackgroundDeviceMonitor:
    """Non-blocking background device monitor with caching."""
    
    def __init__(self, callback: Optional[Callable[[List[Dict[str, Any]]], None]] = None, 
                 scan_interval: float = 2.0, cache_ttl: float = 1.0, wmi_client: Optional[Any] = None):
        """
        Initialize the background device monitor.
        
        Args:
            callback: Function to call with new devices when they change
            scan_interval: How often to scan for devices (seconds)
            cache_ttl: How long to cache device list before forcing refresh (seconds)
            wmi_client: Windows WMI client (optional)
        """
        self.callback = callback
        self.scan_interval = scan_interval
        self.cache_ttl = cache_ttl
        self.wmi_client = wmi_client
        
        self.is_running = False
        self.thread: Optional[threading.Thread] = None
        
        # Device caching
        self._cached_devices: List[Dict[str, Any]] = []
        self._last_scan_time: float = 0.0
        self._device_ids_seen: set = set()
        self._lock = threading.Lock()
    
    def start(self) -> None:
        """Start the background monitoring thread."""
        if self.is_running:
            return
        
        self.is_running = True
        self.thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.thread.start()
    
    def stop(self) -> None:
        """Stop the background monitoring thread."""
        self.is_running = False
        if self.thread:
            self.thread.join(timeout=5)
    
    def _monitoring_loop(self) -> None:
        """Main monitoring loop running in background thread."""
        while self.is_running:
            try:
                devices = self._get_devices_with_cache()
                
                # Detect new devices
                current_ids = {d['id'] for d in devices}
                new_ids = current_ids - self._device_ids_seen
                
                if new_ids and self.callback:
                    # Call callback with only new devices
                    new_devices = [d for d in devices if d['id'] in new_ids]
                    self.callback(new_devices)
                
                self._device_ids_seen = current_ids
                
            except Exception as e:
                print(f"Error in device monitoring loop: {e}")
            
            time.sleep(self.scan_interval)
    
    def _get_devices_with_cache(self) -> List[Dict[str, Any]]:
        """Get devices, using cache if still valid."""
        now = time.time()
        
        with self._lock:
            # Use cache if it's still fresh
            if self._cached_devices and (now - self._last_scan_time) < self.cache_ttl:
                return self._cached_devices
        
        # Perform actual scan
        if IS_MACOS:
            devices = get_macos_usb_devices()
        elif IS_WINDOWS and self.wmi_client:
            devices = get_windows_usb_devices(self.wmi_client)
        elif IS_WINDOWS:
            # Fallback: use built-in wmic command (no wmi package needed)
            devices = get_windows_usb_devices_wmic()
        else:
            devices = []
        
        # Update cache
        with self._lock:
            self._cached_devices = devices
            self._last_scan_time = now
        
        return devices
    
    def get_current_devices(self) -> List[Dict[str, Any]]:
        """Get the currently cached device list."""
        with self._lock:
            return list(self._cached_devices)
