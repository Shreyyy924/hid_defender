# ==========================================
# USB Device Monitoring Module
# ==========================================

import subprocess
import json
from datetime import datetime

# Handle both package imports and standalone execution
try:
    from .config import IS_WINDOWS, IS_MACOS, IS_LINUX
except ImportError:
    from config import IS_WINDOWS, IS_MACOS, IS_LINUX


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
    """Get USB devices on Windows using WMI."""
    devices = []
    try:
        for dev in wmi_client.Win32_PnPEntity():
            if _is_valid_hid(dev):
                devices.append(_parse_windows_device(dev))
    except Exception as e:
        print(f"Error querying USB devices: {e}")
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
