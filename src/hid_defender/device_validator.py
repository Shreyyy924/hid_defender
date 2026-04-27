# ==========================================
# Device Validation & Whitelist Management
# ==========================================

import os
import re
import json
import time
from datetime import datetime

# Handle both package imports and standalone execution
try:
    from .config import (
        WHITELIST_PATH, ATTACK_VECTORS, BIG_BRANDS,
        SUSPICIOUS_MAPPING, RECENT_SEEN, KNOWN_VENDORS
    )
    from .device_monitor import get_macos_usb_devices
except ImportError:
    # Fallback for testing or standalone execution
    from config import (  # type: ignore
        WHITELIST_PATH, ATTACK_VECTORS, BIG_BRANDS,
        SUSPICIOUS_MAPPING, RECENT_SEEN, KNOWN_VENDORS
    )
    from device_monitor import get_macos_usb_devices  # type: ignore

HWID_RE = re.compile(r"(VID_[0-9A-F]{4}).*(PID_[0-9A-F]{4})")


def normalize_hardware_id(hardware_id):
    """Normalize a Windows PNP device ID to VID_xxxx&PID_xxxx."""
    hw = str(hardware_id).upper()
    match = HWID_RE.search(hw)
    if match:
        return f"{match.group(1)}&{match.group(2)}"
    return hw.strip()


def hardware_id_matches(stored_id, raw_id):
    """Compare whitelist entries against the detected device ID."""
    normalized_stored = normalize_hardware_id(stored_id)
    normalized_raw = normalize_hardware_id(raw_id)
    return normalized_stored and normalized_raw and normalized_stored == normalized_raw


def get_whitelist():
    """Loads the trusted devices from JSON."""
    if not os.path.exists(WHITELIST_PATH):
        return []
    try:
        with open(WHITELIST_PATH, "r") as f:
            return json.load(f)
    except:
        return []


def save_whitelist(data):
    """Saves the trusted device list to JSON."""
    os.makedirs(os.path.dirname(WHITELIST_PATH), exist_ok=True)
    with open(WHITELIST_PATH, "w") as f:
        json.dump(data, f, indent=4)


def _now_str():
    """Return current timestamp string."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _touch_device(whitelist, hw_id):
    """Update last_seen for a device already in the whitelist. Returns True if found."""
    now = _now_str()
    for item in whitelist:
        if hardware_id_matches(item.get("hardware_id", ""), hw_id):
            item["last_seen"] = now
            if "first_seen" not in item:
                item["first_seen"] = now
            save_whitelist(whitelist)
            return True
    return False


def run_baseline_setup(wmi_obj=None, logger=None):
    """First-run logic to trust currently connected hardware."""
    current_whitelist = get_whitelist()
    if current_whitelist:
        return current_whitelist

    print("Initial startup: Establishing trusted hardware baseline...")
    new_baseline = []

    try:
        from .config import IS_WINDOWS
    except ImportError:
        from config import IS_WINDOWS  # type: ignore

    if wmi_obj:
        # Windows with wmi package available
        from .device_monitor import _is_valid_hid, _parse_windows_device
        for dev in wmi_obj.Win32_PnPEntity():
            if _is_valid_hid(dev):
                details = _parse_windows_device(dev)
                hw_id = normalize_hardware_id(details['id'])
                entry = {"hardware_id": hw_id, "vendor": details['vendor'], "name": details['name']}
                if entry not in new_baseline:
                    entry["first_seen"] = _now_str()
                    entry["last_seen"]  = _now_str()
                    new_baseline.append(entry)
    elif IS_WINDOWS:
        # Windows fallback: use built-in wmic command (no wmi package needed)
        from .device_monitor import get_windows_usb_devices_wmic
        devices = get_windows_usb_devices_wmic()
        for details in devices:
            hw_id = normalize_hardware_id(details['id'])
            entry = {"hardware_id": hw_id, "vendor": details['vendor'], "name": details['name']}
            if entry not in new_baseline:
                entry["first_seen"] = _now_str()
                entry["last_seen"]  = _now_str()
                new_baseline.append(entry)
    else:
        # macOS/Linux
        devices = get_macos_usb_devices()
        for details in devices:
            hw_id = normalize_hardware_id(details['id'])
            entry = {"hardware_id": hw_id, "vendor": details['vendor'], "name": details['name']}
            if entry not in new_baseline:
                entry["first_seen"] = _now_str()
                entry["last_seen"]  = _now_str()
                new_baseline.append(entry)

    save_whitelist(new_baseline)
    print(f"Done. {len(new_baseline)} devices registered as trusted.")
    return new_baseline


def parse_device(dev_info):
    """Convert device info to standard format with vendor mapping."""
    # If it's a dict (from macOS/Linux), use it directly
    if isinstance(dev_info, dict):
        name = dev_info.get('name', 'Unknown')
        vendor = dev_info.get('vendor', 'Unknown')
        product = dev_info.get('product', 'Unknown')
        hw_id = dev_info.get('id', 'Unknown')
    else:
        # Windows WMI object
        pnp_id = str(getattr(dev_info, "PNPDeviceID", "Unknown"))
        name = str(getattr(dev_info, "Name", "Unknown")).strip()
        manu = str(getattr(dev_info, "Manufacturer", "Unknown")).strip()
        prod = str(getattr(dev_info, "Caption", "Unknown")).strip()
        
        vendor = manu if manu and "standard" not in manu.lower() else "Unknown"
        product = prod
        hw_id = pnp_id
        
        # Smart Vendor Mapping (Expanded with 100+ manufacturers)
        for vid, brand in KNOWN_VENDORS.items():
            if vid in pnp_id.upper():
                vendor = brand
                break
        
        # Secondary check for legacy mapping
        if vendor == "Unknown":
            for vid, brand in SUSPICIOUS_MAPPING.items():
                if vid in pnp_id.upper():
                    vendor = brand
                    break
        
        # Name refinement
        if ("Input Device" in name or name == "Unknown") and vendor != "Unknown":
            name = f"{vendor} Peripheral"
        elif vendor != "Unknown" and vendor not in name:
            if "HID-compliant" in name or "Standard" in name:
                name = f"{vendor} {name}"
    
    return {
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "name": name,
        "vendor": vendor,
        "product": product,
        "id": hw_id
    }


def evaluate(info, whitelist):
    """Analyzes a new connection for suspicious traits."""
    if not isinstance(info, dict):
        return "ERROR", "ALLOW", "Invalid device info format"

    # Handle both 'id' (from device_monitor) and 'hardware_id' (from fixtures)
    device_id = info.get('id') or info.get('hardware_id')
    if not device_id:
        return "UNKNOWN", "ALLOW", "No device ID available"
    
    raw_id = normalize_hardware_id(device_id)
    v_low = info.get('vendor', '').lower()
    p_low = info.get('product', info.get('description', info.get('name', ''))).lower()
    n_low = info.get('name', info.get('description', info.get('product', ''))).lower()

    # Step 1: Check blacklisted hardware IDs for known attack vectors
    # Note: If a VID is in BOTH KNOWN_VENDORS and ATTACK_VECTORS (like Pi Pico),
    # we allow it initially but keep the behavioral monitor active.
    for vid, brand in KNOWN_VENDORS.items():
        if vid in raw_id:
            return "TRUSTED", "ALLOWED", f"Manufacturer: {brand} (Known VID)"

    for bad_vid in ATTACK_VECTORS:
        if bad_vid in raw_id:
            return "UNTRUSTED", "BLOCKED", f"Attack-vector VID detected: {bad_vid}"

    # Step 2: Check the trusted whitelist by exact normalized VID/PID match
    for item in whitelist:
        if hardware_id_matches(item.get("hardware_id", ""), raw_id):
            # Update last_seen timestamp in the JSON file
            _touch_device(whitelist, raw_id)
            return "TRUSTED", "ALLOWED", "Whitelisted device"

    # Step 3: Heuristic allow-list for familiar brands and mice
    if any(brand in v_low or brand in p_low or brand in n_low for brand in BIG_BRANDS):
        return "SAFE", "ALLOWED", "Known peripheral brand"

    if "mouse" in p_low or "mouse" in n_low:
        return "SAFE", "ALLOWED", "Likely mouse device"

    # Default: unknown HID device is treated as suspicious in student demo mode
    return "UNTRUSTED", "BLOCKED", "Unknown HID device"


def should_debounce(device_id):
    """Check if device was recently seen (debouncing logic)."""
    base_sig = device_id
    if "VID_" in base_sig.upper():
        try:
            start = base_sig.upper().index("VID_")
            base_sig = base_sig[start:start+17]
        except:
            pass
    
    now = time.time()
    if base_sig in RECENT_SEEN and (now - RECENT_SEEN[base_sig] < 5):
        return True
    
    RECENT_SEEN[base_sig] = now
    return False
