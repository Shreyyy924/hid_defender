# ==========================================
# Configuration & Constants
# ==========================================

import os
import sys
import platform

# Platform detection
IS_WINDOWS = sys.platform == "win32"
IS_MACOS = sys.platform == "darwin"
IS_LINUX = sys.platform.startswith("linux")

# File paths - point to parent directory where data files are stored
DIR_PATH = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
WHITELIST_PATH = os.path.join(DIR_PATH, "data", "trusted_devices.json")
LOG_PATH = os.path.join(DIR_PATH, "hid_alerts.log")

# List of major peripheral brands to reduce false positives
BIG_BRANDS = [
    "logitech", "dell", "hp", "microsoft", "lenovo", "corsair", 
    "razer", "steelseries", "asus", "acer", "apple", "intel"
]

# Hardware Vendor IDs (VIDs) associated with attack tools
ATTACK_VECTORS = [
    "VID_2E8A", "VID_239A", "VID_16C0", "VID_2341", 
    "VID_1209", "VID_6666", "VID_CAFE", "VID_1B4F"
]

# Mapping for suspicious VIDs to friendly names
SUSPICIOUS_MAPPING = {
    "VID_2E8A": "Raspberry Pi",
    "VID_239A": "Adafruit",
    "VID_16C0": "Teensy/Arduino",
    "VID_2341": "Arduino",
    "VID_1209": "Open Source Platform",
    "VID_6666": "Prototype/Generic",
    "VID_CAFE": "Prototype/BadUSB",
    "VID_1B4F": "SparkFun"
}

# Malicious command patterns to detect
MALICIOUS_PATTERNS = [
    "powershell", "pwsh", "cmd.exe", "cmd ",
    "reg add", "reg delete",
    "taskkill", "schtasks",
    "wmic", "Get-Process", "Stop-Service",
    "Set-MpPreference", "Disable-WindowsOptionalFeature",
    "wget", "curl", "invoke-webrequest",
    "certutil", "bitsadmin",
    "net user", "net group",
    "icacls", "attrib", "del ", "rmdir"
]

# Keystroke monitoring thresholds
KEYSTROKE_THRESHOLD = 15  # keystrokes per second (normal: 5-10)
FIRST_INPUT_DELAY_THRESHOLD = 1  # seconds (automated: <1 sec)

# Globals for logic processing
RECENT_SEEN = {}  # Helps avoid double-logging the same device (debouncing)
