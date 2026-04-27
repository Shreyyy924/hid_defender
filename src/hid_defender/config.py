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

# File paths - point to project root where data files are stored
DIR_PATH = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
WHITELIST_PATH = os.path.join(DIR_PATH, "data", "trusted_devices.json")
LOG_PATH = os.path.join(DIR_PATH, "hid_alerts.log")

# List of major peripheral brands to reduce false positives
BIG_BRANDS = [
    "logitech", "dell", "hp", "microsoft", "lenovo", "corsair", 
    "razer", "steelseries", "asus", "acer", "apple", "intel"
]

# Comprehensive mapping of Trusted Vendor IDs (VIDs) to manufacturer names
KNOWN_VENDORS = {
    "VID_413C": "Dell", "VID_046D": "Logitech", "VID_045E": "Microsoft", "VID_03F0": "HP",
    "VID_8087": "Intel", "VID_05AC": "Apple", "VID_17EF": "Lenovo", "VID_0502": "Acer",
    "VID_0B05": "ASUS", "VID_04E8": "Samsung", "VID_054C": "Sony", "VID_0930": "Toshiba",
    "VID_04A9": "Canon", "VID_04B8": "Epson", "VID_04F9": "Brother", "VID_0951": "Kingston",
    "VID_0781": "SanDisk", "VID_1058": "Western Digital", "VID_0BC2": "Seagate", "VID_8564": "Transcend",
    "VID_12D1": "Huawei", "VID_19D2": "ZTE", "VID_2717": "Xiaomi", "VID_05C6": "Qualcomm",
    "VID_0BDA": "Realtek", "VID_0A5C": "Broadcom", "VID_0E8D": "MediaTek", "VID_0955": "NVIDIA",
    "VID_1022": "AMD", "VID_0451": "Texas Instruments", "VID_04B4": "Cypress / Infineon", "VID_04D8": "Microchip",
    "VID_0483": "STMicroelectronics", "VID_1FC9": "NXP", "VID_0403": "FTDI", "VID_067B": "Prolific",
    "VID_10C4": "Silicon Labs", "VID_2341": "Arduino", "VID_2E8A": "Raspberry Pi", "VID_18D1": "Google",
    "VID_1949": "Amazon", "VID_2833": "Meta (Oculus)", "VID_1532": "Razer", "VID_1B1C": "Corsair",
    "VID_1038": "SteelSeries", "VID_2516": "Cooler Master", "VID_1462": "MSI", "VID_1458": "Gigabyte",
    "VID_1849": "ASRock", "VID_2357": "TP-Link", "VID_0846": "Netgear", "VID_2001": "D-Link",
    "VID_13B1": "Linksys", "VID_050D": "Belkin", "4112": "Ubiquiti", "VID_2636": "Juniper",
    "VID_1050": "Yubico", "VID_096E": "Feitian", "VID_291A": "Anker", "VID_2568": "UGREEN",
    "VID_0B0E": "Jabra", "VID_047F": "Plantronics / Poly", "VID_1395": "Sennheiser", "VID_05A7": "Bose",
    "VID_041E": "Creative", "VID_0ECB": "JBL", "VID_1397": "Behringer", "VID_0FD9": "Elgato",
    "VID_056A": "Wacom", "VID_0A5F": "Zebra", "VID_0C2E": "Honeywell", "VID_1B55": "ZKTeco",
    "VID_04C5": "Fujitsu", "VID_0409": "NEC", "VID_04DA": "Panasonic", "VID_05CA": "Ricoh",
    "VID_043D": "Lexmark", "VID_0543": "ViewSonic", "VID_04A5": "BenQ", "VID_1004": "LG",
    "VID_0471": "Philips", "VID_04DD": "Sharp", "VID_0547": "Hitachi", "VID_040A": "Kodak",
    "VID_07B4": "Olympus", "VID_091E": "Garmin", "VID_1390": "TomTom", "VID_2CA3": "DJI",
    "VID_2672": "GoPro", "VID_174C": "Synology", "VID_1C04": "QNAP", "VID_C0A9": "Crucial",
    "VID_125F": "Adata", "VID_154B": "PNY", "VID_0833": "Targus", "VID_047D": "Kensington",
    "VID_058F": "Alcor Micro"
}

# Hardware Vendor IDs (VIDs) associated with attack tools
ATTACK_VECTORS = [
    "VID_2E8A", "VID_239A", "VID_16C0", "VID_2341", 
    "VID_1209", "VID_6666", "VID_CAFE", "VID_1B4F"
]

# Mapping for suspicious VIDs to friendly names
SUSPICIOUS_MAPPING = {
    "VID_2E8A": "Raspberry Pi Pico (BadUSB)",
    "VID_239A": "Adafruit / CircuitPython (attack tool)",
    "VID_16C0": "Teensy / Arduino (BadUSB)",
    "VID_2341": "Arduino (BadUSB)",
    "VID_1209": "Open-source attack platform",
    "VID_6666": "Prototype / Generic BadUSB",
    "VID_CAFE": "BadUSB prototype",
    "VID_1B4F": "SparkFun (attack tool)",
    "VID_DEAD": "Spoofed / Fake USB Device",
}

# Malicious command patterns to detect
MALICIOUS_PATTERNS = [
    # Shell launchers
    "powershell", "pwsh", "cmd.exe", "cmd /c",
    # Registry & scheduling
    "reg add", "reg delete",
    "taskkill", "schtasks",
    # WMI & process
    "wmic", "Get-Process", "Stop-Service",
    # AV/security bypass
    "Set-MpPreference", "Disable-WindowsOptionalFeature",
    # Remote download
    "wget", "curl", "invoke-webrequest",
    "certutil", "bitsadmin",
    # User & ACL manipulation
    "net user", "net group",
    "icacls", "attrib", "del /f", "rmdir /s",
    # Additional BadUSB vectors
    "mshta", "rundll32", "wscript", "cscript",
    "Start-Process", "Invoke-Expression", "iex ",
    "DownloadString", "-EncodedCommand",
]

# Keystroke monitoring thresholds
KEYSTROKE_THRESHOLD = 15  # keystrokes per second (normal: 5-10)
FIRST_INPUT_DELAY_THRESHOLD = 2  # seconds (automated: <2 sec — Pico scripts often wait ~0.5s)

# Globals for logic processing
RECENT_SEEN = {}  # Helps avoid double-logging the same device (debouncing)
