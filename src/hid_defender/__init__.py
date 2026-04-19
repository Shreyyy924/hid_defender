"""
HID Defender - Cross-Platform USB Device Security Monitor

A security monitoring system that detects and prevents unauthorized HID (Human Interface Device)
connections, such as malicious keyboards and mice, from accessing your system.

Main Features:
    - Real-time USB device monitoring
    - Trusted device whitelisting
    - Keystroke pattern detection for malicious payloads
    - Automated device disabling and workstation locking
    - Cross-platform support (Windows, macOS, Linux)
    - Web-based dashboard for event monitoring

Usage:
    Command-line:
        hid-defender --monitor          # Start monitoring
        hid-defender --dashboard        # Start web dashboard
        hid-defender --setup            # Configure trusted devices
    
    Programmatic:
        from hid_defender.device_monitor import get_macos_usb_devices
        from hid_defender.device_validator import get_whitelist
        
        devices = get_macos_usb_devices()
        whitelist = get_whitelist()

Author: HID Defender Team
License: MIT
Version: 1.0.0
"""

__version__ = "1.0.0"
__author__ = "HID Defender Team"
__license__ = "MIT"

# Import main components for easier access
from .config import (
    IS_WINDOWS,
    IS_MACOS,
    IS_LINUX,
    LOG_PATH,
    WHITELIST_PATH,
    KEYSTROKE_THRESHOLD,
    MALICIOUS_PATTERNS,
)
from .device_monitor import get_macos_usb_devices
from .device_validator import (
    get_whitelist,
    parse_device,
    evaluate,
)
from .logging_setup import init_logger, log_event

__all__ = [
    "IS_WINDOWS",
    "IS_MACOS",
    "IS_LINUX",
    "LOG_PATH",
    "WHITELIST_PATH",
    "KEYSTROKE_THRESHOLD",
    "MALICIOUS_PATTERNS",
    "get_macos_usb_devices",
    "get_whitelist",
    "parse_device",
    "evaluate",
    "init_logger",
    "log_event",
]
