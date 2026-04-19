# HID Defender Test Suite
# Comprehensive test cases for the HID Defender security system

import pytest
import json
import os
import tempfile
import time
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
import sys

# Add src to path so hid_defender can be imported as a package
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root / "src"))

# Import modules as hid_defender.module
import hid_defender.config as config
import hid_defender.device_validator as device_validator
import hid_defender.device_monitor as device_monitor
import hid_defender.logging_setup as logging_setup
import hid_defender.keystroke_monitor as keystroke_monitor
import hid_defender.alert_system as alert_system

# Re-export for easier access
WHITELIST_PATH = config.WHITELIST_PATH
LOG_PATH = config.LOG_PATH
IS_MACOS = config.IS_MACOS
IS_WINDOWS = config.IS_WINDOWS
IS_LINUX = config.IS_LINUX
IS_LINUX = config.IS_LINUX
ATTACK_VECTORS = config.ATTACK_VECTORS
BIG_BRANDS = config.BIG_BRANDS

get_whitelist = device_validator.get_whitelist
save_whitelist = device_validator.save_whitelist
evaluate = device_validator.evaluate
get_macos_usb_devices = device_monitor.get_macos_usb_devices
init_logger = logging_setup.init_logger
log_event = logging_setup.log_event
KeystrokeMonitor = keystroke_monitor.KeystrokeMonitor
show_alert = alert_system.show_alert


@pytest.fixture
def temp_whitelist_file(tmp_path):
    """Create a temporary whitelist file for testing."""
    whitelist_path = tmp_path / "trusted_devices.json"
    sample_data = [
        {
            "hardware_id": "VID_1B1C&PID_1BAC",
            "vendor": "Corsair",
            "description": "Gaming Keyboard"
        },
        {
            "hardware_id": "VID_046D&PID_C077",
            "vendor": "Logitech",
            "description": "USB Mouse"
        }
    ]
    with open(whitelist_path, 'w') as f:
        json.dump(sample_data, f)
    return whitelist_path


@pytest.fixture
def temp_log_file(tmp_path):
    """Create a temporary log file for testing."""
    log_path = tmp_path / "hid_alerts.log"
    return log_path


@pytest.fixture
def mock_device():
    """Mock USB device for testing."""
    return {
        "hardware_id": "VID_DEAD&PID_BEEF",
        "vendor": "Unknown Vendor",
        "description": "Suspicious HID Device",
        "device_type": "keyboard"
    }


@pytest.fixture
def trusted_device():
    """Mock trusted USB device for testing."""
    return {
        "hardware_id": "VID_1B1C&PID_1BAC",
        "vendor": "Corsair",
        "description": "Gaming Keyboard",
        "device_type": "keyboard"
    }


@pytest.fixture(autouse=True)
def mock_config_paths(tmp_path, monkeypatch):
    """Mock configuration paths to use temporary files."""
    # Mock the paths in config module
    monkeypatch.setattr('hid_defender.config.WHITELIST_PATH', str(tmp_path / "trusted_devices.json"))
    monkeypatch.setattr('hid_defender.config.LOG_PATH', str(tmp_path / "hid_alerts.log"))

    # Also mock in device_validator and logging_setup
    monkeypatch.setattr('hid_defender.device_validator.WHITELIST_PATH', str(tmp_path / "trusted_devices.json"))
    monkeypatch.setattr('hid_defender.logging_setup.LOG_PATH', str(tmp_path / "hid_alerts.log"))


@pytest.fixture
def mock_system_profiler_output():
    """Mock output from system_profiler command."""
    return """{
  "SPUSBDataType": [
    {
      "_name": "USB Input Device",
      "manufacturer": "Corsair",
      "product_name": "Gaming Keyboard",
      "vendor_id": "0x1b1c",
      "product_id": "0x1bac",
      "_items": []
    },
    {
      "_name": "Suspicious Device",
      "manufacturer": "Unknown Vendor",
      "product_name": "Suspicious HID Device",
      "vendor_id": "0xdead",
      "product_id": "0xbeef",
      "_items": []
    }
  ]
}"""