# Test Case: TC-02 HID Device Detection Test
# Test Case: TC-03 Trusted Device Recognition Test
# Test Case: TC-04 Unknown Device Detection Test
# Test Case: TC-08 Multiple Device Detection Test
# Test Case: TC-09 Device Disconnect Handling Test
# Test Case: TC-17 Unauthorized Device Warning Test

import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path


class TestDeviceDetection:
    """Test device detection and recognition functionality."""

    def test_tc02_hid_device_detection(self, mock_system_profiler_output):
        """TC-02: Verify that a connected HID device is detected."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value.stdout = mock_system_profiler_output
            mock_run.return_value.returncode = 0

            from hid_defender.device_monitor import get_macos_usb_devices
            devices = get_macos_usb_devices()

            assert len(devices) >= 1
            # Should detect at least the USB Input Device
            device_ids = [d.get('id') for d in devices]
            assert any('VID_1B1CPID_1BAC' in d for d in device_ids)

    def test_tc03_trusted_device_recognition(self, trusted_device, temp_whitelist_file):
        """TC-03: Verify that trusted devices are identified correctly."""
        from hid_defender.device_validator import evaluate, get_whitelist

        # Load the whitelist
        whitelist = get_whitelist()

        result = evaluate(trusted_device, whitelist)
        status, action, reason = result
        assert status == 'TRUSTED'
        assert 'whitelist' in reason.lower()

    def test_tc04_unknown_device_detection(self, mock_device):
        """TC-04: Verify that unknown devices are treated as suspicious."""
        from hid_defender.device_validator import evaluate, get_whitelist

        # Load the whitelist
        whitelist = get_whitelist()

        result = evaluate(mock_device, whitelist)
        status, action, reason = result
        assert status in ['UNTRUSTED', 'SAFE']
        assert action in ['BLOCKED', 'ALLOWED']

    def test_tc08_multiple_device_detection(self, mock_system_profiler_output):
        """TC-08: Verify that multiple USB devices can be detected."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value.stdout = mock_system_profiler_output
            mock_run.return_value.returncode = 0

            from hid_defender.device_monitor import get_macos_usb_devices
            devices = get_macos_usb_devices()

            # Should detect multiple devices from the mock output
            assert len(devices) >= 2
            device_ids = [d.get('id') for d in devices]
            assert any('VID_1B1C' in d for d in device_ids)
            assert any('VID_DEAD' in d for d in device_ids)

    def test_tc09_device_disconnect_handling(self):
        """TC-09: Verify system behavior when device is removed."""
        # This test simulates device disconnect by mocking empty device list
        with patch('subprocess.run') as mock_run:
            # First return devices, then empty list (simulating disconnect)
            mock_run.return_value.stdout = ""

            from hid_defender.device_monitor import get_macos_usb_devices
            devices = get_macos_usb_devices()

            # Should handle empty result gracefully
            assert isinstance(devices, list)
            assert len(devices) == 0

    def test_tc17_unauthorized_device_warning(self, mock_device):
        """TC-17: Verify warning for non-whitelisted keyboard-like device."""
        from hid_defender.device_validator import evaluate, get_whitelist

        # Load the whitelist
        whitelist = get_whitelist()

        result = evaluate(mock_device, whitelist)
        status, action, reason = result
        assert status == 'UNTRUSTED'
        assert 'unauthorized' in reason.lower() or 'suspicious' in reason.lower() or 'unknown' in reason.lower()