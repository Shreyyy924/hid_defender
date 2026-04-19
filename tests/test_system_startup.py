# Test Case: TC-01 System Startup Test
# Test Case: TC-12 Whitelist File Loading Test
# Test Case: TC-13 Invalid Whitelist Entry Test

import pytest
import json
import os
from pathlib import Path
from unittest.mock import patch


class TestSystemStartup:
    """Test system startup and initialization functionality."""

    def test_tc01_system_startup_success(self, tmp_path, capsys):
        """TC-01: Verify that the defensive system starts properly."""
        # Setup temporary files
        whitelist_file = tmp_path / "trusted_devices.json"
        log_file = tmp_path / "hid_alerts.log"

        # Create empty whitelist
        with open(whitelist_file, 'w') as f:
            json.dump([], f)

        # Mock the paths
        with patch('hid_defender.config.WHITELIST_PATH', str(whitelist_file)), \
             patch('hid_defender.config.LOG_PATH', str(log_file)), \
             patch('hid_defender.device_validator.WHITELIST_PATH', str(whitelist_file)), \
             patch('hid_defender.logging_setup.LOG_PATH', str(log_file)):

            # Import after patching
            from hid_defender.logging_setup import init_logger
            from hid_defender.device_validator import get_whitelist

            # Test logger initialization
            logger = init_logger()
            assert logger is not None

            # Test whitelist loading
            whitelist = get_whitelist()
            assert isinstance(whitelist, list)

            # Verify no errors in startup
            captured = capsys.readouterr()
            assert "Error" not in captured.out
            assert "Exception" not in captured.err

    def test_tc12_whitelist_file_loading_success(self, temp_whitelist_file):
        """TC-12: Verify that whitelist file loads properly during startup."""
        with patch('hid_defender.device_validator.WHITELIST_PATH', str(temp_whitelist_file)):
            from hid_defender.device_validator import get_whitelist

            whitelist = get_whitelist()
            assert len(whitelist) == 2
            assert whitelist[0]['hardware_id'] == 'VID_1B1C&PID_1BAC'
            assert whitelist[1]['hardware_id'] == 'VID_046D&PID_C077'

    def test_tc13_invalid_whitelist_entry_handling(self, tmp_path):
        """TC-13: Verify system handling of wrong whitelist data."""
        # Create invalid JSON file
        invalid_whitelist = tmp_path / "invalid_trusted_devices.json"
        with open(invalid_whitelist, 'w') as f:
            f.write("invalid json content {")

        with patch('hid_defender.device_validator.WHITELIST_PATH', str(invalid_whitelist)):
            from hid_defender.device_validator import get_whitelist

            # Should handle error gracefully and return empty list
            whitelist = get_whitelist()
            assert isinstance(whitelist, list)
            assert len(whitelist) == 0

    def test_tc19_system_stability_repeated_tests(self, temp_whitelist_file):
        """TC-19: Verify that the system does not crash during repeated testing."""
        with patch('hid_defender.device_validator.WHITELIST_PATH', str(temp_whitelist_file)):
            from hid_defender.device_validator import get_whitelist

            # Run multiple times to test stability
            for i in range(10):
                whitelist = get_whitelist()
                assert len(whitelist) == 2
                assert whitelist[0]['hardware_id'] == 'VID_1B1C&PID_1BAC'