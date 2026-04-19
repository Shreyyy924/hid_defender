# Test Case: TC-18 Continuous Monitoring Test
# Test Case: TC-20 End-to-End System Test

import pytest
import time
import threading
from unittest.mock import patch, MagicMock
from pathlib import Path


class TestIntegration:
    """Integration tests for end-to-end functionality."""

    def test_tc18_continuous_monitoring(self, temp_whitelist_file, temp_log_file):
        """TC-18: Verify that system keeps monitoring over time."""
        with patch('hid_defender.device_validator.WHITELIST_PATH', str(temp_whitelist_file)), \
             patch('hid_defender.logging_setup.LOG_PATH', str(temp_log_file)), \
             patch('hid_defender.config.WHITELIST_PATH', str(temp_whitelist_file)), \
             patch('hid_defender.config.LOG_PATH', str(temp_log_file)):

            from hid_defender.logging_setup import init_logger
            from hid_defender.device_validator import get_whitelist, evaluate
            from hid_defender.logging_setup import log_event

            # Initialize components
            logger = init_logger()
            whitelist = get_whitelist()

            # Simulate continuous monitoring for a short period
            start_time = time.time()
            monitoring_duration = 2  # seconds

            events_logged = 0

            while time.time() - start_time < monitoring_duration:
                # Simulate device detection
                test_device = {
                    'hardware_id': 'VID_DEAD&PID_BEEF',
                    'vendor': 'Test Vendor',
                    'description': 'Test Device'
                }

                result = evaluate(test_device, whitelist)
                status, action, reason = result

                if status == 'UNTRUSTED':
                    info_dict = {
                        'time': time.strftime('%Y-%m-%d %H:%M:%S'),
                        'name': test_device['description'],
                        'vendor': test_device['vendor'],
                        'product': test_device['description'],
                        'id': test_device['hardware_id']
                    }
                    log_event(logger, info_dict, status, action, reason)
                    events_logged += 1

                time.sleep(0.1)  # Small delay to prevent tight loop

            # Verify monitoring continued and logged events
            assert events_logged > 0
            assert temp_log_file.exists()

    def test_tc20_end_to_end_workflow(self, temp_whitelist_file, temp_log_file):
        """TC-20: Verify complete workflow from attack detection to logging."""
        with patch('hid_defender.device_validator.WHITELIST_PATH', str(temp_whitelist_file)), \
             patch('hid_defender.logging_setup.LOG_PATH', str(temp_log_file)), \
             patch('hid_defender.config.WHITELIST_PATH', str(temp_whitelist_file)), \
             patch('hid_defender.config.LOG_PATH', str(temp_log_file)), \
             patch('hid_defender.alert_system.subprocess.run') as mock_alert:

            from hid_defender.logging_setup import init_logger
            from hid_defender.device_validator import get_whitelist, evaluate
            from hid_defender.logging_setup import log_event
            from hid_defender.alert_system import show_alert

            # Step 1: Initialize system
            logger = init_logger()
            whitelist = get_whitelist()
            assert len(whitelist) == 2

            # Step 2: Simulate attack device connection
            attack_device = {
                'hardware_id': 'VID_2E8A&PID_0003',  # Raspberry Pi Pico
                'vendor': 'Raspberry Pi',
                'description': 'Pico Attack Device',
                'device_type': 'keyboard'
            }

            # Step 3: Evaluate device (should be detected as suspicious)
            result = evaluate(attack_device, whitelist)
            status, action, reason = result
            assert status == 'UNTRUSTED'
            assert 'attack' in reason.lower() or 'suspicious' in reason.lower()

            # Step 4: Generate alert
            show_alert({
                'name': attack_device['description'],
                'id': attack_device['hardware_id']
            })
            mock_alert.assert_called_once()

            # Step 5: Log the event
            info_dict = {
                'time': time.strftime('%Y-%m-%d %H:%M:%S'),
                'name': attack_device['description'],
                'vendor': attack_device['vendor'],
                'product': attack_device['description'],
                'id': attack_device['hardware_id']
            }
            log_event(logger, info_dict, status, action, reason)

            # Step 6: Verify log was created and contains correct data
            assert temp_log_file.exists()

            with open(temp_log_file, 'r', newline='') as f:
                import csv
                reader = csv.DictReader(f)
                rows = list(reader)

            assert len(rows) == 1
            row = rows[0]
            assert row['ID'] == attack_device['hardware_id']
            assert row['Vendor'] == attack_device['vendor']
            assert row['Result'] == status

    def test_attack_device_detection_integration(self, temp_whitelist_file):
        """Test integration with known attack devices."""
        with patch('hid_defender.device_validator.WHITELIST_PATH', str(temp_whitelist_file)):
            from hid_defender.device_validator import evaluate, get_whitelist
            from hid_defender.config import ATTACK_VECTORS

            whitelist = get_whitelist()  # Will be empty since temp file is empty

            # Test various attack devices
            attack_devices = [
                {'hardware_id': 'VID_2E8A&PID_0003', 'vendor': 'Raspberry Pi', 'description': 'Pico'},
                {'hardware_id': 'VID_2341&PID_8036', 'vendor': 'Arduino', 'description': 'Leonardo'},
                {'hardware_id': 'VID_16C0&PID_0483', 'vendor': 'Teensy', 'description': 'USB Device'},
            ]

            for device in attack_devices:
                result = evaluate(device, whitelist)
                status, action, reason = result
                assert status == 'UNTRUSTED'
                assert action in ['BLOCKED', 'ALLOWED']

    def test_whitelist_integration_workflow(self, tmp_path):
        """Test complete whitelist workflow."""
        whitelist_file = tmp_path / "test_whitelist.json"

        with patch('hid_defender.device_validator.WHITELIST_PATH', str(whitelist_file)):
            from hid_defender.device_validator import save_whitelist, get_whitelist

            # Start with empty whitelist
            assert not whitelist_file.exists()

            # Save devices to whitelist
            test_devices = [
                {'hardware_id': 'VID_1234&PID_5678', 'vendor': 'Test Vendor', 'description': 'Test Device'}
            ]
            save_whitelist(test_devices)

            # Verify file was created
            assert whitelist_file.exists()

            # Load and verify
            loaded = get_whitelist()
            assert len(loaded) == 1
            assert loaded[0]['hardware_id'] == 'VID_1234&PID_5678'

    def test_cross_module_integration(self, temp_whitelist_file, temp_log_file):
        """Test integration between multiple modules."""
        with patch('hid_defender.config.WHITELIST_PATH', str(temp_whitelist_file)), \
             patch('hid_defender.config.LOG_PATH', str(temp_log_file)):
            # Import all modules
            from hid_defender.logging_setup import init_logger
            from hid_defender.device_validator import get_whitelist, evaluate
            from hid_defender.logging_setup import log_event
            from hid_defender.alert_system import show_alert

            # Test that all components work together
            logger = init_logger()
            whitelist = get_whitelist()
            assert len(whitelist) == 2

            # Test evaluation
            device = {'hardware_id': 'VID_DEAD&PID_BEEF', 'vendor': 'Test'}
            result = evaluate(device, whitelist)
            status, action, reason = result
            assert status == 'UNTRUSTED'

            # Test logging
            info_dict = {
                'time': '2024-01-01 12:00:00',
                'name': device['hardware_id'],
                'id': device['hardware_id']
            }
            log_event(logger, info_dict, status, action, reason)

            # Verify everything worked
            assert temp_log_file.exists()
            assert temp_log_file.stat().st_size > 0