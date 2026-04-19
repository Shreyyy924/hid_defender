# Test Case: TC-06 Log File Creation Test
# Test Case: TC-07 Log Content Accuracy Test

import pytest
import csv
import os
from pathlib import Path
from unittest.mock import patch


class TestLogging:
    """Test logging functionality."""

    def test_tc06_log_file_creation(self, temp_log_file):
        """TC-06: Verify that a log file is created when event occurs."""
        with patch('hid_defender.logging_setup.LOG_PATH', str(temp_log_file)):
            from hid_defender.logging_setup import log_event

            # Initially file should not exist
            assert not temp_log_file.exists()

            # Log an event
            from hid_defender.logging_setup import init_logger
            logger = init_logger()
            log_event(logger, {
                'time': '2024-01-01 12:00:00',
                'name': 'Test Device',
                'vendor': 'Test Vendor',
                'product': 'Test Product',
                'id': 'VID_1234&PID_5678'
            }, 'suspicious', 'alert', 'Unknown device')

            # File should now exist
            assert temp_log_file.exists()
            assert temp_log_file.stat().st_size > 0

    def test_tc07_log_content_accuracy(self, temp_log_file):
        """TC-07: Verify that correct device details are stored in logs."""
        with patch('hid_defender.logging_setup.LOG_PATH', str(temp_log_file)):
            from hid_defender.logging_setup import log_event, init_logger
            logger = init_logger()

            test_data = {
                'time': '2024-01-01 12:00:00',
                'name': 'Suspicious Device',
                'vendor': 'Unknown Vendor',
                'product': 'Suspicious Device',
                'id': 'VID_DEAD&PID_BEEF'
            }

            log_event(logger, test_data, 'untrusted', 'blocked', 'Not in whitelist')

            # Read the log file and verify content
            with open(temp_log_file, 'r', newline='') as f:
                reader = csv.DictReader(f)
                rows = list(reader)

            assert len(rows) == 1
            row = rows[0]

            # Verify all expected fields are present
            assert row['Time'] == test_data['time']
            assert row['ID'] == test_data['id']
            assert row['Vendor'] == test_data['vendor']
            assert row['Product'] == test_data['product']
            assert row['Result'] == 'untrusted'
            assert row['Action'] == 'blocked'
            assert row['Reason'] == 'Not in whitelist'

    def test_log_file_headers(self, temp_log_file):
        """Test that log file has correct CSV headers."""
        with patch('hid_defender.logging_setup.LOG_PATH', str(temp_log_file)):
            from hid_defender.logging_setup import log_event, init_logger
            logger = init_logger()

            log_event(logger, {
                'time': '2024-01-01 12:00:00',
                'name': 'Test Device',
                'vendor': 'Test Vendor',
                'product': 'Test Product',
                'id': 'test'
            }, 'test', 'none')

            with open(temp_log_file, 'r', newline='') as f:
                reader = csv.DictReader(f)
                # Check headers
                expected_headers = ['Time', 'Device', 'Vendor', 'Product', 'ID', 'Result', 'Action', 'Reason']
                assert list(reader.fieldnames) == expected_headers

    def test_multiple_log_entries(self, temp_log_file):
        """Test logging multiple entries."""
        with patch('hid_defender.logging_setup.LOG_PATH', str(temp_log_file)):
            from hid_defender.logging_setup import log_event, init_logger
            logger = init_logger()

            # Log multiple events
            for i in range(3):
                log_event(logger, {
                    'time': f'2024-01-01 12:0{i}:00',
                    'name': f'Test Device {i}',
                    'vendor': f'Test Vendor {i}',
                    'product': f'Test Product {i}',
                    'id': f'VID_1234&PID_567{i}'
                }, 'suspicious', 'alert', f'Test reason {i}')

            # Verify all entries are in the file
            with open(temp_log_file, 'r', newline='') as f:
                reader = csv.DictReader(f)
                rows = list(reader)

            assert len(rows) == 3
            for i, row in enumerate(rows):
                assert row['ID'] == f'VID_1234&PID_567{i}'
                assert row['Reason'] == f'Test reason {i}'

    def test_logger_initialization(self, temp_log_file):
        """Test logger initialization."""
        with patch('hid_defender.logging_setup.LOG_PATH', str(temp_log_file)):
            from hid_defender.logging_setup import init_logger

            logger = init_logger()
            assert logger is not None

            # Logger should have both file and console handlers
            assert len(logger.handlers) >= 2