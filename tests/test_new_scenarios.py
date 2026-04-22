import pytest
import time
from unittest.mock import patch, MagicMock

# Handle pynput availability for typing tests
try:
    from pynput.keyboard import KeyCode, Key
    PYNPUT_AVAILABLE = True
except ImportError:
    PYNPUT_AVAILABLE = False
    KeyCode = MagicMock()
    Key = MagicMock()


class TestNewScenarios:
    """Implementation of test cases TC013-TC020."""

    @pytest.mark.skipif(not PYNPUT_AVAILABLE, reason="pynput not available")
    @patch('time.time')
    def test_tc013_abnormal_typing_detection(self, mock_time):
        """TC013: Abnormal Typing Detection - Simulate rapid keystroke input."""
        from hid_defender.keystroke_monitor import KeystrokeMonitor
        
        current_time = 1000.0
        mock_time.return_value = current_time
        monitor = KeystrokeMonitor()

        # Simulate rapid typing (abnormal)
        for i in range(20):
            mock_time.return_value = current_time
            monitor.on_press(KeyCode.from_char('a'))
            current_time += 0.01  # 10ms gap (very fast)

        assert monitor.rapid_typing_detected is True
        assert monitor.keystroke_count >= 15

    @pytest.mark.skipif(not PYNPUT_AVAILABLE, reason="pynput not available")
    @patch('time.time')
    def test_tc014_normal_typing_behavior_validation(self, mock_time):
        """TC014: Normal Typing Behavior Validation - Type normally using a trusted keyboard."""
        from hid_defender.keystroke_monitor import KeystrokeMonitor
        
        current_time = 2000.0
        mock_time.return_value = current_time
        monitor = KeystrokeMonitor()

        # Simulate normal human typing
        for i in range(10):
            mock_time.return_value = current_time
            monitor.on_press(KeyCode.from_char('a'))
            current_time += 0.2  # 200ms gap (normal)

        assert monitor.rapid_typing_detected is False
        assert monitor.keystroke_count < 15

    @pytest.mark.skipif(not PYNPUT_AVAILABLE, reason="pynput not available")
    def test_tc015_first_input_delay_detection(self):
        """TC015: First Input Delay Detection - Measure delay between connection and first input."""
        from hid_defender.keystroke_monitor import KeystrokeMonitor
        
        monitor = KeystrokeMonitor()
        
        # Connect device
        monitor.register_device_connection({'name': 'Test Keyboard', 'id': 'VID_1234&PID_5678'})
        assert monitor.pending_device is not None
        
        # Wait a safe amount of time before first input
        monitor.pending_device_time = time.time() - 5.0  # 5 seconds ago
        
        with patch.object(monitor.logger, 'warning') as mock_log:
            monitor.on_press(KeyCode.from_char('x'))
            
            # The input was delayed enough, so it shouldn't trigger the FIRST INPUT DELAY warning
            warning_called_for_delay = any("FIRST INPUT DELAY" in call[0][0] for call in mock_log.call_args_list)
            assert not warning_called_for_delay
            assert monitor.pending_device is None

    @pytest.mark.skipif(not PYNPUT_AVAILABLE, reason="pynput not available")
    def test_tc016_abnormal_delay_detection(self):
        """TC016: Abnormal Delay Detection - Very short delay after device connection."""
        from hid_defender.keystroke_monitor import KeystrokeMonitor
        
        monitor = KeystrokeMonitor()
        
        # Connect device
        monitor.register_device_connection({'name': 'Suspicious Keyboard', 'id': 'VID_DEAD&PID_BEEF'})
        
        # Input happens almost immediately (e.g., 0.1 seconds after connection)
        monitor.pending_device_time = time.time() - 0.1
        
        with patch.object(monitor, 'trigger_input_delay_alert') as mock_alert:
            monitor.on_press(KeyCode.from_char('x'))
            
            # Abnormal delay should trigger the alert
            mock_alert.assert_called_once()
            assert monitor.pending_device is None

    @pytest.mark.skipif(not PYNPUT_AVAILABLE, reason="pynput not available")
    def test_tc017_suspicious_command_detection(self):
        """TC017: Suspicious Command Detection - Detect PowerShell, Run dialog, or script execution."""
        from hid_defender.keystroke_monitor import KeystrokeMonitor
        
        monitor = KeystrokeMonitor()
        
        with patch.object(monitor, 'trigger_command_alert') as mock_alert:
            # Simulate typing "powershell"
            for char in "powershell -WindowStyle Hidden":
                monitor.on_press(KeyCode.from_char(char))
                
            # The pattern should be detected and alert triggered
            mock_alert.assert_called()
            
        with patch.object(monitor, 'trigger_command_alert') as mock_alert2:
            # Simulate Run Dialog (Ctrl/Cmd + R)
            monitor.on_press(Key.cmd)
            monitor.on_press(KeyCode.from_char('r'))
            monitor.on_release(Key.cmd)
            
            mock_alert2.assert_called()

    def test_tc018_dashboard_update_verification(self):
        """TC018: Dashboard Update Verification - Dashboard updates when events occur."""
        from dashboard.app import app, _new_alerts
        
        # Add a test alert to the dashboard's internal queue
        _new_alerts.append({
            "time": "2026-04-22 10:00:00",
            "device": "Test Device",
            "vendor": "Test Vendor",
            "id": "VID_1234&PID_5678",
            "reason": "Test Reason",
            "action": "BLOCKED"
        })
        
        # Verify the dashboard API returns the new event for the UI to update
        with app.test_client() as client:
            response = client.get('/api/monitor/new-alerts')
            assert response.status_code == 200
            data = response.get_json()
            assert data['count'] >= 1
            assert any(alert['device'] == 'Test Device' for alert in data['alerts'])

    def test_tc019_multiple_device_handling(self):
        """TC019: Multiple Device Handling - Detect and manage more than one connected device."""
        from hid_defender.device_validator import evaluate
        
        whitelist = [
            {'hardware_id': 'VID_1111&PID_1111', 'vendor': 'Trusted Inc'}
        ]
        
        devices_to_connect = [
            {'hardware_id': 'VID_1111&PID_1111', 'vendor': 'Trusted Inc', 'description': 'Mouse 1'},
            {'hardware_id': 'VID_2222&PID_2222', 'vendor': 'Unknown', 'description': 'Keyboard 1'},
            {'hardware_id': 'VID_3333&PID_3333', 'vendor': 'BadActor', 'description': 'Rubber Ducky'}
        ]
        
        results = []
        for device in devices_to_connect:
            status, action, reason = evaluate(device, whitelist)
            results.append(status)
            
        assert len(results) == 3
        assert results[0] == 'TRUSTED'
        assert results[1] == 'UNTRUSTED'
        assert results[2] == 'UNTRUSTED'

    def test_tc020_error_handling_and_stability(self):
        """TC020: Error Handling and Stability - Handle runtime errors without crashing."""
        from hid_defender.device_validator import evaluate
        
        whitelist = [
            {'hardware_id': 'VID_1111&PID_1111', 'vendor': 'Trusted Inc'}
        ]
        
        # Trigger an invalid input (None instead of a dictionary)
        # The system should handle the error gracefully without crashing the application
        try:
            status, action, reason = evaluate(None, whitelist)
            assert status == 'ERROR' or status == 'UNTRUSTED'
        except Exception as e:
            pytest.fail(f"System crashed on invalid input: {e}")
            
        # Trigger missing keys
        try:
            status, action, reason = evaluate({'wrong_key': 'value'}, whitelist)
            # Should safely process and return UNKNOWN because ID is missing
            assert status == 'UNKNOWN'
        except Exception as e:
            pytest.fail(f"System crashed on malformed input: {e}")
