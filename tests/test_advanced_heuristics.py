import pytest
import time
from unittest.mock import patch, MagicMock
from hid_defender.keystroke_monitor import KeystrokeMonitor

try:
    from pynput.keyboard import KeyCode
    PYNPUT_AVAILABLE = True
except ImportError:
    PYNPUT_AVAILABLE = False
    KeyCode = MagicMock()

class TestAdvancedHeuristics:
    """Test suite for advanced keystroke analysis (variance, entropy, and expanded signatures)."""

    @pytest.mark.skipif(not PYNPUT_AVAILABLE, reason="pynput not available")
    @patch('time.time')
    def test_low_entropy_detection(self, mock_time):
        """Test detection of scripts with fixed/robotic delays (low entropy)."""
        current_time = 3000.0
        mock_time.return_value = current_time
        monitor = KeystrokeMonitor()

        # Simulate fixed 30ms delay (robotic/low entropy)
        for i in range(15):
            mock_time.return_value = current_time
            monitor.on_press(KeyCode.from_char('b'))
            current_time += 0.03

        # Entropy should be very low for fixed delays
        entropy = monitor._calculate_typing_entropy(list(monitor.keystroke_times))
        assert entropy < 0.8
        assert monitor.rapid_typing_detected is True

    @pytest.mark.skipif(not PYNPUT_AVAILABLE, reason="pynput not available")
    @patch('time.time')
    def test_human_jitter_validation(self, mock_time):
        """Test that human-like jitter (high entropy) doesn't trigger the heuristic."""
        current_time = 4000.0
        mock_time.return_value = current_time
        monitor = KeystrokeMonitor()

        # Simulate human-like variable delays (avg 80ms with 20ms jitter)
        import random
        delays = [0.07, 0.09, 0.06, 0.1, 0.08, 0.075, 0.085, 0.095, 0.065, 0.105]
        
        for delay in delays:
            mock_time.return_value = current_time
            monitor.on_press(KeyCode.from_char('c'))
            current_time += delay

        # High entropy human typing should be safe
        entropy = monitor._calculate_typing_entropy(list(monitor.keystroke_times))
        assert entropy > 0.8
        assert monitor.rapid_typing_detected is False

    def test_expanded_signature_detection(self):
        """Test detection of new malicious command patterns."""
        monitor = KeystrokeMonitor()
        
        with patch.object(monitor, 'trigger_command_alert') as mock_alert:
            # Simulate typing "mimikatz"
            for char in "mimikatz":
                monitor.check_command_patterns(char)
            mock_alert.assert_called_with("mimikatz")

        with patch.object(monitor, 'trigger_command_alert') as mock_alert:
            # Simulate reverse shell attempt
            for char in "nc -e /bin/sh":
                monitor.check_command_patterns(char)
            mock_alert.assert_any_call("nc -e")
            mock_alert.assert_any_call("/bin/sh")
