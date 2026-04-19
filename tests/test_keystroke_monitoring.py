# Test Case: TC-10 Rapid Keystroke Detection Test
# Test Case: TC-11 Normal Typing Test

import pytest
import time
from unittest.mock import patch, MagicMock

# Handle pynput availability
try:
    from pynput.keyboard import Key, KeyCode
    PYNPUT_AVAILABLE = True
except ImportError:
    PYNPUT_AVAILABLE = False
    Key = MagicMock()
    KeyCode = MagicMock()


@pytest.mark.skipif(not PYNPUT_AVAILABLE, reason="pynput not available")
class TestKeystrokeMonitoring:
    """Test keystroke monitoring and detection functionality."""

    def test_tc10_rapid_keystroke_detection(self):
        """TC-10: Verify that automated fast typing is detected."""
        from hid_defender.keystroke_monitor import KeystrokeMonitor

        monitor = KeystrokeMonitor()

        # Simulate rapid keystrokes (15+ keys/sec threshold)
        start_time = time.time()

        # Generate 20 keystrokes in less than 1 second
        for i in range(20):
            # Simulate key press
            monitor.on_press(KeyCode.from_char('a'))
            time.sleep(0.01)  # 10ms delay = 100 keys/sec

        # Check if rapid typing was detected
        assert monitor.rapid_typing_detected
        assert monitor.keystroke_count >= 15

    def test_tc11_normal_typing_no_false_alert(self):
        """TC-11: Verify that normal keyboard typing is not flagged."""
        from hid_defender.keystroke_monitor import KeystrokeMonitor

        monitor = KeystrokeMonitor()

        # Simulate normal human typing (5-10 keys/sec)
        for i in range(10):
            monitor.on_press(KeyCode.from_char('h'))
            monitor.on_press(KeyCode.from_char('e'))
            monitor.on_press(KeyCode.from_char('l'))
            monitor.on_press(KeyCode.from_char('l'))
            monitor.on_press(KeyCode.from_char('o'))
            time.sleep(0.2)  # 200ms delay = ~5 keys/sec

        # Should not detect rapid typing
        assert not monitor.rapid_typing_detected
        assert monitor.keystroke_count < 15

    @patch('hid_defender.keystroke_monitor.contextlib.redirect_stderr')
    @patch('hid_defender.keystroke_monitor.pynput.keyboard.Listener')
    def test_keystroke_monitor_macos_permissions(self, mock_listener, mock_redirect):
        """Test macOS accessibility permissions handling."""
        from hid_defender.keystroke_monitor import KeystrokeMonitor

        # Simulate permission denied error
        mock_listener.side_effect = Exception("not trusted")

        monitor = KeystrokeMonitor()

        # Should handle permission error gracefully
        # The contextlib.redirect_stderr should be called to suppress system warnings
        assert mock_redirect.called

    def test_keystroke_threshold_configuration(self):
        """Test keystroke threshold configuration."""
        from hid_defender.keystroke_monitor import KeystrokeMonitor
        from hid_defender.config import KEYSTROKE_THRESHOLD

        monitor = KeystrokeMonitor()

        # Verify threshold is properly set from config
        assert hasattr(monitor, 'threshold')
        assert monitor.threshold == KEYSTROKE_THRESHOLD

    def test_keystroke_reset_mechanism(self):
        """Test that keystroke counter resets properly."""
        from hid_defender.keystroke_monitor import KeystrokeMonitor

        monitor = KeystrokeMonitor()

        # Generate some keystrokes
        for i in range(5):
            monitor.on_press(KeyCode.from_char('a'))

        initial_count = monitor.keystroke_count
        assert initial_count == 5

        # Simulate time passing (reset window)
        monitor.last_reset_time = time.time() - 10  # 10 seconds ago

        # Next keystroke should trigger reset due to time window
        monitor.on_press(KeyCode.from_char('a'))

        # Count should be reset or lower
        assert monitor.keystroke_count <= initial_count