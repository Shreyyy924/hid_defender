# Test Case: TC-05 Alert Generation Test

import pytest
from unittest.mock import patch, MagicMock, call
import platform


class TestAlertSystem:
    """Test alert generation and notification functionality."""

    @patch('hid_defender.alert_system.subprocess.run')
    def test_tc05_alert_generation_macos(self, mock_subprocess, monkeypatch):
        """TC-05: Verify that alert is shown for suspicious device (macOS)."""
        monkeypatch.setattr('hid_defender.alert_system.IS_MACOS', True)
        monkeypatch.setattr('hid_defender.alert_system.IS_WINDOWS', False)
        monkeypatch.setattr('hid_defender.alert_system.IS_LINUX', False)

        from hid_defender.alert_system import show_alert

        # show_alert expects a dict with 'name' and 'id' keys
        device_info = {
            'name': 'Suspicious USB Device',
            'id': 'VID_DEAD&PID_BEEF'
        }
        show_alert(device_info)

        # Verify osascript was called for macOS notification
        mock_subprocess.assert_called_once()
        call_args = mock_subprocess.call_args[0][0]
        assert 'osascript' in call_args
        assert 'display notification' in ' '.join(call_args)

    def test_alert_generation_windows(self, monkeypatch):
        """Test alert generation on Windows."""
        pytest.skip("Windows-specific test")

    @patch('hid_defender.alert_system.subprocess.run')
    def test_alert_generation_linux(self, mock_subprocess, monkeypatch):
        """Test alert generation on Linux."""
        monkeypatch.setattr('hid_defender.alert_system.IS_MACOS', False)
        monkeypatch.setattr('hid_defender.alert_system.IS_WINDOWS', False)
        monkeypatch.setattr('hid_defender.alert_system.IS_LINUX', True)

        from hid_defender.alert_system import show_alert

        # show_alert expects a dict with 'name' and 'id' keys
        device_info = {
            'name': 'Suspicious USB Device',
            'id': 'VID_DEAD&PID_BEEF'
        }
        show_alert(device_info)

        # Verify notify-send was called for Linux
        mock_subprocess.assert_called_once()
        call_args = mock_subprocess.call_args[0][0]
        assert 'notify-send' in call_args

    @patch('hid_defender.alert_system.subprocess.run')
    def test_play_alert_sound_macos(self, mock_subprocess, monkeypatch):
        """Test alert sound on macOS."""
        monkeypatch.setattr('hid_defender.alert_system.IS_MACOS', True)

        from hid_defender.alert_system import play_alert_sound

        play_alert_sound()

        # Verify afplay was called
        mock_subprocess.assert_called_once()
        call_args = mock_subprocess.call_args[0][0]
        assert 'afplay' in call_args

    @patch('hid_defender.alert_system.winsound')
    def test_play_alert_sound_windows(self, mock_winsound, monkeypatch):
        """Test alert sound on Windows."""
        pytest.skip("Windows-specific test")
        monkeypatch.setattr('hid_defender.alert_system.IS_WINDOWS', True)

        from hid_defender.alert_system import play_alert_sound

        play_alert_sound()

        # Verify winsound.Beep was called
        mock_winsound.Beep.assert_called_once()

    def test_lock_workstation_not_implemented(self):
        """Test that lock_workstation raises NotImplementedError."""
        from hid_defender.alert_system import lock_workstation

        with pytest.raises(NotImplementedError):
            lock_workstation()

    def test_alert_message_formatting(self, monkeypatch):
        """Test that alert messages are properly formatted."""
        monkeypatch.setattr('hid_defender.alert_system.IS_MACOS', True)

        with patch('hid_defender.alert_system.subprocess.run') as mock_subprocess:
            from hid_defender.alert_system import show_alert

            # show_alert expects a dict with 'name' and 'id' keys
            device_info = {
                'name': 'Suspicious USB Device',
                'id': 'VID_DEAD&PID_BEEF'
            }

            show_alert(device_info)

            # Verify the device info is included in the notification
            call_args = mock_subprocess.call_args[0][0]
            command_str = ' '.join(call_args)
            assert 'Suspicious USB Device' in command_str
            assert 'VID_DEAD&PID_BEEF' in command_str