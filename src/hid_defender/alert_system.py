# ==========================================
# Alert System & Notifications
# ==========================================

import subprocess
import threading
import platform
import logging
from typing import cast, Any

# Handle both package imports and standalone execution
try:
    from .config import IS_WINDOWS, IS_MACOS, IS_LINUX
except ImportError:
    from config import IS_WINDOWS, IS_MACOS, IS_LINUX

# Setup logger
logger = logging.getLogger(__name__)

# Import platform-specific modules at module level for patching
import ctypes
windll: Any = getattr(ctypes, "windll", None)
if IS_WINDOWS:
    try:
        import winsound
    except ImportError:
        winsound = None
else:
    winsound = None


def play_alert_sound():
    """Play a system alert sound based on platform.
    
    Attempts to play a beep/alert sound on the current platform.
    Silently continues if sound playback fails.
    """
    if IS_WINDOWS and winsound:
        try:
            beep = getattr(winsound, "Beep", None)
            if beep:
                beep(1000, 400)
                beep(1000, 400)
        except (OSError, AttributeError) as e:
            logger.debug(f"Failed to play Windows alert sound: {e}")
    elif IS_MACOS:
        try:
            subprocess.run(["afplay", "/System/Library/Sounds/Alarm.aiff"], timeout=2, check=False)
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
            logger.debug(f"Failed to play macOS alert sound: {e}")
    elif IS_LINUX:
        try:
            subprocess.run(["beep"], timeout=2, check=False)
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
            logger.debug(f"Failed to play Linux alert sound: {e}")


def show_alert(info):
    """Shows a loud, modal security warning to the user.
    
    Args:
        info (dict): Device information dict with keys:
            - 'name': Device name (required)
            - 'id': Hardware ID (required)
    
    Raises:
        TypeError: If info is not a dict or is None
    """
    if not isinstance(info, dict):
        logger.error(f"show_alert() received invalid info type: {type(info)}")
        raise TypeError(f"info must be a dict, got {type(info)}")
    
    device_name = info.get('name', 'Unknown Device')
    device_id = info.get('id', 'Unknown ID')
    
    if IS_WINDOWS and windll:
        def _popup(wdll: Any = windll):
            try:
                title = "SECURE HID DEFENDER: THREAT DETECTED"
                msg = (
                    "!!! UNAUTHORIZED USB DEVICE DETECTED !!!\n\n"
                    f"Device Name: {device_name}\n"
                    f"Hardware ID: {device_id}\n\n"
                    "Action Taken: The workstation was locked and the device has been flagged."
                )
                wdll.user32.MessageBoxW(0, msg, title, 0x10 | 0x1000 | 0x10000)
            except (AttributeError, OSError) as e:
                logger.error(f"Failed to show Windows alert popup: {e}")

        threading.Thread(target=_popup, daemon=True).start()
    
    elif IS_MACOS:
        # Use native macOS notification
        def _macos_alert():
            try:
                title = "SECURE HID DEFENDER: THREAT DETECTED"
                msg = f"Unauthorized USB device detected: {device_name}"
                hw_id = device_id
                script = f'display notification "{msg}" with title "{title}" subtitle "Hardware ID: {hw_id}"'
                subprocess.run(["osascript", "-e", script], timeout=5, check=False)
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
                logger.error(f"Failed to show macOS alert: {e}")
        
        threading.Thread(target=_macos_alert, daemon=True).start()
    
    elif IS_LINUX:
        # Use notify-send for Linux
        def _linux_alert():
            try:
                title = "SECURE HID DEFENDER: THREAT DETECTED"
                msg = f"Unauthorized USB device: {device_name} ({device_id})"
                subprocess.run(["notify-send", title, msg], timeout=5, check=False)
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
                logger.error(f"Failed to show Linux alert: {e}")
        
        threading.Thread(target=_linux_alert, daemon=True).start()


def lock_workstation():
    """Lock the workstation to prevent unauthorized access.
    
    Returns:
        bool: True if lock was successful, False otherwise
    
    Raises:
        NotImplementedError: If called on non-Windows platforms
    
    Note:
        This function only works on Windows. On other platforms,
        it will raise NotImplementedError.
    """
    if IS_WINDOWS and windll:
        try:
            cast(Any, windll).user32.LockWorkStation()
            logger.info("Workstation locked successfully")
            return True
        except (AttributeError, OSError) as e:
            logger.error(f"Failed to lock workstation: {e}")
            return False
    else:
        raise NotImplementedError("Workstation locking is only supported on Windows")
