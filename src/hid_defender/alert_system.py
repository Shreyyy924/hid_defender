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
    from config import IS_WINDOWS, IS_MACOS, IS_LINUX  # type: ignore

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
        # Use native macOS dialog box (more intrusive than notification)
        def _macos_alert():
            try:
                title = "🛡️ SECURE HID DEFENDER: THREAT DETECTED"
                device_name = info.get('name', 'Unknown Device')
                device_id = info.get('id', 'Unknown ID')
                msg = (
                    f"!!! UNAUTHORIZED USB DEVICE DETECTED !!!\n\n"
                    f"Device: {device_name}\n"
                    f"ID: {device_id}\n\n"
                    f"Actions Taken:\n"
                    f"✓ Screen locked\n"
                    f"✓ Device ejected\n"
                    f"✓ Threat logged\n\n"
                    f"Contact your IT security team."
                )
                # Use osascript to show a dialog box
                script = f'''
                display dialog "{msg}" \\
                    with title "{title}" \\
                    with icon caution \\
                    buttons {{"OK"}} \\
                    default button "OK" \\
                    giving up after 30
                '''
                subprocess.run(["osascript", "-e", script], timeout=10, check=False)
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
                logger.error(f"Failed to show macOS alert dialog: {e}")
        
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
    """
    if IS_WINDOWS and windll:
        try:
            cast(Any, windll).user32.LockWorkStation()
            logger.info("Workstation locked successfully")
            return True
        except (AttributeError, OSError) as e:
            logger.error(f"Failed to lock workstation: {e}")
            return False
    elif IS_MACOS:
        try:
            # Lock macOS screen
            subprocess.run(
                ["/System/Library/CoreServices/Menu Extras/User.menu/Contents/Resources/CGSession", "-suspend"],
                timeout=5, check=False
            )
            logger.info("macOS screen locked successfully")
            return True
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
            logger.error(f"Failed to lock macOS screen: {e}")
            return False
    elif IS_LINUX:
        try:
            # Try common Linux screen lockers
            for locker in ["gnome-screensaver-command -l", "xdg-screensaver lock", "loginctl lock-session"]:
                result = subprocess.run(locker, shell=True, timeout=5, capture_output=True)
                if result.returncode == 0:
                    logger.info(f"Linux screen locked successfully with: {locker}")
                    return True
            logger.warning("No Linux screen locker found")
            return False
        except (subprocess.TimeoutExpired, OSError) as e:
            logger.error(f"Failed to lock Linux screen: {e}")
            return False
    else:
        logger.warning("Screen locking not supported on this platform")
        return False


def eject_usb_device(device_id: str) -> bool:
    """Eject/unmount a USB device from the system.
    
    Args:
        device_id: The device hardware ID or path
    
    Returns:
        bool: True if ejection was successful, False otherwise
    """
    if IS_MACOS:
        try:
            # On macOS, try to eject by device name or mount point
            # First attempt: use diskutil to eject if it's a mounted volume
            logger.warning(f"Attempting to eject macOS device: {device_id}")
            
            # Try common mount points for USB devices
            for mount_point in ["/Volumes/PICO", "/Volumes/USB"]:
                result = subprocess.run(
                    ["diskutil", "eject", mount_point],
                    timeout=5, capture_output=True, text=True
                )
                if result.returncode == 0:
                    logger.info(f"Successfully ejected device at {mount_point}")
                    return True
            
            # Fallback: try to identify and eject by device name
            result = subprocess.run(
                ["diskutil", "list"],
                timeout=5, capture_output=True, text=True
            )
            # Parse output to find the device
            for line in result.stdout.split("\n"):
                if "PICO" in line.upper() or "USB" in line.upper():
                    # Extract device identifier and try to eject
                    parts = line.split()
                    if parts:
                        device_ref = parts[0]
                        eject_result = subprocess.run(
                            ["diskutil", "eject", device_ref],
                            timeout=5, capture_output=True, text=True
                        )
                        if eject_result.returncode == 0:
                            logger.info(f"Successfully ejected device: {device_ref}")
                            return True
            
            logger.warning("Could not find device to eject on macOS")
            return False
            
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
            logger.error(f"Failed to eject macOS device: {e}")
            return False
    
    elif IS_WINDOWS:
        try:
            # Windows device ejection using pnputil
            logger.warning(f"Attempting to eject Windows device: {device_id}")
            result = subprocess.run(
                f'pnputil /remove-device "{device_id}" /force /reboot',
                shell=True, capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                logger.info("Device ejected/removed successfully from Windows")
                return True
            logger.error(f"Failed to eject Windows device: {result.stderr}")
            return False
        except (subprocess.TimeoutExpired, OSError) as e:
            logger.error(f"Failed to eject Windows device: {e}")
            return False
    
    elif IS_LINUX:
        try:
            # Linux device ejection using eject or umount
            logger.warning(f"Attempting to eject Linux device: {device_id}")
            
            # Try eject first
            result = subprocess.run(
                ["eject", device_id],
                timeout=5, capture_output=True, text=True
            )
            if result.returncode == 0:
                logger.info("Device ejected successfully from Linux")
                return True
            
            # Fallback to umount
            result = subprocess.run(
                ["umount", device_id],
                timeout=5, capture_output=True, text=True
            )
            if result.returncode == 0:
                logger.info("Device unmounted successfully on Linux")
                return True
            
            logger.error(f"Failed to eject Linux device: {result.stderr}")
            return False
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
            logger.error(f"Failed to eject Linux device: {e}")
            return False
    
    logger.warning("USB ejection not supported on this platform")
    return False
