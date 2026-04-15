# ==========================================
# Cross-Platform HID Defender - USB Monitoring Tool
# Final Year Project: Cybersecurity Defense
# ==========================================

import os
import sys
import time
import platform

# Import configuration and constants
from src.config import (
    IS_WINDOWS, IS_MACOS, IS_LINUX, LOG_PATH, 
    KEYSTROKE_THRESHOLD, MALICIOUS_PATTERNS, RECENT_SEEN
)

# Import modules
from src.logging_setup import init_logger, log_event
from src.keystroke_monitor import KeystrokeMonitor, PYNPUT_AVAILABLE
from src.device_monitor import get_macos_usb_devices
from src.device_validator import (
    get_whitelist, run_baseline_setup, parse_device, 
    evaluate, should_debounce
)
from src.alert_system import play_alert_sound, show_alert, lock_workstation


def check_admin():
    """Returns True if the script is running with elevated privileges."""
    if not IS_WINDOWS:
        return os.geteuid() == 0
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def kill_device(hw_id, logger):
    """Forces Windows to disable the specific hardware port. Requires Admin."""
    if not IS_WINDOWS:
        logger.warning(f"Device disabling not supported on {platform.system()}. Logging only.")
        return False
    
    logger.warning(f"Response Triggered: Disabling hardware {hw_id}")
    try:
        import subprocess
        proc = subprocess.run(f'pnputil /disable-device "{hw_id}"', 
                             shell=True, capture_output=True, text=True)
        if proc.returncode == 0:
            logger.info("Success: Device disabled.")
            return True
        logger.error(f"Failed to disable: {proc.stderr.strip()}")
    except Exception as e:
        logger.error(f"Error executing kill command: {e}")
    return False


def handle_new_event(dev_obj, whitelist, logger, keystroke_mon=None):
    """Main event coordinator for a new hardware plug-in."""
    info = parse_device(dev_obj)
    
    if should_debounce(info['id']):
        return

    result, action, reason = evaluate(info, whitelist)
    log_event(logger, info, result, action, reason)

    if result == "TRUSTED":
        print(f"[*] Trusted device connected: {info['name']}")
    elif result == "SAFE":
        print(f"[+] Safe device permitted: {info['name']}")
    else:  # UNTRUSTED
        print("\n" + "!"*50)
        print("! SECURITY WARNING: UNTRUSTED HID HARDWARE !")
        print(f"! Target ID: {info['id']}")
        print("!"*50 + "\n")

        play_alert_sound()

        if keystroke_mon:
            keystroke_mon.register_device_connection(info)

        if IS_WINDOWS:
            try:
                logger.info("Locking screen to stop keyboard payloads...")
                if lock_workstation():
                    action = "LOCKED"
            except Exception as e:
                print(f"Warning: Failed to lock station: {e}")

        if check_admin():
            action = "DISABLED"
            kill_device(info['id'], logger)
        
        show_alert(info)


def simulate_rubber_ducky(logger):
    """Simulate a Rubber Ducky attack for testing purposes."""
    print("\n" + "="*60)
    print("  DEMO MODE: Rubber Ducky Attack Simulation")
    print("="*60)
    print("\nThis demo simulates various attack scenarios:")
    print("1. Fast keystroke injection (15+ keys/sec)")
    print("2. Command execution detection (PowerShell)")
    print("3. First input delay (< 1 second)")
    print("\nScenario starting in 3 seconds...")
    print("(Watch for alerts from keystroke monitoring)\n")
    time.sleep(3)
    
    print("[DEMO] Simulating fast keystroke injection...")
    print("[DEMO] Typing command: powershell Get-Process | Stop-Service")
    
    if PYNPUT_AVAILABLE:
        try:
            keystroke_mon = KeystrokeMonitor(logger)
            keystroke_mon.start()
            
            for i in range(25):
                keystroke_mon.keystroke_times.append(time.time() + (i * 0.05))
            
            if len(keystroke_mon.keystroke_times) >= 5:
                time_span = keystroke_mon.keystroke_times[-1] - keystroke_mon.keystroke_times[0]
                if time_span > 0:
                    speed = len(keystroke_mon.keystroke_times) / time_span
                    print(f"\n[ALERT] Detected suspicious keystroke speed: {speed:.1f} keys/sec")
                    print(f"[ALERT] Threshold: {KEYSTROKE_THRESHOLD} keys/sec")
            
            keystroke_mon.stop()
        except Exception as e:
            print(f"[DEMO] Keystroke simulation error: {e}")
    
    print("\n[DEMO] Command analysis:")
    detected_patterns = []
    test_command = "powershell Get-Process | Stop-Service"
    for pattern in MALICIOUS_PATTERNS:
        if pattern.lower() in test_command.lower():
            detected_patterns.append(pattern)
    
    if detected_patterns:
        print(f"[ALERT] Detected {len(detected_patterns)} suspicious command patterns:")
        for p in detected_patterns:
            print(f"        - {p}")
    
    print("\n" + "="*60)
    print("Demo complete! The application would block this attack.")
    print("="*60 + "\n")


def main_windows(logger):
    """Windows-specific monitoring loop."""
    print("\n[+] Running on Windows - Real-time WMI monitoring enabled")
    if not check_admin():
        print("[!] Note: Running without Admin. Hardware blocking is disabled.")
    else:
        print("[+] Admin rights detected. Hardware blocking is active.")

    keystroke_mon = None
    if PYNPUT_AVAILABLE:
        keystroke_mon = KeystrokeMonitor(logger)
        keystroke_mon.start()
        if keystroke_mon.is_monitoring:
            print("[+] Keystroke monitoring enabled")
        else:
            print("[!] Keystroke monitoring disabled (see above for details)")
    else:
        print("[!] Keystroke monitoring disabled (pynput not available)")

    try:
        import wmi
        import pythoncom
    except ImportError:
        logger.error("Error: Please install missing dependencies: pip install wmi pypiwin32")
        return

    pythoncom.CoInitialize()
    wmi_client = wmi.WMI()
    
    trusted_baseline = run_baseline_setup(wmi_client, logger)
    print(f"Loaded {len(trusted_baseline)} trusted HID devices from whitelist.")
    print(f"Monitoring hidden USB events... (Log file: {os.path.basename(LOG_PATH)})")
    
    watcher = wmi_client.Win32_PnPEntity.watch_for("creation")
    try:
        while True:
            try:
                new_dev = watcher()
                from src.device_monitor import _is_valid_hid
                if _is_valid_hid(new_dev):
                    handle_new_event(new_dev, trusted_baseline, logger, keystroke_mon)
            except Exception as e:
                logger.error(f"Error processing device event: {e}")
                time.sleep(1)
                    
    except KeyboardInterrupt:
        if keystroke_mon:
            keystroke_mon.stop()
        print("\nStopping monitor...")


def main_macos(logger):
    """macOS-specific monitoring loop."""
    print("\n[+] Running on macOS - Polling USB devices every 2 seconds")
    
    keystroke_mon = None
    if PYNPUT_AVAILABLE:
        keystroke_mon = KeystrokeMonitor(logger)
        keystroke_mon.start()
        if keystroke_mon.is_monitoring:
            print("[+] Keystroke monitoring enabled")
        else:
            print("[!] Keystroke monitoring disabled (see above for details)")
    else:
        print("[!] Keystroke monitoring disabled (pynput not available)")
    
    trusted_baseline = run_baseline_setup(logger=logger)
    print(f"Monitoring USB devices... (Log file: {os.path.basename(LOG_PATH)})")
    
    previous_devices = {}
    poll_interval = 2
    
    try:
        while True:
            try:
                current_devices = get_macos_usb_devices()
                current_ids = {dev['id']: dev for dev in current_devices}
                previous_ids = set(previous_devices.keys())
                current_ids_set = set(current_ids.keys())
                
                new_device_ids = current_ids_set - previous_ids
                for dev_id in new_device_ids:
                    dev_obj = current_ids[dev_id]
                    handle_new_event(dev_obj, trusted_baseline, logger, keystroke_mon)
                
                previous_devices = current_ids
                time.sleep(poll_interval)
                
            except Exception as e:
                logger.error(f"Error scanning USB devices: {e}")
                time.sleep(1)
                
    except KeyboardInterrupt:
        if keystroke_mon:
            keystroke_mon.stop()
        print("\nStopping monitor...")


def main_linux(logger):
    """Linux-specific monitoring loop."""
    print("\n[+] Running on Linux - Polling USB devices every 2 seconds")
    
    keystroke_mon = None
    if PYNPUT_AVAILABLE:
        keystroke_mon = KeystrokeMonitor(logger)
        keystroke_mon.start()
        if keystroke_mon.is_monitoring:
            print("[+] Keystroke monitoring enabled")
        else:
            print("[!] Keystroke monitoring disabled (see above for details)")
    else:
        print("[!] Keystroke monitoring disabled (pynput not available)")
    
    trusted_baseline = run_baseline_setup(logger=logger)
    print(f"Monitoring USB devices... (Log file: {os.path.basename(LOG_PATH)})")
    
    previous_devices = {}
    poll_interval = 2
    
    try:
        while True:
            try:
                current_devices = get_macos_usb_devices()
                current_ids = {dev['id']: dev for dev in current_devices}
                previous_ids = set(previous_devices.keys())
                current_ids_set = set(current_ids.keys())
                
                new_device_ids = current_ids_set - previous_ids
                for dev_id in new_device_ids:
                    dev_obj = current_ids[dev_id]
                    handle_new_event(dev_obj, trusted_baseline, logger, keystroke_mon)
                
                previous_devices = current_ids
                time.sleep(poll_interval)
                
            except Exception as e:
                logger.error(f"Error scanning USB devices: {e}")
                time.sleep(1)
                
    except KeyboardInterrupt:
        if keystroke_mon:
            keystroke_mon.stop()
        print("\nStopping monitor...")


def main():
    """Main entry point."""
    print("-" * 50)
    print(" HID Defender - Real-time USB Monitor")
    print("-" * 50)

    logger = init_logger()

    if len(sys.argv) > 1:
        arg = sys.argv[1].lower()
        if arg == "--demo":
            simulate_rubber_ducky(logger)
            return
        elif arg == "--help":
            print("\nUsage: python3 hid_defender.py [OPTIONS]")
            print("\nOptions:")
            print("  --demo       Run demo mode (simulate Rubber Ducky attack)")
            print("  --help       Show this help message")
            print("  (no args)    Run normal monitoring mode")
            return

    if IS_WINDOWS:
        main_windows(logger)
    elif IS_MACOS:
        main_macos(logger)
    elif IS_LINUX:
        main_linux(logger)
    else:
        print("Error: Unsupported platform")
        sys.exit(1)


if __name__ == "__main__":
    main()
