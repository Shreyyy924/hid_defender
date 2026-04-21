"""
HID Defender CLI Entry Point

Command-line interface for the HID Defender security monitoring system.
"""

import os
import sys
import time
import platform
import argparse
from pathlib import Path


def main():
    """Main entry point for the HID Defender CLI application."""
    parser = argparse.ArgumentParser(
        prog="hid-defender",
        description="Cross-Platform USB Device Security Monitor",
        epilog="For more information, visit: https://github.com/yourusername/hid-defender"
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 1.0.0"
    )
    
    parser.add_argument(
        "--monitor",
        action="store_true",
        help="Start the HID device monitoring system"
    )
    
    parser.add_argument(
        "--dashboard",
        action="store_true",
        help="Start the Flask dashboard web server"
    )
    
    parser.add_argument(
        "--port",
        type=int,
        default=5001,
        help="Port for the dashboard (default: 5001)"
    )
    
    parser.add_argument(
        "--setup",
        action="store_true",
        help="Run baseline setup for device whitelisting"
    )
    
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Set logging level (default: INFO)"
    )
    
    args = parser.parse_args()
    
    # If no arguments, show help and start monitoring by default
    if len(sys.argv) == 1:
        parser.print_help()
        print("\nNo options provided. Starting monitoring system...\n")
        args.monitor = True
    
    # Setup logging
    from .logging_setup import init_logger
    logger = init_logger(args.log_level)
    
    try:
        if args.setup:
            logger.info("Starting baseline device setup...")
            from .device_validator import run_baseline_setup
            run_baseline_setup()
            logger.info("Baseline setup complete!")
            return 0
        
        if args.dashboard:
            logger.info(f"Starting Flask dashboard on port {args.port}...")
            from dashboard.app import app
            app.run(host="0.0.0.0", port=args.port, debug=False)
            return 0
        
        if args.monitor:
            logger.info("Starting HID monitoring system...")
            return _run_monitor(logger)
        
        parser.print_help()
        return 0
        
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        return 0
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        return 1


def _run_monitor(logger):
    """Internal function to run the monitoring system."""
    from .config import (
        IS_WINDOWS, IS_MACOS, IS_LINUX
    )
    from .logging_setup import log_event
    from .keystroke_monitor import KeystrokeMonitor, PYNPUT_AVAILABLE
    from .device_monitor import BackgroundDeviceMonitor
    from .device_validator import (
        get_whitelist, parse_device, 
        evaluate, should_debounce
    )
    from .alert_system import play_alert_sound, show_alert, lock_workstation, eject_usb_device

    def check_admin() -> bool:
        """Check if running with elevated privileges."""
        if not IS_WINDOWS:
            try:
                return os.geteuid() == 0
            except (OSError, AttributeError) as e:
                logger.debug(f"Failed to check admin status on non-Windows: {e}")
                return False
        try:
            import ctypes
            windll = getattr(ctypes, "windll", None)  # type: ignore
            if windll:
                return windll.shell32.IsUserAnAdmin()
            return False
        except (OSError, AttributeError, TypeError) as e:
            logger.debug(f"Failed to check admin status: {e}")
            return False

    def kill_device(hw_id):
        """Disable device on Windows (requires admin)."""
        if not IS_WINDOWS:
            logger.warning(f"Device disabling not supported on {platform.system()}")
            return False
        
        logger.warning(f"Disabling hardware: {hw_id}")
        try:
            import subprocess
            proc = subprocess.run(
                f'pnputil /disable-device "{hw_id}"',
                shell=True, capture_output=True, text=True
            )
            if proc.returncode == 0:
                logger.info("Device disabled successfully")
                return True
            logger.error(f"Failed to disable device: {proc.stderr}")
        except Exception as e:
            logger.error(f"Error disabling device: {e}")
        return False

    def handle_event(dev_obj, whitelist, keystroke_mon=None):
        """Handle a new hardware connection event."""
        info = parse_device(dev_obj)
        
        if should_debounce(info['id']):
            return
        
        result, action, reason = evaluate(info, whitelist)
        log_event(logger, info, result, action, reason)
        
        if result == "TRUSTED":
            logger.info(f"Trusted device: {info['name']}")
        elif result == "SAFE":
            logger.info(f"Safe device: {info['name']}")
        else:  # UNTRUSTED
            logger.warning(f"🚨 UNTRUSTED DEVICE DETECTED: {info['id']}")
            
            # ===== SECURITY RESPONSE =====
            # 1. Play alert sound
            play_alert_sound()
            
            # 2. Show critical alert to user
            try:
                show_alert(info)
            except Exception as e:
                logger.error(f"Failed to show alert: {e}")
            
            # 3. Register with keystroke monitor for first-input delay detection
            if keystroke_mon:
                keystroke_mon.register_device_connection(info)
            
            # 4. Lock the workstation on all platforms
            try:
                logger.info("🔒 Locking workstation...")
                if lock_workstation():
                    logger.warning("✓ Workstation locked successfully")
                    action = "LOCKED"
            except Exception as e:
                logger.error(f"Failed to lock workstation: {e}")
            
            # 5. Eject/disable the device
            try:
                logger.info("⏏️  Ejecting malicious USB device...")
                from .alert_system import eject_usb_device
                if eject_usb_device(info['id']):
                    logger.warning("✓ USB device ejected successfully")
                    action = "EJECTED"
                else:
                    logger.warning("⚠️  Could not eject device, will attempt to disable...")
                    # Fallback on Windows: disable the device
                    if IS_WINDOWS and check_admin():
                        if kill_device(info['id']):
                            action = "DISABLED"
            except Exception as e:
                logger.error(f"Failed to eject device: {e}")


    def device_callback(new_devices):
        """Callback when new devices are detected."""
        for dev in new_devices:
            handle_event(dev, whitelist, keystroke_mon)

    # Initialize monitoring
    logger.info(f"HID Defender {platform.system()} {platform.release()}")
    logger.info("Loading whitelisted devices...")
    
    whitelist = get_whitelist()
    keystroke_mon = None
    
    if PYNPUT_AVAILABLE:
        keystroke_mon = KeystrokeMonitor(logger=logger)
        logger.info("Keystroke monitor enabled")
    
    logger.info("Monitoring started. Press Ctrl+C to stop.")
    
    # Start background device monitor
    wmi_client = None
    if IS_WINDOWS:
        try:
            import wmi
            wmi_client = wmi.WMI()
        except Exception as e:
            logger.warning(f"Could not initialize WMI: {e}")
    
    monitor = BackgroundDeviceMonitor(
        callback=device_callback,
        scan_interval=2.0,
        cache_ttl=1.0,
        wmi_client=wmi_client
    )
    monitor.start()
    logger.info("Background device monitor started (non-blocking)")
    
    try:
        # Main thread stays responsive for Ctrl+C
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    finally:
        monitor.stop()
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
