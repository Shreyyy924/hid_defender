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
    from .device_monitor import get_macos_usb_devices
    from .device_validator import (
        get_whitelist, parse_device, 
        evaluate, should_debounce
    )
    from .alert_system import play_alert_sound, show_alert, lock_workstation

    def check_admin():
        """Check if running with elevated privileges."""
        if not IS_WINDOWS:
            return os.geteuid() == 0
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin()
        except Exception:
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
            logger.warning(f"UNTRUSTED DEVICE DETECTED: {info['id']}")
            play_alert_sound()
            
            if keystroke_mon:
                keystroke_mon.register_device_connection(info)
            
            if IS_WINDOWS:
                try:
                    logger.info("Locking workstation...")
                    if lock_workstation():
                        action = "LOCKED"
                except Exception as e:
                    logger.error(f"Failed to lock workstation: {e}")
            
            if check_admin():
                action = "DISABLED"
                kill_device(info['id'])

    # Initialize monitoring
    logger.info(f"HID Defender {platform.system()} {platform.release()}")
    logger.info("Loading whitelisted devices...")
    
    whitelist = get_whitelist()
    keystroke_mon = None
    
    if PYNPUT_AVAILABLE:
        keystroke_mon = KeystrokeMonitor(logger=logger)
        logger.info("Keystroke monitor enabled")
    
    logger.info("Monitoring started. Press Ctrl+C to stop.")
    
    if IS_MACOS:
        # macOS monitoring loop
        while True:
            try:
                devices = get_macos_usb_devices()
                # Process devices...
                time.sleep(2)
            except KeyboardInterrupt:
                break
            except Exception as e:
                logger.error(f"Monitoring error: {e}")
    else:
        logger.warning(f"Monitoring not fully implemented for {platform.system()}")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
