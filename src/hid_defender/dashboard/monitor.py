import threading
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional

# Core imports
from hid_defender.device_monitor import BackgroundDeviceMonitor
from hid_defender.device_validator import evaluate, get_whitelist, normalize_hardware_id
from hid_defender.logging_setup import log_event, init_logger
from hid_defender.alert_system import lock_workstation, eject_usb_device

class USBMonitor:
    def __init__(self, log_path: str, whitelist_path: str):
        self.log_path = Path(log_path)
        self.whitelist_path = Path(whitelist_path)
        self.new_alerts: List[Dict] = []
        self.lock = threading.Lock()
        
        # Initialize core monitor and logger
        self.logger = init_logger()
        self.core_monitor = BackgroundDeviceMonitor(
            callback=self._on_new_devices,
            scan_interval=5.0
        )

    def _on_new_devices(self, devices: List[Dict]):
        """Callback for new devices from core monitor."""
        whitelist = get_whitelist()
        
        with self.lock:
            for dev in devices:
                result, action, reason = evaluate(dev, whitelist)
                
                # Log the event using core library
                log_event(self.logger, dev, result, action, reason)

                if result == "UNTRUSTED":
                    self.new_alerts.append({
                        "time":   datetime.now().isoformat(),
                        "device": dev.get("name", "Unknown"),
                        "vendor": dev.get("vendor", "Unknown"),
                        "id":     dev.get("id", "Unknown"),
                        "reason": reason,
                        "action": action,
                    })
                    
                    # Defensive actions via core library
                    print(f"[HID Defender] 🚨 UNTRUSTED DEVICE: {dev.get('name')} ({dev.get('id')})")
                    print(f"[HID Defender]    Reason : {reason}")
                    
                    # Run defensive actions in separate threads to not block monitor
                    threading.Thread(target=lock_workstation, daemon=True).start()
                    threading.Thread(target=eject_usb_device, args=(dev.get("id"),), daemon=True).start()

    def start(self):
        self.core_monitor.start()

    def get_new_alerts(self):
        with self.lock:
            alerts = list(self.new_alerts)
            self.new_alerts.clear()
        return alerts

    def get_status(self):
        return {
            "running": self.core_monitor.is_running,
            "seen_devices": len(self.core_monitor._device_ids_seen),
            "queued_alerts": len(self.new_alerts),
            "timestamp": datetime.now().isoformat()
        }
