import sys
import csv
import json
from datetime import datetime
from pathlib import Path

# Add src to path
project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root / "src"))

from hid_defender.config import LOG_PATH  # noqa: E402


def simulate_attacks():
    """Simulate attacks by writing realistic threat events to the audit log."""
    log_path = Path(LOG_PATH)

    # Ensure log file exists and has headers
    file_exists = log_path.exists()
    headers = ["Time", "Device", "Vendor", "Product", "ID", "Result", "Action", "Reason"]

    if not file_exists:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(log_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(headers)

    attacks = [
        {
            "event": "Keystroke Injection",
            "device": "Rubber Ducky Clone",
            "vendor": "Hak5",
            "product": "BadUSB Keyboard",
            "id": "VID_16C0&PID_27DB",
            "result": "UNTRUSTED",
            "action": "BLOCKED",
            "reason": "Rapid keystroke injection detected",
        },
        {
            "event": "Unauthorized Device Detection",
            "device": "Raspberry Pi Pico",
            "vendor": "Raspberry Pi",
            "product": "Pico HID Payload",
            "id": "VID_2E8A&PID_0003",
            "result": "UNTRUSTED",
            "action": "BLOCKED",
            "reason": "Attack-vector VID detected: VID_2E8A",
        },
        {
            "event": "Payload Escalation Attempt",
            "device": "Malicious Mouse Payload",
            "vendor": "Unknown",
            "product": "Composite HID Adapter",
            "id": "VID_0000&PID_0000",
            "result": "UNTRUSTED",
            "action": "DISABLED",
            "reason": "Suspicious interface descriptors detected",
        },
    ]

    with open(log_path, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        for index, attack in enumerate(attacks):
            event_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            writer.writerow(
                [
                    event_time,
                    attack["device"],
                    attack["vendor"],
                    attack["product"],
                    attack["id"],
                    attack["result"],
                    attack["action"],
                    attack["reason"],
                ]
            )
            attack["time"] = event_time
            attack["sequence"] = index + 1

    # Print JSON output for the backend to consume
    print(json.dumps(attacks))
    return True


if __name__ == "__main__":
    simulate_attacks()
