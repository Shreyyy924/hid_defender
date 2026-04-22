import sys
import csv
import json
from datetime import datetime
from pathlib import Path

project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root / "src"))

from hid_defender.config import LOG_PATH


def simulate_attacks():
    """Simulate attacks by appending 8-column CSV rows to the log file."""
    log_path = Path(LOG_PATH)

    # Create file with correct header if missing
    if not log_path.exists() or log_path.stat().st_size == 0:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(log_path, 'w', newline='', encoding='utf-8') as f:
            csv.writer(f).writerow(
                ["Time", "Device", "Vendor", "Product", "ID", "Result", "Action", "Reason"]
            )

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    attacks = [
        {
            "Device":  "Unknown Keyboard (BadUSB)",
            "Vendor":  "Unknown",
            "Product": "HID Keyboard",
            "ID":      "USB\\VID_046D&PID_C31C",
            "Result":  "UNTRUSTED",
            "Action":  "BLOCKED",
            "Reason":  "Rapid Keystroke Injection Detected (BadUSB Signature)"
        },
        {
            "Device":  "Rubber Ducky Clone",
            "Vendor":  "Unknown",
            "Product": "HID Keyboard",
            "ID":      "USB\\VID_16C0&PID_27DB",
            "Result":  "UNTRUSTED",
            "Action":  "BLOCKED",
            "Reason":  "Unauthorized Vendor / Blacklisted Device ID"
        },
        {
            "Device":  "Malicious Mouse Payload",
            "Vendor":  "Unknown",
            "Product": "HID Composite",
            "ID":      "USB\\VID_0000&PID_0000",
            "Result":  "UNTRUSTED",
            "Action":  "DISABLED",
            "Reason":  "Suspicious Interface Descriptors (Mouse acting as Keyboard)"
        },
        {
            "Device":  "Raspberry Pi Pico (BadUSB)",
            "Vendor":  "Unknown",
            "Product": "BadUSB Payload",
            "ID":      "USB\\VID_2E8A&PID_0003",
            "Result":  "UNTRUSTED",
            "Action":  "BLOCKED",
            "Reason":  "Known Attack Vector (Raspberry Pi Pico)"
        }
    ]

    with open(log_path, 'a', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        for attack in attacks:
            writer.writerow([
                now,
                attack["Device"],
                attack["Vendor"],
                attack["Product"],
                attack["ID"],
                attack["Result"],
                attack["Action"],
                attack["Reason"]
            ])

    print(json.dumps(attacks))
    return True


if __name__ == "__main__":
    simulate_attacks()
