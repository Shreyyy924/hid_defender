import os
import sys
import csv
import json
from datetime import datetime
from pathlib import Path

# Add src to path
project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root / "src"))

from hid_defender.config import LOG_PATH

def simulate_attacks():
    """Simulates attacks by writing fake threat events to the log file and returns JSON details."""
    log_path = Path(LOG_PATH)
    
    # Ensure log file exists and has headers
    file_exists = log_path.exists()
    headers = ["Time", "Event", "Device", "Vendor", "Product", "ID", "Result", "Action", "Reason"]
    
    if not file_exists:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(log_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(headers)

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    attacks = [
        {
            "Event": "Keystroke Monitor",
            "Device": "Unknown Keyboard",
            "Vendor": "046d",
            "Product": "c31c",
            "ID": "USB_046D_C31C",
            "Result": "UNTRUSTED",
            "Action": "BLOCKED",
            "Reason": "Rapid Keystroke Injection Detected (BadUSB Signature)"
        },
        {
            "Event": "Device Monitor",
            "Device": "Rubber Ducky Clone",
            "Vendor": "16c0",
            "Product": "27db",
            "ID": "USB_16C0_27DB",
            "Result": "UNTRUSTED",
            "Action": "BLOCKED",
            "Reason": "Unauthorized Vendor / Blacklisted Device ID"
        },
        {
            "Event": "Device Validator",
            "Device": "Malicious Mouse payload",
            "Vendor": "0000",
            "Product": "0000",
            "ID": "USB_0000_0000",
            "Result": "UNTRUSTED",
            "Action": "DISABLED",
            "Reason": "Suspicious Interface Descriptors (Mouse acting as Keyboard)"
        },
        {
            "Event": "Device Monitor",
            "Device": "Raspberry Pi Pico (BadUSB)",
            "Vendor": "2e8a",
            "Product": "0003",
            "ID": "USB_2E8A_0003",
            "Result": "UNTRUSTED",
            "Action": "BLOCKED",
            "Reason": "Known Attack Vector (Raspberry Pi Pico)"
        }
    ]

    with open(log_path, 'a', newline='') as f:
        writer = csv.writer(f)
        for attack in attacks:
            writer.writerow([
                now,
                attack["Event"],
                attack["Device"],
                attack["Vendor"],
                attack["Product"],
                attack["ID"],
                attack["Result"],
                attack["Action"],
                attack["Reason"]
            ])

    # Print JSON output for the backend to consume
    print(json.dumps(attacks))
    return True

if __name__ == "__main__":
    simulate_attacks()
