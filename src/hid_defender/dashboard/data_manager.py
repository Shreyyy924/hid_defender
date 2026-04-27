import csv
from datetime import datetime
from pathlib import Path
from collections import defaultdict
from typing import List, Dict, Optional

# Core imports
from hid_defender.device_validator import get_whitelist, save_whitelist

class DataManager:
    def __init__(self, log_path: str, whitelist_path: str):
        self.log_path = Path(log_path)
        self.whitelist_path = Path(whitelist_path)

    def load_log_rows(self) -> List[Dict]:
        """Load event log rows from CSV file, skipping malformed rows."""
        if not self.log_path.exists():
            return []

        rows = []
        try:
            with self.log_path.open(newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    clean = {}
                    for k, v in row.items():
                        if k is None: continue
                        if v is None: v = ""
                        elif isinstance(v, list): v = v[0] if v else ""
                        clean[k] = v.strip().strip('"') if isinstance(v, str) else ""
                    
                    result_val = (clean.get("Result") or "").upper()
                    if not clean.get("Time") or result_val not in ("TRUSTED", "SAFE", "UNTRUSTED"):
                        continue
                    
                    time_value = clean.get("Time")
                    try:
                        clean["parsed_time"] = datetime.strptime(time_value, "%Y-%m-%d %H:%M:%S") if time_value else None
                    except Exception:
                        clean["parsed_time"] = None
                    rows.append(clean)
        except Exception as e:
            print(f"Error reading log file: {e}")
        return rows

    def load_whitelist(self) -> List[Dict]:
        """Load whitelisted devices using core library."""
        return get_whitelist()

    def save_whitelist(self, whitelist: List[Dict]):
        """Save whitelisted devices using core library."""
        save_whitelist(whitelist)

    def build_summary(self, rows: List[Dict]) -> Dict:
        """Build summary statistics from log rows."""
        summary = {
            "total_events": len(rows),
            "trusted": 0,
            "safe": 0,
            "untrusted": 0,
            "blocked": 0,
            "disabled": 0,
            "unique_devices": len({row.get("ID") for row in rows if row.get("ID")}),
            "reasons": {},
            "last_event": None,
            "average_interval": None,
        }

        for row in rows:
            result = (row.get("Result") or "").upper()
            action = (row.get("Action") or "").upper()
            reason = row.get("Reason") or "Unknown"

            if result == "TRUSTED": summary["trusted"] += 1
            elif result == "SAFE": summary["safe"] += 1
            elif result == "UNTRUSTED": summary["untrusted"] += 1

            if action == "BLOCKED": summary["blocked"] += 1
            elif action == "DISABLED": summary["disabled"] += 1

            summary["reasons"][reason] = summary["reasons"].get(reason, 0) + 1

        sorted_rows = sorted(
            [r for r in rows if r.get("parsed_time")],
            key=lambda r: r["parsed_time"],
        )
        if sorted_rows:
            summary["last_event"] = sorted_rows[-1]["parsed_time"]
            intervals = []
            for previous, current in zip(sorted_rows, sorted_rows[1:]):
                delta = current["parsed_time"] - previous["parsed_time"]
                intervals.append(delta.total_seconds())
            if intervals:
                summary["average_interval"] = sum(intervals) / len(intervals)

        return summary

    def build_device_summary(self, rows: List[Dict]) -> Dict:
        """Build device information from rows."""
        devices = defaultdict(lambda: {
            "count": 0,
            "status": "Safe",
            "last_activity": None,
            "device_type": "Unknown",
            "vendor": "",
            "product": "",
            "events": []
        })
        
        for row in rows:
            device_id = row.get('ID', 'Unknown')
            device = devices[device_id]
            device["count"] += 1
            device["last_activity"] = row.get("parsed_time") or device.get("last_activity")
            device["device_type"] = row.get('Device', device.get("device_type"))
            device["vendor"] = row.get('Vendor', device.get("vendor"))
            device["product"] = row.get('Product', device.get("product"))
            device["status"] = row.get('Result', 'Safe')
            device["events"].append({
                "time": row.get("Time"),
                "action": row.get("Action"),
                "reason": row.get("Reason")
            })
        
        return dict(devices)

    def clear_logs(self):
        """Clear the alert logs."""
        if self.log_path.exists():
            with self.log_path.open("w", encoding="utf-8", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["Time", "Device", "Vendor", "Product", "ID", "Result", "Action", "Reason"])
