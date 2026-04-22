from pathlib import Path
import csv
import json
import sys
import os
import re
import subprocess
import threading
import time
from datetime import datetime
from collections import defaultdict

# Setup path for imports
project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root / "src"))

from flask import Flask, render_template, jsonify, request
from hid_defender.config import LOG_PATH, WHITELIST_PATH


app = Flask(__name__, template_folder="templates", static_folder="static")


# ── Live USB Monitor ──────────────────────────────────────────────────────────

ATTACK_VIDS = {
    "VID_2E8A": "Raspberry Pi Pico (BadUSB)",
    "VID_239A": "Adafruit / CircuitPython (attack tool)",
    "VID_16C0": "Teensy / Arduino (BadUSB)",
    "VID_2341": "Arduino (BadUSB)",
    "VID_1209": "Open-source attack platform",
    "VID_6666": "Prototype / Generic BadUSB",
    "VID_CAFE": "BadUSB prototype",
    "VID_1B4F": "SparkFun (attack tool)",
    "VID_DEAD": "Spoofed / Fake USB Device",
}

HWID_RE = re.compile(r"(VID_[0-9A-F]{4}).*(PID_[0-9A-F]{4})", re.IGNORECASE)

_monitor_seen_ids: set = set()       # device IDs already evaluated
_new_alerts: list      = []          # queue of new UNTRUSTED events for the UI
_monitor_lock          = threading.Lock()
_monitor_started       = False


def _normalize_id(raw: str) -> str:
    m = HWID_RE.search(raw.upper())
    return f"{m.group(1)}&{m.group(2)}" if m else raw.strip().upper()


def _scan_usb_devices():
    """Enumerate USB HID devices via wmic (Windows only)."""
    devices = []
    try:
        result = subprocess.run(
            ["wmic", "path", "Win32_PnPEntity",
             "where", "PNPDeviceID like 'USB%'",
             "get", "PNPDeviceID,Name,Manufacturer,Caption",
             "/format:csv"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            return devices
        lines = [l.strip() for l in result.stdout.splitlines() if l.strip()]
        if len(lines) < 2:
            return devices
        header = [h.strip() for h in lines[0].split(",")]
        for line in lines[1:]:
            parts = line.split(",")
            if len(parts) < len(header):
                continue
            row  = dict(zip(header, [p.strip() for p in parts]))
            pnp  = row.get("PNPDeviceID", "")
            name = row.get("Name", "Unknown")
            desc = name.lower()
            if "hub" in desc or "host controller" in desc:
                continue
            keywords = ["hid", "keyboard", "mouse", "input", "audio", "composite", "media"]
            if not any(k in desc for k in keywords):
                continue
            devices.append({
                "name":    name,
                "vendor":  row.get("Manufacturer", "Unknown"),
                "product": row.get("Caption", name),
                "id":      pnp,
            })
    except Exception:
        pass
    return devices


def _evaluate_device(device: dict, whitelist: list):
    """Returns (result, action, reason)."""
    nid   = _normalize_id(device.get("id", ""))
    comb  = " ".join([device.get("vendor", ""), device.get("name", ""),
                      device.get("product", "")]).lower()

    for bad_vid, label in ATTACK_VIDS.items():
        if bad_vid in nid.upper():
            return "UNTRUSTED", "BLOCKED", f"Attack-vector VID: {label}"

    for entry in whitelist:
        stored = _normalize_id(entry.get("hardware_id", entry.get("id", "")))
        if stored and stored == nid:
            return "TRUSTED", "ALLOWED", "Whitelisted device"

    big_brands = ["logitech","dell","hp","microsoft","lenovo","corsair",
                  "razer","steelseries","asus","acer","apple","intel"]
    if any(b in comb for b in big_brands):
        return "SAFE", "ALLOWED", "Known peripheral brand (heuristic)"

    return "UNTRUSTED", "BLOCKED", "Unknown HID device — not in whitelist"


def _log_monitor_event(device: dict, result: str, action: str, reason: str):
    log_path = Path(LOG_PATH)
    write_header = not log_path.exists() or log_path.stat().st_size == 0
    with log_path.open("a", encoding="utf-8", newline="") as f:
        if write_header:
            f.write("Time,Device,Vendor,Product,ID,Result,Action,Reason\n")
        row = ",".join([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            f'"{device.get("name", "")}"',
            f'"{device.get("vendor", "")}"',
            f'"{device.get("product", "")}"',
            f'"{device.get("id", "")}"',
            result, action,
            f'"{reason}"',
        ])
        f.write(row + "\n")


def _take_defensive_action(device_id: str):
    """Lock workstation and attempt to disable the rogue device."""
    # 1. Alert beep (Windows)
    try:
        import winsound
        winsound.MessageBeep(winsound.MB_ICONHAND)
    except Exception:
        pass

    # 2. Lock the workstation immediately
    try:
        import ctypes
        ctypes.windll.user32.LockWorkStation()
        print("[HID Defender] \ud83d\udd12 Workstation locked")
    except Exception as e:
        print(f"[HID Defender] \u26a0 Could not lock workstation: {e}")

    # 3. Disable the USB device via pnputil (requires admin)
    try:
        result = subprocess.run(
            ["pnputil", "/disable-device", device_id],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            print(f"[HID Defender] \u2713 Device disabled: {device_id}")
        else:
            # Try ejecting as fallback
            subprocess.run(
                ["pnputil", "/remove-device", device_id],
                capture_output=True, text=True, timeout=10
            )
            print(f"[HID Defender] \u26a0 pnputil disable failed (admin required?) \u2014 attempted removal")
    except Exception as e:
        print(f"[HID Defender] \u26a0 Device disable error: {e}")


def _monitor_loop():
    """Background thread: scans USB every 5 seconds, logs & queues new threats."""

    global _monitor_seen_ids
    # Seed with current devices silently on first run
    for d in _scan_usb_devices():
        _monitor_seen_ids.add(d["id"])

    while True:
        time.sleep(5)
        try:
            from hid_defender.config import WHITELIST_PATH as WL_PATH
            wl_path = Path(WL_PATH)
            whitelist = json.loads(wl_path.read_text(encoding="utf-8")) if wl_path.exists() else []
        except Exception:
            whitelist = []

        try:
            current = _scan_usb_devices()
        except Exception:
            continue

        with _monitor_lock:
            for dev in current:
                if dev["id"] in _monitor_seen_ids:
                    continue
                _monitor_seen_ids.add(dev["id"])
                result, action, reason = _evaluate_device(dev, whitelist)
                _log_monitor_event(dev, result, action, reason)

                if result == "UNTRUSTED":
                    _new_alerts.append({
                        "time":   datetime.now().isoformat(),
                        "device": dev["name"],
                        "vendor": dev["vendor"],
                        "id":     dev["id"],
                        "reason": reason,
                        "action": action,
                    })
                    # ── Defensive actions (non-blocking threads) ──────────────
                    print(f"[HID Defender] 🚨 UNTRUSTED DEVICE: {dev['name']} ({dev['id']})")
                    print(f"[HID Defender]    Reason : {reason}")
                    threading.Thread(
                        target=_take_defensive_action,
                        args=(dev["id"],),
                        daemon=True
                    ).start()


def _start_monitor():
    global _monitor_started
    if _monitor_started:
        return
    _monitor_started = True
    t = threading.Thread(target=_monitor_loop, daemon=True, name="usb-monitor")
    t.start()
    print("[HID Defender] Background USB monitor started (5s polling)")


_start_monitor()


@app.route("/api/monitor/new-alerts")
def api_new_alerts():
    """Pop and return queued real-time UNTRUSTED alerts for the UI toast system."""
    with _monitor_lock:
        alerts = list(_new_alerts)
        _new_alerts.clear()
    return jsonify({"alerts": alerts, "count": len(alerts),
                    "timestamp": datetime.now().isoformat()})


@app.route("/api/monitor/status")
def api_monitor_status():
    """Return current monitor state."""
    return jsonify({
        "running": _monitor_started,
        "seen_devices": len(_monitor_seen_ids),
        "queued_alerts": len(_new_alerts),
        "timestamp": datetime.now().isoformat()
    })



def discover_tests():
    """Discover test functions from Chapter-4 test files."""
    test_dir = project_root / "tests"
    priority_files = ["test_unit_cases.py", "test_system_cases.py"]
    all_files = (
        [test_dir / f for f in priority_files if (test_dir / f).exists()]
        + sorted(f for f in test_dir.glob("test_*.py")
                 if f.name not in priority_files)
    )

    tests = []
    import re
    for test_file in all_files:
        module_name = test_file.stem
        try:
            content = test_file.read_text(encoding="utf-8")
            # Find class names and their docstrings for friendly labels
            class_docs = {}
            for m in re.finditer(r'class\s+(Test\w+)[^:]*:\s*\n\s+"""([^"]+)"""', content):
                class_docs[m.group(1)] = m.group(2).strip()

            # Find every test_ method
            for m in re.finditer(r'def\s+(test_\w+)\s*\(', content):
                func = m.group(1)
                # Guess which class owns this function
                class_name = ""
                for cm in re.finditer(r'class\s+(Test\w+)', content[:content.index(func)]):
                    class_name = cm.group(1)

                label = class_docs.get(class_name, class_name) or func
                tests.append({
                    "id":     f"{module_name}::{class_name}::{func}" if class_name else f"{module_name}::{func}",
                    "module": module_name,
                    "class":  class_name,
                    "name":   func,
                    "label":  label,
                    "file":   test_file.name,
                })
        except Exception as e:
            print(f"Error reading {test_file}: {e}")
    return tests


def run_test(test_id):
    """Run a specific pytest test_id and return pass/fail + output."""
    parts = test_id.split("::")
    module_name = parts[0]
    test_path   = str(project_root / "tests" / f"{module_name}.py")

    # Build node id for pytest (module::class::func or module::func)
    node_id = "::".join(parts)

    venv_pytest = project_root / ".venv" / "Scripts" / "pytest.exe"
    if not venv_pytest.exists():
        venv_pytest = project_root / ".venv" / "bin" / "pytest"
    pytest_cmd = [str(venv_pytest)] if venv_pytest.exists() else [sys.executable, "-m", "pytest"]

    try:
        result = subprocess.run(
            pytest_cmd + [test_path, "::" .join(parts[1:]) and f"{test_path}::{parts[1]}" or test_path,
                          "-v", "--tb=short", "--no-header", "-q"],
            cwd=project_root,
            capture_output=True,
            text=True,
            timeout=60,
        )
        return {
            "passed":     result.returncode == 0,
            "stdout":     result.stdout,
            "stderr":     result.stderr,
            "returncode": result.returncode,
        }
    except subprocess.TimeoutExpired:
        return {"passed": False, "stdout": "", "stderr": "Timed out", "returncode": -1}
    except Exception as e:
        return {"passed": False, "stdout": "", "stderr": str(e), "returncode": -1}


@app.route("/api/tests")
def api_tests():
    """API endpoint to list all available tests."""
    tests = discover_tests()
    return jsonify({"tests": tests, "total": len(tests),
                    "timestamp": datetime.now().isoformat()})


@app.route("/api/tests/run", methods=["POST"])
def api_run_test():
    """Run a single test by id."""
    data    = request.get_json()
    test_id = data.get("test_id")
    if not test_id:
        return jsonify({"error": "test_id required"}), 400
    result = run_test(test_id)
    return jsonify({"test_id": test_id, "result": result,
                    "timestamp": datetime.now().isoformat()})


@app.route("/api/tests/run/all", methods=["POST"])
def api_run_all_tests():
    """Run the full test suite and return summary."""
    data     = request.get_json() or {}
    pattern  = data.get("file", "")          # e.g. "test_unit_cases" or ""

    venv_pytest = project_root / ".venv" / "Scripts" / "pytest.exe"
    if not venv_pytest.exists():
        venv_pytest = project_root / ".venv" / "bin" / "pytest"
    pytest_cmd = [str(venv_pytest)] if venv_pytest.exists() else [sys.executable, "-m", "pytest"]

    target = str(project_root / "tests" / f"{pattern}.py") if pattern else str(project_root / "tests")
    try:
        result = subprocess.run(
            pytest_cmd + [target, "-v", "--tb=short", "--no-header"],
            cwd=project_root,
            capture_output=True, text=True, timeout=120,
        )
        # Parse passed/failed counts from pytest output
        import re
        summary = result.stdout.split("\n")[-3] if result.stdout else ""
        passed  = len(re.findall(r" PASSED", result.stdout))
        failed  = len(re.findall(r" FAILED", result.stdout))
        errors  = len(re.findall(r" ERROR",  result.stdout))

        return jsonify({
            "passed":     result.returncode == 0,
            "pass_count": passed,
            "fail_count": failed,
            "error_count":errors,
            "summary":    summary,
            "stdout":     result.stdout[-8000:],   # trim for JSON size
            "stderr":     result.stderr[-2000:],
            "timestamp":  datetime.now().isoformat(),
        })
    except subprocess.TimeoutExpired:
        return jsonify({"passed": False, "stderr": "Test suite timed out"}), 500
    except Exception as e:
        return jsonify({"passed": False, "stderr": str(e)}), 500


@app.route("/tests")
def tests_page():
    """Dedicated test runner page."""
    tests = discover_tests()
    unit_tests   = [t for t in tests if "unit"   in t["file"]]
    system_tests = [t for t in tests if "system" in t["file"]]
    other_tests  = [t for t in tests if "unit" not in t["file"] and "system" not in t["file"]]
    return render_template("tests.html",
                           unit_tests=unit_tests,
                           system_tests=system_tests,
                           other_tests=other_tests,
                           total=len(tests))


@app.route("/api/simulate_attack", methods=["POST"])
def api_simulate_attack():
    """API endpoint to trigger the attack simulation script."""
    try:
        script_path = project_root / "scripts" / "simulate_attacks.py"
        result = subprocess.run(
            [sys.executable, str(script_path)],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            try:
                attacks_data = json.loads(result.stdout)
            except json.JSONDecodeError:
                attacks_data = []
            return jsonify({"success": True, "message": "Attacks simulated", "attacks": attacks_data})
        else:
            return jsonify({"success": False, "error": result.stderr}), 500
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500



def load_log_rows():
    """Load event log rows from CSV file, skipping malformed rows."""
    log_path = Path(LOG_PATH)
    if not log_path.exists():
        return []

    rows = []
    try:
        with log_path.open(newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Safely clean row: skip None keys, handle None/list values
                clean = {}
                for k, v in row.items():
                    if k is None:
                        continue
                    if v is None:
                        v = ""
                    elif isinstance(v, list):
                        v = v[0] if v else ""
                    clean[k] = v.strip().strip('"') if isinstance(v, str) else ""
                row = clean
                # Skip rows with invalid or missing Result classification
                result_val = (row.get("Result") or "").upper()
                if not row.get("Time") or result_val not in ("TRUSTED", "SAFE", "UNTRUSTED"):
                    continue
                time_value = row.get("Time")
                try:
                    row["parsed_time"] = datetime.strptime(time_value, "%Y-%m-%d %H:%M:%S") if time_value else None
                except Exception:
                    row["parsed_time"] = None
                rows.append(row)
    except Exception as e:
        print(f"Error reading log file: {e}")
    return rows


def load_whitelist():
    """Load whitelisted devices from JSON file."""
    whitelist_path = Path(WHITELIST_PATH)
    if not whitelist_path.exists():
        return []
    
    try:
        with whitelist_path.open(encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"Error reading whitelist: {e}")
        return []


def build_summary(rows):
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

        if result == "TRUSTED":
            summary["trusted"] += 1
        elif result == "SAFE":
            summary["safe"] += 1
        elif result == "UNTRUSTED":
            summary["untrusted"] += 1

        if action == "BLOCKED":
            summary["blocked"] += 1
        elif action == "DISABLED":
            summary["disabled"] += 1

        summary["reasons"][reason] = summary["reasons"].get(reason, 0) + 1

    # Calculate timing statistics
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


def build_device_summary(rows):
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


@app.route("/")
def dashboard():
    """Main dashboard route."""
    rows = load_log_rows()
    rows = sorted(rows, key=lambda r: r.get("parsed_time") or datetime.min, reverse=True)
    summary = build_summary(rows)
    whitelist = load_whitelist()

    return render_template(
        "index.html",
        rows=rows,
        summary=summary,
        whitelist=whitelist,
    )


@app.route("/api/events")
def api_events():
    """API endpoint for recent events (JSON)."""
    rows = load_log_rows()
    rows = sorted(rows, key=lambda r: r.get("parsed_time") or datetime.min, reverse=True)
    
    limit = 100
    events = []
    for row in rows[:limit]:
        events.append({
            "time": row.get("parsed_time").isoformat() if row.get("parsed_time") else row.get("Time"),
            "device": row.get("Device"),
            "vendor": row.get("Vendor"),
            "product": row.get("Product"),
            "id": row.get("ID"),
            "result": row.get("Result"),
            "action": row.get("Action"),
            "reason": row.get("Reason")
        })
    
    return jsonify({
        "events": events,
        "total": len(rows),
        "timestamp": datetime.now().isoformat()
    })


@app.route("/api/summary")
def api_summary():
    """API endpoint for summary statistics (JSON)."""
    rows = load_log_rows()
    summary = build_summary(rows)
    
    # Convert datetime to string
    if summary["last_event"]:
        summary["last_event"] = summary["last_event"].isoformat()
    
    summary["timestamp"] = datetime.now().isoformat()
    return jsonify(summary)


@app.route("/api/alerts")
def api_alerts():
    """API endpoint for alerts (untrusted devices)."""
    rows = load_log_rows()
    rows = sorted(rows, key=lambda r: r.get("parsed_time") or datetime.min, reverse=True)
    
    alerts = []
    for row in rows:
        if row.get("Result", "").upper() == "UNTRUSTED":
            alerts.append({
                "time": row.get("parsed_time").isoformat() if row.get("parsed_time") else row.get("Time"),
                "reason": row.get("Reason", "Unknown Alert"),
                "device": row.get("Device"),
                "vendor": row.get("Vendor"),
                "id": row.get("ID")
            })
    
    return jsonify({
        "alerts": alerts[:10],
        "total": len(alerts),
        "timestamp": datetime.now().isoformat()
    })


@app.route("/api/whitelist")
def api_whitelist():
    """API endpoint for the trusted devices whitelist."""
    raw = load_whitelist()
    # Normalize field names: hardware_id→id, name→device so the JS can use them uniformly
    whitelist = []
    for entry in raw:
        whitelist.append({
            "id":      entry.get("id") or entry.get("hardware_id", ""),
            "device":  entry.get("device") or entry.get("name", "Unknown"),
            "vendor":  entry.get("vendor", "Unknown"),
            "product": entry.get("product", ""),
            "added":   entry.get("added", ""),
        })
    return jsonify({
        "whitelist": whitelist,
        "total": len(whitelist),
        "timestamp": datetime.now().isoformat()
    })


@app.route("/api/whitelist/add", methods=["POST"])
def api_add_trusted():
    """API endpoint to add a device to the trusted whitelist."""
    data = request.get_json()
    hw_id = data.get("id")
    device_name = data.get("device", "Unknown Device")
    vendor = data.get("vendor", "Unknown Vendor")
    product = data.get("product", "Unknown Product")
    
    if not hw_id:
        return jsonify({"success": False, "error": "Hardware ID (VID/PID) is required"}), 400
        
    whitelist = load_whitelist()
    
    # Check if already exists
    for entry in whitelist:
        if entry.get("id") == hw_id:
            return jsonify({"success": False, "error": "Device already in whitelist"}), 400
            
    # Add new entry
    new_entry = {
        "id": hw_id,
        "device": device_name,
        "vendor": vendor,
        "product": product,
        "added": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    whitelist.append(new_entry)
    
    try:
        whitelist_path = Path(WHITELIST_PATH)
        whitelist_path.parent.mkdir(parents=True, exist_ok=True)
        with whitelist_path.open("w", encoding="utf-8") as f:
            json.dump(whitelist, f, indent=4)
        return jsonify({"success": True, "message": f"Added {device_name} to whitelist"})
    except Exception as e:
        return jsonify({"success": False, "error": f"Failed to save whitelist: {str(e)}"}), 500


@app.route("/api/whitelist/delete", methods=["POST"])
def api_delete_trusted():
    """API endpoint to remove a device from the trusted whitelist."""
    data = request.get_json()
    hw_id = data.get("id")
    
    if not hw_id:
        return jsonify({"success": False, "error": "Hardware ID required"}), 400
        
    whitelist = load_whitelist()
    new_whitelist = [entry for entry in whitelist if entry.get("id") != hw_id]
    
    if len(new_whitelist) == len(whitelist):
        return jsonify({"success": False, "error": "Device not found in whitelist"}), 404
        
    try:
        with open(WHITELIST_PATH, "w", encoding="utf-8") as f:
            json.dump(new_whitelist, f, indent=4)
        return jsonify({"success": True, "message": "Device removed from whitelist"})
    except Exception as e:
        return jsonify({"success": False, "error": f"Failed to save whitelist: {str(e)}"}), 500


@app.route("/api/logs/clear", methods=["POST"])
def api_clear_logs():
    """API endpoint to clear the alert logs."""
    try:
        log_path = Path(LOG_PATH)
        if log_path.exists():
            # Keep header if CSV
            with log_path.open("w", encoding="utf-8", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["Time", "Device", "Vendor", "Product", "ID", "Result", "Action", "Reason"])
        return jsonify({"success": True, "message": "Logs cleared successfully"})
    except Exception as e:
        return jsonify({"success": False, "error": f"Failed to clear logs: {str(e)}"}), 500


@app.route("/api/devices")
def api_devices():
    """API endpoint for device information."""
    rows = load_log_rows()
    devices_data = build_device_summary(rows)
    
    devices = []
    for device_id, info in list(devices_data.items())[:10]:
        devices.append({
            "id": device_id,
            "type": info["device_type"],
            "vendor": info["vendor"],
            "product": info["product"],
            "status": info["status"],
            "event_count": info["count"],
            "last_activity": info["last_activity"].isoformat() if info["last_activity"] else None
        })
    
    return jsonify({
        "devices": devices,
        "total": len(devices_data),
        "timestamp": datetime.now().isoformat()
    })


@app.route("/api/activity")
def api_activity():
    """API endpoint for recent activity logs."""
    rows = load_log_rows()
    rows = sorted(rows, key=lambda r: r.get("parsed_time") or datetime.min, reverse=True)
    
    activity = []
    for row in rows[:20]:
        activity.append({
            "time": row.get("parsed_time").isoformat() if row.get("parsed_time") else row.get("Time"),
            "action": row.get("Action", "Event"),
            "device": row.get("Device"),
            "result": row.get("Result"),
            "reason": row.get("Reason")
        })
    
    return jsonify({
        "activity": activity,
        "timestamp": datetime.now().isoformat()
    })


@app.route("/api/stats")
def api_stats():
    """API endpoint for statistics and charts."""
    rows = load_log_rows()
    summary = build_summary(rows)
    
    # Top reasons
    top_reasons = sorted(
        summary["reasons"].items(),
        key=lambda x: x[1],
        reverse=True
    )[:10]
    
    return jsonify({
        "total_events": summary["total_events"],
        "trusted": summary["trusted"],
        "safe": summary["safe"],
        "untrusted": summary["untrusted"],
        "blocked": summary["blocked"],
        "disabled": summary["disabled"],
        "unique_devices": summary["unique_devices"],
        "last_event": summary["last_event"].isoformat() if summary["last_event"] else None,
        "average_interval": summary["average_interval"],
        "top_reasons": [{"reason": r[0], "count": r[1]} for r in top_reasons],
        "timestamp": datetime.now().isoformat()
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5001"))
    app.run(host="0.0.0.0", port=port, debug=False)
