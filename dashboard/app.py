from pathlib import Path
import csv
import json
import sys
import os
import subprocess
from datetime import datetime
from collections import defaultdict

# Setup path for imports
project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root / "src"))

from flask import Flask, render_template, jsonify, request
from hid_defender.config import LOG_PATH, WHITELIST_PATH


app = Flask(__name__, template_folder="templates", static_folder="static")


def discover_tests():
    """Discover all test files and test functions."""
    test_dir = project_root / "tests"
    tests = []
    
    if test_dir.exists():
        for test_file in sorted(test_dir.glob("test_*.py")):
            module_name = test_file.stem
            try:
                with open(test_file, 'r') as f:
                    content = f.read()
                    # Extract test functions and class methods
                    import re
                    # Find all test functions and methods
                    test_funcs = re.findall(r'def (test_[a-zA-Z0-9_]+)\(', content)
                    for func in test_funcs:
                        tests.append({
                            "id": f"{module_name}::{func}",
                            "module": module_name,
                            "name": func,
                            "file": str(test_file.name)
                        })
            except Exception as e:
                print(f"Error reading {test_file}: {e}")
    
    return tests


def run_test(test_id):
    """Run a specific test and capture output."""
    module_name, test_name = test_id.split("::")
    test_path = f"tests/{module_name}.py"
    
    # Try to find the virtualenv pytest first, fallback to sys.executable -m pytest
    venv_pytest = project_root / ".venv" / "bin" / "pytest"
    if venv_pytest.exists():
        pytest_cmd = [str(venv_pytest)]
    else:
        pytest_cmd = [sys.executable, "-m", "pytest"]
        
    try:
        result = subprocess.run(
            pytest_cmd + [test_path, "-k", test_name, "-v", "--tb=short"],
            cwd=project_root,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        return {
            "passed": result.returncode == 0,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode
        }
    except subprocess.TimeoutExpired:
        return {
            "passed": False,
            "stdout": "",
            "stderr": "Test execution timed out",
            "returncode": -1
        }
    except Exception as e:
        return {
            "passed": False,
            "stdout": "",
            "stderr": str(e),
            "returncode": -1
        }


def load_log_rows():
    """Load event log rows from CSV file."""
    log_path = Path(LOG_PATH)
    if not log_path.exists():
        return []

    rows = []
    try:
        with log_path.open(newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                time_value = row.get("Time") or row.get("time")
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
    whitelist = load_whitelist()
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


@app.route("/api/tests")
def api_tests():
    """API endpoint to list all available tests."""
    tests = discover_tests()
    return jsonify({
        "tests": tests,
        "total": len(tests),
        "timestamp": datetime.now().isoformat()
    })


@app.route("/api/tests/run", methods=["POST"])
def api_run_test():
    """API endpoint to run a specific test."""
    data = request.get_json()
    test_id = data.get("test_id")
    
    if not test_id:
        return jsonify({"error": "test_id required"}), 400
    
    result = run_test(test_id)
    return jsonify({
        "test_id": test_id,
        "result": result,
        "timestamp": datetime.now().isoformat()
    })


@app.route("/api/simulate_attack", methods=["POST"])
def api_simulate_attack():
    """API endpoint to trigger the attack simulation script."""
    try:
        script_path = project_root / "scripts" / "simulate_attacks.py"
        result = subprocess.run(
            [sys.executable, str(script_path)],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            import json
            try:
                attacks_data = json.loads(result.stdout)
            except json.JSONDecodeError:
                attacks_data = []
            return jsonify({"success": True, "message": "Attacks simulated successfully", "attacks": attacks_data})
        else:
            return jsonify({"success": False, "error": result.stderr}), 500
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5001"))
    app.run(host="0.0.0.0", port=port, debug=False)
