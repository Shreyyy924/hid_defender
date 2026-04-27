from pathlib import Path
import sys
import os
import subprocess
import json
from datetime import datetime
from flask import Flask, render_template, jsonify, request

# The app is now located at src/hid_defender/dashboard/app.py
# Project root is three levels up
dashboard_dir = Path(__file__).resolve().parent
package_root = dashboard_dir.parent
project_root = package_root.parent.parent

# Add src to sys.path if not already there (for standalone runs)
if str(package_root.parent) not in sys.path:
    sys.path.insert(0, str(package_root.parent))

from hid_defender.config import LOG_PATH, WHITELIST_PATH
from .monitor import USBMonitor
from .test_manager import TestManager
from .data_manager import DataManager

app = Flask(__name__, 
            template_folder=str(dashboard_dir / "templates"), 
            static_folder=str(dashboard_dir / "static"))

# Initialize managers
monitor = USBMonitor(LOG_PATH, WHITELIST_PATH)
test_manager = TestManager(project_root)
data_manager = DataManager(LOG_PATH, WHITELIST_PATH)

# Start background monitor
monitor.start()

# ── API Routes ──────────────────────────────────────────────────────────────

@app.route("/")
def dashboard():
    """Main dashboard route."""
    rows = data_manager.load_log_rows()
    rows = sorted(rows, key=lambda r: r.get("parsed_time") or datetime.min, reverse=True)
    summary = data_manager.build_summary(rows)
    whitelist = data_manager.load_whitelist()

    return render_template(
        "index.html",
        rows=rows,
        summary=summary,
        whitelist=whitelist,
    )

@app.route("/api/monitor/new-alerts")
def api_new_alerts():
    """Pop and return queued real-time UNTRUSTED alerts for the UI toast system."""
    alerts = monitor.get_new_alerts()
    return jsonify({"alerts": alerts, "count": len(alerts),
                    "timestamp": datetime.now().isoformat()})

@app.route("/api/monitor/status")
def api_monitor_status():
    """Return current monitor state."""
    return jsonify(monitor.get_status())

@app.route("/api/tests")
def api_tests():
    """API endpoint to list all available tests."""
    tests = test_manager.discover_tests()
    return jsonify({"tests": tests, "total": len(tests),
                    "timestamp": datetime.now().isoformat()})

@app.route("/api/tests/run", methods=["POST"])
def api_run_test():
    """Run a single test by id."""
    data    = request.get_json()
    test_id = data.get("test_id")
    if not test_id:
        return jsonify({"error": "test_id required"}), 400
    result = test_manager.run_test(test_id)
    return jsonify({"test_id": test_id, "result": result,
                    "timestamp": datetime.now().isoformat()})

@app.route("/api/tests/run/all", methods=["POST"])
def api_run_all_tests():
    """Run the full test suite and return summary."""
    data     = request.get_json() or {}
    pattern  = data.get("file", "")
    try:
        results = test_manager.run_all_tests(pattern)
        return jsonify(results)
    except TimeoutError:
        return jsonify({"passed": False, "stderr": "Test suite timed out"}), 500
    except Exception as e:
        return jsonify({"passed": False, "stderr": str(e)}), 500

@app.route("/tests")
def tests_page():
    """Dedicated test runner page."""
    tests = test_manager.discover_tests()
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

@app.route("/api/events")
def api_events():
    """API endpoint for recent events (JSON)."""
    rows = data_manager.load_log_rows()
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
    rows = data_manager.load_log_rows()
    summary = data_manager.build_summary(rows)
    
    if summary["last_event"]:
        summary["last_event"] = summary["last_event"].isoformat()
    
    summary["timestamp"] = datetime.now().isoformat()
    return jsonify(summary)

@app.route("/api/alerts")
def api_alerts():
    """API endpoint for alerts (untrusted devices)."""
    rows = data_manager.load_log_rows()
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
    raw = data_manager.load_whitelist()
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
        
    whitelist = data_manager.load_whitelist()
    
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
        data_manager.save_whitelist(whitelist)
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
        
    whitelist = data_manager.load_whitelist()
    new_whitelist = [entry for entry in whitelist if entry.get("id") != hw_id]
    
    if len(new_whitelist) == len(whitelist):
        return jsonify({"success": False, "error": "Device not found in whitelist"}), 404
        
    try:
        data_manager.save_whitelist(new_whitelist)
        return jsonify({"success": True, "message": "Device removed from whitelist"})
    except Exception as e:
        return jsonify({"success": False, "error": f"Failed to save whitelist: {str(e)}"}), 500

@app.route("/api/logs/clear", methods=["POST"])
def api_clear_logs():
    """API endpoint to clear the alert logs."""
    try:
        data_manager.clear_logs()
        return jsonify({"success": True, "message": "Logs cleared successfully"})
    except Exception as e:
        return jsonify({"success": False, "error": f"Failed to clear logs: {str(e)}"}), 500

@app.route("/api/devices")
def api_devices():
    """API endpoint for device information."""
    rows = data_manager.load_log_rows()
    devices_data = data_manager.build_device_summary(rows)
    
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
    rows = data_manager.load_log_rows()
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
    rows = data_manager.load_log_rows()
    summary = data_manager.build_summary(rows)
    
    top_reasons = sorted(
        summary["reasons"].items(),
        key=lambda x: x[1],
        reverse=True
    )[:10]
    
    return jsonify({
        "total_events": summary["total_events"],
        "trusted_count": summary["trusted"],
        "safe_count": summary["safe"],
        "untrusted_count": summary["untrusted"],
        "blocked_count": summary["blocked"],
        "disabled_count": summary["disabled"],
        "unique_devices": summary["unique_devices"],
        "top_reasons": top_reasons,
        "average_interval": summary["average_interval"],
        "timestamp": datetime.now().isoformat()
    })

if __name__ == "__main__":
    app.run(debug=True, port=8888)
