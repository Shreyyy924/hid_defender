import sys
from pathlib import Path
import json

import pytest


project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from dashboard.app import app


def test_test_runner_rejects_malformed_test_identifiers():
    """Verify that the test runner properly rejects malformed test IDs"""
    result = app.view_functions["api_run_test"].__globals__["run_test"]("invalid")

    assert result["passed"] is False
    assert result["returncode"] == -1
    assert "Invalid test_id format" in result["stderr"]


def test_whitelist_add_endpoint_enforces_required_device_id_parameter(client):
    """Verify that adding to whitelist requires a device ID parameter"""
    response = client.post(
        "/api/whitelist/add",
        data="{not-json",
        content_type="application/json",
    )

    assert response.status_code == 400
    assert response.get_json()["error"] == "device_id required"


def test_test_execution_endpoint_enforces_required_test_id_parameter(client):
    """Verify that test execution endpoint requires a test ID parameter"""
    response = client.post(
        "/api/tests/run",
        data="{not-json",
        content_type="application/json",
    )

    assert response.status_code == 400
    assert response.get_json()["error"] == "test_id required"


def test_whitelist_removal_handles_corrupted_whitelist_file_gracefully(tmp_path, monkeypatch, client):
    """Verify that whitelist removal handles corrupted JSON files with proper error reporting"""
    broken_whitelist = tmp_path / "trusted_devices.json"
    broken_whitelist.write_text("{broken", encoding="utf-8")
    monkeypatch.setattr("dashboard.app.WHITELIST_PATH", str(broken_whitelist))

    response = client.delete("/api/whitelist/remove/test-device")

    assert response.status_code == 500
    assert "Failed to remove device:" in response.get_json()["error"]


def test_whitelist_add_correctly_extracts_and_stores_hardware_identifiers(tmp_path, monkeypatch, client):
    """Verify that whitelist correctly extracts hardware ID from full device ID and stores it"""
    whitelist_file = tmp_path / "trusted_devices.json"
    monkeypatch.setattr("dashboard.app.WHITELIST_PATH", str(whitelist_file))

    response = client.post(
        "/api/whitelist/add",
        json={
            "device_id": "USB\\VID_16C0&PID_27DB\\123",
            "device_info": {"vendor": "Hak5", "product": "Rubber Ducky Clone"},
        },
    )

    assert response.status_code == 200
    stored = json.loads(whitelist_file.read_text(encoding="utf-8"))
    assert stored[0]["hardware_id"] == "VID_16C0&PID_27DB"
    assert stored[0]["id"] == "VID_16C0&PID_27DB"


def test_whitelist_candidates_correctly_filters_out_already_trusted_devices(tmp_path, monkeypatch, client):
    """Verify that whitelist candidates API excludes devices that are already in the trusted whitelist"""
    log_file = tmp_path / "hid_alerts.log"
    whitelist_file = tmp_path / "trusted_devices.json"
    log_file.write_text(
        "\n".join(
            [
                "Time,Device,Vendor,Product,ID,Result,Action,Reason",
                "2026-01-01 12:00:00,Rubber Ducky,Hak5,BadUSB Keyboard,VID_16C0&PID_27DB,UNTRUSTED,BLOCKED,Injected payload",
                "2026-01-01 12:01:00,Safe Mouse,Logitech,Mouse,VID_046D&PID_C05A,SAFE,ALLOWED,Known peripheral",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    whitelist_file.write_text(
        json.dumps(
            [
                {
                    "hardware_id": "VID_046D&PID_C05A",
                    "vendor": "Logitech",
                    "product": "Mouse",
                }
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr("dashboard.app.LOG_PATH", str(log_file))
    monkeypatch.setattr("dashboard.app.WHITELIST_PATH", str(whitelist_file))

    response = client.get("/api/whitelist/candidates")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["total"] == 1
    assert payload["candidates"][0]["id"] == "VID_16C0&PID_27DB"


def test_attack_simulation_returns_structured_step_by_step_attack_flow(monkeypatch, client):
    """Verify that attack simulation endpoint returns properly structured attack flow with step-by-step details"""
    class Result:
        returncode = 0
        stdout = json.dumps(
            [
                {
                    "event": "Keystroke Injection",
                    "device": "Rubber Ducky Clone",
                    "vendor": "Hak5",
                    "product": "BadUSB Keyboard",
                    "id": "VID_16C0&PID_27DB",
                    "result": "UNTRUSTED",
                    "action": "BLOCKED",
                    "reason": "Rapid keystroke injection detected",
                }
            ]
        )

    monkeypatch.setattr("dashboard.app.subprocess.run", lambda *args, **kwargs: Result())

    response = client.post("/api/simulate_attack")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["success"] is True
    assert payload["steps"][0]["title"] == "Keystroke Injection"
    assert payload["steps"][0]["status"] == "BLOCKED"


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as test_client:
        yield test_client
