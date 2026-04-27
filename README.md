# HID Defender

**HID Defender** is a cross-platform security monitoring system designed to detect and neutralize malicious USB HID (Human Interface Device) attacks, such as those from BadUSB, Rubber Ducky, or Raspberry Pi Pico.

---

## 🚀 Quick Start

The easiest way to run HID Defender is using the `run.py` launcher at the root of the repository.

### 1. Start the Dashboard
Visualize system events and security alerts in a modern web interface.
```bash
python3 run.py --dashboard
```
Open your browser to: `http://localhost:8888`

### 2. Start the Monitor
Run the core security engine in your terminal to monitor for suspicious devices.
```bash
python3 run.py --monitor
```

---

## 📂 Project Structure

- **`src/hid_defender/`**: The core security engine and logic.
- **`src/hid_defender/dashboard/`**: The web-based event monitor.
- **`data/`**: Storage for trusted devices and audit logs.
- **`docs/`**: Detailed project documentation and architecture guides.
- **`scripts/`**: Helper scripts for attack simulation and testing.
- **`tests/`**: Comprehensive test suite for system verification.

---

## 🛡️ Key Features

- **Real-time Monitoring**: Detects unauthorized HID connections instantly.
- **Heuristic Analysis**: Identifies suspicious device behavior and rapid keystroke patterns.
- **Automated Response**: Automatically locks the workstation and ejects malicious devices.
- **Trusted Whitelisting**: Easy management of authorized hardware.
- **Integrated Dashboard**: Real-time stats, event history, and interactive test runner.

---

## 📖 Documentation
For a deep dive into the architecture and demo scenarios, please refer to the **[Project Guide](docs/project_guide.md)**.
