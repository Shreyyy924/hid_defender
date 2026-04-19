# 🛡️ HID Defender — USB Device Security Monitor

**Cross-Platform USB HID Detection & Prevention System**

A Python-based security application that detects suspicious USB Human Interface Devices (HIDs) like malicious keyboards and mice, logs untrusted connections, and responds to Rubber Ducky and Raspberry Pi Pico attacks.

---

## 📋 Table of Contents

- [Features](#features)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Dashboard](#dashboard)
- [Architecture](#architecture)
- [Development](#development)

---

## ✨ Features

### Core Detection Features

#### 1. **Real-Time USB Device Monitoring** ✅
- **Windows**: Real-time WMI-based event monitoring
- **macOS**: USB device polling (2-second intervals)
- **Linux**: USB device scanning
- Automatic baseline generation on first run

#### 2. **Trusted Device Whitelisting** ✅
- Maintain trusted device database (`data/trusted_devices.json`)
- Match devices by Vendor ID (VID) and Product ID (PID)
- Descriptive metadata (vendor name, device name)
- Interactive first-run setup

#### 3. **Attack Tool Detection** ✅
Pre-configured detection for common attack vectors:
- Raspberry Pi Pico (`VID_2E8A`)
- Adafruit boards (`VID_239A`)
- Arduino variants (`VID_2341`, `VID_16C0`)
- Teensy (`VID_16C0`)
- BadUSB/prototype boards (`VID_CAFE`, `VID_6666`)

#### 4. **Keystroke Speed Detection** ⚡
- Detects rapid, automated typing patterns
- **Normal human typing**: 5-10 keystrokes/sec
- **Alert threshold**: 15+ keystrokes/sec
- Requires `pynput` library

#### 5. **First Input Delay Detection** ⚡
- Detects devices typing within < 1 second of connection
- Indicates automated HID payload behavior
- Triggers immediate alert

#### 6. **Malicious Command Detection** ⚡
Detects risky command patterns in typed input:
- PowerShell commands (`powershell`, `pwsh`, `Get-Process`)
- Windows management (`cmd`, `taskkill`, `schtasks`)
- Registry modification (`reg add`, `reg delete`)
- Antivirus disabling (`Set-MpPreference`)
- Data exfiltration (`wget`, `curl`, `bitsadmin`)
- File system destruction (`del`, `rmdir`, `attrib`)

#### 7. **Device Disabling (Windows Admin)** ⚡
- Uses `pnputil /disable-device` with admin rights
- Automatically disables detected untrusted HIDs
- Requires administrator privileges

#### 8. **Workstation Locking** ✅
- Locks system when untrusted device detected
- Immediate response to threats
- Works on Windows and macOS

#### 9. **Comprehensive Audit Logging** ✅
CSV-style event log (`hid_alerts.log`) with:
- Timestamp
- Device information (name, vendor, product)
- Hardware ID
- Detection result (Trusted/Safe/Untrusted)
- Action taken (Allowed/Blocked/Disabled/Locked)
- Detection reason

#### 10. **Audio/Visual Alerts** ✅
Platform-specific notifications:
- **Windows**: Alert dialog + beep sound
- **macOS**: Native notification + sound
- **Linux**: `notify-send` notification + beep

#### 11. **Web Dashboard** ✅
Flask-based administrative interface:
- Real-time event monitoring
- Device status dashboard
- Alert history and statistics
- Interactive filtering and search
- Auto-refresh every 3 seconds
- Responsive design

#### 12. **Demo Mode** ⚡
Safe attack simulation for testing:
```bash
python -m hid_defender --demo
```
Simulates keystrokes, malicious commands, and alerts without blocking

---

## 📁 Project Structure

```
hid-defender/
├── src/hid_defender/              # Core application package
│   ├── __init__.py                # Package initialization
│   ├── __main__.py                # Entry point for python -m
│   ├── cli.py                     # Command-line interface
│   ├── alert_system.py            # Alert generation & notifications
│   ├── config.py                  # Configuration constants
│   ├── device_monitor.py          # USB/HID device detection
│   ├── device_validator.py        # Whitelist validation logic
│   ├── keystroke_monitor.py       # Keystroke analysis
│   └── logging_setup.py           # Audit logging configuration
│
├── tests/                          # Comprehensive test suite
│   ├── conftest.py                # Pytest configuration
│   ├── test_system_startup.py     # Startup tests
│   ├── test_device_detection.py   # Device detection tests
│   ├── test_alerts.py             # Alert system tests
│   ├── test_keystroke_monitoring.py # Keystroke analysis tests
│   ├── test_logging.py            # Logging tests
│   └── test_integration.py        # End-to-end integration tests
│
├── dashboard/                      # Flask web dashboard
│   ├── app.py                     # Flask application & API endpoints
│   ├── static/
│   │   ├── styles.css             # Dashboard styling (with animations)
│   │   └── dashboard.js           # Real-time update engine
│   └── templates/
│       ├── index.html             # Main dashboard interface
│       └── layout.html            # Base HTML template
│
├── docs/                           # Documentation
│   ├── FEATURES.md                # Feature descriptions
│   └── (README content now in root README.md)
│
├── data/                           # Data files
│   └── trusted_devices.json       # Runtime whitelist (auto-generated)
│
├── .git/                           # Git repository
├── .venv/                          # Virtual environment (gitignored)
├── .gitignore                      # Git ignore rules
├── pyproject.toml                  # Project configuration & dependencies
├── README.md                       # This file (main documentation)
├── DASHBOARD_IMPLEMENTATION.md     # Technical dashboard guide (for developers)
├── CLEANUP_AUDIT_REPORT.md         # Project cleanup audit findings
└── PROJECT_STRUCTURE.md            # (Deprecated - see this README)
```

---

## 🚀 Installation

### Prerequisites
- Python 3.8+
- pip or conda
- macOS/Windows/Linux

### Basic Setup

1. **Clone the repository**:
```bash
cd /Users/veel/Downloads/hid-defender
```

2. **Create virtual environment** (recommended):
```bash
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

3. **Install dependencies**:
```bash
# Core dependencies
pip install -e .

# With development tools (testing, linting, formatting)
pip install -e ".[dev]"

# Or just testing dependencies
pip install -e ".[test]"
```

### Optional: Keystroke Monitoring
If `pynput` installation fails, install separately:
```bash
pip install pynput
```

---

## ⚡ Quick Start

### 1. Start Monitoring
```bash
# Monitor for suspicious HID devices
python -m hid_defender --monitor
```

### 2. Start Dashboard
```bash
# Launch web dashboard on port 5001
python -m hid_defender --dashboard

# Or specify custom port
python -m hid_defender --dashboard --port 8080
```

Visit: **http://localhost:5001**

### 3. Initial Setup
```bash
# Generate baseline whitelist from current devices
python -m hid_defender --setup
```

### 4. Demo Mode
```bash
# Simulate attack scenarios
python -m hid_defender --demo
```

### 5. Run Tests
```bash
# Run full test suite with coverage
pytest

# Or just tests without coverage
pytest --no-cov
```

---

## 🖥️ Dashboard Guide

### Features

**Real-Time Monitoring**:
- Auto-refresh every 3 seconds
- Manual refresh button
- Toggle auto-refresh on/off
- Live clock with update counter

**Event Monitoring**:
- Summary statistics (total events, trusted, safe, untrusted)
- Alert panel with latest untrusted devices
- Activity logs
- Device monitoring grid
- Detailed events table

**Interactive Filtering**:
- Search events by device name, vendor, or reason
- Filter by result type (Trusted/Safe/Untrusted)
- Live filtering without page reload

**Visual Feedback**:
- Smooth animations on updates
- Status indicators (green = active)
- Color-coded results
- Pulse effect for alerts
- Highlight effect on stat changes

**Statistics**:
- Last event timestamp
- Unique device count
- Average event interval
- Top alert reasons
- Trusted device list

### URL
```
http://localhost:5001
```

### Buttons & Controls
- 🔄 **Refresh** - Fetch all data immediately
- ⏸ **Auto-Refresh Toggle** - Enable/disable 3-second updates
- 🔍 **Event Filter** - Search events
- **Result Filter** - Filter by type

For detailed implementation information, see [DASHBOARD_IMPLEMENTATION.md](DASHBOARD_IMPLEMENTATION.md).

---

## 🏗️ Architecture

### Data Flow

```
USB HID Device Connected
    ↓
Device Monitor
    ↓
Parse Device (VID, PID, name)
    ↓
Validation Engine
    ├─ Check whitelist
    ├─ Check attack VIDs
    ├─ Evaluate risk score
    └─ Classify: TRUSTED / SAFE / UNTRUSTED
    ↓
Response Engine
    ├─ If UNTRUSTED:
    │   ├─ Alert sound
    │   ├─ Lock workstation
    │   ├─ Disable device (if admin)
    │   └─ Log event
    └─ If TRUSTED/SAFE:
        └─ Log event (silent)
    ↓
Event Log & Dashboard Updated
```

### Key Modules

**`device_monitor.py`**: Platform-specific USB device detection
**`device_validator.py`**: Whitelist matching and risk evaluation
**`keystroke_monitor.py`**: Keystroke speed and pattern detection
**`alert_system.py`**: Alert generation and device disabling
**`config.py`**: Configuration constants and attack vectors
**`logging_setup.py`**: Audit log formatting

---

## 🛠️ Development

### Running Tests

```bash
# Run all tests with coverage
pytest

# Run specific test file
pytest tests/test_alerts.py

# Run with verbose output
pytest -v

# Run and show print statements
pytest -s
```

### Code Quality

**Linting**:
```bash
flake8 src/ tests/
```

**Type Checking**:
```bash
mypy src/
```

**Code Formatting**:
```bash
black src/ tests/ dashboard/
```

### Project Configuration

All configuration is in `pyproject.toml`:
- Dependencies
- Test settings
- Tool configurations (black, mypy, pytest)
- Build system
- Entry points

---

## 📊 Event Log Format

Events are logged to `hid_alerts.log` in CSV format:

| Time | Device | Vendor | Product | ID | Result | Action | Reason |
|------|--------|--------|---------|----|---------|---------|------------|
| 2024-01-15 14:23:45 | Mouse | Logitech | USB Receiver | 046D:C52B | TRUSTED | ALLOWED | Known Device |
| 2024-01-15 14:25:10 | USB Keyboard | Unknown | Unknown | 2E8A:0003 | UNTRUSTED | DISABLED | Attack Vector (Raspberry Pi) |

---

## ⚙️ Configuration

Edit `src/hid_defender/config.py` to customize:
- `KEYSTROKE_THRESHOLD` - Detect keystrokes/sec threshold
- `ATTACK_VECTORS` - Suspicious hardware IDs
- `MALICIOUS_PATTERNS` - Command patterns to detect
- `LOG_PATH` - Audit log location
- `WHITELIST_PATH` - Trusted devices file

---

## 🔒 Security Considerations

- ✅ Runs as background service
- ✅ Requires admin for device disabling (Windows)
- ✅ All events logged and timestamped
- ✅ Whitelisting prevents false positives
- ✅ No external network calls
- ✅ Open source for transparency

---

## 📝 Logging

### Console Output
```
[+] Running on Windows - Real-time WMI monitoring enabled
[+] Keystroke monitoring enabled
Loaded 5 trusted HID devices from whitelist.
[!] UNTRUSTED DEVICE DETECTED: 2E8A:0003
[+] Locking workstation...
[+] Disabling hardware: 2E8A:0003
```

### Audit Log (`hid_alerts.log`)
CSV format with columns: Time, Device, Vendor, Product, ID, Result, Action, Reason

---

## 🐛 Troubleshooting

### Dashboard Not Updating
1. Check browser console (F12) for errors
2. Verify Flask app running: `http://localhost:5001/api/stats`
3. Check if log file exists at configured LOG_PATH

### Keystroke Monitoring Not Working
- Verify `pynput` installed: `pip list | grep pynput`
- Some systems require additional permissions
- Check console for warning messages

### Device Not Detected
1. Run `--setup` to generate baseline
2. Check that device is actually HID (keyboard/mouse)
3. Some virtual devices may not be detected
4. Check `hid_alerts.log` for events

### Admin/Permission Issues (Windows)
- Right-click Python and "Run as Administrator"
- Or use admin command prompt

---

## 📚 Additional Resources

- [DASHBOARD_IMPLEMENTATION.md](DASHBOARD_IMPLEMENTATION.md) - Technical deep-dive for developers
- [CLEANUP_AUDIT_REPORT.md](CLEANUP_AUDIT_REPORT.md) - Project cleanup and optimization report
- [docs/FEATURES.md](docs/FEATURES.md) - Detailed feature descriptions

---

## 📄 License

MIT License - See repository for details

---

## 👥 Project Team

**Final Year Cybersecurity Project**

Comprehensive USB HID security solution with:
- Real-time detection
- Multi-platform support  
- Keystroke analysis
- Web dashboard
- Comprehensive testing
- Production-ready code

---

**Last Updated**: April 19, 2026  
**Status**: ✅ Production Ready
