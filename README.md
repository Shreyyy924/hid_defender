# 🛡️ HID Defender — USB HID Defense for Final Year Project

**Cybersecurity Final Year Project — Windows HID defense module**

A Python-based project that detects suspicious USB Human Interface Devices (HID) on Windows, logs untrusted connections, and responds to potential Rubber Ducky / Raspberry Pi Pico HID attacks.

---

## 📁 Project Structure

```
hid-defender/
├── hid_defender.py              ← Main application entrypoint
├── trusted_devices.json         ← Whitelist of trusted HID devices
├── trusted_devices_example.json ← Example whitelist file
├── requirements.txt             ← Python dependency list
├── hid_alerts.log               ← Generated event log (CSV style)
├── README.md                    ← Project documentation
└── src/
    ├── alert_system.py          ← Alert + lock-screen helpers
    ├── config.py                ← Constants and platform detection
    ├── device_monitor.py        ← USB/HID device discovery helpers
    ├── device_validator.py      ← Whitelist + evaluation logic
    ├── keystroke_monitor.py     ← Keystroke and command detection
    └── logging_setup.py         ← Logger / audit log formatter
```

---

## ⚙️ Architecture Overview

This project is designed for a Windows-focused lab demonstration, with fallback paths for macOS/Linux.

```
USB HID device connected
        │
        ▼
  main_windows() / main_macos() / main_linux()
        │
        ▼
  run_baseline_setup() loads or creates trusted whitelist
        │
        ▼
  new device arrives → parse_device()
        │
        ▼
  evaluate() checks:
      • whitelist VID/PID
      • known suspicious VID blacklist
      • trusted brand heuristics
      • unknown HID device
        │
       / \
      /   \
 TRUSTED   UNTRUSTED
   │           │
   │        log_event(..., reason)
   │        show_alert()
   │        optional kill_device()
   │        keystroke_mon tracks first-input delay
```

---

## ✅ What the system does

- **HID Whitelist**
  - Uses normalized `VID_xxxx&PID_xxxx` IDs for trusted devices
  - Stores trusted devices in `trusted_devices.json`
  - Treats unknown HID devices as suspicious by default

- **Windows USB Monitoring**
  - Uses `wmi` and `pythoncom` on Windows to watch `Win32_PnPEntity` creation events
  - Filters new devices to HID-like keyboard / input devices

- **Detection + Response**
  - Logs every new HID event
  - Alerts the user for untrusted devices
  - Attempts to disable the device with `pnputil /disable-device` if running as Admin

- **Keystroke Behavior Analysis**
  - Detects fast typing above `KEYSTROKE_THRESHOLD`
  - Flags first input delay when suspicious device input starts unusually quickly
  - Recognizes suspicious typing patterns like PowerShell and command keywords

- **Malicious Command Detection**
  - Detects patterns such as `powershell`, `wget`, `curl`, `reg add`, `Get-Process`, `Stop-Service`
  - Creates alerts when these patterns appear in keystrokes

- **Logging System**
  - Writes a CSV-style audit log to `hid_alerts.log`
  - Includes `Time`, `Device`, `Vendor`, `Product`, `ID`, `Result`, `Action`, `Reason`

---

## 🔧 Installation

### 1. Install Python dependencies

```bash
python3 -m pip install -r requirements.txt
```

### 2. Windows-specific dependency

On Windows, install:

```bash
python3 -m pip install wmi pypiwin32
```

> If you are on macOS or Linux, the `wmi` package will not install properly and the Windows monitoring path will not run.

---

## ▶️ Running the tool

### Demo mode

```bash
python3 hid_defender.py --demo
```

This runs a built-in attack simulation that shows:
- fast keystroke injection detection
- malicious command pattern detection
- first-input delay explanation

### Real monitoring mode on Windows

```bash
python3 hid_defender.py
```

The script will:
- start USB/HID monitoring
- load the trusted whitelist
- watch for new HID device events
- log and alert when an unknown device connects

---

## 📋 Whitelist format

Use `trusted_devices.json` to define trusted keyboards.

Example format:

```json
[
  {
    "hardware_id": "VID_046D&PID_C52B",
    "vendor": "Logitech",
    "name": "Logitech USB Keyboard"
  },
  {
    "hardware_id": "VID_1B1C&PID_1BAC",
    "vendor": "Standard system devices",
    "name": "USB Input Device"
  }
]
```

- The script normalizes hardware IDs to `VID_xxxx&PID_xxxx`
- For Windows, it extracts this from `PNPDeviceID`
- Add a trusted device entry before demoing the whitelist behavior

---

## 🧠 Code map

| File | Purpose |
|---|---|
| `hid_defender.py` | Main app + platform-specific monitoring loops |
| `src/config.py` | Platform flags, paths, thresholds, malicious patterns |
| `src/device_monitor.py` | Windows and macOS USB/HID parsing helpers |
| `src/device_validator.py` | Whitelist loading, normalization, suspicious evaluation |
| `src/keystroke_monitor.py` | Keystroke speed, first-input delay, command detection |
| `src/logging_setup.py` | Console + audit log formatting |
| `src/alert_system.py` | Alert sound, popup, and workstation lock helpers |

---

## 🧪 Demo & validation steps

1. Add your trusted keyboard to `trusted_devices.json`.
2. Run `python3 hid_defender.py --demo` to verify core detection logic.
3. On Windows, plug in a Raspberry Pi Pico as HID and watch for alerts.
4. Inspect `hid_alerts.log` to confirm logged `UNTRUSTED` events and reasons.

---

## 🎓 Notes for the final year project

- This implementation is designed for a controlled lab demo.
- The real defense is in detection, logging, and alerting.
- Blocking via `pnputil` is optional and only works with Admin privileges on Windows.
- If `wmi` cannot be installed, the code still runs in demo mode.

---

## 📜 Example log output

```
2026-04-15 18:24:14,Logitech USB Keyboard,Logitech,Keyboard,VID_046D&PID_C52B,TRUSTED,ALLOWED,Whitelisted device
2026-04-15 18:24:20,Unknown Device,Unknown,Keyboard,VID_239A&PID_XXXX,UNTRUSTED,BLOCKED,Unknown HID device
```

*Use this file when presenting your project to show clear detection and audit trails.*
