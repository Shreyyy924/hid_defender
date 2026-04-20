# Project Guide: HID Defender (Student Edition)

This guide explains the design and usage of the HID Defense module for your final year project.

## 🏗️ Architecture Design
The system follows an event-driven model aimed at detecting and neutralizing HID-based attacks (Rubber Ducky, Raspberry Pi Pico).

1.  **USB Discovery Layer**: Uses Windows Management Instrumentation (WMI) to listen for `__InstanceCreationEvent` notifications when a new PNP device (keyboard/mouse) is plugged in.
2.  **Validation Layer**: Extracts the Hardware ID (VID/PID) and compares it against `whitelist.json`.
3.  **Behavioral Layer**: If a device is unknown, the system starts monitoring its keystroke behavior using a low-level keyboard hook (`pynput`).
4.  **Enforcement Layer**: If thresholds are exceeded (speed, delay, patterns), system alerts are triggered (sound, console warnings, or workstation locking).

## 📂 File Structure
- `simple_defender.py`: The core logic and main execution script.
- `whitelist.json`: Data file containing trusted device profiles.
- `hid_alerts.csv`: Audit logs for demonstration and reporting.

## ⚙️ Key Requirements & Libraries
- **Language**: Python 3.8+
- **`wmi`**: For real-time Windows hardware monitoring.
- **`pynput`**: For non-intrusive keystroke analysis.
- **`colorama`**: For clear, color-coded console output during the demo.

## 🧪 Demo Scenarios

### Scenario 1: Whitelist Protection (Safe Device)
1.  Add your current keyboard's VID/PID to `whitelist.json`.
2.  Run `python simple_defender.py`.
3.  Plug in the keyboard.
4.  **Result**: Console shows "[v] Device Trusted".

### Scenario 2: Keystroke Speed Attack
1.  Run the defender.
2.  Plug in an untrusted device (or simulate one).
3.  Use a script or type extremely fast (15+ keys/sec).
4.  **Result**: Console triggers "[!] ALERT: Suspicious typing speed detected".

### Scenario 3: First Input Delay
1.  Run the defender.
2.  Plug in a device that immediately types a command (e.g., within 0.5 seconds).
3.  **Result**: Console triggers "[!] ALERT: First input delay too short".

### Scenario 4: Command Detection
1.  Type "powershell" or "Invoke-WebRequest".
2.  **Result**: Console triggers "[!] ALERT: Malicious command pattern detected".

## 🛡️ Real vs Simulated for Demo
| Feature | Implementation | Demo Tip |
| :--- | :--- | :--- |
| **USB Monitoring** | **Real** (WMI) | Plug in any real USB device to show the discovery loop. |
| **Whitelisting** | **Real** (JSON) | Toggle IDs in the JSON file to show "Trusted" vs "Untrusted" states. |
| **Keystroke Speed** | **Real** (`pynput`) | Use a small Python script to simulate typing 20 characters in 0.1s. |
| **Blocking** | **Simulated/Real** | You can call `LockWorkStation()` for a dramatic "Real" block effect. |
