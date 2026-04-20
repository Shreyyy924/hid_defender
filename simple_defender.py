import wmi
import time
import json
import csv
import threading
import sys
import os
from datetime import datetime
from pynput import keyboard
from colorama import Fore, Style, init

# Initialize Colorama for pretty console output
init(autoreset=True)

# --- CONFIGURATION ---
WHITELIST_FILE = "whitelist.json"
LOG_FILE = "hid_alerts.csv"
KEYSTROKE_THRESHOLD = 15.0  # Keystrokes per second
FIRST_INPUT_DELAY_THRESHOLD = 1.5  # Seconds
MALICIOUS_PATTERNS = [
    "powershell", "pwsh", "cmd.exe", "reg add", "taskkill", 
    "wmic", "wget", "curl", "bitsadmin", "net user", "del ", "rmdir",
    "Set-MpPreference" # Often used to disable Windows Defender
]

# --- STATE MANAGEMENT ---
trusted_devices = []
keystroke_times = []
command_buffer = ""
pending_device = None
pending_device_time = 0

# --- HELPERS ---
def log_event(device_name, vid_pid, action, reason):
    """Logs the event to a CSV file for the project demo."""
    file_exists = os.path.isfile(LOG_FILE)
    with open(LOG_FILE, mode='a', newline='') as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(["Timestamp", "Device Name", "VID_PID", "Action", "Reason"])
        writer.writerow([datetime.now().strftime("%Y-%m-%d %H:%M:%S"), device_name, vid_pid, action, reason])

def play_alert():
    """Trigger a simple sound alert."""
    try:
        import winsound
        winsound.Beep(1000, 500)
    except:
        pass

def lock_workstation():
    """Lock the computer logic for demo."""
    import ctypes
    ctypes.windll.user32.LockWorkStation()

def load_whitelist():
    """Load the trusted VID/PID list from JSON."""
    global trusted_devices
    if os.path.exists(WHITELIST_FILE):
        with open(WHITELIST_FILE, 'r') as f:
            trusted_devices = json.load(f)
    else:
        # Default empty whitelist
        with open(WHITELIST_FILE, 'w') as f:
            json.dump([], f)
        trusted_devices = []

# --- KEYSTROKE MONITORING ---
def on_press(key):
    global keystroke_times, command_buffer, pending_device, pending_device_time

    now = time.time()
    
    # 1. First Input Delay Detection
    if pending_device and pending_device_time > 0:
        delay = now - pending_device_time
        if delay < FIRST_INPUT_DELAY_THRESHOLD:
            print(f"{Fore.RED}[!] ALERT: First input delay too short ({delay:.2f}s)!")
            log_event(pending_device['name'], pending_device['id'], "Flagged", "Critical: Input started < 1.5s after connection")
            play_alert()
        pending_device = None
        pending_device_time = 0

    # 2. Keystroke Speed Analysis
    keystroke_times.append(now)
    # Keep only keystrokes from the last 1 second
    keystroke_times = [t for t in keystroke_times if now - t <= 1.0]
    
    if len(keystroke_times) > KEYSTROKE_THRESHOLD:
        print(f"{Fore.RED}[!] ALERT: Suspicious typing speed detected ({len(keystroke_times)} keys/sec)!")
        log_event("Global Monitor", "N/A", "Alert", f"High typing speed: {len(keystroke_times)} keys/sec")
        play_alert()

    # 3. Malicious Command Detection
    try:
        char = key.char.lower()
        command_buffer += char
        if len(command_buffer) > 100: command_buffer = command_buffer[-100:]
        
        for pattern in MALICIOUS_PATTERNS:
            if pattern in command_buffer:
                print(f"{Fore.RED}[!] ALERT: Malicious command pattern detected: '{pattern}'")
                log_event("Global Monitor", "N/A", "Alert", f"Malicious pattern: {pattern}")
                command_buffer = "" # Clear buffer after detection
                play_alert()
    except AttributeError:
        # Handle special keys (enter, space, etc.)
        if key == keyboard.Key.enter:
            command_buffer = ""
        elif key == keyboard.Key.space:
            command_buffer += " "

# --- USB DEVICE MONITORING ---
def device_monitor():
    """Main loop for monitoring USB HID connections via WMI."""
    global pending_device, pending_device_time
    c = wmi.WMI()
    
    # Watch for 'Creation' events on Win32_PnPEntity
    watcher = c.watch_for(
        notification_type="Creation",
        wmi_class="Win32_PnPEntity",
        delay_secs=1
    )
    
    print(f"{Fore.CYAN}[+] Monitoring USB HID devices in real-time...")
    
    while True:
        try:
            device = watcher()
            desc = str(device.Description).lower()
            hw_id = str(device.PNPDeviceID)

            # Filter for HID-related devices
            if "hid" in desc or "keyboard" in desc or "mouse" in desc:
                print(f"{Fore.YELLOW}[*] Device Connected: {device.Name}")
                
                # Whitelist Check
                is_trusted = False
                for trusted in trusted_devices:
                    if trusted['id'] in hw_id:
                        is_trusted = True
                        break
                
                if is_trusted:
                    print(f"{Fore.GREEN}[v] Device Trusted (Whitelisted). Access Granted.")
                    log_event(device.Name, hw_id, "Allowed", "Whitelisted")
                else:
                    print(f"{Fore.RED}[!] ALERT: Unknown/Untrusted HID Device Connected!")
                    log_event(device.Name, hw_id, "Alert", "Untrusted Device")
                    
                    # Track for first-input delay analysis
                    pending_device = {'name': device.Name, 'id': hw_id}
                    pending_device_time = time.time()
                    
                    play_alert()
                    # Uncomment below to actually lock the PC in demo
                    # lock_workstation()

        except Exception as e:
            pass

# --- MAIN EXECUTION ---
if __name__ == "__main__":
    print(f"{Fore.MAGENTA}{Style.BRIGHT}==========================================")
    print(f"{Fore.MAGENTA}{Style.BRIGHT}    HID DEFENDER - STUDENT PROJECT        ")
    print(f"{Fore.MAGENTA}{Style.BRIGHT}==========================================")

    load_whitelist()
    print(f"{Fore.BLUE}[i] Loaded {len(trusted_devices)} trusted devices.")
    
    # Start Keyboard listener thread
    listener = keyboard.Listener(on_press=on_press)
    listener.start()
    print(f"{Fore.CYAN}[+] Keyboard behavior analysis active.")

    # Run USB Monitor in main thread
    try:
        device_monitor()
    except KeyboardInterrupt:
        print(f"\n{Fore.WHITE}Stopping HID Defender...")
        sys.exit(0)
