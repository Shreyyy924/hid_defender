# ==========================================
# Keystroke Monitoring Module
# ==========================================

import time
import io
import contextlib
from collections import deque
from .config import IS_MACOS, IS_WINDOWS, KEYSTROKE_THRESHOLD, FIRST_INPUT_DELAY_THRESHOLD, MALICIOUS_PATTERNS

# Keystroke monitoring
try:
    from pynput import keyboard
    PYNPUT_AVAILABLE = True
except ImportError:
    PYNPUT_AVAILABLE = False


class KeystrokeMonitor:
    """Monitors keystroke patterns to detect automated attacks."""
    
    def __init__(self, logger):
        self.logger = logger
        self.keystroke_times = deque(maxlen=20)  # Keep last 20 keystrokes
        self.is_monitoring = False
        self.listener = None
        self.blocked_devices = set()
        self.command_buffer = ""
        self.pending_device = None
        self.pending_device_time = None
        self.ctrl_pressed = False
        self.cmd_pressed = False
        
    def register_device_connection(self, device_info):
        """Track a newly detected suspicious device for first-input delay analysis."""
        self.pending_device = device_info
        self.pending_device_time = time.time()
        self.logger.info(
            f"Tracking suspicious device for first-input delay: {device_info['name']} ({device_info['id']})"
        )

    def clear_pending_device(self):
        self.pending_device = None
        self.pending_device_time = None

    def on_press(self, key):
        """Callback when a key is pressed."""
        try:
            now = time.time()
            self.keystroke_times.append(now)

            if self.pending_device and self.pending_device_time is not None:
                elapsed = now - self.pending_device_time
                if elapsed < FIRST_INPUT_DELAY_THRESHOLD:
                    self.logger.warning(
                        f"⚠️ FIRST INPUT DELAY: {elapsed:.2f}s after suspicious device connection"
                    )
                    self.trigger_input_delay_alert(elapsed)
                self.clear_pending_device()

            # Check keystroke speed
            if len(self.keystroke_times) >= 5:
                time_span = self.keystroke_times[-1] - self.keystroke_times[0]
                if time_span > 0:
                    keystroke_speed = len(self.keystroke_times) / time_span
                    if keystroke_speed > KEYSTROKE_THRESHOLD:
                        self.logger.warning(
                            f"⚠️ SUSPICIOUS KEYSTROKE SPEED: {keystroke_speed:.1f} keys/sec "
                            f"(threshold: {KEYSTROKE_THRESHOLD})"
                        )
                        self.trigger_keystroke_alert(keystroke_speed)

            # Track key combo and command text patterns
            if key in (keyboard.Key.ctrl_l, keyboard.Key.ctrl_r):
                self.ctrl_pressed = True
            elif key in (keyboard.Key.cmd, keyboard.Key.cmd_l, keyboard.Key.cmd_r):
                self.cmd_pressed = True
            elif hasattr(key, 'char') and key.char:
                self.check_command_patterns(key.char.lower())
            elif key == keyboard.Key.enter:
                self.command_buffer += ' '
            elif key == keyboard.Key.space:
                self.command_buffer += ' '
        except AttributeError:
            pass

    def on_release(self, key):
        """Callback when a key is released."""
        if key in (keyboard.Key.ctrl_l, keyboard.Key.ctrl_r):
            self.ctrl_pressed = False
        elif key in (keyboard.Key.cmd, keyboard.Key.cmd_l, keyboard.Key.cmd_r):
            self.cmd_pressed = False

    def check_command_patterns(self, char):
        """Detect malicious command patterns in typed input."""
        self.command_buffer += char
        if len(self.command_buffer) > 300:
            self.command_buffer = self.command_buffer[-300:]

        if self.ctrl_pressed and char == 'r':
            self.logger.warning("⚠️ Suspicious launcher combo detected: Ctrl/Win + R")
            self.trigger_command_alert("win+r")
            self.command_buffer = ""
            return

        for pattern in MALICIOUS_PATTERNS:
            if pattern.lower() in self.command_buffer:
                self.logger.warning(f"⚠️ Malicious command pattern detected: {pattern}")
                self.trigger_command_alert(pattern)
                self.command_buffer = ""
                return

    def trigger_input_delay_alert(self, delay_seconds):
        """Raise an alert for first-input timing that is too fast."""
        msg = f"Automated HID device input started too quickly: {delay_seconds:.2f}s"
        self.logger.error(msg)
        if IS_WINDOWS:
            try:
                import winsound
                winsound.Beep(1200, 200)
            except:
                pass

    def trigger_command_alert(self, pattern):
        """Alert for suspicious command content detected in keystrokes."""
        msg = f"Malicious command signature detected: {pattern}"
        self.logger.error(msg)
        if IS_WINDOWS:
            try:
                import winsound
                winsound.Beep(1000, 200)
                winsound.Beep(1000, 200)
            except:
                pass

    def trigger_keystroke_alert(self, speed):
        """Alert when suspicious keystroke speed detected."""
        msg = f"Automated keystroke attack detected: {speed:.1f} keys/sec"
        self.logger.error(msg)
        
        # Play alert sound
        if IS_WINDOWS:
            try:
                import winsound
                winsound.Beep(1200, 200)
                winsound.Beep(1200, 200)
            except:
                pass
    
    def start(self):
        """Start monitoring keystrokes."""
        if not PYNPUT_AVAILABLE:
            self.logger.warning("Keystroke monitoring requires pynput. Install with: pip install pynput")
            return
            
        if self.is_monitoring:
            return
        
        try:
            self.is_monitoring = True
            
            # On macOS, suppress stderr to hide permission warnings, then provide our own message
            if IS_MACOS:
                # Try to start with stderr suppressed
                with contextlib.redirect_stderr(io.StringIO()) as stderr_capture:
                    self.listener = keyboard.Listener(
                        on_press=self.on_press, 
                        on_release=self.on_release
                    )
                    self.listener.start()
                    time.sleep(0.1)  # Brief moment for listener to initialize
                
                # Check if the listener is working
                stderr_output = stderr_capture.getvalue()
                if "not trusted" in stderr_output.lower() or not self.listener.is_alive():
                    self.is_monitoring = False
                    self.listener = None
                    self.logger.warning("⚠️  Keystroke monitoring disabled - requires accessibility permissions")
                    self.logger.warning("   On macOS, grant access via: System Preferences → Privacy & Security → Accessibility")
                    self.logger.warning("   Add your Terminal or Python to the list, then restart this script")
                    self.logger.warning("   → Continuing with USB device monitoring only")
                    return
                else:
                    self.logger.info("Keystroke monitoring started")
            else:
                self.listener = keyboard.Listener(
                    on_press=self.on_press, 
                    on_release=self.on_release
                )
                self.listener.start()
                self.logger.info("Keystroke monitoring started")
                
        except Exception as e:
            self.is_monitoring = False
            self.listener = None
            self.logger.warning(f"Failed to start keystroke monitoring: {e}")
            self.logger.warning("→ Continuing with USB device monitoring only")
    
    def stop(self):
        """Stop monitoring keystrokes."""
        if self.listener and self.is_monitoring:
            self.listener.stop()
            self.is_monitoring = False
            self.logger.info("Keystroke monitoring stopped")
