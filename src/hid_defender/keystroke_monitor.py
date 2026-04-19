# ==========================================
# Keystroke Monitoring Module
# ==========================================

import time
import io
import contextlib
import logging
from collections import deque
from typing import Optional, Any, List, Dict

# Handle both package imports and standalone execution
try:
    from .config import IS_MACOS, IS_WINDOWS, KEYSTROKE_THRESHOLD, FIRST_INPUT_DELAY_THRESHOLD, MALICIOUS_PATTERNS
except ImportError:
    from config import IS_MACOS, IS_WINDOWS, KEYSTROKE_THRESHOLD, FIRST_INPUT_DELAY_THRESHOLD, MALICIOUS_PATTERNS

# Keystroke monitoring
try:
    import pynput
    from pynput import keyboard
    PYNPUT_AVAILABLE = True
except ImportError:
    pynput = None
    keyboard = None
    PYNPUT_AVAILABLE = False

# Windows sound support
try:
    import winsound
except ImportError:
    winsound = None


class KeystrokeMonitor:
    """Monitors keystroke patterns to detect automated attacks."""
    
    def __init__(self, logger: Optional[logging.Logger] = None) -> None:
        """Initialize the keystroke monitor.
        
        Args:
            logger: Optional logger instance. If None, creates a new logger.
        """
        # delayed import to avoid circular import at module load
        if logger is None:
            try:
                from .logging_setup import init_logger
                logger = init_logger()
            except Exception:
                logger = logging.getLogger('hid_defender.keystroke')
        self.logger = logger
        self.keystroke_times: deque = deque(maxlen=20)  # Keep last 20 keystrokes
        self.rapid_typing_detected: bool = False
        self.keystroke_count: int = 0
        try:
            from .config import KEYSTROKE_THRESHOLD
            self.threshold: float = float(KEYSTROKE_THRESHOLD)
        except ImportError:
            self.threshold: float = 100.0  # Fallback threshold
        self.last_reset_time: float = time.time()
        self.reset_window: float = 1.0
        self.speed_exceed_streak: int = 0
        self.required_streak: int = 4
        self.is_monitoring: bool = False
        self.listener: Optional[Any] = None
        self.blocked_devices: set = set()
        self.command_buffer: str = ""
        self.pending_device: Optional[Dict[str, Any]] = None
        self.pending_device_time: Optional[float] = None
        self.ctrl_pressed: bool = False
        self.cmd_pressed: bool = False
        
        # If running on macOS and pynput is available, auto-start monitoring
        if PYNPUT_AVAILABLE and IS_MACOS:
            try:
                self.start()
            except Exception as e:
                # squelch startup errors during unit tests
                self.logger.debug(f"Auto-start failed: {e}")
        
    def register_device_connection(self, device_info: Dict[str, Any]) -> None:
        """Track a newly detected suspicious device for first-input delay analysis.
        
        Args:
            device_info: Device information dict with 'name' and 'id' keys
        """
        self.pending_device = device_info
        self.pending_device_time = time.time()

        name = device_info.get("name", "Unknown Device")
        device_id = device_info.get("id", "Unknown ID")

        self.logger.info(
            f"Tracking suspicious device for first-input delay: {name} ({device_id})"
        )

    def clear_pending_device(self) -> None:
        """Clear the pending device tracking state."""
        self.pending_device = None
        self.pending_device_time = None

    def on_press(self, key: Any) -> None:
        """Callback when a key is pressed.
        
        Args:
            key: The key pressed (from pynput.keyboard)
        """
        if not PYNPUT_AVAILABLE or keyboard is None:
            return
            
        try:
            now = time.time()
            # reset if long inactivity since last_reset_time
            if now - self.last_reset_time > getattr(self, 'reset_window', 1.0):
                self.keystroke_times.clear()
                self.keystroke_count = 0

            # store the keystroke timestamp
            self.keystroke_times.append(now)

            # keystroke count reflects recent activity (updated further below)

            if self.pending_device and self.pending_device_time is not None:
                elapsed = now - self.pending_device_time
                if elapsed < FIRST_INPUT_DELAY_THRESHOLD:
                    self.logger.warning(
                        f"⚠️ FIRST INPUT DELAY: {elapsed:.2f}s after suspicious device connection"
                    )
                    self.trigger_input_delay_alert(elapsed)
                self.clear_pending_device()

            # Check keystroke speed
            # compute instantaneous keys/sec over recent window to avoid
            # treating small intra-word bursts as automated typing
            window = 0.5
            cutoff = now - window
            recent = [t for t in self.keystroke_times if t >= cutoff]
            if len(recent) >= 3:
                keystroke_speed = len(recent) / window
                # compute contiguous recent keystrokes (small inter-key gaps)
                contiguous_gap = 0.05
                contiguous_count = 1
                for i in range(len(self.keystroke_times) - 1, 0, -1):
                    try:
                        if self.keystroke_times[i] - self.keystroke_times[i - 1] <= contiguous_gap:
                            contiguous_count += 1
                        else:
                            break
                    except Exception:
                        break
                self.keystroke_count = contiguous_count
                if keystroke_speed > KEYSTROKE_THRESHOLD:
                    # ensure the high speed is continuous (no long gaps)
                    diffs = [recent[i] - recent[i - 1] for i in range(1, len(recent))]
                    contiguous = all(d <= 0.05 for d in diffs)
                    if contiguous:
                        self.speed_exceed_streak += 1
                        if self.speed_exceed_streak >= getattr(self, 'required_streak', 4):
                            self.logger.warning(
                                f"⚠️ SUSPICIOUS KEYSTROKE SPEED: {keystroke_speed:.1f} keys/sec "
                                f"(threshold: {KEYSTROKE_THRESHOLD})"
                            )
                            self.trigger_keystroke_alert(keystroke_speed)
                    else:
                        # not a continuous high-speed sequence; reset streak
                        self.speed_exceed_streak = 0
                else:
                    self.speed_exceed_streak = 0
                    self.rapid_typing_detected = False

            # Track key combo and command text patterns
            if key in (keyboard.Key.ctrl_l, keyboard.Key.ctrl_r):
                self.ctrl_pressed = True
            elif hasattr(keyboard.Key, "cmd") and key == keyboard.Key.cmd:
                self.cmd_pressed = True
            elif hasattr(keyboard.Key, "cmd_l") and key == keyboard.Key.cmd_l:
                self.cmd_pressed = True
            elif hasattr(keyboard.Key, "cmd_r") and key == keyboard.Key.cmd_r:
                self.cmd_pressed = True
            elif hasattr(key, 'char') and key.char:
                self.check_command_patterns(key.char.lower())
            elif key in (keyboard.Key.enter, keyboard.Key.space):
                self.command_buffer += ' '
            # update last reset timestamp
            self.last_reset_time = now
        except (AttributeError, TypeError) as e:
            self.logger.debug(f"Error processing keystroke: {e}")

    def on_release(self, key: Any) -> None:
        """Callback when a key is released.
        
        Args:
            key: The key released (from pynput.keyboard)
        """
        if not PYNPUT_AVAILABLE or keyboard is None:
            return

        if key in (keyboard.Key.ctrl_l, keyboard.Key.ctrl_r):
            self.ctrl_pressed = False
        elif hasattr(keyboard.Key, "cmd") and key == keyboard.Key.cmd:
            self.cmd_pressed = False
        elif hasattr(keyboard.Key, "cmd_l") and key == keyboard.Key.cmd_l:
            self.cmd_pressed = False
        elif hasattr(keyboard.Key, "cmd_r") and key == keyboard.Key.cmd_r:
            self.cmd_pressed = False

    def check_command_patterns(self, char: str) -> None:
        """Detect malicious command patterns in typed input.
        
        Args:
            char: The character to check
        """
        self.command_buffer += char

        if len(self.command_buffer) > 300:
            self.command_buffer = self.command_buffer[-300:]

        if (self.ctrl_pressed or self.cmd_pressed) and char == "r":
            self.logger.warning("⚠️ Suspicious launcher combo detected: Ctrl/Cmd + R")
            self.trigger_command_alert("ctrl/cmd+r")
            self.command_buffer = ""
            return

        for pattern in MALICIOUS_PATTERNS:
            if pattern.lower() in self.command_buffer:
                self.logger.warning(f"⚠️ Malicious command pattern detected: {pattern}")
                self.trigger_command_alert(pattern)
                self.command_buffer = ""
                return

    def trigger_input_delay_alert(self, delay_seconds: float) -> None:
        """Raise an alert for first-input timing that is too fast.
        
        Args:
            delay_seconds: Time in seconds before first input was detected
        """
        msg = f"Automated HID device input started too quickly: {delay_seconds:.2f}s"
        self.logger.error(msg)
        if IS_WINDOWS and winsound:
            try:
                winsound.Beep(1200, 200)
            except (OSError, AttributeError, TypeError) as e:
                self.logger.debug(f"Failed to play alert sound: {e}")

    def trigger_command_alert(self, pattern: str) -> None:
        """Alert for suspicious command content detected in keystrokes.
        
        Args:
            pattern: The malicious pattern that was detected
        """
        msg = f"Malicious command signature detected: {pattern}"
        self.logger.error(msg)
        if IS_WINDOWS and winsound:
            try:
                winsound.Beep(1000, 200)
                winsound.Beep(1000, 200)
            except (OSError, AttributeError, TypeError) as e:
                self.logger.debug(f"Failed to play alert sound: {e}")

    def trigger_keystroke_alert(self, speed: float) -> None:
        """Alert when suspicious keystroke speed detected.
        
        Args:
            speed: Keystroke speed in keys per second
        """
        msg = f"Automated keystroke attack detected: {speed:.1f} keys/sec"
        self.logger.error(msg)
        self.rapid_typing_detected = True
        
        # Play alert sound
        if IS_WINDOWS and winsound:
            try:
                winsound.Beep(1200, 200)
                winsound.Beep(1200, 200)
            except (OSError, AttributeError, TypeError) as e:
                self.logger.debug(f"Failed to play alert sound: {e}")
    
    def start(self) -> None:
        """Start monitoring keystrokes."""
        if not PYNPUT_AVAILABLE or keyboard is None:
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
    
    def stop(self) -> None:
        """Stop monitoring keystrokes."""
        if self.listener and self.is_monitoring:
            self.listener.stop()
            self.is_monitoring = False
            self.logger.info("Keystroke monitoring stopped")
