# ==========================================
# Logging System Setup
# ==========================================

import logging
import csv
import os
import sys

# Handle both package imports and standalone execution
try:
    from .config import LOG_PATH
except ImportError:
    from config import LOG_PATH

class CSVLogFormatter(logging.Formatter):
    """Custom formatter to keep our audit log in CSV format."""
    def format(self, record):
        # If the message is a dict (our device info), format it as CSV
        if isinstance(record.msg, dict):
            info = record.msg
            res = getattr(record, 'result', 'UNKNOWN')
            act = getattr(record, 'action', 'NONE')
            reason = getattr(record, 'reason', '')
            return (
                f"{info['time']},{info['name']},{info['vendor']},{info['product']}"
                f",{info['id']},{res},{act},{reason}"
            )
        return super().format(record)


def init_logger():
    """Sets up unified logging for both console and CSV audit log."""
    logger = logging.getLogger("HID_Defender")
    logger.setLevel(logging.INFO)
    
    # Remove any existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # 1. Console Handler (Friendly output)
    console_fmt = logging.Formatter("[%(asctime)s] %(message)s", "%H:%M:%S")
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(console_fmt)
    logger.addHandler(ch)

    # 2. CSV File Handler (Audit log)
    # Ensure header exists first
    if not os.path.exists(LOG_PATH):
        with open(LOG_PATH, 'w', newline='', encoding='utf-8') as f:
            csv.writer(f).writerow([
                "Time", "Device", "Vendor", "Product", "ID", "Result", "Action", "Reason"
            ])
    
    fh = logging.FileHandler(LOG_PATH, encoding='utf-8')
    fh.setFormatter(CSVLogFormatter())
    logger.addHandler(fh)
    
    return logger


def log_event(logger, info, result, action, reason=""):
    """Helper to route a detection event through our logging system."""
    logger.info(info, extra={'result': result, 'action': action, 'reason': reason})
