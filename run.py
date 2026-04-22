"""
HID Defender - Root launcher script.
Run this directly without needing to install the package:
    .venv\Scripts\python.exe run.py --monitor
    .venv\Scripts\python.exe run.py --dashboard
"""

import sys
import os

# Add src/ to the path so hid_defender package can be found
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from hid_defender.cli import main

if __name__ == "__main__":
    sys.exit(main())
