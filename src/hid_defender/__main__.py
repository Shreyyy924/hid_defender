"""
HID Defender main module entry point.

This module serves as the entry point when running:
  python -m hid_defender
"""

import sys
from .cli import main

if __name__ == "__main__":
    sys.exit(main())
