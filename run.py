"""
HID Defender - Root launcher script.
Run this directly without needing to install the package:
    .venv/bin/python3 run.py --monitor
    .venv/bin/python3 run.py --dashboard
"""

import sys
import os

# Add src/ to the path so hid_defender package can be found
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

try:
    from hid_defender.cli import main
except ImportError as e:
    print(f"Error: Could not import hid_defender package. {e}")
    print("Ensure you are running this from the project root and requirements are installed.")
    sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) == 1:
        print("HID Defender Launcher")
        print("-" * 20)
        print("Usage: python3 run.py [options]")
        print("Options:")
        print("  --monitor    Start the core security monitor")
        print("  --dashboard  Start the web dashboard")
        print("  --setup      Run baseline device setup")
        print("\nDefaulting to --help...")
        sys.argv.append("--help")
    
    sys.exit(main())
