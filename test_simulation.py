import time
from pynput.keyboard import Controller

keyboard = Controller()

def simulate_fast_typing():
    print("Simulating fast typing in 3 seconds...")
    time.sleep(3)
    text = "powershell -executionpolicy bypass -file script.ps1"
    for char in text:
        keyboard.press(char)
        keyboard.release(char)
        # Type extremely fast (no sleep or very small sleep)
    print("Simulation complete.")

if __name__ == "__main__":
    simulate_fast_typing()
