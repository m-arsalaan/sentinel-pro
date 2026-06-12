"""
File Ransomware Simulation - Tests File Agent
Creates files in monitored directories to simulate ransomware behavior
"""

import os
import time
import string
import random

print("[ATTACK] Starting file ransomware simulation...")
print("[ATTACK] Creating encrypted-looking files in monitored directories")

MONITORED_DIRS = [
    os.path.expanduser("~/Documents"),
    os.path.expanduser("~/Desktop"),
    os.path.expanduser("~/Downloads"),
    os.path.join(os.environ.get('TMP', '/tmp'), 'sentinel_test'),
    "C:\\Windows\\Temp\\sentinel_test",
]

def random_string(length=10):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def simulate_ransomware():
    for base_dir in MONITORED_DIRS:
        if not os.path.exists(base_dir):
            try:
                os.makedirs(base_dir, exist_ok=True)
            except:
                continue
        
        for i in range(3):
            filename = f"encrypted_{random_string()}.locked"
            filepath = os.path.join(base_dir, filename)
            try:
                with open(filepath, 'w') as f:
                    f.write(f"ENCRYPTED FILE - RANSOMWARE SIMULATION\n")
                    f.write(f"Original: important_document_{i}.docx\n")
                    f.write(f"Key: {random_string(32)}\n")
                    f.write("Pay 0.5 BTC to recover your files\n")
                print(f"[ATTACK] Created: {filepath}")
            except Exception as e:
                print(f"[ATTACK] Failed to create {filepath}: {e}")
        
        time.sleep(0.5)

if __name__ == '__main__':
    print("[ATTACK] File ransomware simulation running for 10 seconds")
    simulate_ransomware()
    print("[ATTACK] File attack complete - check dashboard for File Agent detection")