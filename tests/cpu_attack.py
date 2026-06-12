"""
SENTINEL PRO - CPU Attack Simulation
Directly burns CPU on 4 threads for 30 seconds.
Triggers Process Agent high-CPU detection on this python.exe process.
"""

import threading
import time
import math
import os

DURATION = 30  # seconds

print("=" * 50)
print(f"[CPU ATTACK] Starting CPU storm  PID {os.getpid()}")
print(f"[CPU ATTACK] Running {DURATION} seconds on 4 threads")
print("[CPU ATTACK] Watch dashboard for HIGH CPU alert...")
print("=" * 50)


def burn_cpu():
    end = time.time() + DURATION
    while time.time() < end:
        _ = sum(math.sin(i) * math.cos(i) for i in range(80000))


# Launch 4 threads to spike CPU across cores
threads = [threading.Thread(target=burn_cpu) for _ in range(4)]
for t in threads:
    t.start()

# Show countdown so the window stays visible
for remaining in range(DURATION, 0, -5):
    print(f"[CPU ATTACK] Running... {remaining}s remaining")
    time.sleep(5)

for t in threads:
    t.join()

print("[CPU ATTACK] Complete  closing in 3 seconds")
time.sleep(3)
