"""
SENTINEL PRO - Registry Persistence Simulation (v3)

Previous version used HKLM keys which need admin rights.
v3 uses HKCU keys which work WITHOUT admin, plus adds a cleanup
function so the test doesn't leave real persistence entries behind.

Registry Agent monitors HKCU Run key — this will trigger it reliably.
"""

import subprocess
import time
import os

print("[ATTACK] Registry Persistence simulation starting...")
print("[ATTACK] Using HKCU keys (no admin required)")

# ── Persistence entries using HKCU (no admin needed) ─────────────────────────
REG_ENTRIES = [
    # HKCU Run — most common persistence, monitored by registry agent
    (r'HKCU\Software\Microsoft\Windows\CurrentVersion\Run',
     'WindowsSecurityUpdate',
     r'C:\Users\Public\malware_backdoor.exe'),

    (r'HKCU\Software\Microsoft\Windows\CurrentVersion\Run',
     'AdobeUpdaterHelper',
     r'C:\Users\Public\Downloads\payload.exe'),

    (r'HKCU\Software\Microsoft\Windows\CurrentVersion\Run',
     'ChromeExtensionHelper',
     r'C:\Windows\Temp\c2_agent.exe'),

    # RunOnce — executes on next login
    (r'HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce',
     'SystemMaintenance',
     r'C:\Users\Public\stager.exe'),
]

WRITTEN = []

print("[ATTACK] Writing registry persistence entries...")
for reg_path, name, value in REG_ENTRIES:
    try:
        cmd = f'reg add "{reg_path}" /v "{name}" /t REG_SZ /d "{value}" /f'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            print(f"[ATTACK] ✓ Written: {reg_path}\\{name}")
            WRITTEN.append((reg_path, name))
        else:
            print(f"[ATTACK] ✗ Failed: {result.stderr.strip()}")
    except Exception as e:
        print(f"[ATTACK] Error: {e}")
    time.sleep(0.5)

# Wait for Registry Agent to detect (it polls every 5 seconds)
print("\n[ATTACK] Waiting 8 seconds for Registry Agent to detect changes...")
time.sleep(8)

# ── CLEANUP — remove the test entries ────────────────────────────────────────
print("\n[ATTACK] Cleaning up test registry entries...")
for reg_path, name in WRITTEN:
    try:
        cmd = f'reg delete "{reg_path}" /v "{name}" /f'
        subprocess.run(cmd, shell=True, capture_output=True, timeout=5)
        print(f"[ATTACK] Cleaned: {reg_path}\\{name}")
    except Exception:
        pass

print("\n[ATTACK] Registry attack simulation complete!")
print("[ATTACK] Registry Agent should have detected persistence entries")
print("[ATTACK] NOTE: HKLM entries (system-wide) need admin — run as Administrator for full coverage")
