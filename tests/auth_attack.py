"""
SENTINEL PRO - Brute Force Auth Simulation (v4)

Uses Windows LogonUser() API directly via ctypes.
This is the ONLY reliable way to generate real Event ID 4625 entries
in the Security Event Log without admin — because LogonUser() is a
privileged kernel call that always logs, even for non-admin callers.

The previous version used net use + runas which are unreliable
and require interactive consoles.
"""

import time
import ctypes
import ctypes.wintypes
import subprocess
import os

print("[ATTACK] Brute Force Auth simulation v4 starting...")

# ── Method 1: LogonUser API — generates REAL Event ID 4625 ───────────────────
print("[ATTACK] Phase 1: LogonUser() API brute force (generates Event ID 4625)...")

try:
    advapi32 = ctypes.windll.advapi32
    kernel32  = ctypes.windll.kernel32

    LOGON32_LOGON_NETWORK      = 3
    LOGON32_LOGON_INTERACTIVE  = 2
    LOGON32_PROVIDER_DEFAULT   = 0

    # These usernames look like real attack targets
    fake_creds = [
        ('Administrator', 'Password123!'),
        ('Administrator', 'Admin2025!'),
        ('Administrator', 'Welcome1'),
        ('admin',         'admin'),
        ('Administrator', 'Summer2025!'),
        ('sa',            'sa'),
        ('root',          'root'),
        ('Administrator', 'P@ssw0rd'),
        ('backup',        'backup123'),
        ('Administrator', 'Companyname1!'),
    ]

    token = ctypes.c_void_p()
    success_count = 0
    for username, password in fake_creds:
        result = advapi32.LogonUserW(
            username,                    # lpszUsername
            '.',                         # lpszDomain (. = local machine)
            password,                    # lpszPassword
            LOGON32_LOGON_NETWORK,       # dwLogonType
            LOGON32_PROVIDER_DEFAULT,    # dwLogonProvider
            ctypes.byref(token)          # phToken
        )
        # result=0 means failure — which is what generates Event ID 4625
        if result == 0:
            success_count += 1
            print(f"[ATTACK] Failed logon (good): {username} — Event 4625 generated")
        else:
            # Unexpected success — close the handle
            kernel32.CloseHandle(token)
            print(f"[ATTACK] WARNING: {username} logged in successfully!")
        time.sleep(0.4)

    print(f"[ATTACK] Phase 1 complete: {success_count} failed logon events generated")

except AttributeError:
    print("[ATTACK] Not on Windows — skipping LogonUser")
except Exception as e:
    print(f"[ATTACK] LogonUser phase error: {e}")

# ── Method 2: net use as reliable fallback ────────────────────────────────────
print("[ATTACK] Phase 2: net use IPC$ attempts...")
users = ['Administrator', 'admin', 'backup', 'service_account']
for user in users:
    try:
        cmd = f'net use \\\\\\\\127.0.0.1\\\\IPC$ /user:{user} WrongPass123! 2>nul'
        subprocess.run(cmd, shell=True, capture_output=True, timeout=4)
        print(f"[ATTACK] net use attempt: {user}")
    except Exception:
        pass
    time.sleep(0.3)

print("\n[ATTACK] Brute force simulation complete!")
print("[ATTACK] Auth Agent checks every 5 seconds — allow up to 10s for detection")
print("[ATTACK] Expected dashboard events: 'Brute Force: Administrator' BLOCKED")
print("[ATTACK] Expected dashboard events: 'Brute Force: Administrator' BLOCKED")
