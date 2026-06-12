"""
SENTINEL PRO - C2 Beacon / Network Attack Simulation (v3)

Previous version only hit local ports which showed as FLAGGED (risk 50).
This version does TWO things:
  1. Makes actual socket connections to known-bad IP ranges (will fail/timeout
     but SYN_SENT state IS visible to psutil — triggers c2_beacon detection)
  2. Scans localhost ports to guarantee port-scan detection fires
  3. Also makes connections on high-risk backdoor ports to trigger suspicious-port alerts
"""

import socket
import threading
import time

print("[ATTACK] C2 Beacon + Network Scan simulation starting...")

# ── Part 1: C2 connections to known-bad IP ranges ─────────────────────────────
# These IPs are in the SUSPICIOUS_IP_PREFIXES list in network_agent.py
# Connections will fail (no route/timeout) but SYN_SENT appears in psutil immediately
C2_TARGETS = [
    ('185.220.101.1', 443),    # Tor exit node range
    ('185.220.101.2', 80),
    ('185.220.101.3', 8443),
    ('5.255.97.1',    443),    # Known bad range
    ('91.121.55.1',   4444),   # Metasploit default
]

# ── Part 2: Suspicious backdoor ports on localhost ────────────────────────────
BACKDOOR_PORTS = [4444, 5555, 6666, 7777, 1337, 31337, 9001, 4445, 8443]

# ── Part 3: Port scan simulation (many ports → triggers scan detector) ────────
SCAN_PORTS = [1234, 12345, 2222, 3333, 9999, 54321, 6667, 6668, 8888, 6666, 7777]

def try_connect_nonblocking(host, port, timeout=2):
    """Attempt connection — SYN_SENT shows in psutil even before timeout."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.close()
    except Exception:
        pass  # Expected to fail — SYN_SENT was still seen by psutil

print("[ATTACK] Phase 1: C2 beacon connections to suspicious IP ranges...")
c2_threads = [threading.Thread(target=try_connect_nonblocking, args=(ip, port, 3), daemon=True)
              for ip, port in C2_TARGETS]
for t in c2_threads:
    t.start()
    time.sleep(0.3)

# Let SYN_SENT state be visible for a few seconds
time.sleep(3)

print("[ATTACK] Phase 2: Suspicious backdoor port connections...")
backdoor_threads = [threading.Thread(target=try_connect_nonblocking, args=('127.0.0.1', p, 1), daemon=True)
                    for p in BACKDOOR_PORTS]
for t in backdoor_threads:
    t.start()
    time.sleep(0.15)

time.sleep(2)

print("[ATTACK] Phase 3: Port scan simulation...")
scan_threads = [threading.Thread(target=try_connect_nonblocking, args=('127.0.0.1', p, 1), daemon=True)
                for p in SCAN_PORTS]
for t in scan_threads:
    t.start()
    time.sleep(0.1)

# Wait for all
for t in c2_threads + backdoor_threads + scan_threads:
    t.join(timeout=5)

print(f"[ATTACK] Network attack complete — {len(C2_TARGETS)} C2 attempts, {len(BACKDOOR_PORTS)} backdoor ports, {len(SCAN_PORTS)} scan ports")
print("[ATTACK] Check dashboard: NETWORK agent should show c2_beacon + connect + scan events")
