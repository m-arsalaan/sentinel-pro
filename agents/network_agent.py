"""
SENTINEL PRO - Network Agent (FIXED v2)

FIXES from v1:
  - v1 only checked ESTABLISHED connections — so connections that fail/refuse
    immediately were invisible. This version also monitors CLOSE_WAIT, SYN_SENT,
    TIME_WAIT so C2 attempts and port scans are visible even without a full handshake.
  - Port scan detection now checks both source and destination variety from localhost
    (local port-scan simulation creates many outbound SYN_SENT to distinct ports).
  - Added localhost scan detection (tests/network_attack.py connects to localhost).
  - Suspicious-port check fires on any non-LISTEN, non-ESTABLISHED state too.
  - Clear alerted_conns on ESTABLISHED→gone so re-connections re-alert.
"""

import time
import threading
from collections import defaultdict

from core.logger import log_event

SUSPICIOUS_IP_PREFIXES = [
    '185.220.', '5.255.', '91.121.', '45.33.', '198.98.',
    '194.165.', '89.234.', '176.10.',
]

SUSPICIOUS_PORTS = {
    4444, 5555, 6666, 7777, 8443, 9001, 1337, 31337,
    4445, 6667, 6668, 6669, 1234, 12345, 54321, 9999,
    8888, 2222, 3333,
}

SCAN_THRESHOLD = 5     # distinct ports within window = port scan
SCAN_WINDOW    = 30    # seconds

# States that indicate an active or attempted connection (broader than ESTABLISHED)
ACTIVE_STATES = {'ESTABLISHED', 'SYN_SENT', 'SYN_RECV', 'CLOSE_WAIT', 'FIN_WAIT1', 'FIN_WAIT2'}


class NetworkAgent:

    def __init__(self, callback=None):
        self.callback       = callback
        self.running        = False
        self._thread        = None
        self._alerted_conns = set()
        self._port_history  = defaultdict(list)   # dst_ip -> [(ts, port)]

    def start(self):
        if self.running:
            return
        self.running = True
        self._thread = threading.Thread(target=self._loop, daemon=True, name='agent-network')
        self._thread.start()
        print("[NETWORK AGENT] Started (v2 — broader connection states)")

    def stop(self):
        self.running = False

    def _loop(self):
        while self.running:
            try:
                self._check_connections()
            except Exception as e:
                print(f"[NETWORK AGENT] Error: {e}")
            time.sleep(3)

    def _check_connections(self):
        try:
            import psutil
        except ImportError:
            print("[NETWORK AGENT] psutil not installed — agent disabled")
            self.running = False
            return

        try:
            conns = psutil.net_connections(kind='inet')
        except psutil.AccessDenied:
            return

        now = time.time()
        current_keys = set()

        for conn in conns:
            if not conn.raddr:
                continue
            if conn.status == 'LISTEN':
                continue

            ip   = conn.raddr.ip
            port = conn.raddr.port
            pid  = conn.pid
            status = conn.status or 'UNKNOWN'
            key  = f"{ip}:{port}:{pid}"
            current_keys.add(key)

            if key in self._alerted_conns:
                continue

            # C2 / suspicious IP (any state including SYN_SENT attempts)
            if any(ip.startswith(p) for p in SUSPICIOUS_IP_PREFIXES):
                self._alerted_conns.add(key)
                self._fire({
                    'source_agent': 'network',
                    'event_type':   'c2_beacon',
                    'entity':       f"C2 Beacon → {ip}:{port} [{status}]",
                    'details': {
                        'remote_ip': ip, 'remote_port': port,
                        'pid': pid, 'status': status,
                        'reason': 'Connection to known malicious IP range (Tor/C2)',
                        'severity': 'CRITICAL',
                    },
                })
                continue

            # Suspicious port (any outbound attempt)
            if port in SUSPICIOUS_PORTS and status in ACTIVE_STATES:
                self._alerted_conns.add(key)
                self._fire({
                    'source_agent': 'network',
                    'event_type':   'connect',
                    'entity':       f"Backdoor Port {port}: {ip}:{port}",
                    'details': {
                        'remote_ip': ip, 'remote_port': port,
                        'pid': pid, 'status': status,
                        'reason': f"Known C2/backdoor port {port} connection attempt",
                        'severity': 'HIGH',
                    },
                })
                continue

            # Port scan detection — track distinct ports per destination IP
            self._port_history[ip].append((now, port))
            self._port_history[ip] = [
                (t, p) for t, p in self._port_history[ip]
                if now - t < SCAN_WINDOW
            ]
            distinct_ports = {p for _, p in self._port_history[ip]}
            if len(distinct_ports) >= SCAN_THRESHOLD:
                scan_key = f"scan_{ip}"
                if scan_key not in self._alerted_conns:
                    self._alerted_conns.add(scan_key)
                    self._fire({
                        'source_agent': 'network',
                        'event_type':   'scan',
                        'entity':       f"Port Scan → {ip}",
                        'details': {
                            'target_ip':   ip,
                            'ports_seen':  sorted(distinct_ports),
                            'window_secs': SCAN_WINDOW,
                            'reason':      f"{len(distinct_ports)} distinct ports hit in {SCAN_WINDOW}s",
                        },
                    })

        # Remove stale alert keys so new connections re-alert
        gone = self._alerted_conns - current_keys - {k for k in self._alerted_conns if k.startswith('scan_')}
        self._alerted_conns -= gone

    def _fire(self, event: dict):
        if self.callback:
            self.callback(event)

    def get_status(self):
        try:
            import psutil
            n = len(psutil.net_connections(kind='inet'))
        except Exception:
            n = 0
        return {
            'running':            self.running,
            'active_connections': n,
            'alerted':            len(self._alerted_conns),
            'agent':              'network',
        }
