"""
SENTINEL PRO - Process Agent (v4 - Final)

Key fixes:
  - CPU monitoring is now COMPLETELY SEPARATE from the new-process name check.
    Every non-safe process gets CPU tracked every loop, regardless of known_pids.
  - Python subprocesses with suspicious cmdline get a renamed display name AND
    are tracked for CPU independently.
  - Lowered CPU threshold to 60% and sustained time to 3s for demo reliability.
"""

import os
import time
import threading

from core.logger import log_event

SUSPICIOUS_NAMES = {
    'mimikatz', 'meterpreter', 'cobalt', 'empire', 'metasploit',
    'powershell', 'cmd.exe', 'wscript', 'cscript', 'rundll32',
    'regsvr32', 'mshta', 'certutil', 'bitsadmin', 'wmic',
    'psexec', 'at.exe', 'schtasks', 'net.exe', 'whoami',
}

SAFE_NAMES = {
    'system', 'system idle process', 'idle', 'registry',
    'smss.exe', 'csrss.exe', 'wininit.exe', 'winlogon.exe',
    'services.exe', 'lsass.exe', 'svchost.exe', 'dwm.exe', 'explorer.exe',
    'taskhostw.exe', 'sihost.exe', 'runtimebroker.exe', 'searchindexer.exe',
    'spoolsv.exe', 'audiodg.exe', 'fontdrvhost.exe', 'ctfmon.exe',
    'memory compression', 'secure system', 'ntoskrnl.exe',
}

# Python scripts that should NOT be skipped even though they're python.exe
SUSPICIOUS_SCRIPT_KEYWORDS = ['cpu_storm', 'malware', 'miner', 'keylog', 'exploit', 'payload', 'attack']

CPU_ALERT_THRESHOLD = 60   # % — lowered for demo reliability
CPU_SUSTAINED_SECS  = 3    # seconds — lowered for demo reliability

# PID of THIS process — never alert on ourselves
OWN_PID = os.getpid()


def _is_safe(pid, name, info):
    """Return True if this process should be completely ignored."""
    if pid in (0, 4) or pid == OWN_PID:
        return True
    if name in SAFE_NAMES:
        return True
    if 'idle' in name:
        return True
    return False


def _resolve_name(name, info):
    """
    For python.exe processes: check cmdline to determine if it's running
    a suspicious script. Returns (display_name, is_suspicious_python).
    is_suspicious_python=True means it's python.exe running a bad script — track CPU.
    is_suspicious_python=False means normal python — skip entirely.
    """
    is_python = name in ('python.exe', 'python3.exe', 'python3', 'python')
    if not is_python:
        return name, False

    try:
        cmdline = info.get('cmdline') or []
        script = ' '.join(cmdline).lower()
        if any(kw in script for kw in SUSPICIOUS_SCRIPT_KEYWORDS):
            # Give it a meaningful display name
            script_file = os.path.basename(cmdline[-1]) if cmdline else 'script'
            return f'python({script_file})', True
        # Normal python process — skip
        return name, False
    except Exception:
        return name, False  # Can't read cmdline, skip


class ProcessAgent:

    def __init__(self, callback=None):
        self.callback        = callback
        self.running         = False
        self._thread         = None
        self._known_pids     = set()        # PIDs we've seen (for new-process alerts)
        self._alerted_name   = set()        # PIDs already alerted for suspicious name
        self._alerted_cpu    = set()        # PIDs already alerted for high CPU
        self._cpu_high_since = {}           # pid -> timestamp first seen high

    def start(self):
        if self.running:
            return
        self.running = True
        self._thread = threading.Thread(target=self._loop, daemon=True, name='agent-process')
        self._thread.start()
        print("[PROCESS AGENT] Started (v4)")

    def stop(self):
        self.running = False

    def _loop(self):
        try:
            import psutil
        except ImportError:
            print("[PROCESS AGENT] psutil not installed")
            self.running = False
            return

        # Prime cpu_percent counters (first call always returns 0.0)
        for p in psutil.process_iter(['pid']):
            try:
                p.cpu_percent(interval=None)
            except Exception:
                pass

        while self.running:
            try:
                self._check_processes()
            except Exception as e:
                print(f"[PROCESS AGENT] Error: {e}")
            time.sleep(5)

    def _check_processes(self):
        import psutil
        current_pids = set()
        now = time.time()

        for proc in psutil.process_iter(['pid', 'name', 'ppid',
                                         'cpu_percent', 'memory_percent',
                                         'exe', 'cmdline']):
            try:
                info = proc.info
                pid  = info['pid']
                raw_name = (info['name'] or '').lower()
                current_pids.add(pid)

                # Skip system/safe processes entirely
                if _is_safe(pid, raw_name, info):
                    continue

                # Resolve display name (handles python.exe cmdline check)
                name, is_suspicious_python = _resolve_name(raw_name, info)

                # Pure python.exe with normal cmdline — skip
                if raw_name in ('python.exe', 'python3.exe', 'python3', 'python') and not is_suspicious_python:
                    continue

                # ── NEW PROCESS ALERT (suspicious name) ───────────────────
                if pid not in self._known_pids:
                    self._known_pids.add(pid)
                    if any(s in name for s in SUSPICIOUS_NAMES) and pid not in self._alerted_name:
                        self._alerted_name.add(pid)
                        self._fire({
                            'source_agent': 'process',
                            'event_type':   'create',
                            'entity':       f"Process: {name} (PID {pid})",
                            'details': {
                                'pid':    pid,
                                'name':   name,
                                'ppid':   info['ppid'],
                                'exe':    info.get('exe', ''),
                                'reason': 'Suspicious process name detected',
                            },
                        })

                # ── CPU SPIKE DETECTION ────────────────────────────────────
                # cpu_percent(interval=None) uses time since last call (~5s loop)
                cpu = proc.cpu_percent(interval=None)

                if cpu > CPU_ALERT_THRESHOLD:
                    if pid not in self._cpu_high_since:
                        self._cpu_high_since[pid] = now
                    elif (now - self._cpu_high_since[pid] >= CPU_SUSTAINED_SECS
                            and pid not in self._alerted_cpu):
                        self._alerted_cpu.add(pid)
                        self._fire({
                            'source_agent': 'process',
                            'event_type':   'high_cpu',
                            'entity':       f"CPU Spike: {name} {cpu:.0f}%",
                            'details': {
                                'pid':            pid,
                                'name':           name,
                                'cpu_percent':    round(cpu, 1),
                                'mem_percent':    round(info.get('memory_percent') or 0, 2),
                                'sustained_secs': round(now - self._cpu_high_since[pid], 1),
                                'reason':         f'CPU {cpu:.0f}% sustained >{CPU_SUSTAINED_SECS}s',
                            },
                        })
                else:
                    # CPU back to normal — reset so we re-alert on next spike
                    self._cpu_high_since.pop(pid, None)
                    self._alerted_cpu.discard(pid)

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
            except Exception:
                pass

        # Clean up exited processes
        gone = self._known_pids - current_pids
        self._known_pids   -= gone
        self._alerted_name -= gone
        self._alerted_cpu  -= gone
        for pid in gone:
            self._cpu_high_since.pop(pid, None)

    def _fire(self, event: dict):
        if self.callback:
            self.callback(event)

    def get_status(self):
        try:
            import psutil
            count = sum(1 for _ in psutil.process_iter())
        except Exception:
            count = 0
        return {'running': self.running, 'monitored': count, 'agent': 'process'}
