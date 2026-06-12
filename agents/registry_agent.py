"""
SENTINEL PRO - Registry Agent
Monitors critical Windows registry keys for unauthorized changes.
Takes a clean baseline on startup and diffs every N seconds.
"""

import time
import subprocess
import threading

from core.logger import log_event

MONITORED_KEYS = [
    ('HKLM', r'Software\Microsoft\Windows\CurrentVersion\Run'),
    ('HKCU', r'Software\Microsoft\Windows\CurrentVersion\Run'),
    ('HKLM', r'Software\Microsoft\Windows\CurrentVersion\RunOnce'),
    ('HKLM', r'Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'),
    ('HKLM', r'Software\Microsoft\Windows NT\CurrentVersion\Winlogon'),
    ('HKLM', r'System\CurrentControlSet\Services'),
    ('HKLM', r'Software\Policies\Microsoft\Windows Defender'),
    ('HKLM', r'Software\Microsoft\Windows\CurrentVersion\Policies\System'),
    ('HKLM', r'Software\Microsoft\Windows NT\CurrentVersion\Windows'),
]

HIGH_RISK_VALUE_NAMES = {
    'debugger', 'appinit_dlls', 'shell', 'userinit',
    'disableantispyware', 'enablelua', 'consentpromptbehavioradmin',
    'disableregistrytools', 'disabletaskmgr',
}


class RegistryAgent:
    """
    Monitors Windows Registry for persistence and tampering:
    - New values in Run/RunOnce keys (persistence)
    - Image File Execution Options Debugger hijacking
    - Winlogon shell replacement
    - Windows Defender policy disablement
    - Service installation
    """

    def __init__(self, callback=None):
        self.callback  = callback
        self.running   = False
        self._thread   = None
        self._baseline = {}
        self._alerted  = set()   # deduplicate: (key_path, value_name)

    # ── lifecycle ─────────────────────────────────────────────────────────────

    def start(self):
        if self.running:
            return
        self.running = True
        self._thread = threading.Thread(target=self._loop, daemon=True, name='agent-registry')
        self._thread.start()
        print("[REGISTRY AGENT] Started")

    def stop(self):
        self.running = False

    # ── monitoring loop ───────────────────────────────────────────────────────

    def _loop(self):
        self._take_baseline()
        print(f"[REGISTRY AGENT] Baseline snapshot taken ({len(self.monitored_keys_count)} keys)")
        while self.running:
            try:
                self._diff_registry()
            except Exception as e:
                print(f"[REGISTRY AGENT] Error: {e}")
            time.sleep(5)

    @property
    def monitored_keys_count(self):
        return MONITORED_KEYS

    # ── baseline & diff ───────────────────────────────────────────────────────

    def _take_baseline(self):
        self._baseline = {}
        for hive, key in MONITORED_KEYS:
            values = self._query_key(hive, key)
            self._baseline[f"{hive}\\{key}"] = values

    def _diff_registry(self):
        for hive, key in MONITORED_KEYS:
            full_path = f"{hive}\\{key}"
            current  = self._query_key(hive, key)
            baseline = self._baseline.get(full_path, {})

            if not current:
                continue

            # New values not in baseline
            for name, value in current.items():
                if name not in baseline:
                    alert_key = (full_path, name)
                    if alert_key not in self._alerted:
                        self._alerted.add(alert_key)
                        risk = self._calc_risk(hive, key, name)
                        self._fire({
                            'source_agent': 'registry',
                            'event_type':   'persistence',
                            'entity':       f"Registry: {full_path}\\{name}",
                            'details': {
                                'hive':        hive,
                                'key':         key,
                                'value_name':  name,
                                'value_data':  value[:200],  # truncate long values
                                'change_type': 'new_value',
                                'risk_reason': self._risk_reason(hive, key, name),
                            },
                        })
                    # Update baseline
                    self._baseline[full_path][name] = value

                elif current[name] != baseline[name]:
                    # Value was modified
                    alert_key = (full_path, f"MOD_{name}")
                    if alert_key not in self._alerted:
                        self._alerted.add(alert_key)
                        self._fire({
                            'source_agent': 'registry',
                            'event_type':   'modify',
                            'entity':       f"Registry Modified: {full_path}\\{name}",
                            'details': {
                                'hive':       hive,
                                'key':        key,
                                'value_name': name,
                                'old_value':  baseline[name][:100],
                                'new_value':  current[name][:100],
                                'change_type':'modified_value',
                            },
                        })
                    self._baseline[full_path][name] = current[name]

    # ── registry query ────────────────────────────────────────────────────────

    def _query_key(self, hive: str, key: str) -> dict:
        try:
            result = subprocess.run(
                ['reg', 'query', f'{hive}\\{key}'],
                capture_output=True, text=True, timeout=3
            )
            if result.returncode != 0:
                return {}

            values = {}
            for line in result.stdout.splitlines():
                line = line.strip()
                if not line or line.startswith('HKEY'):
                    continue
                # Format: "    ValueName    REG_SZ    ValueData"
                parts = line.split(None, 2)
                if len(parts) == 3:
                    vname, vtype, vdata = parts
                    values[vname] = vdata
            return values

        except subprocess.TimeoutExpired:
            return {}
        except FileNotFoundError:
            return {}  # not on Windows
        except Exception as e:
            print(f"[REGISTRY AGENT] Query error {hive}\\{key}: {e}")
            return {}

    # ── risk scoring helpers ──────────────────────────────────────────────────

    def _calc_risk(self, hive: str, key: str, name: str) -> int:
        score = 30
        if name.lower() in HIGH_RISK_VALUE_NAMES:            score += 40
        if 'Run' in key and 'RunOnce' not in key:             score += 20
        if 'Image File Execution' in key:                     score += 35
        if 'Defender' in key:                                 score += 30
        if 'Services' in key:                                 score += 25
        if 'Winlogon' in key:                                 score += 30
        return min(score, 100)

    def _risk_reason(self, hive: str, key: str, name: str) -> str:
        if name.lower() == 'debugger':
            return 'Image File Execution Options Debugger — classic persistence hijack'
        if name.lower() == 'appinit_dlls':
            return 'AppInit_DLLs — DLL injection into every user-mode process'
        if 'Defender' in key:
            return 'Windows Defender policy modification — possible AV bypass'
        if 'Run' in key:
            return 'Autorun key modification — persistence mechanism'
        if 'Winlogon' in key:
            return 'Winlogon modification — possible shell replacement'
        return 'Sensitive registry key modified'

    def _fire(self, event: dict):
        if self.callback:
            self.callback(event)

    def get_status(self):
        return {
            'running':        self.running,
            'monitored_keys': len(MONITORED_KEYS),
            'alerted':        len(self._alerted),
            'agent':          'registry',
        }
