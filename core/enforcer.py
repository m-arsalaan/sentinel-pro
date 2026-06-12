"""
SENTINEL PRO - Enforcement Engine
Executes real OS-level responses to blocked events.
Process termination, firewall rules, file quarantine, registry restore.
"""

import os
import sys
import shutil
import subprocess
import threading
from datetime import datetime

_IS_WINDOWS = sys.platform == 'win32'

QUARANTINE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    'quarantine'
)


class EnforcementEngine:
    """
    Executes enforcement actions based on agent type and event details.
    All actions are logged and non-destructive where possible
    (processes are suspended/terminated, files are moved not deleted,
     IPs are blocked at firewall, registry keys are backed up then removed).
    """

    def __init__(self, dry_run=False):
        self.dry_run = dry_run
        self._lock   = threading.Lock()
        self._actions_taken = []
        os.makedirs(QUARANTINE_DIR, exist_ok=True)
        mode = "DRY-RUN" if dry_run else "LIVE"
        print(f"[ENFORCE] Enforcement engine started ({mode} mode)")

    # ── public dispatch ───────────────────────────────────────────────────────

    def enforce(self, event: dict) -> str:
        """
        Decide and execute the appropriate enforcement action.
        Returns a human-readable string describing what was done.
        """
        if event.get('decision') != 'blocked':
            return None

        agent   = event.get('source_agent', '')
        details = event.get('details', {})

        action = None
        try:
            if agent == 'process':
                action = self._handle_process(details, event)
            elif agent == 'network':
                action = self._handle_network(details, event)
            elif agent == 'file':
                action = self._handle_file(details, event)
            elif agent == 'registry':
                action = self._handle_registry(details, event)
            elif agent == 'auth':
                action = self._handle_auth(details, event)
            elif agent == 'orchestrator':   # kill chain
                action = self._handle_kill_chain(details, event)
        except Exception as e:
            action = f"Enforcement error: {e}"

        if action:
            record = {
                'timestamp': datetime.utcnow().isoformat(),
                'agent': agent,
                'action': action,
                'entity': event.get('entity', ''),
            }
            with self._lock:
                self._actions_taken.append(record)
                if len(self._actions_taken) > 500:
                    self._actions_taken = self._actions_taken[-500:]
            print(f"[ENFORCE] {action}")

        return action

    # ── process enforcement ───────────────────────────────────────────────────

    def _handle_process(self, details: dict, event: dict) -> str:
        pid  = details.get('pid')
        name = details.get('name', 'unknown')

        if not pid:
            return f"Process '{name}' has no PID (system/virtual process) — no action taken"

        if self.dry_run:
            return f"[DRY-RUN] Would terminate PID {pid} ({name})"

        try:
            import psutil
            # Check the process still exists before attempting termination
            if not psutil.pid_exists(pid):
                return f"Process '{name}' (PID {pid}) already exited — no action needed"
            proc = psutil.Process(pid)
            # Double-check name matches to avoid killing wrong process if PID was reused
            current_name = (proc.name() or '').lower()
            if name and name not in current_name and current_name not in name:
                return f"PID {pid} is now '{current_name}' (was '{name}') — skipped to avoid wrong kill"
            proc.terminate()
            return f"Terminated process '{name}' (PID {pid})"
        except ImportError:
            if _IS_WINDOWS:
                r = subprocess.run(['taskkill', '/PID', str(pid), '/F'],
                                   capture_output=True, text=True)
                if r.returncode == 0:
                    return f"Killed PID {pid} via taskkill"
                return f"taskkill failed for PID {pid}: {r.stderr.strip()}"
            else:
                if not os.path.exists(f'/proc/{pid}'):
                    return f"Process PID {pid} already gone"
                os.kill(pid, 9)
                return f"Sent SIGKILL to PID {pid} ({name})"
        except psutil.NoSuchProcess:
            return f"Process '{name}' (PID {pid}) already exited"
        except psutil.AccessDenied:
            return f"Access denied terminating '{name}' (PID {pid}) — run as Administrator"
        except Exception as e:
            return f"Failed to terminate PID {pid}: {e}"

    # ── network enforcement ────────────────────────────────────────────────────

    def _handle_network(self, details: dict, event: dict) -> str:
        ip   = details.get('remote_ip', '')
        port = details.get('remote_port', '')

        if not ip:
            return "No IP in network event"

        rule_name = f"SENTINEL_BLOCK_{ip.replace('.','_')}"

        if self.dry_run:
            return f"[DRY-RUN] Would block outbound to {ip}:{port}"

        if _IS_WINDOWS:
            cmd = (
                f'netsh advfirewall firewall add rule '
                f'name="{rule_name}" dir=out action=block remoteip={ip}'
            )
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if r.returncode == 0:
                return f"Firewall rule added: blocked outbound to {ip}"
            return f"Firewall rule failed for {ip}: {r.stderr.strip()}"
        else:
            # Linux iptables
            r = subprocess.run(
                ['iptables', '-A', 'OUTPUT', '-d', ip, '-j', 'DROP'],
                capture_output=True, text=True
            )
            if r.returncode == 0:
                return f"iptables: blocked outbound to {ip}"
            return f"iptables failed: {r.stderr.strip()}"

    # ── file enforcement ──────────────────────────────────────────────────────

    def _handle_file(self, details: dict, event: dict) -> str:
        filepath = details.get('filepath', '')

        if not filepath or not os.path.exists(filepath):
            return f"File not found for quarantine: {filepath}"

        if self.dry_run:
            return f"[DRY-RUN] Would quarantine {os.path.basename(filepath)}"

        try:
            dest = os.path.join(QUARANTINE_DIR, os.path.basename(filepath))
            # Avoid overwrite
            if os.path.exists(dest):
                ts   = datetime.utcnow().strftime('%H%M%S')
                name, ext = os.path.splitext(os.path.basename(filepath))
                dest = os.path.join(QUARANTINE_DIR, f"{name}_{ts}{ext}")
            shutil.move(filepath, dest)
            return f"Quarantined '{os.path.basename(filepath)}' → {QUARANTINE_DIR}"
        except Exception as e:
            return f"Quarantine failed for {filepath}: {e}"

    # ── registry enforcement ──────────────────────────────────────────────────

    def _handle_registry(self, details: dict, event: dict) -> str:
        hive       = details.get('hive', '')
        key        = details.get('key', '')
        value_name = details.get('value_name', '')

        if not (hive and key and value_name):
            return "Incomplete registry details — cannot enforce"

        if self.dry_run:
            return f"[DRY-RUN] Would delete registry value {hive}\\{key}\\{value_name}"

        if not _IS_WINDOWS:
            return "Registry enforcement only available on Windows"

        try:
            # First, backup the value
            backup_dir = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                'logs', 'registry_backups'
            )
            os.makedirs(backup_dir, exist_ok=True)
            ts  = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            bak = os.path.join(backup_dir, f"backup_{ts}.reg")
            subprocess.run(
                f'reg export "{hive}\\{key}" "{bak}" /y',
                shell=True, capture_output=True
            )

            # Delete the malicious value
            r = subprocess.run(
                f'reg delete "{hive}\\{key}" /v "{value_name}" /f',
                shell=True, capture_output=True, text=True
            )
            if r.returncode == 0:
                return f"Deleted registry value '{value_name}' from {hive}\\{key}"
            return f"Registry delete failed: {r.stderr.strip()}"
        except Exception as e:
            return f"Registry enforcement error: {e}"

    # ── auth enforcement ──────────────────────────────────────────────────────

    def _handle_auth(self, details: dict, event: dict) -> str:
        username = details.get('username', '')
        count    = details.get('total_failures', 0)

        if not username or not _IS_WINDOWS:
            return f"Auth alert for '{username}' — manual review required"

        if self.dry_run:
            return f"[DRY-RUN] Would lock account '{username}'"

        try:
            r = subprocess.run(
                f'net user "{username}" /active:no',
                shell=True, capture_output=True, text=True
            )
            if r.returncode == 0:
                return f"Account '{username}' disabled after {count} failed attempts"
            return f"Account lock failed for '{username}': {r.stderr.strip()}"
        except Exception as e:
            return f"Auth enforcement error: {e}"

    # ── kill chain enforcement ────────────────────────────────────────────────

    def _handle_kill_chain(self, details: dict, event: dict) -> str:
        agents = details.get('agents_involved', [])
        if self.dry_run:
            return f"[DRY-RUN] Kill chain isolation — would quarantine agents: {agents}"
        # For kill chain: suspend all involved agent monitors and alert
        return (
            f"KILL CHAIN DETECTED across {len(agents)} subsystems "
            f"({', '.join(agents)}). All blocked events enforced. "
            f"Immediate review required."
        )

    # ── status ────────────────────────────────────────────────────────────────

    def get_recent_actions(self, n=20):
        with self._lock:
            return list(self._actions_taken[-n:])
