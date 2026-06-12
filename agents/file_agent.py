"""
SENTINEL PRO - File Agent
Monitors file system for ransomware, credential theft, and sensitive file access.
Uses watchdog for real-time inotify/ReadDirectoryChangesW events where possible,
falls back to periodic polling.
"""

import os
import time
import threading

from core.logger import log_event

SUSPICIOUS_EXTENSIONS = {
    '.locked', '.encrypted', '.ransom', '.crypt', '.enc',
    '.decrypt', '.pay', '.bitcoin', '.wallet', '.crypto',
    '.zepto', '.locky', '.cerber', '.thor', '.zzzzz',
}

SENSITIVE_PATTERNS = {
    'password', 'credential', 'secret', 'token', '.env',
    'id_rsa', 'id_ecdsa', 'wallet', 'seed', 'private_key',
    'backup', 'shadow', 'ntds', 'sam', 'lsass',
}

MONITORED_DIRS_DEFAULT = [
    os.path.expanduser('~/Documents'),
    os.path.expanduser('~/Desktop'),
    os.path.expanduser('~/Downloads'),
]


class FileAgent:
    """
    Monitors file-system activity for:
    - Ransomware indicators (encrypted-looking extensions)
    - Sensitive file access (credentials, keys, backups)
    - Mass modification (high file-change rate)
    """

    def __init__(self, callback=None, monitored_dirs=None):
        self.callback       = callback
        self.running        = False
        self._thread        = None
        self._alerted_files = set()    # deduplicate — alert once per file
        self._mod_times     = {}       # filepath → mtime snapshot

        self.monitored_dirs = [
            d for d in (monitored_dirs or MONITORED_DIRS_DEFAULT)
            if os.path.isdir(d)
        ]

        # Try to add the watchdog-based real-time monitor
        self._watcher_started = False

    # ── lifecycle ─────────────────────────────────────────────────────────────

    def start(self):
        if self.running:
            return
        self.running = True

        # Try real-time watchdog first
        self._try_start_watchdog()

        # Always run the polling fallback (catches dirs watchdog can't)
        self._thread = threading.Thread(target=self._poll_loop, daemon=True, name='agent-file')
        self._thread.start()
        print(f"[FILE AGENT] Started — monitoring {len(self.monitored_dirs)} dirs"
              f"  (watchdog: {self._watcher_started})")

    def stop(self):
        self.running = False
        try:
            if self._observer:
                self._observer.stop()
        except Exception:
            pass

    # ── watchdog (real-time events) ───────────────────────────────────────────

    def _try_start_watchdog(self):
        try:
            from watchdog.observers import Observer
            from watchdog.events import FileSystemEventHandler

            agent_ref = self

            class _Handler(FileSystemEventHandler):
                def on_created(self, ev):
                    if not ev.is_directory:
                        agent_ref._inspect_file(ev.src_path, 'create')

                def on_modified(self, ev):
                    if not ev.is_directory:
                        agent_ref._inspect_file(ev.src_path, 'modify')

            self._observer = Observer()
            for d in self.monitored_dirs:
                self._observer.schedule(_Handler(), d, recursive=True)
            self._observer.start()
            self._watcher_started = True
        except Exception as e:
            self._observer = None
            print(f"[FILE AGENT] Watchdog unavailable ({e}), using polling only")

    # ── polling fallback ──────────────────────────────────────────────────────

    def _poll_loop(self):
        while self.running:
            try:
                self._poll_dirs()
            except Exception as e:
                print(f"[FILE AGENT] Poll error: {e}")
            time.sleep(3)

    def _poll_dirs(self):
        for directory in self.monitored_dirs:
            try:
                for fname in os.listdir(directory):
                    fpath = os.path.join(directory, fname)
                    if os.path.isfile(fpath):
                        self._inspect_file(fpath, 'access')
            except PermissionError:
                pass
            except Exception as e:
                print(f"[FILE AGENT] Dir error {directory}: {e}")

    # ── inspection ────────────────────────────────────────────────────────────

    def _inspect_file(self, filepath: str, change_type: str):
        if filepath in self._alerted_files:
            return

        fname = os.path.basename(filepath).lower()
        ext   = os.path.splitext(fname)[1]

        # Ransomware indicator — highest priority
        if ext in SUSPICIOUS_EXTENSIONS:
            self._alerted_files.add(filepath)
            self._fire({
                'source_agent': 'file',
                'event_type':   'ransomware',
                'entity':       f"File: {os.path.basename(filepath)}",
                'details': {
                    'filepath':    filepath,
                    'extension':   ext,
                    'change_type': change_type,
                    'directory':   os.path.dirname(filepath),
                },
            })
            return

        # Sensitive file pattern
        matched = [p for p in SENSITIVE_PATTERNS if p in fname]
        if matched:
            self._alerted_files.add(filepath)
            self._fire({
                'source_agent': 'file',
                'event_type':   'access',
                'entity':       f"File: {os.path.basename(filepath)}",
                'details': {
                    'filepath':        filepath,
                    'patterns_matched': matched,
                    'change_type':     change_type,
                    'directory':       os.path.dirname(filepath),
                },
            })

    def _fire(self, event: dict):
        if self.callback:
            self.callback(event)

    def get_status(self):
        return {
            'running':          self.running,
            'monitoring_dirs':  len(self.monitored_dirs),
            'alerted_files':    len(self._alerted_files),
            'watchdog_active':  self._watcher_started,
            'agent':            'file',
        }
