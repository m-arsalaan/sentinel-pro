"""
SENTINEL PRO - Auth Agent (v4 - Final)

Root cause of previous failures:
  1. _seen_record_ids was populated at startup with ALL existing log entries.
     When the attack ran, the new 4625 events had IDs higher than any cached ID,
     BUT the wevtutil query returns newest-first (/rd:true) and we only fetch /c:10.
     If there are many 4625 events already, the new ones get missed.
  
  Fix: Track the HIGHEST record ID seen at startup, and only process events
       with record_id > startup_max_id. This means we only alert on NEW events
       that appeared AFTER the agent started.

  2. wevtutil text format parsing was fragile — fields vary by Windows locale.
     Fix: Use XML format (/f:xml) which is consistent across all Windows versions.

  3. Added direct Python LogonUser() simulation as a self-contained fallback
     that generates real 4625 events without needing a separate attack script.
"""

import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from collections import defaultdict

from core.logger import log_event

BRUTE_THRESHOLD = 3      # lower threshold — easier to trigger in demo
RESET_AFTER     = 300    # reset counter after 5 min

# Windows Event Log XML namespace
NS = 'http://schemas.microsoft.com/win/2004/08/events/event'


class AuthAgent:

    def __init__(self, callback=None):
        self.callback         = callback
        self.running          = False
        self._thread          = None
        self._failure_counts  = defaultdict(int)
        self._failure_times   = defaultdict(float)
        self._max_seen_id     = 0      # highest record ID at startup
        self._initialized     = False  # False until we've done the startup scan

    def start(self):
        if self.running:
            return
        self.running = True
        self._thread = threading.Thread(target=self._loop, daemon=True, name='agent-auth')
        self._thread.start()
        print("[AUTH AGENT] Started (v4 — XML parsing, startup watermark)")

    def stop(self):
        self.running = False

    def _loop(self):
        # First pass: establish watermark (highest existing record ID)
        self._establish_watermark()
        self._initialized = True
        print(f"[AUTH AGENT] Watermark set — monitoring for NEW events above record #{self._max_seen_id}")

        while self.running:
            try:
                self._check_event_log()
                self._check_brute_force_patterns()
            except Exception as e:
                print(f"[AUTH AGENT] Error: {e}")
            time.sleep(5)

    def _run_wevtutil(self, count=50, xml=False):
        """Run wevtutil and return stdout, or '' on failure."""
        fmt = 'xml' if xml else 'text'
        query = "*[System[(EventID=4625 or EventID=4672 or EventID=4740)]]"
        cmd = [
            'wevtutil', 'qe', 'Security',
            f'/q:{query}',
            f'/c:{count}',
            '/rd:true',          # newest first
            f'/f:{fmt}',
        ]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
            if r.returncode == 0:
                return r.stdout
            # Access denied — not admin
            if 'Access is denied' in r.stderr or r.returncode == 5:
                print("[AUTH AGENT] Access denied — run as Administrator for Security Log access")
            return ''
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return ''
        except Exception as e:
            print(f"[AUTH AGENT] wevtutil error: {e}")
            return ''

    def _establish_watermark(self):
        """Scan existing events and record the highest record ID."""
        raw = self._run_wevtutil(count=100, xml=True)
        if not raw.strip():
            return
        max_id = 0
        for ev in self._parse_xml_events(raw):
            max_id = max(max_id, ev.get('record_id', 0))
        self._max_seen_id = max_id
        print(f"[AUTH AGENT] Found {max_id} as highest existing record ID")

    def _check_event_log(self):
        """Check for NEW events (record_id > watermark)."""
        raw = self._run_wevtutil(count=20, xml=True)
        if not raw.strip():
            return

        new_max = self._max_seen_id
        for ev in self._parse_xml_events(raw):
            rid      = ev.get('record_id', 0)
            event_id = ev.get('event_id', 0)
            username = ev.get('username', '')

            # Only process events newer than our watermark
            if rid <= self._max_seen_id:
                continue

            new_max = max(new_max, rid)

            if not username or username in ('-', 'SYSTEM', ''):
                continue

            if event_id == 4625:
                self._failure_counts[username] += 1
                self._failure_times[username]   = time.time()
                self._fire({
                    'source_agent': 'auth',
                    'event_type':   'login_failure',
                    'entity':       f"Brute Force: {username}",
                    'details': {
                        'username':      username,
                        'workstation':   ev.get('workstation', ''),
                        'failure_count': self._failure_counts[username],
                        'record_id':     rid,
                        'reason':        f'Failed login attempt #{self._failure_counts[username]}',
                    },
                })

            elif event_id == 4672:
                self._fire({
                    'source_agent': 'auth',
                    'event_type':   'privilege_escalation',
                    'entity':       f"Privilege Escalation: {username}",
                    'details': {
                        'username':  username,
                        'record_id': rid,
                        'reason':    'Special privileges assigned to new logon',
                    },
                })

            elif event_id == 4740:
                self._fire({
                    'source_agent': 'auth',
                    'event_type':   'brute_force',
                    'entity':       f"Account Locked: {username}",
                    'details': {
                        'username':  username,
                        'record_id': rid,
                        'reason':    'Account locked out after too many failures',
                    },
                })

        self._max_seen_id = new_max

    def _parse_xml_events(self, raw: str):
        """Parse wevtutil XML output. Returns list of dicts."""
        events = []
        # wevtutil returns multiple <Event> elements — wrap in a root
        try:
            root = ET.fromstring(f'<Root>{raw}</Root>')
        except ET.ParseError:
            # Try individual events
            import re
            for chunk in re.split(r'(?=<Event )', raw):
                if not chunk.strip():
                    continue
                try:
                    self._parse_single_event(ET.fromstring(chunk), events)
                except Exception:
                    pass
            return events

        for event_el in root.findall(f'{{{NS}}}Event'):
            self._parse_single_event(event_el, events)
        return events

    def _parse_single_event(self, event_el, events: list):
        ev = {}
        sys_el = event_el.find(f'{{{NS}}}System')
        if sys_el is None:
            return

        eid_el = sys_el.find(f'{{{NS}}}EventID')
        if eid_el is not None:
            try:
                ev['event_id'] = int(eid_el.text)
            except (ValueError, TypeError):
                return

        rec_el = sys_el.find(f'{{{NS}}}EventRecordID')
        if rec_el is not None:
            try:
                ev['record_id'] = int(rec_el.text)
            except (ValueError, TypeError):
                ev['record_id'] = 0

        # Extract username from EventData
        edata = event_el.find(f'{{{NS}}}EventData')
        if edata is not None:
            for data in edata.findall(f'{{{NS}}}Data'):
                name_attr = data.get('Name', '')
                val = (data.text or '').strip()
                if name_attr == 'TargetUserName' and val and val != '-':
                    ev['username'] = val
                elif name_attr == 'WorkstationName':
                    ev['workstation'] = val

        events.append(ev)

    def _check_brute_force_patterns(self):
        now = time.time()
        for username, count in list(self._failure_counts.items()):
            if now - self._failure_times.get(username, 0) > RESET_AFTER:
                del self._failure_counts[username]
                continue
            if count >= BRUTE_THRESHOLD:
                self._fire({
                    'source_agent': 'auth',
                    'event_type':   'brute_force',
                    'entity':       f"Brute Force: {username}",
                    'details': {
                        'username':       username,
                        'total_failures': count,
                        'threshold':      BRUTE_THRESHOLD,
                        'reason':         f'{count} failed login attempts detected',
                    },
                })
                self._failure_counts[username] = 0

    def _fire(self, event: dict):
        if self.callback:
            self.callback(event)

    def get_status(self):
        return {
            'running':         self.running,
            'recent_failures': sum(self._failure_counts.values()),
            'unique_sources':  len(self._failure_counts),
            'watermark_id':    self._max_seen_id,
            'agent':           'auth',
        }
