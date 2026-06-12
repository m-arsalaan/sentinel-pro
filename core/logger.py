"""
SENTINEL PRO - Core Logger
SQLite-backed event storage with thread-safe operations and rich statistics.
"""

import os, json, sqlite3, threading
from datetime import datetime

_BASE    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_FILE  = os.path.join(_BASE, 'logs', 'sentinel.db')
LOG_FILE = os.path.join(_BASE, 'logs', 'sentinel_events.log')

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp    TEXT    NOT NULL,
    source_agent TEXT    NOT NULL,
    event_type   TEXT    NOT NULL,
    entity       TEXT    NOT NULL,
    risk_score   INTEGER NOT NULL DEFAULT 0,
    decision     TEXT    NOT NULL DEFAULT 'allowed',
    action_taken TEXT    DEFAULT NULL,
    details      TEXT    DEFAULT '{}',
    kill_chain   INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_ts       ON events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_agent    ON events(source_agent);
CREATE INDEX IF NOT EXISTS idx_decision ON events(decision);
CREATE INDEX IF NOT EXISTS idx_risk     ON events(risk_score DESC);
"""


class SentinelLogger:
    def __init__(self, db_file=None, log_file=None):
        self.db_file     = db_file  or DB_FILE
        self.log_file    = log_file or LOG_FILE
        self._lock       = threading.Lock()
        self._cache      = []
        self._cache_lock = threading.Lock()
        self._max_cache  = 1000
        os.makedirs(os.path.dirname(self.db_file),  exist_ok=True)
        os.makedirs(os.path.dirname(self.log_file), exist_ok=True)
        self._init_db()
        print(f"[LOGGER] SQLite DB  : {self.db_file}")
        print(f"[LOGGER] JSONL mirror: {self.log_file}")

    # ── internal ──────────────────────────────────────────────────────────────

    def _init_db(self):
        with self._conn() as c:
            c.executescript(_SCHEMA)

    def _conn(self):
        c = sqlite3.connect(self.db_file, check_same_thread=False)
        c.row_factory = sqlite3.Row
        return c

    # ── write ─────────────────────────────────────────────────────────────────

    def log_event(self, event: dict) -> dict:
        """Normalise, persist to SQLite + JSONL, cache. Returns the event."""
        now = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
        event.setdefault('timestamp',    now)
        event.setdefault('source_agent', 'unknown')
        event.setdefault('event_type',   'unknown')
        event.setdefault('entity',       'unknown')
        event.setdefault('risk_score',   0)
        event.setdefault('decision',     'allowed')
        event.setdefault('action_taken', None)
        event.setdefault('details',      {})
        event.setdefault('kill_chain',   False)

        try:
            with self._lock, self._conn() as c:
                c.execute(
                    "INSERT INTO events (timestamp,source_agent,event_type,entity,"
                    "risk_score,decision,action_taken,details,kill_chain) VALUES (?,?,?,?,?,?,?,?,?)",
                    (event['timestamp'], event['source_agent'], event['event_type'],
                     event['entity'],    event['risk_score'],   event['decision'],
                     event.get('action_taken'),
                     json.dumps(event.get('details', {})),
                     1 if event.get('kill_chain') else 0)
                )
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(json.dumps(event) + '\n')
        except Exception as e:
            print(f"[LOGGER] Write error: {e}")

        with self._cache_lock:
            self._cache.append(event)
            if len(self._cache) > self._max_cache:
                self._cache = self._cache[-self._max_cache:]

        return event

    # ── read ──────────────────────────────────────────────────────────────────

    def get_recent_events(self, limit=100, agent=None, decision=None, min_risk=0):
        try:
            q, p = "SELECT * FROM events WHERE risk_score >= ?", [min_risk]
            if agent:    q += " AND source_agent=?"; p.append(agent)
            if decision: q += " AND decision=?";     p.append(decision)
            q += " ORDER BY id DESC LIMIT ?"; p.append(limit)
            with self._conn() as c:
                rows = c.execute(q, p).fetchall()
            result = []
            for r in rows:
                e = dict(r)
                e['details']    = json.loads(e['details'] or '{}')
                e['kill_chain'] = bool(e['kill_chain'])
                result.append(e)
            return result
        except Exception as e:
            print(f"[LOGGER] Read error: {e}")
            with self._cache_lock:
                return list(reversed(self._cache[-limit:]))

    def get_stats(self):
        try:
            with self._conn() as c:
                r = c.execute("""
                    SELECT COUNT(*) AS total,
                           SUM(decision='blocked')  AS blocked,
                           SUM(decision='flagged')  AS flagged,
                           SUM(decision='allowed')  AS allowed,
                           ROUND(AVG(risk_score),1) AS avg_risk,
                           SUM(kill_chain)          AS kill_chains,
                           SUM(action_taken IS NOT NULL AND action_taken!='null') AS enforced
                    FROM events WHERE timestamp >= datetime('now','-1 hour')
                """).fetchone()
                by_agent    = c.execute(
                    "SELECT source_agent, COUNT(*) cnt FROM events "
                    "WHERE timestamp>=datetime('now','-1 hour') GROUP BY source_agent"
                ).fetchall()
                hourly      = c.execute(
                    "SELECT strftime('%H',timestamp) hr, COUNT(*) cnt FROM events "
                    "WHERE timestamp>=datetime('now','-24 hours') GROUP BY hr ORDER BY hr"
                ).fetchall()
                top_threats = c.execute(
                    "SELECT entity,risk_score,decision,source_agent FROM events "
                    "ORDER BY risk_score DESC LIMIT 5"
                ).fetchall()

            total   = r['total']   or 0
            blocked = r['blocked'] or 0
            return {
                'total_events': total,
                'blocked':      blocked,
                'flagged':      r['flagged']    or 0,
                'allowed':      r['allowed']    or 0,
                'avg_risk':     r['avg_risk']   or 0,
                'kill_chains':  r['kill_chains']or 0,
                'enforced':     r['enforced']   or 0,
                'block_rate':   round(blocked / total * 100, 1) if total else 0,
                'by_agent':     {x['source_agent']: x['cnt'] for x in by_agent},
                'hourly':       [{'hour': x['hr'], 'count': x['cnt']} for x in hourly],
                'top_threats':  [dict(x) for x in top_threats],
            }
        except Exception as e:
            print(f"[LOGGER] Stats error: {e}")
            return {'total_events': 0, 'blocked': 0, 'flagged': 0, 'allowed': 0,
                    'avg_risk': 0, 'kill_chains': 0, 'enforced': 0, 'block_rate': 0,
                    'by_agent': {}, 'hourly': [], 'top_threats': []}


# ── module-level singletons ───────────────────────────────────────────────────

_logger = None
_logger_lock = threading.Lock()

def _get_logger():
    global _logger
    with _logger_lock:
        if _logger is None:
            _logger = SentinelLogger()
    return _logger

def log_event(event):         return _get_logger().log_event(event)
def get_event_stats():        return _get_logger().get_stats()
def get_recent_events(n=100): return _get_logger().get_recent_events(n)
