"""
SENTINEL PRO - Kill Chain Detector
Correlates events across multiple agents within a time window.
A multi-agent correlated sequence = likely attack kill chain.
"""

import time
import threading
from collections import deque


# MITRE ATT&CK-inspired kill-chain stages
STAGE_MAP = {
    'process':  'Execution',
    'network':  'Command & Control',
    'file':     'Impact / Exfiltration',
    'auth':     'Credential Access',
    'registry': 'Persistence',
}

# How many distinct agents must fire within the window to declare a kill chain
AGENT_THRESHOLD = 3    # >= 3 different agents
WINDOW_SECONDS  = 90   # within 90 seconds


class KillChainDetector:
    """
    Sliding-window kill chain detector.

    Call add_event(event) for every security event.
    Returns a kill-chain alert dict if a kill chain is confirmed, else None.
    """

    def __init__(self, window=WINDOW_SECONDS, threshold=AGENT_THRESHOLD):
        self._window    = window
        self._threshold = threshold
        self._events    = deque()     # (timestamp_float, agent, event_copy)
        self._lock      = threading.Lock()
        self._alerted   = False       # suppress duplicate alerts within same window
        self._alert_cooldown = 120    # seconds before re-alerting same kill chain
        self._last_alert_ts  = 0

    def add_event(self, event: dict):
        """
        Process a new event. Returns a kill-chain alert dict if kill chain
        is detected, otherwise returns None.
        """
        now = time.time()

        with self._lock:
            self._events.append((now, event.get('source_agent', 'unknown'), dict(event)))

            # Evict events outside the window
            while self._events and now - self._events[0][0] > self._window:
                self._events.popleft()

            # Count distinct agents in the current window
            window_events = list(self._events)
            agents_in_window = {e[1] for e in window_events}
            n_agents = len(agents_in_window)

            if n_agents >= self._threshold:
                # Cooldown check
                if now - self._last_alert_ts < self._alert_cooldown:
                    return None

                self._last_alert_ts = now
                stages = [STAGE_MAP.get(a, a.title()) for a in agents_in_window]

                # Build summary of contributing events
                contributors = [
                    {
                        'agent':      e[1],
                        'event_type': e[2].get('event_type', '?'),
                        'entity':     e[2].get('entity', '?'),
                        'risk_score': e[2].get('risk_score', 0),
                    }
                    for e in window_events
                ]

                alert = {
                    'source_agent': 'orchestrator',
                    'event_type':   'kill_chain',
                    'entity':       f"Kill Chain: {' → '.join(sorted(stages))}",
                    'risk_score':   95,
                    'decision':     'blocked',
                    'kill_chain':   True,
                    'details': {
                        'agents_involved':   sorted(agents_in_window),
                        'stages':            stages,
                        'event_count':       len(window_events),
                        'window_seconds':    self._window,
                        'contributors':      contributors[:10],
                        'description': (
                            f"Multi-stage attack detected across {n_agents} subsystems "
                            f"within {self._window}s. MITRE stages: {', '.join(stages)}."
                        ),
                    },
                }
                return alert

        return None

    def get_window_summary(self):
        """Return current window stats for dashboard."""
        now = time.time()
        with self._lock:
            active = [(ts, ag) for ts, ag, _ in self._events if now - ts <= self._window]
            agents = {a for _, a in active}
        return {
            'events_in_window': len(active),
            'agents_active':    sorted(agents),
            'threat_level':     min(len(agents) * 33, 99),
        }
