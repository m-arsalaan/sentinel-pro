"""
SENTINEL PRO - Central Orchestrator
Coordinates all agents, ML risk scoring, kill chain detection, and enforcement.
"""

import os, sys, time, threading, queue
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.logger     import SentinelLogger, get_event_stats, get_recent_events
from core.risk_engine import MLRiskEngine, make_decision
from core.kill_chain  import KillChainDetector
from core.enforcer    import EnforcementEngine

from agents.process_agent  import ProcessAgent
from agents.file_agent     import FileAgent
from agents.network_agent  import NetworkAgent
from agents.auth_agent     import AuthAgent
from agents.registry_agent import RegistryAgent


class SentinelOrchestrator:
    """
    Central brain of SENTINEL PRO.

    Responsibilities:
    ─────────────────
    1. Agent lifecycle  — start / stop / health-check all five agents
    2. Event pipeline   — receive raw events → score → decide → enforce → log
    3. ML risk engine   — dynamic scoring that improves with data
    4. Kill chain       — cross-agent correlation within 90-second window
    5. Enforcement      — real OS actions on BLOCKED decisions
    6. Dashboard API    — provide status, events, stats to Flask
    """

    def __init__(self, dry_run=False):
        self.running    = False
        self.start_time = None
        self.dry_run    = dry_run
        self._lock      = threading.Lock()

        # Core subsystems
        self.logger   = SentinelLogger()
        self.scorer   = MLRiskEngine()
        self.killchain = KillChainDetector()
        self.enforcer  = EnforcementEngine(dry_run=dry_run)

        # Event queue for async processing
        self._event_queue = queue.Queue(maxsize=5000)

        # WebSocket callback (injected by app.py)
        self.ws_callback = None

        # Initialize agents
        self.agents = {
            'process':  ProcessAgent(callback=self._on_event),
            'file':     FileAgent(callback=self._on_event),
            'network':  NetworkAgent(callback=self._on_event),
            'auth':     AuthAgent(callback=self._on_event),
            'registry': RegistryAgent(callback=self._on_event),
        }

        print("[ORCHESTRATOR] SENTINEL PRO initialized")
        print(f"[ORCHESTRATOR] Agents: {', '.join(self.agents)}")
        print(f"[ORCHESTRATOR] Enforcement mode: {'DRY-RUN' if dry_run else 'LIVE'}")

    # ── lifecycle ─────────────────────────────────────────────────────────────

    def start(self):
        if self.running:
            return
        self.running    = True
        self.start_time = time.time()

        # Start event processor thread
        threading.Thread(target=self._process_loop, daemon=True,
                         name='orchestrator-processor').start()

        # Start all agents
        for name, agent in self.agents.items():
            try:
                agent.start()
                print(f"[ORCHESTRATOR] Agent '{name}' — OK")
            except Exception as e:
                print(f"[ORCHESTRATOR] Agent '{name}' FAILED: {e}")

        print("[ORCHESTRATOR] SENTINEL PRO is active")

    def stop(self):
        self.running = False
        for name, agent in self.agents.items():
            try:
                agent.stop()
            except Exception as e:
                print(f"[ORCHESTRATOR] Stop error '{name}': {e}")
        print("[ORCHESTRATOR] SENTINEL PRO stopped")

    # ── event pipeline ────────────────────────────────────────────────────────

    def _on_event(self, event: dict):
        """Callback invoked by agents — queues for async processing."""
        try:
            self._event_queue.put_nowait(event)
        except queue.Full:
            # Drop oldest event to make room
            try:
                self._event_queue.get_nowait()
                self._event_queue.put_nowait(event)
            except Exception:
                pass

    def _process_loop(self):
        """Background thread — pulls events off queue and processes them."""
        while self.running:
            try:
                event = self._event_queue.get(timeout=0.5)
                self._process_event(event)
            except queue.Empty:
                continue
            except Exception as e:
                print(f"[ORCHESTRATOR] Process loop error: {e}")

    def _process_event(self, event: dict):
        """
        Full event pipeline:
        raw event → ML risk score → policy decision → kill chain check
        → enforcement → log → broadcast to WebSocket
        """
        # 1. ML risk scoring
        risk_score = self.scorer.score(event)
        event['risk_score'] = risk_score

        # 2. Policy decision
        event['decision'] = make_decision(risk_score, event.get('source_agent', ''))

        # 3. Kill chain detection
        kc_alert = self.killchain.add_event(event)
        if kc_alert:
            # Score and log the kill chain alert itself
            kc_alert['risk_score'] = 95
            kc_alert['decision']   = 'blocked'
            self.logger.log_event(kc_alert)
            if self.ws_callback:
                self.ws_callback(kc_alert)

        # 4. Enforcement (only for blocked events)
        action = None
        if event['decision'] == 'blocked':
            action = self.enforcer.enforce(event)
            event['action_taken'] = action

        # 5. Persist event
        self.logger.log_event(event)

        # 6. Broadcast to dashboard
        if self.ws_callback:
            self.ws_callback(event)

        # Console output
        agent    = event.get('source_agent', '?')
        entity   = event.get('entity', '?')[:60]
        decision = event.get('decision', '?').upper()
        risk     = event.get('risk_score', 0)
        tag      = '[KILL CHAIN]' if event.get('kill_chain') else ''
        print(f"[EVENT] [{agent:8s}] {decision:8s} (risk:{risk:3d}) {entity} {tag}")
        if action:
            print(f"         ↳ ACTION: {action}")

    # ── dashboard API ─────────────────────────────────────────────────────────

    def get_status(self):
        agent_statuses = {}
        for name, agent in self.agents.items():
            try:
                agent_statuses[name] = agent.get_status()
            except Exception as e:
                agent_statuses[name] = {'error': str(e)}

        return {
            'orchestrator': {
                'running':    self.running,
                'uptime':     time.time() - self.start_time if self.start_time else 0,
                'started_at': datetime.fromtimestamp(self.start_time).isoformat() if self.start_time else None,
                'queue_size': self._event_queue.qsize(),
                'dry_run':    self.dry_run,
                'ml_active':  self.scorer._model_trained,
            },
            'agents':      agent_statuses,
            'stats':       self.logger.get_stats(),
            'kill_chain':  self.killchain.get_window_summary(),
            'enforcement': {'recent_actions': self.enforcer.get_recent_actions(5)},
        }

    def get_recent_events(self, limit=100):
        return self.logger.get_recent_events(limit)
