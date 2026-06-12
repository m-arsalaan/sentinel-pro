"""
SENTINEL PRO - ML Risk Engine
Isolation Forest anomaly detection trained on live event data.
Falls back to heuristic scoring until enough data is collected.
"""

import os, json, threading, time, pickle
from datetime import datetime

# Optional sklearn import — graceful fallback
try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import LabelEncoder
    import numpy as np
    _ML_AVAILABLE = True
except ImportError:
    _ML_AVAILABLE = False
    print("[ML ENGINE] scikit-learn not installed — using heuristic scoring only")

# ── feature constants ─────────────────────────────────────────────────────────

AGENT_IDX = {'process': 0, 'file': 1, 'network': 2, 'auth': 3, 'registry': 4}
TYPE_IDX  = {
    'create':20, 'modify':25, 'delete':30, 'access':15,
    'connect':35, 'scan':40, 'login_failure':40, 'privilege_escalation':60,
    'persistence':55, 'ransomware':70, 'c2_beacon':70, 'dns_tunnel':50,
    'brute_force':55, 'high_cpu':35, 'unknown':15
}

MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          '..', 'ml', 'risk_model.pkl')


class MLRiskEngine:
    """
    Dual-mode risk scorer:
      - Heuristic mode: fast keyword + weight scoring (always available)
      - ML mode: Isolation Forest trained on accumulated event history
                 (activates automatically after MIN_SAMPLES events)
    """

    MIN_SAMPLES = 200          # train once we have this many events
    RETRAIN_EVERY = 500        # retrain after this many new events
    CONTAMINATION = 0.08       # expected anomaly rate (8%)

    def __init__(self):
        self._model         = None
        self._model_trained = False
        self._event_buffer  = []   # raw feature vectors for training
        self._buffer_lock   = threading.Lock()
        self._events_since_retrain = 0
        self._load_model()
        print(f"[ML ENGINE] ML available: {_ML_AVAILABLE}  |  Model loaded: {self._model_trained}")

    # ── public API ────────────────────────────────────────────────────────────

    def score(self, event: dict) -> int:
        """Return risk score 0-100 for an event."""
        heuristic = self._heuristic_score(event)
        features  = self._extract_features(event, heuristic)

        with self._buffer_lock:
            self._event_buffer.append(features)
            self._events_since_retrain += 1

        # Decide whether to trigger a retrain (background)
        if _ML_AVAILABLE:
            n = len(self._event_buffer)
            if (not self._model_trained and n >= self.MIN_SAMPLES) or \
               (self._model_trained and self._events_since_retrain >= self.RETRAIN_EVERY):
                threading.Thread(target=self._train, daemon=True).start()
                self._events_since_retrain = 0

        # Use ML score if model is ready
        if _ML_AVAILABLE and self._model_trained and self._model is not None:
            try:
                arr = np.array(features).reshape(1, -1)
                # decision_function: negative = anomalous; map to 0-100
                raw = float(self._model.decision_function(arr)[0])
                # typical range [-0.5, 0.5]; invert so anomalies → high score
                ml_score = int(max(0, min(100, (0.5 - raw) * 100)))
                # Blend heuristic 40% + ML 60%
                return min(100, int(heuristic * 0.4 + ml_score * 0.6))
            except Exception as e:
                print(f"[ML ENGINE] Scoring error: {e}")

        return heuristic

    # ── heuristic scoring (always available) ─────────────────────────────────

    def _heuristic_score(self, event: dict) -> int:
        score  = 0
        agent  = event.get('source_agent', '')
        etype  = event.get('event_type', '')
        entity = event.get('entity', '').lower()

        # Agent base weight
        agent_weights = {'process': 30, 'file': 35, 'network': 25, 'auth': 40, 'registry': 35}
        score += agent_weights.get(agent, 20)

        # Event type weight
        score += TYPE_IDX.get(etype, 15)

        # Entity keyword patterns
        if any(k in entity for k in ['malware','ransom','encrypt','backdoor','keylog']): score += 40
        if any(k in entity for k in ['admin','system','lsass','sam','ntds']):            score += 25
        if any(k in entity for k in ['powershell','cmd.exe','wscript','cscript','mshta']): score += 20
        if any(k in entity for k in ['185.','5.255','91.121','10.13','evil','c2 beacon','c2_beacon']): score += 35
        if any(k in entity for k in ['backdoor port','backdoor','beacon']):               score += 25
        if any(k in entity for k in ['debugger','appinit','shell','winlogon']):           score += 30
        if any(k in entity for k in ['disableantispyware','enablelua']):                  score += 35
        if 'brute' in entity or 'failed' in entity:                                       score += 20
        if 'locked' in entity or '.enc' in entity or '.crypt' in entity:                  score += 40

        return min(score, 100)

    # ── ML training ──────────────────────────────────────────────────────────

    def _extract_features(self, event: dict, heuristic: int) -> list:
        """Convert event → fixed-length numeric feature vector."""
        hour = datetime.utcnow().hour
        return [
            AGENT_IDX.get(event.get('source_agent',''), -1),   # [0] agent id
            TYPE_IDX.get(event.get('event_type',''), 15),       # [1] type weight
            heuristic,                                           # [2] heuristic score
            hour,                                                # [3] hour of day
            1 if event.get('kill_chain') else 0,                # [4] kill chain flag
            len(event.get('entity', '')),                        # [5] entity length
        ]

    def _train(self):
        """Train Isolation Forest on buffered events (runs in background thread)."""
        if not _ML_AVAILABLE:
            return
        with self._buffer_lock:
            data = list(self._event_buffer)
        if len(data) < self.MIN_SAMPLES:
            return
        try:
            import numpy as np
            X = np.array(data)
            model = IsolationForest(
                n_estimators=200,
                contamination=self.CONTAMINATION,
                random_state=42,
                n_jobs=-1,
            )
            model.fit(X)
            self._model         = model
            self._model_trained = True
            self._save_model(model)
            print(f"[ML ENGINE] Model trained on {len(data)} samples")
        except Exception as e:
            print(f"[ML ENGINE] Training error: {e}")

    def _save_model(self, model):
        try:
            os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
            with open(MODEL_PATH, 'wb') as f:
                pickle.dump(model, f)
        except Exception as e:
            print(f"[ML ENGINE] Save error: {e}")

    def _load_model(self):
        if not _ML_AVAILABLE:
            return
        try:
            if os.path.exists(MODEL_PATH):
                with open(MODEL_PATH, 'rb') as f:
                    self._model = pickle.load(f)
                self._model_trained = True
                print(f"[ML ENGINE] Loaded persisted model from {MODEL_PATH}")
        except Exception as e:
            print(f"[ML ENGINE] Load error: {e}")


# ── policy decision ───────────────────────────────────────────────────────────

def make_decision(risk_score: int, agent: str = '') -> str:
    """Zero Trust policy: nothing is trusted by default."""
    if risk_score >= 70: return 'blocked'
    if risk_score >= 40: return 'flagged'
    return 'allowed'
