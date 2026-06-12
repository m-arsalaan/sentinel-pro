"""
SENTINEL PRO - Flask Application
Real-time security dashboard with WebSocket streaming.
"""

import os, sys, json, threading, time
from datetime import datetime

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
from flask_cors import CORS

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from orchestrator.orchestrator import SentinelOrchestrator
from core.logger import get_event_stats, get_recent_events

app = Flask(__name__)
app.config['SECRET_KEY'] = 'sentinel-pro-secret-2025'
CORS(app)

socketio  = SocketIO(app, cors_allowed_origins='*', async_mode='threading')
orchestrator: SentinelOrchestrator = None


# ── routes ────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/status')
def api_status():
    return jsonify(orchestrator.get_status() if orchestrator else {'error': 'not running'})


@app.route('/api/events')
def api_events():
    limit    = int(request.args.get('limit', 100))
    agent    = request.args.get('agent')
    decision = request.args.get('decision')
    min_risk = int(request.args.get('min_risk', 0))
    events   = orchestrator.logger.get_recent_events(limit, agent, decision, min_risk) if orchestrator else []
    return jsonify(events)


@app.route('/api/stats')
def api_stats():
    return jsonify(get_event_stats())


@app.route('/api/enforcement/actions')
def api_enforcement():
    if orchestrator:
        return jsonify(orchestrator.enforcer.get_recent_actions(50))
    return jsonify([])


@app.route('/api/enforcement/toggle', methods=['POST'])
def api_toggle_enforcement():
    if orchestrator:
        orchestrator.enforcer.dry_run = not orchestrator.enforcer.dry_run
        mode = 'DRY-RUN' if orchestrator.enforcer.dry_run else 'LIVE'
        return jsonify({'mode': mode, 'dry_run': orchestrator.enforcer.dry_run})
    return jsonify({'error': 'not running'}), 500


@app.route('/api/attack/<attack_type>', methods=['POST'])
def api_launch_attack(attack_type):
    """Launch a simulated attack for demo purposes."""
    import subprocess

    scripts = {
        'cpu':      'tests/cpu_attack.py',
        'file':     'tests/file_attack.py',
        'network':  'tests/network_attack.py',
        'auth':     'tests/auth_attack.py',
        'registry': 'tests/registry_attack.py',
    }

    if attack_type == 'all':
        launched = []
        for atype, script in scripts.items():
            if os.path.exists(script):
                _launch_script(script)
                launched.append(atype)
        return jsonify({'status': 'launched', 'attacks': launched})

    script = scripts.get(attack_type)
    if script and os.path.exists(script):
        _launch_script(script)
        return jsonify({'status': 'launched', 'attack': attack_type})

    return jsonify({'error': f'Unknown attack: {attack_type}'}), 404


def _launch_script(script: str):
    import subprocess
    try:
        kwargs = {'creationflags': subprocess.CREATE_NEW_CONSOLE}
        subprocess.Popen(['python', script], **kwargs)
    except (AttributeError, TypeError):
        subprocess.Popen(['python3', script])


@app.route('/api/agent/<agent_name>/toggle', methods=['POST'])
def api_toggle_agent(agent_name):
    if orchestrator and agent_name in orchestrator.agents:
        agent = orchestrator.agents[agent_name]
        if agent.running:
            agent.stop()
            return jsonify({'agent': agent_name, 'status': 'stopped'})
        else:
            agent.start()
            return jsonify({'agent': agent_name, 'status': 'started'})
    return jsonify({'error': 'agent not found'}), 404


# ── WebSocket ─────────────────────────────────────────────────────────────────

@socketio.on('connect')
def handle_connect():
    print("[WS] Client connected")
    emit('connected', {'status': 'connected', 'version': 'SENTINEL PRO 2.0'})
    if orchestrator:
        emit('status_update', orchestrator.get_status())


@socketio.on('disconnect')
def handle_disconnect():
    print("[WS] Client disconnected")


@socketio.on('request_events')
def handle_request_events(data):
    limit = data.get('limit', 50) if data else 50
    if orchestrator:
        events = orchestrator.get_recent_events(limit)
        emit('events_batch', events)


def _broadcast_loop():
    """Background thread — pushes stats and status every 3 seconds."""
    while True:
        try:
            if orchestrator:
                socketio.emit('stats_update',  get_event_stats())
                socketio.emit('status_update', orchestrator.get_status())
        except Exception as e:
            pass
        time.sleep(3)


# ── app factory ───────────────────────────────────────────────────────────────

def create_app(dry_run=False):
    global orchestrator

    orchestrator = SentinelOrchestrator(dry_run=dry_run)

    # Wire WebSocket callback into orchestrator
    def ws_event_callback(event):
        socketio.emit('security_event', event)

    orchestrator.ws_callback = ws_event_callback
    orchestrator.start()

    threading.Thread(target=_broadcast_loop, daemon=True).start()

    print("=" * 60)
    print("  SENTINEL PRO Dashboard → http://127.0.0.1:5000")
    print(f"  Enforcement mode       → {'DRY-RUN' if dry_run else 'LIVE (real actions)'}")
    print("=" * 60)

    return app


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--dry-run', action='store_true',
                        help='Log enforcement actions without executing them')
    args = parser.parse_args()

    app = create_app(dry_run=args.dry_run)
    socketio.run(app, host='127.0.0.1', port=5000,
                 debug=False, allow_unsafe_werkzeug=True)
