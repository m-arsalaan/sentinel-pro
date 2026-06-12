<div align="center">

# SENTINEL PRO
### Zero Trust OS Security Framework

**Real-Time Endpoint Monitoring · ML Risk Scoring · MITRE ATT&CK Kill Chain · Automated OS Enforcement**

[![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11-blue?style=flat-square&logo=windows)](https://microsoft.com/windows)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Zero Trust](https://img.shields.io/badge/Security-Zero%20Trust-red?style=flat-square)](https://csrc.nist.gov/publications/detail/sp/800-207/final)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-orange?style=flat-square)](https://attack.mitre.org/)

</div>

---

## What is SENTINEL PRO?

SENTINEL PRO is a real-time Windows endpoint security framework built on the **Zero Trust** security model. It monitors your machine across five OS-level attack surfaces simultaneously, scores every event using **Isolation Forest** machine learning, detects coordinated multi-stage attacks via **MITRE ATT&CK kill chain correlation**, and executes real OS-level enforcement — all using documented Windows APIs.

> *"Never Trust. Always Verify. Assume Breach."* — NIST SP 800-207

Built as a semester project for **Operating System LAB** at **Air University, Islamabad** (BS Cybersecurity 4-B, 2026) to demonstrate every major OS concept in a practical, working security context.

---

## Features

| Feature | Description |
|---|---|
| **5 Monitoring Agents** | Process, File, Network, Auth, Registry — all as concurrent daemon threads |
| **ML Risk Engine** | Isolation Forest + heuristic scoring, blended 60/40, trains on live data |
| **Kill Chain Detector** | 90-second sliding window, 3+ agents = MITRE ATT&CK alert, risk 95 |
| **Enforcement Engine** | Process kill, firewall block, file quarantine, registry delete, account disable |
| **Real-Time Dashboard** | Flask + Socket.IO at localhost:5000, live event feed, risk gauge, charts |
| **Attack Simulator** | 5 built-in attack scripts — CPU storm, ransomware, C2 beacon, brute force, persistence |
| **DRY-RUN / LIVE** | Toggle enforcement mode from dashboard without restarting |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Windows OS APIs                              │
├──────────┬──────────┬──────────────┬────────────┬───────────────┤
│ Process  │   File   │   Network    │    Auth    │   Registry    │
│ psutil   │ watchdog │ net_conns    │ wevtutil   │   reg.exe     │
│  (5s)    │  (RT)    │   (5s)       │   (5s)     │    (5s)       │
└────┬─────┴────┬─────┴──────┬───────┴─────┬──────┴───────┬───────┘
     └──────────┴────────────┴─────────────┴──────────────┘
                           callback(event)
                                 │
                    ┌────────────▼────────────┐
                    │      Orchestrator        │
                    │  ┌──────────────────┐   │
                    │  │   Event Queue    │   │
                    │  │  queue.Queue     │   │
                    │  │  (max 5,000)     │   │
                    │  └────────┬─────────┘   │
                    │           │             │
                    │  ┌────────▼──────────┐  │
                    │  │  ML Risk Engine   │  │
                    │  │  Isolation Forest │  │
                    │  │  score: 0–100     │  │
                    │  └────────┬──────────┘  │
                    │           │             │
                    │  ┌────────▼──────────┐  │
                    │  │  Kill Chain       │  │
                    │  │  90s window       │  │
                    │  │  3+ agents=alert  │  │
                    │  └────────┬──────────┘  │
                    │           │             │
                    │  ┌────────▼──────────┐  │
                    │  │  Enforcement      │  │
                    │  │  kill·block       │  │
                    │  │  quarantine·delete│  │
                    │  └───────────────────┘  │
                    └─────────────────────────┘
                              │        │
                    ┌─────────▼──┐  ┌──▼──────────┐
                    │Flask+SockIO│  │SQLite Logger │
                    │ :5000      │  │sentinel.db   │
                    └─────────┬──┘  └─────────────-┘
                              │ WebSocket
                    ┌─────────▼───────────────────────┐
                    │     Browser Dashboard            │
                    │  localhost:5000                  │
                    └──────────────────────────────────┘
```

---

## OS Concepts Demonstrated

| OS Concept | Implementation |
|---|---|
| **Process Management** | `psutil.process_iter()` → `NtQuerySystemInformation` kernel API |
| **Threads & Concurrency** | 5 daemon threads + orchestrator + ML trainer + broadcast thread |
| **Synchronisation** | `threading.Lock()` on SQLite writes, kill chain cooldown, agent state |
| **IPC** | `queue.Queue` (shared memory), WebSocket, subprocess pipes, REST HTTP |
| **System Calls** | `NtQuerySystemInformation`, `GetExtendedTcpTable`, `ReadDirectoryChangesW`, `NtQueryValueKey`, `TerminateProcess` |
| **File System** | `ReadDirectoryChangesW` async kernel notifications, atomic `shutil.move()` for quarantine |
| **Process Termination** | `psutil.Process(pid).terminate()` → `TerminateProcess()` on Windows |
| **Scheduling** | Per-agent intervals (2s/3s/5s), event-driven ML retraining, time-based kill chain window |
| **Memory Management** | Bounded queue (5,000), hot cache (1,000 events), GIL discussion |
| **Network Stack** | `GetExtendedTcpTable`, Windows Filtering Platform via `netsh advfirewall` |
| **Database I/O** | SQLite WAL mode, B-tree indexes, `threading.Lock()` for concurrent writes |
| **Python GIL** | Switched `cpu_attack.py` from `threading` → `multiprocessing` to achieve true parallelism |

---

## MITRE ATT&CK Mapping

| Agent | Tactic | ID | Technique |
|---|---|---|---|
| Process Agent | Execution | TA0002 | T1059 — Command & Scripting Interpreter |
| File Agent | Impact | TA0040 | T1486 — Data Encrypted for Impact |
| Network Agent | Command & Control | TA0011 | T1071 — Application Layer Protocol |
| Auth Agent | Credential Access | TA0006 | T1110 — Brute Force |
| Registry Agent | Persistence | TA0003 | T1547.001 — Boot/Logon Autostart (Run key) |

---

## Project Structure

```
SENTINEL_PRO/
├── app.py                          # Flask app, REST API, Socket.IO, attack launcher
├── requirements.txt                # All dependencies
├── README.md
│
├── orchestrator/
│   └── orchestrator.py             # Event pipeline, agent lifecycle, WebSocket bridge
│
├── agents/
│   ├── __init__.py
│   ├── process_agent.py            # psutil · NtQuerySystemInformation · every 5s
│   ├── file_agent.py               # watchdog · ReadDirectoryChangesW · real-time
│   ├── network_agent.py            # psutil.net_connections · GetExtendedTcpTable · every 5s
│   ├── auth_agent.py               # wevtutil · Event IDs 4625/4672/4740 · every 5s
│   └── registry_agent.py           # reg.exe query · baseline diff · every 5s
│
├── core/
│   ├── risk_engine.py              # Isolation Forest + heuristic blended scoring
│   ├── kill_chain.py               # Sliding window · MITRE ATT&CK · 90s window
│   ├── enforcer.py                 # Real OS enforcement · DRY-RUN / LIVE modes
│   └── logger.py                   # SQLite · JSONL mirror · hot cache · WAL mode
│
├── templates/
│   └── index.html                  # Real-time dashboard · Chart.js · Socket.IO
│
├── tests/
│   ├── cpu_attack.py               # CPU storm · multiprocessing · GIL bypass
│   ├── file_attack.py              # .locked ransomware extension simulation
│   ├── network_attack.py           # C2 beacon · port scan simulation
│   ├── auth_attack.py              # Brute force · Event ID 4625 generation
│   └── registry_attack.py          # Persistence · HKCU Run key write
│
├── logs/                           # sentinel.db + sentinel_events.log (auto-created)
├── ml/                             # risk_model.pkl (auto-created after 200 events)
└── quarantine/                     # Quarantined files (auto-created)
```

---

## Quick Start

### Prerequisites
- Windows 10 / 11
- Python 3.10+
- **Run as Administrator** (required for Auth Agent and Registry enforcement)

### Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/sentinel-pro.git
cd sentinel-pro

# Install dependencies
pip install -r requirements.txt

# Run in safe DRY-RUN mode (recommended for first run)
python app.py --dry-run
```

Open your browser at **http://127.0.0.1:5000**

### Running in LIVE enforcement mode

```bash
# All enforcement actions are REAL (process kill, firewall rules, file quarantine)
# Must be run as Administrator
python app.py
```

Or toggle from the dashboard Enforcement switch at any time.

---

## Attack Simulation

All attacks can be launched from the **Attack Simulator** panel on the dashboard, or manually:

```bash
# Ransomware simulation — creates .locked files
python tests/file_attack.py

# CPU storm — multiprocessing workers saturate CPU cores
python tests/cpu_attack.py

# C2 beacon — connects to suspicious ports (4444, 1337, etc.)
python tests/network_attack.py

# Brute force — generates Windows Event ID 4625 failures
python tests/auth_attack.py

# Persistence — writes to HKCU\...\CurrentVersion\Run
python tests/registry_attack.py
```

### Kill Chain Demo

Click **"Launch All Attacks (Kill Chain Demo)"** on the dashboard. All 5 agents detect their attacks within the 90-second window → Kill Chain fires at risk 95 → red banner appears → compound enforcement → all 5 MITRE ATT&CK stages detected in one correlated event.

---

## Detection Results

| Attack | Detection Time | Risk Score | Enforcement |
|---|---|---|---|
| Ransomware (.locked files) | < 1 second | 100 | File quarantined |
| CPU Storm (multiprocessing) | 5–8 seconds | 65 | Process terminated |
| C2 Beacon (port 4444) | < 3 seconds | 100 | Firewall rule added |
| Brute Force (Event 4625) | < 10 seconds | 100 | Account disabled |
| Registry Persistence (Run key) | < 5 seconds | 90 | reg export → reg delete |
| Kill Chain (all 5) | < 60 seconds | 95 | Compound enforcement |

Zero false positives observed during 30 minutes of normal system operation.

---

## Risk Scoring

```
Score 0–39   →  ALLOWED  (normal activity, silent log)
Score 40–69  →  FLAGGED  (suspicious, dashboard alert)
Score 70–100 →  BLOCKED  (enforcement action executed immediately)
```

**Heuristic mode** (always active): keyword + weight scoring, sub-millisecond response

**ML mode** (activates after 200 events): Isolation Forest, 200 estimators, contamination=0.08
Blended: **60% heuristic + 40% ML**

6D feature vector: `[agent_index, event_type_score, hour_of_day, heuristic_score, heuristic_score², entity_length]`

---

## Dashboard

| Section | Description |
|---|---|
| Metric cards (×7) | Blocked / Flagged / Allowed / Total / Kill Chains / Avg Risk / Enforced |
| Live Event Feed | Real-time events with agent/decision filters |
| Threat Level Gauge | Animated 0–100 risk gauge (Canvas) |
| Events by Agent | Live bar chart (Chart.js) |
| 24h Volume | Live line chart |
| Top Threats | Top 5 highest-risk events |
| Enforcement Log | All enforcement actions with timestamps |
| Attack Simulator | Launch any attack from the browser |
| Agent Toggle | Pause/resume individual agents at runtime |

---

## Technical Notes

**Why multiprocessing for the CPU attack?**
CPython's Global Interpreter Lock (GIL) means threads share one execution context — 4 threads still only use ~25% CPU. `multiprocessing` gives each worker its own Python interpreter + GIL, genuinely saturating multiple cores.

**Why queue.Queue instead of a list?**
`queue.Queue` is thread-safe internally (uses a mutex). A plain list with concurrent appends from 5 threads causes race conditions.

**Why WAL mode for SQLite?**
Write-Ahead Logging allows concurrent reads during a write. Without it, every log write would block the dashboard feed.

**Startup watermark in Auth Agent?**
`wevtutil` returns historical log entries on every call. The watermark records the highest `EventRecordID` at startup — only new events (higher IDs) are processed, preventing re-alerting on history.

---

## Tech Stack

```
Python 3.10+     Flask 3.0        Flask-SocketIO 5.3
psutil           watchdog         scikit-learn
SQLite3          Chart.js 4.4     Socket.IO 4.7
```

---

## Team

| Name | ID | Role |
|---|---|---|
| Muhammad Arslan | 241586 | Architecture, Agents, ML Engine |
| Zobia Rizwan | 241544 | Agents, Dashboard, Testing |
| Kiran Nawaz | 241504 | Kill Chain, Enforcement, Results |

**Instructor:** Ma'am Areeba Fatima
**Subject:** Operating System LAB — Air University, Islamabad
**Department:** Cyber Security · BS CYS 4-B · 2026

---

## References

- Liu, F. T., Ting, K. M., & Zhou, Z. H. (2008). Isolation Forest. *IEEE ICDM*
- Rose, S. et al. (2020). Zero Trust Architecture. *NIST SP 800-207*
- MITRE Corporation. (2023). *ATT&CK for Enterprise v14.0*
- US Department of Defense. (2022). *DoD Zero Trust Strategy*

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">
<b>SENTINEL PRO</b> · Built with documented Windows OS APIs and Python · Air University 2026
</div>
