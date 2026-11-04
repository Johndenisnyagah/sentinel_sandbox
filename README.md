# Sentinel_Sandbox

An educational **attack simulator with a detection dashboard**. You trigger synthetic attacks (brute force, port scan, traffic flood, SYN flood, SQL injection probes) and watch the resulting events and alerts stream into a SOC-style dashboard over a WebSocket.

**[Live demo](https://sentinel-sanbox.vercel.app/)** (the backend runs on a free tier and may take a minute to wake up)

## What it does today

Be clear about what is real and what is simulated:

| Part | Status |
|---|---|
| Attack simulations (5 types) | Real code, synthetic data. Each one emits a sequence of events with randomised source IPs. |
| Alerts | **Scripted.** Each simulation currently raises its own alert at the end; no rule evaluates the events yet. |
| Detection rules panel | **Display only.** The thresholds in the `rules` table are shown but not yet applied. |
| Live packet sniffing (Scapy) and host monitoring (psutil) | Present in `detector.py` but **switched off** (needs root, and has known bugs). |
| Traffic chart | **Placeholder values**, not measured traffic. |
| Persistence | Real. Alerts and events are stored in SQLite and served by the API. |

Turning the scripted alerts into a real threshold engine is the next step (see the roadmap).

## Architecture

- **Backend (Python, FastAPI):** `main.py` serves the REST API and a WebSocket that broadcasts events and alerts. `app/simulation/attacker.py` generates the attack sequences. `app/engine/detector.py` holds the (disabled) Scapy/psutil monitor. `app/db/database.py` manages SQLite.
- **Frontend (React, Vite):** subscribes to the WebSocket and renders status, alerts, an activity feed, the rules list and the simulation controls. Styled with Tailwind CSS v4.

## Getting started

Prerequisites: Python 3.10+ and Node.js 18+.

```bash
# Backend (http://localhost:8000)
cd backend
pip install -r requirements.txt
python -m uvicorn main:app --reload

# Frontend (http://localhost:5173)
cd frontend
cp .env.example .env
npm install
npm run dev
```

## Roadmap

1. A rule engine that applies the `rules` table thresholds to the event stream in sliding time windows, so alerts are detected rather than scripted.
2. Fix the disabled live monitor (duplicate alert writes, broadcasting from the sniffer thread, port-scan time window).
3. Check the WebSocket `Origin` header (cross-site WebSocket hijacking, CWE-1385).
4. Plot real event rates instead of placeholder chart values.
5. Tests and CI.

## License

MIT, see [LICENSE](LICENSE).
