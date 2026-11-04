# Sentinel_Sandbox

An educational **attack simulator with a detection dashboard**. You trigger synthetic attacks (brute force, port scan, traffic flood, SYN flood, SQL injection probes) and watch the resulting events and alerts stream into a SOC-style dashboard over a WebSocket.

**[Live demo](https://sentinel-sanbox.vercel.app/)** (the backend runs on a free tier and may take a minute to wake up)

## What it does today

Be clear about what is real and what is simulated:

| Part | Status |
|---|---|
| Attack simulations (5 types) | Real code, synthetic data. Each one emits a sequence of events (failed logins, port probes, packet bursts, SQLi payloads) from a random source IP. It never raises an alert itself. |
| Alerts | **Detected.** Every event goes through the rule engine (`app/engine/rules.py`), which counts it per source IP in a sliding window and alerts when a rule's threshold is exceeded. |
| Detection rules panel | Shows the same rows the engine applies, read from the `rules` table. |
| Live packet sniffing (Scapy) and host monitoring (psutil) | In `detector.py`, **off by default**: sniffing needs root, so it starts only with `SENTINEL_LIVE_MONITOR=1`. Detects port scans in a 10 s window and CPU above 90 %. |
| Traffic chart | **Placeholder values**, not measured traffic. |
| Persistence | Real. Alerts and events are stored in SQLite and served by the API. |

### How detection works

Each rule names the event type it watches, a measure, a threshold and a window:

| Rule | Watches | Measure | Fires when, per source IP |
|---|---|---|---|
| Brute Force | `failed_login` | count | more than 5 in 30 s |
| Port Scan | `connection_attempt` | distinct ports | more than 10 in 10 s |
| Traffic Flood | `traffic_burst` | sum of packets | more than 1000 in 60 s |
| SYN Flood | `syn_burst` | sum of packets | more than 50 in 5 s |
| SQLi Probe | `suspicious_query` | count | more than 3 in 10 s |
| Host Metric Anomaly | (live monitor only) | CPU % | above 90 % |

Old events drop out of the window as time passes, and a source's window is cleared after it fires, so one burst gives one alert. The simulations are sized to cross their rule's threshold. The tests cover the boundaries (5 failed logins no alert, 6 alert), the sliding window and each simulation end to end.

## Architecture

- **Backend (Python, FastAPI):** `main.py` serves the REST API and a WebSocket that broadcasts events and alerts. `app/simulation/attacker.py` generates the attack sequences. `app/engine/rules.py` is the threshold rule engine. `app/engine/detector.py` is the opt-in Scapy/psutil monitor. `app/db/database.py` manages SQLite.
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

1. Plot real event rates instead of placeholder chart values.

## License

MIT, see [LICENSE](LICENSE).
