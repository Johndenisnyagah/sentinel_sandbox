# Changelog

## Unreleased (November 2026)

### Removed
- The hosted demo (Render backend, Vercel frontend) and its config files (`render.yaml`, `frontend/vercel.json`). The free-tier backend slept when idle and was too slow to use; the project now runs locally only. (#8)

## November 2026: detection made real

Findings from a portfolio audit, fixed in PRs #1–#7.

### Changed
- **Rule engine** (`app/engine/rules.py`). Simulations now emit events only. The engine applies the `rules` table to every event, per source IP, in sliding windows, using three measures: count, distinct and sum. Before this, each simulation raised its own alert, and the rules table was only displayed. (#5)
- "DDoS Botnet Pattern" renamed "SYN Flood", because it comes from a single source. "Unauthorized Access" removed, because nothing produced it. (#5)
- The chart plots the events received per 2 s instead of `Math.random()`. `/status` reports `events_processed` and `rules_active` instead of a double-counted `packets_monitored`. (#6)
- The live monitor is opt-in via `SENTINEL_LIVE_MONITOR=1`, and `/status` reports `live_monitor`. (#3)
- The README describes what is simulated and what is real. (#1, #7)

### Fixed
- One detector alert was stored twice. (#3)
- Alerts raised on the sniffer thread never reached the WebSocket ("no current event loop"). (#3)
- Port-scan detection had no time window. (#3)
- The WebSocket accepted connections from any origin (CWE-1385). It now checks `Origin`, and the CORS default is no longer `*`. (#4)
- Frontend: the reconnect timer referenced `connectWS` before it existed, and unmounting scheduled a reconnect. (#2)
- SQLite connections were never closed. Simulation tasks were not kept referenced, so they could be garbage-collected mid-run. (#7)
- LICENSE named "John Doe". (#1)

### Added
- 41 backend tests; CI for ruff, pytest, eslint and the frontend build. (#2 onwards)
- Dependabot (grouped per ecosystem), `SECURITY.md`, a dashboard screenshot. (#7)
- FastAPI lifespan handler instead of the deprecated `on_event`; `logging` instead of `print`; Python 3.12 on Render. (#7)

## v2.0 (March 2026)

First public version: FastAPI backend, five attack simulations, React dashboard, deployed to Render and Vercel.
