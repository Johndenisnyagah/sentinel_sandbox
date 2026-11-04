# Security policy

Sentinel_Sandbox is an educational project. It generates synthetic attack traffic for a dashboard and should not be relied on as a production intrusion detection system.

## Reporting a vulnerability

Please use GitHub's **private vulnerability reporting** (Security tab → "Report a vulnerability") rather than a public issue. I aim to acknowledge reports within 14 days.

In scope: the backend API and WebSocket (`backend/`), and the dashboard (`frontend/`). Out of scope: findings that need root access on the host running the opt-in live monitor, and the synthetic payloads the simulations emit by design.
