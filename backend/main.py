"""
Main entry point for the SentinelSandbox FastAPI backend.
Handles API routing, WebSocket connections, and coordination between
the detection engine and simulation modules.
"""

import asyncio
import os

import psutil
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from app.db.database import get_db_connection, init_db, load_rules, log_alert, log_event
from app.engine.detector import DetectionEngine
from app.engine.rules import RuleEngine
from app.simulation.attacker import SimulationModule

app = FastAPI(title="SentinelSandbox API")

# Origins allowed to call the API and open the WebSocket. Set ALLOWED_ORIGINS
# (comma-separated) in production, e.g. the Vercel frontend URL.
DEFAULT_ORIGINS = "http://localhost:5173,http://127.0.0.1:5173"
allowed_origins = [
    o.strip() for o in os.getenv("ALLOWED_ORIGINS", DEFAULT_ORIGINS).split(",") if o.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=False,  # no cookies or auth headers are used
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


def origin_allowed(origin: str | None) -> bool:
    """
    CORS does not apply to WebSockets: a page on any site can open one. So the
    WebSocket handshake checks Origin itself (cross-site WebSocket hijacking,
    CWE-1385). Clients that send no Origin (curl, scripts) are not browsers
    and cannot be driven by another site, so they are allowed.
    """
    return origin is None or "*" in allowed_origins or origin in allowed_origins


# Initialize Database on startup
init_db()

# Track simulation and system stats globally
stats = {
    "simulations_run": 0,
}

class ConnectionManager:
    """
    Manages active WebSocket connections for real-time alert/event broadcasting.
    Includes a heartbeat mechanism to prevent connection timeouts on hosting
    providers like Render (which closes idle connections after ~55s).
    """
    def __init__(self):
        self.active_connections: list[WebSocket] = []
        self.heartbeat_task: asyncio.Task | None = None

    async def connect(self, websocket: WebSocket):
        """Accepts a new WebSocket connection and adds it to the pool."""
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        """Removes a WebSocket connection from the pool."""
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        """Sends a JSON message to all currently connected clients."""
        if not self.active_connections:
            return

        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                disconnected.append(connection)

        for conn in disconnected:
            self.disconnect(conn)

    async def _heartbeat(self):
        """Background task that sends a keep-alive pulse every 30 seconds."""
        while True:
            await asyncio.sleep(30)
            if self.active_connections:
                await self.broadcast({"category": "system", "type": "pulse", "details": "heartbeat"})

    def start_heartbeat(self):
        """Standard entry point to launch the heartbeat loop."""
        if self.heartbeat_task is None:
            self.heartbeat_task = asyncio.create_task(self._heartbeat())

manager = ConnectionManager()

# The server's event loop, captured at startup. Alerts can come from the
# sniffer thread, which has no loop of its own, so they are handed over here.
main_loop: asyncio.AbstractEventLoop | None = None


def schedule_broadcast(message: dict):
    """Broadcast from any thread: on the loop thread schedule a task, elsewhere hand over safely."""
    if main_loop is None:
        return  # server not started (e.g. a unit test calling the callback directly)
    try:
        running = asyncio.get_running_loop()
    except RuntimeError:
        running = None
    if running is main_loop:
        main_loop.create_task(manager.broadcast(message))
    else:
        asyncio.run_coroutine_threadsafe(manager.broadcast(message), main_loop)

def on_alert(alert_data):
    """
    Called by the RuleEngine or the live DetectionEngine when a threat is identified.
    The single place that stores an alert; then broadcasts it to the UI.
    """
    # Persist to DB for history
    log_alert(
        alert_data.get("type", "Unknown"),
        alert_data.get("source_ip", alert_data.get("ip", "N/A")),
        alert_data.get("description", ""),
        alert_data.get("severity", "LOW"),
        alert_data.get("rule_name")
    )

    schedule_broadcast(alert_data)


def on_event(event_data):
    """
    Called for every telemetry event (from the simulations). Stores it, shows it
    in the activity feed, then hands it to the rule engine, which decides
    whether it completes an attack pattern.
    """
    log_event(
        event_data.get("event_type", "unknown"),
        event_data.get("ip", "N/A"),
        event_data.get("details", "")
    )
    schedule_broadcast(event_data)
    rule_engine.process(event_data)


# Initialize core modules
rule_engine = RuleEngine(load_rules(), on_alert)
detector = DetectionEngine(on_alert)
attacker = SimulationModule(on_event)

@app.on_event("startup")
async def startup_event():
    """Handles logic needed when the server starts up."""
    global main_loop
    main_loop = asyncio.get_running_loop()
    # Start the WebSocket heartbeat loop to prevent Render timeouts
    manager.start_heartbeat()
    # Live sniffing needs root, so it is opt-in
    if os.getenv("SENTINEL_LIVE_MONITOR") == "1":
        detector.start()

@app.on_event("shutdown")
async def shutdown_event():
    """Ensures clean shutdown of background monitoring threads."""
    detector.stop()

# ── Endpoints ──

@app.get("/")
async def root():
    """Basic health check endpoint."""
    return {"message": "SentinelSandbox IDS API is running"}

@app.get("/status")
async def get_status():
    """
    Returns high-level system metrics including database counts,
    active connections, and CPU usage.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) as cnt FROM alerts")
    alert_count = cursor.fetchone()["cnt"]
    cursor.execute("SELECT COUNT(*) as cnt FROM events")
    event_count = cursor.fetchone()["cnt"]
    conn.close()

    return {
        "ids_running": True,  # the API is up
        "live_monitor": detector.running,  # Scapy/psutil monitor (opt-in)
        "events_processed": event_count,
        "rules_active": len(rule_engine.rules),
        "alerts_triggered": alert_count,
        "active_connections": len(manager.active_connections),
        "cpu_usage": psutil.cpu_percent(interval=0),
        "simulations_run": stats["simulations_run"],
    }

@app.get("/alerts")
async def get_alerts():
    """Fetches the most recent 50 alerts from the database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 50")
    alerts = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return alerts

@app.get("/activity")
async def get_activity():
    """Fetches the most recent 100 activity feed events."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM events ORDER BY timestamp DESC LIMIT 100")
    events = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return events

@app.get("/rules")
async def get_rules():
    """Retrieves all active detection rules from the system."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM rules")
    rules = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rules

@app.post("/simulate")
async def simulate_attack(attack_type: str):
    """
    Triggers a background attack simulation to test detection and visual response.
    Valid types: BRUTE_FORCE, PORT_SCAN, TRAFFIC_FLOOD.
    """
    stats["simulations_run"] += 1
    if attack_type == "BRUTE_FORCE":
        asyncio.create_task(attacker.simulate_brute_force())
    elif attack_type == "PORT_SCAN":
        asyncio.create_task(attacker.simulate_port_scan())
    elif attack_type == "TRAFFIC_FLOOD":
        asyncio.create_task(attacker.simulate_traffic_flood())
    elif attack_type == "DDOS":
        asyncio.create_task(attacker.simulate_ddos())
    elif attack_type == "SQLI":
        asyncio.create_task(attacker.simulate_sqli())
    else:
        raise HTTPException(status_code=400, detail="Invalid attack type")

    return {"status": "simulation_started", "type": attack_type}

@app.websocket("/ws/alerts")
async def websocket_endpoint(websocket: WebSocket):
    """
    Main WebSocket entry point for the frontend dashboard.
    Keeps the connection open to receive broadcast updates.
    """
    if not origin_allowed(websocket.headers.get("origin")):
        await websocket.close(code=1008)  # before accept -> HTTP 403 on the handshake
        return
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
