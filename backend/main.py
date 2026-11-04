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

from app.db.database import get_db_connection, init_db, log_alert, log_event
from app.engine.detector import DetectionEngine
from app.simulation.attacker import SimulationModule

app = FastAPI(title="SentinelSandbox API")

# Configure CORS for production (Render/Vercel)
# Fetch allowed origins from environment variable, defaulting to wildcard
allowed_origins = os.getenv("ALLOWED_ORIGINS", "*").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize Database on startup
init_db()

# Track simulation and system stats globally
stats = {
    "packets_monitored": 0,
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

def on_alert(alert_data):
    """
    Callback triggered by the DetectionEngine or SimulationModule when a threat is identified.
    Persists the alert to the database and broadcasts it to connected UI clients.
    """
    # Persist to DB for history
    log_alert(
        alert_data.get("type", "Unknown"),
        alert_data.get("source_ip", alert_data.get("ip", "N/A")),
        alert_data.get("description", ""),
        alert_data.get("severity", "LOW"),
        alert_data.get("rule_name")
    )

    # Update global metrics
    stats["packets_monitored"] += alert_data.get("packets_detected", 1)

    # Broadcast to WebSocket clients
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.run_coroutine_threadsafe(manager.broadcast(alert_data), loop)
        else:
            asyncio.run(manager.broadcast(alert_data))
    except Exception as e:
        print(f"Error broadcasting alert: {e}")

def on_event(event_data):
    """
    Callback triggered for non-alert system events (e.g., intermediate simulation steps).
    Logs the activity and broadcasts it to the UI activity feed.
    """
    log_event(
        event_data.get("event_type", "unknown"),
        event_data.get("ip", "N/A"),
        event_data.get("details", "")
    )
    stats["packets_monitored"] += 1

    # Broadcast to WebSocket clients
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.run_coroutine_threadsafe(manager.broadcast(event_data), loop)
        else:
            asyncio.run(manager.broadcast(event_data))
    except Exception as e:
        print(f"Error broadcasting event: {e}")

# Initialize core modules
detector = DetectionEngine(on_alert)
attacker = SimulationModule(on_alert, on_event)

@app.on_event("startup")
async def startup_event():
    """Handles logic needed when the server starts up."""
    # Start the WebSocket heartbeat loop to prevent Render timeouts
    manager.start_heartbeat()
    # detector.start()  # Uncomment to enable live NIC monitoring (requires Admin/Sudo)

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
        "ids_running": True,
        "packets_monitored": stats["packets_monitored"] + event_count,
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
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
