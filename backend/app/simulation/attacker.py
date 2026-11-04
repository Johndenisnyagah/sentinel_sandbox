"""
Attack simulation module for Sentinel_Sandbox.

Each simulation emits a sequence of synthetic events, the kind of telemetry a
sensor or log source would produce. It does NOT decide whether that is an
attack: every event goes through the rule engine (``app/engine/rules.py``),
which raises the alert if a rule's threshold is crossed.

Each simulation is sized to cross its rule's threshold, with the margin noted
next to it, so the demo is predictable; the engine's tests cover the
boundaries.
"""

import asyncio
import random
import time

# Attack sizes: comfortably above each rule's threshold
BRUTE_FORCE_ATTEMPTS = 8  # rule: >5 failed logins / 30s
PORT_SCAN_PORTS = 15  # rule: >10 distinct ports / 10s
FLOOD_BURSTS, FLOOD_PACKETS_PER_BURST = 5, 240  # 1200 total; rule: >1000 packets / 60s
SYN_BURSTS, SYN_PACKETS_PER_BURST = 4, 20  # 80 total; rule: >50 SYN packets / 5s
SQLI_PAYLOADS = [  # 4 payloads; rule: >3 / 10s
    "' OR 1=1 --",
    "admin'--",
    "'; DROP TABLE users; --",
    "UNION SELECT null, username, password FROM users",
]


def _now():
    return time.strftime("%H:%M:%S")


class SimulationModule:
    """Generates synthetic attack telemetry."""

    def __init__(self, event_callback):
        """:param event_callback: receives every event (stores, broadcasts, evaluates)."""
        self.emit_event = event_callback

    def _emit(self, event_type, ip, details, **fields):
        self.emit_event(
            {"category": "event", "event_type": event_type, "ip": ip, "details": details, "time": _now(), **fields}
        )

    async def simulate_brute_force(self):
        """Repeated failed SSH logins from one address."""
        src_ip = f"192.168.1.{random.randint(2, 254)}"
        for i in range(BRUTE_FORCE_ATTEMPTS):
            self._emit("failed_login", src_ip, f"Failed password for root from {src_ip} (attempt {i + 1})")
            await asyncio.sleep(0.4)

    async def simulate_port_scan(self):
        """SYN probes across many distinct ports from one address."""
        src_ip = f"10.0.0.{random.randint(2, 254)}"
        for port in sorted(random.sample(range(20, 1024), PORT_SCAN_PORTS)):
            self._emit("connection_attempt", src_ip, f"SYN probe on port {port} from {src_ip}", port=port)
            await asyncio.sleep(0.15)

    async def simulate_traffic_flood(self):
        """High-volume bursts from one address."""
        src_ip = f"172.16.0.{random.randint(2, 254)}"
        for _ in range(FLOOD_BURSTS):
            self._emit(
                "traffic_burst",
                src_ip,
                f"Burst of {FLOOD_PACKETS_PER_BURST} packets from {src_ip}",
                packets=FLOOD_PACKETS_PER_BURST,
            )
            await asyncio.sleep(0.3)

    async def simulate_ddos(self):
        """SYN flood: rapid SYN bursts aimed at web ports (single source, so not a botnet)."""
        src_ip = f"185.22.{random.randint(10, 200)}.{random.randint(2, 254)}"
        for _ in range(SYN_BURSTS):
            self._emit(
                "syn_burst",
                src_ip,
                f"{SYN_PACKETS_PER_BURST} SYN packets to :80/:443 from {src_ip}",
                packets=SYN_PACKETS_PER_BURST,
            )
            await asyncio.sleep(0.25)

    async def simulate_sqli(self):
        """HTTP requests carrying SQL injection payloads."""
        src_ip = f"45.88.1.{random.randint(2, 254)}"
        for payload in SQLI_PAYLOADS:
            self._emit("suspicious_query", src_ip, f"Request parameter contains: {payload}")
            await asyncio.sleep(0.8)
