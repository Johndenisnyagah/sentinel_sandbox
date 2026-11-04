"""
Attack Simulation Module for Sentinel_Sandbox.
Generates synthetic network events and security alerts to demonstrate
the IDS detection capabilities and UI response.
"""

import asyncio
import random
import time


class SimulationModule:
    """
    Simulates various cyber-attack patterns by emitting granular events
    followed by a final high-severity alert.
    """
    def __init__(self, alert_callback, event_callback):
        """
        Initializes the simulation module with dual callbacks.
        :param alert_callback: Triggered at the end of a successful simulation.
        :param event_callback: Triggered for each intermediate 'step' of the attack.
        """
        self.trigger_alert = alert_callback
        self.emit_event = event_callback

    async def simulate_brute_force(self):
        """
        Simulates a Brute Force login attack.
        Patterns: Multiple rapid failed login events followed by a 'Brute Force' alert.
        """
        src_ip = f"192.168.1.{random.randint(2, 254)}"
        attempts = random.randint(5, 8)

        # ── Phase 1: Granular Login Failures ──
        # These events populate the Activity Feed in real-time
        for i in range(attempts):
            self.emit_event({
                "category": "event",
                "event_type": "login_attempt",
                "ip": src_ip,
                "details": f"Login attempt #{i+1} from {src_ip} — FAILED",
                "time": time.strftime("%H:%M:%S")
            })
            await asyncio.sleep(0.4) # Brief delay to make the feed 'live'

        # ── Phase 2: Final Detection Alert ──
        # Triggered when thresholds (simulated) are met
        self.trigger_alert({
            "category": "alert",
            "type": "Brute Force Attempt",
            "source_ip": src_ip,
            "description": f"{attempts} failed login attempts detected within 30 seconds",
            "severity": "HIGH",
            "rule_name": "Brute Force",
            "ports_accessed": None,
            "packets_detected": attempts,
            "time_window": "30s",
            "time": time.strftime("%H:%M:%S")
        })

    async def simulate_port_scan(self):
        """
        Simulates a TCP Port Scan (SYN stealth scan).
        Patterns: Sequential probes on multiple ports from a single source.
        """
        src_ip = f"10.0.0.{random.randint(2, 254)}"
        ports = sorted(random.sample(range(20, 1024), 15))

        # ── Phase 1: Port Probing ──
        for port in ports:
            self.emit_event({
                "category": "event",
                "event_type": "connection_attempt",
                "ip": src_ip,
                "details": f"SYN probe on port {port} from {src_ip}",
                "time": time.strftime("%H:%M:%S")
            })
            await asyncio.sleep(0.15)

        # ── Phase 2: Port Scan Alert ──
        self.trigger_alert({
            "category": "alert",
            "type": "Port Scan Detected",
            "source_ip": src_ip,
            "description": f"Multiple sequential port probes detected ({len(ports)} ports)",
            "severity": "CRITICAL",
            "rule_name": "Port Scan",
            "ports_accessed": ports,
            "packets_detected": len(ports) * 3,
            "time_window": "5s",
            "time": time.strftime("%H:%M:%S")
        })

    async def simulate_traffic_flood(self):
        """
        Simulates a DoS/Traffic Flood attack.
        Patterns: High volume packet spikes from a single source.
        """
        src_ip = f"172.16.0.{random.randint(2, 254)}"
        packet_count = random.randint(800, 1500)

        # ── Phase 1: Traffic Bursts ──
        # Simulates bursts of traffic appearing in the network activity graph
        for _ in range(5):
            chunk = packet_count // 5
            self.emit_event({
                "category": "event",
                "event_type": "traffic_spike",
                "ip": src_ip,
                "details": f"High volume burst from {src_ip}: {chunk} packets/s",
                "time": time.strftime("%H:%M:%S")
            })
            await asyncio.sleep(0.3)

        # ── Phase 2: Traffic Flood Alert ──
        self.trigger_alert({
            "category": "alert",
            "type": "Traffic Flood",
            "source_ip": src_ip,
            "description": f"Abnormal request volume: {packet_count} packets from single source",
            "severity": "MEDIUM",
            "rule_name": "Traffic Flood",
            "ports_accessed": None,
            "packets_detected": packet_count,
            "time_window": "60s",
            "time": time.strftime("%H:%M:%S")
        })

    async def simulate_ddos(self):
        """
        Simulates a DDoS/SYN Flood attack.
        Patterns: High intensity protocol spikes aimed at service disruption.
        """
        src_ip = f"185.22.{random.randint(10, 200)}.{random.randint(2, 254)}"
        self.emit_event({
            "category": "event",
            "event_type": "syn_flood",
            "ip": src_ip,
            "details": f"CRITICAL: SYN Flood burst detected from {src_ip}",
            "time": time.strftime("%H:%M:%S")
        })
        await asyncio.sleep(1)

        self.trigger_alert({
            "category": "alert",
            "type": "DDoS Botnet Pattern",
            "source_ip": src_ip,
            "description": "Rapid SYN packet sequence characteristic of botnet coordination",
            "severity": "CRITICAL",
            "rule_name": "DDoS Botnet Pattern",
            "ports_accessed": [80, 443],
            "packets_detected": 5000,
            "time_window": "5s",
            "time": time.strftime("%H:%M:%S")
        })

    async def simulate_sqli(self):
        """
        Simulates an SQL Injection probe.
        Patterns: URL parameter manipulation with SQL keywords.
        """
        src_ip = f"45.88.1.{random.randint(2, 254)}"
        payloads = ["' OR 1=1 --", "'; DROP TABLE users; --", "UNION SELECT null, username, password FROM users"]

        for payload in payloads:
            self.emit_event({
                "category": "event",
                "event_type": "suspicious_query",
                "ip": src_ip,
                "details": f"Malicious payload detected: {payload}",
                "time": time.strftime("%H:%M:%S")
            })
            await asyncio.sleep(0.8)

        self.trigger_alert({
            "category": "alert",
            "type": "SQLi Probe",
            "source_ip": src_ip,
            "description": "Multiple SQL injection patterns identified in HTTP request parameters",
            "severity": "HIGH",
            "rule_name": "SQLi Probe",
            "ports_accessed": [80, 443],
            "packets_detected": 12,
            "time_window": "10s",
            "time": time.strftime("%H:%M:%S")
        })
