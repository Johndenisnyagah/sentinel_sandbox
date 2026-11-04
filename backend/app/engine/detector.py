"""
Core detection engine for Sentinel_Sandbox.
Provides packet-level analysis using Scapy and system-level monitoring
using psutil. Identifies threats based on threshold-based logic.
"""

import threading
import time

import psutil
from scapy.all import IP, TCP, UDP, sniff

from ..db.database import log_alert


class DetectionEngine:
    """
    Main engine responsible for monitoring network traffic and host metrics.
    Runs background threads for sniffing and telemetry collection.
    """
    def __init__(self, alert_callback):
        """
        Initializes the engine.
        :param alert_callback: Function to call when an alert is triggered (usually broadcasts to UI).
        """
        self.alert_callback = alert_callback
        self.running = False

        # Internal state for threshold tracking
        self.failed_logins = {} # IP -> count (placeholder for log analysis)
        self.connection_attempts = {} # IP -> set of unique ports targeted
        self.last_check_time = time.time()

    def analyze_packet(self, packet):
        """
        Analyzes a single sniffed packet for malicious patterns.
        Currently focuses on basic port scan detection.
        """
        if packet.haslayer(IP):
            src_ip = packet[IP].src

            # ── Port Scan Detection ──
            if packet.haslayer(TCP) or packet.haslayer(UDP):
                dst_port = packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport

                if src_ip not in self.connection_attempts:
                    self.connection_attempts[src_ip] = set()

                self.connection_attempts[src_ip].add(dst_port)

                # If an IP probes more than 10 unique ports, flag as a scan
                if len(self.connection_attempts[src_ip]) > 10:
                    self.trigger_alert(
                        "Port Scan Detected",
                        src_ip,
                        f"Multiple sequential port probes detected ({len(self.connection_attempts[src_ip])} ports)",
                        "CRITICAL"
                    )
                    # Reset tracker for this IP after alert
                    self.connection_attempts[src_ip] = set()

    def monitor_system(self):
        """
        Background loop for monitoring host telemetry (CPU, memory, processes).
        Runs every few seconds.
        """
        while self.running:
            # ── CPU Usage Monitoring ──
            # Alerts if host CPU sustains very high load
            cpu_percent = psutil.cpu_percent(interval=1)
            if cpu_percent > 90:
                self.trigger_alert(
                    "High CPU Usage",
                    "LocalHost",
                    f"Abnormal CPU spike detected: {cpu_percent}%",
                    "HIGH"
                )


            time.sleep(5) # Throttled check interval

    def trigger_alert(self, alert_type, src_ip, description, severity, rule_name=None):
        """
        Standardizes the processing of a newly identified threat.
        Logs to DB and triggers the UI broadcast callback.
        """
        # Persist to database using centralized helper
        log_alert(alert_type, src_ip, description, severity, rule_name)

        # Prepare payload for real-time UI notification
        alert_data = {
            "type": alert_type,
            "ip": src_ip,
            "description": description,
            "severity": severity,
            "rule_name": rule_name,
            "time": time.strftime("%H:%M:%S"),
            "category": "alert" # UI uses this to route message
        }
        self.alert_callback(alert_data)

    def _run_sniff(self):
        """
        Internal target for the sniffing thread.
        Utilizes Scapy's high-level sniff function.
        """
        try:
            # Note: store=0 prevents memory leaks during long sniffing sessions
            sniff(prn=self.analyze_packet, store=0)
        except Exception as e:
            print(f"Scapy sniffing failed (likely permission issue): {e}")
            self.running = False

    def start(self):
        """
        Starts the detection threads (Network Sniffing + System Monitoring).
        """
        self.running = True

        # Create and start sniffing thread
        self.sniff_thread = threading.Thread(target=self._run_sniff)
        self.sniff_thread.daemon = True # Thread dies when main process ends
        self.sniff_thread.start()

        # Create and start host telemetry thread
        self.sys_thread = threading.Thread(target=self.monitor_system)
        self.sys_thread.daemon = True
        self.sys_thread.start()

    def stop(self):
        """Stops the management loops."""
        self.running = False
