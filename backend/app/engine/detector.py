"""
Live detection engine for Sentinel_Sandbox.

Watches real traffic with Scapy and host load with psutil, and reports
threats through a callback. It is off by default: sniffing needs root, so it
only starts when SENTINEL_LIVE_MONITOR=1 is set.

The engine never writes to the database itself. Persistence and broadcasting
belong to the callback (``on_alert`` in ``main.py``), so every alert is
stored exactly once, whichever component raised it.
"""

import threading
import time
from collections import defaultdict, deque

import psutil

# A source that touches more than this many distinct ports ...
PORT_SCAN_THRESHOLD = 10
# ... within this many seconds is reported as a port scan.
PORT_SCAN_WINDOW_SECONDS = 10
CPU_ALERT_PERCENT = 90


class DetectionEngine:
    """Port-scan detection on sniffed packets, plus a host CPU check."""

    def __init__(self, alert_callback, clock=time.monotonic):
        """
        :param alert_callback: called with an alert dict; stores and broadcasts it.
        :param clock: time source in seconds (injectable for tests).
        """
        self.alert_callback = alert_callback
        self.clock = clock
        self.running = False
        # source IP -> deque of (timestamp, destination port), oldest first
        self._probes: dict[str, deque] = defaultdict(deque)

    def analyze_packet(self, packet):
        """Track destination ports per source and alert on a scan inside the window."""
        from scapy.all import IP, TCP, UDP  # imported lazily: scapy is slow to load

        if not packet.haslayer(IP):
            return
        if packet.haslayer(TCP):
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            dst_port = packet[UDP].dport
        else:
            return

        src_ip = packet[IP].src
        now = self.clock()
        probes = self._probes[src_ip]
        probes.append((now, dst_port))
        # Forget probes that fell out of the window
        while probes and now - probes[0][0] > PORT_SCAN_WINDOW_SECONDS:
            probes.popleft()

        distinct_ports = {port for _, port in probes}
        if len(distinct_ports) > PORT_SCAN_THRESHOLD:
            self.trigger_alert(
                "Port Scan Detected",
                src_ip,
                f"{len(distinct_ports)} distinct ports probed within {PORT_SCAN_WINDOW_SECONDS}s",
                "CRITICAL",
                rule_name="Port Scan",
            )
            probes.clear()  # one alert per burst, not one per extra packet

    def check_cpu(self, cpu_percent):
        """Alert when host CPU is above the limit."""
        if cpu_percent > CPU_ALERT_PERCENT:
            self.trigger_alert(
                "High CPU Usage",
                "LocalHost",
                f"Abnormal CPU spike detected: {cpu_percent}%",
                "HIGH",
                rule_name="Host Metric Anomaly",
            )

    def monitor_system(self):
        """Background loop sampling host CPU every few seconds."""
        while self.running:
            self.check_cpu(psutil.cpu_percent(interval=1))
            time.sleep(5)

    def trigger_alert(self, alert_type, src_ip, description, severity, rule_name=None):
        """Build the alert payload and hand it to the callback (which stores it)."""
        self.alert_callback(
            {
                "category": "alert",
                "type": alert_type,
                "source_ip": src_ip,
                "description": description,
                "severity": severity,
                "rule_name": rule_name,
                "time": time.strftime("%H:%M:%S"),
            }
        )

    def _run_sniff(self):
        try:
            from scapy.all import sniff

            sniff(prn=self.analyze_packet, store=0)  # store=0: don't keep packets in memory
        except Exception as e:
            print(f"Scapy sniffing failed (likely a permission issue): {e}")
            self.running = False

    def start(self):
        """Start the sniffing and host-monitoring threads."""
        self.running = True
        threading.Thread(target=self._run_sniff, daemon=True).start()
        threading.Thread(target=self.monitor_system, daemon=True).start()

    def stop(self):
        self.running = False
