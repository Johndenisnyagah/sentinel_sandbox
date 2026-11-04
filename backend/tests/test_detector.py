"""Live-monitor detection logic and the alert/broadcast path."""

import threading

from scapy.all import IP, TCP, UDP

from app.engine.detector import PORT_SCAN_THRESHOLD, PORT_SCAN_WINDOW_SECONDS, DetectionEngine


class FakeClock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


def make_engine():
    alerts, clock = [], FakeClock()
    return DetectionEngine(alerts.append, clock=clock), alerts, clock


def probe(engine, port, src="10.0.0.5"):
    engine.analyze_packet(IP(src=src, dst="10.0.0.1") / TCP(dport=port))


def test_scan_at_threshold_does_not_alert():
    engine, alerts, _ = make_engine()
    for port in range(PORT_SCAN_THRESHOLD):
        probe(engine, port)
    assert alerts == []


def test_scan_over_threshold_alerts_once():
    engine, alerts, _ = make_engine()
    for port in range(PORT_SCAN_THRESHOLD + 1):
        probe(engine, port)
    assert len(alerts) == 1
    assert alerts[0]["source_ip"] == "10.0.0.5"
    assert alerts[0]["rule_name"] == "Port Scan"


def test_slow_probes_outside_window_do_not_alert():
    """Before the fix, 11 ports spread over a day counted as a scan."""
    engine, alerts, clock = make_engine()
    for port in range(PORT_SCAN_THRESHOLD * 3):
        probe(engine, port)
        clock.t += PORT_SCAN_WINDOW_SECONDS  # one probe per window
    assert alerts == []


def test_repeated_port_does_not_count_twice():
    engine, alerts, _ = make_engine()
    for _ in range(50):
        probe(engine, 22)
    assert alerts == []


def test_sources_are_tracked_separately():
    engine, alerts, _ = make_engine()
    for port in range(PORT_SCAN_THRESHOLD):
        probe(engine, port, src="10.0.0.5")
        probe(engine, port, src="10.0.0.6")
    assert alerts == []


def test_udp_counts():
    engine, alerts, _ = make_engine()
    for port in range(PORT_SCAN_THRESHOLD + 1):
        engine.analyze_packet(IP(src="10.0.0.7") / UDP(dport=port))
    assert len(alerts) == 1


def test_cpu_check():
    engine, alerts, _ = make_engine()
    engine.check_cpu(50)
    engine.check_cpu(95)
    assert len(alerts) == 1 and alerts[0]["type"] == "High CPU Usage"


def test_detector_alert_is_stored_once(app_module, client):
    """Before the fix, one detector alert wrote two rows."""
    app_module.detector.trigger_alert("Port Scan Detected", "1.2.3.4", "x", "CRITICAL", "Port Scan")
    rows = client.get("/alerts").json()
    assert len(rows) == 1 and rows[0]["source_ip"] == "1.2.3.4"


def test_alert_from_other_thread_reaches_websocket(app_module, client):
    """Before the fix, broadcasting from the sniffer thread raised and the UI never saw the alert."""
    with client.websocket_connect("/ws/alerts") as ws:
        t = threading.Thread(
            target=app_module.detector.trigger_alert,
            args=("Port Scan Detected", "9.9.9.9", "x", "CRITICAL", "Port Scan"),
        )
        t.start()
        t.join()
        msg = ws.receive_json()
        assert msg["category"] == "alert" and msg["source_ip"] == "9.9.9.9"


def test_status_reports_live_monitor_off(client):
    assert client.get("/status").json()["live_monitor"] is False


def test_schedule_broadcast_without_server_is_noop(app_module):
    app_module.main_loop = None
    app_module.schedule_broadcast({"x": 1})  # must not raise
