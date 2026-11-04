"""Rule engine: thresholds, windows, measures, and the simulations end to end."""

import asyncio

import pytest

from app.engine.rules import Rule, RuleEngine


class FakeClock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


BRUTE = Rule("Brute Force", "failed_login", "count", 5, 30, "HIGH")
SCAN = Rule("Port Scan", "connection_attempt", "distinct:port", 10, 10, "CRITICAL")
FLOOD = Rule("Traffic Flood", "traffic_burst", "sum:packets", 1000, 60, "MEDIUM")


def make(*rules):
    alerts, clock = [], FakeClock()
    return RuleEngine(rules, alerts.append, clock=clock), alerts, clock


def login(engine, ip="1.1.1.1"):
    return engine.process({"event_type": "failed_login", "ip": ip})


def test_at_threshold_does_not_fire():
    engine, alerts, _ = make(BRUTE)
    for _ in range(5):
        login(engine)
    assert alerts == []


def test_above_threshold_fires_once():
    engine, alerts, _ = make(BRUTE)
    for _ in range(6):
        login(engine)
    assert len(alerts) == 1
    a = alerts[0]
    assert (a["type"], a["source_ip"], a["severity"], a["packets_detected"]) == ("Brute Force", "1.1.1.1", "HIGH", 6)
    assert a["time_window"] == "30s"


def test_window_expires_old_events():
    engine, alerts, clock = make(BRUTE)
    for _ in range(5):
        login(engine)
    clock.t = 31  # first five are now outside the 30 s window
    login(engine)
    assert alerts == []


def test_window_is_sliding_not_fixed():
    engine, alerts, clock = make(BRUTE)
    for t in (0, 10, 20, 25, 28):
        clock.t = t
        login(engine)
    clock.t = 35  # drops t=0, keeps 10..28 (4) + this one = 5 -> no alert
    login(engine)
    assert alerts == []
    clock.t = 36
    login(engine)  # 10..36 is 6 events within 30 s
    assert len(alerts) == 1


def test_after_firing_the_window_resets():
    engine, alerts, _ = make(BRUTE)
    for _ in range(6):
        login(engine)
    for _ in range(5):
        login(engine)
    assert len(alerts) == 1  # a new burst needs >5 again


def test_sources_are_independent():
    engine, alerts, _ = make(BRUTE)
    for _ in range(5):
        login(engine, "1.1.1.1")
        login(engine, "2.2.2.2")
    assert alerts == []


def test_other_event_types_are_ignored():
    engine, alerts, _ = make(BRUTE)
    for _ in range(20):
        engine.process({"event_type": "info", "ip": "1.1.1.1"})
    assert alerts == []


def test_distinct_measure_ignores_repeats():
    engine, alerts, _ = make(SCAN)
    for _ in range(30):
        engine.process({"event_type": "connection_attempt", "ip": "x", "port": 22})
    assert alerts == []
    for port in range(1, 11):
        engine.process({"event_type": "connection_attempt", "ip": "x", "port": port})
    assert len(alerts) == 1
    assert alerts[0]["ports_accessed"] == list(range(1, 11)) + [22]


def test_sum_measure():
    engine, alerts, _ = make(FLOOD)
    for _ in range(4):
        engine.process({"event_type": "traffic_burst", "ip": "x", "packets": 250})
    assert alerts == []  # exactly 1000
    engine.process({"event_type": "traffic_burst", "ip": "x", "packets": 1})
    assert len(alerts) == 1 and alerts[0]["packets_detected"] == 1001


def test_reload_replaces_rules():
    engine, alerts, _ = make(BRUTE)
    engine.load([Rule("Strict", "failed_login", "count", 1, 30, "LOW")])
    login(engine)
    login(engine)
    assert [a["type"] for a in alerts] == ["Strict"]


# ── End to end: simulation -> events -> engine -> stored alert ──

SIMULATIONS = {
    "simulate_brute_force": "Brute Force",
    "simulate_port_scan": "Port Scan",
    "simulate_traffic_flood": "Traffic Flood",
    "simulate_ddos": "SYN Flood",
    "simulate_sqli": "SQLi Probe",
}


@pytest.fixture
def no_sleep(monkeypatch):
    async def instant(_):
        return None

    monkeypatch.setattr("app.simulation.attacker.asyncio.sleep", instant)


@pytest.mark.parametrize("method,rule", SIMULATIONS.items())
def test_each_simulation_is_detected_by_its_rule(app_module, client, no_sleep, method, rule):
    asyncio.run(getattr(app_module.attacker, method)())
    alerts = client.get("/alerts").json()
    assert [a["rule_name"] for a in alerts] == [rule]


def test_simulation_alone_does_not_store_alerts(app_module, client, no_sleep):
    """The simulator only produces events; with no rules loaded, nothing alerts."""
    app_module.rule_engine.load([])
    asyncio.run(app_module.attacker.simulate_brute_force())
    assert client.get("/alerts").json() == []
    assert len(client.get("/activity").json()) == 8


def test_rules_endpoint_matches_engine(app_module, client):
    shown = {r["name"] for r in client.get("/rules").json() if r["measure"] != "live"}
    assert shown == {r.name for r in app_module.rule_engine.rules}


def test_old_display_only_rules_table_is_replaced(tmp_path, monkeypatch):
    import importlib
    import sqlite3
    import sys

    db = tmp_path / "old.db"
    with sqlite3.connect(db) as conn:
        conn.execute(
            "CREATE TABLE rules (id INTEGER PRIMARY KEY, name TEXT, pattern TEXT, threshold INTEGER,"
            " window INTEGER, severity TEXT, condition_text TEXT)"
        )
        conn.execute("INSERT INTO rules (name) VALUES ('Unauthorized Access')")
    monkeypatch.setenv("SENTINEL_DB_PATH", str(db))
    for name in [m for m in sys.modules if m == "main" or m.startswith("app")]:
        del sys.modules[name]
    database = importlib.import_module("app.db.database")
    database.init_db()
    names = {r.name for r in database.load_rules()}
    assert "Unauthorized Access" not in names and "Brute Force" in names
