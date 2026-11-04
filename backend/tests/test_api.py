"""Smoke tests for the REST API."""


def test_root(client):
    assert client.get("/").status_code == 200


def test_rules_are_seeded(client):
    rules = client.get("/rules").json()
    assert len(rules) == 6
    assert {r["name"] for r in rules} >= {"Brute Force", "Port Scan"}


def test_status_shape(client):
    body = client.get("/status").json()
    assert {"alerts_triggered", "active_connections", "simulations_run"} <= body.keys()


def test_unknown_simulation_is_rejected(client):
    assert client.post("/simulate", params={"attack_type": "NOPE"}).status_code == 400


def test_alerts_start_empty(client):
    assert client.get("/alerts").json() == []


def test_status_counts_real_events(app_module, client, monkeypatch):
    """events_processed is the stored event count (was a double-counted 'packets' figure)."""
    import asyncio

    async def instant(_):
        return None

    monkeypatch.setattr("app.simulation.attacker.asyncio.sleep", instant)
    asyncio.run(app_module.attacker.simulate_port_scan())
    body = client.get("/status").json()
    assert body["events_processed"] == len(client.get("/activity").json()) == 15
    assert "packets_monitored" not in body
    assert body["rules_active"] == 5
