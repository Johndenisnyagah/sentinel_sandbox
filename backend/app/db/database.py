"""
Database utility module for Sentinel_Sandbox.
Handles SQLite initialization, connection management, and simplified
logging for system events and security alerts.
"""

import os
import sqlite3

# Database file path; override with SENTINEL_DB_PATH (tests use a temp file)
DB_PATH = os.environ.get(
    "SENTINEL_DB_PATH", os.path.join(os.path.dirname(__file__), "sentinel.db")
)

# (name, event_type it watches, measure, threshold, window s, severity, shown text).
# A rule fires when the measure over the window is GREATER than the threshold.
DEFAULT_RULES = [
    ("Brute Force", "failed_login", "count", 5, 30, "HIGH", ">5 failed logins / 30s"),
    ("Port Scan", "connection_attempt", "distinct:port", 10, 10, "CRITICAL", ">10 distinct ports / 10s"),
    ("Traffic Flood", "traffic_burst", "sum:packets", 1000, 60, "MEDIUM", ">1000 packets / 60s"),
    ("SYN Flood", "syn_burst", "sum:packets", 50, 5, "CRITICAL", ">50 SYN packets / 5s"),
    ("SQLi Probe", "suspicious_query", "count", 3, 10, "HIGH", ">3 SQL injection payloads / 10s"),
    ("Host Metric Anomaly", "cpu_usage", "live", 90, 0, "HIGH", "CPU > 90% (live monitor only)"),
]


def load_rules():
    """Rules the engine applies (rows with the 'live' measure belong to the live monitor)."""
    from ..engine.rules import Rule

    conn = get_db_connection()
    rows = conn.execute(
        "SELECT name, pattern, measure, threshold, window, severity, condition_text "
        "FROM rules WHERE measure != 'live'"
    ).fetchall()
    conn.close()
    return [Rule(**dict(r)) for r in rows]


def init_db():
    """
    Initializes the SQLite database with required tables if they do not exist.
    Populates default detection rules on first initialization.
    """
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()

        # Alerts Table — Stores final detected threats with severity
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT NOT NULL,
            source_ip TEXT,
            description TEXT,
            severity TEXT,
            rule_name TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        """)

        # Events Table — Stores intermediate activity feed data (e.g., login attempts)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            source_ip TEXT,
            details TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        """)

        # Rules Table — threshold rules applied by app/engine/rules.py.
        # Databases from before the rule engine have no `measure` column;
        # their rules were display-only, so they are replaced.
        cols = [row[1] for row in cursor.execute("PRAGMA table_info(rules)")]
        if cols and "measure" not in cols:
            cursor.execute("DROP TABLE rules")
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            pattern TEXT,
            measure TEXT NOT NULL DEFAULT 'count',
            threshold INTEGER,
            window INTEGER,
            severity TEXT,
            condition_text TEXT
        )
        """)

        cursor.execute("SELECT COUNT(*) FROM rules")
        if cursor.fetchone()[0] == 0:
            cursor.executemany(
                "INSERT INTO rules (name, pattern, measure, threshold, window, severity, condition_text) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                DEFAULT_RULES,
            )

        conn.commit()

def log_event(event_type, source_ip, details):
    """
    Inserts a new system event into the 'events' table.
    Used for granular activity tracking (Activity Feed).
    """
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO events (event_type, source_ip, details) VALUES (?, ?, ?)",
                (event_type, source_ip, details)
            )
            conn.commit()
    except Exception as e:
        print(f"Failed to log event: {e}")

def log_alert(alert_type, source_ip, description, severity, rule_name=None):
    """
    Inserts a new security alert into the 'alerts' table.
    Returns the ID of the new record (useful for forensic linkage).
    """
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO alerts (type, source_ip, description, severity, rule_name) VALUES (?, ?, ?, ?, ?)",
                (alert_type, source_ip, description, severity, rule_name)
            )
            conn.commit()
            return cursor.lastrowid
    except Exception as e:
        print(f"Failed to log alert: {e}")
        return None

def get_db_connection():
    """
    Utility function to create a database connection.
    Sets 'Row' factory for dictionary-like access to results.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn
