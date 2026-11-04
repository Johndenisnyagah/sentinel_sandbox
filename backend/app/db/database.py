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

        # Rules Table — Stores threshold-based detection rules
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            pattern TEXT,
            threshold INTEGER,
            window INTEGER,
            severity TEXT,
            condition_text TEXT
        )
        """)

        # Bootstrap default rules for simulation purposes
        cursor.execute("SELECT COUNT(*) FROM rules")
        if cursor.fetchone()[0] == 0:
            default_rules = [
                ("Brute Force", "failed_login", 5, 30, "HIGH", ">5 login failures / 30s"),
                ("Port Scan", "connection_attempt", 10, 10, "CRITICAL", ">10 ports accessed / 10s"),
                ("Traffic Flood", "packet_count", 1000, 60, "MEDIUM", ">1000 packets / 60s"),
                ("Host Metric Anomaly", "cpu_usage", 90, 30, "HIGH", "CPU > 90% for 30s"),
                ("DDoS Botnet Pattern", "syn_flood", 50, 5, "CRITICAL", ">50 SYN packets / 5s"),
                ("Unauthorized Access", "auth_bypass", 1, 1, "CRITICAL", "Admin path probe detected"),
                ("SQLi Probe", "suspicious_query", 3, 10, "HIGH", "SQL injection patterns detected")
            ]
            cursor.executemany(
                "INSERT INTO rules (name, pattern, threshold, window, severity, condition_text) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                default_rules
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
