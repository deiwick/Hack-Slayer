import sqlite3
from datetime import datetime

def get_conn():
    conn = sqlite3.connect("incidents.db")
    conn.execute("""
    CREATE TABLE IF NOT EXISTS incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        type TEXT,
        source TEXT,
        risk_score REAL,
        severity TEXT,
        summary TEXT,
        details TEXT,
        created_at TEXT
    )
    """)
    return conn

def log_incident(typ, source, risk, severity, summary, details):
    conn = get_conn()
    conn.execute(
        "INSERT INTO incidents (type, source, risk_score, severity, summary, details, created_at) VALUES (?,?,?,?,?,?,?)",
        (typ, source, risk, severity, summary, details, datetime.utcnow().isoformat())
    )
    conn.commit()
    conn.close()
