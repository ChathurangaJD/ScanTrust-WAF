import sqlite3
import datetime

DB_NAME = 'waf_logs.db'

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS threat_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            payload TEXT,
            risk_score REAL,
            action TEXT
        )
    ''')
    conn.commit()
    conn.close()

def log_threat(payload, risk_score):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    c.execute(
        'INSERT INTO threat_logs (timestamp, payload, risk_score, action) VALUES (?, ?, ?, ?)',
        (timestamp, payload, risk_score, 'DETECTED')
    )
    conn.commit()
    conn.close()