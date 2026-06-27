"""Simple SQLite helper for storing scan history."""
import sqlite3
from datetime import datetime
from typing import List, Dict

DB_PATH = 'scans.db'


def init_db() -> None:
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        '''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            scanned_at TEXT NOT NULL,
            score INTEGER NOT NULL,
            risk TEXT NOT NULL
        )
        '''
    )
    conn.commit()
    conn.close()


def insert_scan(url: str, score: int, risk: str, scanned_at: str | None = None) -> None:
    if scanned_at is None:
        scanned_at = datetime.utcnow().isoformat()
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute('INSERT INTO scans (url, scanned_at, score, risk) VALUES (?, ?, ?, ?)', (url, scanned_at, score, risk))
    conn.commit()
    conn.close()


def fetch_scans(limit: int = 200) -> List[Dict]:
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute('SELECT id, url, scanned_at, score, risk FROM scans ORDER BY scanned_at DESC LIMIT ?', (limit,))
    rows = cur.fetchall()
    conn.close()
    return [
        {'id': r[0], 'url': r[1], 'scanned_at': r[2], 'score': r[3], 'risk': r[4]}
        for r in rows
    ]
