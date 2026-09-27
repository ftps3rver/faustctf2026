"""Persistent flag store for dedupe + submission bookkeeping (SQLite)."""
import sqlite3
import threading
import time

_LOCK = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS flags (
    flag       TEXT PRIMARY KEY,
    status     TEXT NOT NULL DEFAULT 'NEW',  -- NEW | SUBMITTED | ACCEPTED | REJECTED
    service    TEXT,
    target     TEXT,
    exploit    TEXT,
    response   TEXT,
    first_seen REAL,
    last_try   REAL
);
"""


class FlagDB:
    def __init__(self, path):
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def add(self, flag, service=None, target=None, exploit=None):
        """Insert a freshly captured flag. Returns True if it was new."""
        with _LOCK:
            cur = self.conn.execute(
                "INSERT OR IGNORE INTO flags(flag, status, service, target, exploit, first_seen)"
                " VALUES(?, 'NEW', ?, ?, ?, ?)",
                (flag, service, target, exploit, time.time()),
            )
            self.conn.commit()
            return cur.rowcount > 0

    def pending(self, limit=5000):
        """Flags not yet accepted/rejected - worth (re)submitting."""
        with _LOCK:
            rows = self.conn.execute(
                "SELECT flag FROM flags WHERE status IN ('NEW','SUBMITTED') LIMIT ?",
                (limit,),
            ).fetchall()
        return [r[0] for r in rows]

    def mark(self, flag, status, response=None):
        with _LOCK:
            self.conn.execute(
                "UPDATE flags SET status=?, response=COALESCE(?, response), last_try=? WHERE flag=?",
                (status, response, time.time(), flag),
            )
            self.conn.commit()

    def stats(self):
        with _LOCK:
            rows = self.conn.execute(
                "SELECT status, COUNT(*) FROM flags GROUP BY status"
            ).fetchall()
        return dict(rows)
