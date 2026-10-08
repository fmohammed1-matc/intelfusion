"""SQLite persistence for IOCs, feed-run metadata and alerts."""
from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS iocs (
    value      TEXT NOT NULL,
    ioc_type   TEXT NOT NULL,
    feed       TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    PRIMARY KEY (value, feed)
);
CREATE TABLE IF NOT EXISTS feed_runs (
    feed       TEXT PRIMARY KEY,
    fetched_at TEXT NOT NULL,
    ioc_count  INTEGER NOT NULL DEFAULT 0,
    status     TEXT NOT NULL DEFAULT 'ok',
    error      TEXT
);
CREATE TABLE IF NOT EXISTS alerts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc_value  TEXT NOT NULL,
    ioc_type   TEXT NOT NULL,
    feeds      TEXT NOT NULL,
    severity   INTEGER NOT NULL,
    level      TEXT NOT NULL,
    log_file   TEXT NOT NULL,
    log_line   TEXT NOT NULL,
    matched_at TEXT NOT NULL,
    dedupe_key TEXT NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS idx_alerts_matched ON alerts(matched_at);
CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(ioc_type);
"""


class Store:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.path))
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)

    # ---- IOCs ---------------------------------------------------------
    def upsert_iocs(self, iocs) -> int:
        """Insert IOCs, ignoring (value, feed) duplicates. Returns # newly added."""
        new = 0
        with self.conn:
            for ioc in iocs:
                cur = self.conn.execute(
                    "INSERT OR IGNORE INTO iocs (value, ioc_type, feed, first_seen)"
                    " VALUES (?,?,?,?)",
                    (ioc.value, ioc.ioc_type, ioc.feed, ioc.first_seen),
                )
                new += cur.rowcount
        return new

    def get_iocs(self) -> list[dict]:
        return [
            dict(r) for r in self.conn.execute("SELECT * FROM iocs ORDER BY value")
        ]

    def ioc_count_by_feed(self) -> dict[str, int]:
        rows = self.conn.execute(
            "SELECT feed, COUNT(*) AS c FROM iocs GROUP BY feed"
        ).fetchall()
        return {r["feed"]: r["c"] for r in rows}

    def feeds_for_value(self, value: str) -> list[str]:
        rows = self.conn.execute(
            "SELECT feed FROM iocs WHERE value = ?", (value,)
        ).fetchall()
        return sorted(r["feed"] for r in rows)

    # ---- feed runs ----------------------------------------------------
    def record_feed_run(
        self,
        feed: str,
        fetched_at: str,
        ioc_count: int,
        status: str = "ok",
        error: str | None = None,
    ) -> None:
        with self.conn:
            self.conn.execute(
                "INSERT OR REPLACE INTO feed_runs"
                " (feed, fetched_at, ioc_count, status, error)"
                " VALUES (?,?,?,?,?)",
                (feed, fetched_at, ioc_count, status, error),
            )

    def get_feed_runs(self) -> list[dict]:
        return [
            dict(r)
            for r in self.conn.execute("SELECT * FROM feed_runs ORDER BY feed")
        ]

    # ---- alerts -------------------------------------------------------
    def insert_alert(self, alert: dict) -> bool:
        """Insert an alert; returns True if it was new, False if deduplicated."""
        try:
            with self.conn:
                self.conn.execute(
                    "INSERT INTO alerts (ioc_value, ioc_type, feeds, severity, level,"
                    " log_file, log_line, matched_at, dedupe_key)"
                    " VALUES (?,?,?,?,?,?,?,?,?)",
                    (
                        alert["ioc_value"],
                        alert["ioc_type"],
                        alert["feeds"],
                        alert["severity"],
                        alert["level"],
                        alert["log_file"],
                        alert["log_line"],
                        alert["matched_at"],
                        alert["dedupe_key"],
                    ),
                )
            return True
        except sqlite3.IntegrityError:
            return False

    def get_alerts(self, limit: int = 200) -> list[dict]:
        return [
            dict(r)
            for r in self.conn.execute(
                "SELECT * FROM alerts ORDER BY matched_at DESC, id DESC LIMIT ?",
                (limit,),
            )
        ]

    def get_alert(self, alert_id: int) -> dict | None:
        row = self.conn.execute(
            "SELECT * FROM alerts WHERE id = ?", (alert_id,)
        ).fetchone()
        return dict(row) if row else None

    def alert_count(self) -> int:
        row = self.conn.execute("SELECT COUNT(*) AS c FROM alerts").fetchone()
        return row["c"]

    def close(self) -> None:
        self.conn.close()
