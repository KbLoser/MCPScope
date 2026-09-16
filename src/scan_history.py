from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List


def _connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS scan_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            label TEXT,
            source_file TEXT,
            target_count INTEGER NOT NULL,
            confirmed_count INTEGER NOT NULL,
            critical_count INTEGER NOT NULL,
            auth_none_count INTEGER NOT NULL,
            average_priority REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS target_snapshots (
            run_id INTEGER NOT NULL REFERENCES scan_runs(id),
            url TEXT NOT NULL,
            auth_state TEXT,
            risk_level TEXT,
            priority_score INTEGER,
            tool_count INTEGER,
            tool_name_hash TEXT,
            status TEXT,
            capability_clusters TEXT NOT NULL,
            record_json TEXT NOT NULL,
            PRIMARY KEY (run_id, url)
        );
        CREATE INDEX IF NOT EXISTS target_snapshots_url_idx ON target_snapshots(url, run_id);
        CREATE TABLE IF NOT EXISTS target_lifecycle (
            url TEXT PRIMARY KEY,
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            confirmed_runs INTEGER NOT NULL DEFAULT 0,
            missed_runs INTEGER NOT NULL DEFAULT 0,
            active INTEGER NOT NULL DEFAULT 1
        );
        """
    )
    return connection


def record_scan(path: Path, document: Dict[str, Any], label: str = "", source_file: str = "") -> int:
    records = document.get("records", [])
    confirmed = [record for record in records if record.get("confirmed_mcp")]
    average = sum(int(record.get("priority_score", 0)) for record in confirmed) / len(confirmed) if confirmed else 0
    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with _connect(path) as connection:
        cursor = connection.execute(
            """INSERT INTO scan_runs
               (created_at, label, source_file, target_count, confirmed_count, critical_count, auth_none_count, average_priority)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                timestamp, label or None, source_file or None,
                len(records), len(confirmed), sum(record.get("risk_level") == "严重" for record in confirmed),
                sum(record.get("auth_state") == "none" for record in confirmed), average,
            ),
        )
        run_id = int(cursor.lastrowid)
        connection.executemany(
            """INSERT INTO target_snapshots
               (run_id, url, auth_state, risk_level, priority_score, tool_count, tool_name_hash, status, capability_clusters, record_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [
                (
                    run_id, record.get("url", ""), record.get("auth_state"), record.get("risk_level"),
                    record.get("priority_score"), record.get("tool_count"), record.get("tool_name_hash"),
                    record.get("status"), json.dumps(record.get("capability_clusters", []), ensure_ascii=False),
                    json.dumps(record, ensure_ascii=False),
                )
                for record in records if record.get("url")
            ],
        )
        for record in records:
            url = record.get("url")
            if not url:
                continue
            if record.get("confirmed_mcp"):
                connection.execute(
                    """INSERT INTO target_lifecycle (url, first_seen_at, last_seen_at, confirmed_runs, missed_runs, active)
                       VALUES (?, ?, ?, 1, 0, 1)
                       ON CONFLICT(url) DO UPDATE SET last_seen_at=excluded.last_seen_at,
                           confirmed_runs=confirmed_runs+1, missed_runs=0, active=1""",
                    (url, timestamp, timestamp),
                )
            else:
                connection.execute(
                    "UPDATE target_lifecycle SET missed_runs=missed_runs+1, active=0 WHERE url=?",
                    (url,),
                )
    return run_id


def persistence_counts(path: Path, urls: Iterable[str]) -> Dict[str, int]:
    values = list(dict.fromkeys(urls))
    if not path.exists() or not values:
        return {}
    placeholders = ",".join("?" for _ in values)
    with _connect(path) as connection:
        rows = connection.execute(
            f"SELECT url, COUNT(*) AS count FROM target_snapshots WHERE url IN ({placeholders}) AND status IN ('success', 'no_tools') GROUP BY url",
            values,
        ).fetchall()
    return {str(row["url"]): int(row["count"]) for row in rows}


def list_runs(path: Path, limit: int = 50) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    with _connect(path) as connection:
        rows = connection.execute("SELECT * FROM scan_runs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(row) for row in rows]


def trend(path: Path, metric: str) -> List[Dict[str, Any]]:
    columns = {
        "target_count", "confirmed_count", "critical_count", "auth_none_count", "average_priority",
    }
    if metric not in columns:
        raise ValueError(f"unsupported trend metric: {metric}")
    if not path.exists():
        return []
    with _connect(path) as connection:
        rows = connection.execute(f"SELECT id, created_at, label, {metric} AS value FROM scan_runs ORDER BY id").fetchall()
    return [dict(row) for row in rows]


def target_history(path: Path, url: str) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    with _connect(path) as connection:
        rows = connection.execute(
            """SELECT r.id AS run_id, r.created_at, s.auth_state, s.risk_level, s.priority_score,
                      s.tool_count, s.tool_name_hash, s.status, s.capability_clusters
               FROM target_snapshots s JOIN scan_runs r ON r.id = s.run_id
               WHERE s.url = ? ORDER BY r.id""",
            (url,),
        ).fetchall()
    values = []
    for row in rows:
        item = dict(row)
        item["capability_clusters"] = json.loads(item["capability_clusters"] or "[]")
        values.append(item)
    return values


def latest_watch_targets(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    with _connect(path) as connection:
        latest = connection.execute("SELECT MAX(id) AS id FROM scan_runs").fetchone()["id"]
        if latest is None:
            return []
        rows = connection.execute(
            "SELECT record_json FROM target_snapshots WHERE run_id = ? AND risk_level = '严重'",
            (latest,),
        ).fetchall()
    records = [json.loads(row["record_json"]) for row in rows]
    return [record for record in records if any(key.startswith("exec+") for key in record.get("capability_clusters", [])) or any("命令或代码执行" in reason for reason in record.get("risk_reasons", []))]


def decay_stats(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {"total": 0, "active": 0, "inactive": 0, "average_confirmed_runs": 0}
    with _connect(path) as connection:
        row = connection.execute(
            """SELECT COUNT(*) AS total, SUM(active) AS active,
                      AVG(confirmed_runs) AS average_confirmed_runs
               FROM target_lifecycle"""
        ).fetchone()
    total = int(row["total"] or 0)
    active = int(row["active"] or 0)
    return {
        "total": total,
        "active": active,
        "inactive": total - active,
        "average_confirmed_runs": round(float(row["average_confirmed_runs"] or 0), 2),
    }
