"""SQLite storage for scan results — lets you track a network's exposure
over time rather than just looking at the most recent snapshot.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

from .models import Host, Service

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_file TEXT NOT NULL,
    scanned_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id),
    ip TEXT NOT NULL,
    hostname TEXT,
    status TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL REFERENCES hosts(id),
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    state TEXT NOT NULL,
    name TEXT,
    product TEXT,
    version TEXT
);

CREATE INDEX IF NOT EXISTS idx_hosts_scan ON hosts(scan_id);
CREATE INDEX IF NOT EXISTS idx_services_host ON services(host_id);
CREATE INDEX IF NOT EXISTS idx_services_product_version ON services(product, version);
"""


def connect(db_path: str = ":memory:") -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def insert_scan(conn: sqlite3.Connection, source_file: str, hosts: list[Host]) -> int:
    """Persist a full scan (hosts + their services) and return the new scan id."""
    cur = conn.execute(
        "INSERT INTO scans (source_file, scanned_at) VALUES (?, ?)",
        (source_file, datetime.now(timezone.utc).isoformat()),
    )
    scan_id = cur.lastrowid

    for host in hosts:
        host_cur = conn.execute(
            "INSERT INTO hosts (scan_id, ip, hostname, status) VALUES (?, ?, ?, ?)",
            (scan_id, host.ip, host.hostname, host.status),
        )
        host_id = host_cur.lastrowid
        for svc in host.services:
            conn.execute(
                "INSERT INTO services (host_id, port, protocol, state, name, product, version) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (host_id, svc.port, svc.protocol, svc.state, svc.name, svc.product, svc.version),
            )

    conn.commit()
    return scan_id


def fetch_hosts(conn: sqlite3.Connection, scan_id: int | None = None) -> list[Host]:
    """Reconstruct Host/Service records from storage, optionally filtered to one scan."""
    if scan_id is None:
        host_rows = conn.execute("SELECT * FROM hosts ORDER BY id").fetchall()
    else:
        host_rows = conn.execute(
            "SELECT * FROM hosts WHERE scan_id = ? ORDER BY id", (scan_id,)
        ).fetchall()

    hosts = []
    for row in host_rows:
        service_rows = conn.execute(
            "SELECT * FROM services WHERE host_id = ? ORDER BY port", (row["id"],)
        ).fetchall()
        services = [
            Service(
                port=s["port"], protocol=s["protocol"], state=s["state"],
                name=s["name"], product=s["product"], version=s["version"],
            )
            for s in service_rows
        ]
        hosts.append(Host(ip=row["ip"], hostname=row["hostname"], status=row["status"], services=services))
    return hosts


def host_count(conn: sqlite3.Connection, scan_id: int | None = None) -> int:
    if scan_id is None:
        return conn.execute("SELECT COUNT(*) FROM hosts").fetchone()[0]
    return conn.execute("SELECT COUNT(*) FROM hosts WHERE scan_id = ?", (scan_id,)).fetchone()[0]


def latest_scan_id(conn: sqlite3.Connection) -> int | None:
    row = conn.execute("SELECT id FROM scans ORDER BY id DESC LIMIT 1").fetchone()
    return row["id"] if row else None
