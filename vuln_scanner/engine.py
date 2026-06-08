"""Orchestrates a single analysis run: parse -> store -> match."""

from __future__ import annotations

import sqlite3

from . import db
from .matcher import match_hosts
from .models import Vulnerability
from .parser import parse_xml


def analyze(xml_path: str, db_path: str = ":memory:") -> tuple[list[Vulnerability], sqlite3.Connection]:
    """Parse an Nmap XML report, persist it, and return (findings, connection).

    The caller owns the returned connection and should close it when done
    (mirrors `soc_dashboard.engine.analyze` so both portfolio tools share
    the same "caller manages the resource" contract).
    """
    hosts = parse_xml(xml_path)

    conn = db.connect(db_path)
    db.insert_scan(conn, source_file=xml_path, hosts=hosts)

    findings = match_hosts(hosts)
    return findings, conn
