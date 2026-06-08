"""Tests for the Nmap XML parser and SQLite storage layers in isolation
from the matching/reporting logic above them."""

from __future__ import annotations

from pathlib import Path

import pytest

from vuln_scanner import db
from vuln_scanner.parser import parse_xml

FIXTURES = Path(__file__).parent / "fixtures"


def _xml(name: str) -> str:
    path = FIXTURES / name
    if not path.exists():
        pytest.skip(f"fixture {name} missing - run tests/fixtures/generate.py")
    return str(path)


def test_parse_xml_reads_hosts_and_services():
    hosts = parse_xml(_xml("vulnerable_single.xml"))
    assert len(hosts) == 1
    host = hosts[0]
    assert host.ip == "10.0.0.20"
    assert host.hostname == "lab-ftp.local"
    assert host.status == "up"
    assert len(host.services) == 2

    ftp = next(s for s in host.services if s.port == 21)
    assert ftp.protocol == "tcp"
    assert ftp.state == "open"
    assert ftp.product == "vsftpd"
    assert ftp.version == "2.3.4"


def test_parse_xml_handles_multiple_hosts():
    hosts = parse_xml(_xml("multi_host.xml"))
    assert [h.ip for h in hosts] == ["10.0.0.30", "10.0.0.31", "10.0.0.32"]
    assert sum(len(h.services) for h in hosts) == 6


def test_parse_xml_rejects_non_nmap_xml(tmp_path):
    bad = tmp_path / "bad.xml"
    bad.write_text("<not-nmap><thing/></not-nmap>", encoding="utf-8")
    with pytest.raises(ValueError, match="not an Nmap XML report"):
        parse_xml(str(bad))


def test_parse_xml_rejects_malformed_xml(tmp_path):
    bad = tmp_path / "bad.xml"
    bad.write_text("<nmaprun><host>", encoding="utf-8")
    with pytest.raises(ValueError, match="not valid XML"):
        parse_xml(str(bad))


def test_insert_and_fetch_round_trip():
    hosts = parse_xml(_xml("multi_host.xml"))
    conn = db.connect()  # in-memory
    scan_id = db.insert_scan(conn, source_file="multi_host.xml", hosts=hosts)

    assert db.host_count(conn) == 3
    assert db.host_count(conn, scan_id=scan_id) == 3
    assert db.latest_scan_id(conn) == scan_id

    fetched = db.fetch_hosts(conn, scan_id=scan_id)
    assert [h.ip for h in fetched] == [h.ip for h in hosts]
    assert fetched[0].services[0].product == "Microsoft-DS"
    conn.close()


def test_fetch_hosts_without_scan_id_returns_everything():
    hosts1 = parse_xml(_xml("clean.xml"))
    hosts2 = parse_xml(_xml("vulnerable_single.xml"))
    conn = db.connect()
    db.insert_scan(conn, source_file="clean.xml", hosts=hosts1)
    db.insert_scan(conn, source_file="vulnerable_single.xml", hosts=hosts2)

    assert db.host_count(conn) == 2
    assert len(db.fetch_hosts(conn)) == 2
    conn.close()
