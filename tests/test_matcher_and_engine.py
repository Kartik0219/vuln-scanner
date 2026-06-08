"""End-to-end matching tests against small synthetic Nmap XML fixtures.

Each fixture isolates a scenario (a clean host, a single known-vulnerable
service, a mixed multi-host network) so we can assert both that real
matches are caught and that patched/unknown services stay quiet."""

from __future__ import annotations

from pathlib import Path

import pytest

from vuln_scanner.engine import analyze
from vuln_scanner.matcher import match_hosts
from vuln_scanner.parser import parse_xml

FIXTURES = Path(__file__).parent / "fixtures"


def _xml(name: str) -> str:
    path = FIXTURES / name
    if not path.exists():
        pytest.skip(f"fixture {name} missing - run tests/fixtures/generate.py")
    return str(path)


def test_clean_host_produces_no_findings():
    hosts = parse_xml(_xml("clean.xml"))
    assert match_hosts(hosts) == []


def test_vulnerable_single_is_detected():
    hosts = parse_xml(_xml("vulnerable_single.xml"))
    findings = match_hosts(hosts)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.host_ip == "10.0.0.20"
    assert finding.port == 21
    assert finding.product == "vsftpd"
    assert finding.version == "2.3.4"
    assert finding.cve_id == "CVE-2011-2523"
    assert finding.severity == "critical"


def test_multi_host_finds_every_match_and_sorts_by_severity():
    hosts = parse_xml(_xml("multi_host.xml"))
    findings = match_hosts(hosts)

    cve_ids = {f.cve_id for f in findings}
    assert cve_ids == {"CVE-2017-0144", "CVE-2021-41773", "CVE-2016-6515"}

    # Critical findings must sort ahead of medium ones
    severities = [f.severity for f in findings]
    assert severities.index("medium") > max(
        i for i, s in enumerate(severities) if s == "critical"
    )


def test_matcher_ignores_closed_ports_and_missing_versions():
    hosts = parse_xml(_xml("multi_host.xml"))
    # Microsoft Terminal Services has no version - must not crash or false-positive
    rdp_host = next(h for h in hosts if h.ip == "10.0.0.30")
    rdp_service = next(s for s in rdp_host.services if s.port == 3389)
    assert rdp_service.version is None

    findings = match_hosts(hosts)
    assert all(f.port != 3389 for f in findings)


def test_analyze_persists_and_returns_findings():
    findings, conn = analyze(_xml("vulnerable_single.xml"))
    assert len(findings) == 1
    assert findings[0].cve_id == "CVE-2011-2523"

    from vuln_scanner import db
    assert db.host_count(conn) == 1
    conn.close()
