"""Tests for the report rendering layer (console / CSV / HTML+charts)."""

from __future__ import annotations

from vuln_scanner import report
from vuln_scanner.models import Vulnerability

SAMPLE = [
    Vulnerability(host_ip="10.0.0.20", port=21, protocol="tcp", service="ftp",
                  product="vsftpd", version="2.3.4", cve_id="CVE-2011-2523",
                  severity="critical", description="Backdoored vsftpd build",
                  remediation="Upgrade and verify checksums"),
    Vulnerability(host_ip="10.0.0.31", port=22, protocol="tcp", service="ssh",
                  product="OpenSSH", version="7.2p2", cve_id="CVE-2016-6515",
                  severity="medium", description="Password-length DoS",
                  remediation="Upgrade to 7.3+"),
]


def test_console_report_lists_all_findings_and_counts():
    text = report.to_console(SAMPLE)
    assert "10.0.0.20" in text
    assert "CVE-2011-2523" in text
    assert "2 finding(s)" in text
    assert "1 critical" in text and "1 medium" in text


def test_console_report_handles_empty_findings():
    assert report.to_console([]) == "No known vulnerabilities detected."


def test_csv_report_round_trips_core_fields():
    text = report.to_csv(SAMPLE)
    lines = text.strip().splitlines()
    assert lines[0].startswith("severity,host,port")
    assert any("CVE-2011-2523" in line for line in lines)
    assert any("vsftpd" in line for line in lines)


def test_html_report_includes_charts_and_findings():
    text = report.to_html(SAMPLE, source="scan.xml", host_count=12)
    assert "<html" in text
    assert "10.0.0.20" in text
    assert "scan.xml" in text
    assert "12 host(s) scanned" in text
    assert 'class="badge critical"' in text
    assert 'class="badge medium"' in text
    # Charts are embedded as base64 PNG data URIs
    assert "data:image/png;base64," in text


def test_html_report_handles_empty_findings():
    text = report.to_html([], source="scan.xml", host_count=4)
    assert "No known vulnerabilities detected." in text
    assert "No findings to chart." in text


def test_findings_sort_by_severity_then_host_then_port():
    rows = report._sorted(SAMPLE)
    assert [f.severity for f in rows] == ["critical", "medium"]
