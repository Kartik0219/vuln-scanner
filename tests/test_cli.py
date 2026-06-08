"""CLI smoke tests covering exit codes, report generation, the
authorization gate, and --db persistence."""

from __future__ import annotations

from pathlib import Path

import pytest

from vuln_scanner import db
from vuln_scanner.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def _xml(name: str) -> str:
    path = FIXTURES / name
    if not path.exists():
        pytest.skip(f"fixture {name} missing - run tests/fixtures/generate.py")
    return str(path)


def test_main_returns_zero_when_clean(capsys):
    rc = main(["--xml", _xml("clean.xml")])
    out = capsys.readouterr().out
    assert rc == 0
    assert "No known vulnerabilities detected." in out
    assert "host(s) scanned" in out


def test_main_returns_nonzero_when_findings_present(capsys):
    rc = main(["--xml", _xml("vulnerable_single.xml")])
    out = capsys.readouterr().out
    assert rc == 1
    assert "CVE-2011-2523" in out


def test_main_writes_csv_and_html_reports(tmp_path, capsys):
    csv_path = tmp_path / "findings.csv"
    html_path = tmp_path / "report.html"
    rc = main([
        "--xml", _xml("vulnerable_single.xml"), "-q",
        "--csv", str(csv_path), "--html", str(html_path),
    ])
    out = capsys.readouterr().out
    assert rc == 1
    assert out == ""  # -q suppresses the console table
    assert csv_path.exists() and "CVE-2011-2523" in csv_path.read_text(encoding="utf-8")
    assert html_path.exists() and "CVE-2011-2523" in html_path.read_text(encoding="utf-8")


def test_main_persists_scan_to_sqlite_file(tmp_path, capsys):
    db_path = tmp_path / "scans.sqlite3"
    rc = main(["--xml", _xml("multi_host.xml"), "--db", str(db_path), "-q"])
    capsys.readouterr()
    assert rc == 1
    assert db_path.exists()

    conn = db.connect(str(db_path))
    assert db.host_count(conn) == 3
    conn.close()


def test_main_errors_on_missing_xml_file(capsys):
    with pytest.raises(SystemExit) as exc_info:
        main(["--xml", "does-not-exist.xml"])
    assert exc_info.value.code == 2
    assert "report file not found" in capsys.readouterr().err


def test_main_errors_on_malformed_xml(tmp_path, capsys):
    bad = tmp_path / "bad.xml"
    bad.write_text("<not-nmap/>", encoding="utf-8")
    with pytest.raises(SystemExit) as exc_info:
        main(["--xml", str(bad)])
    assert exc_info.value.code == 2
    assert "not an Nmap XML report" in capsys.readouterr().err


def test_live_scan_requires_authorization_flag(capsys):
    with pytest.raises(SystemExit) as exc_info:
        main(["--target", "10.0.0.5"])
    assert exc_info.value.code == 2
    assert "live scans require --i-have-authorization" in capsys.readouterr().err


def test_target_and_xml_are_mutually_exclusive(capsys):
    with pytest.raises(SystemExit) as exc_info:
        main(["--target", "10.0.0.5", "--xml", _xml("clean.xml")])
    assert exc_info.value.code == 2
    assert "not allowed with argument" in capsys.readouterr().err
