"""Tests for CVSS + MITRE ATT&CK enrichment in the vulnerability scanner."""
from __future__ import annotations

import re

from vuln_scanner import attack
from vuln_scanner.cve_data import CATALOG
from vuln_scanner.matcher import match_hosts
from vuln_scanner.models import Host, Service

_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def test_attack_catalog_wellformed():
    for key, tech in attack.TECHNIQUES.items():
        assert _ID.match(key) and tech.id == key and tech.name and tech.tactic


def test_attack_url():
    assert attack.url("T1190") == "https://attack.mitre.org/techniques/T1190/"


def test_every_catalog_entry_has_cvss_and_attack():
    for rec in CATALOG:
        assert 0.0 < rec.cvss <= 10.0, f"{rec.cve_id} missing CVSS"
        assert rec.cvss_vector.startswith("CVSS:"), f"{rec.cve_id} missing vector"
        assert rec.attack_techniques, f"{rec.cve_id} has no ATT&CK technique"
        for tid in rec.attack_techniques:
            assert tid in attack.TECHNIQUES, f"{tid} ({rec.cve_id}) not in ATT&CK catalog"


def test_matcher_carries_cvss_and_attack():
    host = Host(ip="10.0.0.5", services=[
        Service(port=21, protocol="tcp", state="open", name="ftp",
                product="vsftpd", version="2.3.4"),
    ])
    findings = match_hosts([host])
    assert findings, "vsftpd 2.3.4 should match CVE-2011-2523"
    v = findings[0]
    assert v.cve_id == "CVE-2011-2523"
    assert v.cvss == 9.8
    assert v.cvss_vector.startswith("CVSS:3.1/")
    assert v.attack_techniques == ("T1190",)
    assert v.nvd_url == "https://nvd.nist.gov/vuln/detail/CVE-2011-2523"


def test_eternalblue_maps_to_t1210():
    rec = next(r for r in CATALOG if r.cve_id == "CVE-2017-0144")
    assert rec.attack_techniques == ("T1210",)
