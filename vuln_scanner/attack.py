"""A tiny MITRE ATT&CK lookup for the techniques this scanner's CVEs map to.

Vulnerability scanners speak CVE/CVSS natively; ATT&CK is a secondary lens that
ties each flaw to the adversary technique it enables (e.g. EternalBlue -> T1210).
Only the handful of techniques the catalog references live here.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactic: str


TECHNIQUES: dict[str, "Technique"] = {
    "T1190": Technique("T1190", "Exploit Public-Facing Application", "Initial Access"),
    "T1210": Technique("T1210", "Exploitation of Remote Services", "Lateral Movement"),
    "T1499": Technique("T1499", "Endpoint Denial of Service", "Impact"),
}


def url(technique_id: str) -> str:
    """Canonical attack.mitre.org URL for a technique or sub-technique ID."""
    base, _, sub = technique_id.partition(".")
    tail = f"{sub}/" if sub else ""
    return f"https://attack.mitre.org/techniques/{base}/{tail}"


def name(technique_id: str) -> str:
    tech = TECHNIQUES.get(technique_id)
    return tech.name if tech else technique_id


def label(technique_id: str) -> str:
    tech = TECHNIQUES.get(technique_id)
    return f"{technique_id} {tech.name}" if tech else technique_id
