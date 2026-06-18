"""Cross-references discovered services against the local CVE catalog.

Matching is intentionally exact on (product, version): Nmap's service
fingerprinting already normalizes product/version strings reasonably
well, and a fuzzy match risks false positives that would undermine
trust in the report. The catalog is small and curated, so an exact
match is the right trade-off here — a real feed would add range-based
version comparison (e.g. "< 7.3").
"""

from __future__ import annotations

from .cve_data import CATALOG
from .models import Host, Vulnerability

_INDEX: dict[tuple[str, str], list] = {}
for _record in CATALOG:
    _INDEX.setdefault((_record.product.lower(), _record.version), []).append(_record)


def match_hosts(hosts: list[Host]) -> list[Vulnerability]:
    findings = []
    for host in hosts:
        for service in host.services:
            if service.state != "open" or not service.product or not service.version:
                continue
            for record in _INDEX.get((service.product.lower(), service.version), []):
                findings.append(Vulnerability(
                    host_ip=host.ip,
                    port=service.port,
                    protocol=service.protocol,
                    service=service.name or "unknown",
                    product=service.product,
                    version=service.version,
                    cve_id=record.cve_id,
                    severity=record.severity,
                    description=record.description,
                    remediation=record.remediation,
                    cvss=record.cvss,
                    cvss_vector=record.cvss_vector,
                    attack_techniques=record.attack_techniques,
                ))
    return sorted(findings, key=Vulnerability.sort_key)
