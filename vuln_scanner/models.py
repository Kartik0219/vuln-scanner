"""Shared data structures for scan results, findings, and the CVE catalog.

These dataclasses are the contract between every layer of the tool: the
parser builds `Host`/`Service` records from Nmap XML, the matcher turns
them into `Vulnerability` findings, and the report layer renders those
findings without needing to know how they were produced.
"""

from __future__ import annotations

from dataclasses import dataclass, field

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


@dataclass
class Service:
    port: int
    protocol: str  # "tcp" / "udp"
    state: str  # "open" / "closed" / "filtered"
    name: str | None = None  # e.g. "ssh", "http"
    product: str | None = None  # e.g. "OpenSSH", "Apache httpd"
    version: str | None = None  # e.g. "7.2p2", "2.4.49"


@dataclass
class Host:
    ip: str
    hostname: str | None = None
    status: str = "up"
    services: list[Service] = field(default_factory=list)


@dataclass
class CVERecord:
    """One entry in the local known-vulnerable-version catalog."""
    product: str  # lower-cased product name to match against, e.g. "vsftpd"
    version: str  # exact version string to match, e.g. "2.3.4"
    cve_id: str
    severity: str  # "critical" / "high" / "medium" / "low"
    description: str
    remediation: str


@dataclass
class Vulnerability:
    host_ip: str
    port: int
    protocol: str
    service: str
    product: str
    version: str
    cve_id: str
    severity: str
    description: str
    remediation: str

    def sort_key(self) -> tuple:
        return (SEVERITY_ORDER.get(self.severity, 99), self.host_ip, self.port)
