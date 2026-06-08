"""Parses Nmap's XML output (`-oX`) into Host/Service records.

XML is Nmap's only structured output format with a stable schema across
versions, which is why both `python-nmap` and most SOC tooling parse it
rather than scraping the human-readable console output.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from .models import Host, Service


def parse_xml(xml_path: str) -> list[Host]:
    """Read an Nmap XML report and return one Host per <host> element.

    Raises ValueError if the file isn't a recognizable Nmap XML report —
    fail fast and loudly rather than silently returning an empty scan.
    """
    path = Path(xml_path)
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError as exc:
        raise ValueError(f"{xml_path}: not valid XML ({exc})") from exc

    if root.tag != "nmaprun":
        raise ValueError(f"{xml_path}: not an Nmap XML report (root is <{root.tag}>)")

    return [_parse_host(host_el) for host_el in root.findall("host")]


def _parse_host(host_el: ET.Element) -> Host:
    status_el = host_el.find("status")
    status = status_el.get("state", "unknown") if status_el is not None else "unknown"

    address_el = host_el.find("address[@addrtype='ipv4']")
    if address_el is None:
        address_el = host_el.find("address")
    ip = address_el.get("addr", "") if address_el is not None else ""

    hostname = None
    hostnames_el = host_el.find("hostnames/hostname")
    if hostnames_el is not None:
        hostname = hostnames_el.get("name")

    services = []
    for port_el in host_el.findall("ports/port"):
        services.append(_parse_service(port_el))

    return Host(ip=ip, hostname=hostname, status=status, services=services)


def _parse_service(port_el: ET.Element) -> Service:
    state_el = port_el.find("state")
    service_el = port_el.find("service")

    return Service(
        port=int(port_el.get("portid", "0")),
        protocol=port_el.get("protocol", "tcp"),
        state=state_el.get("state", "unknown") if state_el is not None else "unknown",
        name=service_el.get("name") if service_el is not None else None,
        product=service_el.get("product") if service_el is not None else None,
        version=service_el.get("version") if service_el is not None else None,
    )
