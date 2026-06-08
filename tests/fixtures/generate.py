"""Generates small, deterministic synthetic Nmap XML reports for tests.

Real Nmap XML is verbose and environment-specific (timestamps, scan
arguments, OS-detection guesses). These fixtures keep only the elements
the parser actually reads (`host`, `address`, `hostnames`, `ports`,
`service`) so the test suite can assert exact parsing/matching behavior
without depending on a live scan or a vendored multi-KB capture.

Each fixture isolates a scenario:
  - clean.xml            one host running only patched/unmatched services
  - vulnerable_single.xml one host with a single catalog-matching service
  - multi_host.xml       three hosts mixing vulnerable and clean services,
                         enough to exercise sorting, grouping, and charts
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from pathlib import Path

FIXTURES = Path(__file__).parent

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


def _host(ip: str, hostname: str | None, services: list[dict]) -> ET.Element:
    host = ET.Element("host")
    ET.SubElement(host, "status", state="up", reason="syn-ack")
    ET.SubElement(host, "address", addr=ip, addrtype="ipv4")

    if hostname:
        hostnames = ET.SubElement(host, "hostnames")
        ET.SubElement(hostnames, "hostname", name=hostname, type="PTR")

    ports = ET.SubElement(host, "ports")
    for svc in services:
        port = ET.SubElement(ports, "port", protocol=svc.get("protocol", "tcp"),
                             portid=str(svc["port"]))
        ET.SubElement(port, "state", state=svc.get("state", "open"), reason="syn-ack")
        service_attrs = {"name": svc["name"], "method": "probed", "conf": "10"}
        if "product" in svc:
            service_attrs["product"] = svc["product"]
        if "version" in svc:
            service_attrs["version"] = svc["version"]
        ET.SubElement(port, "service", **service_attrs)

    return host


def _report(hosts: list[ET.Element]) -> ET.Element:
    root = ET.Element("nmaprun", scanner="nmap", args="nmap -sV -oX - <target>", version="7.94")
    for host in hosts:
        root.append(host)
    return root


def _write(name: str, root: ET.Element) -> None:
    ET.indent(root, space="  ")
    tree = ET.ElementTree(root)
    path = FIXTURES / name
    tree.write(path, encoding="utf-8", xml_declaration=True)
    print(f"wrote {path}")


def generate_clean() -> None:
    host = _host("10.0.0.10", "lab-web.local", [
        {"port": 22, "name": "ssh", "product": "OpenSSH", "version": "9.6p1"},
        {"port": 80, "name": "http", "product": "nginx", "version": "1.25.3"},
        {"port": 443, "name": "https", "product": "nginx", "version": "1.25.3"},
    ])
    _write("clean.xml", _report([host]))


def generate_vulnerable_single() -> None:
    host = _host("10.0.0.20", "lab-ftp.local", [
        {"port": 21, "name": "ftp", "product": "vsftpd", "version": "2.3.4"},
        {"port": 22, "name": "ssh", "product": "OpenSSH", "version": "9.6p1"},
    ])
    _write("vulnerable_single.xml", _report([host]))


def generate_multi_host() -> None:
    hosts = [
        _host("10.0.0.30", "lab-dc.local", [
            {"port": 445, "name": "microsoft-ds", "product": "Microsoft-DS", "version": "6.1"},
            {"port": 3389, "name": "ms-wbt-server", "product": "Microsoft Terminal Services"},
        ]),
        _host("10.0.0.31", "lab-web2.local", [
            {"port": 80, "name": "http", "product": "Apache httpd", "version": "2.4.49"},
            {"port": 22, "name": "ssh", "product": "OpenSSH", "version": "7.2p2"},
        ]),
        _host("10.0.0.32", "lab-clean.local", [
            {"port": 22, "name": "ssh", "product": "OpenSSH", "version": "9.6p1"},
            {"port": 53, "name": "domain", "product": "ISC BIND", "version": "9.18.24"},
        ]),
    ]
    _write("multi_host.xml", _report(hosts))


if __name__ == "__main__":
    generate_clean()
    generate_vulnerable_single()
    generate_multi_host()
