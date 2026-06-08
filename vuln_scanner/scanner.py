"""Thin wrapper that invokes Nmap and captures its XML report.

This module is deliberately small: Nmap already does the hard part
(packet crafting, service fingerprinting). All we do is run it with
sane defaults, write the XML to a temp file, and hand the path back to
`parser.parse_xml`. Keeping the subprocess boundary this thin makes the
rest of the tool testable purely against XML fixtures, with no need for
a live network or root/administrator privileges in CI.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

NMAP_NOT_FOUND = (
    "nmap executable not found on PATH. Install Nmap (https://nmap.org/download.html) "
    "to run live scans, or pass an existing --xml report to analyze offline."
)


class ScanError(RuntimeError):
    pass


def run_scan(target: str, *, ports: str | None = None, extra_args: list[str] | None = None) -> str:
    """Run `nmap -oX -` against `target` and return the path to the XML output.

    The caller is responsible for the authorization check — this function
    only handles process invocation. Raises ScanError if Nmap is missing
    or exits non-zero.
    """
    nmap_path = shutil.which("nmap")
    if not nmap_path:
        raise ScanError(NMAP_NOT_FOUND)

    out_path = Path(tempfile.gettempdir()) / f"vuln_scanner_{abs(hash(target))}.xml"
    args = [nmap_path, "-sV", "-oX", str(out_path)]
    if ports:
        args += ["-p", ports]
    if extra_args:
        args += extra_args
    args.append(target)

    result = subprocess.run(args, capture_output=True, text=True)
    if result.returncode != 0:
        raise ScanError(f"nmap exited with status {result.returncode}: {result.stderr.strip()}")

    return str(out_path)
