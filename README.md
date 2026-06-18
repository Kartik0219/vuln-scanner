# Vulnerability Scanner & Reporting Tool

A command-line tool that scans lab networks (or analyzes saved Nmap XML
reports), stores results in SQLite for historical comparison, cross-
references discovered service versions against a curated CVE catalog,
and produces console, CSV, and self-contained HTML reports with
severity charts and remediation guidance.

```
$ python -m vuln_scanner.cli --xml scan.xml

Severity | Host      | Port    | Service      | Product/Version     | CVE            | Description
---------+-----------+---------+--------------+---------------------+----------------+------------------------------------------------------------------------------------
CRITICAL | 10.0.0.30 | 445/tcp | microsoft-ds | Microsoft-DS 6.1    | CVE-2017-0144  | The SMBv1 server ("EternalBlue") mishandles crafted packets, allowing RCE as SYSTEM.
CRITICAL | 10.0.0.31 | 80/tcp  | http         | Apache httpd 2.4.49 | CVE-2021-41773 | Path-traversal flaw allows mapping URLs outside the document root; RCE if CGI enabled.
MEDIUM   | 10.0.0.31 | 22/tcp  | ssh          | OpenSSH 7.2p2       | CVE-2016-6515  | Allows remote DoS via a long password string (CPU exhaustion during bcrypt hashing).

3 finding(s) - 2 critical, 0 high, 1 medium, 0 low
```

## What it detects

The tool ships a curated catalog of well-known, textbook-level
vulnerabilities — the kind that appear in CTF lab images and
deliberately-vulnerable VMs (Metasploitable 2, VulnHub) — so findings
are both demonstrably real and well-documented:

| CVE | Service | Severity | Why it matters |
|---|---|---|---|
| CVE-2011-2523 | vsftpd 2.3.4 | Critical | Backdoored build opens a root shell on a trigger username |
| CVE-2010-4221 | ProFTPD 1.3.3c | Critical | Backdoored source tarball grants remote root |
| CVE-2017-0144 | SMBv1 / Windows 6.1 | Critical | EternalBlue — used by WannaCry and NotPetya for lateral movement |
| CVE-2021-41773 | Apache 2.4.49 | Critical | Path traversal / RCE via CGI; CVSS 9.8 |
| CVE-2007-2447 | Samba 3.0.20 | Critical | Remote code execution via username map script |
| CVE-2010-2075 | UnrealIRCd 3.2.8.1 | Critical | Backdoored distribution archive |
| CVE-2014-0160 | Apache 2.4.7 (OpenSSL) | High | Heartbleed — reads up to 64KB of process memory per request |
| CVE-2016-6515 | OpenSSH 7.2p2 | Medium | Long-password DoS via bcrypt CPU exhaustion |

Each finding includes a severity rating and a specific remediation step
so you can verify *why* something was flagged and know what to fix.

### CVSS scores & MITRE ATT&CK

Every finding also carries its **CVSS v3.1 base score** (with vector), a link to
the **NVD** entry, and the **MITRE ATT&CK** technique the flaw enables — shown in
the console and CSV, and as a score column + clickable badges/links in the HTML
report:

| CVE | CVSS | ATT&CK technique |
|---|---|---|
| CVE-2017-0144 (EternalBlue) | 8.1 | [T1210 — Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210/) |
| CVE-2021-41773 (Apache RCE) | 9.8 | [T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) |
| CVE-2016-6515 (OpenSSH DoS) | 7.5 | [T1499 — Endpoint Denial of Service](https://attack.mitre.org/techniques/T1499/) |

## Installation

```bash
git clone <this-repo>
cd vuln-scanner
python -m venv venv
# Windows: venv\Scripts\activate   |   macOS/Linux: source venv/bin/activate
pip install -r requirements.txt
```

Requires Python 3.10+ and [matplotlib](https://matplotlib.org/)
(installed via `requirements.txt`). Everything else — XML parsing,
SQLite storage, CVE matching — uses only the standard library.

Nmap is **only** required for live `--target` scans; analyzing saved
`--xml` reports works without it.

## Usage

```bash
# Analyze a saved Nmap XML report
python -m vuln_scanner.cli --xml scan.xml

# Run a live scan (requires nmap on PATH and explicit authorization)
python -m vuln_scanner.cli --target 192.168.1.100 --i-have-authorization

# Restrict scan to a port range
python -m vuln_scanner.cli --target 192.168.1.100 --i-have-authorization --ports 1-1024

# Persist scan history to a SQLite file
python -m vuln_scanner.cli --xml scan.xml --db scans.sqlite3

# Export machine-readable / shareable reports
python -m vuln_scanner.cli --xml scan.xml --csv findings.csv --html report.html

# Suppress the console table (handy alongside --csv/--html)
python -m vuln_scanner.cli --xml scan.xml -q --html report.html
```

Run `python -m vuln_scanner.cli --help` for the full option list.
The process exits with status `1` if any findings were produced and
`0` if nothing matched — handy for scripting/CI checks.

## How it's built

```
vuln_scanner/
├── models.py    # Service, Host, CVERecord, Vulnerability dataclasses
├── cve_data.py  # Static curated catalog of known-vulnerable versions
├── parser.py    # Parses Nmap -oX XML into Host/Service records
├── matcher.py   # Cross-references services against cve_data -> Vulnerability findings
├── db.py        # SQLite schema + scan/host/service storage (tracks history over time)
├── engine.py    # Orchestrates: parse -> store -> match
├── report.py    # Console table, CSV, and self-contained HTML+chart renderers
└── cli.py       # argparse front-end with authorization gate for live scans
```

The XML parsing and CVE matching are decoupled from the scan-invocation
code, so the entire analysis path is testable via XML fixtures without
needing a live network or root/administrator privileges.

## Testing

The test suite uses small, deterministic **synthetic** Nmap XML fixtures
(`tests/fixtures/generate.py`) — each targeting one scenario (clean
host, single known-vulnerable service, mixed multi-host network). This
mirrors the approach of building synthetic PCAPs or log CSVs for the
other tools in this portfolio, keeping tests fast, offline, and free of
environment-specific scan output.

```bash
pip install -r requirements-dev.txt
pytest
```

To regenerate the fixtures after changing detection logic:

```bash
python tests/fixtures/generate.py
```

`samples/README.md` lists public sources of intentionally-vulnerable
lab images (Metasploitable 2, VulnHub) for manual demos against real
targets, plus the exact Nmap command to produce XML suitable for the
`--xml` flag.

## Design notes & limitations

- **Exact version matching.** The CVE catalog uses exact product/version
  string matches against what Nmap's service fingerprinting (`-sV`)
  reports. This keeps false-positive rates near zero but means a service
  advertising a patched version (e.g. a custom build) won't be flagged.
  A production tool would add version-range comparisons (e.g. "< 7.3")
  against a live NVD/CVE feed.
- **Curated catalog, not a live feed.** The built-in catalog covers
  textbook vulnerabilities found in lab environments; it does not attempt
  to cover CVEs published after the project was written. Swapping in the
  NVD API means only replacing `cve_data.CATALOG` with a real data
  source — the matcher, engine, and reports don't need to change.
- **Scan-once, in-memory by default.** Without `--db`, results are
  stored in an in-memory SQLite database that is discarded on exit. Pass
  `--db path/to/scans.sqlite3` to persist history and track how your
  network's exposure changes over time.

## Ethical use

Only scan systems you own or have explicit written permission to test.
Using the `--target` flag without `--i-have-authorization` is blocked
by design and raises an error explaining the legal context (US CFAA, UK
Computer Misuse Act). The `--xml` path accepts any Nmap report — if you
already have a report, the tool analyzes it without re-scanning.

`samples/README.md` lists safe, legal sources of vulnerable lab images
specifically built for this kind of practice.
