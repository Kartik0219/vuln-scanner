# Sample Nmap XML reports for manual demos

The automated test suite runs against small, deterministic synthetic
Nmap XML files (`tests/fixtures/generate.py`), so it doesn't depend on
a live network or a local Nmap installation. To see the tool work
against **real** scan output for a demo or write-up, you have two
options.

## Option 1: Scan your own lab machine (recommended)

If Nmap is installed and you have a target you own (e.g. a home lab VM):

```bash
# Service-version scan, save XML for the tool to analyze
nmap -sV -oX scan_output.xml 192.168.1.0/24

# Then analyze offline
python -m vuln_scanner.cli --xml scan_output.xml --html report.html
```

You can also use the `--target` flag to scan and analyze in one step —
but that requires `--i-have-authorization` to confirm you own the target:

```bash
python -m vuln_scanner.cli --target 192.168.1.100 --i-have-authorization --html report.html
```

## Option 2: Intentionally vulnerable lab images

These are virtual machines built specifically to contain known
vulnerabilities for practicing security skills. Scanning them will
produce real matches against the CVE catalog:

- **Metasploitable 2** — https://sourceforge.net/projects/metasploitable/
  A deliberately insecure Ubuntu VM with vsftpd 2.3.4, Samba 3.0.20,
  UnrealIRCd 3.2.8.1, and many others — several are in the built-in
  CVE catalog and will show up as critical findings.

- **VulnHub** — https://www.vulnhub.com/
  Hundreds of community-contributed vulnerable VMs; look for "beginner"
  entries that run common services with known outdated versions.

Both are designed for exactly this kind of offline practice — they're
distributed specifically for security training on isolated networks.

## Suggested demo flow

1. Boot Metasploitable 2 in an isolated VM network (host-only adapter
   so it can't reach the internet).
2. Run `nmap -sV -oX lab_scan.xml <metasploitable-ip>`.
3. Analyze: `python -m vuln_scanner.cli --xml lab_scan.xml --html lab_report.html`
4. Open `lab_report.html` — you should see several CRITICAL/HIGH
   findings (vsftpd backdoor, Samba command injection, etc.) with CVE
   IDs and remediation steps.

Never run Nmap against systems you don't own. Keep any generated XML
and report files out of the repo (the `.gitignore` already excludes
`*.sqlite3` and generated reports).
