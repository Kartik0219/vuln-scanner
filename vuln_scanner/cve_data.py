"""A small, curated catalog of well-known vulnerable service versions.

A production scanner would query the live NVD API or a mirrored CVE
feed. For a portfolio-sized project that means either a multi-GB local
mirror or a network dependency that makes tests slow, flaky, and rate
limited — none of which is worth it for what is fundamentally a
product/version lookup. Instead we ship a small table of textbook,
widely-documented vulnerabilities (the kind that show up in CTFs and
vulnerable-by-design lab images) so detection stays fast, deterministic,
and offline. `matcher.py` does the lookup; swapping in a live NVD/CVE
feed later only means replacing `CATALOG` with a real data source.
"""

from __future__ import annotations

from .models import CVERecord

CATALOG: list[CVERecord] = [
    CVERecord(
        product="vsftpd",
        version="2.3.4",
        cve_id="CVE-2011-2523",
        severity="critical",
        description="vsftpd 2.3.4 contains a backdoor that opens a root shell on "
                    "port 6200 when a username ending in ':)' is supplied.",
        remediation="Upgrade to a current vsftpd release and verify the binary "
                    "against upstream checksums; this version was a compromised build.",
    ),
    CVERecord(
        product="proftpd",
        version="1.3.3c",
        cve_id="CVE-2010-4221",
        severity="critical",
        description="ProFTPD 1.3.3c ships with a backdoored source tarball that "
                    "grants remote attackers a root shell via a crafted command.",
        remediation="Upgrade to a current ProFTPD release sourced from the "
                    "official distribution and verify checksums.",
    ),
    CVERecord(
        product="openssh",
        version="7.2p2",
        cve_id="CVE-2016-6515",
        severity="medium",
        description="OpenSSH through 7.2 allows remote attackers to cause a "
                    "denial of service (crypt CPU consumption) via a long password "
                    "string.",
        remediation="Upgrade to OpenSSH 7.3 or later, which caps password length "
                    "before hashing.",
    ),
    CVERecord(
        product="apache httpd",
        version="2.4.49",
        cve_id="CVE-2021-41773",
        severity="critical",
        description="A path-traversal flaw in Apache HTTP Server 2.4.49 allows "
                    "mapping URLs to files outside the document root, and can lead "
                    "to remote code execution if CGI is enabled.",
        remediation="Upgrade to Apache HTTP Server 2.4.51 or later.",
    ),
    CVERecord(
        product="apache httpd",
        version="2.4.7",
        cve_id="CVE-2014-0160",
        severity="high",
        description="Bundled OpenSSL is vulnerable to Heartbleed: an attacker can "
                    "read up to 64KB of process memory per request, potentially "
                    "exposing private keys, session tokens, and credentials.",
        remediation="Upgrade OpenSSL to 1.0.1g or later, reissue TLS certificates, "
                    "and rotate any secrets that may have transited the process.",
    ),
    CVERecord(
        product="microsoft-ds",
        version="6.1",
        cve_id="CVE-2017-0144",
        severity="critical",
        description="The SMBv1 server (\"EternalBlue\") mishandles crafted packets, "
                    "allowing remote code execution as SYSTEM. Used by WannaCry and "
                    "NotPetya for self-propagation.",
        remediation="Disable SMBv1 entirely and apply MS17-010 / current security "
                    "updates; isolate any hosts that cannot be patched.",
    ),
    CVERecord(
        product="unrealircd",
        version="3.2.8.1",
        cve_id="CVE-2010-2075",
        severity="critical",
        description="UnrealIRCd 3.2.8.1 distribution archives were replaced with "
                    "a backdoored version that executes arbitrary commands sent by "
                    "remote attackers.",
        remediation="Re-download UnrealIRCd from the official site, verify "
                    "checksums/signatures, and rebuild from a clean source tree.",
    ),
    CVERecord(
        product="samba",
        version="3.0.20",
        cve_id="CVE-2007-2447",
        severity="critical",
        description="The 'username map script' option in Samba 3.0.20 through "
                    "3.0.25rc3 allows remote command execution via shell "
                    "metacharacters in a crafted username.",
        remediation="Upgrade Samba to 3.0.25rc4 or later, or remove the "
                    "'username map script' configuration directive.",
    ),
]
