"""Renders vulnerability findings as a console table, CSV, or a
self-contained HTML report with embedded matplotlib charts."""

from __future__ import annotations

import base64
import csv
import html
import io
from collections import Counter
from datetime import datetime, timezone

import matplotlib
matplotlib.use("Agg")  # headless backend - no display server needed
import matplotlib.pyplot as plt

from .models import SEVERITY_ORDER, Vulnerability

SEVERITY_COLORS = {"critical": "#82071e", "high": "#cf222e", "medium": "#9a6700", "low": "#57606a"}


def _sorted(findings: list[Vulnerability]) -> list[Vulnerability]:
    return sorted(findings, key=Vulnerability.sort_key)


# ----------------------------------------------------------------- console

def to_console(findings: list[Vulnerability]) -> str:
    if not findings:
        return "No known vulnerabilities detected."

    rows = _sorted(findings)
    headers = ["Severity", "Host", "Port", "Service", "Product/Version", "CVE", "Description"]
    table = [headers]
    for f in rows:
        table.append([
            f.severity.upper(), f.host_ip, f"{f.port}/{f.protocol}", f.service,
            f"{f.product} {f.version}", f.cve_id, f.description,
        ])

    widths = [max(len(str(row[i])) for row in table) for i in range(len(headers))]
    lines = []
    for i, row in enumerate(table):
        lines.append(" | ".join(str(c).ljust(widths[j]) for j, c in enumerate(row)))
        if i == 0:
            lines.append("-+-".join("-" * w for w in widths))

    counts = Counter(f.severity for f in findings)
    summary = (f"\n{len(findings)} finding(s) - "
               f"{counts.get('critical', 0)} critical, {counts.get('high', 0)} high, "
               f"{counts.get('medium', 0)} medium, {counts.get('low', 0)} low")
    return "\n".join(lines) + summary


# --------------------------------------------------------------------- csv

def to_csv(findings: list[Vulnerability]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["severity", "host", "port", "protocol", "service", "product",
                     "version", "cve_id", "description", "remediation"])
    for f in _sorted(findings):
        writer.writerow([f.severity, f.host_ip, f.port, f.protocol, f.service, f.product,
                         f.version, f.cve_id, f.description, f.remediation])
    return buf.getvalue()


# -------------------------------------------------------------------- charts

def _fig_to_data_uri(fig) -> str:
    buf = io.BytesIO()
    fig.savefig(buf, format="png", bbox_inches="tight", dpi=110)
    plt.close(fig)
    encoded = base64.b64encode(buf.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded}"


def _severity_chart(findings: list[Vulnerability]) -> str | None:
    if not findings:
        return None
    counts = Counter(f.severity for f in findings)
    severities = [s for s in SEVERITY_ORDER if counts.get(s)]

    fig, ax = plt.subplots(figsize=(6, 3.2))
    ax.barh(severities, [counts[s] for s in severities],
            color=[SEVERITY_COLORS[s] for s in severities])
    ax.set_xlabel("Finding count")
    ax.set_title("Findings by severity")
    ax.invert_yaxis()
    fig.tight_layout()
    return _fig_to_data_uri(fig)


def _top_hosts_chart(findings: list[Vulnerability]) -> str | None:
    if not findings:
        return None
    counts = Counter(f.host_ip for f in findings)
    top = counts.most_common(8)
    if not top:
        return None
    hosts, values = zip(*top)

    fig, ax = plt.subplots(figsize=(6, 3.2))
    ax.barh(hosts, values, color="#0969da")
    ax.set_xlabel("Finding count")
    ax.set_title("Most-vulnerable hosts")
    ax.invert_yaxis()
    fig.tight_layout()
    return _fig_to_data_uri(fig)


def _top_cves_chart(findings: list[Vulnerability]) -> str | None:
    if not findings:
        return None
    counts = Counter(f.cve_id for f in findings)
    top = counts.most_common(8)
    if not top:
        return None
    cves, values = zip(*top)

    fig, ax = plt.subplots(figsize=(6, 3.2))
    ax.barh(cves, values, color="#bf3989")
    ax.set_xlabel("Affected host count")
    ax.set_title("Most common CVEs")
    ax.invert_yaxis()
    fig.tight_layout()
    return _fig_to_data_uri(fig)


# -------------------------------------------------------------------- html

_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Vulnerability Scan Report</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 2rem; color: #1b1f23; }}
  h1 {{ margin-bottom: 0.2rem; }}
  h2 {{ margin-top: 2rem; font-size: 1.1rem; color: #57606a; }}
  .meta {{ color: #57606a; margin-bottom: 1.5rem; }}
  .charts {{ display: flex; flex-wrap: wrap; gap: 1rem; }}
  .charts img {{ max-width: 100%; border: 1px solid #d0d7de; border-radius: 6px; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: 1rem; }}
  th, td {{ border: 1px solid #d0d7de; padding: 0.5rem 0.75rem; text-align: left; vertical-align: top; }}
  th {{ background: #f6f8fa; }}
  tr.critical {{ background: #ffd7d5; }}
  tr.high {{ background: #ffeef0; }}
  tr.medium {{ background: #fff8e6; }}
  tr.low {{ background: #f6f8fa; }}
  .badge {{ font-weight: 600; padding: 0.1rem 0.5rem; border-radius: 0.3rem; color: white; }}
  .badge.critical {{ background: #82071e; }}
  .badge.high {{ background: #cf222e; }}
  .badge.medium {{ background: #9a6700; }}
  .badge.low {{ background: #57606a; }}
  code {{ font-size: 0.85em; }}
</style>
</head>
<body>
  <h1>Vulnerability Scan Report</h1>
  <p class="meta">Source: <code>{source}</code> &middot; {host_count} host(s) scanned
     &middot; Generated {generated} &middot; {summary}</p>

  <h2>Overview</h2>
  <div class="charts">{charts}</div>

  <h2>Findings</h2>
  <table>
    <thead>
      <tr><th>Severity</th><th>Host</th><th>Port</th><th>Service</th>
          <th>Product / Version</th><th>CVE</th><th>Description</th><th>Remediation</th></tr>
    </thead>
    <tbody>
      {rows}
    </tbody>
  </table>
</body>
</html>
"""


def to_html(findings: list[Vulnerability], source: str = "", host_count: int = 0) -> str:
    rows = _sorted(findings)
    counts = Counter(f.severity for f in findings)
    summary = (f"{counts.get('critical', 0)} critical, {counts.get('high', 0)} high, "
               f"{counts.get('medium', 0)} medium, {counts.get('low', 0)} low "
               f"({len(findings)} total)") if findings else "No known vulnerabilities found"

    chart_imgs = [
        ("Findings by severity", _severity_chart(findings)),
        ("Most-vulnerable hosts", _top_hosts_chart(findings)),
        ("Most common CVEs", _top_cves_chart(findings)),
    ]
    charts_html = "\n".join(
        f'<figure><img src="{uri}" alt="{html.escape(title)}"></figure>'
        for title, uri in chart_imgs if uri
    ) or "<p>No findings to chart.</p>"

    body_rows = []
    for f in rows:
        body_rows.append(
            f'<tr class="{f.severity}">'
            f'<td><span class="badge {f.severity}">{f.severity.upper()}</span></td>'
            f'<td>{html.escape(f.host_ip)}</td>'
            f'<td>{f.port}/{html.escape(f.protocol)}</td>'
            f'<td>{html.escape(f.service)}</td>'
            f'<td>{html.escape(f.product)} {html.escape(f.version)}</td>'
            f'<td><code>{html.escape(f.cve_id)}</code></td>'
            f'<td>{html.escape(f.description)}</td>'
            f'<td>{html.escape(f.remediation)}</td>'
            f'</tr>'
        )
    if not body_rows:
        body_rows.append('<tr><td colspan="8">No known vulnerabilities detected.</td></tr>')

    return _HTML_TEMPLATE.format(
        source=html.escape(source),
        host_count=host_count,
        generated=datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        summary=summary,
        charts=charts_html,
        rows="\n      ".join(body_rows),
    )
