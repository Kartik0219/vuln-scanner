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

from . import attack
from .models import SEVERITY_ORDER, Vulnerability

SEVERITY_COLORS = {"critical": "#82071e", "high": "#cf222e", "medium": "#9a6700", "low": "#57606a"}


def _sorted(findings: list[Vulnerability]) -> list[Vulnerability]:
    return sorted(findings, key=Vulnerability.sort_key)


# ----------------------------------------------------------------- console

def to_console(findings: list[Vulnerability]) -> str:
    if not findings:
        return "No known vulnerabilities detected."

    rows = _sorted(findings)
    headers = ["Severity", "CVSS", "Host", "Port", "Service", "Product/Version", "CVE", "ATT&CK", "Description"]
    table = [headers]
    for f in rows:
        table.append([
            f.severity.upper(), f"{f.cvss:.1f}", f.host_ip, f"{f.port}/{f.protocol}", f.service,
            f"{f.product} {f.version}", f.cve_id, ", ".join(f.attack_techniques) or "-", f.description,
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
                     "version", "cve_id", "description", "remediation",
                     "cvss", "cvss_vector", "attack"])
    for f in _sorted(findings):
        writer.writerow([f.severity, f.host_ip, f.port, f.protocol, f.service, f.product,
                         f.version, f.cve_id, f.description, f.remediation,
                         f.cvss, f.cvss_vector, ";".join(f.attack_techniques)])
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
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Vulnerability Scan Report</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; }}
  body {{
    font-family: -apple-system, "Helvetica Neue", Arial, sans-serif;
    background: #f5f5f7;
    margin: 0;
    padding: 2.5rem 1.5rem 5rem;
    color: #1d1d1f;
    -webkit-font-smoothing: antialiased;
  }}
  .container {{ max-width: 1040px; margin: 0 auto; }}
  h1 {{
    font-size: 2.2rem;
    font-weight: 700;
    letter-spacing: -0.025em;
    margin: 0 0 0.4rem;
  }}
  h2 {{
    font-size: 0.72rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.07em;
    color: #6e6e73;
    margin: 2.5rem 0 0.8rem;
  }}
  .meta {{
    font-size: 0.88rem;
    color: #6e6e73;
    margin: 0 0 0.5rem;
  }}
  .card {{
    background: #fff;
    border-radius: 18px;
    box-shadow: 0 2px 14px rgba(0,0,0,.06);
    overflow: hidden;
    margin-bottom: 1rem;
  }}
  .charts {{ display: flex; flex-wrap: wrap; gap: 1rem; padding: 1.5rem; }}
  .charts img {{ max-width: 100%; border-radius: 10px; }}
  table {{ border-collapse: collapse; width: 100%; font-size: 0.88rem; }}
  th {{
    font-size: 0.7rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: #6e6e73;
    padding: 0.85rem 1.25rem;
    text-align: left;
    background: #fafafa;
    border-bottom: 1px solid #f0f0f0;
    white-space: nowrap;
  }}
  td {{
    padding: 0.85rem 1.25rem;
    border-bottom: 1px solid #f5f5f7;
    vertical-align: top;
  }}
  tr:last-child td {{ border-bottom: none; }}
  tr.critical {{ background: rgba(255,59,48,.045); }}
  tr.high     {{ background: rgba(255,103,0,.045); }}
  tr.medium   {{ background: rgba(255,149,0,.045); }}
  tr.low      {{ background: transparent; }}
  .badge {{
    display: inline-block;
    font-size: 0.7rem;
    font-weight: 600;
    letter-spacing: 0.03em;
    padding: 0.22rem 0.65rem;
    border-radius: 20px;
    color: #fff;
    white-space: nowrap;
  }}
  .badge.critical {{ background: #ff3b30; }}
  .badge.high     {{ background: #ff6700; }}
  .badge.medium   {{ background: #ff9500; }}
  .badge.low      {{ background: #34c759; }}
  .cvss {{ font-weight: 700; font-variant-numeric: tabular-nums; }}
  .att {{
    display: inline-block;
    font-size: 0.7rem;
    font-weight: 600;
    text-decoration: none;
    margin: 0 0.15rem 0.15rem 0;
    padding: 0.1rem 0.45rem;
    border-radius: 5px;
    background: #eaf2ff;
    color: #0969da;
    border: 1px solid #d0e2ff;
    white-space: nowrap;
  }}
  .att:hover {{ border-color: #0969da; }}
  code {{
    font-family: "SF Mono", Menlo, Monaco, Consolas, monospace;
    font-size: 0.82em;
    background: #f5f5f7;
    padding: 0.1em 0.4em;
    border-radius: 5px;
  }}
</style>
</head>
<body>
<div class="container">
  <h1>Vulnerability Scan Report</h1>
  <p class="meta">Source: <code>{source}</code> &middot; {host_count} host(s) scanned
     &middot; Generated {generated} &middot; {summary}</p>

  <h2>Overview</h2>
  <div class="card"><div class="charts">{charts}</div></div>

  <h2>Findings</h2>
  <div class="card">
    <table>
      <thead>
        <tr><th>Severity</th><th>CVSS</th><th>Host</th><th>Port</th><th>Service</th>
            <th>Product / Version</th><th>CVE</th><th>ATT&amp;CK</th><th>Description</th><th>Remediation</th></tr>
      </thead>
      <tbody>
        {rows}
      </tbody>
    </table>
  </div>
</div>
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
        att_html = " ".join(
            f'<a class="att" href="{html.escape(attack.url(t))}" target="_blank" '
            f'rel="noopener" title="{html.escape(attack.name(t))}">{html.escape(t)}</a>'
            for t in f.attack_techniques
        ) or "-"
        cvss_disp = f"{f.cvss:.1f}" if f.cvss else "-"
        body_rows.append(
            f'<tr class="{f.severity}">'
            f'<td><span class="badge {f.severity}">{f.severity.upper()}</span></td>'
            f'<td class="cvss" title="{html.escape(f.cvss_vector)}">{cvss_disp}</td>'
            f'<td>{html.escape(f.host_ip)}</td>'
            f'<td>{f.port}/{html.escape(f.protocol)}</td>'
            f'<td>{html.escape(f.service)}</td>'
            f'<td>{html.escape(f.product)} {html.escape(f.version)}</td>'
            f'<td><a href="{html.escape(f.nvd_url)}" target="_blank" rel="noopener"><code>{html.escape(f.cve_id)}</code></a></td>'
            f'<td>{att_html}</td>'
            f'<td>{html.escape(f.description)}</td>'
            f'<td>{html.escape(f.remediation)}</td>'
            f'</tr>'
        )
    if not body_rows:
        body_rows.append('<tr><td colspan="10">No known vulnerabilities detected.</td></tr>')

    return _HTML_TEMPLATE.format(
        source=html.escape(source),
        host_count=host_count,
        generated=datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        summary=summary,
        charts=charts_html,
        rows="\n      ".join(body_rows),
    )
