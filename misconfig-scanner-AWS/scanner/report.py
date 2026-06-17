"""
Report Generator
Supports text (console), JSON, and HTML output formats.
"""

import json
from datetime import datetime
from typing import Dict, List

SEVERITY_COLORS = {
    "CRITICAL": "#dc2626",
    "HIGH":     "#ea580c",
    "MEDIUM":   "#d97706",
    "LOW":      "#2563eb",
    "INFO":     "#6b7280",
}

SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🔵",
    "INFO":     "⚪",
}


def generate_report(findings: List[Dict], meta: Dict, summary: Dict, fmt: str = "text") -> str:
    if fmt == "json":
        return _json_report(findings, meta, summary)
    if fmt == "html":
        return _html_report(findings, meta, summary)
    return _text_report(findings, meta, summary)


def _text_report(findings, meta, summary) -> str:
    lines = [
        "",
        "=" * 70,
        "  AWS MISCONFIGURATION SCANNER REPORT",
        f"  Scanned: {meta['scan_time']}  |  Region: {meta['region']}",
        "=" * 70,
    ]

    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    for sev in sev_order:
        sev_findings = [f for f in findings if f["severity"] == sev]
        if not sev_findings:
            continue
        lines.append(f"\n{SEVERITY_EMOJI[sev]} {sev} ({len(sev_findings)})")
        lines.append("-" * 50)
        for f in sev_findings:
            lines.append(f"  [{f['check_id']}] {f['title']}")
            lines.append(f"  Resource:    {f['resource']}")
            lines.append(f"  Detail:      {f['detail']}")
            lines.append(f"  Remediation: {f['remediation']}")
            lines.append("")

    lines += [
        "=" * 70,
        "  SUMMARY",
        *[f"  {s}: {summary[s]}" for s in sev_order if summary[s]],
        f"  TOTAL: {len(findings)}",
        "=" * 70,
        "",
    ]
    return "\n".join(lines)


def _json_report(findings, meta, summary) -> str:
    return json.dumps({
        "meta":     meta,
        "summary":  summary,
        "findings": findings,
    }, indent=2, default=str)


def _html_report(findings, meta, summary) -> str:
    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    total = len(findings)

    summary_cards = ""
    for sev in sev_order:
        count = summary.get(sev, 0)
        color = SEVERITY_COLORS[sev]
        summary_cards += f"""
        <div class="card">
          <div class="card-num" style="color:{color}">{count}</div>
          <div class="card-label">{sev}</div>
        </div>"""

    findings_rows = ""
    for f in sorted(findings, key=lambda x: sev_order.index(x["severity"])):
        color = SEVERITY_COLORS[f["severity"]]
        findings_rows += f"""
        <tr>
          <td><span class="badge" style="background:{color}">{f['severity']}</span></td>
          <td>{f['service']}</td>
          <td>{f['check_id']}</td>
          <td>{f['title']}</td>
          <td class="mono">{f['resource']}</td>
          <td>{f['remediation']}</td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>AWS Misconfig Scanner Report</title>
<style>
  body {{ font-family: system-ui, sans-serif; margin: 0; background: #f8fafc; color: #1e293b; }}
  .header {{ background: #1e293b; color: white; padding: 2rem; }}
  .header h1 {{ margin: 0; font-size: 1.5rem; }}
  .header p {{ margin: 0.25rem 0 0; color: #94a3b8; font-size: 0.9rem; }}
  .content {{ max-width: 1200px; margin: 2rem auto; padding: 0 1rem; }}
  .cards {{ display: flex; gap: 1rem; margin-bottom: 2rem; flex-wrap: wrap; }}
  .card {{ background: white; border-radius: 8px; padding: 1.25rem 1.5rem; min-width: 120px; text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
  .card-num {{ font-size: 2rem; font-weight: 700; }}
  .card-label {{ font-size: 0.8rem; color: #64748b; font-weight: 500; margin-top: 0.25rem; }}
  table {{ width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
  th {{ background: #1e293b; color: white; padding: 0.75rem 1rem; text-align: left; font-size: 0.85rem; }}
  td {{ padding: 0.75rem 1rem; border-bottom: 1px solid #e2e8f0; font-size: 0.875rem; vertical-align: top; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: #f8fafc; }}
  .badge {{ color: white; padding: 3px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; white-space: nowrap; }}
  .mono {{ font-family: monospace; font-size: 0.8rem; word-break: break-all; }}
</style>
</head>
<body>
<div class="header">
  <h1>AWS Misconfiguration Scanner Report</h1>
  <p>Scanned: {meta['scan_time']} &nbsp;|&nbsp; Region: {meta['region']} &nbsp;|&nbsp; {total} total findings</p>
</div>
<div class="content">
  <div class="cards">{summary_cards}</div>
  <table>
    <thead><tr>
      <th>Severity</th><th>Service</th><th>Check ID</th>
      <th>Title</th><th>Resource</th><th>Remediation</th>
    </tr></thead>
    <tbody>{findings_rows}</tbody>
  </table>
</div>
</body>
</html>"""
