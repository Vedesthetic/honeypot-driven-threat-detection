#!/usr/bin/env python3

import argparse
import json
from pathlib import Path
from html import escape


def load_report(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def bar_rows(items, value_key="count"):
    if not items:
        return "<div class='empty'>No data</div>"

    maximum = max(item[value_key] for item in items) or 1
    rows = []

    for item in items:
        label = escape(str(item["value"]))
        value = item[value_key]
        width = max(3, int((value / maximum) * 100))

        rows.append(f"""
        <div class="bar-row">
            <div class="bar-label">{label}</div>
            <div class="bar-track">
                <div class="bar-fill" style="width:{width}%"></div>
            </div>
            <div class="bar-value">{value}</div>
        </div>
        """)

    return "\n".join(rows)


def severity_cards(severity):
    levels = ["critical", "high", "medium", "low"]

    return "\n".join(
        f"""
        <div class="severity-card {level}">
            <div class="severity-name">{level.upper()}</div>
            <div class="severity-value">{severity.get(level, 0)}</div>
        </div>
        """
        for level in levels
    )


def critical_incidents(incidents):
    if not incidents:
        return "<div class='empty'>No critical incidents detected.</div>"

    rows = []

    for incident in incidents:
        timestamp = escape(str(incident.get("timestamp", "Unknown")))
        source_ip = escape(str(incident.get("source_ip", "Unknown")))
        session = escape(str(incident.get("session", "Unknown")))
        risk = incident.get("risk_score", 0)

        tags = incident.get("tags", [])
        tag_html = " ".join(
            f"<span class='tag'>{escape(str(tag))}</span>"
            for tag in tags[:8]
        )

        rows.append(f"""
        <div class="incident">
            <div class="incident-top">
                <strong>Risk {risk}</strong>
                <span>{timestamp}</span>
            </div>

            <div class="incident-source">
                Source: <strong>{source_ip}</strong>
                &nbsp; | &nbsp;
                Session: <code>{session}</code>
            </div>

            <div class="tags">
                {tag_html}
            </div>
        </div>
        """)

    return "\n".join(rows)


def generate_html(report):
    summary = report.get("summary", {})
    severity = report.get("severity", {})

    countries = report.get("top_countries", [])
    ips = report.get("top_source_ips", [])
    passwords = report.get("top_passwords", [])
    usernames = report.get("top_usernames", [])
    techniques = report.get("top_techniques", [])
    incidents = report.get("critical_incidents", [])

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">

<title>Honeypot Threat Detection Dashboard</title>

<style>

* {{
    box-sizing: border-box;
}}

body {{
    margin: 0;
    background: #0b0f14;
    color: #e6edf3;
    font-family:
        Inter,
        system-ui,
        -apple-system,
        BlinkMacSystemFont,
        "Segoe UI",
        sans-serif;
}}

.container {{
    max-width: 1400px;
    margin: auto;
    padding: 32px;
}}

header {{
    margin-bottom: 30px;
}}

h1 {{
    margin: 0;
    font-size: 30px;
}}

.subtitle {{
    margin-top: 8px;
    color: #8b949e;
}}

.grid {{
    display: grid;
    gap: 18px;
}}

.summary-grid {{
    grid-template-columns:
        repeat(4, minmax(0, 1fr));
}}

.card {{
    background: #111820;
    border: 1px solid #26313c;
    border-radius: 12px;
    padding: 22px;
}}

.metric-label {{
    color: #8b949e;
    font-size: 13px;
    text-transform: uppercase;
    letter-spacing: .08em;
}}

.metric-value {{
    margin-top: 8px;
    font-size: 32px;
    font-weight: 700;
}}

.section-grid {{
    grid-template-columns:
        repeat(2, minmax(0, 1fr));
    margin-top: 18px;
}}

.section-title {{
    margin: 0 0 18px 0;
    font-size: 18px;
}}

.severity-grid {{
    display: grid;
    grid-template-columns:
        repeat(4, 1fr);
    gap: 12px;
}}

.severity-card {{
    padding: 18px;
    border-radius: 10px;
    background: #161d25;
    border: 1px solid #26313c;
}}

.severity-name {{
    font-size: 11px;
    letter-spacing: .08em;
    color: #8b949e;
}}

.severity-value {{
    font-size: 28px;
    font-weight: 700;
    margin-top: 5px;
}}

.critical {{
    border-color: #8b2635;
}}

.high {{
    border-color: #8b5a26;
}}

.medium {{
    border-color: #756c25;
}}

.low {{
    border-color: #315d78;
}}

.bar-row {{
    display: grid;
    grid-template-columns:
        150px 1fr 45px;
    align-items: center;
    gap: 10px;
    margin: 11px 0;
}}

.bar-label {{
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    font-size: 13px;
}}

.bar-track {{
    height: 9px;
    background: #202a34;
    border-radius: 99px;
    overflow: hidden;
}}

.bar-fill {{
    height: 100%;
    background: #3b82f6;
    border-radius: 99px;
}}

.bar-value {{
    text-align: right;
    color: #8b949e;
    font-size: 13px;
}}

.incident {{
    border: 1px solid #3a2027;
    background: #171115;
    border-radius: 10px;
    padding: 16px;
    margin-bottom: 12px;
}}

.incident-top {{
    display: flex;
    justify-content: space-between;
    gap: 15px;
    color: #ff7b8a;
}}

.incident-top span {{
    color: #8b949e;
    font-size: 12px;
}}

.incident-source {{
    margin-top: 10px;
    font-size: 13px;
    color: #c9d1d9;
}}

code {{
    color: #79c0ff;
}}

.tags {{
    margin-top: 12px;
}}

.tag {{
    display: inline-block;
    padding: 4px 8px;
    margin: 3px;
    border-radius: 5px;
    background: #252b33;
    color: #c9d1d9;
    font-size: 11px;
}}

.empty {{
    color: #8b949e;
}}

footer {{
    margin-top: 30px;
    color: #6e7681;
    font-size: 12px;
    text-align: center;
}}

@media (max-width: 900px) {{

    .summary-grid,
    .section-grid {{
        grid-template-columns: 1fr;
    }}

    .severity-grid {{
        grid-template-columns:
            repeat(2, 1fr);
    }}

}}

</style>
</head>

<body>

<div class="container">

<header>
    <h1>Honeypot Threat Detection</h1>
    <div class="subtitle">
        Cowrie SSH telemetry &amp; threat intelligence dashboard
    </div>
</header>

<!-- Summary -->

<div class="grid summary-grid">

    <div class="card">
        <div class="metric-label">Events</div>
        <div class="metric-value">
            {summary.get("total_events", 0)}
        </div>
    </div>

    <div class="card">
        <div class="metric-label">Incidents</div>
        <div class="metric-value">
            {summary.get("total_alerts", 0)}
        </div>
    </div>

    <div class="card">
        <div class="metric-label">Source IPs</div>
        <div class="metric-value">
            {summary.get("unique_source_ips", 0)}
        </div>
    </div>

    <div class="card">
        <div class="metric-label">Sessions</div>
        <div class="metric-value">
            {summary.get("unique_sessions", 0)}
        </div>
    </div>

</div>


<!-- Severity -->

<div class="card" style="margin-top:18px">

    <h2 class="section-title">Alert Severity</h2>

    <div class="severity-grid">
        {severity_cards(severity)}
    </div>

</div>


<!-- Countries / IPs -->

<div class="grid section-grid">

    <div class="card">
        <h2 class="section-title">
            Top Attacking Countries
        </h2>

        {bar_rows(countries)}
    </div>


    <div class="card">
        <h2 class="section-title">
            Top Source IPs
        </h2>

        {bar_rows(ips)}
    </div>

</div>


<!-- Passwords / usernames -->

<div class="grid section-grid">

    <div class="card">
        <h2 class="section-title">
            Most Attempted Passwords
        </h2>

        {bar_rows(passwords)}
    </div>


    <div class="card">
        <h2 class="section-title">
            Most Used Usernames
        </h2>

        {bar_rows(usernames)}
    </div>

</div>


<!-- Techniques -->

<div class="card" style="margin-top:18px">

    <h2 class="section-title">
        Detection Techniques
    </h2>

    {bar_rows(techniques)}

</div>


<!-- Critical incidents -->

<div class="card" style="margin-top:18px">

    <h2 class="section-title">
        Critical Incidents
    </h2>

    {critical_incidents(incidents)}

</div>


<footer>
    Generated from Cowrie normalized events, AbuseIPDB enrichment,
    and the custom detection engine.
</footer>

</div>

</body>
</html>
"""


def main():
    parser = argparse.ArgumentParser(
        description="Generate HTML dashboard from threat report."
    )

    parser.add_argument(
        "report",
        help="Path to report.json",
    )

    parser.add_argument(
        "--output",
        default="output/dashboard.html",
        help="Output HTML path",
    )

    args = parser.parse_args()

    report = load_report(args.report)
    html = generate_html(report)

    output_path = Path(args.output)
    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    output_path.write_text(
        html,
        encoding="utf-8",
    )

    print(f"Dashboard generated: {output_path}")


if __name__ == "__main__":
    main()