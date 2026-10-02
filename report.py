#!/usr/bin/env python3

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path


def load_jsonl(path):
    events = []

    with open(path, "r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            line = line.strip()

            if not line:
                continue

            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                print(f"[WARN] Invalid JSON at {path}:{line_number}")
                continue

            if isinstance(data, dict):
                events.append(data)

    return events


def top_items(counter, limit=10):
    return [
        {
            "value": value,
            "count": count,
        }
        for value, count in counter.most_common(limit)
    ]


def build_report(events, alerts):
    report = {
        "summary": {},
        "severity": {},
        "attack_trends": [],
        "top_source_ips": [],
        "top_countries": [],
        "top_passwords": [],
        "top_usernames": [],
        "top_techniques": [],
        "top_alert_tags": [],
        "critical_incidents": [],
    }

    # ---------------------------------------------------------
    # Basic summary
    # ---------------------------------------------------------

    source_ips = {
        event.get("source_ip")
        for event in events
        if event.get("source_ip")
    }

    sessions = {
        event.get("session_id") or event.get("session")
        for event in events
        if event.get("session_id") or event.get("session")
    }

    report["summary"] = {
        "total_events": len(events),
        "total_alerts": len(alerts),
        "unique_source_ips": len(source_ips),
        "unique_sessions": len(sessions),
    }

    # ---------------------------------------------------------
    # Severity
    # ---------------------------------------------------------

    severity_counter = Counter(
        alert.get("severity", "unknown")
        for alert in alerts
    )

    report["severity"] = dict(severity_counter)

    # ---------------------------------------------------------
    # Attack trends by day
    # ---------------------------------------------------------

    daily = Counter()

    for event in events:
        timestamp = event.get("timestamp")

        if timestamp:
            day = timestamp[:10]
            daily[day] += 1

    report["attack_trends"] = [
        {
            "date": date,
            "events": count,
        }
        for date, count in sorted(daily.items())
    ]

    # ---------------------------------------------------------
    # Top attacking IPs
    # ---------------------------------------------------------

    ip_counter = Counter(
        event.get("source_ip")
        for event in events
        if event.get("source_ip")
    )

    report["top_source_ips"] = top_items(ip_counter)

    # ---------------------------------------------------------
    # Top countries
    #
    # Supports common enrichment field names.
    # ---------------------------------------------------------

    country_counter = Counter()

    for event in events:
        abuseipdb = event.get("enrichment", {}).get("abuseipdb", {})

        country = (
            abuseipdb.get("countryName")
            or abuseipdb.get("countryCode")
        )

        if country:
            country_counter[country] += 1

    report["top_countries"] = top_items(country_counter)

    # ---------------------------------------------------------
    # Attempted passwords
    # ---------------------------------------------------------

    password_counter = Counter()

    for event in events:
        if event.get("event_type") != "cowrie.login.success":
            continue

        password = (
            event.get("attempted_password")
            or event.get("password")
        )

        if password:
            password_counter[str(password)] += 1

    report["top_passwords"] = top_items(password_counter)

    # ---------------------------------------------------------
    # Usernames
    # ---------------------------------------------------------

    username_counter = Counter()

    for event in events:
        if event.get("event_type") != "cowrie.login.success":
            continue

        username = event.get("username")

        if username:
            username_counter[str(username)] += 1

    report["top_usernames"] = top_items(username_counter)

    # ---------------------------------------------------------
    # Detection techniques
    # ---------------------------------------------------------

    technique_counter = Counter()

    for alert in alerts:
        for tag in alert.get("tags", []):
            technique_counter[tag] += 1

    report["top_techniques"] = top_items(technique_counter)

    # ---------------------------------------------------------
    # Alert tags
    # ---------------------------------------------------------

    report["top_alert_tags"] = top_items(technique_counter)

    # ---------------------------------------------------------
    # Critical incidents
    # ---------------------------------------------------------

    critical = [
        alert
        for alert in alerts
        if alert.get("severity") == "critical"
    ]

    critical.sort(
        key=lambda alert: alert.get("risk_score", 0),
        reverse=True,
    )

    report["critical_incidents"] = critical

    return report


def print_dashboard(report):
    summary = report["summary"]
    severity = report["severity"]

    print()
    print("=" * 60)
    print("        HONEYPOT THREAT DETECTION REPORT")
    print("=" * 60)

    print()
    print("SUMMARY")
    print("-" * 60)
    print(f"Total events       : {summary['total_events']}")
    print(f"Total incidents    : {summary['total_alerts']}")
    print(f"Unique source IPs  : {summary['unique_source_ips']}")
    print(f"Unique sessions    : {summary['unique_sessions']}")

    print()
    print("SEVERITY")
    print("-" * 60)

    for level in ["critical", "high", "medium", "low"]:
        print(f"{level:<12}: {severity.get(level, 0)}")

    print()
    print("TOP ATTACKING IPs")
    print("-" * 60)

    for item in report["top_source_ips"]:
        print(f"{item['value']:<20} {item['count']} events")

    print()
    print("TOP COUNTRIES")
    print("-" * 60)

    for item in report["top_countries"]:
        print(f"{item['value']:<20} {item['count']} events")

    print()
    print("MOST ATTEMPTED PASSWORDS")
    print("-" * 60)

    for item in report["top_passwords"]:
        print(f"{item['value']:<20} {item['count']} attempts")

    print()
    print("MOST USED USERNAMES")
    print("-" * 60)

    for item in report["top_usernames"]:
        print(f"{item['value']:<20} {item['count']} attempts")

    print()
    print("TOP DETECTION TECHNIQUES")
    print("-" * 60)

    for item in report["top_techniques"]:
        print(f"{item['value']:<30} {item['count']}")

    print()
    print("CRITICAL INCIDENTS")
    print("-" * 60)

    for alert in report["critical_incidents"]:
        print(
            f"{alert.get('timestamp')} | "
            f"{alert.get('source_ip')} | "
            f"risk={alert.get('risk_score')} | "
            f"session={alert.get('session')}"
        )

    print()
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="Generate a report from honeypot events and alerts."
    )

    parser.add_argument(
        "events",
        help="Path to enriched-events.jsonl",
    )

    parser.add_argument(
        "alerts",
        help="Path to alerts.jsonl",
    )

    parser.add_argument(
        "--output",
        default="output/report.json",
        help="Output JSON report path",
    )

    args = parser.parse_args()

    events = load_jsonl(args.events)
    alerts = load_jsonl(args.alerts)

    print(
        f"Loaded {len(events)} enriched events "
        f"and {len(alerts)} alerts."
    )

    report = build_report(events, alerts)

    output_path = Path(args.output)
    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with output_path.open(
        "w",
        encoding="utf-8",
    ) as handle:
        json.dump(
            report,
            handle,
            indent=2,
            ensure_ascii=False,
        )

    print_dashboard(report)

    print()
    print(f"Report: {output_path}")


if __name__ == "__main__":
    main()