#!/usr/bin/env python3

import argparse
import ipaddress
import json
import os
import sys
import time
from pathlib import Path

import requests


ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"


def is_public_ip(ip):
    """Check whether an IP is publicly routable."""
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def load_cache(path):
    """Load previously collected AbuseIPDB results."""
    if not path.exists():
        return {}

    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        print(f"Warning: Could not read cache: {path}")
        return {}


def save_cache(path, cache):
    """Save AbuseIPDB results to disk."""
    path.parent.mkdir(parents=True, exist_ok=True)

    temp_path = path.with_suffix(".tmp")

    with temp_path.open("w", encoding="utf-8") as f:
        json.dump(cache, f, indent=2)

    temp_path.replace(path)


def check_abuseipdb(ip, api_key, max_age_days=90):
    """Query AbuseIPDB for one IP."""

    headers = {
        "Accept": "application/json",
        "Key": api_key,
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": max_age_days,
    }

    try:
        response = requests.get(
            ABUSEIPDB_URL,
            headers=headers,
            params=params,
            timeout=15,
        )

    except requests.RequestException as exc:
        return {
            "status": "error",
            "error": str(exc),
        }

    if response.status_code != 200:
        try:
            error_data = response.json()
        except ValueError:
            error_data = response.text

        return {
            "status": "error",
            "http_status": response.status_code,
            "error": error_data,
        }

    try:
        data = response.json()["data"]
    except (ValueError, KeyError):
        return {
            "status": "error",
            "error": "Invalid response from AbuseIPDB",
        }

    return {
        "status": "success",
        "ipAddress": data.get("ipAddress"),
        "isWhitelisted": data.get("isWhitelisted"),
        "abuseConfidenceScore": data.get("abuseConfidenceScore"),
        "countryCode": data.get("countryCode"),
        "countryName": data.get("countryName"),
        "usageType": data.get("usageType"),
        "isp": data.get("isp"),
        "domain": data.get("domain"),
        "hostnames": data.get("hostnames"),
        "totalReports": data.get("totalReports"),
        "numDistinctUsers": data.get("numDistinctUsers"),
        "lastReportedAt": data.get("lastReportedAt"),
    }


def collect_ips(input_files):
    """Collect unique public source IPs."""

    ips = set()
    event_count = 0

    for input_file in input_files:
        with open(input_file, "r", encoding="utf-8") as f:

            for line_number, line in enumerate(f, 1):
                line = line.strip()

                if not line:
                    continue

                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    print(
                        f"Warning: Invalid JSON in "
                        f"{input_file}:{line_number}",
                        file=sys.stderr,
                    )
                    continue

                event_count += 1

                ip = event.get("source_ip")

                if ip and is_public_ip(ip):
                    ips.add(ip)

    return ips, event_count


def main():

    parser = argparse.ArgumentParser(
        description="Enrich Cowrie events using AbuseIPDB."
    )

    parser.add_argument(
        "input",
        nargs="+",
        help="Normalized JSONL file(s)",
    )

    parser.add_argument(
        "--output",
        default="output/enriched-events.jsonl",
        help="Output JSONL file",
    )

    parser.add_argument(
        "--cache",
        default="output/abuseipdb-cache.json",
        help="AbuseIPDB cache file",
    )

    parser.add_argument(
        "--max-age",
        type=int,
        default=90,
        help="Only consider reports from this many days",
    )

    args = parser.parse_args()

    api_key = os.environ.get("ABUSEIPDB_API_KEY")

    if not api_key:
        print(
            "ERROR: ABUSEIPDB_API_KEY is not set.",
            file=sys.stderr,
        )
        print(
            'Run: export ABUSEIPDB_API_KEY="YOUR_KEY"',
            file=sys.stderr,
        )
        sys.exit(1)

    cache_path = Path(args.cache)
    output_path = Path(args.output)

    cache = load_cache(cache_path)

    ips, event_count = collect_ips(args.input)

    print(f"Found {event_count} normalized events.")
    print(f"Found {len(ips)} unique public source IPs.")

    uncached_ips = sorted(
        ip for ip in ips
        if ip not in cache
    )

    print(
        f"Need to query AbuseIPDB for "
        f"{len(uncached_ips)} IPs."
    )

    # Query AbuseIPDB only for IPs not already cached.
    for index, ip in enumerate(uncached_ips, 1):

        print(
            f"[{index}/{len(uncached_ips)}] "
            f"Checking {ip}..."
        )

        result = check_abuseipdb(
            ip,
            api_key,
            max_age_days=args.max_age,
        )

        cache[ip] = result

        # Save after every request.
        save_cache(cache_path, cache)

        if result["status"] == "success":

            print(
                f"    Score: "
                f"{result.get('abuseConfidenceScore')} | "
                f"Reports: "
                f"{result.get('totalReports')} | "
                f"Country: "
                f"{result.get('countryCode')} | "
                f"ISP: "
                f"{result.get('isp')}"
            )

        else:

            print(
                f"    Error: "
                f"{result.get('error')}"
            )

        # Avoid hammering the API.
        time.sleep(1)

    # Create enriched JSONL.
    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    written = 0

    with output_path.open(
        "w",
        encoding="utf-8",
    ) as out:

        for input_file in args.input:

            with open(
                input_file,
                "r",
                encoding="utf-8",
            ) as f:

                for line in f:

                    line = line.strip()

                    if not line:
                        continue

                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    ip = event.get("source_ip")

                    if ip and ip in cache:

                        event["enrichment"] = {
                            "abuseipdb": cache[ip]
                        }

                    out.write(
                        json.dumps(
                            event,
                            separators=(",", ":"),
                        )
                        + "\n"
                    )

                    written += 1

    print()
    print(f"Enriched {written} events.")
    print(f"Output: {output_path}")
    print(f"Cache:  {cache_path}")


if __name__ == "__main__":
    main()