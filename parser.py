#!/usr/bin/env python3
"""
Cowrie JSON log parser for the Honeypot-Driven Threat Detection Pipeline.

Reads Cowrie JSON-lines logs (including rotated files), normalizes the
different Cowrie event types into a common event structure, and writes
JSONL output suitable for later detection/enrichment.

Usage:
    python parser.py ~/honeypot-logs/cowrie.json*
    python parser.py ~/honeypot-logs/*.json --output output/normalized-events.jsonl

The parser deliberately does NOT perform external enrichment yet.
"""

from __future__ import annotations

import argparse
import glob
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


# Event categories we currently understand from the collected Cowrie logs.
EVENT_SEVERITY = {
    "cowrie.session.connect": "info",
    "cowrie.session.closed": "info",
    "cowrie.client.version": "info",
    "cowrie.client.kex": "info",
    "cowrie.client.size": "info",
    "cowrie.client.var": "info",
    "cowrie.session.params": "info",
    "cowrie.log.closed": "info",
    "cowrie.login.success": "high",
    "cowrie.command.input": "medium",
    "cowrie.command.failed": "low",
    "cowrie.session.file_download": "high",
    "cowrie.direct-tcpip.request": "high",
    "cowrie.direct-tcpip.data": "medium",
    "cowrie.direct-tcpip.ja4": "info",
    "cowrie.client.malformed_packet": "medium",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Parse and normalize Cowrie JSON logs."
    )
    parser.add_argument(
        "inputs",
        nargs="+",
        help="Cowrie JSON files or shell-expanded glob paths.",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="output/normalized-events.jsonl",
        help="Output JSONL path (default: output/normalized-events.jsonl)",
    )
    return parser.parse_args()


def expand_inputs(inputs: list[str]) -> list[Path]:
    """Expand globs and remove duplicate paths while preserving order."""
    paths: list[Path] = []

    for item in inputs:
        matches = glob.glob(item)
        if matches:
            paths.extend(Path(m) for m in matches)
        else:
            paths.append(Path(item))

    unique: list[Path] = []
    seen: set[Path] = set()

    for path in paths:
        path = path.expanduser().resolve()
        if path not in seen:
            seen.add(path)
            unique.append(path)

    return unique


def load_events(paths: Iterable[Path]) -> Iterable[dict[str, Any]]:
    """Yield valid JSON objects from Cowrie JSONL files."""
    for path in paths:
        if not path.exists():
            print(f"[WARN] File not found: {path}", file=sys.stderr)
            continue

        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line_number, line in enumerate(handle, start=1):
                line = line.strip()

                if not line:
                    continue

                try:
                    event = json.loads(line)
                except json.JSONDecodeError as exc:
                    print(
                        f"[WARN] Invalid JSON in {path}:{line_number}: {exc}",
                        file=sys.stderr,
                    )
                    continue

                if isinstance(event, dict):
                    event["_source_file"] = str(path)
                    event["_source_line"] = line_number
                    yield event


def iso_timestamp(value: Any) -> str | None:
    """Return a normalized UTC ISO timestamp when possible."""
    if not value:
        return None

    text = str(value)

    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    except ValueError:
        return text


def base_event(raw):
    return {
        "timestamp": iso_timestamp(raw.get("timestamp")),
        "session": raw.get("session"),
        "event_type": raw.get("eventid"),
        "protocol": raw.get("protocol"),
        "source_ip": raw.get("src_ip"),
        "source_port": raw.get("src_port"),
        "destination_ip": raw.get("dst_ip"),
        "destination_port": raw.get("dst_port"),
        "sensor": raw.get("sensor"),
        "severity": EVENT_SEVERITY.get(raw.get("eventid"), "unknown"),
    }

def normalize(raw: dict[str, Any]) -> dict[str, Any]:
    """
    Convert one Cowrie event into a stable schema.

    Event-specific fields are added only when relevant, which keeps the
    normalized output compact without throwing away useful evidence.
    """
    event_type = raw.get("eventid")
    event = base_event(raw)

    if event_type == "cowrie.login.success":
        event.update(
            {
                "username": raw.get("username"),
                # Kept locally for analysis. Do not publish raw output.
                "attempted_password": raw.get("password"),
                "successful_login": True,
            }
        )

    elif event_type == "cowrie.command.input":
        event.update(
            {
                "command": raw.get("input"),
                "command_success": True,
            }
        )

    elif event_type == "cowrie.command.failed":
        event.update(
            {
                "command": raw.get("input"),
                "command_success": False,
            }
        )

    elif event_type == "cowrie.session.closed":
        event["duration_ms"] = raw.get("duration_ms")

    elif event_type == "cowrie.session.params":
        event["architecture"] = raw.get("arch")

    elif event_type == "cowrie.client.version":
        event["ssh_client_version"] = raw.get("version")

    elif event_type == "cowrie.client.kex":
        event.update(
            {
                "hassh": raw.get("hassh"),
                "hassh_algorithms": raw.get("hasshAlgorithms"),
                "key_algorithms": raw.get("keyAlgs"),
                "encryption_algorithms": raw.get("encCS"),
                "mac_algorithms": raw.get("macCS"),
                "compression_algorithms": raw.get("compCS"),
            }
        )

    elif event_type == "cowrie.client.size":
        event.update(
            {
                "terminal_width": raw.get("width"),
                "terminal_height": raw.get("height"),
            }
        )

    elif event_type == "cowrie.client.var":
        event.update(
            {
                "client_variable": raw.get("name"),
                "client_variable_value": raw.get("value"),
            }
        )

    elif event_type == "cowrie.client.malformed_packet":
        event.update(
            {
                "message_number": raw.get("messagenum"),
                "packet_length": raw.get("datalen"),
                "malformed_data": raw.get("data"),
            }
        )

    elif event_type == "cowrie.session.file_download":
        event.update(
            {
                "download_path": raw.get("destfile"),
                "download_output": raw.get("outfile"),
                "sha256": raw.get("shasum"),
                "duplicate": raw.get("duplicate", False),
            }
        )

    elif event_type == "cowrie.direct-tcpip.request":
        event.update(
            {
                "forwarded_source_ip": raw.get("orig_ip"),
                "forwarded_source_port": raw.get("orig_port"),
                "forwarded_destination_ip": raw.get("dst_ip"),
                "forwarded_destination_port": raw.get("dst_port"),
            }
        )

    elif event_type == "cowrie.direct-tcpip.data":
        # Cowrie's exact fields can vary by version, so retain useful
        # event-specific data without assuming every field is present.
        for key in ("direction", "data", "dst_ip", "dst_port", "orig_ip", "orig_port"):
            if key in raw:
                event[f"tcpip_{key}"] = raw[key]

    elif event_type == "cowrie.direct-tcpip.ja4":
        event["ja4"] = raw.get("ja4")

    elif event_type == "cowrie.log.closed":
        event.update(
            {
                "tty_log": raw.get("ttylog"),
                "tty_size": raw.get("size"),
                "tty_sha256": raw.get("shasum"),
                "tty_duplicate": raw.get("duplicate", False),
                "duration_ms": raw.get("duration_ms"),
            }
        )

    # Keep the original Cowrie message as analyst-readable evidence.
    event["message"] = raw.get("message")

    return event


def main() -> int:
    args = parse_args()

    input_paths = expand_inputs(args.inputs)
    if not input_paths:
        print("[ERROR] No input files found.", file=sys.stderr)
        return 1

    output_path = Path(args.output).expanduser()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    total = 0
    by_type: dict[str, int] = {}

    with output_path.open("w", encoding="utf-8") as output:
        for raw in load_events(input_paths):
            normalized = normalize(raw)
            output.write(json.dumps(normalized, ensure_ascii=False) + "\n")

            total += 1
            event_type = normalized.get("event_type", "unknown")
            by_type[event_type] = by_type.get(event_type, 0) + 1

    print(f"Parsed {total} events from {len(input_paths)} file(s).")
    print(f"Output: {output_path}")
    print("\nEvents by type:")
    for event_type, count in sorted(by_type.items(), key=lambda item: (-item[1], item[0])):
        print(f"  {count:4}  {event_type}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
