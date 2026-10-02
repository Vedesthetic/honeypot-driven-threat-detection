#!/usr/bin/env python3

import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path


# ============================================================
# Honeypot-Driven Threat Detection Pipeline
# Detection layer for normalized + enriched Cowrie events
# ============================================================


SEVERITY_THRESHOLDS = {
    "critical": 80,
    "high": 60,
    "medium": 30,
    "low": 1,
}


# ------------------------------------------------------------
# Events that are meaningful for detection.
# Everything else is treated as telemetry/noise.
# ------------------------------------------------------------

DETECTION_EVENTS = {
    "cowrie.login.success",
    "cowrie.command.input",
    "cowrie.command.failed",
    "cowrie.session.file_download",
    "cowrie.direct-tcpip.request",
    "cowrie.client.malformed_packet",
}


# ------------------------------------------------------------
# Reconnaissance commands
# ------------------------------------------------------------

RECON_COMMANDS = {
    "uname",
    "uname -a",
    "uname -s -m",
    "whoami",
    "id",
    "hostname",
    "arch",
    "pwd",
    "ls",
    "ifconfig",
    "ip addr",
    "ip route",
    "cat /etc/os-release",
}


# ------------------------------------------------------------
# Common/default credentials
# ------------------------------------------------------------

WEAK_CREDENTIALS = {
    ("root", ""),
    ("root", "root"),
    ("root", "123456"),
    ("root", "password"),
    ("root", "123"),
    ("admin", "admin"),
    ("admin", "password"),
    ("support", "support"),
    ("user", "user"),
    ("test", "test"),
    ("guest", "guest"),
}


# ------------------------------------------------------------
# Suspicious command patterns
# ------------------------------------------------------------

COMMAND_PATTERNS = [
    (
        r"\bwget\b",
        25,
        "Payload/download activity using wget",
        "payload-download",
    ),
    (
        r"\bcurl\b",
        25,
        "Payload/download activity using curl",
        "payload-download",
    ),
    (
        r"\bscp\b",
        25,
        "Remote file transfer using scp",
        "file-transfer",
    ),
    (
        r"\bssh\b",
        15,
        "Remote SSH activity",
        "remote-access",
    ),
    (
        r"\bchmod\s+[0-7]*[2367][0-7]*\b",
        25,
        "File permission modification",
        "permission-change",
    ),
    (
        r"\bchmod\s+\+x\b",
        30,
        "File made executable",
        "executable-file",
    ),
    (
        r"\bcrontab\b",
        35,
        "Potential scheduled persistence",
        "persistence",
    ),
    (
        r"\buseradd\b|\badduser\b",
        35,
        "Potential account creation",
        "account-creation",
    ),
    (
        r"/etc/shadow",
        35,
        "Attempt to access password hashes",
        "credential-access",
    ),
    (
        r"/etc/passwd",
        15,
        "System account enumeration",
        "account-enumeration",
    ),
    (
        r"authorized_keys",
        40,
        "SSH persistence through authorized_keys",
        "ssh-persistence",
    ),
    (
        r"\bnc\b|\bnetcat\b",
        35,
        "Potential network shell/tool activity",
        "network-tool",
    ),
    (
        r"\bbash\s+-i\b|\bsh\s+-i\b",
        45,
        "Interactive shell over network",
        "interactive-shell",
    ),
]


# ------------------------------------------------------------
# Strong payload-execution indicators
# ------------------------------------------------------------

CRITICAL_COMMAND_PATTERNS = [
    (
        r"\b(wget|curl)\b.*\|\s*(sh|bash)",
        60,
        "Remote payload downloaded and immediately executed",
        "remote-code-execution",
    ),
    (
        r"\|\s*(sh|bash)(\s|$)",
        50,
        "Content piped directly to shell",
        "shell-execution",
    ),
    (
        r"BEGIN OPENSSH PRIVATE KEY",
        50,
        "Private SSH key material created",
        "credential-theft",
    ),
    (
        r"chmod\s+\+x.*\b(sh|bash)\b",
        45,
        "Downloaded executable prepared for shell execution",
        "payload-execution",
    ),
]


# ============================================================
# Helpers
# ============================================================


def load_events(path):
    events = []

    with open(path, "r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            line = line.strip()

            if not line:
                continue

            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                print(
                    f"Warning: invalid JSON at "
                    f"{path}:{line_number}"
                )

    return events


def get_event_type(event):
    return (
        event.get("event_type")
        or event.get("eventid")
        or ""
    )


def get_source_ip(event):
    return (
        event.get("source_ip")
        or event.get("src_ip")
    )


def get_session(event):
    return event.get("session")


def get_command(event):
    return str(
        event.get("command")
        or event.get("input")
        or ""
    ).strip()


def get_username(event):
    return event.get("username")


def get_password(event):
    return event.get("password")


def get_abuse_score(event):
    abuse = event.get("abuseipdb")

    if isinstance(abuse, dict):
        value = abuse.get("abuseConfidenceScore")

        if value is not None:
            try:
                return int(value)
            except (TypeError, ValueError):
                pass

    value = event.get("abuse_confidence_score")

    if value is not None:
        try:
            return int(value)
        except (TypeError, ValueError):
            pass

    return 0


def get_destination(event):
    ip = (
        event.get("destination_ip")
        or event.get("dst_ip")
    )

    port = (
        event.get("destination_port")
        or event.get("dst_port")
    )

    try:
        port = int(port)
    except (TypeError, ValueError):
        port = None

    return ip, port


def classify(score):
    if score >= SEVERITY_THRESHOLDS["critical"]:
        return "critical"

    if score >= SEVERITY_THRESHOLDS["high"]:
        return "high"

    if score >= SEVERITY_THRESHOLDS["medium"]:
        return "medium"

    if score >= SEVERITY_THRESHOLDS["low"]:
        return "low"

    return "none"


def unique_append(items, value):
    if value not in items:
        items.append(value)


# ============================================================
# Command detection
# ============================================================


def detect_command(command):
    command_lower = command.lower()
    normalized = re.sub(
        r"\s+",
        " ",
        command_lower,
    ).strip()

    score = 0
    evidence = []
    tags = []

    # Reconnaissance
    if normalized in {
        item.lower()
        for item in RECON_COMMANDS
    }:
        score += 5
        evidence.append(
            f"System reconnaissance command: {command}"
        )
        tags.append("reconnaissance")

    # Strong indicators
    for pattern, points, description, tag in (
        CRITICAL_COMMAND_PATTERNS
    ):
        if re.search(pattern, command, re.IGNORECASE):
            score += points
            evidence.append(description)
            tags.append(tag)

    # Suspicious indicators
    for pattern, points, description, tag in COMMAND_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            score += points
            evidence.append(description)
            tags.append(tag)

    return score, evidence, tags


# ============================================================
# Correlation
# ============================================================


def build_context(events):
    by_source = defaultdict(list)
    by_session = defaultdict(list)

    for event in events:
        source_ip = get_source_ip(event)
        session = get_session(event)

        if source_ip:
            by_source[source_ip].append(event)

        if session:
            by_session[session].append(event)

    return by_source, by_session


def session_context(events):
    return {
        get_event_type(event)
        for event in events
    }


def source_behavior(source_events):
    """
    Identify meaningful behaviors performed by a source IP.
    Used only as correlation context.
    """

    behaviors = set()

    for event in source_events:
        event_type = get_event_type(event)

        if event_type in DETECTION_EVENTS:
            behaviors.add(event_type)

    return behaviors


# ============================================================
# Detection
# ============================================================


def detect_event(event, source_events, session_events):
    event_type = get_event_type(event)
    source_ip = get_source_ip(event)
    session = get_session(event)

    # Ignore protocol/connection telemetry completely.
    if event_type not in DETECTION_EVENTS:
        return None

    score = 0
    evidence = []
    tags = []

    # --------------------------------------------------------
    # AbuseIPDB context
    #
    # Reputation alone does NOT generate an alert.
    # It modifies the score of actual suspicious behavior.
    # --------------------------------------------------------

    abuse_score = get_abuse_score(event)

    if abuse_score >= 75:
        score += 20
        tags.append("known-malicious-ip")
        evidence.append(
            f"High AbuseIPDB confidence score: {abuse_score}"
        )

    elif abuse_score >= 25:
        score += 10
        tags.append("reported-ip")
        evidence.append(
            f"AbuseIPDB confidence score: {abuse_score}"
        )

    # --------------------------------------------------------
    # Successful login
    # --------------------------------------------------------

    if event_type == "cowrie.login.success":
        score += 10
        tags.append("successful-login")

        username = get_username(event)
        password = get_password(event)

        if username is not None and password is not None:
            credential = (
                str(username).lower(),
                str(password).lower(),
            )

            if credential in WEAK_CREDENTIALS:
                score += 20
                tags.append("weak-credential")
                evidence.append(
                    "Successful login using a common/default credential"
                )

            if str(username).lower() in {
                "root",
                "admin",
                "support",
            }:
                score += 10
                tags.append("privileged-account")
                evidence.append(
                    f"Privileged/common account used: {username}"
                )

    # --------------------------------------------------------
    # Command execution
    # --------------------------------------------------------

    if event_type in {
        "cowrie.command.input",
        "cowrie.command.failed",
    }:
        command = get_command(event)

        if command:
            command_score, command_evidence, command_tags = (
                detect_command(command)
            )

            score += command_score
            evidence.extend(command_evidence)

            for tag in command_tags:
                unique_append(tags, tag)

            if event_type == "cowrie.command.failed":
                tags.append("failed-command")

    # --------------------------------------------------------
    # File download
    # --------------------------------------------------------

    if event_type == "cowrie.session.file_download":
        score += 25
        tags.append("file-download")

        destfile = event.get("destfile")

        if destfile:
            evidence.append(
                f"File downloaded to {destfile}"
            )

        shasum = event.get("shasum")

        if shasum:
            evidence.append(
                f"Downloaded file SHA-256: {shasum}"
            )

    # --------------------------------------------------------
    # SSH forwarding
    # --------------------------------------------------------

    if event_type == "cowrie.direct-tcpip.request":
        score += 30
        tags.append("ssh-forwarding")

        destination, port = get_destination(event)

        if destination and port:
            evidence.append(
                f"SSH direct TCP forwarding to "
                f"{destination}:{port}"
            )

    # --------------------------------------------------------
    # Malformed SSH packet
    # --------------------------------------------------------

    if event_type == "cowrie.client.malformed_packet":
        score += 20
        tags.append("malformed-packet")
        evidence.append(
            "Malformed SSH packet observed"
        )

    # --------------------------------------------------------
    # Session correlation
    # --------------------------------------------------------

    session_types = session_context(session_events)

    if {
        "cowrie.login.success",
        "cowrie.command.input",
    }.issubset(session_types):

        score += 15
        tags.append("post-login-activity")
        evidence.append(
            "Successful login followed by command execution"
        )

    if {
        "cowrie.login.success",
        "cowrie.session.file_download",
    }.issubset(session_types):

        score += 20
        tags.append("post-login-download")
        evidence.append(
            "Successful login followed by file download"
        )

    if {
        "cowrie.login.success",
        "cowrie.direct-tcpip.request",
    }.issubset(session_types):

        score += 20
        tags.append("post-login-forwarding")
        evidence.append(
            "Successful login followed by SSH forwarding"
        )

    # --------------------------------------------------------
    # Source-level correlation
    #
    # Only add a small amount of context. This prevents one
    # attacker from making every harmless event an alert.
    # --------------------------------------------------------

    source_behaviors = source_behavior(source_events)

    meaningful_behavior_count = len(source_behaviors)

    if meaningful_behavior_count >= 3:
        score += 10
        tags.append("multi-stage-source")
        evidence.append(
            f"Source exhibited {meaningful_behavior_count} "
            f"different suspicious behavior types"
        )

    # --------------------------------------------------------
    # Minimum alert threshold
    #
    # Successful login by itself is recorded but isn't treated
    # as a security alert unless there is additional context.
    # --------------------------------------------------------

    if event_type == "cowrie.login.success":
        if not (
            "weak-credential" in tags
            or abuse_score >= 25
            or meaningful_behavior_count >= 2
        ):
            return None

    # Recon alone should remain low priority.
    if (
        event_type == "cowrie.command.input"
        and tags == ["reconnaissance"]
    ):
        score = max(score, 5)

    if not evidence:
        return None

    score = min(score, 100)

    return {
        "timestamp": event.get("timestamp"),
        "session": session,
        "source_ip": source_ip,
        "event_type": event_type,
        "severity": classify(score),
        "risk_score": score,
        "tags": sorted(set(tags)),
        "evidence": list(dict.fromkeys(evidence)),
    }


# ============================================================
# Alert deduplication
# ============================================================


def deduplicate_alerts(alerts):
    """
    Prevent identical detections from flooding the output.

    Events are grouped by:
        source IP
        session
        detection category

    The highest-risk alert is retained.
    """

    grouped = {}

    for alert in alerts:
        category_tags = tuple(
            sorted(
                tag
                for tag in alert["tags"]
                if tag not in {
                    "reported-ip",
                    "known-malicious-ip",
                    "successful-login",
                }
            )
        )

        key = (
            alert.get("source_ip"),
            alert.get("session"),
            category_tags,
        )

        existing = grouped.get(key)

        if existing is None:
            grouped[key] = alert
            continue

        if alert["risk_score"] > existing["risk_score"]:
            grouped[key] = alert

    return list(grouped.values())


# ============================================================
# Main
# ============================================================

def consolidate_alerts(alerts):
    """
    Consolidate multiple alerts belonging to the same
    Cowrie session into a single incident.

    The highest-risk alert becomes the base alert, while
    evidence and tags from all alerts in the session are merged.
    """

    incidents = {}

    for alert in alerts:
        session = alert.get("session")

        # If there is no session, don't accidentally merge
        # unrelated events together.
        if not session:
            key = (
                "no-session",
                alert.get("source_ip"),
                alert.get("timestamp"),
                alert.get("event_type"),
            )
        else:
            key = ("session", session)

        if key not in incidents:
            incidents[key] = {
                **alert,
                "tags": list(alert.get("tags", [])),
                "evidence": list(alert.get("evidence", [])),
                "event_types": [alert.get("event_type")],
            }
            continue

        incident = incidents[key]

        # Keep highest risk score.
        if alert["risk_score"] > incident["risk_score"]:
            incident["risk_score"] = alert["risk_score"]
            incident["severity"] = alert["severity"]

        # Keep earliest timestamp.
        if (
            alert.get("timestamp")
            and (
                not incident.get("timestamp")
                or alert["timestamp"] < incident["timestamp"]
            )
        ):
            incident["timestamp"] = alert["timestamp"]

        # Merge tags.
        for tag in alert.get("tags", []):
            unique_append(incident["tags"], tag)

        # Merge evidence.
        for item in alert.get("evidence", []):
            unique_append(incident["evidence"], item)

        # Keep every event type involved.
        event_type = alert.get("event_type")

        if event_type and event_type not in incident["event_types"]:
            incident["event_types"].append(event_type)

    # Clean output ordering.
    results = list(incidents.values())

    for incident in results:
        incident["tags"] = sorted(set(incident["tags"]))
        incident["event_types"] = sorted(set(incident["event_types"]))

    return results

def main():
    parser = argparse.ArgumentParser(
        description=(
            "Detect suspicious activity in "
            "enriched Cowrie events"
        )
    )

    parser.add_argument(
        "input",
        help="Enriched JSONL file",
    )

    parser.add_argument(
        "--output",
        default="output/alerts.jsonl",
        help="Alert output JSONL file",
    )

    args = parser.parse_args()

    events = load_events(args.input)

    print(f"Loaded {len(events)} events.")

    by_source, by_session = build_context(events)

    alerts = []

    for event in events:
        source_ip = get_source_ip(event)
        session = get_session(event)

        source_events = (
            by_source.get(source_ip, [])
            if source_ip
            else []
        )

        session_events = (
            by_session.get(session, [])
            if session
            else []
        )

        alert = detect_event(
            event,
            source_events,
            session_events,
        )

        if alert:
            alerts.append(alert)

    before = len(alerts)

    alerts = deduplicate_alerts(alerts)

    after = len(alerts)

    # Consolidate alerts belonging to the same Cowrie session
    raw_alert_count = len(alerts)

    alerts = consolidate_alerts(alerts)

    print(
      f"Consolidated {raw_alert_count} event alerts "
        f"into {len(alerts)} incidents."
    )

    output_path = Path(args.output)
    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with open(
        output_path,
        "w",
        encoding="utf-8",
    ) as handle:

        for alert in alerts:
            handle.write(
                json.dumps(alert)
                + "\n"
            )

    severity_counts = Counter(
        alert["severity"]
        for alert in alerts
    )

    tag_counts = Counter(
        tag
        for alert in alerts
        for tag in alert["tags"]
    )

    print(f"Generated {after} alerts.")
    print(
        f"Deduplicated {before - after} duplicate alerts."
    )
    print(f"Output: {output_path}")

    print("\nAlerts by severity:")

    for severity in (
        "critical",
        "high",
        "medium",
        "low",
    ):
        print(
            f"  {severity:8} "
            f"{severity_counts[severity]}"
        )

    print("\nDetection tags:")

    for tag, count in tag_counts.most_common():
        print(
            f"  {tag:25} {count}"
        )


if __name__ == "__main__":
    main()
