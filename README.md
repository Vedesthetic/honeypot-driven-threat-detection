# Honeypot-Driven Threat Detection Pipeline

A cybersecurity MVP that uses a Cowrie SSH honeypot to collect real attacker activity and a custom Python pipeline to normalize, enrich, detect, score, and report threats.

Wazuh SIEM integration is planned as a later implementation phase.

## Current MVP Architecture

```text
Internet Attackers
        ↓
   Cowrie Honeypot
        ↓
     Cowrie Logs
        ↓
   parser.py
        ↓
 Normalized Events
        ↓
  enricher.py
        ↓
AbuseIPDB Enrichment
        ↓
  detector.py
        ↓
Detection Rules + Risk Scoring
        ↓
   report.py
        ↓
 Report + Incident Data
        ↓
 dashboard.py
        ↓
 Offline Dashboard
```

## What the MVP Does

- Collects real SSH attack activity using Cowrie
- Parses Cowrie logs into normalized events
- Extracts attacker/source IP information
- Enriches public IPs using AbuseIPDB
- Caches AbuseIPDB responses
- Detects suspicious and multi-stage behavior
- Assigns risk scores and severity levels
- Generates JSONL alerts
- Generates a structured threat report
- Generates an offline HTML dashboard
- Supports analysis of previously collected logs without keeping the honeypot online

## Current Results

The current test dataset contains:

- **512 normalized/enriched events**
- **63 unique source IPs**
- **117 unique sessions**
- **27 detected incidents**
- **4 critical incidents**
- **8 medium incidents**
- **15 low incidents**

The report also includes:

- Top attacking source IPs
- Source countries
- Attempted usernames
- Attempted passwords
- Detection techniques
- Critical incidents
- AbuseIPDB reputation information

## Project Structure

```text
honeypot-driven-threat-detection/
├── .venv/
├── output/
│   ├── normalized-events.jsonl
│   ├── enriched-events.jsonl
│   ├── abuseipdb-cache.json
│   ├── alerts.jsonl
│   ├── report.json
│   └── dashboard.html
├── samples/
├── parser.py
├── enricher.py
├── detector.py
├── report.py
├── dashboard.py
├── requirements.txt
├── README.md
└── .gitignore
```

## Requirements

- Python 3
- Linux/macOS/WSL or another Unix-like environment
- Cowrie logs for analysis
- AbuseIPDB API key for live enrichment

The parsing, detection, reporting, and dashboard stages can operate on already-enriched/local data without making new AbuseIPDB requests.

## Setup

Create and activate a virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Check the available command-line options:

```bash
python parser.py --help
python enricher.py --help
python detector.py --help
python report.py --help
python dashboard.py --help
```

## Pipeline

The processing flow is:

```text
Cowrie logs
    ↓
parser.py
    ↓
enricher.py
    ↓
detector.py
    ↓
report.py
    ↓
dashboard.py
```

Example detection/report workflow using the current generated files:

```bash
python detector.py     output/enriched-events.jsonl     --output output/alerts.jsonl

python report.py     output/enriched-events.jsonl     output/alerts.jsonl     --output output/report.json
```

## AbuseIPDB Enrichment

`enricher.py` uses AbuseIPDB to add threat-intelligence context to public source IPs.

The enrichment can include:

- Abuse confidence score
- Country code
- ISP
- Usage type
- Domain
- Number of reports
- Number of distinct reporting users
- Last reported time

Responses are cached in:

```text
output/abuseipdb-cache.json
```

Previously enriched IPs can therefore be reused without another API request.

**Never commit your AbuseIPDB API key to Git.**

## Detection

`detector.py` identifies suspicious behavior from honeypot activity.

Examples include:

- Successful login followed by command execution
- Successful login followed by file download
- Payload downloads using `wget` or `curl`
- Downloaded executable preparation
- Remote payload execution
- Shell execution
- SSH/SCP activity
- Credential-related activity
- Suspicious file activity
- Multi-stage behavior from the same source

The detector combines evidence into a risk score and assigns severity such as low, medium, high, or critical.

## Offline Analysis

The project can analyze previously collected logs locally.

Generated files include:

```text
normalized-events.jsonl
enriched-events.jsonl
alerts.jsonl
report.json
dashboard.html
```

Once enrichment data has been cached, the existing dataset can be analyzed without keeping the Azure honeypot online.

Live AbuseIPDB lookups require network access and a valid API key. Cached enrichment does not.

## Dashboard

The generated dashboard is:

```text
output/dashboard.html
```

It provides a local view of:

- Attack activity
- Severity distribution
- Top source IPs
- Source countries
- Common usernames/passwords
- Detection techniques
- Critical incidents

The dashboard is intended to work offline with the generated report data.

## Current Status

### Completed MVP

- [x] Azure honeypot deployment
- [x] Ubuntu Server environment
- [x] Cowrie SSH honeypot
- [x] Real-world SSH traffic collection
- [x] Python log parsing
- [x] Event normalization
- [x] AbuseIPDB enrichment
- [x] Enrichment caching
- [x] Severity/risk scoring
- [x] Custom detection logic
- [x] Alert generation
- [x] Threat reporting
- [x] Offline dashboard
- [x] Analysis of real collected attack data

### Planned / Later Phase

- [ ] Wazuh SIEM integration
- [ ] Wazuh custom detection rules
- [ ] Real-time SIEM dashboards and alerting
- [ ] Automated response / IP blocking

Automated blocking is intentionally outside the current MVP and is treated as a later phase.

## Technology Stack

- **Honeypot:** Cowrie
- **Cloud:** Microsoft Azure
- **Server OS:** Ubuntu Server
- **Development OS:** Linux
- **Language:** Python 3
- **Threat Intelligence:** AbuseIPDB
- **SIEM:** Wazuh (planned integration)
- **Visualization:** HTML/JavaScript dashboard
- **Version Control:** Git/GitHub

## Project Goal

The goal is to demonstrate an end-to-end honeypot-driven threat detection workflow using real attacker telemetry:

```text
Capture → Normalize → Enrich → Detect → Score → Report → Visualize
```

The current MVP focuses on making this pipeline reproducible and demonstrable. Wazuh SIEM integration is the next major implementation phase.
