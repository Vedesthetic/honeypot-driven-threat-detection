# Honeypot-Driven Threat Detection Pipeline

A cybersecurity project that uses a Cowrie SSH honeypot to collect
attacker activity and enrich the collected data before sending it
to Wazuh SIEM for detection and visualization.

## Current Architecture

Internet
↓
Azure VM
↓
Cowrie SSH Honeypot
↓
Cowrie Logs
↓
Python Log Parser
↓
IP Geolocation + Threat Intelligence + Severity
↓
Wazuh SIEM
↓
Alerts & Dashboard

## Current Status

- [x] Azure VPS deployed
- [x] Ubuntu Server configured
- [x] Cowrie installed
- [x] Cowrie SSH honeypot deployed
- [x] Port 2222 exposed
- [x] Real-world SSH traffic collected
- [ ] Python log parser
- [ ] IP geolocation enrichment
- [ ] AbuseIPDB integration
- [ ] Severity scoring
- [ ] Wazuh integration
- [ ] Custom detection rules
- [ ] Dashboard

## Technology Stack

- Azure
- Ubuntu Server
- Cowrie
- Python
- Wazuh
- AbuseIPDB
- Git/GitHub
