# SOC Incident Response Playbooks & Tooling

Personal collection of incident response SOPs, detection engineering rules, and forensic triage utilities.

## Overview
Documentation and code developed during cybersecurity lab simulations.

## Severity Matrix
| Level | Description | Target SLA |
|---|---|---|
| P1 - Critical | Active ransomware, Domain Controller compromise | Immediate (< 15m) |
| P2 - High | Multi-system malware outbreak, confirmed data exfiltration | < 1 hour |
| P3 - Medium | Isolated malware on workstation, suspicious lateral attempt | < 4 hours |
| P4 - Low | Phishing blocked at gateway, policy violations | < 24 hours |

## Toolset Quickstart
```bash
python scripts/parse_auth_logs.py /var/log/auth.log --threshold 10
python scripts/extract_iocs.py triage_notes.txt --defang --json
pytest tests/
```
