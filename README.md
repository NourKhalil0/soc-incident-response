# SOC Incident Response Playbooks & Tooling

Personal collection of incident response standard operating procedures (SOPs), detection engineering rules, and triage scripts developed during cybersecurity lab simulations.

## Repository Structure
- `playbooks/`: Incident response SOPs mapped to common threat vectors.
- `rules/`: Sigma detection rules for Windows endpoint and cloud telemetry.
- `scripts/`: Python command-line utilities for artifact extraction and log analysis.
- `templates/`: Post-mortem incident report templates.

## Severity Matrix
| Level | Description | Target SLA |
|---|---|---|
| P1 - Critical | Active ransomware, Domain Controller compromise | Immediate (< 15m) |
| P2 - High | Multi-system malware outbreak, confirmed data exfiltration | < 1 hour |
| P3 - Medium | Isolated malware on workstation, suspicious lateral attempt | < 4 hours |
| P4 - Low | Phishing blocked at gateway, policy violations | < 24 hours |

## Toolset Quickstart
```bash
# Parse SSH authentication logs for brute-force attacks
python scripts/parse_auth_logs.py /var/log/auth.log --threshold 10

# Extract and defang IOCs from incident reports
python scripts/extract_iocs.py triage_notes.txt --defang --json

# Run test suite
pytest tests/
```
