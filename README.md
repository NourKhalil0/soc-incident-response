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

- `cheatsheets/windows-memory-acquisition.md`: Volatile RAM acquisition guide.

```bash
# Parse Volatility malfind reports for injected shellcode
python scripts/analyze_memory_dump.py malfind.txt
```

- `cheatsheets/wireshark-filters-for-soc.md`: Network packet analysis filters.

- `playbooks/06-insider-threat-data-exfiltration.md`: Insider threat SOP.

```bash
# Parse exported Windows Security XML events
python scripts/parse_evtx_events.py security_export.xml --filter 4625
```

- `cheatsheets/powershell-incident-response-commands.md`: Live PowerShell triage commands.

- `docs/lab-simulation-02-cobalt-strike.md`: Beacon triage simulation.
