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

- MITRE ATT&CK T1047: WMI triage procedures documented.

```bash
# Analyze domain entropy for algorithmically generated C2 domains
python scripts/summarize_pcap_conversations.py evilcorp.biz xyz981723498172.cc
```

- `playbooks/07-ransomware-root-cause-analysis.md`: Root cause analysis.

<!-- Formatted documentation tables -->

## MITRE ATT&CK Matrix Mapping
| Playbook | MITRE ID | Technique Name | Detection Rule |
|---|---|---|---|
| 01-Phishing | T1566.001 | Spearphishing Attachment | `rules/proc_creation_win_powershell_download_cradle.yml` |
| 02-Ransomware | T1490 | Inhibit System Recovery | `rules/proc_creation_win_vssadmin_shadow_delete.yml` |
| 03-Credentials | T1078.004 | Cloud Accounts | Sentinel KQL Password Spray Query |
| 04-Lateral Movement | T1569.002 | Service Execution (PsExec) | `rules/proc_creation_win_psexec_service_install.yml` |

## August 2026 Homelab Milestones
- Implemented 3 triage CLI utilities with passing unit tests.
- Formulated 7 comprehensive incident response playbooks.
- Integrated memory, event log, and network DGA detection workflows.

## Lab Validation Reports
- [September 2026 Simulation Results](docs/lab-simulation-results.md)

## References & Standards
- [NIST SP 800-61 Rev. 2](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
- [SANS Incident Handler's Handbook](https://www.sans.org/white-papers/33393/)

---
*Maintained by Nour Mo - Cybersecurity Lab Research*
