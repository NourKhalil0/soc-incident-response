# Lab Simulation Results & Validation (September 2026)

## 1. Testbed Architecture
- **Victim Subnet (VLAN 50):** Windows 11 Enterprise (23H2), Sysmon v15.1, M365 Defender.
- **Domain Controller (VLAN 60):** Windows Server 2025, Active Directory Domain Services.
- **SIEM / Log Collector:** Ubuntu 24.04 LTS running Microsoft Sentinel forwarding agent.

## 2. Test Cases & SLA Validation
| Threat Scenario | Emulation Tool | Detection Mechanism | Result | Time to Detect |
|---|---|---|---|---|
| Phishing Macro Execution | Atomic Red Team (T1059.001) | Sigma: PowerShell Download Cradle | PASS | 12 seconds |
| Shadow Copy Deletion | Atomic Red Team (T1490) | Sigma: Vssadmin Shadow Delete | PASS | 8 seconds |
| Lateral Movement (PsExec) | Sysinternals PsExec.exe | Sysmon Event ID 7045 | PASS | 15 seconds |
| Failed SSH Brute-Force | Hydra password spray | `scripts/parse_auth_logs.py` | PASS | Instant |

All tested playbooks and Sigma rules proved operational with zero critical false negatives.

## 3. Final Verification
All 4 incident response playbooks and detection engineering rules passed final peer review.
