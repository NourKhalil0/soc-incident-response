# Incident Response Post-Mortem Report

**Incident ID:** INC-YYYYMMDD-XX  
**Classification:** Phishing / Ransomware / Unauthorized Access  
**Severity Level:** P1 / P2 / P3 / P4  
**Lead Analyst:** Nour Mo  
**Date of Incident:** YYYY-MM-DD  

---

## 1. Executive Summary
Brief 2-3 paragraph summary of the event, business impact, and resolution.

## 2. Timeline of Key Events (UTC)
| Timestamp | Telemetry Source | Observed Activity |
|---|---|---|
| HH:MM:SS | SIEM / EDR | Initial detection alert triggered |
| HH:MM:SS | SOC Tier 1 | Host isolated and triage initiated |
| HH:MM:SS | SOC Tier 2 | Remediation verified and case resolved |

## 3. Root Cause Analysis
Detailed explanation of attack path and initial ingress vector.

## 4. Remediation & Action Items
- [ ] Update detection signatures in SIEM
- [ ] Remediate identified configuration vulnerabilities
- [ ] Conduct end-user awareness refresher

## 5. MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name | Evidence |
|---|---|---|---|
| Initial Access | T1566.001 | Spearphishing Attachment | Malicious `.xlsm` attachment |
| Execution | T1059.001 | PowerShell | WebClient download cradle |
| Impact | T1490 | Inhibit System Recovery | `vssadmin delete shadows` execution |
