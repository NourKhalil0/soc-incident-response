# Playbook 04: Lateral Movement & Unauthorized Access

## 1. Triggers
- Pass-the-Hash / Pass-the-Ticket attempts.
- Remote command execution via PsExec or WMI.

## 2. Key Triage Event IDs
- Event ID 4624 (Logon Type 3 / Type 10)
- Event ID 7045 (Service Installed)

## 3. WMI Remote Execution Triage
- Review Event ID 5861 in `Microsoft-Windows-WMI-Activity/Operational`.
- Identify parent process executing `wmic.exe /node:<target>`.

- Rule `rules/proc_creation_win_wmic_remote_process.yml` operational.

- Cross-referenced with Playbook 07 for root cause analysis.

## 4. DCSync Detection & Remediation
- Look for Directory Service Access (Event ID `4662`) with extended rights:
  - `DS-Replication-Get-Changes`
  - `DS-Replication-Get-Changes-All`
