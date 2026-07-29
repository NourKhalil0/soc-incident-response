# Playbook 02: Ransomware Containment & Incident Response

## 1. Goal
Rapidly isolate affected endpoints to prevent lateral propagation, preserve volatile memory for root cause analysis, and recover securely from offline immutable backups.

## 2. Immediate Containment Checklist
1. Isolate Affected Endpoints via EDR.
2. Restrict SMB (445) and RDP (3389) inter-VLAN routing.
3. Rotate KRBTGT twice and reset compromised privileged credentials.

## 3. Evidence Preservation
- Capture RAM using WinPmem / LiME.
- Verify state of Volume Shadow Copies (`vssadmin list shadows`).
- Check ransom note timestamp to establish breach timeline.

- Cross-reference memory triage findings with `cheatsheets/windows-memory-acquisition.md`.
