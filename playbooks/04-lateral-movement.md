# Playbook 04: Lateral Movement & Unauthorized Access

## 1. Triggers
- Pass-the-Hash / Pass-the-Ticket attempts.
- Remote command execution via PsExec or WMI.
- Anomalous RDP sessions across internal subnet boundaries.

## 2. Key Triage Event IDs
- **Event ID 4624 (Logon Type 3 / Type 10):** Network logon and Remote Interactive logon.
- **Event ID 7045:** Service creation (frequently created by PsExec / lateral movement frameworks).
- **Event ID 4104:** PowerShell Script Block Logging.

## 3. Containment Sequence
1. Isolate originating workstation using EDR network containment.
2. Invalidate active Kerberos tickets with `klist purge`.
3. Restrict internal SMB (`TCP 445`) and RDP (`TCP 3389`) inter-VLAN routing.
