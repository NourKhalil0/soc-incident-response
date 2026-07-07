# Playbook 02: Ransomware Containment & Incident Response

## 1. Goal
Rapidly isolate affected endpoints to prevent lateral propagation, preserve volatile memory for root cause analysis, and recover securely from offline immutable backups.

## 2. Immediate Containment Checklist
1. **Isolate Affected Endpoints:**
   - Trigger EDR Network Containment.
   - If EDR fails, physically disconnect Ethernet cable or disable Wi-Fi adapter.
   - **DO NOT reboot or power off the machine** (preserves memory forensics and potential key material).
2. **Network Perimeter:**
   - Block known C2 domains and egress IP addresses on perimeter firewalls.
   - Restrict internal SMB (`TCP 445`) and RDP (`TCP 3389`) inter-VLAN routing.
3. **Identity & Directory Service:**
   - Disable compromised service accounts and domain admin credentials.
   - Enable Kerberos Armor (FAST) and rotate KRBTGT password twice.

## 3. Evidence Preservation & Forensic Artifacts
- Capture RAM using WinPmem / LiME.
- Extract Security Event Logs:
  - `4624` (Successful Logon)
  - `4625` (Failed Logon)
  - `7045` (Service Installed)
- Verify state of Volume Shadow Copies (`vssadmin list shadows`).
- Check Ransom note timestamp to pinpoint the start of the encryption wave.
